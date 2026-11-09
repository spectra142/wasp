use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::Result;
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, CLOUDFLARE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use log::{debug, warn};
use regex::Regex;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Host;

/// Maximum WHOIS response size we are willing to buffer.
const MAX_WHOIS_BYTES: usize = 64 * 1024;

pub struct Recon;

#[async_trait]
impl Module for Recon {
    fn name(&self) -> &'static str {
        "recon"
    }

    fn description(&self) -> &'static str {
        "DNS, WHOIS, subdomain enumeration, and technology fingerprinting"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if config.modules.recon.enable_dns {
            findings.append(&mut dns_records(target, config).await?);
        }

        if config.modules.recon.enable_whois {
            findings.append(&mut whois(target, config).await?);
        }

        if config.modules.recon.enable_subdomain_bruteforce {
            findings.append(&mut subdomain_bruteforce(target, config).await?);
        }

        if config.modules.recon.enable_tech_fingerprint {
            findings.append(&mut tech_fingerprint(target, config).await?);
        }

        Ok(findings)
    }
}

/// Build a DNS resolver from the system configuration (`/etc/resolv.conf` or
/// the Windows registry), falling back to public resolvers when that fails.
fn resolver() -> Result<TokioResolver> {
    let system = TokioResolver::builder_tokio().and_then(|b| b.build());
    match system {
        Ok(r) => Ok(r),
        Err(e) => {
            debug!(
                "system DNS configuration unavailable ({}); using public resolvers",
                e
            );
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                TokioRuntimeProvider::default(),
            )
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build DNS resolver: {}", e))
        }
    }
}

/// Render the answers of a DNS lookup as strings.
fn record_strings(lookup: &hickory_resolver::lookup::Lookup) -> Vec<String> {
    lookup
        .answers()
        .iter()
        .map(|r| r.data.to_string())
        .collect()
}

async fn dns_records(target: &Target, config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    if !matches!(target.host, Host::Domain(_)) {
        debug!("DNS record lookups skipped for IP target");
        return Ok(findings);
    }
    let host = target.host();
    let resolver = resolver()?;
    let dur = config.timeout();

    // A / AAAA
    match timeout(dur, resolver.lookup_ip(host.as_str())).await {
        Ok(Ok(ips)) => {
            let records: Vec<IpAddr> = ips.iter().collect();
            if !records.is_empty() {
                findings.push(
                    Finding::new(
                        "recon",
                        "DNS A/AAAA records found",
                        Severity::Info,
                        &format!("Resolved {} to {} IP address(es)", host, records.len()),
                    )
                    .with_evidence(
                        records
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                );
            }
        }
        Ok(Err(e)) => debug!("DNS A/AAAA lookup failed for {}: {}", host, e),
        Err(_) => debug!("DNS A/AAAA lookup timed out for {}", host),
    }

    // MX
    if let Ok(Ok(response)) = timeout(dur, resolver.lookup(host.as_str(), RecordType::MX)).await {
        let mx = record_strings(&response);
        if !mx.is_empty() {
            findings.push(
                Finding::new(
                    "recon",
                    "MX records found",
                    Severity::Info,
                    "Mail exchange records were discovered",
                )
                .with_evidence(mx.join(", ")),
            );
        }
    }

    // NS
    if let Ok(Ok(response)) = timeout(dur, resolver.lookup(host.as_str(), RecordType::NS)).await {
        let ns = record_strings(&response);
        if !ns.is_empty() {
            findings.push(
                Finding::new(
                    "recon",
                    "NS records found",
                    Severity::Info,
                    "Name servers were discovered",
                )
                .with_evidence(ns.join(", ")),
            );
        }
    }

    // TXT
    if let Ok(Ok(response)) = timeout(dur, resolver.lookup(host.as_str(), RecordType::TXT)).await {
        let txt = record_strings(&response);
        if !txt.is_empty() {
            findings.push(
                Finding::new(
                    "recon",
                    "TXT records found",
                    Severity::Info,
                    "TXT records (SPF, DKIM, verification tokens) were discovered",
                )
                .with_evidence(txt.join(" | ")),
            );
        }
    }

    Ok(findings)
}

async fn whois(target: &Target, config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let domain = match &target.host {
        Host::Domain(d) => d.clone(),
        Host::Ipv4(_) | Host::Ipv6(_) => {
            debug!("WHOIS skipped for IP target");
            return Ok(findings);
        }
    };

    let dur = config.timeout();
    let iana_text = query_whois_server("whois.iana.org:43", &domain, dur).await;
    if iana_text.trim().is_empty() {
        debug!("IANA WHOIS returned no data for {}", domain);
        return Ok(findings);
    }

    // IANA returns a referral to the authoritative WHOIS server. Follow it once
    // to obtain the actual registration record.
    let text = if let Some(referral) = extract_whois_referral(&iana_text) {
        debug!("WHOIS referral for {}: {}", domain, referral);
        let referral_text = query_whois_server(&referral, &domain, dur).await;
        if referral_text.trim().is_empty() {
            iana_text
        } else {
            referral_text
        }
    } else {
        iana_text
    };

    if !text.trim().is_empty() {
        findings.push(
            Finding::new(
                "recon",
                "WHOIS record retrieved",
                Severity::Info,
                &format!("WHOIS data for {}", domain),
            )
            .with_evidence(text.lines().take(10).collect::<Vec<_>>().join("\n")),
        );
    }

    Ok(findings)
}

async fn query_whois_server(server: &str, domain: &str, dur: Duration) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    match timeout(dur, TcpStream::connect(server)).await {
        Ok(Ok(mut stream)) => {
            if let Err(e) = stream.write_all(format!("{}\r\n", domain).as_bytes()).await {
                warn!("WHOIS write to {} failed: {}", server, e);
                return String::new();
            }
            // WHOIS servers stream the record and then close the connection,
            // so keep reading until EOF (bounded by size and time).
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let deadline = tokio::time::Instant::now() + dur;
            while buf.len() < MAX_WHOIS_BYTES {
                match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            String::from_utf8_lossy(&buf).to_string()
        }
        Ok(Err(e)) => {
            debug!("WHOIS connection to {} failed: {}", server, e);
            String::new()
        }
        Err(_) => {
            debug!("WHOIS connection to {} timed out", server);
            String::new()
        }
    }
}

fn extract_whois_referral(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let trimmed = lower.trim();
        if let Some(server) = trimmed
            .strip_prefix("refer:")
            .or_else(|| trimmed.strip_prefix("whois server:"))
            .or_else(|| trimmed.strip_prefix("referralserver:"))
        {
            let server = server.trim();
            // Remove possible whois:// prefix.
            let server = server.strip_prefix("whois://").unwrap_or(server);
            // Append default WHOIS port if missing.
            if server.contains(':') {
                return Some(server.to_string());
            }
            return Some(format!("{}:43", server));
        }
    }
    None
}

/// Probe a few unlikely subdomains. If they all resolve to the same IP, the
/// target likely has a wildcard DNS record and brute-force would produce false
/// positives for every word in the wordlist.
async fn detect_wildcard_dns(domain: &str, config: &Config) -> Option<String> {
    let resolver = match resolver() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            debug!("failed to build resolver for wildcard check: {}", e);
            return None;
        }
    };
    let dur = config.timeout();
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let probes: Vec<String> = (0..3)
        .map(|i| format!("wasp-wildcard-{}-{}-{}.{}", pid, now, i, domain))
        .collect();

    let mut first_ip: Option<String> = None;
    for probe in &probes {
        match timeout(dur, resolver.lookup_ip(probe.as_str())).await {
            Ok(Ok(ips)) => {
                let addrs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                if addrs.is_empty() {
                    return None;
                }
                let representative = addrs.join(", ");
                match &first_ip {
                    None => first_ip = Some(representative),
                    Some(ip) if *ip == representative => {}
                    Some(_) => return None,
                }
            }
            _ => return None,
        }
    }

    first_ip
}

async fn subdomain_bruteforce(target: &Target, config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let domain = match &target.host {
        Host::Domain(d) => d.clone(),
        Host::Ipv4(_) | Host::Ipv6(_) => return Ok(findings),
    };

    if let Some(wildcard) = detect_wildcard_dns(&domain, config).await {
        findings.push(
            Finding::new(
                "recon",
                &format!("Wildcard DNS detected for {}", domain),
                Severity::Info,
                "A wildcard DNS record resolves arbitrary subdomains, making brute-force enumeration unreliable",
            )
            .with_evidence(format!("Sample resolved to: {}", wildcard))
            .with_remediation("Use other enumeration sources or disable subdomain brute-force for wildcard domains."),
        );
        return Ok(findings);
    }

    let words = crate::config::load_wordlist(
        &config.modules.recon.subdomain_wordlist,
        crate::config::EMBEDDED_SUBDOMAIN_WORDLIST,
    );

    if words.is_empty() {
        return Ok(findings);
    }

    let resolver = Arc::new(resolver()?);
    let semaphore = config.request_limiter();
    let dur = config.timeout();
    let mut handles = Vec::new();

    for word in words {
        let full = format!("{}.{}", word, domain);
        let permit = semaphore.clone().acquire_owned().await?;
        let resolver = Arc::clone(&resolver);
        let handle = tokio::spawn(async move {
            let _permit = permit;
            match timeout(dur, resolver.lookup_ip(full.as_str())).await {
                Ok(Ok(ips)) => {
                    let addrs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                    if !addrs.is_empty() {
                        Some(
                            Finding::new(
                                "recon",
                                &format!("Subdomain discovered: {}", full),
                                Severity::Info,
                                "A subdomain resolved to an IP address",
                            )
                            .with_evidence(addrs.join(", ")),
                        )
                    } else {
                        None
                    }
                }
                _ => None,
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Ok(Some(finding)) = handle.await {
            findings.push(finding);
        }
    }

    if !findings.is_empty() {
        findings.insert(
            0,
            Finding::new(
                "recon",
                &format!("Subdomain brute-force summary for {}", domain),
                Severity::Info,
                &format!("Discovered {} subdomain(s)", findings.len()),
            ),
        );
    }

    Ok(findings)
}

async fn tech_fingerprint(target: &Target, config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let host = target.to_string();
    let client = config.http_client()?;

    let urls: Vec<String> = {
        let mut v = Vec::new();
        if config.modules.recon.check_https {
            v.push(format!("https://{}/", host));
        }
        if config.modules.recon.check_http {
            v.push(format!("http://{}/", host));
        }
        v
    };

    for url in urls {
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("tech fingerprint request to {} failed: {}", url, e);
                continue;
            }
        };

        let headers = resp.headers().clone();
        let status = resp.status();
        let body = crate::http::read_body(resp).await;
        let header_text = headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, String::from_utf8_lossy(v.as_bytes())))
            .collect::<Vec<_>>()
            .join("\n");

        let mut detected = Vec::new();

        if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
            detected.push(format!("Server: {}", server));
        }
        if let Some(powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
            detected.push(format!("X-Powered-By: {}", powered));
        }
        if let Some(via) = headers.get("via").and_then(|v| v.to_str().ok()) {
            detected.push(format!("Via: {}", via));
        }

        for (name, re) in FINGERPRINTS.iter() {
            if re.is_match(&body) || re.is_match(&header_text) {
                detected.push(name.to_string());
            }
        }

        detected.sort();
        detected.dedup();

        if !detected.is_empty() {
            findings.push(
                Finding::new(
                    "recon",
                    "Technology fingerprint detected",
                    Severity::Info,
                    &format!("Detected technologies/services on {}", url),
                )
                .with_evidence(format!(
                    "Status: {} | Detected: {}",
                    status,
                    detected.join(", ")
                ))
                .with_remediation(
                    "Review exposed technology versions and remove unnecessary banners/headers.",
                ),
            );
        }
    }

    Ok(findings)
}

/// Technology fingerprints matched against response bodies and headers.
static FINGERPRINTS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("WordPress", r"/wp-content/|/wp-includes/"),
        ("Drupal", r"/sites/default/files|Drupal\.settings|X-Drupal-"),
        (
            "Joomla",
            r"/media/jui/|/media/system/js/|(?i)content=.joomla",
        ),
        (
            "React",
            r"data-reactroot|__REACT_DEVTOOLS|react-dom(?:\.production)?(?:\.min)?\.js",
        ),
        ("Next.js", r"__NEXT_DATA__|/_next/static/"),
        ("Angular", r"\bng-version=|\bng-app\b"),
        (
            "Vue.js",
            r"data-v-[0-9a-f]{8}|__VUE__|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js",
        ),
        (
            "Bootstrap",
            r"(?i)bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)",
        ),
        ("jQuery", r"(?i)jquery(?:-\d[\d.]*)?(?:\.min)?\.js"),
        ("PHP", r"(?i)X-Powered-By: PHP|PHPSESSID"),
        (
            "ASP.NET",
            r"(?i)X-AspNet-Version|__VIEWSTATE|ASP\.NET_SessionId",
        ),
        ("Cloudflare", r"(?i)cf-ray:|server: cloudflare"),
    ]
    .into_iter()
    .map(|(name, pattern)| (name, Regex::new(pattern).expect("valid fingerprint regex")))
    .collect()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whois_referral_is_extracted_with_default_port() {
        let text = "domain: COM\nrefer: whois.verisign-grs.com\n";
        assert_eq!(
            extract_whois_referral(text).as_deref(),
            Some("whois.verisign-grs.com:43")
        );
    }

    #[test]
    fn fingerprints_compile_and_match() {
        let body = r#"<script src="/wp-includes/js/jquery/jquery.min.js"></script>"#;
        let names: Vec<&str> = FINGERPRINTS
            .iter()
            .filter(|(_, re)| re.is_match(body))
            .map(|(n, _)| *n)
            .collect();
        assert!(names.contains(&"WordPress"));
        assert!(names.contains(&"jQuery"));
        assert!(!names.contains(&"PHP"));
    }
}
