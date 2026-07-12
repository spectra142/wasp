use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use regex::Regex;
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;
use url::Host;

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

fn resolver() -> Result<TokioAsyncResolver> {
    Ok(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ))
}

async fn dns_records(target: &Target, config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let host = target.host();
    let resolver = resolver()?;
    let dur = config.timeout();

    // A / AAAA
    match timeout(dur, resolver.lookup_ip(&host)).await {
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
    if let Ok(Ok(response)) = timeout(dur, resolver.lookup(&host, RecordType::MX)).await {
        let mx: Vec<String> = response.iter().map(|r| r.to_string()).collect();
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
    if let Ok(Ok(response)) = timeout(dur, resolver.lookup(&host, RecordType::NS)).await {
        let ns: Vec<String> = response.iter().map(|r| r.to_string()).collect();
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
    if let Ok(Ok(response)) = timeout(dur, resolver.lookup(&host, RecordType::TXT)).await {
        let txt: Vec<String> = response.iter().map(|r| r.to_string()).collect();
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
            let mut buf = vec![0u8; 8192];
            match timeout(dur, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).to_string(),
                _ => String::new(),
            }
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
        match timeout(dur, resolver.lookup_ip(probe)).await {
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

    let wordlist_path = &config.modules.recon.subdomain_wordlist;
    let words = match fs::read_to_string(wordlist_path) {
        Ok(content) => content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        Err(e) => {
            warn!(
                "failed to read subdomain wordlist {:?}: {}",
                wordlist_path, e
            );
            return Ok(findings);
        }
    };

    if words.is_empty() {
        return Ok(findings);
    }

    let resolver = Arc::new(resolver()?);
    let semaphore = config
        .scanner
        .concurrency_semaphore
        .clone()
        .unwrap_or_else(|| {
            Arc::new(tokio::sync::Semaphore::new(
                config.scanner.concurrency.max(1),
            ))
        });
    let dur = config.timeout();
    let mut handles = Vec::new();

    for word in words {
        let full = format!("{}.{}", word, domain);
        let permit = semaphore.clone().acquire_owned().await?;
        let resolver = Arc::clone(&resolver);
        let handle = tokio::spawn(async move {
            let _permit = permit;
            match timeout(dur, resolver.lookup_ip(&full)).await {
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

    let fingerprints: Vec<(&str, Regex)> = vec![
        (
            "WordPress",
            Regex::new(r#"/wp-content/|/wp-includes/"#).unwrap(),
        ),
        (
            "Drupal",
            Regex::new(r#"/sites/default/|Drupal.settings"#).unwrap(),
        ),
        ("Joomla", Regex::new(r#"/media/jui/|/templates/"#).unwrap()),
        (
            "React",
            Regex::new(r#"reactroot|__REACT__|data-reactroot"#).unwrap(),
        ),
        ("Angular", Regex::new(r#"ng-app|angular"#).unwrap()),
        ("Vue.js", Regex::new(r#"vue-router|__VUE__"#).unwrap()),
        (
            "Bootstrap",
            Regex::new(r#"bootstrap|bootstrapcdn"#).unwrap(),
        ),
        ("jQuery", Regex::new(r#"jquery"#).unwrap()),
        ("PHP", Regex::new(r#"\.php|PHP/"#).unwrap()),
        ("ASP.NET", Regex::new(r#"ASP.NET|__VIEWSTATE"#).unwrap()),
    ];

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
        let body = resp.text().await.unwrap_or_default();

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

        for (name, re) in &fingerprints {
            if re.is_match(&body) || re.is_match(&format!("{:?}", headers)) {
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
