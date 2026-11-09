use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::debug;
use reqwest::{Client, Response};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct Web;

#[async_trait]
impl Module for Web {
    fn name(&self) -> &'static str {
        "web"
    }

    fn description(&self) -> &'static str {
        "HTTP security headers, HTTPS redirect, and TLS certificate checks"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let host = target.to_string();

        let client = config.http_client()?;

        let mut https_resp: Option<Response> = None;
        let mut http_resp: Option<Response> = None;

        if config.modules.web.check_https {
            let url = format!("https://{}/", host);
            https_resp = fetch(&client, &url).await;
        }

        if config.modules.web.check_http {
            let url = format!("http://{}/", host);
            http_resp = fetch(&client, &url).await;
        }

        if config.modules.web.check_headers {
            let primary = https_resp.as_ref().or(http_resp.as_ref());
            if let Some(resp) = primary {
                findings.append(&mut check_security_headers(resp));
            }
        }

        if config.modules.web.check_cookies {
            let primary = https_resp.as_ref().or(http_resp.as_ref());
            if let Some(resp) = primary {
                findings.append(&mut check_cookies(resp));
            }
        }

        if config.modules.web.check_https {
            if let Some(resp) = &http_resp {
                findings.append(&mut check_https_redirect(
                    resp,
                    &format!("http://{}/", host),
                ));
            }
        }

        if config.modules.web.check_tls_cert && config.modules.web.check_https {
            findings.append(&mut check_tls_certificate(target, config).await?);
        }

        Ok(findings)
    }
}

async fn fetch(client: &Client, url: &str) -> Option<Response> {
    match client.get(url).send().await {
        Ok(resp) => Some(resp),
        Err(e) => {
            debug!("request to {} failed: {}", url, e);
            None
        }
    }
}

fn check_security_headers(resp: &Response) -> Vec<Finding> {
    let mut findings = Vec::new();
    let headers = resp.headers();
    let url = resp.url().to_string();
    // Browsers ignore Strict-Transport-Security received over plain HTTP, so
    // its absence there is not a finding (the missing HTTPS redirect is).
    let is_https = resp.url().scheme() == "https";

    let expected = vec![
        (
            "strict-transport-security",
            "HSTS",
            "Missing HSTS header",
            Severity::High,
        ),
        (
            "content-security-policy",
            "CSP",
            "Missing Content-Security-Policy header",
            Severity::Medium,
        ),
        (
            "x-frame-options",
            "X-Frame-Options",
            "Missing X-Frame-Options header",
            Severity::Medium,
        ),
        (
            "x-content-type-options",
            "X-Content-Type-Options",
            "Missing X-Content-Type-Options header",
            Severity::Medium,
        ),
        (
            "referrer-policy",
            "Referrer-Policy",
            "Missing Referrer-Policy header",
            Severity::Low,
        ),
        (
            "permissions-policy",
            "Permissions-Policy",
            "Missing Permissions-Policy header",
            Severity::Low,
        ),
    ];

    for (header, name, message, severity) in expected {
        if header == "strict-transport-security" && !is_https {
            continue;
        }
        if headers.get(header).is_none() {
            findings.push(
                Finding::new(
                    "web",
                    &format!("Missing {} header", name),
                    severity,
                    message,
                )
                .with_evidence(format!("URL: {}", url))
                .with_remediation(format!("Add the {} header to HTTP responses.", name)),
            );
        }
    }

    if let Some(hsts) = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
        .filter(|_| is_https)
    {
        if let Some(max_age) = parse_hsts_max_age(hsts) {
            // Six months is the commonly recommended minimum.
            if max_age < 15_552_000 {
                findings.push(
                    Finding::new(
                        "web",
                        "Weak HSTS max-age",
                        Severity::Low,
                        "The Strict-Transport-Security max-age is shorter than six months",
                    )
                    .with_evidence(format!(
                        "URL: {} | Strict-Transport-Security: {}",
                        url, hsts
                    ))
                    .with_remediation(
                        "Set max-age to at least 15552000 (180 days); 31536000 is typical.",
                    ),
                );
            }
        }
    }

    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        findings.push(
            Finding::new(
                "web",
                "Server banner disclosed",
                Severity::Low,
                "The Server header reveals implementation details",
            )
            .with_evidence(format!("Server: {}", server))
            .with_remediation("Remove or genericize the Server header."),
        );
    }

    findings
}

/// Extract the `max-age` directive (in seconds) from an HSTS header value.
fn parse_hsts_max_age(value: &str) -> Option<u64> {
    value.split(';').find_map(|directive| {
        let (name, val) = directive.trim().split_once('=')?;
        if name.trim().eq_ignore_ascii_case("max-age") {
            val.trim().trim_matches('"').parse().ok()
        } else {
            None
        }
    })
}

fn check_cookies(resp: &Response) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = resp.url().to_string();

    for cookie in resp.cookies() {
        // Never copy cookie values into reports; they are often session tokens.
        let raw = format!(
            "{}=<redacted>; Domain={}; Path={}",
            cookie.name(),
            cookie.domain().unwrap_or(""),
            cookie.path().unwrap_or("")
        );
        let checks = [
            (
                "HttpOnly",
                cookie.http_only(),
                "Set HttpOnly on session cookies",
            ),
            (
                "Secure",
                cookie.secure(),
                "Set Secure on cookies when served over HTTPS",
            ),
            (
                "SameSite",
                cookie.same_site_strict() || cookie.same_site_lax(),
                "Set SameSite on cookies to prevent CSRF",
            ),
        ];
        for (flag, present, remediation) in &checks {
            if !present {
                findings.push(
                    Finding::new(
                        "web",
                        &format!("Cookie missing {} flag", flag),
                        Severity::Medium,
                        &format!(
                            "A Set-Cookie header does not include the {} attribute",
                            flag
                        ),
                    )
                    .with_evidence(format!("URL: {} | Cookie: {}", url, raw))
                    .with_remediation(*remediation),
                );
            }
        }
    }

    findings
}

fn check_https_redirect(resp: &Response, requested_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let final_url = resp.url();
    let final_scheme = final_url.scheme();

    if final_scheme != "https" {
        findings.push(
            Finding::new(
                "web",
                "HTTP does not redirect to HTTPS",
                Severity::High,
                "The HTTP endpoint is accessible and does not enforce HTTPS",
            )
            .with_evidence(format!(
                "Requested: {} | Final: {}",
                requested_url, final_url
            ))
            .with_remediation("Configure a 301 redirect from HTTP to HTTPS for all requests."),
        );
    }

    findings
}

async fn check_tls_certificate(target: &Target, config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let host = target.host();
    // Bare targets carry no port; HTTPS lives on 443 unless told otherwise.
    let addr = target.socket_address(443);
    let dur = config.timeout();

    let server_name = match &target.host {
        url::Host::Ipv4(ip) => ServerName::IpAddress(std::net::IpAddr::V4(*ip).into()),
        url::Host::Ipv6(ip) => ServerName::IpAddress(std::net::IpAddr::V6(*ip).into()),
        url::Host::Domain(_) => ServerName::try_from(host.clone())
            .map_err(|e| anyhow::anyhow!("invalid server name '{}': {}", host, e))?,
    };

    // The detailed certificate evaluation (expiry, self-signed, SANs, signature
    // algorithms, etc.) lives in the tlsaudit module. Web only reports whether
    // TLS is reachable and whether the chain is trusted, avoiding duplicate
    // findings when both modules are enabled.
    //
    // A plain handshake (no verification) runs first so that "TLS is not
    // offered at all" is never misreported as "certificate not trusted".
    if let Err(e) = handshake(&addr, &server_name, dur, false).await {
        debug!("TLS not available on {}: {:#}", addr, e);
        return Ok(findings);
    }

    if !config.scanner.verify_tls_certificates {
        findings.push(
            Finding::new(
                "web",
                "TLS endpoint reachable",
                Severity::Info,
                "The target accepted a TLS handshake",
            )
            .with_evidence(format!("Target: {}", addr))
            .with_remediation(
                "Use tlsaudit for detailed certificate, version, and cipher findings.",
            ),
        );
        return Ok(findings);
    }

    match handshake(&addr, &server_name, dur, true).await {
        Ok(()) => {
            findings.push(
                Finding::new(
                    "web",
                    "TLS certificate chain trusted",
                    Severity::Info,
                    "The server's TLS certificate chain validated against the bundled Mozilla root store",
                )
                .with_evidence(format!("Target: {}", addr))
                .with_remediation("No action required; the certificate is trusted."),
            );
        }
        Err(e) => {
            findings.push(
                Finding::new(
                    "web",
                    "TLS certificate chain not trusted",
                    Severity::High,
                    "The server's TLS certificate chain failed validation",
                )
                .with_evidence(format!("Target: {} | Error: {:#}", addr, e))
                .with_remediation(
                    "Install a valid certificate (with its full intermediate chain) from a trusted CA. For internal CAs, re-run with --insecure.",
                ),
            );
        }
    }

    Ok(findings)
}

async fn handshake(
    addr: &str,
    server_name: &ServerName<'static>,
    dur: std::time::Duration,
    verify: bool,
) -> Result<()> {
    let connector = if verify {
        crate::tls::build_verified_connector()?
    } else {
        crate::tls::build_unverified_connector()?
    };
    let stream = timeout(dur, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timed out"))?
        .context("TCP connect failed")?;
    timeout(dur, connector.connect(server_name.clone(), stream))
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))?
        .context("TLS handshake failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hsts_max_age() {
        assert_eq!(
            parse_hsts_max_age("max-age=31536000; includeSubDomains"),
            Some(31536000)
        );
        assert_eq!(
            parse_hsts_max_age("includeSubDomains; MAX-AGE=\"300\""),
            Some(300)
        );
        assert_eq!(parse_hsts_max_age("includeSubDomains"), None);
    }
}
