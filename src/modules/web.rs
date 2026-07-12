use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::debug;
use reqwest::{Client, Response};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

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
                findings.append(&mut check_security_headers(resp, config));
            }
        }

        if config.modules.web.check_cookies {
            let primary = https_resp.as_ref().or(http_resp.as_ref());
            if let Some(resp) = primary {
                findings.append(&mut check_cookies(resp));
            }
        }

        if config.modules.web.check_https
            && let Some(resp) = &http_resp
        {
            findings.append(&mut check_https_redirect(resp, config));
        }

        if config.modules.web.check_tls_cert {
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

fn check_security_headers(resp: &Response, _config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let headers = resp.headers();
    let url = resp.url().to_string();

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

fn check_cookies(resp: &Response) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = resp.url().to_string();

    for cookie in resp.cookies() {
        let raw = format!(
            "{}={}; Domain={}; Path={}",
            cookie.name(),
            cookie.value(),
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

fn check_https_redirect(resp: &Response, _config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let initial_url = resp.url().to_string();

    let final_url = resp.url();
    let is_https = final_url.scheme() == "https";
    let redirected_to_https = resp.url().scheme() == "https";

    if !is_https && !redirected_to_https {
        findings.push(
            Finding::new(
                "web",
                "HTTP does not redirect to HTTPS",
                Severity::High,
                "The HTTP endpoint is accessible and does not enforce HTTPS",
            )
            .with_evidence(format!("Requested: {}", initial_url))
            .with_remediation("Configure a 301 redirect from HTTP to HTTPS for all requests."),
        );
    }

    findings
}

async fn check_tls_certificate(target: &Target, config: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let host = target.host();
    let addr = target.address();
    let dur = config.timeout();

    let server_name = match &target.host {
        url::Host::Ipv4(ip) => ServerName::IpAddress(std::net::IpAddr::V4(*ip).into()),
        url::Host::Ipv6(ip) => ServerName::IpAddress(std::net::IpAddr::V6(*ip).into()),
        url::Host::Domain(_) => ServerName::try_from(host.clone())
            .map_err(|e| anyhow::anyhow!("invalid server name '{}': {}", host, e))?,
    };

    // When verification is enabled, first check whether the chain is trusted.
    // We still perform an unverified handshake afterwards so we can inspect and
    // report certificate details even for self-signed/internal certs.
    if config.scanner.verify_tls_certificates {
        match check_tls_trust(&addr, &server_name, dur).await {
            Ok(()) => {
                findings.push(
                    Finding::new(
                        "web",
                        "TLS certificate chain trusted",
                        Severity::Info,
                        "The server's TLS certificate chain validated against the system's root store",
                    )
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
                    .with_evidence(format!("Error: {}", e))
                    .with_remediation(
                        "Install a valid certificate from a trusted CA, or import the issuing CA into the scanner's trust store.",
                    ),
                );
            }
        }
    }

    let connector = build_unverified_connector()?;
    let stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!("TLS cert check: TCP connect failed: {}", e);
            return Ok(findings);
        }
        Err(_) => {
            debug!("TLS cert check: TCP connect timed out");
            return Ok(findings);
        }
    };

    let tls_stream = match timeout(dur, connector.connect(server_name, stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!("TLS handshake failed: {}", e);
            return Ok(findings);
        }
        Err(_) => {
            debug!("TLS handshake timed out");
            return Ok(findings);
        }
    };

    let (_, conn) = tls_stream.get_ref();
    let certs = match conn.peer_certificates() {
        Some(c) if !c.is_empty() => c,
        _ => {
            findings.push(Finding::new(
                "web",
                "TLS handshake succeeded but no certificate presented",
                Severity::Medium,
                "The server completed TLS but did not send a certificate",
            ));
            return Ok(findings);
        }
    };

    let leaf: &CertificateDer<'_> = &certs[0];
    let (_, cert) =
        X509Certificate::from_der(leaf.as_ref()).context("failed to parse TLS certificate")?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_after = cert.validity().not_after.timestamp();
    let expiry = DateTime::from_timestamp(not_after, 0).unwrap_or_default();
    let now = Utc::now();

    findings.push(
        Finding::new(
            "web",
            "TLS certificate retrieved",
            Severity::Info,
            "TLS certificate details from the HTTPS endpoint",
        )
        .with_evidence(format!(
            "Subject: {} | Issuer: {} | Expires: {}",
            subject, issuer, expiry
        ))
        .with_remediation("Ensure the certificate is valid, trusted, and renewed before expiry."),
    );

    if expiry < now {
        findings.push(
            Finding::new(
                "web",
                "TLS certificate expired",
                Severity::Critical,
                "The server's TLS certificate has expired",
            )
            .with_evidence(format!("Expired on: {}", expiry))
            .with_remediation("Renew and install a valid TLS certificate immediately."),
        );
    } else if (expiry - now).num_days() < 30 {
        findings.push(
            Finding::new(
                "web",
                "TLS certificate expiring soon",
                Severity::Low,
                "The server's TLS certificate expires within 30 days",
            )
            .with_evidence(format!("Expires on: {}", expiry))
            .with_remediation("Renew the TLS certificate before expiry."),
        );
    }

    if subject == issuer {
        findings.push(
            Finding::new(
                "web",
                "Self-signed TLS certificate",
                Severity::High,
                "The TLS certificate appears to be self-signed",
            )
            .with_evidence(format!("Subject == Issuer: {}", subject))
            .with_remediation("Use a certificate issued by a trusted public or internal CA."),
        );
    }

    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        let sans: Vec<String> = san_ext
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                x509_parser::extensions::GeneralName::DNSName(s) => Some(s.to_string()),
                x509_parser::extensions::GeneralName::IPAddress(octets) => {
                    Some(format!("{:?}", octets))
                }
                _ => None,
            })
            .collect();
        if !sans.is_empty() {
            findings.push(
                Finding::new(
                    "web",
                    "TLS certificate SANs",
                    Severity::Info,
                    "Subject Alternative Names discovered",
                )
                .with_evidence(sans.join(", ")),
            );
        }
    }

    Ok(findings)
}

async fn check_tls_trust(
    addr: &str,
    server_name: &ServerName<'static>,
    dur: std::time::Duration,
) -> Result<()> {
    let connector = build_verified_connector()?;
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

fn build_verified_connector() -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn build_unverified_connector() -> Result<TlsConnector> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
