#![allow(clippy::collapsible_if)]

use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use crate::tls;
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::debug;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{version, CipherSuite};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

pub struct TlsAudit;

#[async_trait]
impl Module for TlsAudit {
    fn name(&self) -> &'static str {
        "tlsaudit"
    }

    fn description(&self) -> &'static str {
        "Built-in TLS/SSL audit (versions, ciphers, certificates)"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let addr = target.address();
        let server_name = server_name_for(target)?;
        let host = target.host();
        let dur = config.timeout();

        if !is_port_reachable(&addr, dur).await {
            debug!("TLS audit: {} is not reachable", addr);
            return Ok(vec![Finding::new(
                "tlsaudit",
                "TLS service unreachable",
                Severity::Info,
                "Could not establish a TCP connection to the TLS port",
            )
            .with_evidence(format!("Target: {}", addr))
            .with_remediation(
                "Ensure the target is reachable and TLS is enabled on the expected port.",
            )]);
        }

        let mut findings = Vec::new();

        if config.modules.tlsaudit.check_versions {
            findings.append(&mut check_versions(&addr, &server_name, &host, dur).await?);
        }

        if config.modules.tlsaudit.check_ciphers {
            findings.append(&mut check_ciphers(&addr, &server_name, dur).await?);
        }

        if config.modules.tlsaudit.check_certificate {
            findings.append(&mut check_certificate(target, &server_name, dur).await?);
        }

        Ok(findings)
    }
}

fn server_name_for(target: &Target) -> Result<ServerName<'static>> {
    let host = target.host();
    match &target.host {
        url::Host::Ipv4(ip) => Ok(ServerName::IpAddress(std::net::IpAddr::V4(*ip).into())),
        url::Host::Ipv6(ip) => Ok(ServerName::IpAddress(std::net::IpAddr::V6(*ip).into())),
        url::Host::Domain(_) => ServerName::try_from(host.clone())
            .map_err(|e| anyhow::anyhow!("invalid server name '{}': {}", host, e)),
    }
}

async fn is_port_reachable(addr: &str, dur: Duration) -> bool {
    matches!(timeout(dur, TcpStream::connect(addr)).await, Ok(Ok(_)))
}

async fn check_versions(
    addr: &str,
    server_name: &ServerName<'static>,
    host: &str,
    dur: Duration,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let (tls13, tls12) = tokio::join!(
        probe_version(addr, server_name, &version::TLS13, dur),
        probe_version(addr, server_name, &version::TLS12, dur),
    );

    let (tls10, tls11) = tokio::join!(
        probe_legacy_tls_version(addr, LegacyTlsVersion::Tls10, host, dur),
        probe_legacy_tls_version(addr, LegacyTlsVersion::Tls11, host, dur),
    );

    let mut supported = Vec::new();
    if tls13 {
        supported.push("TLS 1.3");
    }
    if tls12 {
        supported.push("TLS 1.2");
    }

    let any_supported = !supported.is_empty() || tls10 || tls11;

    if !any_supported {
        findings.push(
            Finding::new(
                "tlsaudit",
                "No supported TLS versions detected",
                Severity::Info,
                "Could not negotiate TLS 1.2 or TLS 1.3 with the target",
            )
            .with_evidence(format!("Target: {}", addr))
            .with_remediation("Ensure the target supports at least TLS 1.2, preferably TLS 1.3."),
        );
        return Ok(findings);
    }

    if !supported.is_empty() {
        findings.push(
            Finding::new(
                "tlsaudit",
                "Supported TLS versions",
                Severity::Info,
                "TLS versions that the target accepted during handshake",
            )
            .with_evidence(supported.join(", ")),
        );
    }

    if tls12 && !tls13 {
        findings.push(
            Finding::new(
                "tlsaudit",
                "TLS 1.3 not supported",
                Severity::Medium,
                "The server supports TLS 1.2 but not the latest TLS version",
            )
            .with_evidence("Only TLS 1.2 handshake succeeded")
            .with_remediation(
                "Enable TLS 1.3 on the server for improved security and performance.",
            ),
        );
    }

    if tls12 {
        findings.push(
            Finding::new(
                "tlsaudit",
                "Legacy TLS 1.2 supported",
                Severity::Low,
                "TLS 1.2 is considered legacy and should be disabled where possible",
            )
            .with_evidence("The server accepted a TLS 1.2 handshake")
            .with_remediation("Disable TLS 1.2 and require TLS 1.3 if clients support it."),
        );
    }

    if tls10 {
        findings.push(
            Finding::new(
                "tlsaudit",
                "Deprecated TLS 1.0 supported",
                Severity::Critical,
                "TLS 1.0 is obsolete and enables known attacks such as BEAST/POODLE",
            )
            .with_evidence("The server accepted a TLS 1.0 handshake")
            .with_remediation("Disable TLS 1.0 and enforce TLS 1.2 or higher."),
        );
    }

    if tls11 {
        findings.push(
            Finding::new(
                "tlsaudit",
                "Deprecated TLS 1.1 supported",
                Severity::High,
                "TLS 1.1 is obsolete and should not be used",
            )
            .with_evidence("The server accepted a TLS 1.1 handshake")
            .with_remediation("Disable TLS 1.1 and enforce TLS 1.2 or higher."),
        );
    }

    Ok(findings)
}

async fn probe_version(
    addr: &str,
    server_name: &ServerName<'static>,
    version: &'static rustls::SupportedProtocolVersion,
    dur: Duration,
) -> bool {
    let connector = match build_version_connector(version) {
        Ok(c) => c,
        Err(e) => {
            debug!("failed to build connector for {:?}: {}", version.version, e);
            return false;
        }
    };
    try_handshake(&connector, addr, server_name, dur)
        .await
        .is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyTlsVersion {
    Tls10,
    Tls11,
}

impl LegacyTlsVersion {
    fn version_bytes(&self) -> [u8; 2] {
        match self {
            LegacyTlsVersion::Tls10 => [0x03, 0x01],
            LegacyTlsVersion::Tls11 => [0x03, 0x02],
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            LegacyTlsVersion::Tls10 => "TLS 1.0",
            LegacyTlsVersion::Tls11 => "TLS 1.1",
        }
    }
}

/// Probe whether a server accepts a legacy TLS version by sending a minimal
/// ClientHello over a raw TCP connection and looking for a ServerHello response.
/// This avoids pulling in a TLS library that still supports TLS 1.0/1.1.
async fn probe_legacy_tls_version(
    addr: &str,
    version: LegacyTlsVersion,
    hostname: &str,
    dur: Duration,
) -> bool {
    let hello = build_legacy_client_hello(version, hostname);

    let mut stream = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    if timeout(dur, stream.write_all(&hello)).await.is_err() {
        return false;
    }

    let mut header = [0u8; 5];
    match timeout(dur, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        _ => return false,
    }

    let content_type = header[0];
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    if content_type == 0x15 {
        // Alert record: read level and description.
        let mut alert = [0u8; 2];
        if timeout(dur, stream.read_exact(&mut alert)).await.is_err() {
            return false;
        }
        let (level, description) = (alert[0], alert[1]);
        debug!(
            "legacy {} probe for {} received Alert level=0x{:02x} description=0x{:02x}",
            version.as_str(),
            addr,
            level,
            description
        );
        // A "protocol_version" alert (0x46) means the server explicitly refuses this version.
        return false;
    }

    if content_type != 0x16 {
        // Not a handshake (likely an alert).
        debug!(
            "legacy {} probe for {} returned content type 0x{:02x}, record len {}",
            version.as_str(),
            addr,
            content_type,
            record_len
        );
        return false;
    }

    let mut handshake_header = [0u8; 4];
    if timeout(dur, stream.read_exact(&mut handshake_header))
        .await
        .is_err()
    {
        return false;
    }

    // ServerHello is handshake type 0x02. The server version follows immediately.
    if handshake_header[0] == 0x02 {
        let mut server_version = [0u8; 2];
        if timeout(dur, stream.read_exact(&mut server_version))
            .await
            .is_err()
        {
            return false;
        }
        debug!(
            "legacy {} probe for {} succeeded; server chose 0x{:02x}{:02x}",
            version.as_str(),
            addr,
            server_version[0],
            server_version[1]
        );
        true
    } else {
        false
    }
}

/// Build a minimal TLS ClientHello for a legacy version probe. SNI is included
/// when the host looks like a domain name.
fn build_legacy_client_hello(version: LegacyTlsVersion, hostname: &str) -> Vec<u8> {
    let ver = version.version_bytes();
    let random = [0u8; 32];
    let session_id_len = 0u8;

    // Common cipher suites that a TLS 1.0/1.1 server is likely to accept.
    let cipher_suites: &[u8] = &[
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xc0, 0x09, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        0xc0, 0x0a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    ];

    let compression_methods: &[u8] = &[0x01, 0x00]; // length 1, null

    let mut extensions = Vec::new();
    if should_include_sni(hostname) {
        let host_bytes = hostname.as_bytes();
        let sni_list_len = 1 + 2 + host_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        extensions.extend_from_slice(&[0x00, 0x00]); // extension_type = server_name
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        extensions.push(0x00); // name_type = hostname
        extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(host_bytes);
    }

    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&ver);
    client_hello.extend_from_slice(&random);
    client_hello.push(session_id_len);
    client_hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(cipher_suites);
    client_hello.extend_from_slice(compression_methods);
    if !extensions.is_empty() {
        client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(&extensions);
    }

    let mut handshake = Vec::new();
    handshake.push(0x01); // handshake_type = ClientHello
    let ch_len = client_hello.len();
    handshake.extend_from_slice(&[(ch_len >> 16) as u8, (ch_len >> 8) as u8, ch_len as u8]);
    handshake.extend_from_slice(&client_hello);

    let mut record = Vec::new();
    record.push(0x16); // content_type = handshake
    record.extend_from_slice(&ver);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn should_include_sni(hostname: &str) -> bool {
    !hostname.is_empty()
        && !hostname.starts_with('[')
        && hostname.parse::<std::net::IpAddr>().is_err()
}

async fn check_ciphers(
    addr: &str,
    server_name: &ServerName<'static>,
    dur: Duration,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let concurrency = 4;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for cipher in rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES {
        let permit = semaphore.clone().acquire_owned().await?;
        let addr = addr.to_string();
        let server_name = server_name.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            probe_cipher(&addr, &server_name, *cipher, dur).await
        });
        handles.push(handle);
    }

    let mut supported = Vec::new();
    for handle in handles {
        if let Ok(Some(info)) = handle.await {
            supported.push(info);
        }
    }

    if supported.is_empty() {
        findings.push(
            Finding::new(
                "tlsaudit",
                "No TLS cipher suites detected",
                Severity::Info,
                "Could not negotiate any tested cipher suite",
            )
            .with_evidence(format!("Target: {}", addr))
            .with_remediation("Ensure the target supports modern TLS cipher suites."),
        );
        return Ok(findings);
    }

    supported.sort_by(|a, b| a.version.cmp(&b.version).then_with(|| a.name.cmp(&b.name)));

    let summary: Vec<String> = supported
        .iter()
        .map(|i| format!("{} ({})", i.name, i.version))
        .collect();
    findings.push(
        Finding::new(
            "tlsaudit",
            "Supported TLS cipher suites",
            Severity::Info,
            "Cipher suites that the target accepted during handshake",
        )
        .with_evidence(summary.join(", ")),
    );

    let weak: Vec<&CipherInfo> = supported
        .iter()
        .filter(|i| i.strength == CipherStrength::Weak)
        .collect();
    if !weak.is_empty() {
        findings.push(
            Finding::new(
                "tlsaudit",
                "Weak TLS cipher suites supported",
                Severity::High,
                "The server accepts weak or non-forward-secret cipher suites",
            )
            .with_evidence(
                weak.iter()
                    .map(|i| format!("{} ({})", i.name, i.version))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .with_remediation(
                "Disable weak ciphers and keep only AEAD cipher suites with forward secrecy.",
            ),
        );
    }

    if supported.iter().any(|i| i.version == "TLS 1.2") {
        findings.push(
            Finding::new(
                "tlsaudit",
                "TLS 1.2 cipher suites supported",
                Severity::Low,
                "Cipher suites used with the legacy TLS 1.2 protocol were accepted",
            )
            .with_evidence("At least one TLS 1.2 cipher suite handshake succeeded")
            .with_remediation("Disable TLS 1.2 cipher suites if all clients support TLS 1.3."),
        );
    }

    Ok(findings)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CipherInfo {
    name: String,
    version: String,
    strength: CipherStrength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CipherStrength {
    Strong,
    Weak,
}

async fn probe_cipher(
    addr: &str,
    server_name: &ServerName<'static>,
    cipher: rustls::SupportedCipherSuite,
    dur: Duration,
) -> Option<CipherInfo> {
    let connector = build_cipher_connector(cipher).ok()?;
    if try_handshake(&connector, addr, server_name, dur)
        .await
        .is_ok()
    {
        let version = if cipher.version() == &version::TLS13 {
            "TLS 1.3"
        } else {
            "TLS 1.2"
        };
        Some(CipherInfo {
            name: cipher.suite().as_str().unwrap_or("unknown").to_string(),
            version: version.to_string(),
            strength: classify_cipher(cipher.suite()),
        })
    } else {
        None
    }
}

fn classify_cipher(suite: CipherSuite) -> CipherStrength {
    match suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256
        | CipherSuite::TLS13_AES_256_GCM_SHA384
        | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => CipherStrength::Strong,
        // Treat any other negotiated cipher as weak. This is intentionally
        // conservative for a security scanner: CBC-only, RSA key exchange,
        // RC4, 3DES, export ciphers, and unknown suites are all reported.
        _ => CipherStrength::Weak,
    }
}

async fn check_certificate(
    target: &Target,
    server_name: &ServerName<'static>,
    dur: Duration,
) -> Result<Vec<Finding>> {
    let addr = target.address();
    let host = target.host();
    let mut findings = Vec::new();

    let connector = build_connector(all_cipher_provider(), &[&version::TLS13, &version::TLS12])?;
    let tls_stream = match try_handshake_stream(&connector, &addr, server_name, dur).await {
        Ok(s) => s,
        Err(e) => {
            debug!("TLS certificate check failed for {}: {}", addr, e);
            findings.push(
                Finding::new(
                    "tlsaudit",
                    "TLS handshake failed for certificate inspection",
                    Severity::Info,
                    "Could not complete a TLS handshake to inspect the certificate",
                )
                .with_evidence(format!("Target: {} | Error: {}", addr, e))
                .with_remediation(
                    "Ensure the target supports TLS and is reachable on the expected port.",
                ),
            );
            return Ok(findings);
        }
    };

    let (_, conn) = tls_stream.get_ref();
    let certs = match conn.peer_certificates() {
        Some(c) if !c.is_empty() => c,
        _ => {
            findings.push(
                Finding::new(
                    "tlsaudit",
                    "No TLS certificate presented",
                    Severity::Medium,
                    "The server completed the TLS handshake but did not send a certificate",
                )
                .with_evidence(format!("Target: {}", addr))
                .with_remediation("Ensure the server is configured with a valid TLS certificate."),
            );
            return Ok(findings);
        }
    };

    let leaf: &CertificateDer<'_> = &certs[0];
    let (_, cert) =
        X509Certificate::from_der(leaf.as_ref()).context("failed to parse TLS certificate")?;

    findings.append(&mut evaluate_certificate(&cert, &host));
    Ok(findings)
}

fn evaluate_certificate(cert: &X509Certificate, host: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_after = cert.validity().not_after.timestamp();
    let not_before = cert.validity().not_before.timestamp();
    let expiry = DateTime::from_timestamp(not_after, 0).unwrap_or_default();
    let start = DateTime::from_timestamp(not_before, 0).unwrap_or_default();
    let now = Utc::now();
    let key_size = cert
        .public_key()
        .parsed()
        .map(|pk| pk.key_size())
        .unwrap_or(0);

    let signature_oid = cert.signature_algorithm.oid().to_id_string();

    findings.push(
        Finding::new(
            "tlsaudit",
            "TLS certificate retrieved",
            Severity::Info,
            "TLS certificate details from the target",
        )
        .with_evidence(format!(
            "Subject: {} | Issuer: {} | Valid: {} to {} | Key size: {} bits | Signature: {}",
            subject, issuer, start, expiry, key_size, signature_oid
        ))
        .with_remediation("Ensure the certificate is valid, trusted, and renewed before expiry."),
    );

    if expiry < now {
        findings.push(
            Finding::new(
                "tlsaudit",
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
                "tlsaudit",
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
                "tlsaudit",
                "Self-signed TLS certificate",
                Severity::High,
                "The TLS certificate appears to be self-signed",
            )
            .with_evidence(format!("Subject == Issuer: {}", subject))
            .with_remediation("Use a certificate issued by a trusted public or internal CA."),
        );
    }

    if is_weak_signature_algorithm(&signature_oid) {
        findings.push(
            Finding::new(
                "tlsaudit",
                "Weak TLS certificate signature algorithm",
                Severity::High,
                "The certificate is signed with a cryptographically weak hash algorithm",
            )
            .with_evidence(format!("Signature algorithm OID: {}", signature_oid))
            .with_remediation(
                "Re-issue the certificate using SHA-256 or stronger with a modern signature algorithm.",
            ),
        );
    }

    if key_size > 0 && key_size < 2048 {
        findings.push(
            Finding::new(
                "tlsaudit",
                "Weak TLS certificate key size",
                Severity::High,
                "The certificate uses a key smaller than 2048 bits",
            )
            .with_evidence(format!("Key size: {} bits", key_size))
            .with_remediation(
                "Re-issue the certificate with at least a 2048-bit RSA or 256-bit ECDSA key.",
            ),
        );
    }

    let mut dns_sans = Vec::new();
    let mut ip_sans = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for gn in &san_ext.value.general_names {
            match gn {
                GeneralName::DNSName(s) => dns_sans.push(s.to_string()),
                GeneralName::IPAddress(octets) => {
                    let ip_str = match octets.len() {
                        4 => std::net::Ipv4Addr::from(
                            <[u8; 4]>::try_from(*octets).unwrap_or_default(),
                        )
                        .to_string(),
                        16 => std::net::Ipv6Addr::from(
                            <[u8; 16]>::try_from(*octets).unwrap_or_default(),
                        )
                        .to_string(),
                        _ => format!("{:?}", octets),
                    };
                    ip_sans.push(ip_str);
                }
                _ => {}
            }
        }
    }

    if !dns_sans.is_empty() || !ip_sans.is_empty() {
        let mut evidence = Vec::new();
        if !dns_sans.is_empty() {
            evidence.push(format!("DNS: {}", dns_sans.join(", ")));
        }
        if !ip_sans.is_empty() {
            evidence.push(format!("IP: {}", ip_sans.join(", ")));
        }
        findings.push(
            Finding::new(
                "tlsaudit",
                "TLS certificate SANs",
                Severity::Info,
                "Subject Alternative Names discovered",
            )
            .with_evidence(evidence.join(" | ")),
        );
    } else {
        findings.push(
            Finding::new(
                "tlsaudit",
                "TLS certificate missing SAN extension",
                Severity::Medium,
                "The certificate has no Subject Alternative Name extension",
            )
            .with_evidence("No SANs found in the certificate")
            .with_remediation(
                "Re-issue the certificate with a SAN extension containing all hostnames and IP addresses.",
            ),
        );
    }

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok());

    if !host_matches(host, &dns_sans, &ip_sans, cn) {
        findings.push(
            Finding::new(
                "tlsaudit",
                "TLS certificate hostname mismatch",
                Severity::Medium,
                "The certificate does not appear to cover the target hostname",
            )
            .with_evidence(format!(
                "Target host: {} | SANs: {:?} | CN: {:?}",
                host, dns_sans, cn
            ))
            .with_remediation(
                "Ensure the certificate includes the target hostname or IP address in its SANs.",
            ),
        );
    }

    findings
}

fn is_weak_signature_algorithm(oid: &str) -> bool {
    const WEAK: &[&str] = &[
        "1.2.840.113549.1.1.4", // md5WithRSAEncryption
        "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
        "1.2.840.10045.4.1",    // ecdsa-with-SHA1
        "1.2.840.10040.4.3",    // dsa-with-sha1
        "1.3.14.3.2.29",        // sha1WithRSA (older)
    ];
    WEAK.contains(&oid)
}

fn host_matches(host: &str, dns_sans: &[String], ip_sans: &[String], cn: Option<&str>) -> bool {
    if ip_sans.iter().any(|ip| ip == host) {
        return true;
    }
    if dns_sans.iter().any(|san| dns_matches(san, host)) {
        return true;
    }
    if let Some(cn) = cn {
        if dns_matches(cn, host) {
            return true;
        }
    }
    false
}

fn dns_matches(pattern: &str, host: &str) -> bool {
    if pattern.eq_ignore_ascii_case(host) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some(pos) = host.find('.') {
            return host[pos + 1..].eq_ignore_ascii_case(suffix);
        }
    }
    false
}

async fn try_handshake(
    connector: &TlsConnector,
    addr: &str,
    server_name: &ServerName<'static>,
    dur: Duration,
) -> Result<()> {
    let stream = timeout(dur, TcpStream::connect(addr)).await??;
    let _tls = timeout(dur, connector.connect(server_name.clone(), stream)).await??;
    Ok(())
}

async fn try_handshake_stream(
    connector: &TlsConnector,
    addr: &str,
    server_name: &ServerName<'static>,
    dur: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let stream = timeout(dur, TcpStream::connect(addr)).await??;
    Ok(timeout(dur, connector.connect(server_name.clone(), stream)).await??)
}

fn build_version_connector(
    version: &'static rustls::SupportedProtocolVersion,
) -> Result<TlsConnector> {
    build_connector(all_cipher_provider(), std::slice::from_ref(&version))
}

fn build_cipher_connector(cipher: rustls::SupportedCipherSuite) -> Result<TlsConnector> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![cipher];
    build_connector(provider, std::slice::from_ref(&cipher.version()))
}

fn all_cipher_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES.to_vec();
    provider
}

fn build_connector(
    provider: rustls::crypto::CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<TlsConnector> {
    tls::build_unverified_connector_with_provider(provider, versions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn server_name_for_domain() {
        let target = Target::parse("example.com").unwrap();
        assert!(server_name_for(&target).is_ok());
    }

    #[test]
    fn server_name_for_ipv4() {
        let target = Target::parse("192.0.2.1").unwrap();
        let sn = server_name_for(&target).unwrap();
        assert!(matches!(sn, ServerName::IpAddress(_)));
    }

    #[test]
    fn server_name_for_ipv6() {
        let target = Target::parse("[::1]").unwrap();
        let sn = server_name_for(&target).unwrap();
        assert!(matches!(sn, ServerName::IpAddress(_)));
    }

    #[test]
    fn detects_weak_signature_algorithms() {
        assert!(is_weak_signature_algorithm("1.2.840.113549.1.1.4"));
        assert!(is_weak_signature_algorithm("1.2.840.113549.1.1.5"));
        assert!(is_weak_signature_algorithm("1.2.840.10045.4.1"));
        assert!(!is_weak_signature_algorithm("1.2.840.113549.1.1.11")); // sha256WithRSAEncryption
    }

    #[test]
    fn classifies_modern_ciphers_as_strong() {
        assert_eq!(
            classify_cipher(CipherSuite::TLS13_AES_128_GCM_SHA256),
            CipherStrength::Strong
        );
        assert_eq!(
            classify_cipher(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            CipherStrength::Strong
        );
    }

    #[test]
    fn classifies_unknown_and_legacy_ciphers_as_weak() {
        // RSA key exchange with AES-CBC is not forward-secret and should be
        // reported as weak.
        assert_eq!(
            classify_cipher(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA),
            CipherStrength::Weak
        );
        // Any suite rustls does not explicitly recognize as strong is treated
        // as weak so the finding is never silently dropped.
        assert_eq!(
            classify_cipher(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
            CipherStrength::Weak
        );
    }

    #[test]
    fn dns_wildcard_matching() {
        assert!(dns_matches("*.example.com", "foo.example.com"));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "bar.foo.example.com"));
        assert!(dns_matches("example.com", "example.com"));
    }

    #[test]
    fn host_matches_san_and_cn() {
        let dns = vec!["example.com".to_string(), "*.example.com".to_string()];
        let ip: Vec<String> = vec!["127.0.0.1".to_string()];
        assert!(host_matches("example.com", &dns, &[], None));
        assert!(host_matches("foo.example.com", &dns, &[], None));
        assert!(host_matches("127.0.0.1", &[], &ip, None));
        assert!(host_matches("example.com", &[], &[], Some("example.com")));
        assert!(!host_matches("other.com", &dns, &ip, Some("example.com")));
    }

    fn canned_server_hello(version: [u8; 2]) -> Vec<u8> {
        let random = [0u8; 32];
        let session_id_len = 0u8;
        let cipher_suite = [0x00, 0x2f]; // TLS_RSA_WITH_AES_128_CBC_SHA
        let compression_method = 0u8;
        let extensions_len = 0u16;

        let mut server_hello = Vec::new();
        server_hello.extend_from_slice(&version);
        server_hello.extend_from_slice(&random);
        server_hello.push(session_id_len);
        server_hello.extend_from_slice(&cipher_suite);
        server_hello.push(compression_method);
        server_hello.extend_from_slice(&extensions_len.to_be_bytes());

        let mut handshake = Vec::new();
        handshake.push(0x02); // ServerHello
        let len = server_hello.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&server_hello);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&version);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[tokio::test]
    async fn legacy_probe_detects_tls_1_0_server_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.try_read(&mut buf);
            let response = canned_server_hello([0x03, 0x01]);
            let _ = stream.write_all(&response).await;
        });

        let target = format!("127.0.0.1:{}", port);
        let found = probe_legacy_tls_version(
            &target,
            LegacyTlsVersion::Tls10,
            "localhost",
            Duration::from_secs(2),
        )
        .await;
        assert!(found, "probe should detect the canned TLS 1.0 ServerHello");
    }

    #[tokio::test]
    async fn legacy_probe_detects_tls_1_1_server_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.try_read(&mut buf);
            let response = canned_server_hello([0x03, 0x02]);
            let _ = stream.write_all(&response).await;
        });

        let target = format!("127.0.0.1:{}", port);
        let found = probe_legacy_tls_version(
            &target,
            LegacyTlsVersion::Tls11,
            "localhost",
            Duration::from_secs(2),
        )
        .await;
        assert!(found, "probe should detect the canned TLS 1.1 ServerHello");
    }

    #[tokio::test]
    async fn legacy_probe_rejects_protocol_version_alert() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.try_read(&mut buf);
            // Alert record: fatal, protocol_version (0x46).
            let alert = [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46];
            let _ = stream.write_all(&alert).await;
        });

        let target = format!("127.0.0.1:{}", port);
        let found = probe_legacy_tls_version(
            &target,
            LegacyTlsVersion::Tls10,
            "localhost",
            Duration::from_secs(2),
        )
        .await;
        assert!(
            !found,
            "probe should treat a protocol_version alert as unsupported"
        );
    }
}
