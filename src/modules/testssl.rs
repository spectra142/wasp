use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use log::{debug, warn};
use serde::Deserialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct Testssl;

#[async_trait]
impl Module for Testssl {
    fn name(&self) -> &'static str {
        "testssl"
    }

    fn description(&self) -> &'static str {
        "TLS/SSL configuration assessment via testssl.sh JSON output"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let host_arg = target.address();

        debug!("running testssl.sh against {}", host_arg);

        let tmp_path = temp_json_path();
        let mut cmd = Command::new(&config.tools.testssl_path);
        cmd.arg("--jsonfile-pretty")
            .arg(&tmp_path)
            .arg(&host_arg)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && config.tools.skip_missing_tools =>
            {
                warn!(
                    "testssl.sh binary not found at {:?}, skipping",
                    config.tools.testssl_path
                );
                return Ok(vec![
                    Finding::new(
                        "testssl",
                        "testssl.sh unavailable",
                        Severity::Info,
                        "The configured testssl.sh binary could not be found.",
                    )
                    .with_evidence(format!("path: {:?}", config.tools.testssl_path))
                    .with_remediation(
                        "Install testssl.sh or update tools.testssl_path in the configuration.",
                    ),
                ]);
            }
            Err(e) => return Err(e.into()),
        };

        let dur = Duration::from_secs(config.tools.testssl_timeout_secs);

        let result = async {
            let status = match timeout(dur, child.wait()).await {
                Ok(status) => status.context("testssl.sh process failed")?,
                Err(_) => {
                    let _ = child.kill().await;
                    anyhow::bail!("testssl.sh execution timed out after {:?}", dur);
                }
            };

            if !status.success() {
                warn!("testssl.sh exited with status {}", status);
            }

            if !tokio::fs::try_exists(&tmp_path).await.unwrap_or(false) {
                if status.success() {
                    anyhow::bail!(
                        "testssl.sh did not produce the expected JSON file at {:?}",
                        tmp_path
                    );
                } else {
                    anyhow::bail!(
                        "testssl.sh failed (exit {}) and did not produce a JSON file",
                        status
                    );
                }
            }

            let json = tokio::fs::read_to_string(&tmp_path)
                .await
                .with_context(|| format!("failed to read testssl.sh JSON from {:?}", tmp_path))?;
            parse_testssl_json(&json)
        }
        .await;

        let _ = tokio::fs::remove_file(&tmp_path).await;
        result
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestsslOutput {
    #[serde(default)]
    scan_result: Vec<ScanFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanFinding {
    id: String,
    severity: String,
    #[serde(default)]
    finding: String,
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    cwe: Option<String>,
    #[serde(default)]
    hint: Option<String>,
}

fn parse_severity(severity: &str) -> Option<Severity> {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" | "WARN" => Some(Severity::Low),
        "INFO" | "FATAL" => Some(Severity::Info),
        "OK" => None,
        _ => {
            warn!(
                "unknown testssl.sh severity '{}' treating as info",
                severity
            );
            Some(Severity::Info)
        }
    }
}

fn remediation_for(id: &str) -> &'static str {
    match id {
        "heartbleed" => "Upgrade OpenSSL and disable the TLS heartbeat extension.",
        "ccs" => {
            "Patch OpenSSL against CVE-2014-0224 and disable ChangeCipherSpec injection vectors."
        }
        "ticketbleed" => {
            "Update affected load balancers/devices and disable session ticket support if vulnerable."
        }
        "crime" => "Disable TLS compression on the server.",
        "breach" => {
            "Disable HTTP compression for sensitive responses or mitigate with CSRF tokens."
        }
        "poodle" | "poodle_tls" | "sslv2" | "sslv3" => {
            "Disable SSLv2/SSLv3 and block CBC-based POODLE vectors."
        }
        "sweet32" => "Disable 3DES cipher suites and prefer AES-GCM/ChaCha20-Poly1305.",
        "freak" => "Disable export-grade RSA cipher suites.",
        "logjam" => "Disable DHE_EXPORT cipher suites and use 2048-bit or stronger DH parameters.",
        "drown" => "Disable SSLv2 on all servers sharing the certificate/private key.",
        "rc4" | "rc4_expected" => "Disable RC4 cipher suites.",
        "tls1" | "tls1_1" => "Disable TLS 1.0/1.1 and enforce TLS 1.2 or higher.",
        "expired" | "cert_notAfter" => "Renew and install a valid TLS certificate before expiry.",
        "selfsigned" => "Replace the self-signed certificate with one issued by a trusted CA.",
        "chain_of_trust" | "chain_of_trust_warn" => {
            "Install the complete and correct intermediate certificate chain."
        }
        "ocsp" | "ocsp_stapling" => {
            "Enable OCSP stapling for better revocation checking performance."
        }
        "hsts" => "Configure the Strict-Transport-Security header with a long max-age.",
        _ => {
            "Review the finding in the testssl.sh output and apply the relevant security hardening guidance."
        }
    }
}

fn scan_entry_to_finding(entry: &ScanFinding) -> Option<Finding> {
    let severity = parse_severity(&entry.severity)?;

    if entry.id == "service" && severity == Severity::Info {
        return None;
    }

    let title = format!("TLS issue: {}", entry.id.replace('_', " "));
    let description = if entry.finding.is_empty() {
        title.clone()
    } else {
        entry.finding.clone()
    };

    let mut evidence_lines = vec![
        format!("id: {}", entry.id),
        format!("severity: {}", entry.severity),
    ];
    if !entry.finding.is_empty() {
        evidence_lines.push(format!("finding: {}", entry.finding));
    }
    if let Some(cve) = &entry.cve {
        evidence_lines.push(format!("CVE: {}", cve));
    }
    if let Some(cwe) = &entry.cwe {
        evidence_lines.push(format!("CWE: {}", cwe));
    }
    if let Some(hint) = &entry.hint {
        evidence_lines.push(format!("hint: {}", hint));
    }

    Some(
        Finding::new("testssl", &title, severity, &description)
            .with_evidence(evidence_lines.join("\n"))
            .with_remediation(remediation_for(&entry.id)),
    )
}

fn parse_testssl_json(json: &str) -> Result<Vec<Finding>> {
    let output: TestsslOutput =
        serde_json::from_str(json).context("failed to parse testssl.sh JSON")?;

    let mut findings: Vec<Finding> = output
        .scan_result
        .iter()
        .filter_map(scan_entry_to_finding)
        .collect();

    let highest = findings.iter().map(|f| f.severity).max();
    let summary = Finding::new(
        "testssl",
        "TLS/SSL scan summary",
        Severity::Info,
        &format!(
            "testssl.sh produced {} actionable finding(s)",
            findings.len()
        ),
    )
    .with_evidence(format!(
        "highest severity: {}",
        highest
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".to_string())
    ))
    .with_remediation("Review all TLS findings and prioritize high/critical items.");

    findings.push(summary);
    Ok(findings)
}

fn temp_json_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "wasp-testssl-{}-{}.json",
        std::process::id(),
        Utc::now().timestamp_millis()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    const SAMPLE_JSON: &str = r#"
    {
        "Invocation": "testssl.sh example.com",
        "version": "3.0.8",
        "startTime": "1234567890",
        "scanResult": [
            { "id": "service", "severity": "INFO", "finding": "HTTP" },
            { "id": "sslv2", "severity": "OK", "finding": "not offered" },
            { "id": "sslv3", "severity": "HIGH", "finding": "offered", "cve": "CVE-2014-3566" },
            { "id": "tls1", "severity": "MEDIUM", "finding": "offered" },
            { "id": "rc4", "severity": "LOW", "finding": "Vulnerable", "cwe": "CWE-327" },
            { "id": "heartbleed", "severity": "CRITICAL", "finding": "vulnerable" },
            { "id": "optimal_proto", "severity": "INFO", "finding": "TLS 1.3" }
        ],
        "targetHost": "example.com",
        "ip": "93.184.216.34",
        "port": "443"
    }
    "#;

    #[test]
    fn severity_mapping() {
        assert_eq!(parse_severity("CRITICAL"), Some(Severity::Critical));
        assert_eq!(parse_severity("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity("MEDIUM"), Some(Severity::Medium));
        assert_eq!(parse_severity("LOW"), Some(Severity::Low));
        assert_eq!(parse_severity("WARN"), Some(Severity::Low));
        assert_eq!(parse_severity("INFO"), Some(Severity::Info));
        assert_eq!(parse_severity("FATAL"), Some(Severity::Info));
        assert_eq!(parse_severity("OK"), None);
    }

    #[test]
    fn parse_sample_produces_findings() {
        let findings = parse_testssl_json(SAMPLE_JSON).unwrap();
        // sslv2 OK excluded, service INFO excluded, plus summary = 5
        assert_eq!(findings.len(), 6);
        assert!(
            findings
                .iter()
                .any(|f| f.title == "TLS issue: sslv3" && f.severity == Severity::High)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title == "TLS issue: heartbleed" && f.severity == Severity::Critical)
        );
        assert!(findings.iter().any(|f| f.title == "TLS/SSL scan summary"));
    }

    #[tokio::test]
    async fn missing_binary_is_skipped_when_configured() {
        let mut config = Config::load(None).unwrap();
        config.tools.testssl_path = "/definitely/does/not/exist/testssl.sh".into();
        config.tools.skip_missing_tools = true;

        let target = Target::parse("example.com").unwrap();
        let module = Testssl;
        let findings = module.run(&target, &config).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("unavailable"));
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn fake_testssl_binary_is_invoked() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-testssl.sh");
        {
            let mut f = std::fs::File::create(&script).unwrap();
            write!(
                f,
                r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --jsonfile-pretty) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -z "$out" ]; then exit 1; fi
cat > "$out" <<'EOF'
{{
  "scanResult": [
    {{ "id": "tls1_2", "severity": "OK", "finding": "offered" }},
    {{ "id": "tls1_1", "severity": "MEDIUM", "finding": "offered" }},
    {{ "id": "sweet32", "severity": "LOW", "finding": "Vulnerable", "cve": "CVE-2016-2183" }}
  ]
}}
EOF
"#
            )
            .unwrap();
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let mut config = Config::load(None).unwrap();
        config.tools.testssl_path = script;
        config.tools.skip_missing_tools = true;
        config.scanner.timeout_ms = 5000;

        let target = Target::parse("example.com").unwrap();
        let module = Testssl;
        let findings = module.run(&target, &config).await.unwrap();

        assert!(
            findings
                .iter()
                .any(|f| f.title == "TLS issue: tls1 1" && f.severity == Severity::Medium)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title == "TLS issue: sweet32" && f.severity == Severity::Low)
        );
        assert!(findings.iter().any(|f| f.title == "TLS/SSL scan summary"));
    }
}
