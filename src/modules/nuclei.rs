use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{debug, warn};
use serde::Deserialize;
use std::io;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct Nuclei;

#[async_trait]
impl Module for Nuclei {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    fn description(&self) -> &'static str {
        "Vulnerability scan using ProjectDiscovery Nuclei JSON output"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut schemes = Vec::new();

        if config.modules.nuclei.check_http {
            schemes.push("http");
        }
        if config.modules.nuclei.check_https {
            schemes.push("https");
        }

        if schemes.is_empty() {
            debug!("nuclei skipped: neither http nor https checks are enabled");
            return Ok(findings);
        }

        let binary = &config.tools.nuclei_path;
        if !nuclei_available(binary, config).await {
            if config.tools.skip_missing_tools {
                warn!("nuclei binary not found at {:?}; skipping", binary);
                return Ok(vec![tool_unavailable_finding(binary)]);
            }
            return Err(anyhow::anyhow!("nuclei binary not found at {:?}", binary));
        }

        let host = target.to_string();

        for scheme in schemes {
            let url = format!("{}://{}", scheme, host);
            match run_nuclei_scan(&url, config).await {
                Ok(scan_findings) => findings.extend(scan_findings),
                Err(e) => {
                    debug!("nuclei scan for {} failed: {}", url, e);
                }
            }
        }

        Ok(findings)
    }
}

async fn nuclei_available(binary: &std::path::Path, config: &Config) -> bool {
    if crate::modules::external::resolve_tool(binary).is_none() {
        return false;
    }
    let dur = Duration::from_secs(config.tools.nuclei_timeout_secs.min(30));
    match timeout(
        dur,
        Command::new(binary)
            .arg("-version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) if e.kind() == io::ErrorKind::NotFound => false,
        Ok(Err(e)) => {
            debug!("nuclei --version failed: {}", e);
            true
        }
        Err(_) => {
            debug!("nuclei --version timed out");
            true
        }
    }
}

async fn run_nuclei_scan(url: &str, config: &Config) -> Result<Vec<Finding>> {
    let binary = &config.tools.nuclei_path;
    let mut cmd = Command::new(binary);
    // -jsonl: one JSON object per line; -silent/-nc: findings only, no colour;
    // -duc: never block on the template/engine update check.
    cmd.arg("-u")
        .arg(url)
        .args(["-jsonl", "-silent", "-nc", "-duc"])
        .kill_on_drop(true);

    debug!(
        "running nuclei scan: {:?} -u {} -jsonl -silent -nc -duc",
        binary, url
    );

    let output = match timeout(
        Duration::from_secs(config.tools.nuclei_timeout_secs),
        cmd.output(),
    )
    .await
    {
        Ok(Ok(out)) => out,
        Ok(Err(e)) if e.kind() == io::ErrorKind::NotFound => {
            if config.tools.skip_missing_tools {
                warn!("nuclei binary not found at {:?}; skipping", binary);
                return Ok(vec![tool_unavailable_finding(binary)]);
            }
            return Err(anyhow::anyhow!(
                "nuclei binary not found at {:?}: {}",
                binary,
                e
            ));
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!(
                "failed to execute nuclei for {}: {}",
                url,
                e
            ));
        }
        Err(_) => {
            let actual = Duration::from_secs(config.tools.nuclei_timeout_secs);
            warn!("nuclei scan for {} timed out after {:?}", url, actual);
            return Ok(Vec::new());
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.trim().is_empty() {
            debug!("nuclei exited with status {:?}", output.status);
        } else {
            debug!("nuclei exited with status {:?}: {}", output.status, stderr);
        }
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_nuclei_json_line(line) {
            Ok(finding) => findings.push(finding),
            Err(e) => debug!("failed to parse nuclei JSON line: {} (line: {})", e, line),
        }
    }

    Ok(findings)
}

fn tool_unavailable_finding(binary: &std::path::Path) -> Finding {
    Finding::new(
        "nuclei",
        "Nuclei scanner unavailable",
        Severity::Info,
        "The configured nuclei binary was not found on this system",
    )
    .with_evidence(format!("Configured path: {:?}", binary))
    .with_remediation("Install nuclei or update tools.nuclei_path in the config.")
}

#[derive(Debug, Deserialize)]
struct NucleiJsonLine {
    #[serde(rename = "template-id")]
    template_id: String,
    host: String,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
    #[serde(default, rename = "extracted-results")]
    extracted_results: Vec<String>,
    info: NucleiInfo,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: String,
    severity: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    remediation: Option<String>,
}

fn parse_nuclei_json_line(line: &str) -> Result<Finding> {
    let parsed: NucleiJsonLine = serde_json::from_str(line)
        .with_context(|| format!("invalid nuclei JSON line: {}", line))?;

    let severity = map_nuclei_severity(&parsed.info.severity);
    let description = parsed
        .info
        .description
        .as_deref()
        .unwrap_or(&parsed.info.name)
        .to_string();

    let mut evidence = vec![
        format!("Host: {}", parsed.host),
        format!("Template: {}", parsed.template_id),
    ];

    if let Some(matched) = parsed.matched_at {
        evidence.push(format!("Matched at: {}", matched));
    }

    if !parsed.extracted_results.is_empty() {
        evidence.push(format!(
            "Extracted results: {}",
            parsed.extracted_results.join(", ")
        ));
    }

    let remediation = parsed.info.remediation.unwrap_or_default();

    let mut finding = Finding::new("nuclei", &parsed.info.name, severity, &description)
        .with_remediation(remediation);

    finding.evidence = evidence;
    Ok(finding)
}

fn map_nuclei_severity(severity: &str) -> Severity {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_critical_finding() {
        let line = r#"{"template-id":"CVE-2024-1234","host":"https://example.com","matched-at":"https://example.com/admin","extracted-results":["admin"],"info":{"name":"Remote Code Execution","severity":"critical","description":"RCE via unsafe deserialization","remediation":"Apply the vendor patch"}}"#;
        let finding = parse_nuclei_json_line(line).unwrap();
        assert_eq!(finding.module, "nuclei");
        assert_eq!(finding.title, "Remote Code Execution");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.description, "RCE via unsafe deserialization");
        assert!(finding
            .evidence
            .iter()
            .any(|e| e.contains("https://example.com")));
        assert!(finding.evidence.iter().any(|e| e.contains("CVE-2024-1234")));
        assert!(finding.evidence.iter().any(|e| e.contains("/admin")));
        assert!(finding.evidence.iter().any(|e| e.contains("admin")));
        assert_eq!(finding.remediation, "Apply the vendor patch");
    }

    #[test]
    fn parse_info_finding_with_defaults() {
        let line = r#"{"template-id":"tech-detect","host":"http://example.com","info":{"name":"Technology Detected","severity":"info"}}"#;
        let finding = parse_nuclei_json_line(line).unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.description, "Technology Detected");
        assert!(finding.remediation.is_empty());
    }

    #[test]
    fn parse_unknown_severity_defaults_to_info() {
        let line = r#"{"template-id":"custom","host":"http://example.com","info":{"name":"Custom Finding","severity":"unknown"}}"#;
        let finding = parse_nuclei_json_line(line).unwrap();
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn parse_invalid_json_fails() {
        let line = "not json";
        assert!(parse_nuclei_json_line(line).is_err());
    }

    #[test]
    fn severity_mapping_is_case_insensitive() {
        assert_eq!(map_nuclei_severity("HIGH"), Severity::High);
        assert_eq!(map_nuclei_severity("Medium"), Severity::Medium);
        assert_eq!(map_nuclei_severity("LOW"), Severity::Low);
        assert_eq!(map_nuclei_severity("CRITICAL"), Severity::Critical);
    }
}
