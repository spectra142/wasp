#![allow(clippy::collapsible_if)]

use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::cms_common::{self, CmsKind};
use crate::modules::Module;
use crate::target::Target;
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{debug, warn};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// CMS scanner that fingerprints WordPress, Drupal, and Joomla via HTTP
/// indicators and, when WordPress is found, invokes WPScan for deeper analysis.
pub struct Cms;

#[async_trait]
impl Module for Cms {
    fn name(&self) -> &'static str {
        "cms"
    }

    fn description(&self) -> &'static str {
        "CMS fingerprinting (WordPress/Drupal/Joomla) with WPScan integration"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let client = cms_common::build_client(config)?;
        let host = target.to_string();

        let mut schemes = Vec::new();
        if config.modules.cms.check_https {
            schemes.push("https");
        }
        if config.modules.cms.check_http {
            schemes.push("http");
        }
        if schemes.is_empty() {
            debug!("[cms] both HTTP and HTTPS checks are disabled; skipping");
            return Ok(findings);
        }

        let mut wordpress_url: Option<String> = None;

        for scheme in schemes {
            let base = format!("{}://{}/", scheme, host);
            debug!("[cms] fingerprinting {}", base);

            let hits = cms_common::fingerprint(&client, &base).await;
            if hits.is_empty() {
                continue;
            }

            for hit in &hits {
                if hit.kind == CmsKind::WordPress && wordpress_url.is_none() {
                    wordpress_url = Some(hit.url.clone());
                }
                findings.push(hit.to_finding("cms"));
            }
        }

        if let Some(url) = wordpress_url {
            match run_wpscan(&url, &config.tools.wpscan_path, config).await {
                Ok(mut wpscan_findings) => findings.append(&mut wpscan_findings),
                Err(e) if config.tools.skip_missing_tools => {
                    debug!("[cms] WPScan skipped: {}", e);
                    findings.push(
                        Finding::new(
                            "cms",
                            "WPScan unavailable",
                            Severity::Info,
                            "WordPress was detected but WPScan could not be executed",
                        )
                        .with_evidence(format!("Error: {}", e))
                        .with_remediation(
                            "Install WPScan or verify the configured wpscan_path in the config file.",
                        ),
                    );
                }
                Err(e) => return Err(e),
            }
        }

        Ok(findings)
    }
}

async fn run_wpscan(url: &str, path: &Path, config: &Config) -> Result<Vec<Finding>> {
    debug!(
        "[cms] running WPScan: {} --url {} --format json",
        path.display(),
        url
    );

    let output = match timeout(
        Duration::from_secs(config.tools.wpscan_timeout_secs),
        Command::new(path)
            .kill_on_drop(true)
            .arg("--url")
            .arg(url)
            .arg("--format")
            .arg("json")
            .output(),
    )
    .await
    {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::NotFound && config.tools.skip_missing_tools {
                debug!("[cms] WPScan binary not found at {}", path.display());
                return Ok(vec![Finding::new(
                    "cms",
                    "WPScan unavailable",
                    Severity::Info,
                    "WordPress was detected but WPScan could not be executed",
                )
                .with_evidence(format!("Error: {}", e))
                .with_remediation(
                    "Install WPScan or verify the configured wpscan_path in the config file.",
                )]);
            }
            return Err(e).with_context(|| format!("failed to run WPScan at {}", path.display()));
        }
        Err(_) => {
            warn!(
                "[cms] WPScan timed out after {:?}",
                Duration::from_secs(config.tools.wpscan_timeout_secs)
            );
            return Ok(vec![Finding::new(
                "cms",
                "WPScan timed out",
                Severity::Info,
                "WPScan did not complete within the configured timeout",
            )
            .with_evidence(format!(
                "Timeout: {:?}",
                Duration::from_secs(config.tools.wpscan_timeout_secs)
            ))
            .with_remediation(
                "Increase tools.wpscan_timeout_secs or run WPScan manually for deeper analysis.",
            )]);
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "[cms] WPScan exited with status {}: {}",
            output.status, stderr
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(vec![Finding::new(
            "cms",
            "WPScan produced no output",
            Severity::Info,
            "WPScan ran but returned no JSON output",
        )
        .with_evidence(format!("Exit status: {}", output.status))
        .with_remediation(
            "Verify WPScan is installed and the target is reachable.",
        )]);
    }

    Ok(parse_wpscan_json(&stdout, url))
}

fn parse_wpscan_json(json: &str, target_url: &str) -> Vec<Finding> {
    let value: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            warn!("[cms] failed to parse WPScan JSON: {}", e);
            return vec![Finding::new(
                "cms",
                "WPScan output is not valid JSON",
                Severity::Info,
                "WPScan returned output that could not be parsed as JSON",
            )
            .with_evidence(format!("Error: {}", e))
            .with_remediation("Check WPScan installation and command-line arguments.")];
        }
    };

    let mut findings = Vec::new();

    // WordPress core version vulnerabilities.
    if let Some(version) = value.get("version") {
        let number = version.get("number").and_then(|v| v.as_str());
        if let Some(vulns) = version.get("vulnerabilities").and_then(|v| v.as_array()) {
            add_vulns("WordPress core", number, vulns, &mut findings);
        }
    }

    // Top-level core vulnerabilities (older WPScan schema).
    if let Some(vulns) = value.get("vulnerabilities").and_then(|v| v.as_array()) {
        add_vulns("WordPress core", None, vulns, &mut findings);
    }

    // Active theme.
    if let Some(theme) = value.get("main_theme") {
        let slug = theme
            .get("slug")
            .and_then(|v| v.as_str())
            .unwrap_or("theme");
        let number = theme
            .get("version")
            .and_then(|v| v.get("number"))
            .and_then(|v| v.as_str());
        let vuln_array = theme
            .get("version")
            .and_then(|v| v.get("vulnerabilities"))
            .and_then(|v| v.as_array())
            .or_else(|| theme.get("vulnerabilities").and_then(|v| v.as_array()));
        if let Some(vulns) = vuln_array {
            add_vulns(
                &format!("WordPress theme: {}", slug),
                number,
                vulns,
                &mut findings,
            );
        }
    }

    // Plugins.
    if let Some(plugins) = value.get("plugins").and_then(|v| v.as_object()) {
        for (slug, plugin) in plugins {
            let number = plugin
                .get("version")
                .and_then(|v| v.get("number"))
                .and_then(|v| v.as_str());
            let vuln_array = plugin
                .get("version")
                .and_then(|v| v.get("vulnerabilities"))
                .and_then(|v| v.as_array())
                .or_else(|| plugin.get("vulnerabilities").and_then(|v| v.as_array()));
            if let Some(vulns) = vuln_array {
                add_vulns(
                    &format!("WordPress plugin: {}", slug),
                    number,
                    vulns,
                    &mut findings,
                );
            }
        }
    }

    // Interesting findings (exposed files, debug info, etc.).
    if let Some(items) = value.get("interesting_findings").and_then(|v| v.as_array()) {
        for item in items {
            let finding_type = item
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("interesting finding");
            let found_by = item
                .get("found_by")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let data = format_value(item.get("data"));
            let severity = interesting_finding_severity(finding_type, &data);

            findings.push(
                Finding::new(
                    "cms",
                    &format!("WPScan: {}", finding_type),
                    severity,
                    "WPScan reported an interesting finding",
                )
                .with_evidence(format!(
                    "Target: {} | Found by: {} | Data: {}",
                    target_url, found_by, data
                ))
                .with_remediation(
                    "Review the finding and restrict or remove exposed resources as appropriate.",
                ),
            );
        }
    }

    findings
}

fn add_vulns(component: &str, version: Option<&str>, vulns: &[Value], findings: &mut Vec<Finding>) {
    for vuln in vulns {
        let title = vuln
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown vulnerability");
        let cvss_score = vuln
            .get("cvss")
            .and_then(|v| v.get("score"))
            .and_then(|v| v.as_f64());
        let fixed_in = format_value(vuln.get("fixed_in"));
        let references = flatten_references(vuln.get("references"));

        let severity = cvss_score
            .map(severity_from_cvss)
            .unwrap_or(Severity::Medium);

        let mut description = format!("{} vulnerability: {}", component, title);
        if let Some(v) = version {
            description.push_str(&format!(" (version {})", v));
        }

        let mut finding = Finding::new(
            "cms",
            &format!("{} - {}", component, title),
            severity,
            &description,
        );

        if let Some(score) = cvss_score {
            finding = finding.with_evidence(format!("CVSS score: {}", score));
        }
        if !fixed_in.is_empty() && fixed_in != "null" {
            finding = finding.with_evidence(format!("Fixed in: {}", fixed_in));
        }
        if !references.is_empty() {
            finding = finding.with_evidence(format!("References: {}", references.join(", ")));
        }

        let remediation = if !fixed_in.is_empty() && fixed_in != "null" {
            format!("Update {} to version {} or later.", component, fixed_in)
        } else {
            "Review the vulnerability and apply the vendor patch or mitigation guidance."
                .to_string()
        };

        findings.push(finding.with_remediation(remediation));
    }
}

fn severity_from_cvss(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Medium
    }
}

fn interesting_finding_severity(finding_type: &str, data: &str) -> Severity {
    let text = format!("{} {}", finding_type, data).to_lowercase();
    if text.contains("backup")
        || text.contains("database")
        || text.contains("sql")
        || text.contains("dump")
        || text.contains("listing")
    {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn flatten_references(value: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(v) = value {
        flatten_value_strings(v, &mut out);
    }
    out
}

fn flatten_value_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => {
            for v in arr {
                flatten_value_strings(v, out);
            }
        }
        Value::Object(obj) => {
            for v in obj.values() {
                flatten_value_strings(v, out);
            }
        }
        _ => {}
    }
}

fn format_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_from_cvss_mapping() {
        assert_eq!(severity_from_cvss(9.5), Severity::Critical);
        assert_eq!(severity_from_cvss(8.0), Severity::High);
        assert_eq!(severity_from_cvss(5.5), Severity::Medium);
        assert_eq!(severity_from_cvss(2.0), Severity::Low);
        assert_eq!(severity_from_cvss(0.0), Severity::Medium);
    }

    #[test]
    fn parses_wpscan_vulnerabilities() {
        let json = r#"{
            "target_url": "http://example.com/",
            "version": {
                "number": "6.4.2",
                "vulnerabilities": [
                    {
                        "title": "Test Core Vuln",
                        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        "fixed_in": "6.4.3",
                        "references": {"url": ["https://example.com/cve"], "cve": "CVE-2024-0001"}
                    }
                ]
            },
            "plugins": {
                "contact-form-7": {
                    "version": {"number": "5.8.1"},
                    "vulnerabilities": [
                        {
                            "title": "Test Plugin Vuln",
                            "cvss": {"score": 4.2},
                            "fixed_in": "5.8.2",
                            "references": {"url": "https://example.com/plugin-cve"}
                        }
                    ]
                }
            },
            "main_theme": {
                "slug": "twentytwentyfour",
                "version": {"number": "1.0"},
                "vulnerabilities": [
                    {
                        "title": "Test Theme Vuln",
                        "fixed_in": "1.1",
                        "references": {}
                    }
                ]
            },
            "interesting_findings": [
                {
                    "type": "Directory listing",
                    "found_by": "Direct Access",
                    "data": {"path": "/wp-content/uploads/"}
                }
            ]
        }"#;

        let findings = parse_wpscan_json(json, "http://example.com/");
        assert!(!findings.is_empty());

        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles
            .iter()
            .any(|t| t.contains("WordPress core - Test Core Vuln")));
        assert!(titles
            .iter()
            .any(|t| t.contains("WordPress plugin: contact-form-7 - Test Plugin Vuln")));
        assert!(titles
            .iter()
            .any(|t| t.contains("WordPress theme: twentytwentyfour - Test Theme Vuln")));
        assert!(titles
            .iter()
            .any(|t| t.contains("WPScan: Directory listing")));

        let core = findings
            .iter()
            .find(|f| f.title.contains("WordPress core - Test Core Vuln"))
            .unwrap();
        assert_eq!(core.severity, Severity::High);
        assert!(core.evidence.iter().any(|e| e.contains("6.4.3")));

        let theme = findings
            .iter()
            .find(|f| {
                f.title
                    .contains("WordPress theme: twentytwentyfour - Test Theme Vuln")
            })
            .unwrap();
        assert_eq!(theme.severity, Severity::Medium);
    }
}
