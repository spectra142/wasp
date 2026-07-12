use crate::finding::{Finding, Report, Severity};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json;
use std::fs;
use std::path::Path;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

#[derive(Debug, Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
struct Driver {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "informationUri")]
    information_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    message: Message,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    locations: Vec<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

#[derive(Debug, Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
}

#[derive(Debug, Serialize)]
struct ArtifactLocation {
    uri: String,
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

fn information_uri() -> Option<String> {
    let uri = env!("CARGO_PKG_REPOSITORY");
    if uri.is_empty() {
        None
    } else {
        Some(uri.to_string())
    }
}

fn finding_to_result(finding: &Finding, target: &str) -> SarifResult {
    SarifResult {
        rule_id: finding.module.clone(),
        message: Message {
            text: format!("{}: {}", finding.title, finding.description),
        },
        level: Some(severity_to_sarif_level(finding.severity).to_string()),
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: target.to_string(),
                },
            },
        }],
        properties: Some(serde_json::json!({
            "severity": finding.severity.to_string(),
            "title": finding.title,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "timestamp": finding.timestamp.to_rfc3339(),
        })),
    }
}

pub fn write(report: &Report, path: &Path) -> Result<()> {
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|f| finding_to_result(f, &report.target))
        .collect();

    let sarif = SarifLog {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "WASP".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    information_uri: information_uri(),
                },
            },
            results,
        }],
    };

    let json = serde_json::to_string_pretty(&sarif).context("failed to serialize SARIF report")?;
    fs::write(path, json).with_context(|| format!("failed to write SARIF report to {:?}", path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tempfile::TempDir;

    fn sample_report() -> Report {
        let mut report = Report::new("example.com:443");
        report.add_findings(vec![
            Finding::new(
                "web",
                "Missing HSTS header",
                Severity::High,
                "The server does not send an HSTS header.",
            )
            .with_evidence("Strict-Transport-Security: absent")
            .with_remediation("Enable HSTS."),
        ]);
        report.finalize();
        report
    }

    #[test]
    fn sarif_report_is_valid_json_with_required_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.sarif");
        write(&sample_report(), &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let value: Value = serde_json::from_str(&content).unwrap();

        assert_eq!(value["version"], SARIF_VERSION);
        assert_eq!(value["$schema"], SARIF_SCHEMA);

        let runs = value["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);

        let driver = &runs[0]["tool"]["driver"];
        assert_eq!(driver["name"], "WASP");
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));

        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "web");
        assert_eq!(results[0]["level"], "error");
        assert!(
            results[0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("Missing HSTS header")
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "example.com:443"
        );
        assert_eq!(results[0]["properties"]["severity"], "high");
    }

    #[test]
    fn severity_maps_to_expected_sarif_levels() {
        assert_eq!(severity_to_sarif_level(Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(Severity::High), "error");
        assert_eq!(severity_to_sarif_level(Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(Severity::Info), "none");
    }

    #[test]
    fn empty_report_has_empty_results() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.sarif");
        let report = Report::new("example.com");
        write(&report, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let value: Value = serde_json::from_str(&content).unwrap();
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }
}
