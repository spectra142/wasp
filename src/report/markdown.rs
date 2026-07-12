use crate::finding::{Finding, Report, Severity};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn from_report(report: &Report) -> Self {
        let mut counts = Self::default();
        for finding in &report.findings {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

pub fn write(report: &Report, path: &Path) -> Result<()> {
    let mut md = String::new();

    md.push_str("# WASP Report\n\n");
    md.push_str(&format!("- **Target:** {}\n", report.target));
    md.push_str(&format!(
        "- **Started:** {}\n",
        report.started_at.to_rfc3339()
    ));
    md.push_str(&format!(
        "- **Finished:** {}\n",
        report.finished_at.to_rfc3339()
    ));
    md.push_str(&format!(
        "- **Total findings:** {}\n\n",
        report.findings.len()
    ));

    let counts = SeverityCounts::from_report(report);
    md.push_str("## Summary by severity\n\n");
    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|------:|\n");
    md.push_str(&format!("| Critical | {} |\n", counts.critical));
    md.push_str(&format!("| High | {} |\n", counts.high));
    md.push_str(&format!("| Medium | {} |\n", counts.medium));
    md.push_str(&format!("| Low | {} |\n", counts.low));
    md.push_str(&format!("| Info | {} |\n\n", counts.info));

    md.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        md.push_str("No findings.\n");
    } else {
        for finding in &report.findings {
            md.push_str(&render_finding(finding));
        }
    }

    fs::write(path, md)
        .with_context(|| format!("failed to write Markdown report to {:?}", path))?;
    Ok(())
}

fn render_finding(finding: &Finding) -> String {
    let mut s = String::new();
    s.push_str(&format!("### {} ({})\n\n", finding.title, finding.severity));
    s.push_str(&format!("- **Module:** {}\n", finding.module));
    s.push_str(&format!("- **Severity:** {}\n", finding.severity));
    s.push_str(&format!(
        "- **Timestamp:** {}\n\n",
        finding.timestamp.to_rfc3339()
    ));
    s.push_str(&format!("{}\n\n", finding.description));
    if !finding.evidence.is_empty() {
        s.push_str("#### Evidence\n\n");
        for ev in &finding.evidence {
            s.push_str(&format!("```\n{}\n```\n\n", ev));
        }
    }
    if !finding.remediation.is_empty() {
        s.push_str(&format!("**Remediation:** {}\n\n", finding.remediation));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use tempfile::TempDir;

    fn sample_report() -> Report {
        let mut report = Report::new("example.com:443");
        report.add_findings(vec![Finding::new(
            "web",
            "Missing HSTS header",
            Severity::High,
            "The server does not send an HSTS header.",
        )
        .with_evidence("Strict-Transport-Security: absent")
        .with_remediation("Enable HSTS.")]);
        report.finalize();
        report
    }

    #[test]
    fn markdown_report_contains_key_sections() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.md");
        write(&sample_report(), &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# WASP Report"));
        assert!(content.contains("example.com:443"));
        assert!(content.contains("Missing HSTS header"));
        assert!(content.contains("## Summary by severity"));
        assert!(content.contains("## Findings"));
        assert!(content.contains("Enable HSTS."));
        assert!(content.contains("Critical"));
    }

    #[test]
    fn empty_report_shows_no_findings() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.md");
        let report = Report::new("example.com");
        write(&report, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("No findings."));
    }
}
