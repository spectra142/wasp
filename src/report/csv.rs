use crate::finding::Report;
use anyhow::{Context, Result};
use std::path::Path;

const CSV_HEADER: &[&str] = &[
    "target",
    "module",
    "title",
    "severity",
    "description",
    "evidence",
    "remediation",
    "timestamp",
];

pub fn write(report: &Report, path: &Path) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to create CSV writer for {:?}", path))?;

    writer
        .write_record(CSV_HEADER)
        .context("failed to write CSV header")?;

    for finding in &report.findings {
        writer
            .write_record([
                &report.target,
                &finding.module,
                &finding.title,
                &finding.severity.to_string(),
                &finding.description,
                &finding.evidence.join("\n"),
                &finding.remediation,
                &finding.timestamp.to_rfc3339(),
            ])
            .context("failed to write CSV row")?;
    }

    writer.flush().context("failed to flush CSV writer")?;
    Ok(())
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
    fn csv_report_has_header_and_rows() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.csv");
        write(&sample_report(), &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with(
            "target,module,title,severity,description,evidence,remediation,timestamp\n"
        ));
        assert!(content.contains("example.com:443"));
        assert!(content.contains("Missing HSTS header"));
        assert!(content.contains("high"));
        assert!(content.contains("Strict-Transport-Security: absent"));
        assert!(content.contains("Enable HSTS."));
    }

    #[test]
    fn empty_report_writes_header_only() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("report.csv");
        let report = Report::new("example.com");
        write(&report, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], CSV_HEADER.join(","));
    }
}
