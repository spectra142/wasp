use crate::finding::Report;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub mod csv;
pub mod html;
pub mod json;
pub mod markdown;
pub mod sarif;

pub fn write_reports(report: &Report, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {:?}", output_dir))?;

    json::write(report, &output_dir.join("report.json"))?;
    html::write(report, &output_dir.join("report.html"))?;
    csv::write(report, &output_dir.join("report.csv"))?;
    markdown::write(report, &output_dir.join("report.md"))?;
    sarif::write(report, &output_dir.join("report.sarif"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use tempfile::TempDir;

    #[test]
    fn write_reports_creates_all_outputs() {
        let dir = TempDir::new().unwrap();
        let mut report = Report::new("example.com:443");
        report.add_findings(vec![Finding::new(
            "web",
            "Missing HSTS",
            Severity::High,
            "No HSTS header present.",
        )]);
        report.finalize();

        write_reports(&report, dir.path()).unwrap();

        for name in [
            "report.json",
            "report.html",
            "report.csv",
            "report.md",
            "report.sarif",
        ] {
            let path = dir.path().join(name);
            assert!(path.exists(), "expected output file {:?} to exist", path);
            assert!(
                std::fs::metadata(&path).unwrap().len() > 0,
                "expected {:?} to be non-empty",
                path
            );
        }
    }
}
