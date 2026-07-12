use clap::Parser;
use std::path::{Path, PathBuf};

use crate::finding::{Report, Severity};

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_GRAY: &str = "\x1b[90m";

#[derive(Parser, Debug)]
#[command(
    name = "wasp",
    about = "Web Attack Surface Profiler",
    long_about = "WASP is a modular security reconnaissance scanner. Only scan targets you own or have explicit permission to test."
)]
pub struct Args {
    /// Target domain or IP address
    pub target: String,

    /// Output directory for reports
    #[arg(short, long, default_value = "./wasp-report")]
    pub output: PathBuf,

    /// Comma-separated list of modules to run
    /// (recon, portscan, web, secrets, tlsaudit, webvulns, cms, cmsenum, nmap, nuclei, testssl)
    #[arg(short, long, value_delimiter = ',', conflicts_with_all = ["full", "quick"])]
    pub modules: Option<Vec<String>>,

    /// Path to a custom TOML config file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Maximum concurrent requests/connections
    #[arg(short, long)]
    pub rate: Option<usize>,

    /// Run all modules, including external adapters
    #[arg(long, conflicts_with_all = ["modules", "quick"])]
    pub full: bool,

    /// Run only fast built-in modules
    #[arg(long, conflicts_with_all = ["modules", "full"])]
    pub quick: bool,

    /// Disable TLS certificate verification for HTTPS requests.
    /// Useful for self-signed/internal targets; dangerous on untrusted networks.
    #[arg(long)]
    pub insecure: bool,

    /// Disable active or intrusive checks
    #[arg(long)]
    pub safe_mode: bool,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;31m",
        Severity::High => "\x1b[1;33m",
        Severity::Medium => "\x1b[33m",
        Severity::Low => "\x1b[36m",
        Severity::Info => "\x1b[90m",
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn severity_code(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Render a short, colored terminal summary of a completed scan.
pub fn format_summary(report: &Report, output_dir: &Path, top_n: usize) -> String {
    let mut lines = Vec::new();

    let duration = report.finished_at.signed_duration_since(report.started_at);
    let duration_str = if duration.num_seconds() < 60 {
        format!(
            "{}.{:03}s",
            duration.num_seconds(),
            duration.num_milliseconds() % 1000
        )
    } else {
        format!(
            "{}m {:02}s",
            duration.num_minutes(),
            duration.num_seconds() % 60
        )
    };

    lines.push(format!(
        "{}═══════════════════════════════════════{}",
        ANSI_BOLD, ANSI_RESET
    ));
    lines.push(format!(
        "{} WASP Scan Complete{}  {}{}{}",
        ANSI_BOLD, ANSI_RESET, ANSI_BOLD, report.target, ANSI_RESET
    ));
    lines.push(format!(
        "{}═══════════════════════════════════════{}",
        ANSI_BOLD, ANSI_RESET
    ));
    lines.push(String::new());
    lines.push(format!(
        "{}Duration: {}{}",
        ANSI_BOLD, duration_str, ANSI_RESET
    ));
    lines.push(format!(
        "{}Total findings: {}{}",
        ANSI_BOLD,
        report.findings.len(),
        ANSI_RESET
    ));
    lines.push(String::new());

    lines.push(format!("{}Severity Summary{}", ANSI_BOLD, ANSI_RESET));
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .count();
        let color = severity_color(severity);
        let label = severity_label(severity);
        lines.push(format!("  {}{:<10}: {}{}", color, label, count, ANSI_RESET));
    }

    lines.push(String::new());
    lines.push(format!("{}Top Findings{}", ANSI_BOLD, ANSI_RESET));
    if report.findings.is_empty() {
        lines.push(format!(
            "  {}No findings reported.{}",
            ANSI_GRAY, ANSI_RESET
        ));
    } else {
        for finding in report.findings.iter().take(top_n) {
            let color = severity_color(finding.severity);
            let code = severity_code(finding.severity);
            let tag = format!("[{}]", code);
            lines.push(format!(
                "  {}{:<10}{} {:<12} {}",
                color, tag, ANSI_RESET, finding.module, finding.title
            ));
        }
    }

    lines.push(String::new());
    lines.push(format!(
        "{}Reports written to: {}{}{}",
        ANSI_BOLD,
        ANSI_GREEN,
        output_dir.display(),
        ANSI_RESET
    ));
    for name in [
        "report.json",
        "report.html",
        "report.csv",
        "report.md",
        "report.sarif",
    ] {
        lines.push(format!("  {}•{} {}", ANSI_GREEN, ANSI_RESET, name));
    }
    lines.push(String::new());
    lines.push(format!(
        "{}═══════════════════════════════════════{}",
        ANSI_BOLD, ANSI_RESET
    ));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Report};

    fn sample_report() -> Report {
        let mut report = Report::new("example.com");
        report.add_findings(vec![
            Finding::new(
                "web",
                "Missing HSTS",
                Severity::High,
                "No HSTS header present.",
            ),
            Finding::new(
                "web",
                "Missing CSP",
                Severity::Medium,
                "No CSP header present.",
            ),
            Finding::new(
                "tlsaudit",
                "TLS 1.0/1.1 enabled",
                Severity::Critical,
                "Deprecated protocol versions are accepted.",
            ),
            Finding::new(
                "recon",
                "MX record found",
                Severity::Info,
                "Mail exchanger discovered.",
            ),
        ]);
        report.finalize();
        report
    }

    #[test]
    fn summary_includes_severity_counts() {
        let report = sample_report();
        let summary = format_summary(&report, &PathBuf::from("./wasp-report"), 5);

        assert!(summary.contains("Total findings: 4"));
        assert!(summary.contains("Critical  : 1"));
        assert!(summary.contains("High      : 1"));
        assert!(summary.contains("Medium    : 1"));
        assert!(summary.contains("Info      : 1"));
    }

    #[test]
    fn summary_lists_top_findings_sorted_by_severity() {
        let report = sample_report();
        let summary = format_summary(&report, &PathBuf::from("./wasp-report"), 5);

        assert!(summary.contains("[CRITICAL]"));
        assert!(summary.contains("TLS 1.0/1.1 enabled"));
        assert!(summary.contains("[HIGH]"));
        assert!(summary.contains("Missing HSTS"));
    }

    #[test]
    fn summary_limits_top_findings() {
        let report = sample_report();
        let summary = format_summary(&report, &PathBuf::from("./out"), 1);

        assert!(summary.contains("[CRITICAL]"));
        assert!(!summary.contains("[HIGH]"));
    }

    #[test]
    fn summary_shows_report_paths() {
        let report = sample_report();
        let summary = format_summary(&report, &PathBuf::from("./wasp-report"), 5);

        assert!(summary.contains("Reports written to:"));
        assert!(summary.contains("./wasp-report"));
        assert!(summary.contains("report.json"));
        assert!(summary.contains("report.html"));
        assert!(summary.contains("report.csv"));
        assert!(summary.contains("report.md"));
        assert!(summary.contains("report.sarif"));
    }

    #[test]
    fn summary_handles_empty_report() {
        let report = Report::new("example.com");
        let summary = format_summary(&report, &PathBuf::from("./out"), 5);

        assert!(summary.contains("No findings reported"));
        assert!(summary.contains("Total findings: 0"));
    }

    #[test]
    fn args_parse_full_and_quick_flags() {
        let args = Args::try_parse_from(["wasp", "example.com", "--full"]).unwrap();
        assert!(args.full);
        assert!(!args.quick);

        let args = Args::try_parse_from(["wasp", "example.com", "--quick"]).unwrap();
        assert!(args.quick);
        assert!(!args.full);
    }

    #[test]
    fn args_full_conflicts_with_modules_and_quick() {
        assert!(Args::try_parse_from(["wasp", "example.com", "--full", "-m", "recon"]).is_err());
        assert!(Args::try_parse_from(["wasp", "example.com", "--full", "--quick"]).is_err());
    }

    #[test]
    fn args_quick_conflicts_with_modules() {
        assert!(Args::try_parse_from(["wasp", "example.com", "--quick", "-m", "web"]).is_err());
    }
}
