use clap::Parser;
use std::path::{Path, PathBuf};

use crate::config::MODULE_NAMES;
use crate::finding::{Report, Severity};

#[derive(Parser, Debug)]
#[command(
    name = "wasp",
    version,
    about = "Web Attack Surface Profiler",
    long_about = "WASP is a modular security reconnaissance scanner. Only scan targets you own or have explicit permission to test."
)]
pub struct Args {
    /// Target domain, IP address, host:port, or URL (e.g. https://example.com:8443)
    #[arg(required_unless_present = "list_modules")]
    pub target: Option<String>,

    /// Output directory for reports
    #[arg(short, long, default_value = "./wasp-report")]
    pub output: PathBuf,

    /// Comma-separated list of modules to run
    /// (recon, portscan, web, secrets, tlsaudit, webvulns, cms, cmsenum, nmap, nuclei, testssl)
    #[arg(short, long, value_delimiter = ',', conflicts_with_all = ["full", "quick"])]
    pub modules: Option<Vec<String>>,

    /// Path to a custom TOML config file (merged over the built-in defaults)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Global concurrency limit (maximum simultaneous network connections)
    #[arg(short, long, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    pub rate: Option<u32>,

    /// Per-request network timeout in milliseconds
    #[arg(short = 't', long, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: Option<u64>,

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

    /// Disable the most intrusive modules (portscan, secrets, nmap, nuclei, cms, cmsenum)
    #[arg(long)]
    pub safe_mode: bool,

    /// Exit with status 2 if any finding is at or above this severity
    /// (info, low, medium, high, critical). Useful in CI pipelines.
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<Severity>,

    /// Disable coloured terminal output (also honours the NO_COLOR variable)
    #[arg(long)]
    pub no_color: bool,

    /// Print the available modules and exit
    #[arg(long)]
    pub list_modules: bool,

    /// Enable verbose logging (-v info, -vv debug)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl Args {
    /// Reject module names that do not exist, instead of silently ignoring
    /// typos like `-m tlsadit` and running nothing.
    pub fn validate_modules(&self) -> Result<(), String> {
        let Some(modules) = &self.modules else {
            return Ok(());
        };
        let unknown: Vec<&str> = modules
            .iter()
            .map(|m| m.trim())
            .filter(|m| !m.is_empty() && !MODULE_NAMES.contains(&m.to_lowercase().as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(format!(
                "unknown module(s): {}. Available modules: {}",
                unknown.join(", "),
                MODULE_NAMES.join(", ")
            ));
        }
        if modules.iter().all(|m| m.trim().is_empty()) {
            return Err("no modules selected".to_string());
        }
        Ok(())
    }
}

/// ANSI styling that collapses to empty strings when colour is disabled.
struct Palette {
    enabled: bool,
}

impl Palette {
    fn paint(&self, code: &'static str) -> &'static str {
        if self.enabled {
            code
        } else {
            ""
        }
    }
    fn reset(&self) -> &'static str {
        self.paint("\x1b[0m")
    }
    fn bold(&self) -> &'static str {
        self.paint("\x1b[1m")
    }
    fn green(&self) -> &'static str {
        self.paint("\x1b[32m")
    }
    fn gray(&self) -> &'static str {
        self.paint("\x1b[90m")
    }
    fn severity(&self, severity: Severity) -> &'static str {
        self.paint(match severity {
            Severity::Critical => "\x1b[1;31m",
            Severity::High => "\x1b[1;33m",
            Severity::Medium => "\x1b[33m",
            Severity::Low => "\x1b[36m",
            Severity::Info => "\x1b[90m",
        })
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

/// Render a short, coloured terminal summary of a completed scan.
pub fn format_summary(report: &Report, output_dir: &Path, top_n: usize) -> String {
    format_summary_with_color(report, output_dir, top_n, true)
}

/// Render the terminal summary, optionally without ANSI escape codes.
pub fn format_summary_with_color(
    report: &Report,
    output_dir: &Path,
    top_n: usize,
    color: bool,
) -> String {
    let p = Palette { enabled: color };
    let mut lines = Vec::new();

    let duration = report
        .finished_at
        .signed_duration_since(report.started_at)
        .max(chrono::Duration::zero());
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

    let rule = "═══════════════════════════════════════";
    lines.push(format!("{}{}{}", p.bold(), rule, p.reset()));
    lines.push(format!(
        "{} WASP Scan Complete{}  {}{}{}",
        p.bold(),
        p.reset(),
        p.bold(),
        report.target,
        p.reset()
    ));
    lines.push(format!("{}{}{}", p.bold(), rule, p.reset()));
    lines.push(String::new());
    lines.push(format!(
        "{}Duration: {}{}",
        p.bold(),
        duration_str,
        p.reset()
    ));
    if !report.modules.is_empty() {
        lines.push(format!(
            "{}Modules: {}{}",
            p.bold(),
            report.modules.join(", "),
            p.reset()
        ));
    }
    lines.push(format!(
        "{}Total findings: {}{}",
        p.bold(),
        report.findings.len(),
        p.reset()
    ));
    lines.push(String::new());

    lines.push(format!("{}Severity Summary{}", p.bold(), p.reset()));
    for severity in Severity::ALL_DESCENDING {
        lines.push(format!(
            "  {}{:<10}: {}{}",
            p.severity(severity),
            severity_label(severity),
            report.count(severity),
            p.reset()
        ));
    }

    lines.push(String::new());
    lines.push(format!("{}Top Findings{}", p.bold(), p.reset()));
    if report.findings.is_empty() {
        lines.push(format!("  {}No findings reported.{}", p.gray(), p.reset()));
    } else {
        for finding in report.findings.iter().take(top_n) {
            let tag = format!("[{}]", severity_code(finding.severity));
            lines.push(format!(
                "  {}{:<10}{} {:<12} {}",
                p.severity(finding.severity),
                tag,
                p.reset(),
                finding.module,
                finding.title
            ));
        }
    }

    lines.push(String::new());
    lines.push(format!(
        "{}Reports written to: {}{}{}",
        p.bold(),
        p.green(),
        output_dir.display(),
        p.reset()
    ));
    for name in [
        "report.json",
        "report.html",
        "report.csv",
        "report.md",
        "report.sarif",
    ] {
        lines.push(format!("  {}•{} {}", p.green(), p.reset(), name));
    }
    lines.push(String::new());
    lines.push(format!("{}{}{}", p.bold(), rule, p.reset()));

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
    fn summary_without_color_has_no_escape_codes() {
        let report = sample_report();
        let summary = format_summary_with_color(&report, &PathBuf::from("./out"), 5, false);
        assert!(!summary.contains('\x1b'));
        assert!(summary.contains("Critical  : 1"));
    }

    #[test]
    fn unknown_modules_are_rejected() {
        let args = Args::try_parse_from(["wasp", "example.com", "-m", "web,tlsadit"]).unwrap();
        let err = args.validate_modules().unwrap_err();
        assert!(err.contains("tlsadit"));
        let args = Args::try_parse_from(["wasp", "example.com", "-m", "web,TLSAudit"]).unwrap();
        assert!(args.validate_modules().is_ok());
    }

    #[test]
    fn fail_on_parses_severity() {
        let args = Args::try_parse_from(["wasp", "example.com", "--fail-on", "high"]).unwrap();
        assert_eq!(args.fail_on, Some(Severity::High));
        assert!(Args::try_parse_from(["wasp", "example.com", "--fail-on", "nope"]).is_err());
    }

    #[test]
    fn list_modules_does_not_need_target() {
        let args = Args::try_parse_from(["wasp", "--list-modules"]).unwrap();
        assert!(args.list_modules);
        assert!(Args::try_parse_from(["wasp"]).is_err());
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
