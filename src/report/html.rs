use crate::finding::{Finding, Report, Severity};
use anyhow::{Context, Result};
use askama::Template;
use std::fs;
use std::path::Path;

#[derive(Debug)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn from_report(report: &Report) -> Self {
        let mut counts = Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
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

#[derive(Template)]
#[template(
    source = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WASP Report — {{ target }}</title>
    <style>
        :root { color-scheme: light dark; }
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem; background: #0f172a; color: #e2e8f0; }
        h1, h2 { color: #f8fafc; }
        .meta { color: #94a3b8; margin-bottom: 1.5rem; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: #1e293b; border-radius: 0.5rem; padding: 1rem; text-align: center; border-left: 4px solid #64748b; }
        .card.critical { border-color: #ef4444; }
        .card.high { border-color: #f97316; }
        .card.medium { border-color: #eab308; }
        .card.low { border-color: #3b82f6; }
        .card.info { border-color: #64748b; }
        .count { font-size: 2rem; font-weight: 700; display: block; }
        .label { font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 0.5rem; overflow: hidden; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        tr:last-child td { border-bottom: none; }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge.critical { background: #7f1d1d; color: #fecaca; }
        .badge.high { background: #7c2d12; color: #ffedd5; }
        .badge.medium { background: #713f12; color: #fef08a; }
        .badge.low { background: #1e3a8a; color: #bfdbfe; }
        .badge.info { background: #334155; color: #e2e8f0; }
        .evidence { background: #0f172a; padding: 0.75rem; border-radius: 0.25rem; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.8rem; white-space: pre-wrap; margin: 0.5rem 0; }
        .remediation { color: #86efac; }
    </style>
</head>
<body>
    <h1>WASP Report</h1>
    <div class="meta">
        Target: <strong>{{ target }}</strong><br>
        Started: {{ started_at }}<br>
        Finished: {{ finished_at }}<br>
        Total findings: {{ findings.len() }}
    </div>

    <div class="summary">
        <div class="card critical"><span class="count">{{ counts.critical }}</span><span class="label">critical</span></div>
        <div class="card high"><span class="count">{{ counts.high }}</span><span class="label">high</span></div>
        <div class="card medium"><span class="count">{{ counts.medium }}</span><span class="label">medium</span></div>
        <div class="card low"><span class="count">{{ counts.low }}</span><span class="label">low</span></div>
        <div class="card info"><span class="count">{{ counts.info }}</span><span class="label">info</span></div>
    </div>

    <h2>Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Module</th>
                <th>Title</th>
                <th>Description</th>
                <th>Evidence</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
            {% for finding in findings %}
            <tr>
                <td><span class="badge {{ finding.severity }}">{{ finding.severity }}</span></td>
                <td>{{ finding.module }}</td>
                <td>{{ finding.title }}</td>
                <td>{{ finding.description }}</td>
                <td>
                    {% for ev in finding.evidence %}
                    <div class="evidence">{{ ev }}</div>
                    {% endfor %}
                </td>
                <td class="remediation">{{ finding.remediation }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"#,
    ext = "html"
)]
struct HtmlReport {
    target: String,
    started_at: String,
    finished_at: String,
    findings: Vec<Finding>,
    counts: SeverityCounts,
}

pub fn write(report: &Report, path: &Path) -> Result<()> {
    let counts = SeverityCounts::from_report(report);

    let ctx = HtmlReport {
        target: report.target.clone(),
        started_at: report.started_at.to_rfc3339(),
        finished_at: report.finished_at.to_rfc3339(),
        findings: report.findings.clone(),
        counts,
    };

    let rendered = ctx.render().context("failed to render HTML report")?;
    fs::write(path, rendered)
        .with_context(|| format!("failed to write HTML report to {:?}", path))?;
    Ok(())
}
