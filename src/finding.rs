use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// All severities from most to least severe.
    pub const ALL_DESCENDING: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "moderate" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity '{}' (expected info, low, medium, high or critical)",
                other
            )),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub module: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<String>,
    pub remediation: String,
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    pub fn new(module: &str, title: &str, severity: Severity, description: &str) -> Self {
        Self {
            module: module.to_string(),
            title: title.to_string(),
            severity,
            description: description.to_string(),
            evidence: Vec::new(),
            remediation: String::new(),
            timestamp: Utc::now(),
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }
}

/// Mask a secret so reports prove a credential was exposed without becoming
/// a second copy of it. Credentials embedded in URLs keep their scheme, user
/// and host; other values keep at most four characters at each end.
pub fn redact_secret(secret: &str) -> String {
    if let Some(scheme_end) = secret.find("://") {
        let rest = &secret[scheme_end + 3..];
        if let Some(at) = rest.rfind('@') {
            let userinfo = &rest[..at];
            if let Some(colon) = userinfo.find(':') {
                return format!(
                    "{}{}:****{}",
                    &secret[..scheme_end + 3],
                    &userinfo[..colon],
                    &rest[at..]
                );
            }
        }
        return secret.to_string();
    }

    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 12 {
        return "*".repeat(chars.len().max(4));
    }
    let keep = 4;
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{}{}{}", head, "*".repeat(8), tail)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// WASP version that produced the report.
    #[serde(default)]
    pub tool_version: String,
    pub target: String,
    /// Modules that ran during the scan.
    #[serde(default)]
    pub modules: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            target: target.into(),
            modules: Vec::new(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            findings: Vec::new(),
        }
    }

    pub fn add_findings(&mut self, mut findings: Vec<Finding>) {
        self.findings.append(&mut findings);
    }

    pub fn finalize(&mut self) {
        self.finished_at = Utc::now();
        // Stable sort: most severe first, then grouped by module and title so
        // report ordering is deterministic across runs.
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.module.cmp(&b.module))
                .then_with(|| a.title.cmp(&b.title))
        });
    }

    /// Number of findings with exactly the given severity.
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Highest severity present in the report, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Remove near-duplicate findings, keeping the highest-severity instance of
    /// each logical issue. This reduces noise when multiple modules flag the same
    /// exposed file or configuration weakness.
    pub fn deduplicate(&mut self) {
        self.findings = deduplicate_findings(std::mem::take(&mut self.findings));
    }
}

/// Deduplicate findings by grouping on (normalized URL, finding category).
/// The highest-severity finding in each group is retained.
pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut sorted = findings;
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));

    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut result = Vec::with_capacity(sorted.len());

    for finding in sorted {
        let url = extract_url(&finding).unwrap_or_default();
        let category = category_for(&finding);
        let url = normalize_url(&url, &category);
        // Only categories that genuinely overlap between modules are merged
        // across modules; otherwise two modules that happen to share a title
        // (e.g. "Open port 22/tcp") keep their own findings.
        let scope = if category == "exposed_path" {
            String::new()
        } else {
            finding.module.clone()
        };
        let key = (scope, url, category);
        if seen.insert(key) {
            result.push(finding);
        }
    }

    result
}

fn extract_url(finding: &Finding) -> Option<String> {
    let haystack = format!("{}\n{}", finding.description, finding.evidence.join("\n"));

    // Prefer an explicit "URL:" label if present.
    if let Some(cap) = URL_LABEL_RE.captures(&haystack) {
        return cap.get(1).map(|m| m.as_str().to_string());
    }

    // Fall back to the first absolute URL in the description or evidence.
    URL_RE
        .find(&haystack)
        .map(|m| m.as_str().trim_end_matches(['.', ',']).to_string())
}

fn normalize_url(url: &str, category: &str) -> String {
    // For header and cookie findings, the same issue reported over HTTP and HTTPS
    // should be treated as one logical finding.
    if category.ends_with("header") || category.starts_with("Cookie missing") {
        url.replacen("http://", "http(s)://", 1)
            .replacen("https://", "http(s)://", 1)
    } else {
        url.to_string()
    }
}

fn category_for(finding: &Finding) -> String {
    let title = &finding.title;
    if title.starts_with("Possible ") && title.ends_with(" leaked") {
        // Keep one finding per leaked secret pattern per URL.
        title.clone()
    } else if title.starts_with("Exposed path found:")
        || title.starts_with("Sensitive path exposed:")
    {
        // Collapse overlapping secrets/webvulns "exposed path" reports.
        "exposed_path".to_string()
    } else {
        // Everything else is keyed by its title.
        title.clone()
    }
}

static URL_LABEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)URL:\s*(https?://\S+)").unwrap());

static URL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^\s<>\"'\)]+"#).unwrap());

#[cfg(test)]
mod dedup_tests {
    use super::*;

    #[test]
    fn redacts_tokens_and_url_passwords() {
        assert_eq!(
            redact_secret("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            "ghp_********6789"
        );
        assert_eq!(
            redact_secret("postgres://admin:s3cret@db.example.com/app"),
            "postgres://admin:****@db.example.com/app"
        );
        assert_eq!(redact_secret("short"), "*****");
    }

    #[test]
    fn severity_parses_from_str() {
        assert_eq!("HIGH".parse::<Severity>().unwrap(), Severity::High);
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    fn keeps_distinct_findings() {
        let findings = vec![
            Finding::new("web", "Missing HSTS header", Severity::High, "No HSTS"),
            Finding::new("web", "Missing CSP header", Severity::Medium, "No CSP"),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn drops_exact_duplicate() {
        let findings = vec![
            Finding::new("web", "Missing HSTS header", Severity::High, "No HSTS")
                .with_evidence("URL: http://example.com/"),
            Finding::new("web", "Missing HSTS header", Severity::High, "No HSTS")
                .with_evidence("URL: http://example.com/"),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn normalizes_scheme_for_header_findings() {
        let http = Finding::new("web", "Missing HSTS header", Severity::High, "No HSTS")
            .with_evidence("URL: http://example.com/");
        let https = Finding::new("web", "Missing HSTS header", Severity::High, "No HSTS")
            .with_evidence("URL: https://example.com/");

        let deduped = deduplicate_findings(vec![http, https]);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn normalizes_scheme_for_cookie_findings() {
        let http = Finding::new(
            "web",
            "Cookie missing HttpOnly flag",
            Severity::Medium,
            "No HttpOnly",
        )
        .with_evidence("URL: http://example.com/");
        let https = Finding::new(
            "web",
            "Cookie missing HttpOnly flag",
            Severity::Medium,
            "No HttpOnly",
        )
        .with_evidence("URL: https://example.com/");

        let deduped = deduplicate_findings(vec![http, https]);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn keeps_different_schemes_for_non_header_findings() {
        let http = Finding::new(
            "web",
            "Server banner disclosed",
            Severity::Low,
            "Server: nginx",
        )
        .with_evidence("URL: http://example.com/");
        let https = Finding::new(
            "web",
            "Server banner disclosed",
            Severity::Low,
            "Server: nginx",
        )
        .with_evidence("URL: https://example.com/");

        let deduped = deduplicate_findings(vec![http, https]);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn keeps_same_title_from_different_modules() {
        let findings = vec![
            Finding::new("a", "done", Severity::Info, "x"),
            Finding::new("b", "done", Severity::Info, "x"),
        ];
        assert_eq!(deduplicate_findings(findings).len(), 2);
    }

    #[test]
    fn collapses_overlapping_exposed_path_findings() {
        let mut secrets = Finding::new(
            "secrets",
            "Exposed path found: .env",
            Severity::High,
            "http://example.com/.env returned HTTP 200 OK",
        );
        secrets.evidence.push("First 256 chars:\nKEY=val".into());

        let mut webvulns = Finding::new(
            "webvulns",
            "Sensitive path exposed: .env",
            Severity::High,
            "http://example.com/.env returned HTTP 200 OK",
        );
        webvulns
            .evidence
            .push("URL: http://example.com/.env\nStatus: 200 OK".into());

        let deduped = deduplicate_findings(vec![secrets, webvulns]);
        assert_eq!(deduped.len(), 1);
    }
}
