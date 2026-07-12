#![allow(clippy::collapsible_if)]

use crate::config::Config;
use crate::finding::{Finding, Severity};
use anyhow::{Context, Result};
use regex::Regex;
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::sync::LazyLock;
use url::Url;

/// Shared CMS fingerprinting engine used by both the external WPScan-backed
/// `cms` module and the self-contained `cmsenum` module.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmsKind {
    WordPress,
    Drupal,
    Joomla,
}

impl CmsKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CmsKind::WordPress => "WordPress",
            CmsKind::Drupal => "Drupal",
            CmsKind::Joomla => "Joomla",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

pub struct Indicator {
    pub kind: CmsKind,
    pub evidence: String,
    pub weight: u8,
}

pub struct CmsHit {
    pub kind: CmsKind,
    pub url: String,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

impl CmsHit {
    pub fn to_finding(&self, module: &str) -> Finding {
        let severity = match self.confidence {
            Confidence::Low => Severity::Info,
            Confidence::Medium => Severity::Low,
            Confidence::High => Severity::Medium,
        };

        Finding::new(
            module,
            &format!("{} detected", self.kind.as_str()),
            severity,
            &format!(
                "{} was identified on {} with {:?} confidence",
                self.kind.as_str(),
                self.url,
                self.confidence
            ),
        )
        .with_evidence(format!("Indicators: {}", self.evidence.join(" | ")))
        .with_remediation(
            "Remove generator tags and unnecessary CMS artifacts, keep the CMS patched, and consider hiding version information.",
        )
    }
}

pub struct HttpResponse {
    pub status: StatusCode,
    pub body: String,
    pub final_url: Url,
}

pub async fn fetch(client: &Client, url: &str) -> Option<HttpResponse> {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let final_url = resp.url().clone();
            let body = resp.text().await.unwrap_or_default();
            Some(HttpResponse {
                status,
                body,
                final_url,
            })
        }
        Err(e) => {
            log::debug!("[cms] request to {} failed: {}", url, e);
            None
        }
    }
}

pub fn extract_generator(body: &str) -> Option<String> {
    GENERATOR_RE
        .captures(body)
        .and_then(|caps| caps.get(1).or_else(|| caps.get(2)))
        .map(|m| m.as_str().trim().to_string())
}

pub fn generator_to_kinds(generator: &str) -> Vec<CmsKind> {
    let lower = generator.to_lowercase();
    let mut kinds = Vec::new();
    if lower.contains("wordpress") {
        kinds.push(CmsKind::WordPress);
    }
    if lower.contains("drupal") {
        kinds.push(CmsKind::Drupal);
    }
    if lower.contains("joomla") {
        kinds.push(CmsKind::Joomla);
    }
    kinds
}

pub fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_lowercase()
        .contains(needle.to_lowercase().as_str())
}

pub fn consolidate_hits(base: &str, indicators: Vec<Indicator>) -> Vec<CmsHit> {
    if indicators.is_empty() {
        return Vec::new();
    }

    let mut grouped: HashMap<CmsKind, Vec<&Indicator>> = HashMap::new();
    for ind in &indicators {
        grouped.entry(ind.kind).or_default().push(ind);
    }

    let mut hits = Vec::new();
    for (kind, group) in grouped {
        let count = group.len();
        let max_weight = group.iter().map(|i| i.weight).max().unwrap_or(0);
        let confidence = if max_weight >= 3 || count >= 3 {
            Confidence::High
        } else if count == 2 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        let evidence: Vec<String> = group.iter().map(|i| i.evidence.clone()).collect();
        hits.push(CmsHit {
            kind,
            url: base.to_string(),
            confidence,
            evidence,
        });
    }

    hits
}

pub async fn probe_wordpress(client: &Client, base: &str, indicators: &mut Vec<Indicator>) {
    if let Some(resp) = fetch(client, &format!("{}wp-login.php", base)).await {
        if contains_ci(&resp.body, "wp-submit") || contains_ci(&resp.body, "Powered by WordPress") {
            indicators.push(Indicator {
                kind: CmsKind::WordPress,
                evidence: format!("wp-login.php responded with HTTP {}", resp.status),
                weight: 1,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}wp-admin/", base)).await {
        if contains_ci(&resp.body, "wp-admin") || contains_ci(&resp.body, "wp-submit") {
            indicators.push(Indicator {
                kind: CmsKind::WordPress,
                evidence: format!("wp-admin/ responded with HTTP {}", resp.status),
                weight: 1,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}readme.html", base)).await {
        if resp.status.is_success() && contains_ci(&resp.body, "WordPress") {
            indicators.push(Indicator {
                kind: CmsKind::WordPress,
                evidence: "readme.html contains WordPress branding".to_string(),
                weight: 2,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}xmlrpc.php", base)).await {
        if contains_ci(&resp.body, "XML-RPC server accepts POST requests") {
            indicators.push(Indicator {
                kind: CmsKind::WordPress,
                evidence: format!(
                    "xmlrpc.php indicates XML-RPC enabled (HTTP {})",
                    resp.status
                ),
                weight: 1,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}wp-content/", base)).await {
        if resp.status.is_success() && contains_ci(&resp.body, "Index of") {
            indicators.push(Indicator {
                kind: CmsKind::WordPress,
                evidence: "wp-content/ directory listing enabled".to_string(),
                weight: 1,
            });
        }
    }
}

pub async fn probe_drupal(client: &Client, base: &str, indicators: &mut Vec<Indicator>) {
    if let Some(resp) = fetch(client, &format!("{}user/login", base)).await {
        if contains_ci(&resp.body, "Drupal") || contains_ci(&resp.body, "user-login-form") {
            indicators.push(Indicator {
                kind: CmsKind::Drupal,
                evidence: format!("user/login responded with HTTP {}", resp.status),
                weight: 1,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}CHANGELOG.txt", base)).await {
        if resp.status.is_success() && contains_ci(&resp.body, "Drupal") {
            indicators.push(Indicator {
                kind: CmsKind::Drupal,
                evidence: "CHANGELOG.txt contains Drupal version history".to_string(),
                weight: 2,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}sites/default/", base)).await {
        if resp.status.is_success()
            && (contains_ci(&resp.body, "Index of") || contains_ci(&resp.body, "sites/default"))
        {
            indicators.push(Indicator {
                kind: CmsKind::Drupal,
                evidence: "sites/default/ directory listing exposed".to_string(),
                weight: 1,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}core/install.php", base)).await {
        if contains_ci(&resp.body, "Drupal") {
            indicators.push(Indicator {
                kind: CmsKind::Drupal,
                evidence: format!(
                    "core/install.php contains Drupal marker (HTTP {})",
                    resp.status
                ),
                weight: 1,
            });
        }
    }
}

pub async fn probe_joomla(client: &Client, base: &str, indicators: &mut Vec<Indicator>) {
    if let Some(resp) = fetch(client, &format!("{}administrator/", base)).await {
        if contains_ci(&resp.body, "Joomla") || contains_ci(&resp.body, "form-login") {
            indicators.push(Indicator {
                kind: CmsKind::Joomla,
                evidence: format!("administrator/ responded with HTTP {}", resp.status),
                weight: 1,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}README.txt", base)).await {
        if resp.status.is_success() && contains_ci(&resp.body, "Joomla") {
            indicators.push(Indicator {
                kind: CmsKind::Joomla,
                evidence: "README.txt contains Joomla branding".to_string(),
                weight: 2,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}media/jui/", base)).await {
        if resp.status.is_success() && contains_ci(&resp.body, "Index of") {
            indicators.push(Indicator {
                kind: CmsKind::Joomla,
                evidence: "media/jui/ directory listing enabled".to_string(),
                weight: 1,
            });
        }
    }

    if let Some(resp) = fetch(client, &format!("{}templates/", base)).await {
        if resp.status.is_success() && contains_ci(&resp.body, "Index of") {
            indicators.push(Indicator {
                kind: CmsKind::Joomla,
                evidence: "templates/ directory listing enabled".to_string(),
                weight: 1,
            });
        }
    }
}

pub fn build_client(config: &Config) -> Result<Client> {
    config
        .http_client_builder()?
        .build()
        .context("failed to build HTTP client for CMS scanner")
}

pub async fn fingerprint(client: &Client, base: &str) -> Vec<CmsHit> {
    let mut indicators: Vec<Indicator> = Vec::new();

    let root = match fetch(client, base).await {
        Some(r) => r,
        None => return Vec::new(),
    };

    if let Some(generator_value) = extract_generator(&root.body) {
        for kind in generator_to_kinds(&generator_value) {
            indicators.push(Indicator {
                kind,
                evidence: format!("generator tag: {}", generator_value),
                weight: 3,
            });
        }
    }

    if WORDPRESS_BODY_RE.is_match(&root.body) {
        indicators.push(Indicator {
            kind: CmsKind::WordPress,
            evidence: "WordPress assets in root page body".to_string(),
            weight: 1,
        });
    }
    if DRUPAL_BODY_RE.is_match(&root.body) {
        indicators.push(Indicator {
            kind: CmsKind::Drupal,
            evidence: "Drupal assets/settings in root page body".to_string(),
            weight: 1,
        });
    }
    if JOOMLA_BODY_RE.is_match(&root.body) {
        indicators.push(Indicator {
            kind: CmsKind::Joomla,
            evidence: "Joomla assets in root page body".to_string(),
            weight: 1,
        });
    }

    probe_wordpress(client, base, &mut indicators).await;
    probe_drupal(client, base, &mut indicators).await;
    probe_joomla(client, base, &mut indicators).await;

    consolidate_hits(base, indicators)
}

pub(crate) static GENERATOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)<meta\b[^>]*\bcontent=["']([^"']*)["'][^>]*\bname=["']generator["'][^>]*>|<meta\b[^>]*\bname=["']generator["'][^>]*\bcontent=["']([^"']*)["'][^>]*>"#,
    )
    .unwrap()
});

pub(crate) static WORDPRESS_BODY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)/wp-content/|/wp-includes/|/wp-json/|/wp-admin/"#).unwrap());

pub(crate) static DRUPAL_BODY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)Drupal\.settings|/sites/default/|jQuery\.extend\(Drupal\.settings|drupal"#)
        .unwrap()
});

pub(crate) static JOOMLA_BODY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)content=["']Joomla|/media/jui/|/templates/|/administrator/"#).unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_wordpress_generator() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.3"></head></html>"#;
        let generator_value = extract_generator(body).unwrap();
        assert!(generator_value.to_lowercase().contains("wordpress"));
    }

    #[test]
    fn extracts_generator_content_before_name() {
        let body = r#"<html><head><meta content="Drupal 10" name="generator"></head></html>"#;
        let generator_value = extract_generator(body).unwrap();
        assert!(generator_value.to_lowercase().contains("drupal"));
    }

    #[test]
    fn body_wordpress_indicator() {
        let body = r#"<link rel="stylesheet" href="/wp-content/themes/foo/style.css">"#;
        assert!(WORDPRESS_BODY_RE.is_match(body));
    }

    #[test]
    fn consolidate_single_indicator_is_low_confidence() {
        let indicators = vec![Indicator {
            kind: CmsKind::Joomla,
            evidence: "administrator/ responded".to_string(),
            weight: 1,
        }];
        let hits = consolidate_hits("http://example.com/", indicators);
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].confidence, Confidence::Low));
        assert_eq!(hits[0].to_finding("cms").severity, Severity::Info);
    }

    #[test]
    fn consolidate_generator_is_high_confidence() {
        let indicators = vec![Indicator {
            kind: CmsKind::WordPress,
            evidence: "generator tag: WordPress 6.0".to_string(),
            weight: 3,
        }];
        let hits = consolidate_hits("http://example.com/", indicators);
        assert_eq!(hits[0].confidence, Confidence::High);
        assert_eq!(hits[0].to_finding("cms").severity, Severity::Medium);
    }

    #[test]
    fn consolidate_multiple_indicators_boost_confidence() {
        let indicators = vec![
            Indicator {
                kind: CmsKind::Drupal,
                evidence: "user/login responded".to_string(),
                weight: 1,
            },
            Indicator {
                kind: CmsKind::Drupal,
                evidence: "CHANGELOG.txt exposed".to_string(),
                weight: 2,
            },
            Indicator {
                kind: CmsKind::Drupal,
                evidence: "sites/default/ listing".to_string(),
                weight: 1,
            },
        ];
        let hits = consolidate_hits("http://example.com/", indicators);
        assert_eq!(hits[0].confidence, Confidence::High);
    }
}
