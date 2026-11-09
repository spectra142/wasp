#![allow(clippy::collapsible_if)]

use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::cms_common::{self, CmsKind, HttpResponse};
use crate::modules::Module;
use crate::target::Target;
use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use regex::Regex;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Self-contained CMS enumerator.
///
/// Detects WordPress, Drupal, and Joomla through generator tags, asset paths,
/// and CMS-specific files. For WordPress it also enumerates common plugins and
/// themes, checks for an exposed XML-RPC endpoint, and attempts to extract user
/// accounts from the REST API and author-id redirects. No external tools are
/// required.
pub struct CmsEnum;

#[async_trait]
impl Module for CmsEnum {
    fn name(&self) -> &'static str {
        "cmsenum"
    }

    fn description(&self) -> &'static str {
        "Self-contained CMS enumeration (WordPress/Drupal/Joomla) without external tools"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        if !config.modules.cmsenum.enabled {
            return Ok(Vec::new());
        }

        let client = cms_common::build_client(config)?;
        let mut findings = Vec::new();

        let mut schemes = Vec::new();
        if config.modules.cmsenum.check_https {
            schemes.push("https");
        }
        if config.modules.cmsenum.check_http {
            schemes.push("http");
        }
        if schemes.is_empty() {
            debug!("[cmsenum] no HTTP/HTTPS scheme enabled; skipping");
            return Ok(findings);
        }

        for scheme in schemes {
            let base = format!("{}://{}/", scheme, target);
            debug!("[cmsenum] probing {}", base);

            let hits = cms_common::fingerprint(&client, &base).await;
            if hits.is_empty() {
                continue;
            }

            let detected: HashSet<CmsKind> = hits.iter().map(|h| h.kind).collect();
            for hit in &hits {
                findings.push(hit.to_finding("cmsenum"));
            }

            if detected.contains(&CmsKind::WordPress) {
                findings.append(&mut enumerate_wordpress(&client, &base).await?);
            }
            if detected.contains(&CmsKind::Drupal) {
                findings.append(&mut enumerate_drupal(&client, &base).await?);
            }
            if detected.contains(&CmsKind::Joomla) {
                findings.append(&mut enumerate_joomla(&client, &base).await?);
            }
        }

        Ok(findings)
    }
}

async fn enumerate_wordpress(client: &Client, base: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    findings.append(&mut check_xmlrpc(client, base).await);
    findings.append(&mut check_rest_users(client, base).await);
    findings.append(&mut enumerate_authors(client, base).await);

    for slug in WORDPRESS_PLUGINS {
        let url = format!("{}wp-content/plugins/{}/readme.txt", base, slug);
        if let Some(resp) = fetch(client, &url).await {
            if resp.status.is_success() && looks_like_readme(&resp.body, slug) {
                let version = extract_readme_version(&resp.body);
                let mut finding = Finding::new(
                    "cmsenum",
                    &format!("WordPress plugin detected: {}", slug),
                    Severity::Info,
                    "A common WordPress plugin was discovered by probing its readme file.",
                )
                .with_evidence(format!("URL: {}", url))
                .with_remediation("Keep plugins updated and remove unused ones.");
                if let Some(v) = version {
                    finding = finding.with_evidence(format!("Version: {}", v));
                }
                findings.push(finding);
            }
        }
    }

    for slug in WORDPRESS_THEMES {
        let url = format!("{}wp-content/themes/{}/style.css", base, slug);
        if let Some(resp) = fetch(client, &url).await {
            if resp.status.is_success() && looks_like_style(&resp.body) {
                let version = extract_style_version(&resp.body);
                let mut finding = Finding::new(
                    "cmsenum",
                    &format!("WordPress theme detected: {}", slug),
                    Severity::Info,
                    "A common WordPress theme was discovered by probing its style sheet.",
                )
                .with_evidence(format!("URL: {}", url))
                .with_remediation("Keep themes updated and remove unused ones.");
                if let Some(v) = version {
                    finding = finding.with_evidence(format!("Version: {}", v));
                }
                findings.push(finding);
            }
        }
    }

    Ok(findings)
}

async fn check_xmlrpc(client: &Client, base: &str) -> Vec<Finding> {
    let url = format!("{}xmlrpc.php", base);
    if let Some(resp) = fetch(client, &url).await {
        let body_lc = resp.body.to_lowercase();
        // GET /xmlrpc.php answers "XML-RPC server accepts POST requests only."
        // (usually with HTTP 405). A bare 200 proves nothing on catch-all sites.
        if body_lc.contains("xml-rpc server accepts post requests") {
            return vec![Finding::new(
                "cmsenum",
                "WordPress XML-RPC enabled",
                Severity::Medium,
                "The WordPress XML-RPC endpoint is accessible and may be abused for brute-force or pingback attacks.",
            )
            .with_evidence(format!("URL: {} (HTTP {})", url, resp.status))
            .with_remediation("Disable XML-RPC if it is not required, or restrict access to trusted IPs.")];
        }
    }
    Vec::new()
}

async fn check_rest_users(client: &Client, base: &str) -> Vec<Finding> {
    let url = format!("{}wp-json/wp/v2/users", base);
    if let Some(resp) = fetch(client, &url).await {
        if resp.status.is_success() {
            if let Ok(users) = serde_json::from_str::<Value>(&resp.body) {
                if let Some(arr) = users.as_array() {
                    let leaked: Vec<String> = arr
                        .iter()
                        .filter_map(|u| {
                            let slug = u.get("slug").and_then(Value::as_str).unwrap_or("");
                            let name = u.get("name").and_then(Value::as_str).unwrap_or("");
                            if slug.is_empty() {
                                None
                            } else {
                                Some(format!("{} ({})", slug, name))
                            }
                        })
                        .collect();

                    if !leaked.is_empty() {
                        return vec![Finding::new(
                            "cmsenum",
                            "WordPress REST API user leakage",
                            Severity::Medium,
                            "The WordPress REST API exposes WordPress user accounts without authentication.",
                        )
                        .with_evidence(format!("URL: {}", url))
                        .with_evidence(format!("Users: {}", leaked.join(", ")))
                        .with_remediation("Restrict the /wp-json/wp/v2/users endpoint to authenticated users, or disable it if not required.")];
                    }
                }
            }
        }
    }
    Vec::new()
}

async fn enumerate_authors(client: &Client, base: &str) -> Vec<Finding> {
    let mut authors: Vec<(String, String)> = Vec::new();
    let mut seen = HashSet::new();

    for id in 1..=5 {
        let url = format!("{}?author={}", base, id);
        if let Some(resp) = fetch(client, &url).await {
            let path = resp.final_url.path().to_lowercase();
            if let Some(rest) = path.strip_prefix("/author/") {
                let slug = rest.trim_matches('/').to_string();
                if !slug.is_empty() && seen.insert(slug.clone()) {
                    authors.push((slug, resp.final_url.to_string()));
                }
            } else {
                for cap in AUTHOR_LINK_RE.captures_iter(&resp.body) {
                    if let Some(m) = cap.get(1) {
                        let slug = m.as_str().to_lowercase();
                        if !slug.is_empty() && seen.insert(slug.clone()) {
                            authors.push((slug, resp.final_url.to_string()));
                        }
                    }
                }
            }
        }
    }

    if authors.is_empty() {
        return Vec::new();
    }

    let users = authors
        .iter()
        .map(|(slug, url)| format!("{} ({})", slug, url))
        .collect::<Vec<_>>()
        .join(", ");

    vec![Finding::new(
        "cmsenum",
        "WordPress author ID enumeration",
        Severity::Low,
        "WordPress author/user slugs were revealed through ?author=ID redirects or links.",
    )
    .with_evidence(format!("Authors: {}", users))
    .with_remediation("Avoid exposing author usernames; use display names and consider blocking ?author=ID enumeration.")]
}

async fn enumerate_drupal(client: &Client, base: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut found = HashSet::new();

    for module in DRUPAL_MODULES {
        let paths = [
            format!("{}sites/all/modules/{}/README.txt", base, module),
            format!("{}core/modules/{}/README.txt", base, module),
        ];
        for url in paths {
            if let Some(resp) = fetch(client, &url).await {
                if resp.status.is_success() && cms_common::contains_ci(&resp.body, module) {
                    if found.insert(module.to_string()) {
                        findings.push(
                            Finding::new(
                                "cmsenum",
                                &format!("Drupal module detected: {}", module),
                                Severity::Info,
                                "A common Drupal module path responded successfully.",
                            )
                            .with_evidence(format!("URL: {}", url))
                            .with_remediation(
                                "Keep Drupal modules updated and disable unused ones.",
                            ),
                        );
                    }
                    break;
                }
            }
        }
    }

    let mut found_themes = HashSet::new();
    for theme in DRUPAL_THEMES {
        let paths = [
            format!("{}sites/all/themes/{}/", base, theme),
            format!("{}themes/{}/", base, theme),
            format!("{}core/themes/{}/", base, theme),
        ];
        for url in paths {
            if let Some(resp) = fetch(client, &url).await {
                if resp.status.is_success()
                    && (cms_common::contains_ci(&resp.body, "Index of")
                        || cms_common::contains_ci(&resp.body, theme))
                {
                    if found_themes.insert(theme.to_string()) {
                        findings.push(
                            Finding::new(
                                "cmsenum",
                                &format!("Drupal theme detected: {}", theme),
                                Severity::Info,
                                "A common Drupal theme path responded successfully.",
                            )
                            .with_evidence(format!("URL: {}", url))
                            .with_remediation("Keep Drupal themes updated and remove unused ones."),
                        );
                    }
                    break;
                }
            }
        }
    }

    Ok(findings)
}

async fn enumerate_joomla(client: &Client, base: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut found = HashSet::new();

    for template in JOOMLA_TEMPLATES {
        let paths = [
            format!("{}templates/{}/templateDetails.xml", base, template),
            format!(
                "{}administrator/templates/{}/templateDetails.xml",
                base, template
            ),
        ];
        for url in paths {
            if let Some(resp) = fetch(client, &url).await {
                if resp.status.is_success()
                    && (cms_common::contains_ci(&resp.body, "templateDetails")
                        || cms_common::contains_ci(&resp.body, "<name>"))
                {
                    if found.insert(template.to_string()) {
                        findings.push(
                            Finding::new(
                                "cmsenum",
                                &format!("Joomla template detected: {}", template),
                                Severity::Info,
                                "A common Joomla template was discovered by probing its metadata file.",
                            )
                            .with_evidence(format!("URL: {}", url))
                            .with_remediation("Keep Joomla templates updated and remove unused ones."),
                        );
                    }
                    break;
                }
            }
        }
    }

    Ok(findings)
}

async fn fetch(client: &Client, url: &str) -> Option<HttpResponse> {
    cms_common::fetch(client, url).await
}

fn looks_like_readme(body: &str, slug: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("stable tag")
        || lower.contains("== description ==")
        || lower.contains("contributors:")
        || lower.contains(&slug.to_lowercase())
}

fn extract_readme_version(body: &str) -> Option<String> {
    README_VERSION_RE
        .captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn looks_like_style(body: &str) -> bool {
    body.to_lowercase().contains("theme name:")
}

fn extract_style_version(body: &str) -> Option<String> {
    STYLE_VERSION_RE
        .captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

static AUTHOR_LINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)href=["'][^"']*/author/([^/"']+)/?["']"#).unwrap());

static README_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?im)^Stable tag:\s*([^\s]+)"#).unwrap());

static STYLE_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?im)^Version:\s*([^\s]+)"#).unwrap());

const WORDPRESS_PLUGINS: &[&str] = &[
    "contact-form-7",
    "woocommerce",
    "wordfence",
    "wordpress-seo",
    "elementor",
    "akismet",
    "jetpack",
    "wp-super-cache",
    "wpforms-lite",
    "all-in-one-seo-pack",
    "really-simple-ssl",
    "wp-mail-smtp",
    "duplicate-post",
    "advanced-custom-fields",
    "yoast-seo",
];

const WORDPRESS_THEMES: &[&str] = &[
    "twentytwentyfour",
    "twentytwentythree",
    "twentytwentytwo",
    "twentytwentyone",
    "astra",
    "hello-elementor",
    "generatepress",
    "oceanwp",
    "storefront",
    "neve",
];

const DRUPAL_MODULES: &[&str] = &[
    "admin_toolbar",
    "ctools",
    "pathauto",
    "token",
    "views",
    "webform",
    "metatag",
    "redirect",
    "paragraphs",
    "media",
];

const DRUPAL_THEMES: &[&str] = &["bartik", "seven", "olivero", "claro", "bootstrap"];

const JOOMLA_TEMPLATES: &[&str] = &["protostar", "beez3", "cassiopeia", "atomic"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_joomla_body_indicator() {
        let body = r#"<link rel="stylesheet" href="/media/jui/css/chosen.css">"#;
        assert!(cms_common::JOOMLA_BODY_RE.is_match(body));
    }

    #[test]
    fn readme_version_extraction() {
        let body = "=== Plugin Name ===\nStable tag: 5.8.1\n";
        assert_eq!(extract_readme_version(body), Some("5.8.1".to_string()));
    }

    #[test]
    fn style_version_extraction() {
        let body = "/*\nTheme Name: Foo\nVersion: 1.2.3\n*/";
        assert_eq!(extract_style_version(body), Some("1.2.3".to_string()));
    }

    #[test]
    fn looks_like_readme_accepts_stable_tag() {
        assert!(looks_like_readme("Stable tag: 1.0", "foo"));
    }

    #[test]
    fn looks_like_style_requires_theme_name() {
        assert!(looks_like_style("Theme Name: Bar"));
        assert!(!looks_like_style("Some random CSS"));
    }

    #[test]
    fn author_link_regex_extracts_slugs() {
        let body = r#"<a href="/author/admin/">admin</a> <a href='/author/john-doe/'>john</a>"#;
        let slugs: Vec<&str> = AUTHOR_LINK_RE
            .captures_iter(body)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .collect();
        assert_eq!(slugs, vec!["admin", "john-doe"]);
    }

    #[test]
    fn rest_users_json_parsing() {
        let json = r#"[{"id":1,"slug":"admin","name":"Administrator"},{"id":2,"slug":"editor","name":"Editor User"}]"#;
        let users: Value = serde_json::from_str(json).unwrap();
        let leaked: Vec<String> = users
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|u| {
                let slug = u.get("slug").and_then(Value::as_str).unwrap_or("");
                let name = u.get("name").and_then(Value::as_str).unwrap_or("");
                if slug.is_empty() {
                    None
                } else {
                    Some(format!("{} ({})", slug, name))
                }
            })
            .collect();
        assert_eq!(
            leaked,
            vec!["admin (Administrator)", "editor (Editor User)"]
        );
    }
}
