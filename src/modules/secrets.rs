use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;

pub struct Secrets;

#[async_trait]
impl Module for Secrets {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn description(&self) -> &'static str {
        "Exposed files, secret leakage, and API endpoint discovery"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let host = target.to_string();

        let client = config.http_client()?;

        let path_wordlist = &config.modules.secrets.path_wordlist;
        let mut paths = match fs::read_to_string(path_wordlist) {
            Ok(content) => content
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
            Err(e) => {
                debug!(
                    "failed to read exposed paths wordlist {:?}: {}",
                    path_wordlist, e
                );
                return Ok(findings);
            }
        };

        // Merge the configured path wordlist with a small embedded list of common
        // API endpoints so the module probes them even when no dedicated config
        // field is present.
        let known_endpoints = api_endpoint_wordlist();
        for endpoint in known_endpoints {
            if !paths.contains(&endpoint) {
                paths.push(endpoint);
            }
        }

        let secret_patterns = secret_patterns();
        let endpoint_regexes = endpoint_extraction_regexes();
        let semaphore = config
            .scanner
            .concurrency_semaphore
            .clone()
            .unwrap_or_else(|| {
                Arc::new(tokio::sync::Semaphore::new(
                    config.scanner.concurrency.max(1),
                ))
            });
        let check_https = config.modules.secrets.check_https;
        let check_http = config.modules.secrets.check_http;
        let enable_body_regex = config.modules.secrets.enable_body_regex;
        let mut handles = Vec::new();

        for path in paths {
            let urls: Vec<String> = {
                let mut v = Vec::new();
                if check_https {
                    v.push(format!("https://{}/{}", host, path.trim_start_matches('/')));
                }
                if check_http {
                    v.push(format!("http://{}/{}", host, path.trim_start_matches('/')));
                }
                v
            };

            for url in urls {
                let permit = semaphore.clone().acquire_owned().await?;
                let client = client.clone();
                let patterns = secret_patterns.clone();
                let extractors = endpoint_regexes.clone();
                let path_str = path.clone();
                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let resp = match client.get(&url).send().await {
                        Ok(r) => r,
                        Err(_) => return None,
                    };

                    let status = resp.status();
                    if !status.is_success() {
                        return None;
                    }

                    let body = match resp.text().await {
                        Ok(b) => b,
                        Err(_) => return None,
                    };

                    let mut findings = Vec::new();

                    let severity = path_severity(&path_str);
                    findings.push(
                        Finding::new(
                            "secrets",
                            &format!("Exposed path found: {}", path_str),
                            severity,
                            &format!("{} returned HTTP {}", url, status),
                        )
                        .with_evidence(format!(
                            "First 256 chars:\n{}",
                            body.chars().take(256).collect::<String>()
                        ))
                        .with_remediation(
                            "Remove or restrict access to non-public files and backup artifacts.",
                        ),
                    );

                    if enable_body_regex {
                        for (name, re) in &patterns {
                            for mat in re.find_iter(&body) {
                                findings.push(
                                    Finding::new(
                                        "secrets",
                                        &format!("Possible {} leaked", name),
                                        secret_severity(name, mat.as_str()),
                                        &format!("A pattern matching {} was found in {}", name, url),
                                    )
                                    .with_evidence(mat.as_str().to_string())
                                    .with_remediation("Rotate the exposed credential and remove it from source code or public responses."),
                                );
                            }
                        }

                        // Extract URLs and API endpoints from HTML/JS responses.
                        let extracted = extract_links_and_endpoints(&body, &extractors);
                        if !extracted.is_empty() {
                            let evidence = extracted
                                .iter()
                                .take(20)
                                .cloned()
                                .collect::<Vec<_>>()
                                .join("\n");
                            findings.push(
                                Finding::new(
                                    "secrets",
                                    "Potential API endpoints or links discovered in response",
                                    Severity::Info,
                                    &format!(
                                        "Discovered {} unique URL(s)/endpoint(s) in {}",
                                        extracted.len(),
                                        url
                                    ),
                                )
                                .with_evidence(evidence)
                                .with_remediation(
                                    "Review exposed links and endpoints for unintended disclosure.",
                                ),
                            );
                        }
                    }

                    Some(findings)
                });
                handles.push(handle);
            }
        }

        for handle in handles {
            if let Ok(Some(mut f)) = handle.await {
                findings.append(&mut f);
            }
        }

        Ok(findings)
    }
}

/// Embedded wordlist of common API endpoints to probe. These are merged with the
/// configured `path_wordlist` and deduplicated at runtime.
fn api_endpoint_wordlist() -> Vec<String> {
    vec![
        "api/v1/users",
        "api/v2/users",
        "api/v1/auth/login",
        "api/v1/config",
        "api/v1/secrets",
        "api/health",
        "api/swagger.json",
        "api/swagger-ui.html",
        "api-docs",
        "api-docs.json",
        "openapi.json",
        "swagger.json",
        "swagger-ui.html",
        "graphql",
        "graphiql",
        ".well-known/openid-configuration",
        "v1/api",
        "v2/api",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn secret_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "AWS Access Key ID",
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        ),
        (
            "AWS Secret Access Key",
            Regex::new(r#"['\"\s](?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"#).unwrap(),
        ),
        (
            "GitHub Token",
            Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
        ),
        (
            "GitLab Personal Access Token",
            Regex::new(r"glpat-[0-9a-zA-Z_\-]{20,}").unwrap(),
        ),
        (
            "Slack Token",
            Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}").unwrap(),
        ),
        (
            "Slack Webhook",
            Regex::new(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+").unwrap(),
        ),
        (
            "JSON Web Token",
            Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*").unwrap(),
        ),
        (
            "Database URL",
            Regex::new(r#"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite)://[^\s\"'<>]+"#).unwrap(),
        ),
        (
            "Private Key",
            Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
        ),
        (
            "Generic API Key",
            Regex::new(r#"(?i)(?:api[_-]?key|apikey|api_token)\s*[=:]\s*['\"]([a-z0-9_\-]{16,})['\"]"#).unwrap(),
        ),
    ]
}

/// Regexes used to pull URLs and API-style endpoints out of HTML/JS bodies.
fn endpoint_extraction_regexes() -> Vec<Regex> {
    vec![
        // Absolute URLs.
        Regex::new(r#"https?://[^\s\"'<>\)]+"#).unwrap(),
        // Relative paths referenced in common HTML/JS attributes or JS calls.
        Regex::new(r#"(?:(?:href|src|action)\s*=\s*|fetch\(|axios\.(?:get|post|put|delete|patch)\s*\(|url\s*[:=]\s*)['\"\`]?(/[a-zA-Z0-9_\-/]+(?:\.[a-zA-Z0-9]+)?(?:\?[a-zA-Z0-9_=&\-]+)?)['\"\`]?"#).unwrap(),
    ]
}

/// Extract URLs and relative API endpoints from a response body, deduplicating
/// results and trimming trailing punctuation from absolute URLs.
fn extract_links_and_endpoints(body: &str, regexes: &[Regex]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    for re in regexes {
        for cap in re.captures_iter(body) {
            let matched = if cap.len() > 1 {
                cap.get(1).map(|m| m.as_str())
            } else {
                cap.get(0).map(|m| m.as_str())
            };

            if let Some(s) = matched {
                let trimmed = s.trim().trim_end_matches(|c: char| {
                    c == '.' || c == ',' || c == ')' || c == '\'' || c == '"'
                });
                if trimmed.is_empty() {
                    continue;
                }
                if seen.insert(trimmed.to_string()) {
                    results.push(trimmed.to_string());
                }
            }
        }
    }

    results
}

fn secret_severity(name: &str, matched: &str) -> Severity {
    let lower = matched.to_lowercase();
    let is_localhost = lower.contains("localhost")
        || lower.contains("127.0.0.1")
        || lower.contains("::1")
        || lower.contains(".local")
        || lower.contains("@/");

    match name {
        "AWS Secret Access Key"
        | "GitHub Token"
        | "GitLab Personal Access Token"
        | "Slack Token"
        | "Slack Webhook"
        | "Private Key" => Severity::Critical,
        "AWS Access Key ID" => Severity::High,
        "Database URL" => {
            if is_localhost {
                Severity::Medium
            } else {
                Severity::Critical
            }
        }
        "JSON Web Token" | "Generic API Key" => Severity::High,
        _ => Severity::High,
    }
}

fn path_severity(path: &str) -> Severity {
    let p = path.to_ascii_lowercase();
    if p.contains(".env")
        || p.contains("id_rsa")
        || p.contains("id_dsa")
        || p.contains("config")
        || p.contains("credentials")
        || p.contains("secrets")
        || p.contains(".htpasswd")
        || p.contains("backup")
        || p.contains(".sql")
        || p.contains(".zip")
        || p.contains(".tar")
    {
        Severity::High
    } else if p.contains("admin")
        || p.contains("login")
        || p.contains("phpmyadmin")
        || p.contains(".git")
        || p.contains(".svn")
    {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_access_key_regex_matches() {
        let (_, re) = secret_patterns()
            .into_iter()
            .find(|(n, _)| *n == "AWS Access Key ID")
            .unwrap();
        assert!(re.is_match("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn github_token_regex_matches() {
        let patterns = secret_patterns();
        let (_, re) = patterns.iter().find(|(n, _)| *n == "GitHub Token").unwrap();
        assert!(re.is_match("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    }

    #[test]
    fn gitlab_token_regex_matches() {
        let patterns = secret_patterns();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| *n == "GitLab Personal Access Token")
            .unwrap();
        assert!(re.is_match("glpat-1234567890abcdefghij"));
    }

    #[test]
    fn slack_token_regex_matches() {
        let patterns = secret_patterns();
        let (_, re) = patterns.iter().find(|(n, _)| *n == "Slack Token").unwrap();
        assert!(re.is_match("xoxb-EXAMPLE-FAKE-TOKEN-NOT-REAL"));
    }

    #[test]
    fn jwt_regex_matches() {
        let patterns = secret_patterns();
        let (_, re) = patterns
            .iter()
            .find(|(n, _)| *n == "JSON Web Token")
            .unwrap();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(re.is_match(jwt));
    }

    #[test]
    fn database_url_regex_matches() {
        let patterns = secret_patterns();
        let (_, re) = patterns.iter().find(|(n, _)| *n == "Database URL").unwrap();
        assert!(re.is_match("DATABASE_URL=postgresql://user:pass@db.example.com:5432/app"));
        assert!(re.is_match("MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/db"));
        assert!(re.is_match("REDIS_URL=redis://localhost:6379/0"));
    }

    #[test]
    fn extract_absolute_urls() {
        let extractors = endpoint_extraction_regexes();
        let body = r#"<a href="https://api.example.com/v1/users">link</a>"#;
        let found = extract_links_and_endpoints(body, &extractors);
        assert!(found.contains(&"https://api.example.com/v1/users".to_string()));
    }

    #[test]
    fn extract_relative_api_endpoints() {
        let extractors = endpoint_extraction_regexes();
        let body = r#"
            fetch("/api/v1/users")
            axios.get('/api/v2/config')
            <form action="/auth/login">
        "#;
        let found = extract_links_and_endpoints(body, &extractors);
        assert!(found.contains(&"/api/v1/users".to_string()));
        assert!(found.contains(&"/api/v2/config".to_string()));
        assert!(found.contains(&"/auth/login".to_string()));
    }

    #[test]
    fn extracted_endpoints_are_deduplicated() {
        let extractors = endpoint_extraction_regexes();
        let body = r#"fetch("/api/v1/users"); fetch('/api/v1/users');"#;
        let found = extract_links_and_endpoints(body, &extractors);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], "/api/v1/users");
    }

    #[test]
    fn api_endpoint_wordlist_is_non_empty() {
        let endpoints = api_endpoint_wordlist();
        assert!(!endpoints.is_empty());
        assert!(endpoints.iter().any(|e| e.contains("api/v1/users")));
    }

    #[test]
    fn path_severity_classifications() {
        assert_eq!(path_severity(".env"), Severity::High);
        assert_eq!(path_severity("backup.sql"), Severity::High);
        assert_eq!(path_severity("admin/"), Severity::Medium);
        assert_eq!(path_severity("api/v1/users"), Severity::Low);
    }

    #[test]
    fn secret_severity_respects_context() {
        assert_eq!(
            secret_severity("Database URL", "postgres://admin:secret@db.example.com/app"),
            Severity::Critical
        );
        assert_eq!(
            secret_severity("Database URL", "postgres://admin:secret@localhost/app"),
            Severity::Medium
        );
        assert_eq!(
            secret_severity("JSON Web Token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."),
            Severity::High
        );
        assert_eq!(
            secret_severity(
                "AWS Secret Access Key",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ),
            Severity::Critical
        );
        assert_eq!(
            secret_severity("AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE"),
            Severity::High
        );
    }
}
