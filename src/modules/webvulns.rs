#![allow(clippy::collapsible_if)]

use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::http::{read_body, NotFoundBaseline};
use crate::modules::Module;
use crate::target::Target;
use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use reqwest::{Client, Method};
use std::sync::Arc;
use url::Url;

pub struct WebVulns;

#[async_trait]
impl Module for WebVulns {
    fn name(&self) -> &'static str {
        "webvulns"
    }

    fn description(&self) -> &'static str {
        "Built-in web vulnerability checks (CORS, open redirect, HTTP methods, sensitive files, verbose errors, framework paths)"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let cfg = &config.modules.webvulns;
        if !cfg.enabled {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let host = target.to_string();
        let client = build_client(config)?;

        let mut bases = Vec::new();
        if cfg.check_http {
            bases.push(format!("http://{}/", host));
        }
        if cfg.check_https {
            bases.push(format!("https://{}/", host));
        }
        if bases.is_empty() {
            bases.push(format!("http://{}/", host));
        }

        if cfg.check_cors {
            for base in &bases {
                findings.append(&mut check_cors(&client, base).await);
            }
        }

        if cfg.check_open_redirect {
            for base in &bases {
                findings.append(&mut check_open_redirect(&client, base).await);
            }
        }

        if cfg.check_trace {
            for base in &bases {
                findings.append(&mut check_trace(&client, base).await);
            }
        }

        if cfg.check_options {
            for base in &bases {
                findings.append(&mut check_options(&client, base).await);
            }
        }

        if cfg.check_sensitive_files {
            let paths = sensitive_path_wordlist();
            let semaphore = config.request_limiter();
            let mut handles = Vec::new();

            for base in &bases {
                let baseline = Arc::new(NotFoundBaseline::probe(&client, base).await);
                for path in &paths {
                    let permit = semaphore.clone().acquire_owned().await?;
                    let client = client.clone();
                    let path = path.to_string();
                    let baseline = Arc::clone(&baseline);
                    let url = format!("{}{}", base, path.trim_start_matches('/'));
                    let handle = tokio::spawn(async move {
                        let _permit = permit;
                        check_sensitive_path(&client, &url, &path, &baseline).await
                    });
                    handles.push(handle);
                }
            }

            for handle in handles {
                if let Ok(Some(finding)) = handle.await {
                    findings.push(finding);
                }
            }

            // The verbose error probe is part of the sensitive-files check group
            // because it relies on probing paths that are not part of normal content.
            for base in &bases {
                findings.append(&mut check_verbose_error(&client, base).await);
            }
        }

        Ok(findings)
    }
}

fn build_client(config: &Config) -> Result<Client> {
    config
        .http_client_builder()?
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Into::into)
}

/// Probe for CORS origin reflection and wildcard misconfiguration.
///
/// A reflected Origin header (especially with
/// `Access-Control-Allow-Credentials: true`) allows an attacker to make
/// authenticated cross-origin requests.
async fn check_cors(client: &Client, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let test_origin = "https://wasp-cors-test.example";

    // Test the root and a common API path; many APIs enable CORS only under
    // /api or /graphql.
    let targets = [base_url.trim_end_matches('/'), "/api", "/graphql"];

    for target in &targets {
        let url = if target.starts_with('/') {
            format!("{}{}", base_url.trim_end_matches('/'), target)
        } else {
            target.to_string()
        };

        let resp = match client.get(&url).header("Origin", test_origin).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("CORS check request to {} failed: {}", url, e);
                continue;
            }
        };

        let allow_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let allow_credentials = resp
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(origin) = allow_origin {
            let reflected = origin.eq_ignore_ascii_case(test_origin);
            let wildcard = origin == "*";

            if reflected {
                let creds = allow_credentials
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                let (severity, description, remediation) = if creds {
                    (
                        Severity::High,
                        "The server reflects the Origin header and allows credentials, enabling cross-origin authenticated requests",
                        "Implement an explicit whitelist of allowed origins and disable Access-Control-Allow-Credentials unless strictly required.",
                    )
                } else {
                    (
                        Severity::Medium,
                        "The server reflects the Origin header, allowing arbitrary origins to read responses",
                        "Validate the Origin header against an allow-list instead of echoing it back.",
                    )
                };
                findings.push(
                    Finding::new("webvulns", "CORS misconfiguration: Origin reflection", severity, description)
                        .with_evidence(format!(
                            "URL: {} | Origin sent: {} | Access-Control-Allow-Origin: {} | Access-Control-Allow-Credentials: {}",
                            url,
                            test_origin,
                            origin,
                            allow_credentials.as_deref().unwrap_or("not set")
                        ))
                        .with_remediation(remediation),
                );
            } else if wildcard {
                let creds = allow_credentials
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                let severity = if creds { Severity::High } else { Severity::Low };
                findings.push(
                    Finding::new("webvulns", "CORS misconfiguration: wildcard origin", severity, "Access-Control-Allow-Origin is set to *")
                        .with_evidence(format!(
                            "URL: {} | Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: {}",
                            url,
                            allow_credentials.as_deref().unwrap_or("not set")
                        ))
                        .with_remediation("Replace the wildcard with an explicit allow-list of origins. Never combine * with Access-Control-Allow-Credentials: true."),
                );
            }
        }
    }

    findings
}

/// Probe for open redirect via common query parameters.
///
/// The test payloads include a full URL and a protocol-relative URL. A 3xx
/// response whose Location header points to the external host is reported.
async fn check_open_redirect(client: &Client, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let params = [
        "redirect",
        "redirect_uri",
        "redirect_url",
        "url",
        "next",
        "return",
        "returnUrl",
        "return_to",
        "dest",
        "destination",
        "continue",
        "goto",
    ];
    let payloads = [
        format!("https://{}/", REDIRECT_CANARY_HOST),
        format!("//{}/", REDIRECT_CANARY_HOST),
    ];
    let root = base_url.trim_end_matches('/');
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return findings,
    };

    for param in &params {
        for payload in &payloads {
            // `:` and `/` are legal inside a query string, so the payload is
            // sent verbatim, exactly as a crafted phishing link would be.
            let url = format!("{}/?{}={}", root, param, payload);
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    debug!("open redirect request to {} failed: {}", url, e);
                    continue;
                }
            };

            let status = resp.status();
            if status.is_redirection() {
                if let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok())
                {
                    if redirects_to_host(&base, location, REDIRECT_CANARY_HOST) {
                        findings.push(
                            Finding::new(
                                "webvulns",
                                "Open redirect via query parameter",
                                Severity::Medium,
                                &format!(
                                    "The parameter '{}' accepts an external URL and the server redirects to it",
                                    param
                                ),
                            )
                            .with_evidence(format!(
                                "URL: {} | Payload: {} | Status: {} | Location: {}",
                                url, payload, status, location
                            ))
                            .with_remediation("Validate redirect destinations against an allow-list of trusted URLs or use indirect mapping (tokens)."),
                        );
                        return findings;
                    }
                }
            }
        }
    }

    findings
}

/// Host used as the open-redirect destination. `.invalid` is reserved by
/// RFC 2606, so it can never resolve to a real site.
const REDIRECT_CANARY_HOST: &str = "wasp-redirect-canary.invalid";

/// Whether a `Location` header (resolved against `base`) sends the browser to
/// `host`. Matching on the parsed host avoids false positives such as
/// `/login?next=https://canary`, which merely echoes the payload.
fn redirects_to_host(base: &Url, location: &str, host: &str) -> bool {
    // Browsers treat backslashes like forward slashes in this position.
    let normalized = location.trim().replace('\\', "/");
    match base.join(&normalized) {
        Ok(resolved) => resolved
            .host_str()
            .map(|h| h.eq_ignore_ascii_case(host))
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Probe for HTTP TRACE support.
///
/// TRACE is generally unnecessary and enables cross-site tracing (XST) when
/// combined with other weaknesses.
async fn check_trace(client: &Client, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = base_url.trim_end_matches('/').to_string();

    let marker = format!("wasp-trace-{}", crate::http::random_token());
    let resp = match client
        .request(Method::TRACE, &url)
        .header("X-Wasp-Trace", &marker)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!("TRACE request to {} failed: {}", url, e);
            return findings;
        }
    };

    let status = resp.status();
    if status.is_success() {
        let body = read_body(resp).await;
        // A real TRACE implementation echoes the request back. Servers that
        // answer every method with their normal page are not vulnerable.
        if !body.contains(&marker) && !body.to_ascii_uppercase().starts_with("TRACE ") {
            return findings;
        }
        findings.push(
            Finding::new(
                "webvulns",
                "HTTP TRACE method enabled",
                Severity::Medium,
                "The server accepts TRACE requests, which can facilitate cross-site tracing (XST) attacks",
            )
            .with_evidence(format!(
                "TRACE {} returned HTTP {}\nBody snippet: {}",
                url,
                status,
                body.chars().take(256).collect::<String>()
            ))
            .with_remediation("Disable the TRACE method in the web server configuration."),
        );
    }

    findings
}

/// Probe for HTTP OPTIONS support and dangerous allowed methods.
async fn check_options(client: &Client, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = base_url.trim_end_matches('/').to_string();

    let resp = match client.request(Method::OPTIONS, &url).send().await {
        Ok(r) => r,
        Err(e) => {
            debug!("OPTIONS request to {} failed: {}", url, e);
            return findings;
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return findings;
    }

    let allow = resp
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if allow.to_ascii_uppercase().contains("TRACE") {
        findings.push(
            Finding::new(
                "webvulns",
                "OPTIONS response allows TRACE method",
                Severity::Medium,
                "The server reports TRACE as an allowed HTTP method",
            )
            .with_evidence(format!(
                "OPTIONS {} returned HTTP {}\nAllow: {}",
                url, status, allow
            ))
            .with_remediation(
                "Disable TRACE and restrict the Allow header to methods that are actually required.",
            ),
        );
    } else {
        findings.push(
            Finding::new(
                "webvulns",
                "OPTIONS method supported",
                Severity::Info,
                "The server responds to OPTIONS requests",
            )
            .with_evidence(format!(
                "OPTIONS {} returned HTTP {}\nAllow: {}",
                url, status, allow
            ))
            .with_remediation(
                "Ensure OPTIONS responses do not expose unnecessary methods or sensitive information.",
            ),
        );
    }

    findings
}

/// Probe a single sensitive path and report it when the server returns a
/// successful response.
async fn check_sensitive_path(
    client: &Client,
    url: &str,
    path: &str,
    baseline: &NotFoundBaseline,
) -> Option<Finding> {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            debug!("sensitive path request to {} failed: {}", url, e);
            return None;
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return None;
    }

    let body = read_body(resp).await;
    if baseline.is_soft_404(status, path, &body) {
        debug!("{} matches the soft-404 baseline; skipping", url);
        return None;
    }
    let severity = sensitive_path_severity(path);
    let snippet: String = body.chars().take(256).collect();

    Some(
        Finding::new(
            "webvulns",
            &format!("Sensitive path exposed: {}", path),
            severity,
            &format!("{} returned HTTP {}", url, status),
        )
        .with_evidence(format!(
            "URL: {}\nStatus: {}\nFirst 256 chars:\n{}",
            url, status, snippet
        ))
        .with_remediation(
            "Remove or restrict access to sensitive files, directories, and framework artifacts.",
        ),
    )
}

/// Combined wordlist of sensitive files, backups, configuration artifacts, and
/// known framework-specific paths.
fn sensitive_path_wordlist() -> Vec<&'static str> {
    vec![
        // Environment and configuration files
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.bak",
        "config.json",
        "config.yaml",
        "config.yml",
        "settings.json",
        "settings.py",
        "appsettings.json",
        "secrets.json",
        "credentials.json",
        "web.config",
        ".htaccess",
        ".htpasswd",
        // Source control
        ".git/HEAD",
        ".git/config",
        ".git/index",
        ".svn/entries",
        // Backups and dumps
        "backup.zip",
        "backup.tar.gz",
        "backup.sql",
        "dump.sql",
        "site.zip",
        "id_rsa",
        ".ssh/id_rsa",
        // Administrative and framework paths
        "admin/",
        "administrator/",
        "login/",
        "wp-login.php",
        "wp-admin/",
        "wp-json/",
        "phpmyadmin/",
        "pma/",
        "server-status",
        "server-info",
        "phpinfo.php",
        "info.php",
        // API and documentation
        "api/",
        "v1/",
        "v2/",
        "swagger.json",
        "openapi.json",
        "swagger-ui.html",
        "api-docs/",
        "graphql",
        "graphiql",
        ".well-known/openid-configuration",
        // Spring Boot actuators
        "actuator/health",
        "actuator/env",
        "actuator/configprops",
        "actuator/mappings",
        // Misc exposure
        "robots.txt",
        "sitemap.xml",
        ".DS_Store",
        // .NET specific
        "Trace.axd",
        "elmah.axd",
    ]
}

fn sensitive_path_severity(path: &str) -> Severity {
    let p = path.to_ascii_lowercase();
    // Public-by-design discovery documents are informational, not leaks.
    if p.contains(".well-known/") || p == "robots.txt" || p == "sitemap.xml" {
        return Severity::Info;
    }
    if p.contains(".env")
        || p.contains(".git")
        || p.contains("backup")
        || p.contains(".sql")
        || p.contains(".zip")
        || p.contains(".tar")
        || p.contains(".htpasswd")
        || p.contains("credentials")
        || p.contains("secrets")
        || p.contains("id_rsa")
        || p.contains("config")
        || p.contains("settings")
        || p.contains("appsettings")
    {
        Severity::High
    } else if p.contains("admin")
        || p.contains("login")
        || p.contains("phpmyadmin")
        || p.contains("pma")
        || p.contains("server-status")
        || p.contains("server-info")
        || p.contains("actuator")
        || p.contains("trace.axd")
        || p.contains("elmah.axd")
    {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Probe for verbose error pages by requesting paths that are likely to
/// trigger errors and inspecting the response body for stack traces or
/// implementation details.
async fn check_verbose_error(client: &Client, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let probes = ["/?page=error", "/%00", "/test%2e%2e%2fetc%2fpasswd"];

    for probe in &probes {
        let url = format!("{}{}", base_url.trim_end_matches('/'), probe);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("verbose error probe to {} failed: {}", url, e);
                continue;
            }
        };

        let body = read_body(resp).await;

        if is_verbose_error_page(&body) {
            findings.push(
                Finding::new(
                    "webvulns",
                    "Verbose error page",
                    Severity::Medium,
                    "The application returns detailed error information that may reveal implementation details",
                )
                .with_evidence(format!(
                    "URL: {}\nSnippet:\n{}",
                    url,
                    body.chars().take(512).collect::<String>()
                ))
                .with_remediation(
                    "Configure custom error pages, disable debug mode, and avoid exposing stack traces or file paths in production.",
                ),
            );
            break;
        }
    }

    findings
}

fn is_verbose_error_page(body: &str) -> bool {
    VERBOSE_ERROR_RE.is_match(body)
}

/// Signatures of framework debug pages and stack traces. These are specific
/// enough not to fire on ordinary prose such as "Warning: cookies required".
static VERBOSE_ERROR_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)traceback \(most recent call last\)|stack trace:|<b>(?:fatal error|warning|notice|parse error)</b>:|(?:fatal error|parse error): .* on line \d+|you have an error in your sql syntax|sql syntax.{0,40}near|unclosed quotation mark after the character string|ORA-\d{5}|pg_query\(\)|SQLSTATE\[|exception in (?:thread|\w+controller)|at [\w.$]+\([\w]+\.java:\d+\)|server error in '/' application|whitelabel error page|django\.core\.exceptions|werkzeug debugger|undefined index:|runtime error|/var/www/|[a-z]:\\inetpub\\",
    )
    .expect("valid verbose error regex")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_detection_uses_parsed_host() {
        let base = Url::parse("http://example.com/").unwrap();
        let host = REDIRECT_CANARY_HOST;
        assert!(redirects_to_host(
            &base,
            &format!("https://{}/", host),
            host
        ));
        assert!(redirects_to_host(&base, &format!("//{}/x", host), host));
        assert!(redirects_to_host(&base, &format!("/\\{}/", host), host));
        // Echoing the payload in a same-site URL is not an open redirect.
        assert!(!redirects_to_host(
            &base,
            &format!("/login?next=https://{}/", host),
            host
        ));
        assert!(!redirects_to_host(
            &base,
            &format!("https://{}.example.com/", host),
            host
        ));
    }

    #[test]
    fn verbose_error_ignores_ordinary_prose() {
        assert!(!is_verbose_error_page(
            "<p>Warning: this site uses cookies. Read our policy on line 3.</p>"
        ));
    }

    #[test]
    fn sensitive_path_severity_classifications() {
        assert_eq!(sensitive_path_severity(".env"), Severity::High);
        assert_eq!(sensitive_path_severity(".git/HEAD"), Severity::High);
        assert_eq!(sensitive_path_severity("backup.zip"), Severity::High);
        assert_eq!(sensitive_path_severity("config.json"), Severity::High);
        assert_eq!(sensitive_path_severity("admin/"), Severity::Medium);
        assert_eq!(sensitive_path_severity("wp-login.php"), Severity::Medium);
        assert_eq!(sensitive_path_severity("actuator/health"), Severity::Medium);
        assert_eq!(sensitive_path_severity("api/"), Severity::Low);
        assert_eq!(sensitive_path_severity("robots.txt"), Severity::Info);
        assert_eq!(
            sensitive_path_severity(".well-known/openid-configuration"),
            Severity::Info
        );
    }

    #[test]
    fn detects_verbose_error_page_patterns() {
        assert!(is_verbose_error_page(
            "Runtime Error: stack trace at /var/www/app.rb:42"
        ));
        assert!(is_verbose_error_page("Traceback (most recent call last):"));
        assert!(is_verbose_error_page(
            "SQL syntax error near 'SELECT' on line 12"
        ));
        assert!(is_verbose_error_page("Exception in ApplicationController"));
        assert!(!is_verbose_error_page("Page not found"));
    }

    #[test]
    fn sensitive_wordlist_contains_expected_paths() {
        let paths = sensitive_path_wordlist();
        assert!(paths.contains(&".env"));
        assert!(paths.contains(&".git/HEAD"));
        assert!(paths.contains(&"backup.zip"));
        assert!(paths.contains(&"wp-login.php"));
        assert!(paths.contains(&"actuator/health"));
        assert!(paths.contains(&"swagger.json"));
        // No duplicates
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(paths.len(), unique.len());
    }
}
