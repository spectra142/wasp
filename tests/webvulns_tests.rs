use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use wasp::config::Config;
use wasp::finding::Severity;
use wasp::modules::{Module, webvulns::WebVulns};
use wasp::target::Target;

/// Local HTTP fixture tailored to exercise every webvulns check.
struct WebVulnsServer {
    port: u16,
    _handle: tokio::task::JoinHandle<()>,
}

impl WebVulnsServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self::from_listener(listener).await
    }

    async fn from_listener(listener: TcpListener) -> Self {
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                tokio::spawn(handle_request(socket));
            }
        });
        Self {
            port,
            _handle: handle,
        }
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

async fn handle_request(mut socket: TcpStream) {
    let (reader, mut writer) = socket.split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET");

    // Consume headers and capture Origin if present.
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if buf_reader.read_line(&mut line).await.is_err() {
            return;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.trim().split_once(':') {
            headers.insert(k.to_lowercase(), v.trim().to_string());
        }
    }

    let path_and_query = parts.get(1).copied().unwrap_or("/");
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    let (status, resp_headers, body) = build_response(method, path, query, &headers);
    let response = format!(
        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\n{}\r\n{}",
        status,
        body.len(),
        resp_headers,
        body
    );
    let _ = writer.write_all(response.as_bytes()).await;
}

fn build_response(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HashMap<String, String>,
) -> (u16, String, String) {
    match method {
        "TRACE" => (
            200,
            String::new(),
            "TRACE / HTTP/1.1\r\nX-Test: reflected".to_string(),
        ),
        "OPTIONS" => (
            200,
            "Allow: GET, POST, TRACE, OPTIONS\r\n".to_string(),
            String::new(),
        ),
        _ => build_get_response(path, query, headers),
    }
}

fn build_get_response(
    path: &str,
    query: Option<&str>,
    headers: &HashMap<String, String>,
) -> (u16, String, String) {
    // Open redirect checks.
    if let Some(q) = query {
        let params: Vec<(String, String)> = q
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        for (k, v) in &params {
            if ["redirect", "url", "next", "return", "returnurl"].contains(&k.as_str()) {
                return (302, format!("Location: {}\r\n", v), String::new());
            }
        }
        if params.iter().any(|(k, _)| k == "page") {
            return (
                500,
                String::new(),
                "Runtime Error: stack trace at /var/www/app.py:42\nTraceback (most recent call last)".to_string(),
            );
        }
    }

    match path {
        "/" => (
            200,
            "Server: test-webvulns/1.0\r\n".to_string(),
            "<html><body>Home</body></html>".to_string(),
        ),
        "/api" => {
            let origin = headers.get("origin").cloned().unwrap_or_default();
            let cors_headers = format!(
                "Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Credentials: true\r\n",
                origin
            );
            (200, cors_headers, "{\"status\":\"ok\"}".to_string())
        }
        "/graphql" => (
            200,
            "Access-Control-Allow-Origin: *\r\n".to_string(),
            "{\"data\":null}".to_string(),
        ),
        "/.env" => (200, String::new(), "DB_PASSWORD=secret\n".to_string()),
        "/backup.zip" => (200, String::new(), "PK\x03\x04fake zip body".to_string()),
        "/admin/" => (200, String::new(), "<html>Admin panel</html>".to_string()),
        "/wp-login.php" => (
            200,
            String::new(),
            "<html>WordPress login</html>".to_string(),
        ),
        "/actuator/health" => (200, String::new(), "{\"status\":\"UP\"}".to_string()),
        "/%00" => (
            500,
            String::new(),
            "Fatal error: undefined index at /var/www/app.php on line 10".to_string(),
        ),
        _ => (404, String::new(), "not found".to_string()),
    }
}

fn test_config() -> Config {
    let mut config = Config::load(None).unwrap();
    config.scanner.timeout_ms = 2000;
    config.scanner.concurrency = 50;
    config.scanner.max_redirects = 2;
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;
    config.modules.webvulns.enabled = true;
    config.modules.webvulns.check_cors = true;
    config.modules.webvulns.check_open_redirect = true;
    config.modules.webvulns.check_trace = true;
    config.modules.webvulns.check_options = true;
    config.modules.webvulns.check_sensitive_files = true;
    config
}

async fn wait_for_server(addr: &str, timeout_ms: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server did not become ready in time: {}", addr);
}

fn find_finding<'a>(
    findings: &'a [wasp::finding::Finding],
    module: &str,
    title_sub: &str,
) -> Option<&'a wasp::finding::Finding> {
    findings
        .iter()
        .find(|f| f.module == module && f.title.contains(title_sub))
}

#[tokio::test]
async fn detects_cors_origin_reflection_with_credentials() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();

    let findings = WebVulns.run(&target, &test_config()).await.unwrap();

    let finding = find_finding(
        &findings,
        "webvulns",
        "CORS misconfiguration: Origin reflection",
    )
    .expect("missing CORS reflection finding");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.evidence.iter().any(|e| e.contains("/api")));
    assert!(
        finding
            .evidence
            .iter()
            .any(|e| e.contains("wasp-cors-test.example"))
    );
}

#[tokio::test]
async fn detects_cors_wildcard_origin() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();

    let findings = WebVulns.run(&target, &test_config()).await.unwrap();

    let finding = find_finding(
        &findings,
        "webvulns",
        "CORS misconfiguration: wildcard origin",
    )
    .expect("missing CORS wildcard finding");
    assert_eq!(finding.severity, Severity::Low);
    assert!(finding.evidence.iter().any(|e| e.contains("/graphql")));
}

#[tokio::test]
async fn detects_open_redirect() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();

    let findings = WebVulns.run(&target, &test_config()).await.unwrap();

    let finding = find_finding(&findings, "webvulns", "Open redirect")
        .expect("missing open redirect finding");
    assert_eq!(finding.severity, Severity::Medium);
    assert!(finding.evidence.iter().any(|e| e.contains("evil.com")));
}

#[tokio::test]
async fn detects_http_trace_enabled() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();

    let findings = WebVulns.run(&target, &test_config()).await.unwrap();

    let finding = find_finding(&findings, "webvulns", "HTTP TRACE method enabled")
        .expect("missing TRACE finding");
    assert_eq!(finding.severity, Severity::Medium);
}

#[tokio::test]
async fn detects_options_allowing_trace() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();

    let findings = WebVulns.run(&target, &test_config()).await.unwrap();

    let finding = find_finding(
        &findings,
        "webvulns",
        "OPTIONS response allows TRACE method",
    )
    .expect("missing OPTIONS finding");
    assert_eq!(finding.severity, Severity::Medium);
}

#[tokio::test]
async fn detects_sensitive_paths() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();

    let findings = WebVulns.run(&target, &test_config()).await.unwrap();

    assert!(
        find_finding(&findings, "webvulns", ".env").is_some(),
        "missing .env finding: {:?}",
        findings
    );
    assert!(
        find_finding(&findings, "webvulns", "backup.zip").is_some(),
        "missing backup.zip finding"
    );
    assert!(
        find_finding(&findings, "webvulns", "admin/").is_some(),
        "missing admin/ finding"
    );
    assert!(
        find_finding(&findings, "webvulns", "wp-login.php").is_some(),
        "missing wp-login.php finding"
    );
    assert!(
        find_finding(&findings, "webvulns", "actuator/health").is_some(),
        "missing actuator/health finding"
    );
}

#[tokio::test]
async fn detects_verbose_error_page() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();

    let findings = WebVulns.run(&target, &test_config()).await.unwrap();

    let finding = find_finding(&findings, "webvulns", "Verbose error page")
        .expect("missing verbose error finding");
    assert_eq!(finding.severity, Severity::Medium);
    assert!(finding.evidence.iter().any(|e| e.contains("stack trace")));
}

#[tokio::test]
async fn disabled_checks_produce_no_findings() {
    let server = WebVulnsServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.webvulns.check_cors = false;
    config.modules.webvulns.check_open_redirect = false;
    config.modules.webvulns.check_trace = false;
    config.modules.webvulns.check_options = false;
    config.modules.webvulns.check_sensitive_files = false;

    let findings = WebVulns.run(&target, &config).await.unwrap();

    assert!(findings.is_empty(), "expected no findings: {:?}", findings);
}
