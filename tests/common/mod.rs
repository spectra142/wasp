#![allow(dead_code)]

use rustls::pki_types::pem::PemObject;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use wasp::config::Config;

/// A reusable local HTTP server fixture for integration tests.
///
/// The server exposes several endpoints that exercise the web, secrets,
/// portscan, nmap, webvulns and cmsenum modules:
///
/// * `/`          - plain HTML with no security headers and an insecure cookie
/// * `/.env`      - fake environment file with leaked secrets
/// * `/admin`     - admin panel with a server banner and an insecure cookie
/// * `/api`       - JSON API response with a partially-secured cookie
/// * `/robots.txt` - robots file referencing sensitive paths
/// * `/api-keys`  - response containing a generic API key pattern
/// * `/cors`      - reflects arbitrary Origin headers (CORS misconfiguration)
/// * `/open-redirect?url=...` - redirects to the supplied URL
/// * `/trace`     - reflects the request if the method is TRACE
/// * `/options`   - responds to OPTIONS with a broad Allow header
/// * `/config.json`, `/backup.zip`, `/.git/config` - sensitive file probes
/// * `/wp-login.php`, `/wp-admin/`, `/readme.html`, `/xmlrpc.php` - WordPress probes
/// * `/user/login`, `/CHANGELOG.txt`, `/sites/default/` - Drupal probes
/// * `/administrator/`, `/README.txt`, `/media/jui/` - Joomla probes
/// * any other path returns 404
pub struct TestServer {
    port: u16,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Bind to a random loopback port and start the server.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self::from_listener(listener).await
    }

    /// Try to bind to a port in the inclusive range `[base, base + count]`.
    ///
    /// If no port in the range is free, falls back to a random port.
    /// This is useful for tests that need the server's port to fall within a
    /// known range (e.g. port scanners that scan `1..=top_ports`).
    pub async fn start_in_range(base: u16, count: u16) -> Self {
        for port in base..=base.saturating_add(count) {
            if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                return Self::from_listener(listener).await;
            }
        }
        Self::start().await
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

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }
}

async fn handle_request(mut socket: TcpStream) {
    let (reader, mut writer) = socket.split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    let request_line = request_line.trim_end();

    // Bare newline or empty probe: serve the root page without reading headers.
    let (method, path) = if request_line.is_empty() {
        ("GET".to_string(), "/")
    } else {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        (
            parts.first().copied().unwrap_or("GET").to_uppercase(),
            parts.get(1).copied().unwrap_or("/"),
        )
    };

    // Consume headers and capture a few useful ones.
    let mut headers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if !request_line.is_empty() {
        let mut header = String::new();
        loop {
            header.clear();
            match buf_reader.read_line(&mut header).await {
                Ok(0) => break,
                Err(_) => return,
                _ => {}
            }
            if header == "\r\n" || header == "\n" {
                break;
            }
            if let Some((k, v)) = header.trim_end().split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
    }

    let (status, resp_headers, body) = build_response(&method, path, &headers);

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
    headers: &std::collections::HashMap<String, String>,
) -> (u16, String, String) {
    // Missing security headers on most endpoints so the web module has findings.
    match path {
        "/" => (
            200,
            "Server: test-server/1.0\r\nSet-Cookie: session=abc123; Path=/\r\n".to_string(),
            "<html><body>Home</body></html>".to_string(),
        ),
        "/admin" => (
            200,
            "Server: nginx/1.18.0\r\nSet-Cookie: admin=1; Path=/\r\n".to_string(),
            "<html>Admin panel</html>".to_string(),
        ),
        "/api" => (
            200,
            "Server: test-api/2.0\r\nSet-Cookie: token=value; Path=/; Secure\r\n".to_string(),
            "{\"status\":\"ok\"}".to_string(),
        ),
        "/robots.txt" => (
            200,
            String::new(),
            "User-agent: *\nDisallow: /admin\nDisallow: /api\n".to_string(),
        ),
        "/.env" => (
            200,
            String::new(),
            "DB_PASSWORD=secret\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN=ghp_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n".to_string(),
        ),
        "/api-keys" => (
            200,
            String::new(),
            "api_key: \"abcd1234abcd1234abcd1234\"\n".to_string(),
        ),
        // Vulnerability endpoints.
        "/cors" => {
            let origin = headers
                .get("origin")
                .cloned()
                .unwrap_or_else(|| "*".to_string());
            (
                200,
                format!(
                    "Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Credentials: true\r\n",
                    origin
                ),
                "{}".to_string(),
            )
        }
        path if path.starts_with("/open-redirect") => {
            let location = extract_query_param(path, "url")
                .or_else(|| extract_query_param(path, "next"))
                .or_else(|| extract_query_param(path, "redirect"))
                .or_else(|| extract_query_param(path, "return"))
                .or_else(|| extract_query_param(path, "returnUrl"))
                .unwrap_or_else(|| "/".to_string());
            (
                302,
                format!("Location: {}\r\n", location),
                String::new(),
            )
        }
        "/trace" => {
            if method == "TRACE" {
                (
                    200,
                    String::new(),
                    "TRACE /trace HTTP/1.1".to_string(),
                )
            } else {
                (405, String::new(), "method not allowed".to_string())
            }
        }
        "/options" => {
            if method == "OPTIONS" {
                (
                    200,
                    "Allow: GET, POST, PUT, DELETE, TRACE, PATCH\r\n".to_string(),
                    String::new(),
                )
            } else {
                (405, String::new(), "method not allowed".to_string())
            }
        }
        "/config.json" => (
            200,
            String::new(),
            "{\"db_password\":\"secret\",\"api_key\":\" leaked\"}".to_string(),
        ),
        "/backup.zip" => (200, String::new(), "PKfake-zip-content".to_string()),
        "/.git/config" => (
            200,
            String::new(),
            "[core] repositoryformatversion = 0".to_string(),
        ),
        "/web.config" => (200, String::new(), "<configuration></configuration>".to_string()),
        "/phpinfo.php" => (200, String::new(), "<html><body>phpinfo()</body></html>".to_string()),
        // CMS probe endpoints.
        "/wp-login.php" => (
            200,
            String::new(),
            r#"<html><form><input name="wp-submit"></form></html>"#.to_string(),
        ),
        "/wp-admin/" => (
            200,
            String::new(),
            "<html>wp-admin</html>".to_string(),
        ),
        "/readme.html" => (200, String::new(), "WordPress".to_string()),
        "/xmlrpc.php" => (
            200,
            String::new(),
            "XML-RPC server accepts POST requests".to_string(),
        ),
        "/wp-content/" => (200, String::new(), "Index of /wp-content/".to_string()),
        "/user/login" => (
            200,
            String::new(),
            r#"<html><form id="user-login-form">Drupal</form></html>"#.to_string(),
        ),
        "/CHANGELOG.txt" => (200, String::new(), "Drupal version history".to_string()),
        "/sites/default/" => (200, String::new(), "Index of /sites/default/".to_string()),
        "/core/install.php" => (200, String::new(), "Drupal".to_string()),
        "/administrator/" => (
            200,
            String::new(),
            r#"<html><form class="form-login">Joomla</form></html>"#.to_string(),
        ),
        "/README.txt" => (200, String::new(), "Joomla".to_string()),
        "/media/jui/" => (200, String::new(), "Index of /media/jui/".to_string()),
        "/templates/" => (200, String::new(), "Index of /templates/".to_string()),
        _ => (404, String::new(), "not found".to_string()),
    }
}

fn extract_query_param(path: &str, key: &str) -> Option<String> {
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// A local HTTP server fixture configured to look like a WordPress site.
///
/// The root page contains a WordPress generator tag and body indicators, and
/// CMS-specific probe paths respond with WordPress markers.
pub struct CmsTestServer {
    port: u16,
    _handle: tokio::task::JoinHandle<()>,
}

impl CmsTestServer {
    pub async fn wordpress() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_wordpress(socket));
            }
        });
        Self {
            port,
            _handle: handle,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

async fn serve_wordpress(mut socket: TcpStream) {
    let (reader, mut writer) = socket.split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    let request_line = request_line.trim_end();
    let path = if request_line.is_empty() {
        "/"
    } else {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        parts.get(1).copied().unwrap_or("/")
    };

    // Consume headers, if any.
    if !request_line.is_empty() {
        let mut header = String::new();
        loop {
            header.clear();
            match buf_reader.read_line(&mut header).await {
                Ok(0) => break,
                Err(_) => return,
                _ => {}
            }
            if header == "\r\n" || header == "\n" {
                break;
            }
        }
    }

    let (status, body) = match path {
        "/" => (
            200,
            r#"<html><head><meta name="generator" content="WordPress 6.4.3"></head><body><link rel="stylesheet" href="/wp-content/themes/foo/style.css"></body></html>"#,
        ),
        "/wp-login.php" => (200, r#"<html><form><input name="wp-submit"></form></html>"#),
        "/wp-admin/" => (200, "<html>wp-admin</html>"),
        "/readme.html" => (200, "WordPress"),
        "/xmlrpc.php" => (200, "XML-RPC server accepts POST requests"),
        "/wp-content/" => (200, "Index of /wp-content/"),
        _ => (404, "not found"),
    };

    let response = format!(
        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = writer.write_all(response.as_bytes()).await;
}

/// Embedded self-signed certificate for the local TLS test fixture.
const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDJzCCAg+gAwIBAgIUZfMqyS69Quna3EozyRfRF1lDmRcwDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDcxMTIyMzkxOFoYDzIxMjYw\n\
NjE3MjIzOTE4WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQCPW46MrqftpnjcHybIRiCh9ijtYL8AxfASiaUQ4sWU\n\
3l4ij9GAfEF1UNilgg+ezWx7FmiB2aIBTXVLLTaQrNIitOTNThePrDp67wEyTn53\n\
sdHXpdmd+tRgmztgR18NsWHG1cDpczORlDmquO/fmvtBnIzkhJRkCbC3WTsxGHZI\n\
6phcjRoWjFILP3elGj0MlcQ/+NMZQhOyqPWt1qEgfl9kWCCBl6azGu79qVfXfrgz\n\
SbOdkvLoD/srg9PJ251dXLY8u7+ht1dTzrcRxqnCvU4CO1MO3DF4jyOQjRE3vQUH\n\
UvFORhrL18uoCu0/syYH+OtGC43r4DJ1+9WPG5r8ll9rAgMBAAGjbzBtMB0GA1Ud\n\
DgQWBBRMRMjEnGs7cXwnsjFpHkyExVb21zAfBgNVHSMEGDAWgBRMRMjEnGs7cXwn\n\
sjFpHkyExVb21zAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9z\n\
dIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAXEj3c2YsQ0H4igL1TnsUEIWVZOhc\n\
1Eg3dhKU99Kz6JprHGNqZRGWQ1M4JtV3W8YpilBM7WXbsrJYXVpZWJom/oVHZmBY\n\
6v9ErVOCCSno9+vQTOCxXzc22YxPa6A8daV89Xvd1tvwPqoyg94uRqqV0/0t3ExH\n\
4rhWkZz/w/aZ9XkkaIiFY39FJa4k9Qj3rtw6SgV4cCgaXyMkzfXYin4VHom4MFYz\n\
Dvov0l3WOJIqmYh5bvXF/HBrFzc2r764cX1N1+F15w6seYNFSH+1NNxxPRw+2JGt\n\
PMzhsqwASwywzUTswMyGyDhRM+KPwzXTd0rpIK1DivwoWFHRWO2WM4PcKg==\n\
-----END CERTIFICATE-----";

const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCPW46Mrqftpnjc\n\
HybIRiCh9ijtYL8AxfASiaUQ4sWU3l4ij9GAfEF1UNilgg+ezWx7FmiB2aIBTXVL\n\
LTaQrNIitOTNThePrDp67wEyTn53sdHXpdmd+tRgmztgR18NsWHG1cDpczORlDmq\n\
uO/fmvtBnIzkhJRkCbC3WTsxGHZI6phcjRoWjFILP3elGj0MlcQ/+NMZQhOyqPWt\n\
1qEgfl9kWCCBl6azGu79qVfXfrgzSbOdkvLoD/srg9PJ251dXLY8u7+ht1dTzrcR\n\
xqnCvU4CO1MO3DF4jyOQjRE3vQUHUvFORhrL18uoCu0/syYH+OtGC43r4DJ1+9WP\n\
G5r8ll9rAgMBAAECggEABVAoKf8O2qzCBvXqmtYF9k9NCpahH+S2JAZQ8wtVtb9m\n\
E+Wzptah0G+itHp+Lv+bEASBqcXIoNIovst1i3gh+DSc1ELR5APG3/DOKjCk/Ww+\n\
hD2fRg7adOXb8W4M4lE/nIdK2fwfZ2AQfIH4moUt33ST91rIj7hP75X2HJQ1BF14\n\
+XJXJp9WUCd0glhgQRmqnj13G4Bd8TCFKhJYVIpjlCp7jdgTUp/job+DPVM4uuFx\n\
eAx7mQ0Trf039h5UmFNeHUvw63LrXtQ2ODn3ZApNGzr71TDAuDqXAj67cV+ph0yL\n\
Ek3Q8gfF13YQt/iJHnx/r1ivrM74g/cU2dmdTeVNVQKBgQDIQT5/bITineeVq3HZ\n\
SgCuYpsZnQ2awC46UXF1BURm44dNS11lHLQtPRC1je/JS+wmNglxiWDU7FpU02GY\n\
kzS6q8nQ7sC57KbdHcMsB+O43Ao5j6DArumT2U4Yz3zF7n8Lxio/+GssnqYZ2I8K\n\
KOsEgOLaVsjiPud612hg9tqSbwKBgQC3Q6XuA5JsDiwcanlXpFtnMf+AVXOzezhR\n\
SPLXvb1MBDNkfR2QNQP3S1HztT9O3SOIUtypoK50fxpqGLEvq2RV/ITHgNWR0DRZ\n\
zD6dFaayytV3SASi74bSI+/T+04pW/zZY7qT7tWd73vUEbDJ0Wh6oJewZBTc0/tT\n\
uyL7re9QxQKBgDbfWebEr60BI8IpVmr6EjG2p1Vfaajr3D7yrioopVOkKSEO86qP\n\
MPfscbWuDPSVr0HRMMlBoZz2ntH7khSi0aINDKIJqhnINPkF/MMF7mprMQoQxzXF\n\
OA/hTbsSr9f0wC9Tv6QDyCpT1qPiaV+ZUrzLLF4zxZvpLLjGab2YJtBVAoGARh2Z\n\
tHClarYZZl3OQxvc5KSabo1DER5Js7/HOYecjyLkTsQXtX6zH8AvgKCNsiylVZju\n\
V+/kDyo5/vGniOd4IfXVD0dZbspL3TdplUwdVTaJaXOiYnxmBqw9K8twYh6RpNKl\n\
Jcgw7pYbuE10aCK4aIJcxt3jpYFtHOHyRnyLnUkCgYEAq0UYdB9iBwwxjps4OGu3\n\
sYQ4j5aO9eaPKn1B4E91iMrEy7Nyfsbd/DsAUCN3V8Y1K1j3aderrRvdR+/2/z4P\n\
+GE/yQqNyz0vgkg5M7A9W7nX+Zm3WOr6sWY57bjA0gZJ7n6LbKnKS6FTDu+zve+R\n\
qMFi/0psxCrSMIlaYHeIU4M=\n\
-----END PRIVATE KEY-----";

/// A reusable local HTTPS server fixture for integration tests.
///
/// The server uses the embedded self-signed certificate in `TEST_CERT_PEM` and
/// `TEST_KEY_PEM`. It accepts any TLS handshake and returns a minimal HTTP
/// response for every request.
pub struct TlsServer {
    port: u16,
    _handle: tokio::task::JoinHandle<()>,
}

impl TlsServer {
    pub async fn start() -> Self {
        // Ensure a Rustls crypto provider is installed for the test process.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let cert = rustls::pki_types::CertificateDer::from_pem_slice(TEST_CERT_PEM.as_bytes())
            .expect("failed to parse embedded TLS certificate");
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(TEST_KEY_PEM.as_bytes())
            .expect("failed to parse embedded TLS key");

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("failed to build TLS server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let handle = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let stream = match acceptor.accept(socket).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("TLS accept failed: {}", e);
                            return;
                        }
                    };
                    serve_tls_request(stream).await;
                });
            }
        });

        Self {
            port,
            _handle: handle,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{}", self.port, path)
    }
}

async fn serve_tls_request<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Consume headers.
    let mut header = String::new();
    loop {
        header.clear();
        if buf_reader.read_line(&mut header).await.is_err() {
            return;
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
    }

    let body = "<html><body>TLS fixture</body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = writer.write_all(response.as_bytes()).await;
}

/// Base test configuration tuned for fast, deterministic local tests.
///
/// HTTPS/TLS checks are disabled by default so tests can run against the
/// plain HTTP fixture. Individual tests can re-enable checks as needed.
pub fn test_config() -> Config {
    let mut config = Config::load(None).unwrap();
    config.scanner.timeout_ms = 2000;
    config.scanner.concurrency = 50;
    config.scanner.max_redirects = 2;
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;
    config.modules.web.check_tls_cert = false;
    config.modules.web.check_headers = true;
    config.modules.web.check_cookies = true;
    config
}

/// Create a temporary wordlist file from the supplied paths.
///
/// The returned `NamedTempFile` must be kept alive for the duration of the
/// test; dropping it deletes the file.
pub fn temp_wordlist(paths: &[&str]) -> (NamedTempFile, PathBuf) {
    let file = NamedTempFile::new().expect("failed to create temp wordlist");
    let content = paths.join("\n");
    std::fs::write(file.path(), content).expect("failed to write temp wordlist");
    let path = file.path().to_path_buf();
    (file, path)
}

/// Short helper to wait for a server to be accepting connections.
pub async fn wait_for_server(addr: &str, timeout_ms: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server did not become ready in time: {}", addr);
}

/// Wait for a TLS server to be accepting connections.
pub async fn wait_for_tls_server(addr: &str, timeout_ms: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("TLS server did not become ready in time: {}", addr);
}

/// Convenience lookup: find the first Finding matching a module and title substring.
pub fn find_finding<'a>(
    findings: &'a [wasp::finding::Finding],
    module: &str,
    title_sub: &str,
) -> Option<&'a wasp::finding::Finding> {
    findings
        .iter()
        .find(|f| f.module == module && f.title.contains(title_sub))
}
