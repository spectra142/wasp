use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wasp::config::Config;
use wasp::modules::cmsenum::CmsEnum;
use wasp::modules::Module;
use wasp::target::Target;

#[derive(Clone)]
struct MockResponse {
    status: u16,
    body: String,
    location: Option<String>,
}

fn ok(body: impl Into<String>) -> MockResponse {
    MockResponse {
        status: 200,
        body: body.into(),
        location: None,
    }
}

fn redirect(location: impl Into<String>) -> MockResponse {
    MockResponse {
        status: 302,
        body: String::new(),
        location: Some(location.into()),
    }
}

fn not_found() -> MockResponse {
    MockResponse {
        status: 404,
        body: "Not Found".into(),
        location: None,
    }
}

fn build_http_response(resp: &MockResponse) -> String {
    let reason = match resp.status {
        200 => "OK",
        302 => "Found",
        404 => "Not Found",
        _ => "OK",
    };
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        reason,
        resp.body.len()
    );
    if let Some(loc) = &resp.location {
        headers.push_str(&format!("Location: {}\r\n", loc));
    }
    format!("{}\r\n{}", headers, resp.body)
}

async fn mock_server(listener: TcpListener, responses: HashMap<String, MockResponse>) {
    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let responses = responses.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let request = String::from_utf8_lossy(&buf[..n]);
            let first = request.lines().next().unwrap_or("");
            let parts: Vec<&str> = first.split_whitespace().collect();
            let path = parts.get(1).unwrap_or(&"/").to_string();

            let resp = if path.starts_with("/?author=") {
                redirect("/author/admin/")
            } else {
                responses.get(&path).cloned().unwrap_or_else(not_found)
            };

            let _ = socket
                .write_all(build_http_response(&resp).as_bytes())
                .await;
        });
    }
}

fn wordpress_responses() -> HashMap<String, MockResponse> {
    let mut map = HashMap::new();
    map.insert(
        "/".to_string(),
        ok(r#"<html><head><meta name="generator" content="WordPress 6.4.3"><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"></head><body>Hello</body></html>"#),
    );
    map.insert(
        "/wp-login.php".to_string(),
        ok("<form><input id=\"wp-submit\"></form>"),
    );
    map.insert(
        "/xmlrpc.php".to_string(),
        ok("XML-RPC server accepts POST requests only."),
    );
    map.insert(
        "/wp-json/wp/v2/users".to_string(),
        ok(r#"[{"id":1,"slug":"admin","name":"Administrator"}]"#),
    );
    map.insert(
        "/wp-content/plugins/contact-form-7/readme.txt".to_string(),
        ok("=== Contact Form 7 ===\nStable tag: 5.8.1\n"),
    );
    map.insert(
        "/wp-content/themes/twentytwentyfour/style.css".to_string(),
        ok("Theme Name: Twenty Twenty Four\nVersion: 1.0\n"),
    );
    map.insert("/author/admin/".to_string(), ok("<h1>Author: admin</h1>"));
    map
}

#[tokio::test]
async fn cmsenum_detects_wordpress_and_enumerates() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(mock_server(listener, wordpress_responses()));

    let target = Target::parse(&format!("127.0.0.1:{}", port)).unwrap();
    let mut config = Config::load(None).unwrap();
    config.modules.cms.enabled = true;
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;
    config.scanner.timeout_ms = 2000;

    let findings = CmsEnum.run(&target, &config).await.unwrap();

    server.abort();

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    assert!(
        titles.iter().any(|t| t.contains("WordPress detected")),
        "expected WordPress detection, got {:?}",
        titles
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("WordPress XML-RPC enabled")),
        "expected XML-RPC finding"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("WordPress REST API user leakage")),
        "expected REST API user leakage finding"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("WordPress plugin detected: contact-form-7")),
        "expected contact-form-7 plugin finding"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("WordPress theme detected: twentytwentyfour")),
        "expected twentytwentyfour theme finding"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("WordPress author ID enumeration")),
        "expected author enumeration finding"
    );
}
