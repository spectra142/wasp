use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wasp::{config::Config, modules::cms::Cms, modules::Module, target::Target};

#[tokio::test]
async fn detects_wordpress_via_generator_tag_and_missing_wpscan_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => continue,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("/");

            let (status, body) = match path {
                "/" => (
                    "200 OK",
                    r#"<html><head><meta name="generator" content="WordPress 6.4.3"></head><body></body></html>"#,
                ),
                "/wp-login.php" => ("200 OK", r#"<input name="wp-submit">"#),
                "/readme.html" => ("200 OK", "WordPress"),
                _ => ("404 Not Found", "not found"),
            };

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    let mut config = Config::load(None).unwrap();
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;
    config.tools.wpscan_path = PathBuf::from("/nonexistent/wpscan");
    config.tools.skip_missing_tools = true;

    let target = Target::parse(&format!("127.0.0.1:{}", port)).unwrap();
    let findings = Cms.run(&target, &config).await.unwrap();

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    assert!(
        titles.iter().any(|t| t.contains("WordPress detected")),
        "expected WordPress detection finding, got {:?}",
        titles
    );
    assert!(
        titles.iter().any(|t| t.contains("WPScan unavailable")),
        "expected WPScan unavailable finding, got {:?}",
        titles
    );
}
