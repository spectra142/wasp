mod common;

use common::{find_finding, temp_wordlist, test_config, wait_for_server, TestServer};
use wasp::finding::Severity;
use wasp::modules::{secrets::Secrets, Module};
use wasp::target::Target;

#[tokio::test]
async fn secrets_module_detects_exposed_env_file() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.enable_body_regex = false;
    let (_wordlist, path) = temp_wordlist(&[".env"]);
    config.modules.secrets.path_wordlist = path;

    let findings = Secrets.run(&target, &config).await.unwrap();

    let finding = find_finding(&findings, "secrets", "Exposed path found: .env")
        .expect("missing .env exposed path finding");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.evidence.iter().any(|e| e.contains("DB_PASSWORD")));
}

#[tokio::test]
async fn secrets_module_detects_aws_key_leak() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.enable_body_regex = true;
    let (_wordlist, path) = temp_wordlist(&[".env"]);
    config.modules.secrets.path_wordlist = path;

    let findings = Secrets.run(&target, &config).await.unwrap();

    let finding = find_finding(&findings, "secrets", "AWS Access Key ID")
        .expect("missing AWS key leak finding");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding
        .evidence
        .iter()
        .any(|e| e.contains("AKIA********MPLE")));
    // The raw credential must never be copied into the report.
    assert!(findings
        .iter()
        .flat_map(|f| f.evidence.iter())
        .all(|e| !e.contains("AKIAIOSFODNN7EXAMPLE")));
}

#[tokio::test]
async fn secrets_module_detects_github_token_leak() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.enable_body_regex = true;
    let (_wordlist, path) = temp_wordlist(&[".env"]);
    config.modules.secrets.path_wordlist = path;

    let findings = Secrets.run(&target, &config).await.unwrap();

    assert!(
        find_finding(&findings, "secrets", "GitHub Token").is_some(),
        "missing GitHub token leak finding: {:?}",
        findings
    );
}

#[tokio::test]
async fn secrets_module_detects_generic_api_key() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.enable_body_regex = true;
    let (_wordlist, path) = temp_wordlist(&["api-keys"]);
    config.modules.secrets.path_wordlist = path;

    let findings = Secrets.run(&target, &config).await.unwrap();

    assert!(
        find_finding(&findings, "secrets", "Generic API Key").is_some(),
        "missing generic API key finding: {:?}",
        findings
    );
}

#[tokio::test]
async fn secrets_module_assigns_severity_by_path() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.enable_body_regex = false;
    let (_wordlist, path) = temp_wordlist(&[".env", "admin", "robots.txt"]);
    config.modules.secrets.path_wordlist = path;

    let findings = Secrets.run(&target, &config).await.unwrap();

    assert_eq!(
        find_finding(&findings, "secrets", ".env").map(|f| f.severity),
        Some(Severity::High)
    );
    assert_eq!(
        find_finding(&findings, "secrets", "admin").map(|f| f.severity),
        Some(Severity::Medium)
    );
    assert_eq!(
        find_finding(&findings, "secrets", "robots.txt").map(|f| f.severity),
        Some(Severity::Info)
    );
}

#[tokio::test]
async fn secrets_module_falls_back_to_builtin_wordlist_when_missing() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.path_wordlist = std::path::PathBuf::from("/nonexistent/wordlist.txt");

    let findings = Secrets.run(&target, &config).await.unwrap();

    // The built-in list includes `.env`, which the fixture serves.
    assert!(
        find_finding(&findings, "secrets", "Exposed path found: .env").is_some(),
        "expected built-in wordlist to be used: {:?}",
        findings
    );
}

/// Servers that answer every path with the same page (SPAs, catch-all routes)
/// must not produce an "exposed path" finding for every wordlist entry.
#[tokio::test]
async fn secrets_module_ignores_catch_all_soft_404_pages() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let body = "<html><body><div id=\"root\"></div></body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    let target = Target::parse(&addr.to_string()).unwrap();
    let mut config = test_config();
    config.modules.secrets.check_https = false;
    let (_wordlist, path) = temp_wordlist(&[".env", "backup.zip", "admin/", ".git/config"]);
    config.modules.secrets.path_wordlist = path;

    let findings = Secrets.run(&target, &config).await.unwrap();
    assert!(
        !findings
            .iter()
            .any(|f| f.title.starts_with("Exposed path found")),
        "catch-all server produced false positives: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
