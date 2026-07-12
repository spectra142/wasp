mod common;

use common::{TestServer, find_finding, temp_wordlist, test_config, wait_for_server};
use wasp::finding::Severity;
use wasp::modules::{Module, secrets::Secrets};
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
    assert!(
        finding
            .evidence
            .iter()
            .any(|e| e.contains("AKIAIOSFODNN7EXAMPLE"))
    );
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
        Some(Severity::Low)
    );
}

#[tokio::test]
async fn secrets_module_returns_empty_when_wordlist_missing() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.path_wordlist = std::path::PathBuf::from("/nonexistent/wordlist.txt");

    let findings = Secrets.run(&target, &config).await.unwrap();

    assert!(
        findings.is_empty(),
        "expected empty findings: {:?}",
        findings
    );
}
