mod common;

use common::{find_finding, test_config, wait_for_server, TestServer};
use wasp::finding::Severity;
use wasp::modules::{web::Web, Module};
use wasp::target::Target;

#[tokio::test]
async fn web_module_reports_missing_security_headers() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let config = test_config();

    let findings = Web.run(&target, &config).await.unwrap();

    let expected = [
        ("HSTS", Severity::High),
        ("CSP", Severity::Medium),
        ("X-Frame-Options", Severity::Medium),
        ("X-Content-Type-Options", Severity::Medium),
        ("Referrer-Policy", Severity::Low),
        ("Permissions-Policy", Severity::Low),
    ];

    for (name, severity) in &expected {
        let finding = find_finding(&findings, "web", name)
            .unwrap_or_else(|| panic!("missing {} finding: {:?}", name, findings));
        assert_eq!(finding.severity, *severity, "{} severity mismatch", name);
    }
}

#[tokio::test]
async fn web_module_reports_server_banner() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let config = test_config();

    let findings = Web.run(&target, &config).await.unwrap();

    let finding = find_finding(&findings, "web", "Server banner disclosed")
        .expect("server banner finding missing");
    assert_eq!(finding.severity, Severity::Low);
    assert!(finding
        .evidence
        .iter()
        .any(|e| e.contains("test-server/1.0")));
}

#[tokio::test]
async fn web_module_reports_insecure_cookie_flags() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let config = test_config();

    let findings = Web.run(&target, &config).await.unwrap();

    for flag in ["HttpOnly", "Secure", "SameSite"] {
        assert!(
            find_finding(&findings, "web", &format!("Cookie missing {} flag", flag)).is_some(),
            "missing cookie {} flag finding: {:?}",
            flag,
            findings
        );
    }
}

#[tokio::test]
async fn web_module_reports_http_without_https_redirect() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    // Enable HTTPS so the redirect check is performed, but keep TLS cert check off
    // because the fixture does not speak TLS.
    config.modules.web.check_https = true;
    config.modules.web.check_tls_cert = false;

    let findings = Web.run(&target, &config).await.unwrap();

    let finding = find_finding(&findings, "web", "HTTP does not redirect to HTTPS")
        .expect("missing HTTP-to-HTTPS redirect finding");
    assert_eq!(finding.severity, Severity::High);
}

#[tokio::test]
async fn web_module_returns_no_header_findings_when_disabled() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.web.check_headers = false;
    config.modules.web.check_cookies = false;

    let findings = Web.run(&target, &config).await.unwrap();

    assert!(
        !findings.iter().any(|f| f.title.contains("HSTS")),
        "HSTS finding should be disabled: {:?}",
        findings
    );
}
