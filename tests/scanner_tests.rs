mod common;

use common::{TestServer, temp_wordlist, test_config, wait_for_server};
use wasp::scanner::Scanner;
use wasp::target::Target;

#[tokio::test]
async fn scanner_runs_web_and_secrets_modules_concurrently() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();

    // Enable only the HTTP-based modules to keep the test fast and deterministic.
    config.modules.recon.enabled = false;
    config.modules.portscan.enabled = false;
    config.modules.web.enabled = true;
    config.modules.web.check_https = false;
    config.modules.web.check_tls_cert = false;
    config.modules.secrets.enabled = true;
    config.modules.secrets.enable_body_regex = true;
    let (_wordlist, path) = temp_wordlist(&[".env"]);
    config.modules.secrets.path_wordlist = path;

    let scanner = Scanner::new(config);
    let report = scanner.run(&target).await.unwrap();

    let web_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.module == "web")
        .collect();
    let secrets_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.module == "secrets")
        .collect();

    assert!(
        !web_findings.is_empty(),
        "expected web findings: {:?}",
        report.findings
    );
    assert!(
        !secrets_findings.is_empty(),
        "expected secrets findings: {:?}",
        report.findings
    );

    // Report should be finalized (findings sorted by descending severity).
    let severities: Vec<_> = report.findings.iter().map(|f| f.severity).collect();
    let mut sorted = severities.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(
        severities, sorted,
        "report findings are not sorted by severity"
    );
}
