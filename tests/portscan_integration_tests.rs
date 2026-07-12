mod common;

use common::{TestServer, find_finding, test_config, wait_for_server};
use wasp::modules::{Module, portscan::Portscan};
use wasp::scanner::Scanner;
use wasp::target::Target;

const PORT_RANGE_BASE: u16 = 12000;
const PORT_RANGE_COUNT: u16 = 1000;

#[tokio::test]
async fn portscan_banner_grab_returns_service_banner() {
    let server = TestServer::start_in_range(PORT_RANGE_BASE, PORT_RANGE_COUNT).await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.portscan.enabled = true;
    config.modules.portscan.top_ports = server.port() as usize;
    config.modules.portscan.banner_grab = true;
    config.modules.portscan.banner_bytes = 256;

    let findings = Portscan.run(&target, &config).await.unwrap();

    let summary = find_finding(&findings, "portscan", "Port scan summary")
        .expect("port scan summary missing");
    assert!(
        summary
            .evidence
            .iter()
            .any(|e| e.contains(&server.port().to_string())),
        "open port {} not in summary evidence: {:?}",
        server.port(),
        summary.evidence
    );
}

#[tokio::test]
async fn scanner_runs_portscan_and_web_modules_concurrently() {
    let server = TestServer::start_in_range(PORT_RANGE_BASE, PORT_RANGE_COUNT).await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.recon.enabled = false;
    config.modules.portscan.enabled = true;
    config.modules.portscan.top_ports = server.port() as usize;
    config.modules.portscan.banner_grab = false;
    config.modules.web.enabled = true;
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;
    config.modules.web.check_tls_cert = false;
    config.modules.secrets.enabled = false;

    let scanner = Scanner::new(config).with_rate_limit(None);
    let report = scanner.run(&target).await.unwrap();

    let portscan_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.module == "portscan")
        .collect();
    let web_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.module == "web")
        .collect();

    assert!(
        !portscan_findings.is_empty(),
        "expected portscan findings: {:?}",
        report.findings
    );
    assert!(
        !web_findings.is_empty(),
        "expected web findings: {:?}",
        report.findings
    );
}
