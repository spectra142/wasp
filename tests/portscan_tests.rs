mod common;

use common::{find_finding, test_config, wait_for_server, TestServer};
use wasp::modules::{portscan::Portscan, Module};
use wasp::target::Target;

/// Preferred port range for portscan tests.
///
/// Scanning up to a random high ephemeral port is slow. By binding inside a
/// small, high-but-not-ephemeral range we keep the scan range bounded while
/// avoiding the need for privileged low ports.
const PORT_RANGE_BASE: u16 = 12000;
const PORT_RANGE_COUNT: u16 = 1000;

#[tokio::test]
async fn portscan_detects_open_port() {
    let server = TestServer::start_in_range(PORT_RANGE_BASE, PORT_RANGE_COUNT).await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.portscan.enabled = true;
    config.modules.portscan.top_ports = server.port() as usize;
    config.modules.portscan.banner_grab = false;

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
async fn portscan_reports_individual_open_port() {
    let server = TestServer::start_in_range(PORT_RANGE_BASE, PORT_RANGE_COUNT).await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.portscan.enabled = true;
    config.modules.portscan.top_ports = server.port() as usize;
    config.modules.portscan.banner_grab = false;

    let findings = Portscan.run(&target, &config).await.unwrap();

    assert!(
        find_finding(
            &findings,
            "portscan",
            &format!("Open port {}", server.port())
        )
        .is_some(),
        "missing individual open-port finding: {:?}",
        findings
    );
}

#[tokio::test]
async fn portscan_banner_grab_does_not_crash() {
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
        "open port missing with banner grab enabled: {:?}",
        summary.evidence
    );
}

#[tokio::test]
async fn portscan_returns_empty_when_no_ports_open() {
    // Use a port that is extremely unlikely to be open on loopback.
    let target = Target::parse("127.0.0.1:1").unwrap();
    let mut config = test_config();
    config.modules.portscan.enabled = true;
    config.modules.portscan.top_ports = 1;
    config.modules.portscan.banner_grab = false;

    let findings = Portscan.run(&target, &config).await.unwrap();

    assert!(
        findings.is_empty(),
        "expected empty findings: {:?}",
        findings
    );
}
