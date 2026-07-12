mod common;

use common::{find_finding, test_config, wait_for_server, TestServer};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use wasp::finding::Severity;
use wasp::modules::{nmap::Nmap, Module};
use wasp::target::Target;

/// Create a fake nmap binary that emits XML with a single open port.
///
/// The script is placed in a temporary directory and marked executable.
/// Keeping the `TempDir` alive ensures the binary remains on disk.
fn fake_nmap_binary(port: u16) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = dir.path().join("nmap");
    let script = format!(
        r#"#!/bin/sh
cat <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="{}">
        <state state="open"/>
        <service name="http" product="fake-server" version="1.0.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
XML
"#,
        port
    );
    std::fs::write(&path, script).expect("failed to write fake nmap");
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("failed to chmod fake nmap");
    (dir, path)
}

#[tokio::test]
async fn nmap_module_detects_open_port_from_xml() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.portscan.enabled = true;
    config.modules.portscan.top_ports = 10;
    let (_dir, fake_path) = fake_nmap_binary(server.port());
    config.tools.nmap_path = fake_path;

    let findings = Nmap.run(&target, &config).await.unwrap();

    let summary =
        find_finding(&findings, "nmap", "Nmap port scan summary").expect("nmap summary missing");
    assert!(
        summary
            .evidence
            .iter()
            .any(|e| e.contains(&server.port().to_string())),
        "port {} not in summary evidence: {:?}",
        server.port(),
        summary.evidence
    );

    let port_finding = find_finding(
        &findings,
        "nmap",
        &format!("Open port {}/tcp", server.port()),
    )
    .expect("missing open-port finding");
    assert_eq!(port_finding.severity, Severity::Info);
    assert!(port_finding
        .evidence
        .iter()
        .any(|e| e.contains("fake-server")));
}

#[tokio::test]
async fn nmap_module_skips_when_binary_missing_and_configured_to_skip() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.tools.nmap_path = PathBuf::from("/definitely/not/nmap");
    config.tools.skip_missing_tools = true;

    let findings = Nmap.run(&target, &config).await.unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "nmap unavailable");
    assert_eq!(findings[0].severity, Severity::Info);
}

#[tokio::test]
async fn nmap_module_errors_when_binary_missing_and_skip_is_false() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.tools.nmap_path = PathBuf::from("/definitely/not/nmap");
    config.tools.skip_missing_tools = false;

    let result = Nmap.run(&target, &config).await;

    assert!(
        result.is_err(),
        "expected error when nmap missing and skip_missing_tools=false"
    );
}

#[tokio::test]
async fn real_nmap_binary_detects_open_port() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;

    let output = Command::new("nmap")
        .args([
            "-sT",
            "-p",
            &server.port().to_string(),
            "--open",
            "-T5",
            "--max-retries",
            "0",
            "--host-timeout",
            "10s",
            "127.0.0.1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    assert!(
        output.is_ok(),
        "failed to execute real nmap (is it installed?): {:?}",
        output
    );
    let output = output.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "nmap exited with error: stdout={} stderr={}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("open"),
        "nmap did not report the port as open: {}",
        stdout
    );
}

#[tokio::test]
async fn real_nmap_scan_respects_timeout() {
    let _config = test_config();

    let result = timeout(
        Duration::from_secs(10),
        Command::new("nmap")
            .args([
                "-sT",
                "-p",
                "1",
                "--max-retries",
                "0",
                "--host-timeout",
                "5s",
                "127.0.0.1",
            ])
            .output(),
    )
    .await;

    assert!(
        result.is_ok(),
        "nmap scan hung beyond the test timeout: {:?}",
        result
    );
}
