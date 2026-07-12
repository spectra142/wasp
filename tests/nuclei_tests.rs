mod common;

use common::{TestServer, find_finding, test_config, wait_for_server};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;
use wasp::finding::Severity;
use wasp::modules::{Module, nuclei::Nuclei};
use wasp::target::Target;

/// Create a fake nuclei binary that emits one JSON-line finding for the
/// requested URL and exits successfully.
fn fake_nuclei_binary() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = dir.path().join("nuclei");
    let script = r#"#!/bin/sh
# Fake nuclei: expect -u <url> -j and emit one JSON finding for that URL.
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -u) url="$2"; shift 2 ;;
        -j) shift ;;
        *) shift ;;
    esac
done

cat <<JSON
{"template-id":"fake-cve","host":"${url}","matched-at":"${url}/vuln","extracted-results":["poc"],"info":{"name":"Fake Nuclei Finding","severity":"high","description":"Finding from fake nuclei","remediation":"Patch the fake vulnerability"}}
JSON
"#;
    std::fs::write(&path, script).expect("failed to write fake nuclei");
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("failed to chmod fake nuclei");
    (dir, path)
}

#[tokio::test]
async fn nuclei_module_parses_json_line_finding() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;
    let (_dir, fake_path) = fake_nuclei_binary();
    config.tools.nuclei_path = fake_path;

    let findings = Nuclei.run(&target, &config).await.unwrap();

    let finding =
        find_finding(&findings, "nuclei", "Fake Nuclei Finding").expect("missing nuclei finding");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.description, "Finding from fake nuclei");
    assert_eq!(finding.remediation, "Patch the fake vulnerability");
    assert!(
        finding.evidence.iter().any(|e| e.contains("fake-cve")),
        "template id not in evidence: {:?}",
        finding.evidence
    );
    assert!(
        finding.evidence.iter().any(|e| e.contains("/vuln")),
        "matched-at not in evidence: {:?}",
        finding.evidence
    );
    assert!(
        finding.evidence.iter().any(|e| e.contains("poc")),
        "extracted result not in evidence: {:?}",
        finding.evidence
    );
}

#[tokio::test]
async fn nuclei_module_skips_when_binary_missing_and_configured_to_skip() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.tools.nuclei_path = PathBuf::from("/definitely/not/nuclei");
    config.tools.skip_missing_tools = true;

    let findings = Nuclei.run(&target, &config).await.unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Nuclei scanner unavailable");
    assert_eq!(findings[0].severity, Severity::Info);
}

#[tokio::test]
async fn nuclei_module_errors_when_binary_missing_and_skip_is_false() {
    let server = TestServer::start().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.tools.nuclei_path = PathBuf::from("/definitely/not/nuclei");
    config.tools.skip_missing_tools = false;

    let result = Nuclei.run(&target, &config).await;

    assert!(
        result.is_err(),
        "expected error when nuclei missing and skip_missing_tools=false"
    );
}
