mod common;

use common::{find_finding, test_config, wait_for_server, CmsTestServer};
use wasp::finding::Severity;
use wasp::modules::{cmsenum::CmsEnum, Module};
use wasp::target::Target;

#[tokio::test]
async fn cmsenum_detects_wordpress_via_generator_tag() {
    let server = CmsTestServer::wordpress().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.cmsenum.enabled = true;
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;

    let findings = CmsEnum.run(&target, &config).await.unwrap();

    let wp = find_finding(&findings, "cmsenum", "WordPress detected")
        .expect("missing WordPress detection finding");
    assert!(
        wp.evidence.iter().any(|e| e.contains("generator")),
        "WordPress evidence missing generator indicator: {:?}",
        wp.evidence
    );
}

#[tokio::test]
async fn cmsenum_detects_wordpress_via_login_page() {
    let server = CmsTestServer::wordpress().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.cmsenum.enabled = true;
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;

    let findings = CmsEnum.run(&target, &config).await.unwrap();

    let wp = find_finding(&findings, "cmsenum", "WordPress detected")
        .expect("missing WordPress detection finding");
    assert!(
        wp.evidence
            .iter()
            .any(|e| e.contains("wp-login") || e.contains("wp-submit")),
        "WordPress evidence missing login indicator: {:?}",
        wp.evidence
    );
}

#[tokio::test]
async fn cmsenum_assigns_medium_severity_for_high_confidence_wordpress() {
    let server = CmsTestServer::wordpress().await;
    wait_for_server(&server.addr(), 1000).await;
    let target = Target::parse(&server.addr()).unwrap();
    let mut config = test_config();
    config.modules.cmsenum.enabled = true;
    config.modules.web.check_http = true;
    config.modules.web.check_https = false;

    let findings = CmsEnum.run(&target, &config).await.unwrap();

    let wp = find_finding(&findings, "cmsenum", "WordPress detected")
        .expect("missing WordPress detection finding");
    // High-confidence CMS detection now maps to Medium severity.
    assert_eq!(wp.severity, Severity::Medium);
}
