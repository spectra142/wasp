use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use wasp::modules::Module;

fn tlsaudit_only_config() -> anyhow::Result<wasp::config::Config> {
    let mut config = wasp::config::Config::load(None)?;
    config.modules.recon.enabled = false;
    config.modules.portscan.enabled = false;
    config.modules.web.enabled = false;
    config.modules.secrets.enabled = false;
    config.modules.nmap.enabled = false;
    config.modules.nuclei.enabled = false;
    config.modules.testssl.enabled = false;
    config.modules.cms.enabled = false;
    config.modules.webvulns.enabled = false;
    config.scanner.timeout_ms = 2000;
    Ok(config)
}

#[tokio::test]
async fn tlsaudit_detects_self_signed_local_server() -> anyhow::Result<()> {
    let cert = CertificateDer::from_pem_slice(include_bytes!("fixtures/selfsigned.pem"))?;
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/selfsigned.key"))?;

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });

    let config = tlsaudit_only_config()?;
    let target = wasp::target::Target::parse(&format!("127.0.0.1:{}", port))?;
    let findings = wasp::modules::tlsaudit::TlsAudit
        .run(&target, &config)
        .await?;

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    assert!(
        titles.contains(&"Supported TLS versions"),
        "versions not detected: {:?}",
        titles
    );
    assert!(
        titles.contains(&"Supported TLS cipher suites"),
        "ciphers not detected: {:?}",
        titles
    );
    assert!(
        titles.contains(&"Self-signed TLS certificate"),
        "self-signed not detected: {:?}",
        titles
    );
    assert!(
        titles.contains(&"TLS certificate SANs"),
        "SANs not detected: {:?}",
        titles
    );

    Ok(())
}

#[tokio::test]
async fn tlsaudit_handles_unreachable_service() -> anyhow::Result<()> {
    let config = tlsaudit_only_config()?;
    let target = wasp::target::Target::parse("127.0.0.1:65432")?;
    let findings = wasp::modules::tlsaudit::TlsAudit
        .run(&target, &config)
        .await?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "TLS service unreachable");
    Ok(())
}
