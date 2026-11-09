use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::external::{run_tool, tool_available};
use crate::modules::Module;
use crate::target::Target;
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::debug;
use serde::Deserialize;
use std::time::Duration;

pub struct Nmap;

#[async_trait]
impl Module for Nmap {
    fn name(&self) -> &'static str {
        "nmap"
    }

    fn description(&self) -> &'static str {
        "Nmap service/version detection port scanner"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let nmap_path = &config.tools.nmap_path;

        if !tool_available(nmap_path).await {
            if config.tools.skip_missing_tools {
                debug!("nmap not available at {:?}, skipping", nmap_path);
                return Ok(vec![Finding::new(
                    "nmap",
                    "nmap unavailable",
                    Severity::Info,
                    "The configured nmap binary could not be found on the system",
                )
                .with_evidence(format!("nmap_path: {:?}", nmap_path))]);
            }
            anyhow::bail!("nmap not found at {:?}", nmap_path);
        }

        let host = target.host();
        let top_ports = config.modules.portscan.top_ports.clamp(1, 65535);
        let top_ports_str = top_ports.to_string();
        // -Pn treats the host as up so the scan proceeds even when ICMP/ping is
        // filtered, which is common in proxy/TOR/VPN and hardened environments.
        let mut args = vec!["-oX", "-", "-Pn", "-sV", "--top-ports", &top_ports_str];
        if matches!(target.host, url::Host::Ipv6(_)) {
            args.push("-6");
        }
        // `--` stops option parsing so a hostile hostname cannot inject flags.
        args.push("--");
        args.push(&host);

        let output = run_tool(
            nmap_path,
            &args,
            Duration::from_secs(config.tools.nmap_timeout_secs),
        )
        .await
        .context("failed to run nmap")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nmap exited with status {}: {}", output.status, stderr);
        }

        let xml = String::from_utf8_lossy(&output.stdout);
        parse_nmap_xml(&xml, &host)
    }
}

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
struct Host {
    #[serde(rename = "status")]
    status: Option<Status>,
    #[serde(rename = "ports")]
    ports: Option<Ports>,
}

#[derive(Debug, Deserialize)]
struct Status {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct Ports {
    #[serde(rename = "port", default)]
    ports: Vec<Port>,
}

#[derive(Debug, Deserialize)]
struct Port {
    #[serde(rename = "@portid")]
    portid: String,
    #[serde(rename = "@protocol")]
    protocol: String,
    state: PortState,
    service: Option<Service>,
}

#[derive(Debug, Deserialize)]
struct PortState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct Service {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extrainfo: Option<String>,
}

fn parse_nmap_xml(xml: &str, host: &str) -> Result<Vec<Finding>> {
    let run: NmapRun = quick_xml::de::from_str(xml).context("failed to parse nmap XML output")?;

    let mut findings = Vec::new();
    let mut open_ports: Vec<String> = Vec::new();

    for host_entry in &run.hosts {
        if let Some(status) = &host_entry.status {
            if status.state != "up" {
                debug!("nmap reports host {} as {}", host, status.state);
                continue;
            }
        }

        if let Some(ports) = &host_entry.ports {
            for port in &ports.ports {
                if port.state.state != "open" {
                    continue;
                }

                let service_name = port
                    .service
                    .as_ref()
                    .and_then(|s| s.name.as_ref())
                    .map(String::as_str)
                    .unwrap_or("unknown");

                let mut details = vec![format!("Port {}/{}", port.portid, port.protocol)];

                if let Some(service) = &port.service {
                    if let Some(name) = &service.name {
                        details.push(format!("Service: {}", name));
                    }
                    if let Some(product) = &service.product {
                        details.push(format!("Product: {}", product));
                    }
                    if let Some(version) = &service.version {
                        details.push(format!("Version: {}", version));
                    }
                    if let Some(extrainfo) = &service.extrainfo {
                        details.push(format!("Extra info: {}", extrainfo));
                    }
                }

                let port_label = format!("{}/{}", port.portid, port.protocol);
                open_ports.push(port_label.clone());

                findings.push(
                    Finding::new(
                        "nmap",
                        &format!("Open port {} ({})", port_label, service_name),
                        Severity::Info,
                        "Nmap discovered an open port with service/version detection",
                    )
                    .with_evidence(details.join(" | "))
                    .with_remediation(
                        "Close ports that are not required and ensure exposed services are patched.",
                    ),
                );
            }
        }
    }

    if !open_ports.is_empty() {
        findings.insert(
            0,
            Finding::new(
                "nmap",
                "Nmap port scan summary",
                Severity::Info,
                &format!(
                    "Nmap discovered {} open port(s) on {}",
                    open_ports.len(),
                    host
                ),
            )
            .with_evidence(format!("Open ports: {}", open_ports.join(", ")))
            .with_remediation(
                "Review the open port list and disable or restrict any unnecessary services.",
            ),
        );
    } else {
        debug!("nmap found no open ports on {}", host);
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>
"#;

    #[test]
    fn parse_nmap_xml_extracts_open_ports_and_services() {
        let findings = parse_nmap_xml(SAMPLE_XML, "127.0.0.1").unwrap();
        assert_eq!(findings.len(), 3);

        let summary = &findings[0];
        assert_eq!(summary.title, "Nmap port scan summary");
        assert!(summary
            .evidence
            .iter()
            .any(|e| e.contains("22/tcp") && e.contains("80/tcp")));

        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles
            .iter()
            .any(|t| t.contains("22/tcp") && t.contains("ssh")));
        assert!(titles
            .iter()
            .any(|t| t.contains("80/tcp") && t.contains("http")));
        assert!(!titles.iter().any(|t| t.contains("443/tcp")));

        let ssh = findings
            .iter()
            .find(|f| f.title.contains("22/tcp"))
            .unwrap();
        let evidence = ssh.evidence.join(" ");
        assert!(evidence.contains("OpenSSH"));
        assert!(evidence.contains("8.9p1"));
    }

    #[test]
    fn parse_nmap_xml_returns_empty_for_down_host() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun><host><status state="down"/></host></nmaprun>
"#;
        let findings = parse_nmap_xml(xml, "127.0.0.1").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_nmap_xml_returns_empty_when_no_ports() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun><host><status state="up"/></host></nmaprun>
"#;
        let findings = parse_nmap_xml(xml, "127.0.0.1").unwrap();
        assert!(findings.is_empty());
    }
}
