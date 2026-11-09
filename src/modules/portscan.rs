use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::modules::Module;
use crate::target::Target;
use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct Portscan;

/// Nmap-style top-1000 TCP port list, range-compressed.
///
/// Source: <https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/>
const TOP_1000_TCP_PORTS_STR: &str = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389";

static TOP_1000_TCP_PORTS: LazyLock<Vec<u16>> =
    LazyLock::new(|| parse_port_ranges(TOP_1000_TCP_PORTS_STR).expect("valid port list"));

const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(1500);
const PROBE_WRITE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceInfo {
    name: &'static str,
    version: Option<String>,
}

#[derive(Debug)]
struct ServiceFingerprint {
    ports: &'static [u16],
    regex: Regex,
    service: &'static str,
    version_group: Option<usize>,
}

impl ServiceFingerprint {
    fn identify(&self, port: u16, banner: &str) -> Option<ServiceInfo> {
        if !self.ports.is_empty() && !self.ports.contains(&port) {
            return None;
        }
        let caps = self.regex.captures(banner)?;
        let version = self
            .version_group
            .and_then(|g| caps.get(g))
            .map(|m| m.as_str().trim().to_string())
            .filter(|v| !v.is_empty());
        Some(ServiceInfo {
            name: self.service,
            version,
        })
    }
}

static FINGERPRINTS: LazyLock<Vec<ServiceFingerprint>> = LazyLock::new(|| {
    vec![
        // HTTP server banner (more specific than protocol match).
        ServiceFingerprint {
            ports: &[
                80, 81, 82, 83, 84, 85, 88, 89, 90, 443, 591, 593, 631, 832, 8080, 8081, 8082,
                8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8180, 8181, 8443, 8888, 9000, 9001,
                9002, 9003, 9090, 9091, 9100, 9200, 9443, 10000,
            ],
            regex: Regex::new(r"(?i)Server:\s*([^\r\n]+)").unwrap(),
            service: "http",
            version_group: Some(1),
        },
        // Generic HTTP response.
        ServiceFingerprint {
            ports: &[],
            regex: Regex::new(r"(?i)^HTTP/\d\.\d+").unwrap(),
            service: "http",
            version_group: None,
        },
        // SSH.
        ServiceFingerprint {
            ports: &[],
            regex: Regex::new(r"^SSH-(\d+\.\d+)-([^\r\n]+)").unwrap(),
            service: "ssh",
            version_group: Some(2),
        },
        // FTP.
        ServiceFingerprint {
            ports: &[21, 2121],
            regex: Regex::new(r"(?i)^220[\s\-].*?(?:ftp|FileZilla|vsFTPd|ProFTPD|Pure-FTPd)(?:[^\r\n]*?(\d+\.\d+\S*))?").unwrap(),
            service: "ftp",
            version_group: Some(1),
        },
        // SMTP / submission.
        ServiceFingerprint {
            ports: &[25, 465, 587],
            regex: Regex::new(r"(?i)^220[\s\-].*?(?:smtp|Sendmail|Postfix|Exim|Mail|ESMTP)(?:[^\r\n]*?(\d+\.\d+\S*))?").unwrap(),
            service: "smtp",
            version_group: Some(1),
        },
        // Telnet.
        ServiceFingerprint {
            ports: &[23, 2323],
            regex: Regex::new(r"(?i)(?:telnet|login:|password:|user name:)").unwrap(),
            service: "telnet",
            version_group: None,
        },
        // DNS.
        ServiceFingerprint {
            ports: &[53],
            regex: Regex::new(r"(?i)(?:BIND|named|dns|unbound|powerdns)").unwrap(),
            service: "dns",
            version_group: None,
        },
        // POP3.
        ServiceFingerprint {
            ports: &[110, 995],
            regex: Regex::new(r"(?i)^\+OK").unwrap(),
            service: "pop3",
            version_group: None,
        },
        // IMAP.
        ServiceFingerprint {
            ports: &[143, 993],
            regex: Regex::new(r"(?i)^\*\s+OK.*?(?:IMAP4?|Dovecot|Courier).*?(\d+\.\d+\S*)?").unwrap(),
            service: "imap",
            version_group: Some(1),
        },
        // SMB.
        ServiceFingerprint {
            ports: &[139, 445],
            regex: Regex::new(r"(?i)(?:SMB|samba|netbios|NT LM)").unwrap(),
            service: "smb",
            version_group: None,
        },
        // MySQL.
        ServiceFingerprint {
            ports: &[3306],
            regex: Regex::new(r"(?i)^.\x00\x00\x00\x0a([^\x00]+)").unwrap(),
            service: "mysql",
            version_group: Some(1),
        },
        // PostgreSQL.
        ServiceFingerprint {
            ports: &[5432],
            regex: Regex::new(r"(?i)^E\x00\x00\x00.*ERROR").unwrap(),
            service: "postgresql",
            version_group: None,
        },
        // Redis.
        ServiceFingerprint {
            ports: &[6379],
            regex: Regex::new(r"(?i)^[-+](?:ERR|PONG|OK)").unwrap(),
            service: "redis",
            version_group: None,
        },
        // MongoDB.
        ServiceFingerprint {
            ports: &[27017, 27018, 27019],
            regex: Regex::new(r"(?i)(?:MongoDB|ismaster|ok\s*:\s*1)").unwrap(),
            service: "mongodb",
            version_group: None,
        },
        // Microsoft RDP.
        ServiceFingerprint {
            ports: &[3389],
            regex: Regex::new(r"^\x03\x00\x00").unwrap(),
            service: "rdp",
            version_group: None,
        },
        // VNC.
        ServiceFingerprint {
            ports: &[5900, 5901, 5902, 5903, 5904],
            regex: Regex::new(r"(?i)^RFB\s+(\d+\.\d+)").unwrap(),
            service: "vnc",
            version_group: Some(1),
        },
        // Rsync.
        ServiceFingerprint {
            ports: &[873],
            regex: Regex::new(r"(?i)^@RSYNCD:\s*(\d+\.\d+)").unwrap(),
            service: "rsync",
            version_group: Some(1),
        },
        // Elasticsearch.
        ServiceFingerprint {
            ports: &[9200],
            regex: Regex::new(r"(?i)(?:elastic|elasticsearch).*?(\d+\.\d+\S*)?").unwrap(),
            service: "elasticsearch",
            version_group: Some(1),
        },
    ]
});

static COMMON_SERVICES: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(7, "echo");
    map.insert(9, "discard");
    map.insert(13, "daytime");
    map.insert(17, "qotd");
    map.insert(19, "chargen");
    map.insert(21, "ftp");
    map.insert(22, "ssh");
    map.insert(23, "telnet");
    map.insert(25, "smtp");
    map.insert(26, "rsftp");
    map.insert(37, "time");
    map.insert(53, "dns");
    map.insert(79, "finger");
    map.insert(80, "http");
    map.insert(81, "hosts2-ns");
    map.insert(88, "kerberos-sec");
    map.insert(106, "pop3pw");
    map.insert(110, "pop3");
    map.insert(111, "rpcbind");
    map.insert(113, "ident");
    map.insert(119, "nntp");
    map.insert(125, "caictobjob");
    map.insert(135, "msrpc");
    map.insert(139, "netbios-ssn");
    map.insert(143, "imap");
    map.insert(144, "news");
    map.insert(179, "bgp");
    map.insert(199, "smux");
    map.insert(443, "https");
    map.insert(444, "snpp");
    map.insert(445, "microsoft-ds");
    map.insert(465, "smtps");
    map.insert(497, "retrospect");
    map.insert(513, "login");
    map.insert(514, "shell");
    map.insert(515, "printer");
    map.insert(543, "klogin");
    map.insert(544, "kshell");
    map.insert(548, "afp");
    map.insert(554, "rtsp");
    map.insert(587, "submission");
    map.insert(593, "http-rpc-epmap");
    map.insert(631, "ipp");
    map.insert(646, "ldp");
    map.insert(873, "rsync");
    map.insert(990, "ftps");
    map.insert(993, "imaps");
    map.insert(995, "pop3s");
    map.insert(1025, "NFS-or-IIS");
    map.insert(1026, "LSA-or-nterm");
    map.insert(1027, "IIS");
    map.insert(1028, "ms-lsa");
    map.insert(1029, "ms-lsa");
    map.insert(1110, "nfsd-status");
    map.insert(1433, "ms-sql-s");
    map.insert(1720, "h323q931");
    map.insert(1723, "pptp");
    map.insert(1900, "upnp");
    map.insert(2000, "cisco-sccp");
    map.insert(2001, "dc");
    map.insert(2049, "nfs");
    map.insert(2121, "ccproxy-ftp");
    map.insert(2717, "pn-requester");
    map.insert(3000, "ppp");
    map.insert(3128, "squid-http");
    map.insert(3306, "mysql");
    map.insert(3389, "ms-wbt-server");
    map.insert(3986, "mapper-ws_ethd");
    map.insert(4899, "radmin");
    map.insert(5000, "upnp");
    map.insert(5009, "airport-admin");
    map.insert(5051, "ida-agent");
    map.insert(5060, "sip");
    map.insert(5357, "wsdapi");
    map.insert(5432, "postgresql");
    map.insert(5631, "pcanywheredata");
    map.insert(5666, "nrpe");
    map.insert(5800, "vnc-http");
    map.insert(5900, "vnc");
    map.insert(6000, "X11");
    map.insert(6001, "X11:1");
    map.insert(6646, "unknown");
    map.insert(7070, "realserver");
    map.insert(7443, "oracleas-https");
    map.insert(8000, "http-alt");
    map.insert(8008, "http");
    map.insert(8009, "ajp13");
    map.insert(8080, "http-proxy");
    map.insert(8081, "blackice-icecap");
    map.insert(8443, "https-alt");
    map.insert(8888, "sun-answerbook");
    map.insert(9100, "jetdirect");
    map.insert(9200, "elasticsearch");
    map.insert(9999, "abyss");
    map.insert(10000, "snet-sensor-mgmt");
    map.insert(27017, "mongodb");
    map.insert(49152, "unknown");
    map.insert(49153, "unknown");
    map.insert(49154, "unknown");
    map.insert(49155, "unknown");
    map.insert(49156, "unknown");
    map.insert(49157, "unknown");
    map
});

#[async_trait]
impl Module for Portscan {
    fn name(&self) -> &'static str {
        "portscan"
    }

    fn description(&self) -> &'static str {
        "Self-contained async TCP port scanner with banner grabbing and service fingerprinting"
    }

    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        let ports = ports_to_scan(config.modules.portscan.top_ports);
        run_portscan(target, config, &ports).await
    }
}

/// Build the port list to scan. Uses the built-in top-1000 list first, then
/// fills the remainder sequentially so existing `top_ports = N` behaviour is
/// preserved for values larger than 1000.
fn ports_to_scan(top_ports: usize) -> Vec<u16> {
    let top_ports = top_ports.clamp(1, 65535);
    if top_ports <= TOP_1000_TCP_PORTS.len() {
        TOP_1000_TCP_PORTS[..top_ports].to_vec()
    } else {
        // Preserve the historical 1..=top_ports coverage while keeping the
        // top-1000 ports at the front of the scan order.
        let mut ports = Vec::with_capacity(top_ports);
        let mut seen: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for &p in TOP_1000_TCP_PORTS.iter() {
            if p <= top_ports as u16 && seen.insert(p) {
                ports.push(p);
            }
        }
        for p in 1u16..=top_ports as u16 {
            if seen.insert(p) {
                ports.push(p);
            }
        }
        ports
    }
}

fn parse_port_ranges(s: &str) -> Result<Vec<u16>, std::num::ParseIntError> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start.trim().parse()?;
            let end: u16 = end.trim().parse()?;
            ports.extend(start..=end);
        } else {
            ports.push(part.parse()?);
        }
    }
    Ok(ports)
}

async fn run_portscan(target: &Target, config: &Config, ports: &[u16]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    // Resolve once up front instead of once per port. Prefer IPv4 when the name
    // has both address families, matching what most scanners do by default.
    let addrs = target.resolve(0).await?;
    let ip: IpAddr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.ip())
        .ok_or_else(|| anyhow::anyhow!("{} did not resolve", target.host()))?;
    debug!("portscan: scanning {} ({})", target.host(), ip);

    let semaphore = config.request_limiter();
    let connect_timeout = config.timeout();
    let banner_bytes = config.modules.portscan.banner_bytes.max(1);

    let mut handles = Vec::with_capacity(ports.len());
    for &port in ports {
        let permit = semaphore.clone().acquire_owned().await?;
        let handle = tokio::spawn(async move {
            let _permit = permit;
            scan_port(SocketAddr::new(ip, port), connect_timeout, banner_bytes).await
        });
        handles.push(handle);
    }

    let mut open_ports = Vec::new();
    let mut banners: HashMap<u16, String> = HashMap::new();

    for handle in handles {
        if let Ok(Some((port, banner))) = handle.await {
            open_ports.push(port);
            if !banner.is_empty() {
                banners.insert(port, banner);
            }
        }
    }

    if open_ports.is_empty() {
        return Ok(findings);
    }

    open_ports.sort();

    for port in &open_ports {
        let banner = banners.get(port).map(|s| s.as_str()).unwrap_or("");
        let info = identify_service(*port, banner, config.modules.portscan.banner_grab);
        let service_label = format_service(&info);

        let mut evidence = format!("Port {} ({}) is open", port, info.name);
        if config.modules.portscan.banner_grab {
            if !banner.is_empty() {
                evidence.push_str(&format!(" | Banner: {}", sanitize_banner(banner)));
            }
            if info.version.is_some() {
                evidence.push_str(&format!(" | Fingerprinted service: {}", service_label));
            }
        }

        findings.push(
            Finding::new(
                "portscan",
                &format!("Open port {} ({})", port, service_label),
                Severity::Info,
                "A TCP port accepted a connection and responded to a validation read",
            )
            .with_evidence(evidence)
            .with_remediation("Close ports that are not required and ensure services are patched."),
        );
    }

    findings.insert(
        0,
        Finding::new(
            "portscan",
            "Port scan summary",
            Severity::Info,
            &format!(
                "Found {} open TCP port(s) out of {} scanned",
                open_ports.len(),
                ports.len()
            ),
        )
        .with_evidence(format!(
            "Open ports: {}",
            open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    );

    Ok(findings)
}

/// Try to connect and read a banner. Returns `None` when the port is closed,
/// filtered, or the connection is reset immediately after establishment
/// (a common source of false positives).
async fn scan_port(
    addr: SocketAddr,
    connect_timeout: Duration,
    banner_bytes: usize,
) -> Option<(u16, String)> {
    let port = addr.port();
    let mut stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!("port {} connect error: {}", port, e);
            return None;
        }
        Err(_) => {
            debug!("port {} connect timeout", port);
            return None;
        }
    };

    // Send a protocol-appropriate probe, if any.
    let probe = probe_for_port(port);
    if !probe.is_empty() {
        match timeout(PROBE_WRITE_TIMEOUT, stream.write_all(probe)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!("port {} probe write error: {}", port, e),
            Err(_) => debug!("port {} probe write timed out", port),
        }
    }

    // Try to read a response. A reset here is usually a false positive from a
    // stateful firewall/proxy, but TLS-first services send TLS alerts to plain
    // text probes, so those ports must still be reported as open.
    let mut buf = vec![0u8; banner_bytes];
    match timeout(BANNER_READ_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => {
            if n > 0 {
                let banner = String::from_utf8_lossy(&buf[..n]).to_string();
                Some((port, banner))
            } else {
                // Accepted then closed immediately. The port is open but silent.
                Some((port, String::new()))
            }
        }
        Ok(Err(e)) => {
            if is_tls_first_port(port) {
                debug!(
                    "port {} banner read error on TLS-first port (reporting open): {}",
                    port, e
                );
                Some((port, String::new()))
            } else {
                debug!(
                    "port {} banner read error (discarding false positive): {}",
                    port, e
                );
                None
            }
        }
        Err(_) => {
            // Open but no banner within the read window.
            Some((port, String::new()))
        }
    }
}

fn is_tls_first_port(port: u16) -> bool {
    matches!(port, 443 | 465 | 636 | 993 | 995 | 8443 | 9001 | 9443)
}

fn probe_for_port(port: u16) -> &'static [u8] {
    match port {
        // TLS/SSL-first services: sending plaintext can cause immediate close.
        443 | 465 | 636 | 993 | 995 | 8443 | 9001 => b"",
        // HTTP and common HTTP alternates.
        80 | 81 | 82 | 83 | 84 | 85 | 88 | 89 | 90 | 591 | 593 | 631 | 832 | 8000 | 8001 | 8002
        | 8008 | 8009 | 8010 | 8011 | 8080 | 8081 | 8082 | 8083 | 8084 | 8085 | 8086 | 8087
        | 8088 | 8089 | 8090 | 8093 | 8180 | 8181 | 8888 | 9000 | 9002 | 9003 | 9090 | 9091
        | 9100 | 9200 | 9443 | 10000 => b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        // Banner-first plaintext protocols.
        21 | 22 | 23 | 25 | 110 | 143 | 220 | 2222 | 2323 | 3128 => b"",
        // Generic probe for everything else.
        _ => b"\r\n",
    }
}

fn identify_service(port: u16, banner: &str, banner_grab: bool) -> ServiceInfo {
    if banner_grab && !banner.is_empty() {
        for fp in FINGERPRINTS.iter() {
            if let Some(info) = fp.identify(port, banner) {
                return info;
            }
        }
    }
    let name = COMMON_SERVICES.get(&port).copied().unwrap_or("unknown");
    ServiceInfo {
        name,
        version: None,
    }
}

fn format_service(info: &ServiceInfo) -> String {
    match &info.version {
        Some(v) if !v.is_empty() => format!("{} / {}", info.name, v),
        _ => info.name.to_string(),
    }
}

fn sanitize_banner(banner: &str) -> String {
    banner
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c.is_ascii_whitespace() {
                c
            } else {
                '.'
            }
        })
        .collect::<String>()
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn local(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn scan_port_works_over_ipv6_loopback() {
        let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => return, // IPv6 unavailable in this environment.
        };
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        });
        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port);
        let (_, banner) = scan_port(addr, Duration::from_secs(2), 256)
            .await
            .expect("expected open port on ::1");
        assert!(banner.contains("SSH-2.0"));
    }

    #[test]
    fn top_1000_list_has_1000_ports() {
        assert_eq!(TOP_1000_TCP_PORTS.len(), 1000);
    }

    #[test]
    fn parse_port_ranges_handles_individual_and_ranges() {
        let ports = parse_port_ranges("1,3-5,80,443").unwrap();
        assert_eq!(ports, vec![1, 3, 4, 5, 80, 443]);
    }

    #[test]
    fn parse_port_ranges_rejects_invalid() {
        assert!(parse_port_ranges("abc").is_err());
    }

    #[test]
    fn ports_to_scan_caps_top_1000() {
        let ports = ports_to_scan(10);
        assert_eq!(ports.len(), 10);
        assert_eq!(ports, TOP_1000_TCP_PORTS[..10]);
    }

    #[test]
    fn ports_to_scan_fills_beyond_top_1000() {
        let ports = ports_to_scan(1005);
        assert_eq!(ports.len(), 1005);
        // All ports from 1..=1005 are covered exactly once.
        let mut sorted = ports.clone();
        sorted.sort();
        assert_eq!(sorted, (1u16..=1005).collect::<Vec<_>>());
        // The top-1000 ports that fall within the range appear first.
        let seen: std::collections::HashSet<_> = ports.iter().copied().collect();
        assert_eq!(seen.len(), ports.len());
    }

    #[test]
    fn ssh_fingerprint_extracts_version() {
        let info = identify_service(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", true);
        assert_eq!(info.name, "ssh");
        assert_eq!(
            info.version.as_deref(),
            Some("OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        );
    }

    #[test]
    fn http_fingerprint_matches_response() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
        let info = identify_service(80, banner, true);
        assert_eq!(info.name, "http");
        assert_eq!(info.version.as_deref(), Some("nginx/1.18.0"));
    }

    #[test]
    fn ftp_fingerprint_matches_banner() {
        let banner = "220-FileZilla Server 0.9.60 beta\r\n220-written by Tim Kosse (tim.kosse@filezilla-project.org)\r\n";
        let info = identify_service(21, banner, true);
        assert_eq!(info.name, "ftp");
        assert_eq!(info.version.as_deref(), Some("0.9.60"));
    }

    #[test]
    fn unknown_port_falls_back_to_common_services() {
        let info = identify_service(3306, "garbage", true);
        assert_eq!(info.name, "mysql");
        assert!(info.version.is_none());
    }

    #[test]
    fn unknown_port_without_mapping() {
        let info = identify_service(12345, "garbage", true);
        assert_eq!(info.name, "unknown");
    }

    #[test]
    fn banner_grab_false_skips_fingerprinting() {
        let info = identify_service(22, "SSH-2.0-OpenSSH_8.2", false);
        assert_eq!(info.name, "ssh");
        assert!(info.version.is_none());
    }

    #[test]
    fn sanitize_banner_replaces_control_chars() {
        let s = sanitize_banner("SSH-2.0\r\nOpenSSH");
        assert_eq!(s, "SSH-2.0\\r\\nOpenSSH");
    }

    #[test]
    fn format_service_includes_version() {
        let info = ServiceInfo {
            name: "ssh",
            version: Some("OpenSSH_8.2".to_string()),
        };
        assert_eq!(format_service(&info), "ssh / OpenSSH_8.2");
    }

    #[test]
    fn format_service_without_version() {
        let info = ServiceInfo {
            name: "http",
            version: None,
        };
        assert_eq!(format_service(&info), "http");
    }

    #[tokio::test]
    async fn scan_port_detects_open_ssh_service() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_8.2\r\n").await;
        });

        let result = scan_port(local(port), Duration::from_secs(2), 256).await;
        let (found_port, banner) = result.expect("expected open port");
        assert_eq!(found_port, port);
        assert!(banner.contains("SSH-2.0"));
    }

    #[tokio::test]
    async fn scan_port_detects_open_http_service() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read the HTTP probe so the client does not see a reset.
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nServer: test/1.0\r\n\r\n")
                .await;
        });

        let result = scan_port(local(port), Duration::from_secs(2), 256).await;
        let (_, banner) = result.expect("expected open port");
        assert!(banner.contains("HTTP/1.1"));
    }

    #[tokio::test]
    async fn scan_port_returns_none_for_closed_port() {
        let result = scan_port(local(1), Duration::from_millis(500), 256).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn scan_port_discards_immediate_reset() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    drop(stream);
                }
            }
        });

        let result = scan_port(local(port), Duration::from_secs(2), 256).await;
        assert!(result.is_none(), "expected reset port to be discarded");
    }

    #[tokio::test]
    async fn run_portscan_produces_summary_and_individual_findings() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_8.2\r\n").await;
        });

        let target = Target::parse(&format!("127.0.0.1:{}", port)).unwrap();
        let mut config = Config::load(None).unwrap();
        config.scanner.timeout_ms = 2000;
        config.scanner.concurrency = 10;
        config.modules.portscan.enabled = true;
        config.modules.portscan.banner_grab = true;
        config.modules.portscan.banner_bytes = 256;

        let findings = run_portscan(&target, &config, &[port]).await.unwrap();

        let summary = findings
            .iter()
            .find(|f| f.title == "Port scan summary")
            .expect("summary missing");
        assert!(summary
            .evidence
            .iter()
            .any(|e| e.contains(&port.to_string())));

        let individual = findings
            .iter()
            .find(|f| f.title.contains(&format!("Open port {}", port)))
            .expect("individual finding missing");
        assert!(individual.evidence.iter().any(|e| e.contains("SSH-2.0")));
        assert!(individual.title.contains("ssh / OpenSSH_8.2"));
    }
}
