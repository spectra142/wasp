use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use wasp::config::Config;
use wasp::modules::{Module, portscan::Portscan, secrets::Secrets, web::Web};
use wasp::target::Target;

async fn start_test_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(handle_request(socket));
        }
    });

    port
}

async fn handle_request(mut socket: TcpStream) {
    let (reader, mut writer) = socket.split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Consume headers
    let mut header = String::new();
    loop {
        header.clear();
        if buf_reader.read_line(&mut header).await.is_err() {
            return;
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let path = parts.get(1).copied().unwrap_or("/");
    let (status, headers, body) = build_response(path);

    let response = format!(
        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\n{}\r\n{}",
        status,
        body.len(),
        headers,
        body
    );
    let _ = writer.write_all(response.as_bytes()).await;
}

fn build_response(path: &str) -> (u16, String, String) {
    match path {
        "/" => (
            200,
            "Server: test-server/1.0\r\nSet-Cookie: session=abc123; Path=/\r\n".to_string(),
            "<html><body>WordPress</body></html>".to_string(),
        ),
        "/.env" => (
            200,
            String::new(),
            "DB_PASSWORD=secret\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string(),
        ),
        _ => (404, String::new(), "not found".to_string()),
    }
}

fn test_config() -> Config {
    let mut config = Config::load(None).unwrap();
    config.scanner.timeout_ms = 500;
    config.scanner.concurrency = 100;
    config.modules.web.check_https = false;
    config.modules.web.check_tls_cert = false;
    config
}

#[tokio::test]
async fn web_module_detects_missing_headers_and_cookie_flags() {
    let port = start_test_server().await;
    let target = Target::parse(&format!("127.0.0.1:{}", port)).unwrap();
    let config = test_config();

    // Sanity-check the test fixture is reachable before invoking the module.
    let sanity = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await;
    assert!(
        sanity.is_ok() && sanity.as_ref().unwrap().status().is_success(),
        "test server not reachable: {:?}",
        sanity
    );

    let findings = Web.run(&target, &config).await.unwrap();
    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();

    assert!(
        titles.iter().any(|t| t.contains("HSTS")),
        "missing HSTS finding: {:?}",
        titles
    );
    assert!(
        titles.iter().any(|t| t.contains("X-Frame-Options")),
        "missing X-Frame-Options finding: {:?}",
        titles
    );
    assert!(
        titles.iter().any(|t| t.contains("Cookie missing HttpOnly")),
        "missing HttpOnly cookie finding: {:?}",
        titles
    );
}

#[tokio::test]
async fn secrets_module_detects_exposed_path_and_leaked_key() {
    let port = start_test_server().await;
    let target = Target::parse(&format!("127.0.0.1:{}", port)).unwrap();
    let mut config = test_config();
    config.modules.secrets.enabled = true;
    config.modules.secrets.path_wordlist = std::path::PathBuf::from("wordlists/exposed_paths.txt");

    let findings = Secrets.run(&target, &config).await.unwrap();
    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();

    assert!(
        titles
            .iter()
            .any(|t| t.contains("Exposed path found: .env")),
        "missing exposed .env finding: {:?}",
        titles
    );
    assert!(
        titles.iter().any(|t| t.contains("AWS Access Key ID")),
        "missing AWS key leak finding: {:?}",
        findings
    );
}

#[test]
fn aws_regex_matches_sample_key() {
    let re = regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    assert!(re.is_match("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"));
}

#[tokio::test]
async fn portscan_detects_open_port() {
    let port = start_test_server().await;
    let target = Target::parse(&format!("127.0.0.1:{}", port)).unwrap();
    let mut config = test_config();
    config.modules.portscan.enabled = true;
    config.modules.portscan.top_ports = port as usize;

    let findings = Portscan.run(&target, &config).await.unwrap();
    let summary = findings
        .iter()
        .find(|f| f.title == "Port scan summary")
        .expect("port scan summary missing");

    assert!(
        summary
            .evidence
            .iter()
            .any(|e| e.contains(&port.to_string())),
        "open port {} not in summary evidence: {:?}",
        port,
        summary.evidence
    );
}
