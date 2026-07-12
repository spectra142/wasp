use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

const DEFAULT_CONFIG: &str = include_str!("../config/default.toml");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub modules: ModulesConfig,
    pub tools: ToolsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolsConfig {
    pub nmap_path: PathBuf,
    pub nuclei_path: PathBuf,
    pub testssl_path: PathBuf,
    pub wpscan_path: PathBuf,
    pub gitleaks_path: PathBuf,
    pub trufflehog_path: PathBuf,
    pub skip_missing_tools: bool,
    /// Module-specific timeouts for heavy external tools. Defaults are in
    /// seconds and override the global `scanner.timeout_ms` for those adapters.
    pub nmap_timeout_secs: u64,
    pub testssl_timeout_secs: u64,
    pub nuclei_timeout_secs: u64,
    pub wpscan_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScannerConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    /// Verify TLS certificates when making HTTPS requests. Disabling this is
    /// useful for internal/self-signed targets but leaves you open to MITM
    /// attacks on untrusted networks.
    pub verify_tls_certificates: bool,
    /// Optional HTTP proxy URL (e.g. `http://proxy.example.com:8080`).
    /// If unset, reqwest will still honour `HTTP_PROXY`/`HTTPS_PROXY`
    /// environment variables by default.
    #[serde(default)]
    pub http_proxy: Option<String>,
    /// Optional HTTPS proxy URL.
    #[serde(default)]
    pub https_proxy: Option<String>,
    /// Optional default headers added to every HTTP request made by WASP.
    #[serde(default)]
    pub custom_headers: std::collections::HashMap<String, String>,
    /// Shared global concurrency semaphore created from `concurrency`.
    /// Not serialized; set automatically when the config is loaded.
    #[serde(skip)]
    pub concurrency_semaphore: Option<Arc<Semaphore>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModulesConfig {
    pub recon: ReconConfig,
    pub portscan: PortscanConfig,
    pub web: WebConfig,
    pub secrets: SecretsConfig,
    pub tlsaudit: TlsAuditConfig,
    pub webvulns: WebVulnsConfig,
    pub nmap: NmapConfig,
    pub nuclei: NucleiConfig,
    pub testssl: TestsslConfig,
    pub cms: CmsConfig,
    pub cmsenum: CmsEnumConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CmsEnumConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsAuditConfig {
    pub enabled: bool,
    pub check_versions: bool,
    pub check_ciphers: bool,
    pub check_certificate: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebVulnsConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
    pub check_cors: bool,
    pub check_open_redirect: bool,
    pub check_trace: bool,
    pub check_options: bool,
    pub check_sensitive_files: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NmapConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NucleiConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestsslConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CmsConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReconConfig {
    pub enabled: bool,
    pub subdomain_wordlist: PathBuf,
    pub check_http: bool,
    pub check_https: bool,
    pub enable_whois: bool,
    pub enable_dns: bool,
    pub enable_subdomain_bruteforce: bool,
    pub enable_tech_fingerprint: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortscanConfig {
    pub enabled: bool,
    pub top_ports: usize,
    pub banner_grab: bool,
    pub banner_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
    pub check_headers: bool,
    pub check_cookies: bool,
    pub check_tls_cert: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    pub enabled: bool,
    pub path_wordlist: PathBuf,
    pub check_http: bool,
    pub check_https: bool,
    pub enable_body_regex: bool,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut config: Config =
            toml::from_str(DEFAULT_CONFIG).context("failed to parse embedded default config")?;

        let mut base_dir: Option<PathBuf> = None;
        if let Some(p) = path {
            let contents = std::fs::read_to_string(p)
                .with_context(|| format!("failed to read config file {:?}", p))?;
            config = toml::from_str(&contents)
                .with_context(|| format!("failed to parse config file {:?}", p))?;
            base_dir = p.parent().map(|parent| parent.to_path_buf());
        }

        // Resolve relative wordlist paths against the config file directory so
        // that installing the binary elsewhere does not break provided configs.
        if let Some(base) = base_dir {
            config.modules.recon.subdomain_wordlist =
                Self::resolve_relative(&base, &config.modules.recon.subdomain_wordlist);
            config.modules.secrets.path_wordlist =
                Self::resolve_relative(&base, &config.modules.secrets.path_wordlist);
        }

        let permits = config.scanner.concurrency.max(1);
        config.scanner.concurrency_semaphore = Some(Arc::new(Semaphore::new(permits)));

        Ok(config)
    }

    fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        }
    }

    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.scanner.timeout_ms)
    }

    /// Return a pre-configured `reqwest::ClientBuilder` using the scanner's
    /// timeout, user agent, redirect policy, TLS verification setting, and
    /// optional proxy configuration.
    pub fn http_client_builder(&self) -> Result<ClientBuilder> {
        let mut builder = Client::builder()
            .timeout(self.timeout())
            .user_agent(&self.scanner.user_agent)
            .redirect(if self.scanner.follow_redirects {
                reqwest::redirect::Policy::limited(self.scanner.max_redirects.max(1))
            } else {
                reqwest::redirect::Policy::none()
            })
            .danger_accept_invalid_certs(!self.scanner.verify_tls_certificates);

        if let Some(proxy) = self.scanner.http_proxy.as_deref() {
            if !proxy.is_empty() {
                builder =
                    builder.proxy(reqwest::Proxy::http(proxy).context("invalid http_proxy URL")?);
            }
        }
        if let Some(proxy) = self.scanner.https_proxy.as_deref() {
            if !proxy.is_empty() {
                builder =
                    builder.proxy(reqwest::Proxy::https(proxy).context("invalid https_proxy URL")?);
            }
        }
        if !self.scanner.custom_headers.is_empty() {
            let mut headers = reqwest::header::HeaderMap::new();
            for (name, value) in &self.scanner.custom_headers {
                let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .with_context(|| format!("invalid custom header name: {}", name))?;
                let header_value = reqwest::header::HeaderValue::from_str(value)
                    .with_context(|| format!("invalid custom header value for {}", name))?;
                headers.insert(header_name, header_value);
            }
            builder = builder.default_headers(headers);
        }

        Ok(builder)
    }

    /// Build and return a `reqwest::Client` from [`Self::http_client_builder`].
    pub fn http_client(&self) -> Result<Client> {
        self.http_client_builder()?
            .build()
            .context("failed to build HTTP client")
    }
}
