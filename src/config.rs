use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

const DEFAULT_CONFIG: &str = include_str!("../config/default.toml");

/// Built-in copies of the bundled wordlists. These are used when the configured
/// wordlist file cannot be read (for example when the binary is installed
/// somewhere other than the repository checkout), so modules never silently
/// skip their checks.
pub const EMBEDDED_SUBDOMAIN_WORDLIST: &str = include_str!("../wordlists/subdomains.txt");
pub const EMBEDDED_EXPOSED_PATHS_WORDLIST: &str = include_str!("../wordlists/exposed_paths.txt");

/// Names of every module WASP knows about, in the order they are documented.
pub const MODULE_NAMES: &[&str] = &[
    "recon", "portscan", "web", "secrets", "tlsaudit", "webvulns", "cms", "cmsenum", "nmap",
    "nuclei", "testssl",
];

/// Default User-Agent, derived from the crate version so it never goes stale.
pub fn default_user_agent() -> String {
    format!("WASP/{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub modules: ModulesConfig,
    pub tools: ToolsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct CmsEnumConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsAuditConfig {
    pub enabled: bool,
    pub check_versions: bool,
    pub check_ciphers: bool,
    pub check_certificate: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct NmapConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NucleiConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestsslConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CmsConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PortscanConfig {
    pub enabled: bool,
    pub top_ports: usize,
    pub banner_grab: bool,
    pub banner_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    pub enabled: bool,
    pub check_http: bool,
    pub check_https: bool,
    pub check_headers: bool,
    pub check_cookies: bool,
    pub check_tls_cert: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    pub enabled: bool,
    pub path_wordlist: PathBuf,
    pub check_http: bool,
    pub check_https: bool,
    pub enable_body_regex: bool,
}

impl Config {
    /// Load the configuration. The embedded defaults are always parsed first;
    /// a user-supplied file is then merged on top of them, so a custom config
    /// only needs to contain the keys it wants to change.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut base_dir: Option<PathBuf> = None;
        let user = match path {
            Some(p) => {
                let contents = std::fs::read_to_string(p)
                    .with_context(|| format!("failed to read config file {:?}", p))?;
                base_dir = p.parent().map(|parent| parent.to_path_buf());
                Some((contents, format!("{:?}", p)))
            }
            None => None,
        };

        let mut config = match &user {
            Some((contents, name)) => Self::from_toml_with_defaults(contents)
                .with_context(|| format!("failed to parse config file {}", name))?,
            None => Self::from_toml_with_defaults("")?,
        };

        // Resolve relative wordlist paths against the config file directory so
        // that installing the binary elsewhere does not break provided configs.
        if let Some(base) = base_dir {
            config.modules.recon.subdomain_wordlist =
                Self::resolve_relative(&base, &config.modules.recon.subdomain_wordlist);
            config.modules.secrets.path_wordlist =
                Self::resolve_relative(&base, &config.modules.secrets.path_wordlist);
        }

        config.validate()?;
        config.reset_request_limiter();
        Ok(config)
    }

    /// Parse `overrides` (TOML) and deep-merge it over the embedded defaults.
    pub fn from_toml_with_defaults(overrides: &str) -> Result<Self> {
        let mut base: toml::Table =
            toml::from_str(DEFAULT_CONFIG).context("failed to parse embedded default config")?;
        if !overrides.trim().is_empty() {
            let user: toml::Table = toml::from_str(overrides)?;
            merge_tables(&mut base, user);
        }
        let mut config: Config = toml::Value::Table(base).try_into()?;
        if config.scanner.user_agent.trim().is_empty() {
            config.scanner.user_agent = default_user_agent();
        }
        Ok(config)
    }

    /// Reject configurations that would make the scanner misbehave.
    pub fn validate(&self) -> Result<()> {
        if self.scanner.timeout_ms == 0 {
            anyhow::bail!("scanner.timeout_ms must be greater than 0");
        }
        if self.scanner.concurrency == 0 {
            anyhow::bail!("scanner.concurrency must be greater than 0");
        }
        if self.modules.portscan.top_ports == 0 || self.modules.portscan.top_ports > 65535 {
            anyhow::bail!("modules.portscan.top_ports must be between 1 and 65535");
        }
        Ok(())
    }

    /// Rebuild the shared request limiter from `scanner.concurrency`. Call this
    /// after changing the concurrency on an already-loaded config.
    pub fn reset_request_limiter(&mut self) {
        let permits = self.scanner.concurrency.max(1);
        self.scanner.concurrency_semaphore = Some(Arc::new(Semaphore::new(permits)));
    }

    /// Shared semaphore bounding the number of simultaneous network operations
    /// across all modules.
    pub fn request_limiter(&self) -> Arc<Semaphore> {
        self.scanner
            .concurrency_semaphore
            .clone()
            .unwrap_or_else(|| Arc::new(Semaphore::new(self.scanner.concurrency.max(1))))
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
            .user_agent(self.scanner.user_agent.as_str())
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

/// Recursively merge `overlay` into `base`. Tables are merged key by key; any
/// other value in `overlay` replaces the one in `base`.
fn merge_tables(base: &mut toml::Table, overlay: toml::Table) {
    for (key, value) in overlay {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(existing)), toml::Value::Table(incoming)) => {
                merge_tables(existing, incoming);
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Read a newline-separated wordlist, ignoring blank lines and `#` comments.
/// Falls back to `embedded` when the file cannot be read.
pub fn load_wordlist(path: &Path, embedded: &str) -> Vec<String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::debug!(
                "wordlist {:?} unavailable ({}); using built-in wordlist",
                path,
                e
            );
            embedded.to_string()
        }
    };
    let mut seen = std::collections::HashSet::new();
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| seen.insert(l.to_string()))
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_override_keeps_defaults() {
        let config = Config::from_toml_with_defaults(
            "[scanner]\ntimeout_ms = 1234\n[modules.nmap]\nenabled = true\n",
        )
        .unwrap();
        assert_eq!(config.scanner.timeout_ms, 1234);
        assert!(config.modules.nmap.enabled);
        // Untouched keys come from the embedded defaults.
        assert_eq!(config.scanner.concurrency, 100);
        assert!(config.modules.recon.enabled);
    }

    #[test]
    fn empty_user_agent_uses_crate_version() {
        let config = Config::from_toml_with_defaults("").unwrap();
        assert_eq!(config.scanner.user_agent, default_user_agent());
    }

    #[test]
    fn invalid_values_are_rejected() {
        let config = Config::from_toml_with_defaults("[scanner]\nconcurrency = 0\n").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml_with_defaults("[scanner]\ntimeuot_ms = 5\n").is_err());
    }

    #[test]
    fn wordlist_falls_back_to_embedded_copy() {
        let words = load_wordlist(Path::new("/definitely/missing.txt"), "a\n# c\n\nb\na\n");
        assert_eq!(words, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn embedded_wordlists_are_not_empty() {
        assert!(!load_wordlist(Path::new(""), EMBEDDED_SUBDOMAIN_WORDLIST).is_empty());
        assert!(!load_wordlist(Path::new(""), EMBEDDED_EXPOSED_PATHS_WORDLIST).is_empty());
    }
}
