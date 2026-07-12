use crate::config::Config;
use crate::finding::{Finding, Report, Severity};
use crate::modules::{enabled_modules, Module};
use crate::target::Target;
use anyhow::Result;
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;

/// Default maximum number of module invocations per second for a single host.
/// This limits how fast WASP starts new modules, not the requests a module
/// makes internally. This can be tuned with [`Scanner::with_rate_limit`].
const DEFAULT_RATE_LIMIT: usize = 100;

/// Default number of retries for module runs that fail with a transient error.
const DEFAULT_MAX_RETRIES: usize = 2;

/// Initial delay between retries; doubles on each attempt (exponential backoff).
const DEFAULT_RETRY_DELAY_MS: u64 = 500;

pub struct Scanner {
    config: Config,
    modules: Vec<Arc<dyn Module>>,
    /// Maximum module invocations per second per host. `None` disables rate
    /// limiting. This does not throttle requests made inside a module.
    rate_limit: Option<usize>,
    /// Maximum retry attempts for transient failures.
    max_retries: usize,
    /// Initial retry delay in milliseconds.
    retry_delay_ms: u64,
    /// Per-host rate limiters, reused when the same scanner instance is run
    /// against the same host multiple times.
    host_limiters: Mutex<HashMap<String, Arc<RateLimiter>>>,
}

impl Scanner {
    pub fn new(config: Config) -> Self {
        let modules = enabled_modules(&config);
        Self {
            config,
            modules,
            rate_limit: Some(DEFAULT_RATE_LIMIT),
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            host_limiters: Mutex::new(HashMap::new()),
        }
    }

    /// Set a per-host rate limit in module invocations per second. Pass `None`
    /// to disable rate limiting.
    pub fn with_rate_limit(mut self, requests_per_second: Option<usize>) -> Self {
        self.rate_limit = requests_per_second;
        self
    }

    /// Set the maximum number of retries for transient failures.
    pub fn with_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Set the initial retry delay in milliseconds. The delay doubles after each
    /// attempt (exponential backoff).
    pub fn with_retry_delay(mut self, delay_ms: u64) -> Self {
        self.retry_delay_ms = delay_ms;
        self
    }

    pub async fn run(&self, target: &Target) -> Result<Report> {
        let mut report = Report::new(target.to_string());
        let global_semaphore = self
            .config
            .scanner
            .concurrency_semaphore
            .clone()
            .unwrap_or_else(|| Arc::new(Semaphore::new(self.config.scanner.concurrency.max(1))));
        let host = target.host();
        let rate_limiter = self.rate_limiter_for_host(&host).await;

        info!(
            "starting scan of {} with {} module(s), concurrency={}, rate_limit={:?}, retries={}",
            target,
            self.modules.len(),
            self.config.scanner.concurrency,
            self.rate_limit,
            self.max_retries
        );

        let total = self.modules.len();
        let mut handles = Vec::with_capacity(total);

        for (idx, module) in self.modules.iter().enumerate() {
            // Enforce per-host rate limiting before spawning the module.
            if let Some(ref limiter) = rate_limiter {
                limiter.acquire_one().await;
            }

            let permit = global_semaphore.clone().acquire_owned().await?;
            let module_name = module.name().to_string();
            let target = target.clone();
            let config = self.config.clone();
            let module = Arc::clone(module);
            let max_retries = self.max_retries;
            let retry_delay_ms = self.retry_delay_ms;
            let progress = format!("[{}/{}]", idx + 1, total);

            let handle = tokio::spawn(async move {
                let _permit = permit;
                info!("{} [{}] starting", progress, module_name);

                let start = Instant::now();
                let result = run_with_retries(
                    &*module,
                    &target,
                    &config,
                    &module_name,
                    &progress,
                    max_retries,
                    retry_delay_ms,
                )
                .await;
                let elapsed = start.elapsed();

                match result {
                    Ok(findings) => {
                        info!(
                            "{} [{}] completed in {:?} with {} finding(s)",
                            progress,
                            module_name,
                            elapsed,
                            findings.len()
                        );
                        findings
                    }
                    Err(e) => {
                        error!(
                            "{} [{}] failed after {:?}: {}",
                            progress, module_name, elapsed, e
                        );

                        if let Some(finding) = handle_missing_tool_error(&module_name, &e, &config)
                        {
                            warn!(
                                "[{}] treating failure as missing-tool finding because skip_missing_tools=true",
                                module_name
                            );
                            vec![finding]
                        } else {
                            vec![Finding::new(
                                &module_name,
                                &format!("{} module failed", module_name),
                                Severity::Info,
                                &format!("The module encountered an error: {}", e),
                            )]
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let findings = handle.await?;
            report.add_findings(findings);
        }

        report.deduplicate();
        report.finalize();
        let critical_high = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .count();

        info!(
            "scan complete for {}: {} finding(s), {} critical/high",
            target,
            report.findings.len(),
            critical_high
        );
        Ok(report)
    }

    async fn rate_limiter_for_host(&self, host: &str) -> Option<Arc<RateLimiter>> {
        let limit = self.rate_limit?;
        let mut map = self.host_limiters.lock().await;
        let limiter = map
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::new(limit)))
            .clone();
        Some(limiter)
    }
}

/// Run a module, retrying on transient failures with exponential backoff.
async fn run_with_retries(
    module: &dyn Module,
    target: &Target,
    config: &Config,
    module_name: &str,
    progress: &str,
    max_retries: usize,
    retry_delay_ms: u64,
) -> Result<Vec<Finding>> {
    let mut last_error = None;

    for attempt in 0..=max_retries {
        match module.run(target, config).await {
            Ok(findings) => return Ok(findings),
            Err(e) => {
                let transient = is_transient_error(&e);
                last_error = Some(e);

                if attempt == max_retries || !transient {
                    break;
                }

                let delay = Duration::from_millis(retry_delay_ms * 2u64.pow(attempt as u32));
                warn!(
                    "{} [{}] transient failure (attempt {}/{}), retrying in {:?}: {}",
                    progress,
                    module_name,
                    attempt + 1,
                    max_retries + 1,
                    delay,
                    last_error.as_ref().unwrap()
                );
                sleep(delay).await;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("module produced no result")))
}

/// Heuristic that decides whether an error is likely transient (network
/// timeouts, DNS resolution failures, connection resets, etc.) and worth
/// retrying.
fn is_transient_error(error: &anyhow::Error) -> bool {
    let message = format!("{}", error).to_lowercase();
    let chain: String = error
        .chain()
        .skip(1)
        .map(|e| format!("{}", e).to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let text = format!("{} {}", message, chain);

    let patterns = [
        "timeout",
        "timed out",
        "connection refused",
        "connection reset",
        "broken pipe",
        "dns",
        "resolve",
        "io error",
        "temporary",
        "try again",
        "would block",
    ];

    patterns.iter().any(|p| text.contains(p))
}

/// If `skip_missing_tools` is enabled and the error looks like a missing
/// external binary, return an informational Finding instead of propagating the
/// error.
fn handle_missing_tool_error(
    module_name: &str,
    error: &anyhow::Error,
    config: &Config,
) -> Option<Finding> {
    if !config.tools.skip_missing_tools {
        return None;
    }

    if is_missing_tool_error(error) {
        Some(
            Finding::new(
                module_name,
                &format!("{} tool unavailable", module_name),
                Severity::Info,
                &format!(
                    "The external tool required by the {} module is missing or not executable: {}. Skipping because tools.skip_missing_tools is true.",
                    module_name, error
                ),
            )
            .with_evidence(format!("{}", error)),
        )
    } else {
        None
    }
}

/// Heuristic that detects errors caused by a missing executable.
fn is_missing_tool_error(error: &anyhow::Error) -> bool {
    let text = format!("{}", error).to_lowercase();
    let patterns = [
        "no such file",
        "not found",
        "cannot find",
        "could not find",
        "is not recognized",
        "program not found",
        "executable not found",
        "failed to find",
    ];
    patterns.iter().any(|p| text.contains(p))
}

/// Token-bucket rate limiter for a single host. Allows short bursts up to the
/// configured rate and refills one token per `1/rate` second.
struct RateLimiter {
    bucket: Mutex<TokenBucket>,
}

impl RateLimiter {
    fn new(rate_per_second: usize) -> Self {
        Self {
            bucket: Mutex::new(TokenBucket::new(rate_per_second.max(1))),
        }
    }

    async fn acquire_one(&self) {
        loop {
            let wait = {
                let mut bucket = self.bucket.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
                bucket.tokens = (bucket.tokens + elapsed * bucket.rate).min(bucket.max_tokens);
                bucket.last_update = now;

                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    return;
                }

                let deficit = 1.0 - bucket.tokens;
                Duration::from_secs_f64(deficit / bucket.rate)
            };
            sleep(wait).await;
        }
    }
}

struct TokenBucket {
    rate: f64,
    max_tokens: f64,
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(rate_per_second: usize) -> Self {
        let rate = rate_per_second as f64;
        Self {
            rate,
            max_tokens: rate,
            tokens: rate,
            last_update: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::finding::Severity;
    use crate::modules::Module;
    use crate::target::Target;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockModule {
        name: &'static str,
        calls: AtomicUsize,
        fail_transient_until: usize,
        fail_permanent: bool,
    }

    impl MockModule {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                calls: AtomicUsize::new(0),
                fail_transient_until: 0,
                fail_permanent: false,
            }
        }

        fn transient_failures(mut self, count: usize) -> Self {
            self.fail_transient_until = count;
            self
        }

        fn permanent_failure(mut self) -> Self {
            self.fail_permanent = true;
            self
        }
    }

    #[async_trait]
    impl Module for MockModule {
        fn name(&self) -> &'static str {
            self.name
        }

        fn description(&self) -> &'static str {
            "mock module for testing"
        }

        async fn run(&self, _target: &Target, _config: &Config) -> Result<Vec<Finding>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);

            if self.fail_permanent {
                anyhow::bail!("permanent failure: something really bad happened");
            }

            if call < self.fail_transient_until {
                anyhow::bail!("connection reset by peer");
            }

            Ok(vec![Finding::new(
                self.name,
                "mock finding",
                Severity::Low,
                "found by mock module",
            )])
        }
    }

    #[tokio::test]
    async fn scanner_runs_enabled_modules() {
        let mut config = Config::load(None).unwrap();
        config.modules.recon.enabled = false;
        config.modules.portscan.enabled = false;
        config.modules.web.enabled = false;
        config.modules.secrets.enabled = false;
        config.modules.tlsaudit.enabled = false;
        config.modules.webvulns.enabled = false;
        config.modules.cms.enabled = false;
        config.modules.nmap.enabled = false;
        config.modules.nuclei.enabled = false;
        config.modules.testssl.enabled = false;
        config.scanner.timeout_ms = 100;

        let scanner = Scanner::new(config).with_rate_limit(None).with_retries(0);

        let target = Target::parse("127.0.0.1").unwrap();
        let report = scanner.run(&target).await.unwrap();
        assert!(report.findings.is_empty());
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_failure() {
        let mut config = Config::load(None).unwrap();
        config.modules.recon.enabled = false;
        config.modules.portscan.enabled = false;
        config.modules.web.enabled = false;
        config.modules.secrets.enabled = false;
        config.scanner.timeout_ms = 100;

        let scanner = Scanner::new(config)
            .with_rate_limit(None)
            .with_retries(2)
            .with_retry_delay(10);

        let module = Arc::new(MockModule::new("mock-transient").transient_failures(2));
        let target = Target::parse("127.0.0.1").unwrap();

        let findings = run_with_retries(
            &*module,
            &target,
            &scanner.config,
            "mock-transient",
            "[1/1]",
            scanner.max_retries,
            scanner.retry_delay_ms,
        )
        .await
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(module.calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn transient_error_detection() {
        let e = anyhow::anyhow!("connection reset by peer");
        assert!(is_transient_error(&e));

        let e = anyhow::anyhow!("permanent failure: something really bad happened");
        assert!(!is_transient_error(&e));
    }

    #[tokio::test]
    async fn missing_tool_error_handled() {
        let mut config = Config::load(None).unwrap();
        config.tools.skip_missing_tools = true;

        let e = anyhow::anyhow!("No such file or directory (os error 2): nmap");
        let finding = handle_missing_tool_error("portscan", &e, &config).unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("tool unavailable"));

        config.tools.skip_missing_tools = false;
        assert!(handle_missing_tool_error("portscan", &e, &config).is_none());
    }

    #[tokio::test]
    async fn is_missing_tool_detection() {
        let e = anyhow::anyhow!("No such file or directory (os error 2)");
        assert!(is_missing_tool_error(&e));

        let e = anyhow::anyhow!("connection reset by peer");
        assert!(!is_missing_tool_error(&e));
    }

    #[tokio::test]
    async fn permanent_failure_not_retried() {
        let mut config = Config::load(None).unwrap();
        config.modules.recon.enabled = false;
        config.modules.portscan.enabled = false;
        config.modules.web.enabled = false;
        config.modules.secrets.enabled = false;
        config.scanner.timeout_ms = 100;

        let module = Arc::new(MockModule::new("mock-permanent").permanent_failure());
        let target = Target::parse("127.0.0.1").unwrap();

        let result =
            run_with_retries(&*module, &target, &config, "mock-permanent", "[1/1]", 2, 10).await;

        assert!(result.is_err());
        assert_eq!(module.calls.load(Ordering::SeqCst), 1);
    }
}
