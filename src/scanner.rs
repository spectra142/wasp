use crate::config::Config;
use crate::finding::{Finding, Report, Severity};
use crate::modules::{enabled_modules, Module};
use crate::target::Target;
use anyhow::Result;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Default number of retries for module runs that fail with a transient error.
const DEFAULT_MAX_RETRIES: usize = 2;

/// Initial delay between retries; doubles on each attempt (exponential backoff).
const DEFAULT_RETRY_DELAY_MS: u64 = 500;

/// Runs every enabled module against a target and collects the results into a
/// [`Report`].
///
/// All modules start concurrently. Network-level concurrency is bounded by the
/// shared request limiter in [`Config::request_limiter`], which every module
/// acquires before opening a connection. The scanner itself deliberately does
/// *not* hold limiter permits while a module runs: doing so would let a small
/// `--rate` value starve the modules of permits and deadlock the scan.
pub struct Scanner {
    config: Config,
    modules: Vec<Arc<dyn Module>>,
    /// Maximum retry attempts for transient failures.
    max_retries: usize,
    /// Initial retry delay in milliseconds.
    retry_delay_ms: u64,
}

impl Scanner {
    pub fn new(mut config: Config) -> Self {
        // Always build the limiter from the final concurrency value so changes
        // made after `Config::load` (CLI flags, tests) take effect.
        config.reset_request_limiter();
        let modules = enabled_modules(&config);
        Self::with_modules(config, modules)
    }

    /// Build a scanner that runs an explicit list of modules instead of the
    /// ones enabled in `config`. Mainly useful for embedding and testing.
    pub fn with_modules(config: Config, modules: Vec<Arc<dyn Module>>) -> Self {
        Self {
            config,
            modules,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
        }
    }

    /// Names of the modules this scanner will run.
    pub fn module_names(&self) -> Vec<&'static str> {
        self.modules.iter().map(|m| m.name()).collect()
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
        report.modules = self.module_names().iter().map(|m| m.to_string()).collect();

        info!(
            "starting scan of {} with {} module(s), concurrency={}, retries={}",
            target,
            self.modules.len(),
            self.config.scanner.concurrency,
            self.max_retries
        );

        let total = self.modules.len();
        let mut handles = Vec::with_capacity(total);

        for (idx, module) in self.modules.iter().enumerate() {
            let module_name = module.name();
            let target = target.clone();
            let config = self.config.clone();
            let module = Arc::clone(module);
            let max_retries = self.max_retries;
            let retry_delay_ms = self.retry_delay_ms;
            let progress = format!("[{}/{}]", idx + 1, total);

            let handle = tokio::spawn(async move {
                info!("{} [{}] starting", progress, module_name);

                let start = Instant::now();
                let result = run_with_retries(
                    &*module,
                    &target,
                    &config,
                    module_name,
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
                            "{} [{}] failed after {:?}: {:#}",
                            progress, module_name, elapsed, e
                        );

                        if let Some(finding) = handle_missing_tool_error(module_name, &e, &config) {
                            warn!(
                                "[{}] treating failure as missing-tool finding because skip_missing_tools=true",
                                module_name
                            );
                            vec![finding]
                        } else {
                            vec![module_failed_finding(
                                module_name,
                                &format!("The module encountered an error: {:#}", e),
                            )]
                        }
                    }
                }
            });
            handles.push((module_name, handle));
        }

        for (module_name, handle) in handles {
            match handle.await {
                Ok(findings) => report.add_findings(findings),
                Err(e) => {
                    // A panicking module must not take the rest of the scan
                    // (and every other module's findings) down with it.
                    error!("[{}] module task aborted: {}", module_name, e);
                    report.add_findings(vec![module_failed_finding(
                        module_name,
                        &format!("The module crashed unexpectedly: {}", e),
                    )]);
                }
            }
        }

        report.deduplicate();
        report.finalize();
        let critical_high = report
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .count();

        info!(
            "scan complete for {}: {} finding(s), {} critical/high",
            target,
            report.findings.len(),
            critical_high
        );
        Ok(report)
    }
}

fn module_failed_finding(module_name: &str, description: &str) -> Finding {
    Finding::new(
        module_name,
        &format!("{} module failed", module_name),
        Severity::Info,
        description,
    )
    .with_remediation("Re-run with -vv for details. The module's checks did not complete.")
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
    let text = format!("{:#}", error).to_lowercase();
    let patterns = [
        "no such file",
        "binary not found",
        "command not found",
        "nmap not found",
        "cannot find",
        "could not find",
        "is not recognized",
        "program not found",
        "executable not found",
        "failed to find",
    ];
    patterns.iter().any(|p| text.contains(p))
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

        let scanner = Scanner::new(config).with_retries(0);

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

        let scanner = Scanner::new(config).with_retries(2).with_retry_delay(10);

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

    struct LimiterModule(&'static str);

    #[async_trait]
    impl Module for LimiterModule {
        fn name(&self) -> &'static str {
            self.0
        }
        fn description(&self) -> &'static str {
            "acquires request permits like the real network modules"
        }
        async fn run(&self, _target: &Target, config: &Config) -> Result<Vec<Finding>> {
            for _ in 0..3 {
                let _permit = config.request_limiter().acquire_owned().await?;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(vec![Finding::new(self.0, "done", Severity::Info, "done")])
        }
    }

    #[tokio::test]
    async fn concurrency_of_one_does_not_deadlock() {
        let mut config = Config::load(None).unwrap();
        config.scanner.concurrency = 1;
        config.reset_request_limiter();
        let modules: Vec<Arc<dyn Module>> = vec![
            Arc::new(LimiterModule("a")),
            Arc::new(LimiterModule("b")),
            Arc::new(LimiterModule("c")),
        ];
        let scanner = Scanner::with_modules(config, modules).with_retries(0);
        let target = Target::parse("127.0.0.1").unwrap();
        let report = tokio::time::timeout(Duration::from_secs(5), scanner.run(&target))
            .await
            .expect("scan deadlocked")
            .unwrap();
        assert_eq!(report.findings.len(), 3);
    }

    struct PanicModule;

    #[async_trait]
    impl Module for PanicModule {
        fn name(&self) -> &'static str {
            "panicky"
        }
        fn description(&self) -> &'static str {
            "always panics"
        }
        async fn run(&self, _target: &Target, _config: &Config) -> Result<Vec<Finding>> {
            panic!("boom");
        }
    }

    #[tokio::test]
    async fn panicking_module_does_not_abort_scan() {
        let config = Config::load(None).unwrap();
        let modules: Vec<Arc<dyn Module>> =
            vec![Arc::new(PanicModule), Arc::new(MockModule::new("ok"))];
        let scanner = Scanner::with_modules(config, modules).with_retries(0);
        let target = Target::parse("127.0.0.1").unwrap();
        let report = scanner.run(&target).await.unwrap();
        assert!(report.findings.iter().any(|f| f.module == "ok"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.module == "panicky" && f.title.contains("failed")));
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
