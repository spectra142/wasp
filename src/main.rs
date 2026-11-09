use clap::Parser;
use log::info;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::process::ExitCode;
use wasp::cli::{format_summary_with_color, Args};
use wasp::config::{Config, MODULE_NAMES};
use wasp::modules::enabled_modules;
use wasp::scanner::Scanner;
use wasp::target::Target;

/// Exit status used when `--fail-on` is triggered.
const EXIT_FINDINGS: u8 = 2;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<ExitCode> {
    // Install a default Rustls crypto provider so TLS modules work without
    // requiring users to configure Cargo features or environment variables.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();
    init_logger(args.verbose);

    if args.list_modules {
        print_modules();
        return Ok(ExitCode::SUCCESS);
    }

    args.validate_modules().map_err(anyhow::Error::msg)?;
    let target_arg = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("a target is required"))?;
    let target = Target::parse(target_arg)?;

    let mut config = Config::load(args.config.as_deref())?;

    if let Some(rate) = args.rate {
        config.scanner.concurrency = rate as usize;
    }
    if let Some(timeout) = args.timeout {
        config.scanner.timeout_ms = timeout;
    }

    if args.insecure {
        log::warn!("TLS certificate verification disabled; connections are vulnerable to MITM");
        config.scanner.verify_tls_certificates = false;
    }

    apply_profile(&mut config, &args);

    if args.safe_mode {
        info!("safe mode enabled: disabling portscan, secrets, nmap, nuclei, cms and cmsenum");
        config.modules.portscan.enabled = false;
        config.modules.secrets.enabled = false;
        config.modules.nmap.enabled = false;
        config.modules.nuclei.enabled = false;
        config.modules.cms.enabled = false;
        config.modules.cmsenum.enabled = false;
    }

    config.validate()?;
    if enabled_modules(&config).is_empty() {
        anyhow::bail!("no modules are enabled; pick some with -m or use --full/--quick");
    }

    info!("target: {}", target);

    let scanner = Scanner::new(config);
    let report = scanner.run(&target).await?;

    wasp::report::write_reports(&report, &args.output)?;
    info!("reports written to {:?}", args.output);

    let color =
        !args.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    println!(
        "{}",
        format_summary_with_color(&report, &args.output, 5, color)
    );

    if let Some(threshold) = args.fail_on {
        if report.findings.iter().any(|f| f.severity >= threshold) {
            eprintln!(
                "findings at or above '{}' severity were reported; exiting with status {}",
                threshold, EXIT_FINDINGS
            );
            return Ok(ExitCode::from(EXIT_FINDINGS));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn print_modules() {
    let config = match Config::load(None) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut all = config.clone();
    enable_all_modules(&mut all);
    let defaults: HashSet<&str> = enabled_modules(&config).iter().map(|m| m.name()).collect();
    println!("{:<10} {:<8} DESCRIPTION", "MODULE", "DEFAULT");
    for name in MODULE_NAMES {
        if let Some(module) = enabled_modules(&all)
            .into_iter()
            .find(|m| m.name() == *name)
        {
            let on = if defaults.contains(name) { "on" } else { "off" };
            println!("{:<10} {:<8} {}", name, on, module.description());
        }
    }
}

/// Apply the user's chosen module profile (--full, --quick, --modules) on top
/// of the loaded configuration. When none of these flags are supplied the
/// embedded config defaults are used unchanged.
fn apply_profile(config: &mut Config, args: &Args) {
    if args.full {
        enable_all_modules(config);
    } else if args.quick {
        enable_quick_modules(config);
    } else if let Some(ref modules) = args.modules {
        enable_selected_modules(config, modules);
    }
}

fn enable_all_modules(config: &mut Config) {
    config.modules.recon.enabled = true;
    config.modules.portscan.enabled = true;
    config.modules.web.enabled = true;
    config.modules.secrets.enabled = true;
    config.modules.tlsaudit.enabled = true;
    config.modules.webvulns.enabled = true;
    config.modules.cms.enabled = true;
    config.modules.cmsenum.enabled = true;
    config.modules.nmap.enabled = true;
    config.modules.nuclei.enabled = true;
    config.modules.testssl.enabled = true;
}

fn enable_quick_modules(config: &mut Config) {
    config.modules.recon.enabled = true;
    config.modules.web.enabled = true;
    config.modules.tlsaudit.enabled = true;
    config.modules.webvulns.enabled = true;

    config.modules.portscan.enabled = false;
    config.modules.secrets.enabled = false;
    config.modules.cms.enabled = false;
    config.modules.cmsenum.enabled = false;
    config.modules.nmap.enabled = false;
    config.modules.nuclei.enabled = false;
    config.modules.testssl.enabled = false;
}

fn enable_selected_modules(config: &mut Config, modules: &[String]) {
    let wanted: HashSet<String> = modules.iter().map(|m| m.trim().to_lowercase()).collect();
    config.modules.recon.enabled = wanted.contains("recon");
    config.modules.portscan.enabled = wanted.contains("portscan");
    config.modules.web.enabled = wanted.contains("web");
    config.modules.secrets.enabled = wanted.contains("secrets");
    config.modules.tlsaudit.enabled = wanted.contains("tlsaudit");
    config.modules.webvulns.enabled = wanted.contains("webvulns");
    config.modules.cms.enabled = wanted.contains("cms");
    config.modules.cmsenum.enabled = wanted.contains("cmsenum");
    config.modules.nmap.enabled = wanted.contains("nmap");
    config.modules.nuclei.enabled = wanted.contains("nuclei");
    config.modules.testssl.enabled = wanted.contains("testssl");
}

fn init_logger(verbose: u8) {
    // Dependencies log expected scan conditions (an untrusted certificate, a
    // failed DNS query) at ERROR/WARN. WASP reports those as findings, so keep
    // their logs quiet unless -vv is used.
    let filter = match verbose {
        0 => "warn,rustls_platform_verifier=off,hickory_proto=off,hickory_resolver=off,hickory_net=off",
        1 => "info,rustls_platform_verifier=off,hickory_proto=warn,hickory_resolver=warn,hickory_net=warn",
        _ => "debug",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter))
        .format_timestamp_secs()
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_disabled_config() -> Config {
        let mut config = Config::load(None).unwrap();
        config.modules.recon.enabled = false;
        config.modules.portscan.enabled = false;
        config.modules.web.enabled = false;
        config.modules.secrets.enabled = false;
        config.modules.tlsaudit.enabled = false;
        config.modules.webvulns.enabled = false;
        config.modules.cms.enabled = false;
        config.modules.cmsenum.enabled = false;
        config.modules.nmap.enabled = false;
        config.modules.nuclei.enabled = false;
        config.modules.testssl.enabled = false;
        config
    }

    fn args_with_target() -> Args {
        Args::try_parse_from(["wasp", "example.com"]).unwrap()
    }

    #[test]
    fn full_profile_enables_all_modules() {
        let mut args = args_with_target();
        args.full = true;

        let mut config = all_disabled_config();
        apply_profile(&mut config, &args);

        assert!(config.modules.recon.enabled);
        assert!(config.modules.portscan.enabled);
        assert!(config.modules.web.enabled);
        assert!(config.modules.secrets.enabled);
        assert!(config.modules.tlsaudit.enabled);
        assert!(config.modules.webvulns.enabled);
        assert!(config.modules.cms.enabled);
        assert!(config.modules.nmap.enabled);
        assert!(config.modules.nuclei.enabled);
        assert!(config.modules.testssl.enabled);
    }

    #[test]
    fn quick_profile_enables_only_fast_builtins() {
        let mut args = args_with_target();
        args.quick = true;

        let mut config = all_disabled_config();
        apply_profile(&mut config, &args);

        assert!(config.modules.recon.enabled);
        assert!(config.modules.web.enabled);
        assert!(config.modules.tlsaudit.enabled);
        assert!(config.modules.webvulns.enabled);

        assert!(!config.modules.portscan.enabled);
        assert!(!config.modules.secrets.enabled);
        assert!(!config.modules.cms.enabled);
        assert!(!config.modules.cmsenum.enabled);
        assert!(!config.modules.nmap.enabled);
        assert!(!config.modules.nuclei.enabled);
        assert!(!config.modules.testssl.enabled);
    }

    #[test]
    fn selected_modules_profile_respects_list() {
        let mut args = args_with_target();
        args.modules = Some(vec!["recon".to_string(), "nmap".to_string()]);

        let mut config = all_disabled_config();
        apply_profile(&mut config, &args);

        assert!(config.modules.recon.enabled);
        assert!(config.modules.nmap.enabled);
        assert!(!config.modules.portscan.enabled);
        assert!(!config.modules.web.enabled);
        assert!(!config.modules.tlsaudit.enabled);
    }

    #[test]
    fn no_profile_uses_config_defaults() {
        let args = args_with_target();
        let mut config = all_disabled_config();
        apply_profile(&mut config, &args);

        // Without --full/--quick/--modules the config is left as loaded.
        assert!(!config.modules.recon.enabled);
        assert!(!config.modules.web.enabled);
        assert!(!config.modules.nmap.enabled);
    }
}
