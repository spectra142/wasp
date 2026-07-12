# Changelog

All notable changes to WASP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release of WASP — Web Attack Surface Profiler.
- Built-in async modules: `recon`, `portscan`, `web`, `secrets`, `tlsaudit`, `webvulns`, `cmsenum`.
- Optional external adapters: `nmap`, `nuclei`, `testssl`, `cms`.
- Report output in JSON, HTML, CSV, Markdown, and SARIF 2.1.0.
- Shared TLS helper module (`src/tls.rs`) for consistent certificate verification behavior.
- `--quick`, `--full`, `--safe-mode`, `--insecure`, and module-selection CLI flags.
- Configuration via TOML (`config/default.toml`).
- Optional `scanner.http_proxy`, `scanner.https_proxy`, and `scanner.custom_headers` config.
- Per-module `check_http` / `check_https` scheme selection.

### Changed
- Unified TLS certificate verification across `web` and `tlsaudit` modules.
- README build instructions now use the correct relative path (`cd wasp`).
- `web` module certificate checks are now lightweight; detailed cert analysis lives in `tlsaudit`.
- SARIF `ruleId` now uses a stable `{module}/{title-slug}` format.
- Rust edition downgraded to `2021` for broader toolchain compatibility.

### Fixed
- Legacy TLS 1.0/1.1 probes now correctly parse Alert records and report protocol-version alerts.
- Deduplication normalizes `http://`/`https://` prefixes for header and cookie findings.
- Nuclei timeout log now reports the configured `nuclei_timeout_secs` value.
- `scanner.concurrency` is now a true global limit via a shared semaphore.
- Portscan no longer discards TLS-first ports when the plaintext probe triggers a TLS alert.
- `tlsaudit` now reports unknown/legacy cipher suites as `Weak` instead of silently dropping them.
- Subdomain brute-force detects wildcard DNS records and aborts to avoid false positives.
- WHOIS queries now follow IANA referrals to authoritative servers.
- Relative wordlist paths in custom configs resolve against the config file directory.
- Target parser now rejects inputs with paths.
- Crypto provider is consistently `aws_lc_rs` in production and tests.
- testssl.sh temporary file uses `tempfile::NamedTempFile` to avoid race conditions.
- `--rate` / `-r` now correctly rebuilds the global concurrency semaphore instead of only updating the logged number.
- nmap module now passes `-Pn` so scans proceed even when ICMP host discovery is filtered.

## [0.1.0] - 2026-07-12

- First tagged release.
