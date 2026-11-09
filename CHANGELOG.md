# Changelog

All notable changes to WASP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-09

### Fixed
- **TLS checks were broken for bare hostnames.** `tlsaudit`, the `web` certificate check and `testssl` connected to `host` with no port, so `wasp example.com` always reported "TLS service unreachable". They now default to port 443.
- **Deadlock with low `--rate`.** The scanner held a concurrency permit per module while modules waited on the same semaphore for their own requests; `-r 1` (or any value below the number of active modules) could hang forever. Modules now share the limiter only for network operations.
- `web` reported "TLS certificate chain not trusted" (High) for hosts that do not speak TLS at all.
- `web` reported missing HSTS on plain-HTTP responses, where browsers ignore the header.
- `tlsaudit` flagged every ECDSA certificate as a "weak key" (256 < 2048); key size is now judged per algorithm.
- Legacy TLS 1.0/1.1 probes now require the server to actually select the probed version.
- `portscan` built invalid addresses for IPv6 targets and re-resolved DNS for every port; it now resolves once and connects by socket address.
- `testssl` could never succeed: testssl.sh refuses to overwrite an existing file and its JSON shape did not match the parser. It now writes to a fresh path and parses flat, legacy and sectioned JSON.
- Catch-all ("soft 404") sites produced a finding for every probed path in `secrets` and `webvulns`; a baseline of random paths is now used to filter them.
- `cmsenum` reported "XML-RPC enabled" for any HTTP 200 on `xmlrpc.php`.
- Open-redirect detection matched the payload anywhere in `Location` (e.g. `/login?next=...`); it now checks the resolved redirect host.
- `TRACE` was reported whenever the server answered 200; the request must now be echoed back.
- Verbose-error detection no longer fires on ordinary words such as "warning:" or "on line".
- Deduplication merged unrelated findings from different modules that shared a title.
- A panicking module aborted the whole scan and discarded every other module's results.
- WHOIS responses were truncated to the first TCP read.
- `--modules` silently ignored unknown module names.
- Missing wordlists silently disabled subdomain brute-force and exposed-path checks.
- External tool detection relied on `which`, which does not exist on Windows.
- Real-nmap integration tests failed when nmap is not installed (including on CI runners); they are now skipped.

### Security
- Leaked secrets are redacted in all report evidence, including response snippets; cookie values are no longer copied into reports.
- CSV reports escape cells that would be interpreted as spreadsheet formulas.
- Markdown reports can no longer be broken out of by evidence containing backticks or HTML.
- Response bodies are read with a 2 MiB cap.
- nmap/testssl hostnames are passed after `--` so they cannot be parsed as options.

### Added
- `--fail-on <severity>` (exit status 2) for CI pipelines, `--list-modules`, `--timeout`, `--no-color` (and `NO_COLOR` / non-TTY detection).
- Custom config files are merged over the defaults (partial configs work) and unknown keys are rejected.
- Default and exposed-path wordlists are embedded in the binary as a fallback.
- Bare IPv6 targets (`::1`), plus rejection of URLs with query strings.
- `web`: weak HSTS `max-age` check. `tlsaudit`: not-yet-valid and tiered expiry checks.
- SARIF output now includes `rules` with GitHub `security-severity` scores.
- Reports record the WASP version and the modules that ran.
- Release builds for Apple Silicon and a `SHA256SUMS.txt` file; CI now runs on macOS, checks the MSRV, builds on Windows and audits dependencies.

### Changed
- Upgraded dependencies: `trust-dns-resolver` (unmaintained) → `hickory-resolver` 0.26 (uses the system resolver config), `reqwest` 0.13, `webpki-roots` 1, `x509-parser` 0.18, `toml` 1, `askama` 0.16, `quick-xml` 0.42. Removed unused `thiserror`, `ipnet` and `tokio-test`.
- Minimum supported Rust version is now 1.89.
- `--safe-mode` also disables `nmap`, `nuclei`, `cms` and `cmsenum`.
- Supporting TLS 1.2 is no longer reported as a Low finding (it is still listed in the supported-versions summary); missing TLS 1.3 is Low instead of Medium.
- `robots.txt`, `sitemap.xml` and `.well-known/` documents are Info rather than Low/High.
- `nuclei` runs with `-jsonl -silent -nc -duc`; `testssl.sh` runs in batch mode.
- Default User-Agent tracks the crate version (`WASP/<version>`).
- `Scanner::with_rate_limit` was removed (it only throttled module start-up); use `scanner.concurrency` / `-r`.

## [0.1.x]

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
- README rewritten for a general audience with clearer install/run instructions and a development-warning notice.

## [0.1.0] - 2026-07-12

- First tagged release.
