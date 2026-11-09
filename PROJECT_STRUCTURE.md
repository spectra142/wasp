# WASP Project Structure

This file lists every file in the WASP repository and explains what it does.

## Root files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Rust package manifest: name, version, dependencies, authors, license |
| `Cargo.lock` | Locked dependency versions so builds are reproducible |
| `README.md` | Main project documentation: install, usage, configuration |
| `CHANGELOG.md` | History of changes and fixes |
| `CONTRIBUTING.md` | How to contribute, run tests, add modules |
| `SECURITY.md` | Vulnerability reporting and responsible-use policy |
| `LICENSE` | MIT license |
| `.gitignore` | Files and folders Git should ignore |

## Configuration

| File | Purpose |
|------|---------|
| `config/default.toml` | Default scanner configuration: timeouts, concurrency, module toggles, wordlist paths |

## GitHub Actions

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | Runs `cargo fmt`, `cargo clippy`, tests (Linux + macOS), an MSRV check, release builds (Linux + Windows) and a dependency audit on every push/PR |
| `.github/workflows/release.yml` | Builds release binaries for Linux, macOS (Intel + Apple Silicon) and Windows on tags, with SHA-256 checksums |

## Source code (`src/`)

### Core

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point: parses arguments, loads config, starts the scan, prints summary |
| `src/lib.rs` | Crate root: exposes public modules and crate-level docs |
| `src/cli.rs` | clap argument definitions, help text, and summary formatting |
| `src/config.rs` | Configuration structs, embedded defaults and wordlists, merge-over-defaults loading, validation, the shared request limiter, and the HTTP client builder |
| `src/scanner.rs` | `Scanner` orchestrator: runs enabled modules concurrently with retries and panic isolation |
| `src/finding.rs` | `Finding`, `Severity` and `Report` data model, deduplication, and secret redaction |
| `src/http.rs` | Shared HTTP helpers: size-capped body reads and soft-404 (catch-all page) detection |
| `src/target.rs` | `Target` parsing: domains, IPs, IPv6, ports, URL-like inputs |
| `src/tls.rs` | Shared TLS helpers: verified and unverified `tokio_rustls` connectors |

### Modules (`src/modules/`)

| File | Purpose |
|------|---------|
| `src/modules/mod.rs` | Module trait definition and registry of all built-in/external modules |
| `src/modules/recon.rs` | DNS records, WHOIS with referral following, subdomain brute-force with wildcard detection, tech fingerprinting |
| `src/modules/portscan.rs` | TCP connect port scan, banner grabbing, service/version fingerprinting |
| `src/modules/web.rs` | HTTP security headers, cookie flags, HTTPS redirect, TLS trust check |
| `src/modules/secrets.rs` | Exposed path brute-force, regex secret detection, link/endpoint extraction |
| `src/modules/tlsaudit.rs` | TLS version/cipher/certificate audit, legacy TLS 1.0/1.1 detection |
| `src/modules/webvulns.rs` | CORS, open redirect, HTTP TRACE/OPTIONS, sensitive files, verbose errors |
| `src/modules/cms_common.rs` | Shared CMS fingerprinting engine used by `cms` and `cmsenum` |
| `src/modules/cmsenum.rs` | Self-contained CMS enumeration (WordPress, Drupal, Joomla) without external tools |
| `src/modules/cms.rs` | CMS fingerprinting with optional WPScan integration |
| `src/modules/nmap.rs` | Adapter that calls the system `nmap` binary and parses its XML output |
| `src/modules/nuclei.rs` | Adapter that calls `nuclei` and parses JSON-line findings |
| `src/modules/testssl.rs` | Adapter that calls `testssl.sh` and parses its JSON output |
| `src/modules/external.rs` | Shared helpers for running external tools: availability check, runner, output parsing |

### Report writers (`src/report/`)

| File | Purpose |
|------|---------|
| `src/report/mod.rs` | Report dispatcher and shared report types |
| `src/report/json.rs` | JSON report writer |
| `src/report/html.rs` | HTML report writer with severity summary |
| `src/report/csv.rs` | CSV report writer |
| `src/report/markdown.rs` | Markdown report writer |
| `src/report/sarif.rs` | SARIF 2.1.0 report writer |

## Tests (`tests/`)

| File | Purpose |
|------|---------|
| `tests/common/mod.rs` | Shared test helpers: test HTTP/TLS servers, config builders, assertion helpers |
| `tests/integration_tests.rs` | End-to-end tests for web, secrets, and portscan modules |
| `tests/cms.rs` | CMS module integration test with a fake WPScan binary |
| `tests/cmsenum_tests.rs` | CMSEnum module tests |
| `tests/cmsenum_integration.rs` | CMSEnum end-to-end test with a local WordPress-like fixture |
| `tests/nmap_tests.rs` | Nmap adapter tests with a fake nmap binary |
| `tests/nuclei_tests.rs` | Nuclei adapter tests with a fake nuclei binary |
| `tests/portscan_tests.rs` | Portscan unit-style integration tests |
| `tests/portscan_integration_tests.rs` | Portscan end-to-end tests |
| `tests/scanner_tests.rs` | Scanner orchestrator concurrency tests |
| `tests/secrets_tests.rs` | Secrets module tests |
| `tests/tlsaudit_tests.rs` | TLSAudit module tests with a local TLS server |
| `tests/web_tests.rs` | Web module tests |
| `tests/webvulns_tests.rs` | WebVulns module tests |
| `tests/fixtures/selfsigned.pem` | Self-signed certificate for TLS tests |
| `tests/fixtures/selfsigned.key` | Private key for TLS tests |

## Wordlists (`wordlists/`)

| File | Purpose |
|------|---------|
| `wordlists/subdomains.txt` | Subdomain brute-force wordlist |
| `wordlists/exposed_paths.txt` | Exposed path/file brute-force wordlist |

---

Total: 57 tracked files.
