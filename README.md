# WASP — Web Attack Surface Profiler

[![CI](https://github.com/spectra142/wasp/actions/workflows/ci.yml/badge.svg)](https://github.com/spectra142/wasp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

WASP is a fast, modular security reconnaissance scanner written in Rust. Point it at a domain or IP and it will enumerate DNS records, scan ports, inspect HTTP/TLS configuration, hunt for exposed secrets and files, and generate consolidated reports in JSON, HTML, CSV, Markdown, and SARIF.

> **⚠️ Only scan targets you own or have explicit written permission to test.** Unauthorized scanning may be illegal.

## Features

- **No external dependencies required** for the built-in modules
- **Async/concurrent** scanning with a single global concurrency limit
- **Multiple report formats** out of the box: JSON, HTML, CSV, Markdown, SARIF 2.1.0
- **Optional adapters** for `nmap`, `nuclei`, `testssl.sh`, and `wpscan`
- **Configurable via TOML** with per-module toggles and proxy support
- **Clean exit behavior**: missing external tools can be skipped instead of failing the whole scan

## Built-in modules

| Module | What it checks |
|--------|----------------|
| `recon` | DNS (A/AAAA/MX/NS/TXT), WHOIS with referral following, subdomain brute-force with wildcard detection, technology fingerprinting |
| `portscan` | TCP connect scan, banner grabbing, service/version fingerprinting, TLS-first port handling |
| `web` | Security headers, cookie flags, HTTPS redirect, TLS chain trust |
| `secrets` | Exposed path brute-force, regex-based secret detection, endpoint extraction |
| `tlsaudit` | TLS version/cipher/certificate audit, including deprecated TLS 1.0/1.1 detection |
| `webvulns` | CORS misconfigurations, open redirect, HTTP TRACE/OPTIONS, sensitive files, verbose errors |
| `cmsenum` | Self-contained CMS detection and enumeration (WordPress, Drupal, Joomla) |

## Optional external adapters

| Module | External tool | Enabled by default |
|--------|---------------|-------------------|
| `nmap` | `nmap` | no |
| `nuclei` | `nuclei` | no |
| `testssl` | `testssl.sh` | no |
| `cms` | `wpscan` | no |

## Install

You need Rust 1.80 or newer.

```bash
git clone https://github.com/spectra142/wasp.git
cd wasp
cargo build --release
```

The binary is at `./target/release/wasp`.

## Quick start

```bash
# Scan a target with default settings
./target/release/wasp example.com

# Run only the fast built-in modules
./target/release/wasp example.com --quick

# Run everything, including external adapters if installed
./target/release/wasp example.com --full

# Pick specific modules and write reports to a directory
./target/release/wasp example.com -m recon,web,tlsaudit -o ./report

# Limit concurrency
./target/release/wasp example.com -r 50

# Use a custom config file
./target/release/wasp example.com -c myconfig.toml

# Safe mode: disables port scanning and exposed-path probing
./target/release/wasp example.com --safe-mode

# Disable TLS certificate verification (useful for self-signed/internal targets)
./target/release/wasp example.com --insecure
```

## Output

By default reports are written to `./wasp-report/`:

- `report.json` — structured findings
- `report.html` — human-readable report with severity summary
- `report.csv` — spreadsheet-friendly output
- `report.md` — markdown summary
- `report.sarif` — SARIF 2.1.0 for import into GitHub Code Scanning, DefectDojo, etc.

## Configuration

Copy `config/default.toml` and edit it. Useful options:

- `scanner.concurrency` — global concurrent connection/module-task limit
- `scanner.timeout_ms` — per-request timeout
- `scanner.verify_tls_certificates` — verify HTTPS certificates (default: `true`; disable with `--insecure`)
- `scanner.http_proxy` / `scanner.https_proxy` — optional proxy URLs
- `scanner.custom_headers` — default headers for every HTTP request
- `modules.portscan.top_ports` — number of ports to scan (1..N)
- `modules.recon.subdomain_wordlist` — path to subdomain wordlist
- `modules.secrets.path_wordlist` — path to exposed-path wordlist
- `modules.nmap.enabled` / `modules.nuclei.enabled` / `modules.testssl.enabled` / `modules.cms.enabled` — enable external adapters
- `modules.*.check_http` / `modules.*.check_https` — per-module scheme selection
- `tools.nmap_path`, `tools.nuclei_path`, `tools.testssl_path`, `tools.wpscan_path` — binary paths
- `tools.nmap_timeout_secs`, `tools.testssl_timeout_secs`, `tools.nuclei_timeout_secs`, `tools.wpscan_timeout_secs` — timeouts for heavy external tools
- `tools.skip_missing_tools` — if `true`, missing external tools produce an Info finding instead of an error

Relative wordlist/config paths in a custom config file are resolved against that config file's directory.

## Updating

```bash
cd wasp
git pull
cargo build --release
```

## Development

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add modules, open issues, and submit pull requests.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and responsible-use guidelines.

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, distribute, and take apart.
