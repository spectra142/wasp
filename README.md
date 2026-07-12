# WASP — Web Attack Surface Profiler

[![CI](https://github.com/spectra142/wasp/actions/workflows/ci.yml/badge.svg)](https://github.com/spectra142/wasp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

WASP is a modular, async security reconnaissance scanner written in Rust. Given a domain or IP, it discovers attack surface, scans ports, inspects web security posture, hunts exposed secrets and files, and produces consolidated reports.

> **⚠️ Legal warning:** Only scan targets you own or have explicit written permission to test. Unauthorized scanning may be illegal.

## What it does

Built-in modules (no external tools required):

| Module | Checks |
|--------|--------|
| `recon` | DNS records (A/AAAA/MX/NS/TXT), WHOIS, subdomain brute-force, technology fingerprinting |
| `portscan` | Async TCP connect scan with banner grabbing and service/version fingerprinting |
| `web` | Security headers, HTTPS redirect, cookie flags, basic TLS certificate info |
| `secrets` | Exposed path brute-force, regex-based secret detection, link/endpoint extraction |
| `tlsaudit` | Built-in TLS version/cipher/certificate audit, including deprecated TLS 1.0/1.1 detection |
| `webvulns` | CORS misconfig, open redirect, HTTP TRACE/OPTIONS, sensitive files, verbose errors |
| `cmsenum` | Self-contained CMS detection and enumeration (WordPress/Drupal/Joomla) |

Optional external adapters (disabled by default):

| Module | External tool |
|--------|---------------|
| `nmap` | `nmap` |
| `nuclei` | `nuclei` |
| `testssl` | `testssl.sh` |
| `cms` | `wpscan` |

## Build

Requires a recent Rust toolchain (1.70+).

```bash
cd Projects/wasp
cargo build --release
```

## Installation

```bash
git clone https://github.com/spectra142/wasp.git
cd wasp
cargo build --release
# Binary will be at ./target/release/wasp
```

## Usage

```bash
# One command — just give it a target
./target/release/wasp example.com

# Only the fast built-in modules
./target/release/wasp example.com --quick

# Everything, including external adapters if you have them installed
./target/release/wasp example.com --full

# Run specific modules
./target/release/wasp example.com -m recon,web -o ./report

# Limit concurrency
./target/release/wasp example.com -r 50 -o ./report

# Use a custom config
./target/release/wasp example.com -c myconfig.toml -o ./report

# Safe mode: disables port scanning and exposed-path probing
./target/release/wasp example.com --safe-mode -o ./report

# Disable TLS certificate verification (useful for self-signed/internal targets)
./target/release/wasp example.com --insecure -o ./report
```

Reports are written to the output directory:

- `report.json` — structured findings
- `report.html` — human-readable report with severity summary
- `report.csv` — spreadsheet-friendly output
- `report.md` — markdown summary
- `report.sarif` — SARIF 2.1.0 for import into code/security scanners

## Configuration

The default config is `config/default.toml`. Copy it and tune:

- `scanner.concurrency` — global concurrent connection limit
- `scanner.timeout_ms` — per-request timeout
- `scanner.verify_tls_certificates` — verify HTTPS certificates (default: true; disable with `--insecure`)
- `modules.portscan.top_ports` — number of ports to scan (1..N)
- `modules.recon.subdomain_wordlist` — path to subdomain wordlist
- `modules.secrets.path_wordlist` — path to exposed-path wordlist
- `modules.nmap.enabled` / `modules.nuclei.enabled` / `modules.testssl.enabled` / `modules.cms.enabled` — enable external adapters
- `modules.cmsenum.enabled` — enable the self-contained CMS enumerator (default: true)
- `tools.nmap_path`, `tools.nuclei_path`, `tools.testssl_path`, `tools.wpscan_path`, etc. — binary paths
- `tools.nmap_timeout_secs`, `tools.testssl_timeout_secs`, `tools.nuclei_timeout_secs`, `tools.wpscan_timeout_secs` — module-specific timeouts for heavy external tools
- `tools.skip_missing_tools` — if true, missing external tools produce an Info finding instead of an error

## Testing

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

## Roadmap

- More external adapters: OWASP ZAP, `ffuf`, `gitleaks`, `trufflehog`, `masscan`
- Cloud/container misconfiguration adapters
- Manual pen-test checklist generator based on discovered tech stack
- Report filtering and suppression rules

## License

MIT
