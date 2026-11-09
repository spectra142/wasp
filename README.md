# WASP — Web Attack Surface Profiler

[![CI](https://github.com/spectra142/wasp/actions/workflows/ci.yml/badge.svg)](https://github.com/spectra142/wasp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

WASP is a fast, modular security reconnaissance scanner written in Rust. Point it at a domain or IP address and it will discover attack surface: DNS records, open ports, web security issues, leaked secrets, weak TLS settings, and more. It then writes everything into clean reports in JSON, HTML, CSV, Markdown, and SARIF.

> **⚠️ Only scan targets you own or have explicit written permission to test.** Unauthorized scanning may be illegal.

> **🚧 Work in progress.** WASP is still in early development. Expect breaking changes, rough edges, and new modules as the project grows. Issues and pull requests are welcome.

---

## What WASP does

In plain English:

1. You give it a target like `example.com` or `192.168.1.1`.
2. It runs a set of small scanners (modules) against that target.
3. Each module looks for a specific kind of issue.
4. Results are combined, deduplicated, and written to a report folder.

Targets without a port are probed on the standard ports (80 for HTTP, 443 for HTTPS/TLS). Paths that a server answers with a generic catch-all page ("soft 404s") are filtered out so single-page apps don't produce hundreds of false "exposed file" findings.

You can run everything with one command, pick only the modules you want, or tune behavior through a config file.

## Built-in modules

These work out of the box with no extra tools installed:

| Module | What it checks |
|--------|----------------|
| `recon` | DNS records (A/AAAA/MX/NS/TXT), WHOIS with referral following, subdomain brute-force with wildcard detection, technology fingerprinting |
| `portscan` | TCP connect scan, banner grabbing, service/version fingerprinting, TLS-first port handling |
| `web` | Security headers, cookie flags, HTTPS redirect, TLS chain trust |
| `secrets` | Exposed path brute-force, regex-based secret detection, endpoint extraction |
| `tlsaudit` | TLS version/cipher/certificate audit, including deprecated TLS 1.0/1.1 detection |
| `webvulns` | CORS misconfigurations, open redirect, HTTP TRACE/OPTIONS, sensitive files, verbose errors |
| `cmsenum` | Self-contained CMS detection and enumeration (WordPress, Drupal, Joomla) |

## Optional external adapters

If you have these tools installed, WASP can call them:

| Module | External tool | Enabled by default |
|--------|---------------|-------------------|
| `nmap` | `nmap` | no |
| `nuclei` | `nuclei` | no |
| `testssl` | `testssl.sh` | no |
| `cms` | `wpscan` | no |

By default, missing external tools are skipped with an Info finding instead of crashing the scan.

---

## Install

Prebuilt binaries for Linux, macOS (Intel and Apple Silicon) and Windows are attached to each [GitHub release](https://github.com/spectra142/wasp/releases), together with a `SHA256SUMS.txt` file.

To build from source you need [Rust](https://www.rust-lang.org/tools/install) 1.89 or newer.

Open a terminal and run:

```bash
git clone https://github.com/spectra142/wasp.git
cd wasp
cargo build --release
```

This downloads dependencies and builds the scanner. The finished binary is at:

```bash
./target/release/wasp
```

The binary is self-contained: the default config and wordlists are compiled in, so you can copy it anywhere. The `config/` and `wordlists/` folders are only needed if you want to edit them.

---

## How to use it

### Basic scan

```bash
./target/release/wasp example.com
```

This runs the default modules and writes reports to `./wasp-report/`.

### Common options

```bash
# Run only the fast built-in modules
./target/release/wasp example.com --quick

# Run everything, including external adapters if installed
./target/release/wasp example.com --full

# Pick specific modules (unknown names are rejected)
./target/release/wasp example.com -m recon,web,tlsaudit

# List every module and whether it is on by default
./target/release/wasp --list-modules

# Scan a specific port or a URL
./target/release/wasp example.com:8443
./target/release/wasp https://example.com

# Write reports to a custom directory
./target/release/wasp example.com -o ./my-report

# Limit how many connections run at once, and set the per-request timeout (ms)
./target/release/wasp example.com -r 50 -t 3000

# Use a custom config file
./target/release/wasp example.com -c myconfig.toml

# Safe mode: turns off port scanning, exposed-path probing, CMS enumeration
# and the nmap/nuclei/wpscan adapters
./target/release/wasp example.com --safe-mode

# CI gate: exit with status 2 if anything High or worse is found
./target/release/wasp example.com --quick --fail-on high

# Disable TLS certificate verification (useful for self-signed/internal targets)
./target/release/wasp example.com --insecure
```

Run `./target/release/wasp --help` to see every option.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed |
| `1` | Error (bad arguments, unreadable config, report could not be written, ...) |
| `2` | `--fail-on` threshold was met |

Colour output is used only when stdout is a terminal; pass `--no-color` or set `NO_COLOR` to disable it.

---

## Reports

By default WASP creates a `wasp-report/` folder with:

| File | Purpose |
|------|---------|
| `report.json` | Structured findings, easy to feed into other tools |
| `report.html` | Human-readable report with severity summary |
| `report.csv` | Spreadsheet-friendly output |
| `report.md` | Markdown summary |
| `report.sarif` | SARIF 2.1.0 for GitHub Code Scanning, DefectDojo, etc. |

Leaked credentials are redacted in every report (for example `AKIA********MPLE`, `postgres://admin:****@db/app`), so reports can be shared without becoming a second copy of the secret. CSV cells are escaped against spreadsheet formula injection.

---

## Configuration

The built-in defaults live in `config/default.toml`. A custom config is **merged over** those defaults, so it only needs the keys you want to change:

```toml
# myconfig.toml
[scanner]
timeout_ms = 3000
user_agent = "MyCompany-Scanner/1.0"

[modules.nmap]
enabled = true
```

Unknown keys are rejected, so typos are caught instead of silently ignored.

Useful options:

- `scanner.concurrency` — global limit on simultaneous network connections
- `scanner.user_agent` — leave empty to send `WASP/<version>`
- `scanner.timeout_ms` — per-request timeout in milliseconds
- `scanner.verify_tls_certificates` — verify HTTPS certificates (default: `true`; disable with `--insecure`)
- `scanner.http_proxy` / `scanner.https_proxy` — optional proxy URLs
- `scanner.custom_headers` — default headers added to every HTTP request
- `modules.portscan.top_ports` — number of ports to scan (nmap's top-1000 order first, 1..65535)
- `modules.recon.subdomain_wordlist` — path to subdomain wordlist (falls back to the built-in list if unreadable)
- `modules.secrets.path_wordlist` — path to exposed-path wordlist (falls back to the built-in list if unreadable)
- `modules.nmap.enabled` / `modules.nuclei.enabled` / `modules.testssl.enabled` / `modules.cms.enabled` — enable external adapters
- `modules.*.check_http` / `modules.*.check_https` — per-module scheme selection
- `tools.nmap_path`, `tools.nuclei_path`, `tools.testssl_path`, `tools.wpscan_path` — binary paths
- `tools.nmap_timeout_secs`, `tools.testssl_timeout_secs`, `tools.nuclei_timeout_secs`, `tools.wpscan_timeout_secs` — timeouts for heavy external tools
- `tools.skip_missing_tools` — if `true`, missing external tools produce an Info finding instead of an error

If you use a custom config file, relative wordlist paths are resolved against that config file's directory.

---

## Updating

To get the latest version:

```bash
cd wasp
git pull
cargo build --release
```

---

## Development

Run the quality gates before submitting changes:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add modules, open issues, and submit pull requests.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and responsible-use guidelines.

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for a complete file-by-file breakdown of the codebase.

---

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, distribute, and take apart.
