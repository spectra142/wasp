# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

If you discover a security vulnerability in WASP itself — for example, a way to trigger unsafe code execution, credential exposure, or a crash from untrusted input — please report it responsibly:

1. **Do not open a public issue.**
2. Email the maintainers at the contact address in the repository.
3. Include a clear description, reproduction steps, affected versions, and expected impact.
4. Allow reasonable time for investigation and a patch before disclosing publicly.

We will acknowledge receipt within 5 business days and aim to provide a fix or mitigation within 30 days.

## Responsible use

WASP is a security reconnaissance tool. Only use it against targets you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service.

## Security-related configuration

- Keep `scanner.verify_tls_certificates = true` unless you are testing internal or self-signed targets.
- Run external adapters with least-privilege accounts.
- Review generated reports before sharing; they may contain sensitive target data.
