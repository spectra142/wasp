# Contributing to WASP

Thanks for your interest in WASP! This document covers how to get started, open issues, submit pull requests, and keep the codebase healthy.

## Code of conduct

Be respectful, constructive, and assume good intent. Harassment or abusive behavior will not be tolerated.

## How to contribute

1. **Open an issue first** for large changes, new modules, or architectural shifts so we can agree on direction before you invest time.
2. **Fork the repo** and create a feature branch (`git checkout -b feature/my-thing`).
3. **Make your changes** with tests and documentation updates.
4. **Run the quality gates** (see below).
5. **Open a pull request** with a clear description, motivation, and testing notes.

## Development setup

```bash
git clone https://github.com/spectra142/wasp.git
cd wasp
cargo build --release
```

## Quality gates

Run these before pushing:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

PRs that fail CI will not be merged.

## Project structure

```
src/
  main.rs        # CLI entry point and orchestration
  lib.rs         # Crate root, module exports
  cli.rs         # clap argument definitions
  config.rs      # Configuration loading and defaults
  finding.rs     # Finding data model and report generation
  target.rs      # Target parsing and normalization
  tls.rs         # Shared TLS helpers
  modules/       # Scanner modules and adapters
```

## Adding a module

1. Create a new file under `src/modules/`.
2. Implement the `Module` trait from `crate::modules::Module`.
3. Add module configuration under `Config.modules` in `src/config.rs`.
4. Register the module in `src/modules/mod.rs` and `src/main.rs`.
5. Add tests in the module file or under `tests/`.
6. Update `README.md`, `config/default.toml`, and this guide if needed.

## Testing

- Unit tests live next to the code (`#[cfg(test)]` modules).
- Integration tests live in `tests/`.
- Aim for coverage of error paths, not just happy paths.
- Avoid real network calls in tests; use local listeners or canned data.

## Commit messages

Use clear, imperative commit messages:

- `Add HTTP security header checks`
- `Fix TLS 1.0 probe alert parsing`
- `Refactor shared TLS connector helpers`

## Security

If you discover a security issue in WASP itself, please follow the instructions in `SECURITY.md` rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
