---
title: Contributing
layout: default
nav_order: 9
description: "How to contribute to Depsy"
---

# Contributing
{: .no_toc }

Guidelines for contributing to Depsy.
{: .fs-6 .fw-300 }

---

## Get Involved

We welcome contributions! See the full [Contributing Guide](https://github.com/mpiton/zed-depsy/blob/main/CONTRIBUTING.md) for detailed information on:

- Setting up your development environment
- Code style and standards
- Adding support for new languages
- Submitting pull requests

## Quick Links

- [GitHub Repository](https://github.com/mpiton/zed-depsy)
- [Issue Tracker](https://github.com/mpiton/zed-depsy/issues)
- [Pull Requests](https://github.com/mpiton/zed-depsy/pulls)
- [Changelog](https://github.com/mpiton/zed-depsy/blob/main/CHANGELOG.md)

## Types of Contributions

We welcome:
- Bug reports and fixes
- New language/package manager support
- Performance improvements
- Documentation improvements
- Feature requests and implementations

## Development Setup

### Prerequisites

- **Rust 1.94+** (edition 2024)
- **Zed Editor** (latest stable)
- **wasm32-wasip1 target**: `rustup target add wasm32-wasip1`

### Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/zed-depsy.git
cd zed-depsy

# Build LSP
cd depsy-lsp
cargo build --release

# Build extension
cd ../depsy-zed
cargo build --release --target wasm32-wasip1

# Install as dev extension in Zed
# Run: zed: install dev extension
# Select: depsy-zed directory
```

### Running Tests

```bash
cd depsy-lsp

# All tests
cargo test

# Specific modules
cargo test parsers::cargo
cargo test registries::npm

# With output
cargo test -- --nocapture
```

### Code Quality

```bash
# Formatting
cargo fmt --all

# Linting (warnings as errors)
cargo clippy --all-targets -- -D warnings
```

## Commit Convention

Use conventional commit format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Tests
- `chore:` Maintenance

Examples:
```text
feat: add support for Ruby gems
fix: handle scoped npm packages correctly
docs: improve installation instructions
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
