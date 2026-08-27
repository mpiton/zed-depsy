# Contributing to Depsy for Zed

Thank you for your interest in contributing to Depsy! This extension helps developers manage dependencies directly in the Zed editor, and we welcome contributions from the community.

## Types of Contributions

We welcome:
- Bug reports and fixes
- New language/package manager support
- Performance improvements
- Documentation improvements
- Feature requests and implementations

## Getting Started

### Prerequisites

- **Rust 1.94+** (tested with the latest stable)
- **Zed Editor** (latest stable)
- **wasm32-wasip1 target**: `rustup target add wasm32-wasip1`

### Setting Up the Development Environment

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/zed-depsy.git
   cd zed-depsy
   ```

2. **Build the LSP**
   ```bash
   cd depsy-lsp
   cargo build --release
   ```

3. **Build the extension**
   ```bash
   cd ../depsy-zed
   cargo build --release --target wasm32-wasip1
   ```

4. **Install as dev extension in Zed**
   - Open Zed
   - Run command: `zed: install dev extension`
   - Select the `depsy-zed` directory

### Project Structure

```text
zed-depsy/
├── depsy-lsp/           # Language Server (Rust binary)
│   ├── src/
│   │   ├── main.rs        # Entry point
│   │   ├── lib.rs         # Library exports
│   │   ├── backend.rs     # LSP implementation
│   │   ├── config.rs      # Configuration management
│   │   ├── document.rs    # Document/text utilities
│   │   ├── file_types.rs  # File type detection
│   │   ├── reports.rs     # Vulnerability report generation
│   │   ├── utils.rs       # Shared utilities
│   │   ├── auth/          # Registry authentication
│   │   ├── parsers/       # Dependency file parsers + lockfile resolvers
│   │   ├── registries/    # Package registry clients
│   │   ├── providers/     # LSP features (hints, diagnostics, doc links, etc.)
│   │   ├── cache/         # Caching layer (memory + SQLite)
│   │   └── vulnerabilities/ # Security scanning via OSV
│   └── tests/             # Integration tests
├── depsy-zed/           # Zed Extension (WASM)
│   ├── extension.toml     # Extension metadata
│   └── src/lib.rs         # Download + launch LSP
└── .github/workflows/     # CI/CD
```

## Development Workflow

1. **Fork the repository** on GitHub

2. **Create a feature branch**
   ```bash
   git checkout -b feature/my-feature
   ```

3. **Make your changes** following the code style guidelines below

4. **Run tests**
   ```bash
   cd depsy-lsp
   cargo test
   ```

5. **Run formatting**
   ```bash
   cargo fmt --all
   ```

6. **Run clippy** (all warnings as errors)
   ```bash
   cargo clippy --all-targets -- -D warnings
   ```

7. **Commit your changes**
   ```bash
   git commit -m "feat: add support for X"
   ```

8. **Push to your fork**
   ```bash
   git push origin feature/my-feature
   ```

9. **Open a Pull Request** against the `main` branch

## Code Style and Standards

### Rust Guidelines

- **Formatting**: Use `cargo fmt` before committing
- **Linting**: All clippy warnings must be resolved (`-D warnings`)
- **Naming conventions**:
  - `snake_case` for functions and variables
  - `PascalCase` for types and structs
  - `SCREAMING_SNAKE_CASE` for constants
- **Error handling**:
  - Use `anyhow::Result` for internal errors
  - Use `thiserror` for public API errors
  - Avoid `unwrap()` and `expect()` in production code
- **Async I/O**: Use `tokio::fs` instead of `std::fs` for file operations

### Documentation

- Document public APIs with doc comments (`///`)
- Include examples in doc comments where helpful
- Keep comments concise and meaningful

## Adding Support for New Languages

To add support for a new package manager/language:

### 1. Create a Parser

Create a new file in `depsy-lsp/src/parsers/`:

```rust
// parsers/mylang.rs
use crate::parsers::Dependency;

pub fn parse(content: &str) -> Vec<Dependency> {
    // Parse the dependency file format
    // Return list of dependencies with name, version, and position
}
```

### 2. Create a Registry Client

Create a new file in `depsy-lsp/src/registries/`:

```rust
// registries/myregistry.rs
use crate::registries::{Registry, VersionInfo};
use async_trait::async_trait;

pub struct MyRegistry {
    client: reqwest::Client,
}

#[async_trait]
impl Registry for MyRegistry {
    async fn get_versions(&self, package: &str) -> anyhow::Result<VersionInfo> {
        // Query the registry API
        // Return version information
    }
}
```

### 3. Register the Language

Update `depsy-lsp/src/lib.rs` and `backend.rs` to:
- Add the new parser to the file type detection
- Register the registry client
- Map the ecosystem for vulnerability scanning

### 4. Add Tests

- Add unit tests in the parser file
- Add integration tests in `tests/integration_test.rs`

### 5. Update Documentation

- Add the language to the supported languages table in `README.md`
- Update `extension.toml` if new file patterns are needed

## Testing

### Running Tests

```bash
cd depsy-lsp

# Run all tests
cargo test

# Run specific test module
cargo test parsers::cargo
cargo test registries::npm

# Run integration tests
cargo test --test integration_test

# Run with output
cargo test -- --nocapture
```

### Fuzz Testing

We use [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) to find edge cases and potential crashes in parsers.

#### Prerequisites

```bash
# Install Rust nightly
rustup toolchain install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

#### Running Fuzz Tests

```bash
# Run all targets (30 seconds each)
./scripts/fuzz.sh

# Run specific target
./scripts/fuzz.sh cargo

# Run with custom duration (seconds)
./scripts/fuzz.sh npm 300

# List available targets
./scripts/fuzz.sh --list
```

Or manually with cargo-fuzz:

```bash
cd depsy-lsp/fuzz

# Build all fuzz targets
cargo +nightly fuzz build

# Run a specific target
cargo +nightly fuzz run fuzz_cargo -- -max_total_time=60
```

#### Available Fuzz Targets

| Target | Parser | File Format |
|--------|--------|-------------|
| `fuzz_cargo` | CargoParser | Cargo.toml |
| `fuzz_npm` | NpmParser | package.json |
| `fuzz_python` | PythonParser | requirements.txt, pyproject.toml |
| `fuzz_go` | GoParser | go.mod |
| `fuzz_ruby` | RubyParser | Gemfile |
| `fuzz_php` | PhpParser | composer.json |
| `fuzz_dart` | DartParser | pubspec.yaml |
| `fuzz_csharp` | CsharpParser | *.csproj, Directory.Build.props, Directory.Packages.props |

#### Analyzing Crashes

If fuzzing finds a crash, the input is saved to `fuzz/artifacts/`.

From the `depsy-lsp/fuzz` directory:

```bash
# View crash inputs
ls artifacts/fuzz_cargo/

# Reproduce a crash
cargo +nightly fuzz run fuzz_cargo artifacts/fuzz_cargo/crash-*
```

### Writing Tests

- Place unit tests in the same file as the code
- Use `#[cfg(test)]` module pattern
- Test edge cases and error conditions
- For registry tests, consider using mock HTTP responses

## Submitting Changes

### Pull Request Guidelines

1. **Title**: Use conventional commit format
   - `feat: add support for Ruby gems`
   - `fix: handle scoped npm packages`
   - `docs: improve installation instructions`

2. **Description**: Include
   - Summary of changes
   - Motivation/context
   - Testing done
   - Breaking changes (if any)

3. **Size**: Keep PRs focused and reasonably sized

4. **Tests**: Ensure all tests pass

5. **Documentation**: Update relevant docs

### Review Process

- PRs require review before merging
- Address review feedback promptly
- Keep discussions constructive

## Release Process (Maintainers)

This section documents the release workflow for maintainers.

### Versioning Strategy

We follow [Semantic Versioning](https://semver.org/) (SemVer):

| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `fix:` | Patch (0.0.x) | Bug fixes, minor corrections |
| `feat:` | Minor (0.x.0) | New features, non-breaking additions |
| `feat!:` or `BREAKING CHANGE:` | Major (x.0.0) | Breaking API changes |

### Changelog Maintenance

Maintain `CHANGELOG.md` with the following structure:

```markdown
# Changelog

## [Unreleased]
### Added
### Changed
### Fixed
### Removed

## [1.1.0] - 2025-01-08
### Added
- New feature X
### Fixed
- Bug Y
```

When preparing a release, move items from `[Unreleased]` to the new version section.

### Publishing Procedure

1. **Update version numbers**
   ```bash
   # Update depsy-lsp/Cargo.toml
   version = "X.Y.Z"

   # Update depsy-zed/extension.toml
   version = "X.Y.Z"
   ```

2. **Update CHANGELOG.md**
   - Move `[Unreleased]` items to new version section
   - Add release date

3. **Commit and tag**
   ```bash
   git add -A
   git commit -m "chore: release vX.Y.Z"
   git tag vX.Y.Z
   git push origin main --tags
   ```

4. **CI/CD takes over**
   - `.github/workflows/release.yml` triggers on `v*` tags
   - Builds binaries for Linux, macOS (Intel + ARM), Windows
   - Creates GitHub release with auto-generated notes
   - Uploads platform-specific archives

5. **Verify the release**
   - Check [GitHub Releases](https://github.com/mpiton/zed-depsy/releases)
   - Verify all platform binaries are attached
   - Test installation from release

### Build Commands Reference

```bash
# Build LSP (release)
cd depsy-lsp
cargo build --release

# Build extension (WASM)
cd depsy-zed
cargo build --release --target wasm32-wasip1

# Run full CI checks locally
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Developer Scripts

Helper scripts live at the repo root and in `scripts/`. All paths are relative to
the repository root.

| Script | Purpose |
|--------|---------|
| `./run-benchmarks.sh [FILTER]` | Run Criterion benchmarks. Flags: `--baseline` saves results as `main` baseline; `--compare` diffs the current run against it. Opens the HTML report when a browser opener is available. |
| `scripts/coverage.sh` | Generate test coverage with `cargo-tarpaulin` (HTML + JSON in `coverage/`). Honors `FAIL_UNDER=<pct>` to fail the run below a threshold. |
| `scripts/fuzz.sh [TARGET] [SECONDS]` | Run cargo-fuzz targets via the nightly toolchain. `--list` enumerates targets; default duration is 30s per target. See the Fuzz Testing section above. |
| `scripts/profile-parse.sh [FILE] [ITERATIONS]` | Flamegraph profile of the parser hot path. Requires `cargo install flamegraph`. |
| `scripts/profile-registry.sh [REGISTRY] [PACKAGES] [ITERATIONS]` | Flamegraph profile of registry client fetches. `REGISTRY` is a clap value (`crates`, `npm`, `pypi`, `go`, `packagist`, `pub-dev`, `nuget`, `rubygems`); `PACKAGES` is a comma-separated list (default: `lodash,express,react,axios,moment`). |
| `scripts/profile-full.sh [FILE] [ITERATIONS]` | Flamegraph profile of the full document-processing workflow (parse + registry + cache + vulnerabilities). |
| `scripts/check_mermaid_syntax.sh [DOC.md]` | Validate every fenced ````` ```mermaid ````` block in a markdown file using `@mermaid-js/mermaid-cli`. Defaults to `docs/architecture.md`. Used in CI to prevent broken diagrams. |

## Bug Reports

When reporting bugs, please include:

1. **Depsy version** (check Zed extensions panel)
2. **Zed version**
3. **Operating system** and version
4. **Steps to reproduce**
5. **Expected behavior**
6. **Actual behavior**
7. **Relevant logs** (run `zed --foreground` to see logs)

To report a bug, use the [GitHub issue templates](.github/ISSUE_TEMPLATE/) which will guide you through providing the required information.

## Feature Requests

For feature requests:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** - what problem does it solve?
3. **Propose a solution** if you have one in mind
4. **Consider scope** - start with MVP, expand later

We encourage discussion before implementing large features.

## Security Issues

**Do not report security vulnerabilities through public issues.**

Instead, please report security issues privately by emailing the maintainers or using GitHub's private vulnerability reporting feature.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Code of Conduct

- Be respectful and constructive
- Welcome newcomers
- Focus on the technical merits
- Assume good intentions

## License

By contributing to Depsy, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open a GitHub Issue for questions
- Check existing issues first
- Be specific and provide context

Thank you for contributing to Depsy!
