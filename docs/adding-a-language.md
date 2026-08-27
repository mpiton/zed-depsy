---
title: Adding a New Language
layout: default
nav_order: 10
description: "Step-by-step guide for adding support for a new package manager / ecosystem to Depsy"
---

# Adding a New Language
{: .no_toc }

Step-by-step guide to adding a new language/ecosystem to Depsy. Worked example: Swift Package Manager.
{: .fs-6 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## 1. Introduction

This guide walks you through adding support for a new language or package manager to Depsy. By the end, your fork will detect the manifest file, parse its dependencies, fetch versions from the upstream registry, surface vulnerabilities via OSV.dev, and offer the same inlay hints, diagnostics, and code actions every other supported ecosystem gets.

The worked example throughout is **Swift Package Manager** (`Package.swift`). At the time of writing, SwiftPM is not yet supported, which makes it a good candidate: you can follow the tutorial end-to-end and ship a real PR. If you target a different ecosystem, use the example as a template — the wire-up steps are identical.

### What you need before you start

- **Rust 1.94 or newer** (this repository is on edition 2024).
- **Git, Cargo, and the `wasm32-wasip1` target**: `rustup target add wasm32-wasip1`.
- **Familiarity with `async`/`await`**. Registry clients are async; parsers are synchronous.
- **A sample manifest from your target ecosystem** to drive your first test.
- **The OSV.dev ecosystem name**, if your registry is in OSV's coverage list. Look it up at <https://ossf.github.io/osv-schema/#defined-ecosystems> before starting Step 4. For SwiftPM the value the tutorial uses is `"SwiftURL"`; verify against the schema in case it has changed.

### What you'll touch

Five files (six if your ecosystem has lock files):

1. `depsy-lsp/src/file_types.rs` — file detection, ecosystem mapping, cache key.
2. `depsy-lsp/src/parsers/<your-lang>.rs` (new) plus `parsers/mod.rs` declaration.
3. `depsy-lsp/src/registries/<your-lang>.rs` (new) plus `registries/mod.rs` declaration.
4. `depsy-lsp/src/backend.rs` — `ProcessingContext` field, parser dispatch, registry dispatch.
5. `depsy-lsp/src/vulnerabilities/mod.rs` — `Ecosystem` variant + OSV string.
6. (Optional) `depsy-lsp/src/parsers/lockfile_resolver.rs` if your ecosystem has lock files.

The "Reference checklist" at the bottom of this page enumerates every individual edit so you can use it as a final review before opening your PR.

## 2. The big picture

When a user opens a manifest file, the LSP runs roughly this pipeline for every dependency:

```text
URI ──► file_types::FileType::detect ──► dispatch_parse ──► Vec<Dependency>
                                                              │
                                                              ▼
                                              registry.get_version_info ──► VersionInfo
                                                              │
                                                              ▼
                                                vulnerabilities::check ──► Vec<Vulnerability>
                                                              │
                                                              ▼
                                                  inlay hints / diagnostics / code actions
```

To plug a new ecosystem in, you teach each stage of that pipeline what to do with your file type. The five stages map to the five files listed in Section 1.

The two trait surfaces a contributor implements are:

```rust,ignore
// In depsy-lsp/src/parsers/mod.rs
pub trait Parser: Send + Sync {
    fn parse(&self, content: &str) -> Vec<Dependency>;
}

// In depsy-lsp/src/registries/mod.rs
#[allow(async_fn_in_trait)]
pub trait Registry: Send + Sync {
    async fn get_version_info(&self, package_name: &str)
        -> anyhow::Result<VersionInfo>;
    fn http_client(&self) -> std::sync::Arc<reqwest::Client>;
}
```

[`Parser`]: https://docs.rs/depsy-lsp/latest/depsy_lsp/parsers/trait.Parser.html
[`Registry`]: https://docs.rs/depsy-lsp/latest/depsy_lsp/registries/trait.Registry.html

[`Parser`] is synchronous. [`Registry`] is asynchronous and Send + Sync (so it can be wrapped in `Arc` and shared across the request pool). The trait uses native `async fn` rather than the `async-trait` crate; the `#[allow(async_fn_in_trait)]` attribute is needed because the trait is internal and the `Send + Sync` bound is already declared on the trait itself.

## 3. Step 1 — Define the file type

Open `depsy-lsp/src/file_types.rs`. You will make six edits.

### 3.1 Add the enum variant

Add `Swift` to the `FileType` enum. The real enum lists variants in declaration order (Cargo, Npm, Python, Go, Php, Dart, Csharp, Ruby, Maven) — append yours at the end to keep the diff small:

```rust,ignore
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    Cargo,
    Npm,
    Python,
    Go,
    Php,
    Dart,
    Csharp,
    Ruby,
    Maven,
    Swift,        // ← new
}
```

`FileType` derives only `PartialEq`, not `Eq` / `Hash`. If your work needs `FileType` as a `HashMap` key, add the extra derives in that PR explicitly rather than assuming they exist.

### 3.2 Add detection

`FileType::detect` is an `if`/`else if` chain over `path.ends_with(...)`, not a `match` on the filename. Add your branch alongside the existing ones:

```rust,ignore
impl FileType {
    pub fn detect(uri: &Url) -> Option<Self> {
        let path = uri.path();
        let filename = path.rsplit('/').next().unwrap_or(path);
        if path.ends_with("Cargo.toml") {
            Some(FileType::Cargo)
        // ... existing arms ...
        } else if path.ends_with("Package.swift") {              // ← new
            Some(FileType::Swift)
        } else {
            None
        }
    }
}
```

### 3.3 Add ecosystem mapping

Map the variant to its OSV ecosystem in `to_ecosystem`. The existing arms use the full `FileType::` / `Ecosystem::` paths (not `Self::`). Existing variant names: `CratesIo`, `Npm`, `PyPI`, `Go`, `Packagist`, `Pub`, `NuGet`, `RubyGems`, `Maven`. Add your new pair the same way:

```rust,ignore
impl FileType {
    pub fn to_ecosystem(self) -> Ecosystem {
        match self {
            FileType::Cargo => Ecosystem::CratesIo,
            // ... existing arms ...
            FileType::Swift => Ecosystem::SwiftPM,             // ← new (add to Ecosystem too)
        }
    }
}
```

You'll need to add `SwiftPM` to the `Ecosystem` enum in `depsy-lsp/src/vulnerabilities/mod.rs` — Step 4 covers that edit.

### 3.4 Add the registry URL formatter, registry name, and cache key

`fmt_registry_package_url` and `fmt_cache_key` both return `impl fmt::Display + fmt::Debug` via the `fmt::from_fn` helper, so each new arm is a `write!(f, ...)` call rather than a `format!(...)` expression. `registry_name` returns `&'static str`. Three additions:

```rust,ignore
impl FileType {
    pub fn fmt_registry_package_url(self, name: &str) -> impl fmt::Display + fmt::Debug {
        fmt::from_fn(move |f| match self {
            FileType::Cargo => write!(f, "https://crates.io/crates/{name}"),
            // ... existing arms ...
            FileType::Swift => write!(f, "https://swiftpackageindex.com/{name}"),
        })
    }

    pub fn registry_name(self) -> &'static str {
        match self {
            FileType::Cargo => "crates.io",
            // ... existing arms ...
            FileType::Swift => "Swift Package Index",
        }
    }

    pub fn fmt_cache_key(self, package_name: &str) -> impl fmt::Display + fmt::Debug {
        fmt::from_fn(move |f| match self {
            FileType::Cargo => write!(f, "crates:{package_name}"),
            // ... existing arms ...
            FileType::Swift => write!(f, "swift:{package_name}"),
        })
    }
}
```

### 3.5 Verify

Add a unit test in `file_types.rs` (under the existing `#[cfg(test)] mod tests`). Note that `fmt_cache_key` returns an `impl Display`, so call `.to_string()` on it (or use the `cache_key` convenience wrapper):

```rust,ignore
#[test]
fn detects_package_swift() {
    let uri = Url::parse("file:///proj/Package.swift").unwrap();
    assert_eq!(FileType::detect(&uri), Some(FileType::Swift));
    assert_eq!(FileType::Swift.registry_name(), "Swift Package Index");
    assert_eq!(
        FileType::Swift.cache_key("swift-argument-parser"),
        "swift:swift-argument-parser"
    );
}
```

Run it:

```bash
cd depsy-lsp
cargo test file_types::tests::detects_package_swift
```

Expected: `1 passed`. If the test does not yet pass, your variant or match arm is missing.

## 4. Step 2 — Write the parser

Create `depsy-lsp/src/parsers/swift.rs` and declare it in `parsers/mod.rs` with `pub mod swift;`.

### 4.1 Span semantics — read this first

`Span` covers the **inner bytes of a token**, measured from the start of the line, end-exclusive:

```text
    .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
                  ^                                              ^         ^     ^
                  inner start                                inner end  v.start v.end

name_span    = Span { line: 4, line_start: 18, line_end: 71 }
version_span = Span { line: 4, line_start: 80, line_end: 85 }
```

If you accidentally include the surrounding quotes, LSP quick-fix code actions will replace `"1.3.0"` with `"1.4.0""` — broken. The first thing your tests should assert is that spans don't include the quotes.

### 4.2 Test first (TDD)

Add the failing test before any implementation. In `depsy-lsp/src/parsers/swift.rs`:

```rust,ignore
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;

    const SAMPLE: &str = r#"
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-log", exact: "1.5.3"),
    ]
)
"#;

    #[test]
    fn parses_two_dependencies() {
        let parser = SwiftParser::new();
        let deps = parser.parse(SAMPLE);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "swift-argument-parser");
        assert_eq!(deps[0].version, "1.3.0");
        assert_eq!(deps[1].name, "swift-log");
        assert_eq!(deps[1].version, "1.5.3");
    }

    #[test]
    fn version_span_excludes_quotes() {
        let parser = SwiftParser::new();
        let deps = parser.parse(SAMPLE);
        let line_5 = SAMPLE.lines().nth(4).unwrap();
        let inner = &line_5[deps[0].version_span.line_start as usize
            ..deps[0].version_span.line_end as usize];
        assert_eq!(inner, "1.3.0");
        assert!(!inner.starts_with('"') && !inner.ends_with('"'));
    }
}
```

Run it — it should fail to compile (`SwiftParser` doesn't exist):

```bash
cd depsy-lsp
cargo test parsers::swift
```

Expected: compilation error mentioning `cannot find type SwiftParser`.

### 4.3 Implement

Add this minimal implementation above the existing `#[cfg(test)] mod tests` from Section 4.2. Keep that test module unchanged so the file defines it exactly once:

```rust,ignore
//! `Package.swift` parser for Swift Package Manager.

use crate::parsers::{Dependency, Parser, Span};

#[derive(Debug, Default)]
pub struct SwiftParser;

impl SwiftParser {
    pub fn new() -> Self {
        Self
    }
}

impl Parser for SwiftParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with(".package(url:") {
                continue;
            }
            let url_start = match line.find('"') {
                Some(idx) => idx + 1,
                None => continue,
            };
            let url_end = match line[url_start..].find('"') {
                Some(idx) => url_start + idx,
                None => continue,
            };
            let url = &line[url_start..url_end];
            let name = url.rsplit('/').next().unwrap_or(url).to_string();
            let version_marker = match line
                .rfind('"')
                .and_then(|end| line[..end].rfind('"').map(|start| (start + 1, end)))
            {
                Some(pair) if pair.0 > url_end => pair,
                _ => continue,
            };
            let version = line[version_marker.0..version_marker.1].to_string();
            deps.push(Dependency {
                name,
                version,
                name_span: Span {
                    line: line_idx as u32,
                    line_start: url_start as u32,
                    line_end: url_end as u32,
                },
                version_span: Span {
                    line: line_idx as u32,
                    line_start: version_marker.0 as u32,
                    line_end: version_marker.1 as u32,
                },
                dev: false,
                optional: false,
                registry: None,
                resolved_version: None,
            });
        }
        deps
    }
}
```

> **In a real PR**, cover escaping, comments, alternate requirement forms, malformed input, and checked LSP position conversions before shipping this illustrative parser.

### 4.4 Run the tests

```bash
cd depsy-lsp
cargo test parsers::swift
```

Expected: `2 passed`.

### 4.5 If your manifest format is more complex

Some ecosystems use full programming languages as manifests (Swift DSL, Gradle Kotlin DSL). Naïve substring parsing covers ~95% of real-world manifests but breaks on, for example:

- Multi-line `.package(...)` calls.
- `.package(name: "X", url: "Y", ...)` with the `name:` argument.
- Dependencies inside `#if swift(>=5.5)` conditional blocks.

For those cases, study the existing `depsy-lsp/src/parsers/maven.rs` (which uses `quick-xml`) or `depsy-lsp/src/parsers/python.rs` (which uses `taplo`) for richer parsing patterns. Adding a real Swift tokenizer is out of scope for the v1 tutorial.

## 5. Step 3 — Write the registry client

Create `depsy-lsp/src/registries/swift_package_index.rs` and declare it in `registries/mod.rs` with `pub mod swift_package_index;`.

### 5.1 Construct from the shared HTTP client

Every registry takes an `Arc<reqwest::Client>` so connection pooling is shared across the LSP. Use `registries::http_client::create_shared_client()` for the default.

```rust,ignore
use std::sync::Arc;

use reqwest::Client;

use crate::registries::{Registry, VersionInfo, http_client::create_shared_client};

pub struct SwiftPackageIndexRegistry {
    client: Arc<Client>,
    base_url: String,
}

impl SwiftPackageIndexRegistry {
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            base_url: "https://swiftpackageindex.com/api/packages".to_string(),
        }
    }
}

impl Default for SwiftPackageIndexRegistry {
    fn default() -> Self {
        Self::with_client(
            create_shared_client().expect("failed to create HTTP client"),
        )
    }
}
```

### 5.2 Implement the trait

The `Registry` trait uses native `async fn` (`#[allow(async_fn_in_trait)]` on the trait declaration) rather than the `async-trait` crate, so the `impl` block does **not** carry an `#[async_trait]` attribute.

```rust,ignore
impl Registry for SwiftPackageIndexRegistry {
    async fn get_version_info(
        &self,
        package_name: &str,
    ) -> anyhow::Result<VersionInfo> {
        let url = format!("{}/{}", self.base_url, package_name);
        let response = self.client.get(&url).send().await?;
        anyhow::ensure!(
            response.status().is_success(),
            "Swift Package Index returned {}",
            response.status()
        );
        let payload: SpiPackage = response.json().await?;
        Ok(VersionInfo {
            latest: payload.latest_version.clone(),
            versions: payload.versions.clone(),
            description: payload.summary,
            homepage: payload.url,
            repository: payload.url_alt,
            license: payload.license,
            ..Default::default()
        })
    }

    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }
}

#[derive(serde::Deserialize)]
struct SpiPackage {
    latest_version: Option<String>,
    versions: Vec<String>,
    summary: Option<String>,
    url: Option<String>,
    url_alt: Option<String>,
    license: Option<String>,
}
```

The `..Default::default()` spread fills the remaining `VersionInfo` fields (`yanked`, `deprecated`, `release_dates`, `vulnerabilities`, `transitive_vulnerabilities`, `latest_prerelease`, `yanked_versions`) with their defaults.

### 5.3 Test

Use `wiremock` (already in `[dev-dependencies]`) to stub the API:

```rust,ignore
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn fetches_latest_version() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/packages/apple/swift-argument-parser"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "latest_version": "1.3.0",
                "versions": ["1.0.0", "1.3.0"],
                "summary": "Argument parser",
                "url": "https://github.com/apple/swift-argument-parser",
                "url_alt": null,
                "license": "Apache-2.0"
            })))
            .mount(&server)
            .await;

        let registry = SwiftPackageIndexRegistry {
            client: std::sync::Arc::new(reqwest::Client::new()),
            base_url: format!("{}/api/packages", server.uri()),
        };
        let info = registry
            .get_version_info("apple/swift-argument-parser")
            .await
            .unwrap();
        assert_eq!(info.latest.as_deref(), Some("1.3.0"));
        assert_eq!(info.versions.len(), 2);
    }
}
```

Run it:

```bash
cd depsy-lsp
cargo test registries::swift_package_index
```

Expected: `1 passed`.

### 5.4 Pay attention to rate limits

Most registries publish a fair-use limit. Swift Package Index's API is CDN-cached and has no documented hard limit, so no client-side throttling is needed. If your target registry is strict (crates.io, for example, enforces 1 request/second), adopt the pattern in `depsy-lsp/src/registries/crates_io.rs` (look for the `RateLimiter` struct) — never burst-fire a registry.

## 6. Step 4 — Wire into the backend

Open `depsy-lsp/src/backend.rs`. The wiring is mechanical but easy to forget partial steps. Each sub-step ends with a `cargo check` to confirm the next step is set up correctly.

### 6.1 Import

At the top of `backend.rs`, add:

```rust,ignore
use crate::parsers::swift::SwiftParser;
use crate::registries::swift_package_index::SwiftPackageIndexRegistry;
```

```bash
cd depsy-lsp
cargo check
```
Expected: a warning about unused imports (you'll fix it in 6.2). No errors.

### 6.2 Add fields to `DepsyBackend` and `ProcessingContext`

`ProcessingContext` is a private struct with bare (module-visible) fields. Add the two new ones at the bottom of the field list, matching the existing style:

```rust,ignore
struct ProcessingContext {
    // ... existing fields ...
    swift_parser: Arc<SwiftParser>,
    swift_registry: Arc<SwiftPackageIndexRegistry>,
}
```

The `DepsyBackend` struct (also in `backend.rs`) holds the same `Arc<...>` parser/registry fields. Add identically named fields there too — `ProcessingContext` is a per-request snapshot of `DepsyBackend`'s state.

### 6.3 Initialize them in `with_http_client` and `create_processing_context`

`ProcessingContext` is **not** built in `DepsyBackend::new` — it is assembled in the private `async fn create_processing_context(&self) -> ProcessingContext` (around `backend.rs:737`) by `Arc::clone`-ing each of `DepsyBackend`'s parser/registry fields. Two edits:

1. In `DepsyBackend::with_http_client` (the constructor that accepts a custom HTTP client), initialize the new fields:

   ```rust,ignore
   swift_parser: Arc::new(SwiftParser::new()),
   swift_registry: Arc::new(
       SwiftPackageIndexRegistry::with_client(Arc::clone(&http_client))
   ),
   ```

2. In `create_processing_context`, propagate them into the snapshot:

   ```rust,ignore
   swift_parser: Arc::clone(&self.swift_parser),
   swift_registry: Arc::clone(&self.swift_registry),
   ```

```bash
cd depsy-lsp
cargo check
```
Expected: zero errors.

### 6.4 Dispatch in `parse_document`

`ProcessingContext::parse_document` is an exhaustive `match` over `FileType` (no wildcard arm). Add:

```rust,ignore
Some(FileType::Swift) => self.swift_parser.parse(content),
```

### 6.5 Dispatch in the registry-fetch loop

There are two registry dispatch sites and you must edit both:

1. `ProcessingContext::get_version_info` (called for cache-aware single-package lookups). Add an arm to the inner `match file_type`:

   ```rust,ignore
   FileType::Swift => self.swift_registry.get_version_info(package_name).await,
   ```

2. The async-task loop that fetches versions for every dependency in parallel. Inside that block (around `backend.rs:210-285`), the registry `Arc<...>` values are pre-cloned outside the `.map()` closure and re-cloned into each iteration. Two edits:

   - Just below the existing `let crates_io = Arc::clone(&self.crates_io);` block, add `let swift_registry = Arc::clone(&self.swift_registry);`.
   - Inside the `.map(|dep| { ... })` body, before `async move`, add `let swift_registry = Arc::clone(&swift_registry);`. Then add the match arm in the `async move { let result = match file_type { ... } }`:

     ```rust,ignore
     FileType::Swift => swift_registry.get_version_info(&name).await,
     ```

Both arms reference the captured `Arc`, never `self`, because the closure runs after `self` is borrowed.

### 6.6 Add the `Ecosystem` variant

In `depsy-lsp/src/vulnerabilities/mod.rs`:

```rust,ignore
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    CratesIo,
    // ... existing variants ...
    SwiftPM,
}

impl Ecosystem {
    pub fn as_osv_str(&self) -> &'static str {
        match self {
            // ... existing arms ...
            Ecosystem::SwiftPM => "SwiftURL",  // verify against the OSV schema
        }
    }
}
```

### 6.7 Verify the whole pipeline compiles

```bash
cd depsy-lsp
cargo check
cargo test
```

Expected: zero errors. Test count increases by 3 (the two parser tests and the one registry test you wrote in Steps 2 and 3).

## 7. Step 5 — (Optional) Lockfile resolver

If your ecosystem has a lockfile (`Package.resolved` for SwiftPM, `pnpm-lock.yaml` for pnpm, etc.), Depsy can pin diagnostics to the lock-resolved version instead of the manifest range. Skip this section for the SwiftPM v1 walkthrough — it's a good follow-up issue.

### 7.1 Implement the trait

`LockfileResolver` is the only async trait in this codebase that uses the `async-trait` crate macro (`#[async_trait]`). The reason: the LSP backend stores resolvers behind `Box<dyn LockfileResolver>` so it can dispatch dynamically per file type, and `dyn` traits with `async fn` require the boxed-future shape that `async-trait` produces. The `Registry` trait is *not* used through `dyn` anywhere, so it can use native `async fn` with `#[allow(async_fn_in_trait)]`.

The trait already provides defaults for `normalize_name` (identity) and `resolve_version` (lookup with both sides normalized). Override `normalize_name` if your ecosystem's package names are case- or separator-insensitive (Python PEP 503, NuGet, Composer, RubyGems do this); leave the default `resolve_version` alone unless you need genuinely custom matching.

In a new `depsy-lsp/src/parsers/swift_resolved.rs`:

```rust,ignore
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::parsers::{lockfile_graph::LockfileGraph,
                     lockfile_resolver::LockfileResolver};

pub struct SwiftLockfileResolver;

#[async_trait]
impl LockfileResolver for SwiftLockfileResolver {
    async fn find_lockfile(&self, manifest_path: &Path) -> Option<PathBuf> {
        let lockfile = manifest_path.parent()?.join("Package.resolved");
        if tokio::fs::try_exists(&lockfile).await.unwrap_or(false) {
            Some(lockfile)
        } else {
            None
        }
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        // Parse Package.resolved (JSON v2 format) and return a graph.
        // See depsy-lsp/src/parsers/cargo_lock.rs for a complete example.
        let _ = lock_content;
        LockfileGraph::default()
    }

    // Default `resolve_version` already calls `self.normalize_name` on both
    // sides — no override needed for SwiftPM, which uses canonical
    // `owner/repo` identifiers. If your ecosystem requires case-insensitive
    // matching, override `normalize_name` instead:
    //
    //     fn normalize_name(&self, name: &str) -> String {
    //         name.to_lowercase()
    //     }
}
```

### 7.2 Register the resolver

In `depsy-lsp/src/parsers/lockfile_resolver.rs`, extend `select_resolver` (it is an exhaustive `async fn` taking the manifest path and content alongside the file type):

```rust,ignore
pub async fn select_resolver(
    file_type: FileType,
    manifest_path: &Path,
    manifest_content: &str,
) -> Option<Box<dyn LockfileResolver>> {
    match file_type {
        FileType::Cargo => {
            let root_package =
                crate::parsers::cargo::cargo_root_package_name(manifest_content);
            Some(Box::new(crate::parsers::cargo_lock::CargoResolver {
                root_package,
            }))
        }
        // ... existing arms for Npm, Python, Go, Php, Dart, Csharp, Ruby ...
        FileType::Swift => {
            let _ = (manifest_path, manifest_content);
            Some(Box::new(crate::parsers::swift_resolved::SwiftLockfileResolver))
        }
        FileType::Maven => None, // Maven has no lockfile support today
    }
}
```

The match must remain exhaustive (no `_ =>` arm); add explicit `None` for any future `FileType` whose ecosystem genuinely lacks a lockfile.

### 7.3 Verify

```bash
cd depsy-lsp
cargo test parsers::swift_resolved
```

Expected: `1 passed` (assuming you wrote a test). Without this resolver, vulnerability scanning still works on the declared range, but transitive vulnerabilities won't be detected.

## 8. Step 6 — Update docs and CHANGELOG

### 8.1 Add `docs/languages/swift.md`

Take any existing language doc as a template (`docs/languages/rust.md` is the most complete). The minimum sections:

- **Front-matter** with `parent: Languages`, `nav_order: <next free>`.
- **Manifest format** — `Package.swift` syntax, where ecosystem version operators come from.
- **Registry quirks** — Swift Package Index API, OSV ecosystem name, rate limits.
- **Known limitations** — naïve parser doesn't handle multi-line declarations.

### 8.2 Update `docs/registries/index.md`

Add a new row to the registry table covering the Swift Package Index endpoint, license, rate limit, and OSV ecosystem string.

### 8.3 Append to `CHANGELOG.md`

Open `CHANGELOG.md` at the project root. Under `## [Unreleased]` → `### Added`, prepend (newest entries first) a bullet describing your work:

```markdown
- Support for Swift / Swift Package Manager (`Package.swift`):
  - Parse direct dependencies declared via `.package(url:..., from/exact:...)`.
  - Fetch versions from Swift Package Index API.
  - Vulnerability scanning via OSV.dev (`SwiftURL` ecosystem).
  ([#XXX](https://github.com/mpiton/zed-depsy/issues/XXX))
```

Replace `XXX` with the issue number you're closing. Follow the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format already used by neighbours in the file.

## 9. Verifying your work

Before opening a PR, every check below must pass locally. CI runs the same set on every PR (`.github/workflows/ci.yml`), so a green local run is your fastest feedback loop.

```bash
# 1. Formatting (no diff allowed)
cd depsy-lsp
cargo fmt --all -- --check

# 2. Lints (warnings are errors)
cargo clippy -- -D warnings
cargo clippy --all-targets -- -D warnings

# 3. Unit + integration + doctests in one pass
cargo test

# 4. Rustdoc must be clean (broken intra-doc links are deny-level)
cargo doc --no-deps
cd ..

# 5. Extension still builds for WASM
cd depsy-zed
cargo build --release --target wasm32-wasip1
cd ..
```

If you'd like to manually confirm the new ecosystem in Zed:

```bash
./build-and-deploy.sh
```

Then in Zed: **Extensions → Install Dev Extension → select `depsy-zed`**, open a `Package.swift` from any open-source Swift project, and verify inlay hints appear next to each `.package(url:...)` declaration.

## 10. Reference checklist

Use this list as a final review before opening your PR. Every item must be done (or explicitly N/A for your ecosystem).

### Code

- [ ] `depsy-lsp/src/file_types.rs`
  - [ ] Added `FileType::<YourLang>` variant.
  - [ ] Added arm in `detect()`.
  - [ ] Added arm in `to_ecosystem()`.
  - [ ] Added arm in `registry_name()`.
  - [ ] Added arm in `fmt_cache_key()`.
  - [ ] Added arm in `fmt_registry_package_url()`.
  - [ ] Added unit test in `#[cfg(test)] mod tests` covering the new file pattern.
- [ ] `depsy-lsp/src/parsers/<your_lang>.rs`
  - [ ] New file containing struct + `impl Parser`.
  - [ ] `pub mod <your_lang>;` declaration in `parsers/mod.rs`.
  - [ ] Inline `#[cfg(test)] mod tests` with at least one realistic manifest fixture.
- [ ] `depsy-lsp/src/registries/<your_lang>.rs`
  - [ ] New file containing struct + `impl Registry`.
  - [ ] `pub mod <your_lang>;` declaration in `registries/mod.rs`.
  - [ ] `wiremock` test stubbing the upstream API.
- [ ] `depsy-lsp/src/backend.rs`
  - [ ] Imports for the new parser and registry types.
  - [ ] `Arc<>` fields on `ProcessingContext`.
  - [ ] Initialization in `DepsyBackend::new` / `with_http_client`.
  - [ ] Match arm in `parse_document`.
  - [ ] Match arm in the registry-fetch loop.
- [ ] `depsy-lsp/src/vulnerabilities/mod.rs`
  - [ ] Added `Ecosystem::<YourEcosystem>` variant.
  - [ ] Added arm in `as_osv_str()` returning the OSV ecosystem string.
- [ ] (Optional) `depsy-lsp/src/parsers/<your_lang>_resolved.rs` plus dispatch in `lockfile_resolver::select_resolver`.

### Tests

- [ ] `cd depsy-lsp && cargo test` is green.
- [ ] `cd depsy-lsp && cargo test --doc` is green.
- [ ] `cd depsy-lsp && cargo doc --no-deps` is green.

### Docs

- [ ] `docs/languages/<your_lang>.md` (new).
- [ ] Row in `docs/registries/index.md`.
- [ ] `[Unreleased] / Added` entry in `CHANGELOG.md` referencing your issue/PR.

### CI

- [ ] PR opens without `clippy` warnings.
- [ ] All workflow jobs in `.github/workflows/ci.yml` are green.

## 11. Common pitfalls

A short tour of the mistakes most likely to bite a first-time contributor.

### 11.1 Spans include surrounding quotes

`Span::line_start..line_end` must cover the **inner** text. A span that points at `"1.3.0"` (with quotes) makes LSP quick-fixes produce `""1.3.0""` (broken). Always assert in your tests that `&line[span.line_start..span.line_end]` does not start or end with `"`.

### 11.2 Spans are byte offsets, not characters

LSP positions are UTF-16 character offsets. `Span` stores byte offsets within the line. ASCII manifests map 1:1, but non-ASCII content (e.g. a UTF-8 BOM, accented identifier names) does not. If your ecosystem allows non-ASCII names, you must transcode at the LSP boundary — see `depsy-lsp/src/providers/diagnostics.rs` for the pattern.

### 11.3 Blocking I/O inside async fns

The project rule (`CLAUDE.md`): **`tokio::fs`, never `std::fs`**, and never `unwrap()`/`expect()` outside of tests. A blocking `std::fs::read_to_string` call inside `Registry::get_version_info` will stall the runtime under load.

### 11.4 Forgetting the OSV ecosystem string

If `Ecosystem::as_osv_str` returns the wrong value, vulnerabilities silently never surface. Verify by issuing a known-CVE lookup against OSV.dev, e.g.:

```bash
curl -s -X POST 'https://api.osv.dev/v1/query' \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"<known-vulnerable-package>","ecosystem":"<your-osv-string>"}}' \
  | head -50
```

The response must contain at least one `vulns[]` entry. If it's empty, double-check the ecosystem string against <https://ossf.github.io/osv-schema/#defined-ecosystems>.

### 11.5 Forgetting an exhaustive match arm

Rust's exhaustive `match` is your friend. The `parse_document` switch in `backend.rs` lists all `FileType` variants explicitly. After adding `FileType::Swift`, the compiler will tell you exactly which match expressions still need an arm — fix every error before moving on. If you suppress this with `_ => {}`, you'll silently ship a half-integrated ecosystem.

### 11.6 Rate-limiting your way to a ban

Aggressive registry clients get IP-blocked. crates.io enforces 1 req/s strictly; npm tolerates ~1 req/s before blocking; PyPI is CDN-cached but still asks for politeness. If your registry has a documented limit, copy the `RateLimiter` pattern from `depsy-lsp/src/registries/crates_io.rs` rather than burst-firing requests in tests.
