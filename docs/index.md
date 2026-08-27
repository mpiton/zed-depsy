---
title: Home
layout: home
nav_order: 1
description: "Depsy is a dependency management extension for Zed Editor with real-time version checking, vulnerability scanning, and code actions."
permalink: /
---

# Depsy for Zed
{: .fs-9 }

Dependency management extension for the [Zed](https://zed.dev) editor with real-time version checking, vulnerability scanning, and intelligent code actions.
{: .fs-6 .fw-300 }

[Get Started]({% link installation.md %}){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/mpiton/zed-depsy){: .btn .fs-5 .mb-4 .mb-md-0 }

---

![Demo](assets/demo.gif)

## Features

Depsy provides comprehensive dependency management directly in your editor:

- **Inlay Hints** - See latest versions inline next to your dependencies
  - `✓` Version is up to date
  - `-> X.Y.Z` Update available
  - `⚠ N vulns` Vulnerabilities detected
  - `⚠ Deprecated` Package is deprecated
  - `⊘ Yanked` Version has been yanked
  - `→ Local` Local/path dependency
  - `? Unknown` Could not fetch version info

- **Vulnerability Scanning** - Real-time security scanning via [OSV.dev](https://osv.dev)
  - CVE details in hover tooltips
  - Severity indicators: `⚠ CRITICAL`, `▲ HIGH`, `● MEDIUM`, `○ LOW`
  - Generate JSON/Markdown vulnerability reports

- **Code Actions** - Quick fixes to update dependencies with semver-aware labels
  - `⚠ MAJOR` Breaking changes
  - `+ minor` New features
  - `· patch` Bug fixes

- **Hover Info** - Package descriptions, licenses, and links

- **Autocompletion** - Version suggestions when editing dependencies

- **Persistent Cache** - SQLite cache for faster startup across sessions

## Supported Ecosystems

| Language | File | Registry |
|----------|------|----------|
| [Rust]({% link languages/rust.md %}) | `Cargo.toml` | crates.io |
| [JavaScript/TypeScript]({% link languages/nodejs.md %}) | `package.json` | npm |
| [Python]({% link languages/python.md %}) | `requirements.txt`, `constraints.txt`, `pyproject.toml` | PyPI |
| [Go]({% link languages/go.md %}) | `go.mod` | proxy.golang.org |
| [PHP]({% link languages/php.md %}) | `composer.json` | Packagist |
| [Dart/Flutter]({% link languages/dart.md %}) | `pubspec.yaml` | pub.dev |
| [C#/.NET]({% link languages/dotnet.md %}) | `*.csproj`, `Directory.Build.props`, `Directory.Packages.props` | NuGet |
| [Ruby]({% link languages/ruby.md %}) | `Gemfile` | RubyGems.org |

## Quick Start

### 1. Install the Extension

In Zed Editor:
1. Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Linux/Windows)
2. Type "extensions" and select `zed: extensions`
3. Search for "Depsy"
4. Click Install

The extension automatically downloads and installs the language server.

### 2. Open a Dependency File

Open any supported dependency file (`Cargo.toml`, `package.json`, etc.) and Depsy will automatically activate.

### 3. See Version Hints

Version hints appear inline showing the latest version and update status. Hover over any dependency for detailed package information.

---

## What's Next?

<div class="d-flex flex-justify-between">
<div>

### Getting Started
- [Installation Guide]({% link installation.md %})
- [Configuration Reference]({% link configuration.md %})

</div>
<div>

### Learn More
- [Features Overview]({% link features/index.md %})
- [CLI Usage]({% link cli.md %})

</div>
</div>
