---
title: Installation
layout: default
nav_order: 2
description: "How to install Depsy for Zed Editor"
---

# Installation
{: .no_toc }

Get Depsy up and running in your Zed Editor.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## From Zed Extensions (Recommended)

The easiest way to install Depsy:

1. Open Zed editor
2. Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Linux/Windows)
3. Type "extensions" and select `zed: extensions`
4. Search for "Depsy"
5. Click **Install**

The extension automatically downloads and installs the language server for your platform.

The download happens once per extension version, from `https://github.com/mpiton/zed-depsy/releases`: the extension installs the language-server release that matches its own version. Later start-ups use the binary already on disk and make no network request.

## Offline / Air-Gapped Installation

When Zed cannot reach `github.com` (corporate proxy, air-gapped machine), two options:

- **Keep an earlier download.** If an earlier extension version already downloaded a language server, the extension starts that one and prints a line on stderr (`zed --foreground`) saying which. Nothing to configure.
- **Provide the binary yourself.** Download the archive for your platform from the [releases page](https://github.com/mpiton/zed-depsy/releases), or build it with `cargo build --release` in `depsy-lsp/`, copy the binary onto the machine and point Zed at it in `settings.json`:

  ```json
  {
    "lsp": {
      "depsy": {
        "binary": {
          "path": "/opt/depsy/depsy-lsp"
        }
      }
    }
  }
  ```

  Zed then starts that binary directly and never asks the extension to download anything. Keeping it in step with the extension version is up to you.

Downloaded binaries live in Zed's extension work directory: `~/.local/share/zed/extensions/work/depsy-lsp/` on Linux, `~/Library/Application Support/Zed/extensions/work/depsy-lsp/` on macOS, `%LOCALAPPDATA%\Zed\extensions\work\depsy-lsp\` on Windows.

## Manual Installation (Development)

For development or testing pre-release versions:

### Prerequisites

- **Rust 1.94+** (edition 2024)
- **wasm32-wasip1 target**: `rustup target add wasm32-wasip1`

### Build Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/mpiton/zed-depsy.git
   cd zed-depsy
   ```

2. Build the LSP:
   ```bash
   cd depsy-lsp
   cargo build --release
   ```

3. Build the extension:
   ```bash
   cd ../depsy-zed
   cargo build --release --target wasm32-wasip1
   ```

4. Install as dev extension in Zed:
   - Open Zed
   - Run command: `zed: install dev extension`
   - Select the `depsy-zed` directory

## Verify Installation

After installation, open any supported dependency file to verify Depsy is working:

1. Open a `Cargo.toml`, `package.json`, or other dependency file
2. You should see inlay hints next to your dependencies showing version status
3. Hover over a dependency to see package information

If you don't see hints:
- Check if the extension is enabled in Zed's extensions panel
- View Zed logs for errors: run `zed --foreground` from terminal
- See [Troubleshooting]({% link troubleshooting.md %}) for common issues

## System Requirements

### Supported Platforms

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64 | Supported |
| Linux | aarch64 | Supported |
| macOS | x86_64 (Intel) | Supported |
| macOS | aarch64 (Apple Silicon) | Supported |
| Windows | x86_64 | Supported |

### Network Requirements

Depsy needs network access to package registries and the vulnerability database:

| Service | URL | Purpose |
|---------|-----|---------|
| crates.io | `https://crates.io` | Rust packages (+ your alternative registry URLs) |
| npm | `https://registry.npmjs.org` | Node.js packages |
| PyPI | `https://pypi.org` | Python packages |
| Go Proxy | `https://proxy.golang.org` | Go modules |
| Packagist | `https://packagist.org` | PHP packages |
| pub.dev | `https://pub.dev` | Dart packages |
| NuGet | `https://api.nuget.org` | .NET packages |
| RubyGems | `https://rubygems.org` | Ruby gems |
| OSV.dev | `https://api.osv.dev` | Vulnerability data |
| GitHub | `https://github.com`, `https://release-assets.githubusercontent.com` | Language server download, once per extension version |

If you're behind a corporate firewall, ensure these URLs are allowed. If only `github.com` is blocked, see [Offline / Air-Gapped Installation](#offline--air-gapped-installation).

## What's Next?

- [Configure Depsy]({% link configuration.md %}) to customize behavior
- Learn about [Features]({% link features/index.md %}) available
- Set up [Private Registries]({% link registries/private.md %}) for enterprise packages
