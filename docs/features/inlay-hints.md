---
title: Inlay Hints
layout: default
parent: Features
nav_order: 1
description: "Version status displayed inline next to dependencies"
---

# Inlay Hints
{: .no_toc }

Real-time version information displayed inline next to your dependencies.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Inlay hints appear at the end of each dependency line, showing the current version status at a glance. No need to hover or click - you can see outdated dependencies immediately.

## Hint Types

### Up to Date

```text
serde = "1.0.210"     ✓
```

The `✓` symbol indicates your version matches the latest available version.

### Update Available

```text
tokio = "1.35.0"      -> 1.36.0
```

The `-> X.Y.Z` format shows the latest version available. Click the code action to update.

### Vulnerabilities Detected

```text
ring = "0.16.20"      ⚠ 2 vulns
```

The `⚠ N vulns` indicator shows the number of known vulnerabilities. Hover for details.

### Deprecated Package

```text
old-package = "1.0.0"  ⚠ Deprecated
```

The package maintainer has marked this package as deprecated. Consider finding an alternative.

### Yanked Version

```text
problematic = "0.5.0"  ⊘ Yanked
```

The specific version has been yanked/withdrawn from the registry. Update immediately.

### Local/Path Dependency

```text
my-lib = { path = "../my-lib" }  → Local
```

Local path dependencies don't have registry versions to check.

### Unknown Package

```text
typo-package = "1.0.0"  ? Unknown
```

The package couldn't be found on the registry. Check the package name for typos.

## Configuration

### Enable/Disable Hints

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "inlay_hints": {
          "enabled": true
        }
      }
    }
  }
}
```

### Hide Up-to-Date Hints

To reduce visual noise, hide hints for packages that are already current:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "inlay_hints": {
          "enabled": true,
          "show_up_to_date": false
        }
      }
    }
  }
}
```

With this setting, only packages needing attention are shown.

## Hover Information

Hovering over any dependency reveals detailed information:

- **Package description** from the registry
- **Homepage URL** if available
- **Repository URL** for source code
- **License** (SPDX identifier)
- **All available versions** for reference
- **Vulnerability details** if any exist

## Refresh Behavior

- Hints update automatically when you save the file
- Background refresh occurs based on cache TTL (default: 1 hour)
- Force refresh by clearing the cache and restarting Zed

## Troubleshooting

### Hints Not Appearing

1. Verify the extension is installed and enabled
2. Check that `inlay_hints.enabled` is `true`
3. Ensure the file type is supported
4. Check network connectivity to registries

### Stale Hints

1. Wait for cache TTL to expire (default: 1 hour)
2. Clear the cache manually:
   ```bash
   rm -rf ~/.cache/depsy/
   ```
3. Restart Zed

### "Unknown" for Valid Packages

1. Check package name spelling
2. Verify network access to the registry
3. Check if the registry is experiencing issues
4. For scoped npm packages, ensure format is correct (`@scope/name`)
