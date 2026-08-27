---
title: Features
layout: default
nav_order: 4
has_children: true
description: "Overview of Depsy features"
---

# Features
{: .no_toc }

Depsy provides a comprehensive set of features for managing dependencies in Zed Editor.
{: .fs-6 .fw-300 }

---

## Overview

| Feature | Description |
|---------|-------------|
| [Inlay Hints]({% link features/inlay-hints.md %}) | Version status displayed inline |
| [Diagnostics]({% link features/diagnostics.md %}) | Warnings for outdated dependencies |
| [Code Actions]({% link features/code-actions.md %}) | Quick fixes to update versions |
| [Security Scanning]({% link features/security.md %}) | Vulnerability detection via OSV.dev |
| Hover Info | Package descriptions, licenses, links |
| Autocompletion | Version suggestions when editing |
| Persistent Cache | SQLite cache for faster startup |

## Feature Highlights

### Real-time Version Information

When you open a dependency file, Depsy immediately fetches version information from the appropriate registry and displays it inline:

```
serde = "1.0.152"     ✓
tokio = "1.35.0"      -> 1.36.0
```

### Security First

All dependencies are checked against the [OSV.dev](https://osv.dev) vulnerability database. Known vulnerabilities are highlighted with severity indicators:

- `⚠ CRITICAL` - Immediate action required
- `▲ HIGH` - Action recommended
- `● MEDIUM` - Review when possible
- `○ LOW` - Informational

### Smart Updates

Code actions understand semver and help you make informed update decisions:

- `⚠ MAJOR` - Breaking changes (requires review)
- `+ minor` - New features (safe)
- `· patch` - Bug fixes (recommended)

### Performance

- **Memory cache** for fast access during sessions
- **SQLite cache** persists data across restarts
- **Background fetching** keeps UI responsive
- **Rate limiting** respects registry limits

## Configuration

All features can be enabled/disabled individually. See [Configuration]({% link configuration.md %}) for details.

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "inlay_hints": { "enabled": true },
        "diagnostics": { "enabled": true },
        "security": { "enabled": true }
      }
    }
  }
}
```
