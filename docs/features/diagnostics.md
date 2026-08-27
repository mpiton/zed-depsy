---
title: Diagnostics
layout: default
parent: Features
nav_order: 2
description: "Warnings and hints for outdated or vulnerable dependencies"
---

# Diagnostics
{: .no_toc }

Editor diagnostics highlight issues with your dependencies.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Depsy integrates with Zed's diagnostic system to show warnings and hints directly in the editor. This helps you identify outdated or vulnerable dependencies without needing to manually check each one.

## Diagnostic Types

### Outdated Dependencies

Dependencies with available updates are marked with a hint-level diagnostic:

```text
tokio = "1.35.0"
~~~~~~~         HINT: Update available -> 1.36.0
```

The diagnostic appears as an underline with a message in the Problems panel.

### Vulnerability Diagnostics

Dependencies with known vulnerabilities are marked based on severity:

| Severity | Diagnostic Level | Indicator |
|----------|------------------|-----------|
| Critical | Error | `⚠ CRITICAL` |
| High | Error | `▲ HIGH` |
| Medium | Warning | `● MEDIUM` |
| Low | Hint | `○ LOW` |

Example:
```text
ring = "0.16.20"
~~~~            ERROR: 2 vulnerabilities (1 high, 1 medium)
```

## Configuration

### Enable/Disable Diagnostics

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "diagnostics": {
          "enabled": true
        }
      }
    }
  }
}
```

### Vulnerability Diagnostic Settings

Control vulnerability diagnostics separately:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "security": {
          "enabled": true,
          "show_diagnostics": true,
          "min_severity": "medium"
        }
      }
    }
  }
}
```

Setting `min_severity` to `"medium"` or `"high"` reduces noise from low-severity vulnerabilities.

## Viewing Diagnostics

### In the Editor

Diagnostics appear as underlines on the affected lines. The color indicates severity:

- **Red underline**: Error (critical/high vulnerabilities)
- **Yellow underline**: Warning (medium vulnerabilities)
- **Blue underline**: Hint (low vulnerabilities, outdated packages)

### Problems Panel

Open Zed's Problems panel (`Cmd+Shift+M` / `Ctrl+Shift+M`) to see all diagnostics in one place.

### Hover Details

Hover over a diagnostic to see:
- Vulnerability ID (CVE, GHSA, etc.)
- Severity level
- Description
- Affected version range
- Fixed version (if available)
- Link to advisory

## Workflow Integration

### Quick Fixes

Each diagnostic includes a quick fix code action:

1. Place cursor on the diagnostic
2. Press `Cmd+.` / `Ctrl+.` to open code actions
3. Select "Update to X.Y.Z" to fix

### Bulk Updates

Use the "Update all dependencies" code action to fix multiple issues at once.

## Diagnostic Filtering

### Ignore Specific Packages

Skip diagnostics for packages you want to manage manually:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "ignore": ["internal-*", "@company/*"]
      }
    }
  }
}
```

### Severity Threshold

Only show vulnerabilities above a certain severity:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "security": {
          "min_severity": "high"
        }
      }
    }
  }
}
```

## Best Practices

1. **Don't ignore security diagnostics** - Investigate all vulnerability warnings
2. **Review major updates carefully** - They may contain breaking changes
3. **Use ignore patterns sparingly** - Only for packages you actively manage
4. **Check the Problems panel regularly** - Catch issues early
