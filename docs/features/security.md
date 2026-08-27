---
title: Security Scanning
layout: default
parent: Features
nav_order: 4
description: "Vulnerability detection via OSV.dev"
---

# Security Scanning
{: .no_toc }

Real-time vulnerability detection powered by OSV.dev.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Depsy automatically scans your dependencies against the [OSV.dev](https://osv.dev) vulnerability database. This is Google's Open Source Vulnerability database, aggregating data from multiple sources including:

- GitHub Security Advisories
- RustSec Advisory Database
- PyPI Advisory Database
- Go Vulnerability Database
- And many more

## How It Works

1. When you open a dependency file, Depsy parses all dependencies
2. Each dependency is checked against OSV.dev for known vulnerabilities
3. Results are displayed as inlay hints and diagnostics
4. Vulnerability data is cached for 6 hours

## Severity Levels

Vulnerabilities are categorized by severity:

| Level | Indicator | Diagnostic | Action |
|-------|-----------|------------|--------|
| Critical | `⚠ CRITICAL` | Error | Immediate action required |
| High | `▲ HIGH` | Error | Action recommended |
| Medium | `● MEDIUM` | Warning | Review when possible |
| Low | `○ LOW` | Hint | Informational |

## Viewing Vulnerabilities

### Inlay Hints

Vulnerable packages show the count in hints:

```text
ring = "0.16.20"      ⚠ 2 vulns
```

### Hover Details

Hover over a vulnerable dependency for full details:

- Vulnerability ID (CVE-2024-XXXXX, RUSTSEC-2024-XXXX, etc.)
- Severity score
- Description of the issue
- Affected version range
- Fixed version (if available)
- Link to full advisory

### Problems Panel

Open the Problems panel to see all vulnerabilities:
- `Cmd+Shift+M` (Mac)
- `Ctrl+Shift+M` (Linux/Windows)

## Configuration

### Enable/Disable Security Scanning

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "security": {
          "enabled": true
        }
      }
    }
  }
}
```

### Minimum Severity Threshold

Filter out low-severity vulnerabilities:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "security": {
          "min_severity": "medium"
        }
      }
    }
  }
}
```

Options: `"low"`, `"medium"`, `"high"`, `"critical"`

### Display Options

Control where vulnerabilities appear:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "security": {
          "show_in_hints": true,
          "show_diagnostics": true
        }
      }
    }
  }
}
```

## CLI Scanning

For CI/CD integration, use the CLI scan command:

```bash
depsy-lsp scan --file Cargo.toml --min-severity high
```

See [CLI Usage]({% link cli.md %}) for detailed CI/CD integration.

## Responding to Vulnerabilities

### Step 1: Assess Severity

- **Critical/High**: Prioritize immediate fix
- **Medium**: Schedule fix in current sprint
- **Low**: Add to backlog

### Step 2: Check if Fix Exists

Hover over the vulnerability to see if a fixed version is available.

### Step 3: Update the Dependency

Use code actions to update to the fixed version:

1. Place cursor on the dependency
2. Press `Cmd+.` / `Ctrl+.`
3. Select the update action

### Step 4: Verify the Fix

After updating:
1. Clear cache to refresh vulnerability data
2. Verify the vulnerability indicator is gone
3. Run your test suite

## False Positives

Sometimes a vulnerability doesn't affect your usage:

1. The vulnerable code path isn't used
2. Your usage pattern prevents exploitation
3. The vulnerability is in a development-only dependency

To suppress specific packages:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "ignore": ["package-with-false-positive"]
      }
    }
  }
}
```

{: .warning }
Use ignore patterns carefully. Document why a vulnerability is being ignored.

## Data Sources

OSV.dev aggregates vulnerabilities from:

| Source | Ecosystems |
|--------|------------|
| GitHub Security Advisories | All |
| RustSec | Rust |
| PyPA Advisory Database | Python |
| Go Vulnerability Database | Go |
| npm Advisories | Node.js |
| Packagist Advisories | PHP |
| RubyGems Advisories | Ruby |

## Privacy

Security scanning:
- Sends package name and version to api.osv.dev
- Does **not** send your code or file contents
- Results are cached locally
- No telemetry or tracking

## Troubleshooting

### Vulnerabilities Not Showing

1. Check `security.enabled` is `true`
2. Verify network access to api.osv.dev
3. Check `min_severity` setting isn't filtering all results

### Stale Vulnerability Data

Vulnerability cache has a 6-hour TTL. To force refresh:

```bash
rm -rf ~/.cache/depsy/
```

Then restart Zed.

### High False Positive Rate

Consider adjusting `min_severity`:

```json
{
  "security": {
    "min_severity": "medium"
  }
}
```

This filters out low-severity issues that are often informational.
