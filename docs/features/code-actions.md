---
title: Code Actions
layout: default
parent: Features
nav_order: 3
description: "Quick fixes to update dependency versions"
---

# Code Actions
{: .no_toc }

Quick fixes to update dependencies with semver-aware labels.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Code actions provide one-click updates for your dependencies. They understand semantic versioning and label updates so you can make informed decisions.

## Using Code Actions

### Trigger Code Actions

1. Place your cursor on a dependency line
2. Press `Cmd+.` (Mac) or `Ctrl+.` (Linux/Windows)
3. Select an update action from the menu

Alternatively, click the lightbulb icon that appears in the gutter.

### Available Actions

When an update is available, you'll see options like:

- `Update tokio to 1.36.0 (· patch)`
- `Update serde to 2.0.0 (⚠ MAJOR)`

## Semver Labels

Code actions include semver labels to help you understand the impact:

| Label | Meaning | Safety |
|-------|---------|--------|
| `⚠ MAJOR` | Breaking changes | Review changelog before updating |
| `+ minor` | New features, backwards compatible | Generally safe |
| `· patch` | Bug fixes only | Recommended |
| `* prerelease` | Experimental version | Use with caution |

### Major Updates

```
Update dependency to 2.0.0 (⚠ MAJOR)
```

Major updates may include breaking API changes. Always:
1. Read the changelog
2. Check migration guides
3. Test thoroughly after updating

### Minor Updates

```
Update dependency to 1.5.0 (+ minor)
```

Minor updates add features without breaking existing code. Generally safe to apply.

### Patch Updates

```
Update dependency to 1.4.3 (· patch)
```

Patch updates contain only bug fixes. These are the safest updates.

### Prerelease Updates

```
Update dependency to 2.0.0-beta.1 (* prerelease)
```

Prerelease versions are for testing new features. Not recommended for production.

## Bulk Updates

### Update All Dependencies

When multiple dependencies have updates available, a bulk action appears:

```
Update all dependencies (5 packages)
```

This updates all packages to their latest versions in one action.

{: .warning }
Bulk updates apply all changes at once. Review the changes carefully, especially for major version updates.

## Smart Defaults

Depsy prioritizes updates intelligently:

1. **Patch updates** are shown first (safest)
2. **Minor updates** are offered next
3. **Major updates** require explicit selection

This encourages safer update practices while still making major updates accessible.

## Version Constraints

Code actions preserve the structure of simple, recognized version constraints.
The same safety rules apply to individual and bulk updates:

| Original | Action | Result |
|----------|--------|--------|
| `"1.0.0"` | Update to 1.0.5 | `"1.0.5"` |
| `"^1.0.0"` | Update to 1.5.0 | `"^1.5.0"` |
| `"~1.0.0"` | Update to 1.0.5 | `"~1.0.5"` |
| `">=1.0"` | Update to 1.5.0 | `">=1.5.0"` |
| `"~=14.2"` | Update to 14.3.3 | `"~=14.3"` |
| `"~> 7.0"` | Update to 8.1.4 | `"~> 8.1"` |
| `"[1.0]"` | Update to 2.0 | `"[2.0]"` |

Operators, spacing, exact-version wrappers, and range-shaping precision are
retained when Depsy can prove that replacing the single version anchor is
safe. Go module updates preserve exactly one existing `v` prefix. Unprefixed,
multiply-prefixed, or otherwise unsupported prefix shapes receive no automatic
update.

Compound ranges and indirect versions do not receive automatic update actions.
This includes multiple bounds, unions, wildcards, strict or exclusion
constraints, aliases, workspace protocols, pnpm catalogs, Maven properties,
URLs, and other unknown forms. Depsy omits the update instead of replacing
the declaration with a bare version; other actions such as **Ignore package**
remain available.

## Workflow Tips

### Safe Update Strategy

1. Start with patch updates - they're low risk
2. Apply minor updates next
3. Handle major updates individually with testing

### CI Integration

After updating, run your CI pipeline to catch any issues:

```bash
# Run tests
cargo test

# Check for breaking changes
cargo clippy
```

### Lockfile Updates

After applying code actions, update your lockfile:

```bash
# Rust
cargo update

# Node.js
npm install

# Python
pip install -r requirements.txt
```

## Troubleshooting

### No Code Actions Appearing

1. Ensure cursor is on a dependency line
2. Check that the package has available updates
3. Verify inlay hints are showing (same data source)

### Action Not Applying

1. Check file is saved
2. Verify syntax is correct
3. Look for conflicting edits

### Wrong Version Suggested

1. Clear cache: `rm -rf ~/.cache/depsy/`
2. Restart Zed
3. Check if registry has newer version
