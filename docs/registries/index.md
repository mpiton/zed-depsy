---
title: Registries
layout: default
nav_order: 6
has_children: true
description: "Package registry documentation"
---

# Package Registries
{: .no_toc }

Information about supported package registries and their APIs.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Quick Reference

| Registry | Ecosystem | Base URL | Rate Limit |
|----------|-----------|----------|------------|
| crates.io | Rust | `https://crates.io/api/v1` | 1 req/s |
| npm | Node.js | `https://registry.npmjs.org` | ~1 req/s |
| PyPI | Python | `https://pypi.org/pypi` | ~20 req/s |
| Go Proxy | Go | `https://proxy.golang.org` | Fair use |
| Packagist | PHP | `https://repo.packagist.org` | ~60/min |
| pub.dev | Dart | `https://pub.dev/api` | ~100/min |
| NuGet | .NET | `https://api.nuget.org/v3` | Fair use |
| RubyGems | Ruby | `https://rubygems.org/api/v1` | ~10 req/s |

{: .note }
Rate limits are approximate and may change. Verify with each registry before relying on them.

## Common Data Model

All registries return a unified structure:

```rust
VersionInfo {
    latest: Option<String>,           // Latest stable version
    latest_prerelease: Option<String>, // Latest prerelease
    versions: Vec<String>,            // All available versions
    description: Option<String>,      // Package description
    homepage: Option<String>,         // Homepage URL
    repository: Option<String>,       // Repository URL
    license: Option<String>,          // SPDX license
    vulnerabilities: Vec<Vulnerability>, // Known vulnerabilities (via OSV)
    deprecated: bool,                 // Deprecation status
    yanked: bool,                     // Whether latest is yanked
    yanked_versions: Vec<String>,     // List of yanked versions
    release_dates: HashMap<String, DateTime<Utc>>, // Version timestamps
}
```

## Registry Details

### crates.io

**Ecosystem:** Rust
**Endpoint:** `GET https://crates.io/api/v1/crates/{name}`

- Strict rate limiting (1 req/s enforced)
- Name normalization: `foo-bar` = `foo_bar`
- `yanked` field for withdrawn versions
- [Documentation](https://crates.io/data-access)
- **Alternative registries**: Depsy also supports querying alternative Cargo registries (Kellnr, Cloudsmith, etc.) via the sparse index protocol. See [Private Registries]({% link registries/private.md %}) for configuration.

### npm

**Ecosystem:** Node.js
**Endpoint:** `GET https://registry.npmjs.org/{name}`

- Scoped packages: `@scope%2fname`
- `dist-tags.latest` for current version
- `deprecated` field (string message)
- [Documentation](https://github.com/npm/registry)

### PyPI

**Ecosystem:** Python
**Endpoint:** `GET https://pypi.org/pypi/{name}/json`

- Name normalization per PEP 503
- Version format follows PEP 440
- [Documentation](https://docs.pypi.org/api/json/)

### Go Proxy

**Ecosystem:** Go
**Endpoints:**
- `GET https://proxy.golang.org/{module}/@v/list`
- `GET https://proxy.golang.org/{module}/@latest`

- Module path encoding for uppercase
- Version prefix `v` required
- [Documentation](https://go.dev/ref/mod#module-proxy)

### Packagist

**Ecosystem:** PHP
**Endpoint:** `GET https://repo.packagist.org/p2/{vendor}/{package}.json`

- Format: `vendor/package`
- `abandoned` field for deprecated packages
- [Documentation](https://packagist.org/apidoc)

### pub.dev

**Ecosystem:** Dart
**Endpoint:** `GET https://pub.dev/api/packages/{name}`

- `retracted` equivalent to yanked
- `discontinued` for deprecated
- [Documentation](https://pub.dev/help/api)

### NuGet

**Ecosystem:** .NET
**Endpoint:** `GET https://api.nuget.org/v3/registration5-semver1/{id}/index.json`

- Case-insensitive package IDs
- `listed: false` hides from search
- [Documentation](https://learn.microsoft.com/en-us/nuget/api/overview)

### RubyGems

**Ecosystem:** Ruby
**Endpoints:**
- `GET https://rubygems.org/api/v1/gems/{name}.json`
- `GET https://rubygems.org/api/v1/versions/{name}.json`

- Prerelease: `.pre.1` (not `-pre.1`)
- Platform gems: `-java`, `-x86_64-linux`
- [Documentation](https://guides.rubygems.org/rubygems-org-api/)

## Vulnerability Detection

Vulnerabilities are **not** from package registries. Depsy uses [OSV.dev](https://osv.dev) (Google's Open-Source Vulnerabilities database) for all ecosystems.

OSV aggregates from:
- GitHub Security Advisories
- RustSec
- PyPA Advisory Database
- Go Vulnerability Database
- And more

## Network Requirements

Ensure these URLs are accessible through your firewall:

```text
https://crates.io
https://registry.npmjs.org
https://pypi.org
https://proxy.golang.org
https://packagist.org
https://pub.dev
https://api.nuget.org
https://rubygems.org
https://api.osv.dev
```

## Troubleshooting

### Rate Limit Errors (429)

- **crates.io**: Wait 1 second between requests (automatic)
- **Other registries**: Implement backoff, use caching

### Package Not Found

- Check spelling and case sensitivity
- For scoped npm: `@scope/name` format
- For Packagist: `vendor/package` format
- For Go: Check module path encoding

### Timeout Errors

Default timeout is 10 seconds. Slow registries may cause timeouts. Network issues or registry outages may affect availability.

## Private Registries

For enterprise packages and self-hosted registries, see [Private Registries]({% link registries/private.md %}).
