---
title: JavaScript/TypeScript
layout: default
parent: Languages
nav_order: 2
description: "Node.js/npm package.json support"
---

# JavaScript/TypeScript
{: .no_toc }

Support for Node.js projects using package.json.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Supported Files

| File | Description |
|------|-------------|
| `package.json` | npm/yarn/pnpm manifest |

### Lockfile Resolution

Depsy reads lockfiles to show resolved versions and eliminate false-positive "update available" warnings:

| Lockfile | Tool |
|----------|------|
| `package-lock.json` | npm (lockfileVersion 1, 2, 3) |
| `yarn.lock` | Yarn Classic v1 and Berry v2+ |
| `pnpm-lock.yaml` | pnpm v6 and v9 |
| `bun.lock` | Bun (text JSONC format) |

## Registry

**npm** - The Node.js package registry

- Base URL: `https://registry.npmjs.org`
- Rate limit: ~1 request per second recommended
- Documentation: [npmjs.com](https://www.npmjs.com)

### Private Registries

npm supports custom registries. See [Private Registries]({% link registries/private.md %}) for setup.

## Dependency Formats

Depsy parses all npm dependency sections:

### Dependencies

```json
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "4.17.21"
  }
}
```

### Dev Dependencies

```json
{
  "devDependencies": {
    "typescript": "^5.0.0",
    "jest": "^29.0.0"
  }
}
```

### Peer Dependencies

```json
{
  "peerDependencies": {
    "react": "^18.0.0"
  }
}
```

### Optional Dependencies

```json
{
  "optionalDependencies": {
    "fsevents": "^2.3.0"
  }
}
```

## Version Specification

npm uses semantic versioning:

| Syntax | Meaning |
|--------|---------|
| `"1.0.0"` | Exactly 1.0.0 |
| `"^1.0.0"` | >=1.0.0, <2.0.0 |
| `"~1.0.0"` | >=1.0.0, <1.1.0 |
| `"*"` | Any version |
| `">=1.0.0"` | 1.0.0 or higher |
| `"1.0.0 - 2.0.0"` | Range |
| `"latest"` | Latest tag |

## Special Cases

### Scoped Packages

```json
{
  "dependencies": {
    "@types/node": "^20.0.0",
    "@company/internal": "^1.0.0"
  }
}
```

Scoped packages (`@scope/name`) are fully supported. For private scopes, configure [Private Registries]({% link registries/private.md %}).

### Git Dependencies

```json
{
  "dependencies": {
    "my-lib": "git+https://github.com/user/repo.git"
  }
}
```

Git dependencies show `→ Git` hint.

### Local Dependencies

```json
{
  "dependencies": {
    "my-local": "file:../my-local"
  }
}
```

Local dependencies show `→ Local` hint.

### npm Aliases

```json
{
  "dependencies": {
    "lodash-es": "npm:lodash@^4.17.0"
  }
}
```

Aliases are resolved to the actual package.

### Deprecated Packages

Deprecated packages show `⚠ Deprecated` hint with the deprecation message on hover.

## Dist Tags

npm packages can have distribution tags:
- `latest` - Default stable version
- `next` - Pre-release version
- `beta`, `alpha` - Testing versions

Depsy checks against `latest` by default.

## Vulnerability Database

npm vulnerabilities are sourced via the [OSV.dev](https://osv.dev) API, which aggregates:
- [npm Advisories](https://www.npmjs.com/advisories)
- GitHub Security Advisories

## Example package.json

```jsonc
{
  "name": "my-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",         // ✓
    "lodash": "4.17.15",          // -> 4.17.21
    "@types/node": "^20.0.0"      // ✓
  },
  "devDependencies": {
    "typescript": "^5.0.0",       // -> 5.3.0
    "jest": "^29.0.0"             // ✓
  }
}
```

## Troubleshooting

### Scoped Package Not Found

For private scoped packages:
1. Configure the scope in [Private Registries]({% link registries/private.md %})
2. Ensure authentication token is set
3. Verify the scope name doesn't include `@` in config

### Stale Versions

npm has heavy CDN caching. If a just-published version isn't showing:
1. Wait a few minutes for CDN propagation
2. Clear Depsy cache and restart Zed

### Rate Limiting

npm may block aggressive requests. Depsy's caching minimizes API calls, but large monorepos may experience slower initial loads.
