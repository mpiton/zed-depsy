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
| `pnpm-workspace.yaml` | pnpm workspace catalogs (`catalog` and `catalogs`) |

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

### pnpm Workspace Catalogs

```yaml
packages:
  - packages/*
catalog:
  react: ^18.3.1
catalogs:
  legacy:
    react: ^17.0.2
```

Opening `pnpm-workspace.yaml` gives every entry of the default `catalog` and of
each named catalog under `catalogs` the same inlay hints, diagnostics,
vulnerability checks and update code actions as a `package.json` dependency.
Other keys of the file (`packages`, `overrides`, ...) are ignored.

In `package.json`, `catalog:` and `catalog:<name>` references resolve to the
version pinned in the nearest `pnpm-workspace.yaml`.

Catalog entries are resolved against the `catalogs` section of the
`pnpm-lock.yaml` next to the workspace file, so each entry gets the version
locked for its own catalog; lockfiles of other package managers are ignored.
Entries that no workspace project references are absent from that section, and
entries whose range changed since the last `pnpm install` no longer match the
locked `specifier`; both are checked against their declared range instead.

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

Local dependencies show `→ Local` hint. Hovering one does not ask the registry: the hover says the dependency is local, then lists the transitive vulnerabilities the lockfile attributes to it. The same holds for `workspace:`, `link:` and git dependencies.

### npm Aliases

```json
{
  "dependencies": {
    "lodash-es": "npm:lodash@^4.17.0"
  }
}
```

Vulnerabilities are checked against the actual package (`lodash` here) and reported under the name in the manifest. The inlay hint stays `→ Local` unless the package is vulnerable or deprecated, and no update check runs for an alias to another package. `npm:^1.0.0`, with a range only, and the `npm:latest` tag are not aliases: they name the package itself. Their inlay hint and diagnostic still treat them as local dependencies, but hovering any `npm:` spec looks the package up in the registry: the aliased package for an alias, the declared package for a tag or a range.

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
