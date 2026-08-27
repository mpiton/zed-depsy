---
title: Go
layout: default
parent: Languages
nav_order: 4
description: "Go modules go.mod support"
---

# Go
{: .no_toc }

Support for Go projects using go.mod.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Supported Files

| File | Description |
|------|-------------|
| `go.mod` | Go module definition |

### Lockfile Resolution

Depsy reads `go.sum` to show resolved versions and eliminate false-positive "update available" warnings.

## Registry

**Go Module Proxy** - Official Go module mirror

- Base URL: `https://proxy.golang.org`
- Rate limit: Fair use policy (heavily cached)
- Documentation: [go.dev](https://go.dev/ref/mod)

## Dependency Format

### Direct Dependencies

```go
require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/sync v0.6.0
)
```

### Single Dependency

```go
require github.com/gin-gonic/gin v1.9.1
```

### Indirect Dependencies

```go
require (
    github.com/gin-gonic/gin v1.9.1
    github.com/go-playground/validator/v10 v10.14.0 // indirect
)
```

Indirect dependencies are shown with lighter styling.

## Version Specification

Go modules use strict semantic versioning:

| Format | Description |
|--------|-------------|
| `v1.0.0` | Standard semver |
| `v1.0.0+incompatible` | Pre-modules package |
| `v0.0.0-20210101000000-abcdef123456` | Pseudo-version |

### Major Version Paths

Go requires major version suffix for v2+:

```go
require (
    github.com/user/repo v1.5.0      // v1.x
    github.com/user/repo/v2 v2.1.0   // v2.x
    github.com/user/repo/v3 v3.0.0   // v3.x
)
```

## Special Cases

### Module Path Encoding

Go module paths use special encoding:
- Uppercase letters are escaped: `Azure` → `!azure`
- Depsy handles this automatically

### Pseudo-versions

Pseudo-versions reference specific commits:

```go
require github.com/user/repo v0.0.0-20231215000000-abcdef123456
```

These show `→ Pseudo` hint (no direct update path).

### Replace Directives

```go
replace github.com/user/repo => ../local-repo
replace github.com/old/repo => github.com/new/repo v1.0.0
```

Replace directives show `→ Replaced` hint.

### Exclude Directives

```go
exclude github.com/user/repo v1.0.1
```

Excluded versions are noted but don't affect hints.

### Retracted Versions

Retracted versions in Go show `⊘ Retracted` hint (similar to yanked).

## Vulnerability Database

Go vulnerabilities are sourced from:
- [Go Vulnerability Database](https://pkg.go.dev/vuln/)
- GitHub Security Advisories

## Example go.mod

```go
module github.com/myorg/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1          // ✓
    github.com/spf13/cobra v1.7.0            // -> v1.8.0
    golang.org/x/sync v0.6.0                 // ✓
    google.golang.org/grpc v1.59.0           // ✓
)

require (
    github.com/bytedance/sonic v1.9.1 // indirect
    github.com/gabriel-vasile/mimetype v1.4.2 // indirect
)
```

## Tooling Integration

After updating `go.mod` with Depsy:

```bash
# Update go.sum
go mod tidy

# Verify module graph
go mod verify

# Download dependencies
go mod download
```

## Troubleshooting

### Module Not Found

1. Verify module path is correct
2. Check if module is public or requires authentication
3. Ensure `GOPROXY` environment isn't blocking

### Pseudo-version Updates

Pseudo-versions can't be directly updated. You need to:
1. Find the latest tagged version
2. Update manually to the tag
3. Or update the commit reference

### Version Mismatch

Go modules are strictly versioned. If hints show unexpected versions:
1. Check for `replace` directives
2. Verify `go.mod` is in sync with `go.sum`
3. Run `go mod tidy` to clean up

### Rate Limiting

The Go proxy uses CDN caching. First requests may be slower, but subsequent requests are fast.
