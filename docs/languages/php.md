---
title: PHP
layout: default
parent: Languages
nav_order: 5
description: "PHP Composer support"
---

# PHP
{: .no_toc }

Support for PHP projects using composer.json.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Supported Files

| File | Description |
|------|-------------|
| `composer.json` | Composer manifest |

### Lockfile Resolution

Depsy reads `composer.lock` to show resolved versions and eliminate false-positive "update available" warnings.

## Registry

**Packagist** - The PHP package repository

- Base URL: `https://repo.packagist.org`
- Rate limit: ~60 requests per minute
- Documentation: [packagist.org](https://packagist.org)

## Dependency Format

### Regular Dependencies

```json
{
    "require": {
        "php": ">=8.1",
        "laravel/framework": "^10.0",
        "guzzlehttp/guzzle": "^7.0"
    }
}
```

### Development Dependencies

```json
{
    "require-dev": {
        "phpunit/phpunit": "^10.0",
        "phpstan/phpstan": "^1.10"
    }
}
```

## Version Specification

Composer uses semantic versioning:

| Syntax | Meaning |
|--------|---------|
| `1.0.0` | Exactly 1.0.0 |
| `^1.0` | >=1.0.0, <2.0.0 |
| `~1.0` | >=1.0.0, <1.1.0 |
| `>=1.0 <2.0` | Range |
| `1.0.*` | 1.0.x |
| `*` | Any version |
| `dev-main` | Development branch |

## Special Cases

### Package Naming

Packagist uses `vendor/package` format:

```json
{
    "require": {
        "symfony/console": "^6.0",
        "monolog/monolog": "^3.0"
    }
}
```

### PHP Version Constraints

```json
{
    "require": {
        "php": ">=8.1 <8.4"
    }
}
```

PHP constraints show version compatibility info.

### Extensions

```json
{
    "require": {
        "ext-json": "*",
        "ext-mbstring": "*"
    }
}
```

Extension requirements show `→ Extension` hint.

### Development Versions

```json
{
    "require": {
        "vendor/package": "dev-main"
    }
}
```

Dev versions (dev-main, dev-master, x.x.x-dev) are filtered from latest version checks.

### Abandoned Packages

Abandoned packages on Packagist show `⚠ Abandoned` hint. The hover shows the suggested replacement if available.

## Vulnerability Database

PHP vulnerabilities are sourced from:
- [PHP Security Advisories Database](https://github.com/FriendsOfPHP/security-advisories)
- GitHub Security Advisories
- Packagist security notices

## Example composer.json

```json
{
    "name": "myorg/myproject",
    "type": "project",
    "require": {
        "php": ">=8.1",
        "laravel/framework": "^10.0",      // ✓
        "guzzlehttp/guzzle": "^7.0",       // -> 7.8.0
        "symfony/console": "^6.0"          // ✓
    },
    "require-dev": {
        "phpunit/phpunit": "^10.0",        // -> 10.5.0
        "phpstan/phpstan": "^1.10"         // ✓
    }
}
```

## Tooling Integration

After updating `composer.json` with Depsy:

```bash
# Update lockfile and install
composer update

# Update specific package
composer update vendor/package

# Check for outdated packages
composer outdated
```

## Troubleshooting

### Package Not Found

1. Verify vendor/package format
2. Check if package exists on Packagist
3. For private packages, configure repository in `composer.json`

### Version Constraints Too Restrictive

If no updates are shown but versions exist:
1. Check your PHP version constraint
2. Review package's PHP requirements
3. Consider relaxing version constraints

### Private Packages

For private Packagist/Satis repositories:
1. Configure repository in `composer.json`
2. Set up authentication in `auth.json`
3. Note: Depsy currently uses Packagist only

### Abandoned Package Warning

If a package shows abandoned:
1. Check the replacement suggestion on hover
2. Plan migration to the replacement
3. Review the original package's README for migration guide
