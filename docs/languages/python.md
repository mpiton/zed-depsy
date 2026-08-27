---
title: Python
layout: default
parent: Languages
nav_order: 3
description: "Python requirements.txt and pyproject.toml support"
---

# Python
{: .no_toc }

Support for Python projects using requirements.txt and pyproject.toml.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Supported Files

| File | Description |
|------|-------------|
| `requirements.txt` | pip requirements file |
| `constraints.txt` | pip constraints file |
| `pyproject.toml` | PEP 517/518 project file |

### Lockfile Resolution

Depsy reads lockfiles to show resolved versions and eliminate false-positive "update available" warnings:

| Lockfile | Tool |
|----------|------|
| `poetry.lock` | Poetry |
| `uv.lock` | uv |
| `pdm.lock` | PDM |
| `Pipfile.lock` | Pipenv |

## Registry

**PyPI** - The Python Package Index

- Base URL: `https://pypi.org/pypi`
- Rate limit: ~20 requests per second
- Documentation: [pypi.org](https://pypi.org)

## requirements.txt Format

### Basic Syntax

```text
requests==2.31.0
flask>=2.0.0
django>=4.0,<5.0
```

### With Comments

```text
# Web framework
flask>=2.0.0

# HTTP library
requests==2.31.0  # pinned for compatibility
```

### With Extras

```text
requests[security]==2.31.0
celery[redis,auth]>=5.0.0
```

### Editable Installs

```text
-e git+https://github.com/user/repo.git#egg=package
```

Editable installs show `→ Git` hint.

## pyproject.toml Format

### PEP 621 (Standard)

```toml
[project]
dependencies = [
    "requests>=2.31.0",
    "flask>=2.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black>=23.0.0",
]
```

### Poetry

```toml
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
flask = "^2.0.0"

[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
```

### Setuptools (Legacy)

```toml
[options]
install_requires =
    requests>=2.31.0
    flask>=2.0.0
```

## Version Specification

Python uses PEP 440 version specifiers:

| Syntax | Meaning |
|--------|---------|
| `==1.0.0` | Exactly 1.0.0 |
| `>=1.0.0` | 1.0.0 or higher |
| `<=1.0.0` | 1.0.0 or lower |
| `~=1.0.0` | >=1.0.0, <1.1.0 (compatible) |
| `>=1.0,<2.0` | Range |
| `!=1.0.0` | Not 1.0.0 |
| `*` | Any version |

## Special Cases

### Name Normalization

PyPI normalizes package names per PEP 503:
- `Flask` = `flask`
- `typing_extensions` = `typing-extensions`

Depsy handles normalization automatically.

### Pre-release Versions

```text
flask>=2.0.0a1
requests>=2.31.0rc1
```

Pre-release versions (alpha, beta, rc) are tracked separately.

### Development Status

Packages marked with classifier `Development Status :: 7 - Inactive` show as deprecated.

### Yanked Versions

Yanked versions on PyPI show `⊘ Yanked` hint.

## Vulnerability Database

Python vulnerabilities are sourced from:
- [PyPA Advisory Database](https://github.com/pypa/advisory-database)
- GitHub Security Advisories
- [Safety DB](https://github.com/pyupio/safety-db)

## Example Files

### requirements.txt

```text
# Production dependencies
requests==2.31.0                 # ✓
flask>=2.0.0                     # -> 3.0.0
django>=4.0,<5.0                 # ✓
sqlalchemy>=2.0.0                # ✓

# Development
pytest>=7.0.0                    # -> 7.4.0
black>=23.0.0                    # ✓
```

### pyproject.toml

```toml
[project]
name = "my-project"
version = "1.0.0"
dependencies = [
    "requests>=2.31.0",          # ✓
    "flask>=2.0.0",              # -> 3.0.0
    "pydantic>=2.0.0",           # ✓
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",             # -> 7.4.0
    "ruff>=0.1.0",               # ✓
]
```

## Troubleshooting

### Package Not Found

1. Check package name spelling (remember normalization)
2. Verify the package exists on PyPI
3. Check network connectivity to pypi.org

### Wrong Version Shown

1. PyPI may have multiple releases per version
2. Clear cache and restart Zed
3. Check if package uses non-standard versioning

### requirements.txt Not Parsed

1. Ensure standard format (no unusual characters)
2. Check for BOM or encoding issues
3. Remove any complex pip options
