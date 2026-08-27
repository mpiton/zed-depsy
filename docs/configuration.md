---
title: Configuration
layout: default
nav_order: 3
description: "Configure Depsy settings in Zed Editor"
---

# Configuration
{: .no_toc }

Customize Depsy behavior through Zed settings.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Configuration Location

Configure Depsy in your Zed `settings.json`:

- **User settings**: `~/.config/zed/settings.json` (Linux) or `~/Library/Application Support/Zed/settings.json` (macOS)
- **Project settings**: `.zed/settings.json` in your project root

## Full Configuration Example

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "inlay_hints": {
          "enabled": true,
          "show_up_to_date": true
        },
        "diagnostics": {
          "enabled": true
        },
        "cache": {
          "ttl_secs": 3600
        },
        "security": {
          "enabled": true,
          "show_in_hints": true,
          "show_diagnostics": true,
          "min_severity": "low"
        },
        "ignore": ["internal-*", "test-pkg"]
      }
    }
  }
}
```

## Configuration Options Reference

### Inlay Hints

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `inlay_hints.enabled` | boolean | `true` | Enable/disable inlay hints |
| `inlay_hints.show_up_to_date` | boolean | `true` | Show hints for up-to-date packages |

**Example:**
```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "inlay_hints": {
          "enabled": true,
          "show_up_to_date": false
        }
      }
    }
  }
}
```

### Diagnostics

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `diagnostics.enabled` | boolean | `true` | Enable/disable diagnostics for outdated dependencies |

**Example:**
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

### Cache

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cache.ttl_secs` | number | `3600` | Cache time-to-live in seconds (1 hour default) |
| `cache.debounce_ms` | number | `200` | Debounce delay for file change notifications (ms) |

**Example:**
```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "cache": {
          "ttl_secs": 7200
        }
      }
    }
  }
}
```

{: .note }
The cache is stored in your system's cache directory. Increasing TTL reduces network requests but may show stale data.

### Security (Vulnerability Scanning)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `security.enabled` | boolean | `true` | Enable/disable vulnerability scanning |
| `security.show_in_hints` | boolean | `true` | Show vulnerability count in inlay hints |
| `security.show_diagnostics` | boolean | `true` | Show vulnerability diagnostics |
| `security.min_severity` | string | `"low"` | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `security.cache_ttl_secs` | number | `21600` | Vulnerability cache TTL in seconds (6 hours default) |

**Example:**
```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "security": {
          "enabled": true,
          "show_in_hints": true,
          "show_diagnostics": true,
          "min_severity": "high"
        }
      }
    }
  }
}
```

### Ignore Patterns

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ignore` | string[] | `[]` | Package names or glob patterns to ignore |

**Example:**
```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "ignore": [
          "internal-*",
          "my-private-pkg",
          "@company/*"
        ]
      }
    }
  }
}
```

### Private Registries

Configure custom registries for private packages. See [Private Registries]({% link registries/private.md %}) for detailed setup.

#### Cargo Alternative Registries

| Option | Type | Description |
|--------|------|-------------|
| `registries.cargo.registries` | object | Map of registry name to configuration |
| `registries.cargo.registries.<name>.index_url` | string | Sparse index URL (without `sparse+` prefix) |
| `registries.cargo.registries.<name>.auth` | object | Optional authentication configuration |
| `registries.cargo.registries.<name>.auth.type` | string | Auth type (`"env"`) |
| `registries.cargo.registries.<name>.auth.variable` | string | Environment variable containing the token |

**Example:**
```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "registries": {
          "cargo": {
            "registries": {
              "my-registry": {
                "index_url": "https://my-registry.example.com/api/v1/crates",
                "auth": {
                  "type": "env",
                  "variable": "MY_REGISTRY_TOKEN"
                }
              }
            }
          }
        }
      }
    }
  }
}
```

{: .note }
Dependencies using an alternative registry must specify it in `Cargo.toml`: `my-crate = { version = "0.1.0", registry = "my-registry" }`. Dependencies without a `registry` field are fetched from crates.io. Authentication falls back to `~/.cargo/credentials.toml` if not configured in LSP settings.

#### npm Scoped Registries

| Option | Type | Description |
|--------|------|-------------|
| `registries.npm.url` | string | Base registry URL |
| `registries.npm.scoped` | object | Scoped registry configuration |

**Example:**
```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "registries": {
          "npm": {
            "url": "https://registry.npmjs.org",
            "scoped": {
              "company": {
                "url": "https://npm.company.com",
                "auth": {
                  "type": "env",
                  "variable": "COMPANY_NPM_TOKEN"
                }
              }
            }
          }
        }
      }
    }
  }
}
```

{: .warning }
Scope names should **not** include the `@` prefix. Use `"company"` not `"@company"`.

## Cache Locations

Depsy stores cached data in your system's cache directory:

| Platform | Location |
|----------|----------|
| Linux | `~/.cache/depsy/cache.db` |
| macOS | `~/Library/Caches/depsy/cache.db` |
| Windows | `%LOCALAPPDATA%\depsy\cache.db` |

### Clearing the Cache

To force refresh all package data:

```bash
# Linux
rm -rf ~/.cache/depsy/

# macOS
rm -rf ~/Library/Caches/depsy/

# Windows
rmdir /s %LOCALAPPDATA%\depsy
```

Then restart Zed. The cache will rebuild as you open dependency files.

## Configuration Tips

### Offline Work

For working offline, increase the cache TTL:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "cache": {
          "ttl_secs": 86400
        }
      }
    }
  }
}
```

### Noisy Projects

For projects with many internal packages, use ignore patterns:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "ignore": ["@internal/*", "dev-*"]
      }
    }
  }
}
```

### Security-Focused Setup

For strict security scanning:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "security": {
          "enabled": true,
          "show_in_hints": true,
          "show_diagnostics": true,
          "min_severity": "medium"
        }
      }
    }
  }
}
```

### Minimal UI

For a cleaner interface showing only updates:

```json
{
  "lsp": {
    "depsy": {
      "initialization_options": {
        "inlay_hints": {
          "enabled": true,
          "show_up_to_date": false
        }
      }
    }
  }
}
```

## Troubleshooting Configuration

### Configuration Not Applying

1. Verify JSON syntax is valid
2. Ensure settings are under the correct path:
   ```json
   {
     "lsp": {
       "depsy": {
         "initialization_options": {
           // settings here
         }
       }
     }
   }
   ```
3. Restart Zed after configuration changes
4. Check for typos in setting names

### Debugging

Run Zed with debug logging to see configuration loading:

```bash
RUST_LOG=debug zed --foreground
```

### Environment Variables

The LSP reads a small set of environment variables. Most users do not need to set
any of them; they exist for advanced configuration and tests.

| Variable | Used by | Description |
|----------|---------|-------------|
| `RUST_LOG` | `tracing-subscriber` | Log filter (e.g. `debug`, `depsy_lsp=trace`). |
| `OSV_ENDPOINT` | `depsy-lsp scan` | Override the OSV.dev base URL for vulnerability queries. Honored only by the `scan` subcommand (see `depsy-lsp/src/main.rs::run_scan`); `profile-parse`, `profile-registry`, and `profile-full` construct `OsvClient::default()` directly and ignore this variable. Used by the integration test harness to point at a local mock server; can also be set to a private OSV-compatible mirror. |
| `CARGO_HOME` | Cargo registry auth resolver | Standard Cargo variable. When set, the LSP reads `${CARGO_HOME}/credentials.toml` instead of `~/.cargo/credentials.toml` to discover alternative registry tokens. |
| `<TOKEN_VAR>` (e.g. `GITHUB_TOKEN`, `COMPANY_NPM_TOKEN`) | `EnvTokenProvider` in `src/auth/mod.rs` | Read at LSP startup for every registry whose settings declare `"auth": { "type": "env", "variable": "<NAME>" }` (Cargo alternative registries and npm scoped registries — see the configuration examples above). The variable name is whatever the JSON references; there are no hardcoded names. Note: `.npmrc` `${VAR}` expansion is **not** currently wired into the runtime auth path (`src/auth/npmrc.rs` is test-only, gated on `#[cfg(test)]`) — tokens must come from LSP settings. |

#### Example — pointing `scan` at a mock OSV server

```bash
OSV_ENDPOINT=http://127.0.0.1:8787 \
    depsy-lsp scan --file Cargo.toml
```
