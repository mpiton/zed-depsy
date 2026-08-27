//! Configuration management for Depsy LSP

use hashbrown::HashMap;
use serde::Deserialize;

/// Default cache TTL (1 hour)
const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

/// Default vulnerability cache TTL (6 hours)
const DEFAULT_VULN_CACHE_TTL_SECS: u64 = 6 * 3600;

/// LSP configuration
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Inlay hints configuration
    pub inlay_hints: InlayHintsConfig,
    /// Diagnostics configuration
    pub diagnostics: DiagnosticsConfig,
    /// Cache configuration
    pub cache: CacheConfig,
    /// RustSec advisory cache configuration (issue #237)
    pub advisory_cache: AdvisoryCacheConfig,
    /// Security/vulnerability configuration
    pub security: SecurityConfig,
    /// Packages to ignore (glob patterns)
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Package registries configuration
    #[serde(default)]
    pub registries: RegistriesConfig,
}

/// Inlay hints configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InlayHintsConfig {
    /// Enable inlay hints
    pub enabled: bool,
    /// Show hints for up-to-date packages
    pub show_up_to_date: bool,
}

impl Default for InlayHintsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            show_up_to_date: true,
        }
    }
}

/// Diagnostics configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DiagnosticsConfig {
    /// Enable diagnostics
    pub enabled: bool,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Default debounce delay for did_change notifications (200ms)
const DEFAULT_DEBOUNCE_MS: u64 = 200;

/// Cache configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Cache TTL in seconds
    pub ttl_secs: u64,
    /// Debounce delay for did_change notifications in milliseconds
    pub debounce_ms: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_CACHE_TTL_SECS,
            debounce_ms: DEFAULT_DEBOUNCE_MS,
        }
    }
}

/// Configuration for the RustSec advisory cache (issue #237).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AdvisoryCacheConfig {
    /// Enable the cache. Disabled => NullAdvisoryCache (every call hits HTTP).
    pub enabled: bool,
    /// Positive cache TTL in seconds.
    pub ttl_secs: u64,
    /// Negative cache TTL in seconds (used for OSV 404 responses).
    pub negative_ttl_secs: u64,
    /// Optional override for the SQLite database path.
    pub db_path: Option<std::path::PathBuf>,
}

impl Default for AdvisoryCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_secs: 86_400,
            negative_ttl_secs: 3_600,
            db_path: None,
        }
    }
}

/// Security/vulnerability scanning configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Enable vulnerability scanning
    pub enabled: bool,
    /// Show vulnerabilities in inlay hints
    pub show_in_hints: bool,
    /// Show vulnerabilities as diagnostics
    pub show_diagnostics: bool,
    /// Minimum severity level to display ("low", "medium", "high", "critical")
    pub min_severity: String,
    /// Vulnerability cache TTL in seconds (default: 6 hours)
    pub cache_ttl_secs: u64,
}

/// Authentication configuration for a registry.
///
/// Currently supports reading tokens from environment variables.
/// Tokens should NEVER be stored directly in LSP settings.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthConfig {
    /// Authentication type: "env" for environment variable
    #[serde(rename = "type", default)]
    pub auth_type: String,
    /// Environment variable name containing the token
    #[serde(default)]
    pub variable: String,
}

impl AuthConfig {
    /// Read token from the configured source.
    ///
    /// Currently only supports environment variables.
    /// Returns `None` if the auth type is unsupported or the variable is not set.
    pub fn get_token(&self) -> Option<String> {
        match self.auth_type.as_str() {
            "env" => std::env::var(&self.variable).ok(),
            _ => None,
        }
    }

    /// Check if authentication is configured.
    pub fn is_configured(&self) -> bool {
        self.auth_type == "env" && !self.variable.is_empty()
    }
}

/// Configuration for a scoped npm registry
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NpmScopedConfig {
    /// Registry URL for this scope
    pub url: String,
    /// Authentication configuration
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

/// npm registry configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NpmRegistryConfig {
    /// Default registry URL
    pub url: String,
    /// Scope-specific registry configurations (scope name without @)
    #[serde(default)]
    pub scoped: HashMap<String, NpmScopedConfig>,
}

impl Default for NpmRegistryConfig {
    fn default() -> Self {
        Self {
            url: "https://registry.npmjs.org".to_string(),
            scoped: HashMap::new(),
        }
    }
}

/// Configuration for a custom Cargo registry
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CargoCustomRegistryConfig {
    /// Sparse index URL for this registry (without sparse+ prefix)
    pub index_url: String,
    /// Authentication configuration
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

/// Cargo registry configuration
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CargoRegistryConfig {
    /// Named registries (registry name -> config)
    #[serde(default)]
    pub registries: HashMap<String, CargoCustomRegistryConfig>,
}

/// Maven registry configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MavenRegistryConfig {
    /// Base URL for the Maven repository (no trailing slash).
    /// Defaults to Maven Central. Configure to point at Nexus/Artifactory mirrors.
    pub url: String,
}

impl Default for MavenRegistryConfig {
    fn default() -> Self {
        Self {
            url: "https://repo1.maven.org/maven2".to_string(),
        }
    }
}

/// Package registries configuration
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RegistriesConfig {
    /// npm registry configuration
    pub npm: NpmRegistryConfig,
    /// Cargo alternative registries configuration
    #[serde(default)]
    pub cargo: CargoRegistryConfig,
    /// Maven registry configuration (Maven Central by default)
    #[serde(default)]
    pub maven: MavenRegistryConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            show_in_hints: true,
            show_diagnostics: true,
            min_severity: "low".to_string(),
            cache_ttl_secs: DEFAULT_VULN_CACHE_TTL_SECS,
        }
    }
}

impl SecurityConfig {
    /// Parse minimum severity level to VulnerabilitySeverity
    pub fn min_severity_level(&self) -> crate::registries::VulnerabilitySeverity {
        crate::registries::VulnerabilitySeverity::from_str_loose(&self.min_severity)
    }
}

impl Config {
    /// Parse configuration from initialization options
    pub fn from_init_options(options: Option<serde_json::Value>) -> Self {
        match options {
            Some(value) => serde_json::from_value(value).unwrap_or_default(),
            None => Self::default(),
        }
    }
}

/// Returns true if `name` matches any pattern in `patterns`.
///
/// Supported pattern syntax (preserves the historical inlay-hints filter behavior):
/// - exact match: `"lodash"` matches only `"lodash"`
/// - prefix wildcard: `"@company/*"` matches names starting with `"@company/"`
/// - suffix wildcard: `"*-test"` matches names ending with `"-test"`
/// - both wildcards: `"internal-*-lib"` matches names with that prefix AND suffix
///   (the middle may be empty: `"internal--lib"` is matched)
///
/// Caveats — known sharp edges of this simple matcher:
/// - A bare `"*"` pattern matches every package.
/// - Patterns with more than one `*` (e.g., `"a-*-b-*-c"`) are NOT fully supported;
///   they fall back to a prefix-only match against the substring before the first `*`.
///   For richer matching, prefer one or two `*` patterns, or list packages explicitly.
pub fn is_package_ignored(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        if pattern.contains('*') {
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                name.starts_with(parts[0]) && name.ends_with(parts[1])
            } else {
                name.starts_with(parts[0])
            }
        } else {
            name == *pattern
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use serial_test::serial;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.inlay_hints.enabled);
        assert!(config.inlay_hints.show_up_to_date);
        assert!(config.diagnostics.enabled);
        assert_eq!(config.cache.ttl_secs, DEFAULT_CACHE_TTL_SECS);
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn test_parse_from_json() {
        let json = json!({
            "inlay_hints": {
                "enabled": false,
                "show_up_to_date": false
            },
            "diagnostics": {
                "enabled": false
            },
            "cache": {
                "ttl_secs": 7200
            },
            "ignore": ["test-*", "internal-pkg"]
        });

        let config = Config::from_init_options(Some(json));
        assert!(!config.inlay_hints.enabled);
        assert!(!config.inlay_hints.show_up_to_date);
        assert!(!config.diagnostics.enabled);
        assert_eq!(config.cache.ttl_secs, 7200);
        assert_eq!(config.ignore.len(), 2);
    }

    #[test]
    fn test_partial_config() {
        let json = json!({
            "inlay_hints": {
                "enabled": false
            }
        });

        let config = Config::from_init_options(Some(json));
        assert!(!config.inlay_hints.enabled);
        // Other fields should use defaults
        assert!(config.inlay_hints.show_up_to_date);
        assert!(config.diagnostics.enabled);
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(config.enabled);
        assert!(config.show_in_hints);
        assert!(config.show_diagnostics);
        assert_eq!(config.min_severity, "low");
        assert_eq!(config.cache_ttl_secs, DEFAULT_VULN_CACHE_TTL_SECS);
    }

    #[test]
    fn test_security_config_from_json() {
        let json = json!({
            "security": {
                "enabled": false,
                "show_in_hints": false,
                "show_diagnostics": false,
                "min_severity": "high",
                "cache_ttl_secs": 3600
            }
        });

        let config = Config::from_init_options(Some(json));
        assert!(!config.security.enabled);
        assert!(!config.security.show_in_hints);
        assert!(!config.security.show_diagnostics);
        assert_eq!(config.security.min_severity, "high");
        assert_eq!(config.security.cache_ttl_secs, 3600);
    }

    #[test]
    fn test_min_severity_level_parsing() {
        use crate::registries::VulnerabilitySeverity;

        let config = SecurityConfig {
            min_severity: "low".to_string(),
            ..Default::default()
        };
        assert_eq!(config.min_severity_level(), VulnerabilitySeverity::Low);

        let config = SecurityConfig {
            min_severity: "medium".to_string(),
            ..Default::default()
        };
        assert_eq!(config.min_severity_level(), VulnerabilitySeverity::Medium);

        let config = SecurityConfig {
            min_severity: "high".to_string(),
            ..Default::default()
        };
        assert_eq!(config.min_severity_level(), VulnerabilitySeverity::High);

        let config = SecurityConfig {
            min_severity: "critical".to_string(),
            ..Default::default()
        };
        assert_eq!(config.min_severity_level(), VulnerabilitySeverity::Critical);
    }

    #[test]
    fn test_from_init_options_none() {
        let config = Config::from_init_options(None);
        assert!(config.inlay_hints.enabled);
        assert!(config.diagnostics.enabled);
    }

    #[test]
    fn test_from_init_options_invalid_json() {
        let json = json!("invalid");
        let config = Config::from_init_options(Some(json));
        assert!(config.inlay_hints.enabled);
    }

    #[test]
    fn test_cache_config_defaults() {
        let config = CacheConfig::default();
        assert_eq!(config.ttl_secs, DEFAULT_CACHE_TTL_SECS);
        assert_eq!(config.debounce_ms, DEFAULT_DEBOUNCE_MS);
    }

    #[test]
    fn test_diagnostics_config_defaults() {
        let config = DiagnosticsConfig::default();
        assert!(config.enabled);
    }

    #[test]
    fn test_inlay_hints_config_defaults() {
        let config = InlayHintsConfig::default();
        assert!(config.enabled);
        assert!(config.show_up_to_date);
    }

    #[test]
    fn test_npm_registry_config_defaults() {
        let config = NpmRegistryConfig::default();
        assert_eq!(config.url, "https://registry.npmjs.org");
        assert!(config.scoped.is_empty());
    }

    #[test]
    fn test_registries_config_defaults() {
        let config = RegistriesConfig::default();
        assert_eq!(config.npm.url, "https://registry.npmjs.org");
    }

    #[test]
    fn test_registries_config_from_json() {
        let json = json!({
            "registries": {
                "npm": {
                    "url": "https://npm.company.com",
                    "scoped": {
                        "company": {
                            "url": "https://npm.internal.company.com"
                        },
                        "github": {
                            "url": "https://npm.pkg.github.com"
                        }
                    }
                }
            }
        });

        let config = Config::from_init_options(Some(json));
        assert_eq!(config.registries.npm.url, "https://npm.company.com");
        assert_eq!(config.registries.npm.scoped.len(), 2);
        assert_eq!(
            config.registries.npm.scoped.get("company").unwrap().url,
            "https://npm.internal.company.com"
        );
        assert_eq!(
            config.registries.npm.scoped.get("github").unwrap().url,
            "https://npm.pkg.github.com"
        );
    }

    #[test]
    fn test_registries_config_partial() {
        let json = json!({
            "registries": {
                "npm": {
                    "url": "https://custom.registry.com"
                }
            }
        });

        let config = Config::from_init_options(Some(json));
        assert_eq!(config.registries.npm.url, "https://custom.registry.com");
        assert!(config.registries.npm.scoped.is_empty());
    }

    #[test]
    fn test_registries_config_empty() {
        let json = json!({});

        let config = Config::from_init_options(Some(json));
        assert_eq!(config.registries.npm.url, "https://registry.npmjs.org");
    }

    #[test]
    fn test_auth_config_defaults() {
        let config = AuthConfig::default();
        assert_eq!(config.auth_type, "");
        assert_eq!(config.variable, "");
        assert!(!config.is_configured());
        assert!(config.get_token().is_none());
    }

    #[test]
    #[serial]
    fn test_auth_config_env_type() {
        // SAFETY: serial_test ensures this test runs exclusively, preventing race conditions
        unsafe {
            std::env::set_var("TEST_AUTH_TOKEN", "secret123");
        }

        let json = json!({
            "registries": {
                "npm": {
                    "scoped": {
                        "company": {
                            "url": "https://npm.company.com",
                            "auth": {
                                "type": "env",
                                "variable": "TEST_AUTH_TOKEN"
                            }
                        }
                    }
                }
            }
        });

        let config = Config::from_init_options(Some(json));
        let scoped = config.registries.npm.scoped.get("company").unwrap();
        assert_eq!(scoped.url, "https://npm.company.com");

        let auth = scoped.auth.as_ref().unwrap();
        assert_eq!(auth.auth_type, "env");
        assert_eq!(auth.variable, "TEST_AUTH_TOKEN");
        assert!(auth.is_configured());
        assert_eq!(auth.get_token(), Some("secret123".to_string()));

        // SAFETY: serial_test ensures this test runs exclusively, preventing race conditions
        unsafe {
            std::env::remove_var("TEST_AUTH_TOKEN");
        }
    }

    #[test]
    fn test_auth_config_missing_env_var() {
        let json = json!({
            "registries": {
                "npm": {
                    "scoped": {
                        "company": {
                            "url": "https://npm.company.com",
                            "auth": {
                                "type": "env",
                                "variable": "NONEXISTENT_TOKEN_12345"
                            }
                        }
                    }
                }
            }
        });

        let config = Config::from_init_options(Some(json));
        let scoped = config.registries.npm.scoped.get("company").unwrap();
        let auth = scoped.auth.as_ref().unwrap();

        assert!(auth.is_configured());
        assert!(auth.get_token().is_none());
    }

    #[test]
    fn test_cargo_registry_config_defaults() {
        let config = CargoRegistryConfig::default();
        assert!(config.registries.is_empty());
    }

    #[test]
    fn test_cargo_registry_config_from_json() {
        let json = json!({
            "registries": {
                "cargo": {
                    "registries": {
                        "kellnr": {
                            "index_url": "https://kellnr.example.com/api/v1/crates"
                        },
                        "private": {
                            "index_url": "https://private.registry.com/index",
                            "auth": {
                                "type": "env",
                                "variable": "PRIVATE_REGISTRY_TOKEN"
                            }
                        }
                    }
                }
            }
        });

        let config = Config::from_init_options(Some(json));
        assert_eq!(config.registries.cargo.registries.len(), 2);

        let kellnr = config.registries.cargo.registries.get("kellnr").unwrap();
        assert_eq!(kellnr.index_url, "https://kellnr.example.com/api/v1/crates");
        assert!(kellnr.auth.is_none());

        let private = config.registries.cargo.registries.get("private").unwrap();
        assert_eq!(private.index_url, "https://private.registry.com/index");
        assert!(private.auth.is_some());
        let auth = private.auth.as_ref().unwrap();
        assert_eq!(auth.auth_type, "env");
        assert_eq!(auth.variable, "PRIVATE_REGISTRY_TOKEN");
    }

    #[test]
    fn test_cargo_registry_config_empty() {
        let json = json!({});
        let config = Config::from_init_options(Some(json));
        assert!(config.registries.cargo.registries.is_empty());
    }

    #[test]
    fn test_auth_config_unsupported_type() {
        let json = json!({
            "registries": {
                "npm": {
                    "scoped": {
                        "company": {
                            "url": "https://npm.company.com",
                            "auth": {
                                "type": "unknown",
                                "variable": "SOME_VAR"
                            }
                        }
                    }
                }
            }
        });

        let config = Config::from_init_options(Some(json));
        let scoped = config.registries.npm.scoped.get("company").unwrap();
        let auth = scoped.auth.as_ref().unwrap();

        assert!(!auth.is_configured());
        assert!(auth.get_token().is_none());
    }

    #[test]
    fn test_maven_registry_config_default() {
        let config = Config::default();
        assert_eq!(
            config.registries.maven.url,
            "https://repo1.maven.org/maven2"
        );
    }

    #[test]
    fn test_maven_registry_config_custom_url() {
        let json = json!({
            "registries": {
                "maven": {
                    "url": "https://nexus.internal.corp/repository/maven-public"
                }
            }
        });
        let config = Config::from_init_options(Some(json));
        assert_eq!(
            config.registries.maven.url,
            "https://nexus.internal.corp/repository/maven-public"
        );
    }

    #[test]
    fn test_is_package_ignored_exact_match() {
        let patterns = vec!["lodash".to_string(), "react".to_string()];
        assert!(super::is_package_ignored("lodash", &patterns));
        assert!(super::is_package_ignored("react", &patterns));
        assert!(!super::is_package_ignored("vue", &patterns));
    }

    #[test]
    fn test_is_package_ignored_prefix_wildcard() {
        let patterns = vec!["@company/*".to_string()];
        assert!(super::is_package_ignored("@company/utils", &patterns));
        assert!(super::is_package_ignored("@company/", &patterns));
        assert!(!super::is_package_ignored("@other/utils", &patterns));
    }

    #[test]
    fn test_is_package_ignored_suffix_wildcard() {
        let patterns = vec!["*-test".to_string()];
        assert!(super::is_package_ignored("foo-test", &patterns));
        assert!(super::is_package_ignored("-test", &patterns));
        assert!(!super::is_package_ignored("foo-prod", &patterns));
    }

    #[test]
    fn test_is_package_ignored_both_wildcards() {
        let patterns = vec!["internal-*-lib".to_string()];
        assert!(super::is_package_ignored("internal-foo-lib", &patterns));
        assert!(super::is_package_ignored("internal--lib", &patterns));
        assert!(!super::is_package_ignored("external-foo-lib", &patterns));
    }

    #[test]
    fn test_is_package_ignored_empty_patterns() {
        let patterns: Vec<String> = vec![];
        assert!(!super::is_package_ignored("lodash", &patterns));
    }

    #[test]
    fn test_is_package_ignored_multiple_wildcards_falls_back_to_prefix() {
        let patterns = vec!["a-*-b-*-c".to_string()];
        assert!(super::is_package_ignored("a-anything", &patterns));
        assert!(!super::is_package_ignored("b-anything", &patterns));
    }

    #[test]
    fn test_is_package_ignored_bare_wildcard_matches_all() {
        // Documented sharp edge: bare "*" matches every name.
        let patterns = vec!["*".to_string()];
        assert!(super::is_package_ignored("anything", &patterns));
        assert!(super::is_package_ignored("", &patterns));
    }

    #[test]
    fn test_is_package_ignored_prefix_suffix_overlap_with_empty_middle() {
        // Pattern "prefix*suffix" matches when prefix and suffix overlap to zero middle chars.
        let patterns = vec!["internal-*-lib".to_string()];
        assert!(super::is_package_ignored("internal--lib", &patterns));
    }

    #[test]
    fn test_is_package_ignored_empty_pattern_string_matches_only_empty_name() {
        // An empty-string pattern is an exact-match for the empty name.
        let patterns = vec!["".to_string()];
        assert!(super::is_package_ignored("", &patterns));
        assert!(!super::is_package_ignored("anything", &patterns));
    }
}

#[cfg(test)]
mod advisory_config_tests {
    use super::AdvisoryCacheConfig;

    #[test]
    fn defaults_match_design_spec() {
        let cfg = AdvisoryCacheConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.ttl_secs, 86_400);
        assert_eq!(cfg.negative_ttl_secs, 3_600);
        assert!(cfg.db_path.is_none());
    }

    #[test]
    fn deserialise_partial_json_uses_defaults_for_missing_fields() {
        let cfg: AdvisoryCacheConfig =
            serde_json::from_str(r#"{"enabled":false}"#).expect("partial deserialise");
        assert!(!cfg.enabled);
        assert_eq!(cfg.ttl_secs, 86_400);
        assert_eq!(cfg.negative_ttl_secs, 3_600);
    }
}
