//! # npm Registry Client
//!
//! This module implements a client for the [npm](https://www.npmjs.com) registry,
//! the default package registry for Node.js and JavaScript packages.
//!
//! ## API Details
//!
//! - **Base URL**: `https://registry.npmjs.org`
//! - **API Version**: Registry API (stable)
//! - **Authentication**: Bearer token from `.npmrc` (optional)
//! - **CORS**: Enabled for browser-based access
//!
//! ## Rate Limiting
//!
//! npm does **not** enforce hard rate limits on read operations, but implements:
//!
//! - **IP-based blocking**: For abusive behavior patterns
//! - **Cloudflare protection**: May trigger CAPTCHA for suspicious traffic
//! - **Best practice**: Keep requests under 100/minute for bulk operations
//!
//! ## API Endpoints Used
//!
//! ### Fetch Package Info
//!
//! - **Endpoint**: `GET /{package-name}`
//! - **Scoped packages**: `GET /@scope%2fpackage-name` (URL encoded `/`)
//! - **Response**: JSON with full package metadata
//! - **Fields**:
//!   - `dist-tags.latest`: Current stable version
//!   - `dist-tags.next`: Latest prerelease (if exists)
//!   - `versions{}`: Map of version string to version metadata
//!   - `time{}`: Map of version string to publish timestamp
//!
//! ## Response Parsing
//!
//! - **Version format**: Semver with optional prerelease (`-alpha`, `-beta`, `-canary`)
//! - **Date format**: RFC 3339 (`2024-01-15T10:30:00.000Z`)
//! - **Deprecated packages**: `deprecated` field in version metadata (string message)
//! - **License**: Can be string or object with `type` field
//! - **Repository**: Can be string or object with `url` field
//!
//! ## Edge Cases and Quirks
//!
//! - **Scoped packages**: Must URL-encode the slash (`@scope/pkg` → `@scope%2fpkg`)
//! - **Repository URL formats**: May include `git+https://`, `git://`, or `.git` suffix
//! - **Large packages**: May have thousands of versions (e.g., lodash)
//! - **Unpublished packages**: Return 404 but may have been available previously
//! - **Private packages**: Require authentication; return 401/403 without token
//! - **Engines field**: Contains Node.js version constraints (not exposed by this client)
//!
//! ## Error Handling
//!
//! - **Network errors**: Returned as `anyhow::Error`
//! - **API errors**: 404 for not found, 401/403 for auth issues
//! - **Timeouts**: 10 second default timeout
//!
//! ## External References
//!
//! - [npm Registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md)
//! - [Package Metadata Specification](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
//! - [npm CLI Documentation](https://docs.npmjs.com/cli)

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::Deserialize;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use super::http_client::create_shared_client;
use super::version_utils::is_prerelease_npm;
use super::{Registry, VersionInfo};
use crate::auth::fmt_redact_token;
use crate::config::NpmRegistryConfig;
use crate::registries::url_sanitizer::{sanitize_external_url, sanitize_repo_url};

/// Client for the npm registry
pub struct NpmRegistry {
    client: Arc<Client>,
    base_url: String,
    /// Scope to URL mapping for scoped packages (e.g., `"company"` -> <https://npm.company.com>)
    scoped_registries: HashMap<String, String>,
    /// Authentication headers per registry URL (URL prefix -> headers)
    auth_headers: HashMap<String, HeaderMap>,
}

impl NpmRegistry {
    /// Constructs an NpmRegistry with custom configuration for registry URL and scoped packages.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use depsy_lsp::registries::npm::NpmRegistry;
    /// use depsy_lsp::config::NpmRegistryConfig;
    ///
    /// let client = Arc::new(reqwest::Client::new());
    /// let config = NpmRegistryConfig::default();
    /// let registry = NpmRegistry::with_client_and_config(client, &config);
    /// ```
    pub fn with_client_and_config(client: Arc<Client>, config: &NpmRegistryConfig) -> Self {
        let base_url = if config.url.is_empty() {
            "https://registry.npmjs.org".to_string()
        } else {
            config.url.clone()
        };

        let mut scoped_registries: HashMap<String, String> = HashMap::new();
        let mut auth_headers: HashMap<String, HeaderMap> = HashMap::new();

        for (scope, cfg) in &config.scoped {
            if cfg.url.is_empty() {
                continue;
            }

            // Normalize scope name: remove leading '@' and trim whitespace
            let normalized_scope = scope.trim().strip_prefix('@').unwrap_or(scope.trim());
            scoped_registries.insert(normalized_scope.to_string(), cfg.url.clone());

            // Set up authentication if configured
            if let Some(auth) = &cfg.auth {
                // Security: Only attach auth tokens to HTTPS URLs to prevent credential leakage
                if !cfg.url.starts_with("https://") {
                    if auth.is_configured() {
                        tracing::error!(
                            "SECURITY: Refusing to attach auth token for npm scope @{} - \
                             registry URL '{}' is not HTTPS. Tokens must only be sent over secure connections.",
                            normalized_scope,
                            cfg.url
                        );
                    }
                    continue;
                }

                if let Some(token) = auth.get_token() {
                    let mut headers = HeaderMap::new();
                    let auth_value = format!("Bearer {token}");
                    if let Ok(value) = HeaderValue::from_str(&auth_value) {
                        headers.insert(AUTHORIZATION, value);
                        auth_headers.insert(cfg.url.clone(), headers);
                        tracing::info!(
                            "Configured auth for npm scope @{normalized_scope} -> {} (token: {})",
                            cfg.url,
                            fmt_redact_token(&token)
                        );
                    }
                } else if auth.is_configured() {
                    tracing::warn!(
                        "Auth configured for npm scope @{normalized_scope} but token not found in env var {}",
                        auth.variable
                    );
                }
            }
        }

        Self {
            client,
            base_url,
            scoped_registries,
            auth_headers,
        }
    }

    /// Get the registry URL for a package, considering scoped package routing.
    ///
    /// For scoped packages (@scope/package), checks if a custom registry is configured
    /// for that scope. Falls back to the default base URL.
    fn get_registry_url(&self, package_name: &str) -> &str {
        if let Some(scope) = package_name.strip_prefix('@')
            && let Some(scope_end) = scope.find('/')
        {
            let scope_name = &scope[..scope_end];
            if let Some(url) = self.scoped_registries.get(scope_name) {
                return url;
            }
        }
        &self.base_url
    }

    /// Get authentication headers for a registry URL.
    fn get_auth_headers(&self, registry_url: &str) -> Option<&HeaderMap> {
        self.auth_headers.get(registry_url)
    }
}

impl Default for NpmRegistry {
    /// Creates a default NpmRegistry configured with a shared HTTP client and the standard npm registry base URL.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use depsy_lsp::registries::npm::NpmRegistry;
    ///
    /// let registry = NpmRegistry::default();
    /// ```
    fn default() -> Self {
        Self {
            client: create_shared_client().expect("Failed to create HTTP client"),
            base_url: "https://registry.npmjs.org".to_string(),
            scoped_registries: HashMap::new(),
            auth_headers: HashMap::new(),
        }
    }
}

// API response structures
#[derive(Debug, Deserialize)]
struct PackageResponse {
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<Repository>,
    license: Option<LicenseField>,
    #[serde(rename = "dist-tags")]
    dist_tags: Option<DistTags>,
    versions: Option<HashMap<String, VersionMetadata>>,
    time: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Repository {
    String(String),
    Object { url: Option<String> },
}

impl Repository {
    fn url(&self) -> Option<String> {
        match self {
            Repository::String(s) => sanitize_repo_url(s),
            Repository::Object { url } => url.as_ref().and_then(|u| sanitize_repo_url(u)),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LicenseField {
    String(String),
    Object { r#type: Option<String> },
}

impl LicenseField {
    fn as_string(&self) -> Option<String> {
        match self {
            LicenseField::String(s) => Some(s.clone()),
            LicenseField::Object { r#type } => r#type.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DistTags {
    latest: Option<String>,
    next: Option<String>,
}

/// The `deprecated` field on an npm version can be either a deprecation message (string)
/// or a boolean (some packages publish `"deprecated": false`, e.g. react 16.7.0).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DeprecatedField {
    Message(String),
    Flag(bool),
}

impl DeprecatedField {
    fn is_deprecated(&self) -> bool {
        match self {
            DeprecatedField::Message(s) => !s.is_empty(),
            DeprecatedField::Flag(b) => *b,
        }
    }
}

#[derive(Debug, Deserialize)]
struct VersionMetadata {
    deprecated: Option<DeprecatedField>,
}

impl Registry for NpmRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        // Handle scoped packages (@scope/name -> @scope%2fname)
        let encoded_name = if package_name.starts_with('@') {
            package_name.replace('/', "%2f")
        } else {
            package_name.to_string()
        };

        // Get the appropriate registry URL (may differ for scoped packages)
        let registry_url = self.get_registry_url(package_name);
        let url = format!("{registry_url}/{encoded_name}");

        // Build request with optional authentication
        let mut request = self.client.get(&url);
        if let Some(headers) = self.get_auth_headers(registry_url) {
            for (key, value) in headers.iter() {
                request = request.header(key, value);
            }
        }

        let response = request.send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch package info for {package_name}: {}",
            response.status()
        );

        let pkg: PackageResponse = response.json().await?;

        // Get latest version from dist-tags
        let latest = pkg.dist_tags.as_ref().and_then(|t| t.latest.clone());

        // Get all versions
        let versions: Vec<String> = pkg
            .versions
            .as_ref()
            .map(|v| {
                let mut versions: Vec<String> = v.keys().cloned().collect();
                // Sort versions in descending order (newest first)
                versions.sort_by(|a, b| {
                    match (semver::Version::parse(a), semver::Version::parse(b)) {
                        (Ok(va), Ok(vb)) => vb.cmp(&va),
                        _ => b.cmp(a),
                    }
                });
                versions
            })
            .unwrap_or_default();

        // Find latest prerelease
        let latest_prerelease = pkg
            .dist_tags
            .as_ref()
            .and_then(|t| t.next.clone())
            .or_else(|| versions.iter().find(|v| is_prerelease_npm(v)).cloned());

        // Check if latest version is deprecated
        let deprecated = pkg
            .versions
            .as_ref()
            .and_then(|v| latest.as_ref().and_then(|l| v.get(l)))
            .is_some_and(|m| m.deprecated.as_ref().is_some_and(|d| d.is_deprecated()));

        // Get repository URL
        let repository = pkg.repository.as_ref().and_then(|r| r.url());

        // Parse release dates from the time field (excluding "created" and "modified" keys)
        let release_dates: HashMap<String, DateTime<Utc>> = pkg
            .time
            .as_ref()
            .map(|time_map| {
                time_map
                    .iter()
                    .filter(|(k, _)| *k != "created" && *k != "modified")
                    .filter_map(|(version, date_str)| {
                        DateTime::parse_from_rfc3339(date_str)
                            .ok()
                            .map(|dt| (version.clone(), dt.with_timezone(&Utc)))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(VersionInfo {
            latest,
            latest_prerelease,
            versions,
            description: pkg.description,
            homepage: pkg.homepage.as_deref().and_then(sanitize_external_url),
            repository,
            license: pkg.license.and_then(|l| l.as_string()),
            vulnerabilities: vec![], // Filled by the shared OSV vulnerability scan.
            deprecated,
            yanked: false,
            yanked_versions: vec![], // Not applicable to npm
            release_dates,
            transitive_vulnerabilities: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_prerelease() {
        assert!(is_prerelease_npm("1.0.0-alpha"));
        assert!(is_prerelease_npm("1.0.0-beta.1"));
        assert!(is_prerelease_npm("1.0.0-rc.1"));
        assert!(is_prerelease_npm("18.3.0-canary"));
        assert!(!is_prerelease_npm("1.0.0"));
        assert!(!is_prerelease_npm("2.3.4"));
    }

    #[test]
    fn test_repository_string_sanitization() {
        let repo = Repository::String("git+https://github.com/user/repo.git".to_string());
        assert_eq!(repo.url(), Some("https://github.com/user/repo".to_string()));
    }

    #[test]
    fn test_repository_string_legacy_git_protocol() {
        let repo = Repository::String("git://github.com/user/repo".to_string());
        assert_eq!(repo.url(), Some("https://github.com/user/repo".to_string()));
    }

    #[test]
    fn test_repository_string_passthrough_https() {
        let repo = Repository::String("https://github.com/user/repo".to_string());
        assert_eq!(repo.url(), Some("https://github.com/user/repo".to_string()));
    }

    #[test]
    fn test_repository_object_drops_invalid_scheme() {
        let repo = Repository::Object {
            url: Some("ssh://git@github.com/user/repo".to_string()),
        };
        assert_eq!(repo.url(), None);
    }

    #[test]
    fn test_repository_object_none() {
        let repo = Repository::Object { url: None };
        assert_eq!(repo.url(), None);
    }

    #[test]
    fn test_license_field_string() {
        let license = LicenseField::String("MIT".to_string());
        assert_eq!(license.as_string(), Some("MIT".to_string()));
    }

    #[test]
    fn test_license_field_object() {
        let license = LicenseField::Object {
            r#type: Some("Apache-2.0".to_string()),
        };
        assert_eq!(license.as_string(), Some("Apache-2.0".to_string()));
    }

    #[test]
    fn test_license_field_object_none() {
        let license = LicenseField::Object { r#type: None };
        assert_eq!(license.as_string(), None);
    }

    #[test]
    fn test_scoped_package_url_encoding() {
        let package_name = "@types/node";
        let encoded = if package_name.starts_with('@') {
            package_name.replace('/', "%2f")
        } else {
            package_name.to_string()
        };
        assert_eq!(encoded, "@types%2fnode");
    }

    #[test]
    fn test_normal_package_no_encoding() {
        let package_name = "lodash";
        let encoded = if package_name.starts_with('@') {
            package_name.replace('/', "%2f")
        } else {
            package_name.to_string()
        };
        assert_eq!(encoded, "lodash");
    }

    #[test]
    fn test_deprecated_field_string_message() {
        let json = r#"{"deprecated": "use foo instead"}"#;
        let v: VersionMetadata = serde_json::from_str(json).unwrap();
        assert!(v.deprecated.as_ref().unwrap().is_deprecated());
    }

    #[test]
    fn test_deprecated_field_bool_false() {
        // Regression: react publishes `"deprecated": false` on some versions.
        // Previously broke deserialization of the entire package response.
        let json = r#"{"deprecated": false}"#;
        let v: VersionMetadata = serde_json::from_str(json).unwrap();
        assert!(!v.deprecated.as_ref().unwrap().is_deprecated());
    }

    #[test]
    fn test_deprecated_field_bool_true() {
        let json = r#"{"deprecated": true}"#;
        let v: VersionMetadata = serde_json::from_str(json).unwrap();
        assert!(v.deprecated.as_ref().unwrap().is_deprecated());
    }

    #[test]
    fn test_deprecated_field_absent() {
        let json = r#"{}"#;
        let v: VersionMetadata = serde_json::from_str(json).unwrap();
        assert!(v.deprecated.is_none());
    }

    #[test]
    fn test_deprecated_field_empty_string_not_deprecated() {
        let json = r#"{"deprecated": ""}"#;
        let v: VersionMetadata = serde_json::from_str(json).unwrap();
        assert!(!v.deprecated.as_ref().unwrap().is_deprecated());
    }

    #[test]
    fn test_package_response_with_mixed_deprecated_types() {
        // Regression: full PackageResponse must deserialize when versions mix
        // string and bool `deprecated` values (real-world react payload shape).
        let json = r#"{
            "dist-tags": {"latest": "19.2.5"},
            "versions": {
                "16.7.0": {"deprecated": false},
                "0.7.1": {"deprecated": "renamed to autoflow"},
                "19.2.5": {}
            }
        }"#;
        let pkg: PackageResponse = serde_json::from_str(json).unwrap();
        let versions = pkg.versions.unwrap();
        assert_eq!(versions.len(), 3);
        assert!(
            !versions
                .get("16.7.0")
                .unwrap()
                .deprecated
                .as_ref()
                .unwrap()
                .is_deprecated()
        );
        assert!(
            versions
                .get("0.7.1")
                .unwrap()
                .deprecated
                .as_ref()
                .unwrap()
                .is_deprecated()
        );
        assert!(versions.get("19.2.5").unwrap().deprecated.is_none());
    }

    #[test]
    fn test_with_client_and_config_default() {
        use crate::config::NpmRegistryConfig;
        use crate::registries::http_client::create_shared_client;

        let client = create_shared_client().unwrap();
        let config = NpmRegistryConfig::default();
        let registry = NpmRegistry::with_client_and_config(client, &config);

        assert_eq!(registry.base_url, "https://registry.npmjs.org");
        assert!(registry.scoped_registries.is_empty());
    }

    #[test]
    fn test_with_client_and_config_custom_url() {
        use crate::config::NpmRegistryConfig;
        use crate::registries::http_client::create_shared_client;

        let client = create_shared_client().unwrap();
        let config = NpmRegistryConfig {
            url: "https://npm.company.com".to_string(),
            scoped: HashMap::new(),
        };
        let registry = NpmRegistry::with_client_and_config(client, &config);

        assert_eq!(registry.base_url, "https://npm.company.com");
    }

    #[test]
    fn test_with_client_and_config_scoped() {
        use crate::config::{NpmRegistryConfig, NpmScopedConfig};
        use crate::registries::http_client::create_shared_client;

        let client = create_shared_client().unwrap();
        let mut scoped = HashMap::new();
        scoped.insert(
            "company".to_string(),
            NpmScopedConfig {
                url: "https://npm.internal.company.com".to_string(),
                auth: None,
            },
        );
        scoped.insert(
            "github".to_string(),
            NpmScopedConfig {
                url: "https://npm.pkg.github.com".to_string(),
                auth: None,
            },
        );
        let config = NpmRegistryConfig {
            url: "https://registry.npmjs.org".to_string(),
            scoped,
        };
        let registry = NpmRegistry::with_client_and_config(client, &config);

        assert_eq!(registry.base_url, "https://registry.npmjs.org");
        assert_eq!(registry.scoped_registries.len(), 2);
        assert_eq!(
            registry.scoped_registries.get("company"),
            Some(&"https://npm.internal.company.com".to_string())
        );
        assert_eq!(
            registry.scoped_registries.get("github"),
            Some(&"https://npm.pkg.github.com".to_string())
        );

        // End-to-end: verify routing works for scoped packages
        assert_eq!(
            registry.get_registry_url("@company/utils"),
            "https://npm.internal.company.com"
        );
        assert_eq!(
            registry.get_registry_url("@github/actions"),
            "https://npm.pkg.github.com"
        );
    }

    #[test]
    fn test_get_registry_url_default() {
        use crate::config::NpmRegistryConfig;
        use crate::registries::http_client::create_shared_client;

        let client = create_shared_client().unwrap();
        let config = NpmRegistryConfig::default();
        let registry = NpmRegistry::with_client_and_config(client, &config);

        // Non-scoped package should use default
        assert_eq!(
            registry.get_registry_url("express"),
            "https://registry.npmjs.org"
        );

        // Scoped package without specific config should use default
        assert_eq!(
            registry.get_registry_url("@types/node"),
            "https://registry.npmjs.org"
        );
    }

    #[test]
    fn test_get_registry_url_scoped() {
        use crate::config::{NpmRegistryConfig, NpmScopedConfig};
        use crate::registries::http_client::create_shared_client;

        let client = create_shared_client().unwrap();
        let mut scoped = HashMap::new();
        scoped.insert(
            "company".to_string(),
            NpmScopedConfig {
                url: "https://npm.company.com".to_string(),
                auth: None,
            },
        );
        let config = NpmRegistryConfig {
            url: "https://registry.npmjs.org".to_string(),
            scoped,
        };
        let registry = NpmRegistry::with_client_and_config(client, &config);

        // Scoped package with matching config should use scoped URL
        assert_eq!(
            registry.get_registry_url("@company/utils"),
            "https://npm.company.com"
        );

        // Non-scoped package should use default
        assert_eq!(
            registry.get_registry_url("express"),
            "https://registry.npmjs.org"
        );

        // Scoped package without specific config should use default
        assert_eq!(
            registry.get_registry_url("@types/node"),
            "https://registry.npmjs.org"
        );
    }

    #[test]
    fn test_auth_not_attached_for_http_urls() {
        use crate::config::{AuthConfig, NpmRegistryConfig, NpmScopedConfig};
        use crate::registries::http_client::create_shared_client;

        let client = create_shared_client().unwrap();
        let mut scoped = HashMap::new();

        // Configure a scope with HTTP (insecure) URL and auth
        scoped.insert(
            "insecure".to_string(),
            NpmScopedConfig {
                url: "http://insecure.registry.com".to_string(), // HTTP, not HTTPS
                auth: Some(AuthConfig {
                    auth_type: "env".to_string(),
                    variable: "SOME_TOKEN".to_string(),
                }),
            },
        );

        // Configure a scope with HTTPS (secure) URL - no auth for this test
        scoped.insert(
            "secure".to_string(),
            NpmScopedConfig {
                url: "https://secure.registry.com".to_string(),
                auth: None,
            },
        );

        let config = NpmRegistryConfig {
            url: "https://registry.npmjs.org".to_string(),
            scoped,
        };
        let registry = NpmRegistry::with_client_and_config(client, &config);

        // Scoped registries should still be populated
        assert_eq!(registry.scoped_registries.len(), 2);
        assert_eq!(
            registry.scoped_registries.get("insecure"),
            Some(&"http://insecure.registry.com".to_string())
        );

        // But auth headers should NOT be attached for the HTTP URL
        assert!(
            !registry
                .auth_headers
                .contains_key("http://insecure.registry.com"),
            "Auth headers should not be attached to HTTP URLs"
        );
    }
}
