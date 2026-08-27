//! # pub.dev Registry Client
//!
//! This module implements a client for [pub.dev](https://pub.dev),
//! the official package repository for Dart and Flutter packages.
//!
//! ## API Details
//!
//! - **Base URL**: `https://pub.dev/api`
//! - **API Version**: REST API (stable)
//! - **Authentication**: OAuth2 for private packages (not implemented)
//! - **CORS**: Enabled for browser-based access
//!
//! ## Rate Limiting
//!
//! pub.dev enforces rate limits:
//!
//! - **Standard limit**: ~100 requests per minute per IP
//! - **CDN caching**: Responses cached at edge
//! - **Best practice**: Respect `Cache-Control` headers
//!
//! ## API Endpoints Used
//!
//! ### Fetch Package Info
//!
//! - **Endpoint**: `GET /api/packages/{package-name}`
//! - **Response**: JSON with package metadata and all versions
//! - **Fields**:
//!   - `name`: Package name
//!   - `latest`: Latest version info with pubspec
//!   - `versions[]`: Array of all versions
//!   - `versions[].version`: Version string
//!   - `versions[].pubspec`: Parsed pubspec.yaml contents
//!   - `versions[].retracted`: Whether version is retracted
//!   - `versions[].published`: RFC 3339 publish timestamp
//!
//! ## Response Parsing
//!
//! - **Version format**: Semver (`1.0.0`, `2.0.0-dev.1`)
//! - **Date format**: RFC 3339 (`2024-01-15T10:30:00.000Z`)
//! - **Retracted versions**: `retracted: true` (equivalent to yanked)
//! - **Discontinued packages**: `discontinued: true` in pubspec
//!
//! ## Edge Cases and Quirks
//!
//! - **SDK constraints**: `environment.sdk` in pubspec specifies Dart version
//! - **Flutter constraints**: `environment.flutter` for Flutter SDK version
//! - **Retracted versions**: Similar to yanked; still downloadable with warning
//! - **Discontinued packages**: Marked in pubspec, may suggest replacement
//! - **Null safety**: Packages may indicate null-safety migration status
//! - **Platform support**: Flutter packages may specify platform compatibility
//!
//! ## Error Handling
//!
//! - **Network errors**: Returned as `anyhow::Error`
//! - **API errors**: 404 for not found
//! - **Timeouts**: 10 second default timeout
//!
//! ## External References
//!
//! - [pub.dev API](https://pub.dev/help/api)
//! - [Pubspec Format](https://dart.dev/tools/pub/pubspec)
//! - [Version Constraints](https://dart.dev/tools/pub/dependencies#version-constraints)
//! - [Package Scoring](https://pub.dev/help/scoring)

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::Deserialize;

use super::http_client::create_shared_client;
use super::version_utils::is_prerelease_dart;
use super::{Registry, VersionInfo};

/// Client for the pub.dev registry
pub struct PubDevRegistry {
    client: Arc<Client>,
    base_url: String,
}

impl PubDevRegistry {
    /// Creates a `PubDevRegistry` configured to use the given shared HTTP client.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use depsy_lsp::registries::pub_dev::PubDevRegistry;
    ///
    /// let client = Arc::new(reqwest::Client::new());
    /// let _registry = PubDevRegistry::with_client(client);
    /// ```
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            base_url: "https://pub.dev/api".to_string(),
        }
    }
}

impl Default for PubDevRegistry {
    /// Constructs a PubDevRegistry using a shared HTTP client created by `create_shared_client`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use depsy_lsp::registries::pub_dev::PubDevRegistry;
    ///
    /// let registry = PubDevRegistry::default();
    /// ```
    fn default() -> Self {
        Self::with_client(create_shared_client().expect("Failed to create HTTP client"))
    }
}

// pub.dev API response structures
#[derive(Debug, Deserialize)]
struct PubPackageResponse {
    #[serde(rename = "name")]
    _name: String,
    latest: PubVersionInfo,
    versions: Vec<PubVersionInfo>,
}

#[derive(Debug, Deserialize)]
struct PubVersionInfo {
    version: String,
    pubspec: PubPubspec,
    #[serde(default)]
    retracted: bool,
    published: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PubPubspec {
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    #[serde(default)]
    discontinued: bool,
}

impl Registry for PubDevRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    /// Retrieve version metadata for a package from the pub.dev API.
    ///
    /// The returned `VersionInfo` contains the package's available versions (excluding retracted
    /// releases), the latest stable version (falling back to the package's reported latest if none
    /// can be determined), the latest prerelease if any, release dates parsed from RFC 3339 timestamps,
    /// and metadata from the package's latest pubspec (description, homepage, repository, deprecated/yanked flags).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #[tokio::main]
    /// async fn main() {
    ///     let registry = PubDevRegistry::default();
    ///     let info = registry.get_version_info("http").await.unwrap();
    ///     // versions should contain at least one entry for a published package
    ///     assert!(!info.versions.is_empty());
    /// }
    /// ```
    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        let url = format!("{}/packages/{package_name}", self.base_url);

        let response = self.client.get(&url).send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch package info for {package_name}: {}",
            response.status(),
        );

        let pkg: PubPackageResponse = response.json().await?;

        // Get all versions (not retracted)
        let versions: Vec<String> = pkg
            .versions
            .iter()
            .filter(|v| !v.retracted)
            .map(|v| v.version.clone())
            .collect();

        // Find latest stable version (versions are in ascending order, so iterate from end)
        let latest_stable = versions
            .iter()
            .rev()
            .find(|v| !is_prerelease_dart(v))
            .cloned()
            .or_else(|| Some(pkg.latest.version.clone()));

        // Find latest prerelease (iterate from end to get newest)
        let latest_prerelease = versions
            .iter()
            .rev()
            .find(|v| is_prerelease_dart(v))
            .cloned();

        // Collect release dates
        let release_dates: HashMap<String, DateTime<Utc>> = pkg
            .versions
            .iter()
            .filter_map(|v| {
                v.published.as_ref().and_then(|time_str| {
                    DateTime::parse_from_rfc3339(time_str)
                        .ok()
                        .map(|dt| (v.version.clone(), dt.with_timezone(&Utc)))
                })
            })
            .collect();

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease,
            versions,
            description: pkg.latest.pubspec.description,
            homepage: pkg.latest.pubspec.homepage,
            repository: pkg.latest.pubspec.repository,
            license: None,           // pub.dev doesn't expose license in API
            vulnerabilities: vec![], // Will be filled by OSV
            deprecated: pkg.latest.pubspec.discontinued,
            yanked: pkg.latest.retracted,
            yanked_versions: vec![], // Not applicable to pub.dev
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
        assert!(is_prerelease_dart("1.0.0-dev.1"));
        assert!(is_prerelease_dart("1.0.0-alpha"));
        assert!(is_prerelease_dart("1.0.0-beta.1"));
        assert!(is_prerelease_dart("1.0.0-rc.1"));
        assert!(!is_prerelease_dart("1.0.0"));
        assert!(!is_prerelease_dart("2.0.0"));
    }

    #[test]
    fn test_latest_version_from_ascending_list() {
        let versions = [
            "0.5.0",
            "0.5.1",
            "1.0.0",
            "2.0.0-dev.1",
            "2.0.0",
            "3.0.0-beta.1",
            "3.0.0",
        ];

        let latest_stable = versions
            .iter()
            .rev()
            .find(|v| !is_prerelease_dart(v))
            .map(|v| v.to_string());

        let latest_prerelease = versions
            .iter()
            .rev()
            .find(|v| is_prerelease_dart(v))
            .map(|v| v.to_string());

        assert_eq!(latest_stable, Some("3.0.0".to_string()));
        assert_eq!(latest_prerelease, Some("3.0.0-beta.1".to_string()));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_flutter_riverpod_latest_version() {
        let registry = PubDevRegistry::default();
        let info = registry.get_version_info("flutter_riverpod").await.unwrap();

        // Latest stable should be 2.x or 3.x, definitely not 0.5.x
        let latest = info.latest.expect("Should have a latest version");
        assert!(
            latest.starts_with("2.") || latest.starts_with("3."),
            "Expected latest version to be 2.x or 3.x, got: {latest}"
        );
    }
}
