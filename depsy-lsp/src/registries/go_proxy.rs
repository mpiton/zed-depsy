//! # Go Module Proxy Client
//!
//! This module implements a client for the [Go Module Proxy](https://proxy.golang.org),
//! the official module mirror and checksum database for Go modules.
//!
//! ## API Details
//!
//! - **Base URL**: `https://proxy.golang.org`
//! - **API Version**: Module Proxy Protocol (stable)
//! - **Authentication**: Not required for public modules
//! - **GOPROXY**: Supports custom proxy URLs via environment variable
//!
//! ## Rate Limiting
//!
//! The Go proxy does not publish official rate limits but implements:
//!
//! - **Fair use policy**: No hard limits for normal usage
//! - **CDN caching**: Most requests are served from cache
//! - **Best practice**: Respect cache headers
//!
//! ## API Endpoints Used
//!
//! ### List Versions
//!
//! - **Endpoint**: `GET /{module}/@v/list`
//! - **Response**: Plain text, one version per line
//! - **Example**: `v1.0.0\nv1.0.1\nv1.1.0`
//!
//! ### Get Latest Version
//!
//! - **Endpoint**: `GET /{module}/@latest`
//! - **Response**: JSON with version and timestamp
//! - **Fields**:
//!   - `Version`: Version string (e.g., `v1.2.3`)
//!   - `Time`: RFC 3339 timestamp
//!
//! ### Get Version Info
//!
//! - **Endpoint**: `GET /{module}/@v/{version}.info`
//! - **Response**: JSON with version metadata
//! - **Fields**:
//!   - `Version`: Canonical version string
//!   - `Time`: RFC 3339 release timestamp
//!
//! ## Response Parsing
//!
//! - **Version format**: Semver with `v` prefix required (`v1.0.0`, `v2.0.0-rc1`)
//! - **Date format**: RFC 3339 (`2024-01-15T10:30:00Z`)
//! - **Module paths**: May contain version suffix for v2+ (`/v2`, `/v3`)
//!
//! ## Edge Cases and Quirks
//!
//! - **Module path encoding**: Uppercase letters become `!` + lowercase
//!   (`github.com/Azure/sdk` → `github.com/!azure/sdk`)
//! - **Major version suffixes**: v2+ modules have path suffix (`module/v2`)
//! - **Pseudo-versions**: Auto-generated for commits without tags
//!   (`v0.0.0-20210101000000-abcdef123456`)
//! - **Private modules**: Not available on public proxy; require `GOPRIVATE`
//! - **Checksum database**: `sum.golang.org` verifies module integrity
//! - **Retracted versions**: Marked in `go.mod` but still listed
//!
//! ## Error Handling
//!
//! - **Network errors**: Returned as `anyhow::Error`
//! - **API errors**: 404 for not found, 410 for gone/retracted
//! - **Timeouts**: 10 second default timeout
//!
//! ## External References
//!
//! - [Go Module Proxy Protocol](https://go.dev/ref/mod#module-proxy)
//! - [Module Version Numbering](https://go.dev/ref/mod#versions)
//! - [Checksum Database](https://sum.golang.org/)
//! - [GOPROXY Environment Variable](https://go.dev/ref/mod#environment-variables)

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::Deserialize;

use super::http_client::create_shared_client;
use super::version_utils::is_prerelease_go;
use super::{Registry, VersionInfo};

/// Client for the Go module proxy
pub struct GoProxyRegistry {
    client: Arc<Client>,
    base_url: String,
}

impl GoProxyRegistry {
    /// Creates a GoProxyRegistry that uses the provided shared HTTP client and the default Go proxy base URL.
    ///
    /// `client` is the shared `reqwest::Client` used for all outgoing HTTP requests to the Go proxy.
    /// The returned registry is configured with `base_url` set to `https://proxy.golang.org`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use depsy_lsp::registries::go_proxy::GoProxyRegistry;
    ///
    /// let client = Arc::new(reqwest::Client::new());
    /// let _registry = GoProxyRegistry::with_client(client);
    /// ```
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            base_url: "https://proxy.golang.org".to_string(),
        }
    }
}

impl Default for GoProxyRegistry {
    /// Creates a GoProxyRegistry configured with a shared HTTP client.
    ///
    /// The registry's HTTP client is produced by `create_shared_client`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use depsy_lsp::registries::go_proxy::GoProxyRegistry;
    ///
    /// let registry = GoProxyRegistry::default();
    /// ```
    fn default() -> Self {
        Self::with_client(create_shared_client().expect("Failed to create HTTP client"))
    }
}

// Go proxy API response for version info
#[derive(Debug, Deserialize)]
struct VersionInfoResponse {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Time")]
    time: Option<String>,
}

impl Registry for GoProxyRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    async fn get_version_info(&self, module_path: &str) -> anyhow::Result<VersionInfo> {
        // Encode module path for URL
        // Go proxy requires case-encoding: uppercase letters become ! followed by lowercase
        let encoded_path = encode_module_path(module_path);

        // Fetch list of versions
        let versions = self.fetch_versions(&encoded_path).await.unwrap_or_default();

        // Fetch latest version info
        let latest = self.fetch_latest(&encoded_path).await.ok();

        // Sort versions in descending order
        let mut sorted_versions = versions.clone();
        sorted_versions.sort_by(|a, b| compare_go_versions(b, a));

        // Find latest stable version (no prerelease suffix)
        let latest_stable = latest.as_ref().map(|l| l.version.clone()).or_else(|| {
            sorted_versions
                .iter()
                .find(|v| !is_prerelease_go(v))
                .cloned()
        });

        // Find latest prerelease
        let latest_prerelease = sorted_versions
            .iter()
            .find(|v| is_prerelease_go(v))
            .cloned();

        // Build repository URL for common hosts
        let repository =
            if module_path.starts_with("github.com/") || module_path.starts_with("gitlab.com/") {
                Some(format!("https://{module_path}"))
            } else {
                None
            };

        // Fetch release dates for versions (fetch info for each version in parallel)
        let release_dates = self
            .fetch_version_times(&encoded_path, &sorted_versions)
            .await;

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease,
            versions: sorted_versions,
            description: None, // Go proxy doesn't provide descriptions
            homepage: None,
            repository,
            license: None,           // Would need to fetch go.mod or LICENSE file
            vulnerabilities: vec![], // TODO: Integrate vuln.go.dev
            deprecated: false,
            yanked: false,
            yanked_versions: vec![], // Not applicable to Go
            release_dates,
            transitive_vulnerabilities: vec![],
        })
    }
}

impl GoProxyRegistry {
    /// Fetch list of available versions
    async fn fetch_versions(&self, encoded_path: &str) -> anyhow::Result<Vec<String>> {
        let url = format!("{}/{encoded_path}/@v/list", self.base_url);

        let response = self.client.get(&url).send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch versions for {encoded_path}: {}",
            response.status(),
        );

        let text = response.text().await?;
        let versions: Vec<String> = text.lines().map(|s| s.trim().to_string()).collect();

        Ok(versions)
    }

    /// Fetch latest version info
    async fn fetch_latest(&self, encoded_path: &str) -> anyhow::Result<VersionInfoResponse> {
        let url = format!("{}/{encoded_path}/@latest", self.base_url);

        let response = self.client.get(&url).send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch latest for {encoded_path}: {}",
            response.status(),
        );

        let info: VersionInfoResponse = response.json().await?;
        Ok(info)
    }

    /// Fetch version info for a specific version
    async fn fetch_version_info(
        &self,
        encoded_path: &str,
        version: &str,
    ) -> Option<VersionInfoResponse> {
        let url = format!("{}/{encoded_path}/@v/{version}.info", self.base_url);

        let response = self.client.get(&url).send().await.ok()?;

        if !response.status().is_success() {
            return None;
        }

        response.json().await.ok()
    }

    /// Fetch release times for a list of versions (limited to first 10 for performance)
    async fn fetch_version_times(
        &self,
        encoded_path: &str,
        versions: &[String],
    ) -> HashMap<String, DateTime<Utc>> {
        use futures::future::join_all;

        let futures: Vec<_> = versions
            .iter()
            .take(10)
            .map(|v| async move {
                self.fetch_version_info(encoded_path, v)
                    .await
                    .and_then(|info| {
                        info.time.as_ref().and_then(|time_str| {
                            DateTime::parse_from_rfc3339(time_str)
                                .ok()
                                .map(|dt| (v.clone(), dt.with_timezone(&Utc)))
                        })
                    })
            })
            .collect();

        let results = join_all(futures).await;
        results.into_iter().flatten().collect()
    }
}

/// Encode module path for Go proxy URL
/// Uppercase letters are replaced with ! followed by lowercase
fn encode_module_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len() * 2);

    for ch in path.chars() {
        if ch.is_ascii_uppercase() {
            result.push('!');
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }

    result
}

/// Compare Go versions for sorting
fn compare_go_versions(a: &str, b: &str) -> std::cmp::Ordering {
    // Strip 'v' prefix if present
    let a_stripped = a.strip_prefix('v').unwrap_or(a);
    let b_stripped = b.strip_prefix('v').unwrap_or(b);

    // Try parsing as semver
    match (
        semver::Version::parse(a_stripped),
        semver::Version::parse(b_stripped),
    ) {
        (Ok(va), Ok(vb)) => va.cmp(&vb),
        _ => {
            // Fallback to string comparison
            compare_version_strings(a_stripped, b_stripped)
        }
    }
}

/// Simple version string comparison
fn compare_version_strings(a: &str, b: &str) -> std::cmp::Ordering {
    let parse_parts = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter_map(|p| p.parse().ok())
            .collect()
    };

    let parts_a = parse_parts(a);
    let parts_b = parse_parts(b);

    for (pa, pb) in parts_a.iter().zip(parts_b.iter()) {
        match pa.cmp(pb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    parts_a.len().cmp(&parts_b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_module_path() {
        assert_eq!(
            encode_module_path("github.com/Azure/azure-sdk-for-go"),
            "github.com/!azure/azure-sdk-for-go"
        );
        assert_eq!(
            encode_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
        assert_eq!(encode_module_path("golang.org/x/text"), "golang.org/x/text");
    }

    #[test]
    fn test_is_prerelease() {
        assert!(is_prerelease_go("v1.0.0-rc1"));
        assert!(is_prerelease_go("v2.0.0-beta.1"));
        assert!(is_prerelease_go("v3.0.0-alpha"));
        assert!(!is_prerelease_go("v1.0.0"));
        assert!(!is_prerelease_go("v2.3.4"));
    }

    #[test]
    fn test_compare_go_versions() {
        use std::cmp::Ordering;

        assert_eq!(compare_go_versions("v1.0.0", "v2.0.0"), Ordering::Less);
        assert_eq!(compare_go_versions("v2.0.0", "v1.0.0"), Ordering::Greater);
        assert_eq!(compare_go_versions("v1.0.0", "v1.0.0"), Ordering::Equal);
        assert_eq!(compare_go_versions("v1.10.0", "v1.9.0"), Ordering::Greater);
    }
}
