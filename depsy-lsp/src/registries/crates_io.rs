//! # crates.io Registry Client
//!
//! This module implements a client for the [crates.io](https://crates.io) registry,
//! the official Rust package registry managed by the Rust Foundation.
//!
//! ## API Details
//!
//! - **Base URL**: `https://crates.io/api/v1`
//! - **API Version**: v1 (stable)
//!
//! ## Rate Limiting
//!
//! The crates.io API enforces **strict rate limits** to protect the service.
//! This client implements a built-in rate limiter that enforces **1 request per second**.
//!
//! **Exceeding the rate limit may result in IP-based blocking.**
//!
//! ## API Endpoints Used
//!
//! ### Fetch Crate Info
//!
//! - **Endpoint**: `GET /api/v1/crates/{crate_name}`
//! - **Response**: JSON containing crate metadata and all versions
//! - **Fields**:
//!   - `crate.max_stable_version`: Latest stable release
//!   - `crate.description`: Package description
//!   - `crate.homepage`: Optional homepage URL
//!   - `crate.repository`: Optional repository URL
//!   - `versions[]`: Array of all published versions
//!
//! ## Response Parsing
//!
//! - **Version format**: Semver with optional pre-release tags (`-alpha`, `-beta`, `-rc`)
//! - **Date format**: RFC 3339 (`2024-01-15T10:30:00Z`)
//! - **Yanked versions**: Marked with `yanked: true` in versions array
//! - **License**: Per-version field (SPDX expression)
//!
//! ## Edge Cases and Quirks
//!
//! - **Name normalization**: Underscores and hyphens are equivalent (`foo-bar` = `foo_bar`)
//! - **Case sensitivity**: Names are case-insensitive but stored lowercase
//! - **404 responses**: Returned for both "not found" and "private crates"
//! - **Yanked versions**: Still available but marked; users are warned
//! - **Features**: `features` field lists Cargo feature flags (not exposed by this client)
//!
//! ## Error Handling
//!
//! - **Rate limiting**: Client-side enforcement (1 req/s)
//! - **Network errors**: Returned as `anyhow::Error`
//! - **API errors**: Non-success status codes return an error
//!
//! ## External References
//!
//! - [crates.io Data Access](https://crates.io/data-access)
//! - [crates.io Policies](https://crates.io/policies)
//! - [Crate Metadata Schema](https://doc.rust-lang.org/cargo/reference/registry-index.html)

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Mutex;

use super::http_client::create_shared_client;
use super::version_utils::is_prerelease_rust;
use super::{Registry, VersionInfo};

/// Rate limiter to respect crates.io's 1 request/second limit
struct RateLimiter {
    last_request: Instant,
    min_interval: Duration,
}

impl RateLimiter {
    fn new(requests_per_second: f64) -> Self {
        Self {
            last_request: Instant::now() - Duration::from_secs(10),
            min_interval: Duration::from_secs_f64(1.0 / requests_per_second),
        }
    }

    async fn wait(&mut self) {
        let elapsed = self.last_request.elapsed();
        if elapsed < self.min_interval {
            tokio::time::sleep(self.min_interval - elapsed).await;
        }
        self.last_request = Instant::now();
    }
}

/// Client for the crates.io registry
pub struct CratesIoRegistry {
    client: Arc<Client>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    base_url: String,
}

impl CratesIoRegistry {
    /// Creates a CratesIoRegistry that uses the provided shared HTTP client.
    ///
    /// The registry will use the given `client` for all HTTP requests, enforce a
    /// default rate limit of 1 request per second, and target the crates.io API
    /// base URL.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use depsy_lsp::registries::crates_io::CratesIoRegistry;
    /// use depsy_lsp::registries::http_client::create_shared_client;
    ///
    /// let client = create_shared_client().expect("failed to create client");
    /// let registry = CratesIoRegistry::with_client(client);
    /// ```
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1.0))),
            base_url: "https://crates.io/api/v1".to_string(),
        }
    }
}

impl Default for CratesIoRegistry {
    /// Creates a `CratesIoRegistry` configured with a shared HTTP client and default rate limiting.
    ///
    /// The registry is initialized with a shared `reqwest::Client`, a 1 request/second rate limiter,
    /// and the default crates.io API base URL.
    ///
    /// # Panics
    ///
    /// This function will panic if creating the shared HTTP client fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use depsy_lsp::registries::crates_io::CratesIoRegistry;
    ///
    /// let _registry = CratesIoRegistry::default();
    /// ```
    fn default() -> Self {
        Self::with_client(create_shared_client().expect("Failed to create HTTP client"))
    }
}

// API response structures
#[derive(Debug, Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    crate_info: CrateInfo,
    versions: Vec<VersionEntry>,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    max_stable_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VersionEntry {
    num: String,
    yanked: bool,
    license: Option<String>,
    created_at: Option<String>,
}

impl Registry for CratesIoRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        // Rate limiting
        {
            let mut limiter = self.rate_limiter.lock().await;
            limiter.wait().await;
        }

        let url = format!("{}/crates/{package_name}", self.base_url);

        let response = self.client.get(&url).send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch crate info for {package_name}: {}",
            response.status()
        );

        let crate_response: CrateResponse = response.json().await?;

        // Find latest stable version (not yanked, no prerelease)
        let latest_stable = crate_response
            .crate_info
            .max_stable_version
            .clone()
            .or_else(|| {
                crate_response
                    .versions
                    .iter()
                    .find(|v| !v.yanked && !is_prerelease_rust(&v.num))
                    .map(|v| v.num.clone())
            });

        // Find latest prerelease
        let latest_prerelease = crate_response
            .versions
            .iter()
            .find(|v| !v.yanked && is_prerelease_rust(&v.num))
            .map(|v| v.num.clone());

        // Get all versions (not yanked)
        let versions: Vec<String> = crate_response
            .versions
            .iter()
            .filter(|v| !v.yanked)
            .map(|v| v.num.clone())
            .collect();

        // Get license from latest version
        let license = crate_response
            .versions
            .first()
            .and_then(|v| v.license.clone());

        // Collect all yanked versions
        let yanked_versions: Vec<String> = crate_response
            .versions
            .iter()
            .filter(|v| v.yanked)
            .map(|v| v.num.clone())
            .collect();

        // Collect release dates for all versions
        let release_dates: HashMap<String, DateTime<Utc>> = crate_response
            .versions
            .iter()
            .filter_map(|v| {
                v.created_at.as_ref().and_then(|date_str| {
                    DateTime::parse_from_rfc3339(date_str)
                        .ok()
                        .map(|dt| (v.num.clone(), dt.with_timezone(&Utc)))
                })
            })
            .collect();

        // Check if latest version is yanked (kept for backwards compatibility)
        let yanked = crate_response.versions.first().is_some_and(|v| v.yanked);

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease,
            versions,
            description: crate_response.crate_info.description,
            homepage: crate_response.crate_info.homepage,
            repository: crate_response.crate_info.repository,
            license,
            vulnerabilities: vec![], // Filled by OSV
            deprecated: false,       // Filled by OSV
            yanked,
            yanked_versions,
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
        assert!(is_prerelease_rust("1.0.0-alpha"));
        assert!(is_prerelease_rust("1.0.0-beta.1"));
        assert!(is_prerelease_rust("1.0.0-rc1"));
        assert!(!is_prerelease_rust("1.0.0"));
        assert!(!is_prerelease_rust("2.3.4"));
    }
}
