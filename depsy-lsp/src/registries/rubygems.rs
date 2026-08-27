//! # RubyGems Registry Client
//!
//! This module implements a client for [RubyGems.org](https://rubygems.org),
//! the Ruby community's gem hosting service.
//!
//! ## API Details
//!
//! - **Base URL**: `https://rubygems.org/api/v1`
//! - **API Version**: v1 (stable)
//! - **Authentication**: API key for publishing (not needed for reading)
//! - **CORS**: Enabled for browser-based access
//!
//! ## Rate Limiting
//!
//! RubyGems enforces rate limits:
//!
//! - **Standard limit**: ~10 requests per second per IP
//! - **Blocking**: Aggressive crawlers may be blocked
//! - **Best practice**: Use `If-Modified-Since` headers
//!
//! ## API Endpoints Used
//!
//! ### Fetch Gem Info
//!
//! - **Endpoint**: `GET /api/v1/gems/{gem-name}.json`
//! - **Response**: JSON with gem metadata (latest version)
//! - **Fields**:
//!   - `version`: Latest version string
//!   - `info`: Gem description
//!   - `licenses[]`: Array of license identifiers
//!   - `homepage_uri`: Homepage URL
//!   - `source_code_uri`: Repository URL
//!   - `project_uri`: RubyGems project page
//!   - `version_created_at`: RFC 3339 release timestamp
//!
//! ### Fetch All Versions
//!
//! - **Endpoint**: `GET /api/v1/versions/{gem-name}.json`
//! - **Response**: JSON array of version entries
//! - **Fields**:
//!   - `number`: Version string
//!   - `created_at`: RFC 3339 publish timestamp
//!
//! ## Response Parsing
//!
//! - **Version format**: RubyGems versioning (`1.0.0`, `2.0.0.pre.1`)
//! - **Date format**: RFC 3339 (`2024-01-15T10:30:00.000Z`)
//! - **Prerelease**: Versions containing `.pre`, `.alpha`, `.beta`, `.rc`
//!
//! ## Edge Cases and Quirks
//!
//! - **Version ordering**: RubyGems uses its own ordering (not strictly semver)
//! - **Yanked gems**: Available via separate endpoint (not implemented)
//! - **Platform gems**: May have platform suffix (`-java`, `-x86_64-linux`)
//! - **Prerelease format**: Uses `.pre.1` format (not `-pre.1`)
//! - **No deprecation flag**: RubyGems API doesn't expose deprecation status
//!
//! ## Error Handling
//!
//! - **Network errors**: Returned as `anyhow::Error`
//! - **API errors**: 404 for not found
//! - **Timeouts**: 10 second default timeout
//!
//! ## External References
//!
//! - [RubyGems API](https://guides.rubygems.org/rubygems-org-api/)
//! - [Gem Specification](https://guides.rubygems.org/specification-reference/)
//! - [Version Format](https://guides.rubygems.org/patterns/#semantic-versioning)

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::Deserialize;

use super::http_client::create_shared_client;
use super::{Registry, VersionInfo};

/// Client for the RubyGems.org registry
pub struct RubyGemsRegistry {
    client: Arc<Client>,
    base_url: String,
}

impl RubyGemsRegistry {
    /// Creates a RubyGemsRegistry that uses the provided shared HTTP client.
    ///
    /// The provided `client` will be used for all HTTP requests to the RubyGems API. The registry's
    /// base API URL is set to `https://rubygems.org/api/v1`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use depsy_lsp::registries::rubygems::RubyGemsRegistry;
    ///
    /// let client = Arc::new(reqwest::Client::new());
    /// let _registry = RubyGemsRegistry::with_client(client);
    /// ```
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            base_url: "https://rubygems.org/api/v1".to_string(),
        }
    }
}

impl Default for RubyGemsRegistry {
    /// Creates a `RubyGemsRegistry` configured with the shared HTTP client used by the module.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use depsy_lsp::registries::rubygems::RubyGemsRegistry;
    ///
    /// let registry = RubyGemsRegistry::default();
    /// // `registry` is ready to query the RubyGems API.
    /// ```
    fn default() -> Self {
        Self::with_client(create_shared_client().expect("Failed to create HTTP client"))
    }
}

/// RubyGems API response for a gem
#[derive(Debug, Deserialize)]
struct GemResponse {
    #[serde(rename = "name")]
    _name: String,
    version: String,
    info: Option<String>,
    licenses: Option<Vec<String>>,
    homepage_uri: Option<String>,
    source_code_uri: Option<String>,
    project_uri: Option<String>,
    version_created_at: Option<String>,
}

/// RubyGems API response for version list
#[derive(Debug, Deserialize)]
struct VersionResponse {
    number: String,
    created_at: Option<String>,
}

impl Registry for RubyGemsRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        // Fetch gem info (contains latest version)
        let gem_url = format!("{}/gems/{package_name}.json", self.base_url);
        let gem_response = self.client.get(&gem_url).send().await?;

        anyhow::ensure!(
            gem_response.status().is_success(),
            "Failed to fetch gem info for {package_name}: {}",
            gem_response.status(),
        );

        let gem: GemResponse = gem_response.json().await?;

        // Fetch all versions with dates
        let versions_url = format!("{}/versions/{package_name}.json", self.base_url);
        let (versions, release_dates) = match self.client.get(&versions_url).send().await {
            Ok(response) if response.status().is_success() => {
                let version_list: Vec<VersionResponse> = response.json().await.unwrap_or_default();
                let versions: Vec<String> = version_list.iter().map(|v| v.number.clone()).collect();
                let dates: HashMap<String, DateTime<Utc>> = version_list
                    .into_iter()
                    .filter_map(|v| {
                        v.created_at.as_ref().and_then(|time_str| {
                            DateTime::parse_from_rfc3339(time_str)
                                .ok()
                                .map(|dt| (v.number.clone(), dt.with_timezone(&Utc)))
                        })
                    })
                    .collect();
                (versions, dates)
            }
            _ => {
                // Fallback to just latest version with its date
                let mut dates = HashMap::new();
                if let Some(time_str) = &gem.version_created_at
                    && let Ok(dt) = DateTime::parse_from_rfc3339(time_str)
                {
                    dates.insert(gem.version.clone(), dt.with_timezone(&Utc));
                }
                (vec![gem.version.clone()], dates)
            }
        };

        // Use the latest version from gem info
        let latest_stable = Some(gem.version.clone());

        // Get license (first one if multiple)
        let license = gem.licenses.and_then(|l| l.into_iter().next());

        // Get repository URL (prefer source_code_uri, fallback to homepage)
        let repository = gem.source_code_uri.or_else(|| gem.homepage_uri.clone());

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease: None,
            versions,
            description: gem.info,
            homepage: gem.homepage_uri.or(gem.project_uri),
            repository,
            license,
            vulnerabilities: vec![], // Will be filled by OSV
            deprecated: false,       // RubyGems doesn't have a deprecation flag in API
            yanked: false,
            yanked_versions: vec![], // Not applicable to RubyGems
            release_dates,
            transitive_vulnerabilities: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rubygems_url_format() {
        let base_url = "https://rubygems.org/api/v1";
        let name = "rails";
        let url = format!("{base_url}/gems/{name}.json");
        assert_eq!(url, "https://rubygems.org/api/v1/gems/rails.json");
    }
}
