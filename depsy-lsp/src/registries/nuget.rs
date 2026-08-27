//! # NuGet Registry Client
//!
//! This module implements a client for [NuGet Gallery](https://www.nuget.org),
//! the package manager for .NET packages.
//!
//! ## API Details
//!
//! - **Base URL**: `https://api.nuget.org/v3`
//! - **API Version**: v3 (NuGet Server API)
//! - **Authentication**: API key for publishing (not needed for reading)
//! - **CORS**: Limited support
//!
//! ## Rate Limiting
//!
//! NuGet does not publish hard rate limits but implements:
//!
//! - **Fair use policy**: No hard limits for normal usage
//! - **CDN caching**: Most responses served from Azure CDN
//! - **Best practice**: Use conditional requests
//!
//! ## API Endpoints Used
//!
//! ### Package Registration (Metadata)
//!
//! - **Endpoint**: `GET /registration5-semver1/{package-id-lower}/index.json`
//! - **Response**: JSON with registration pages containing version metadata
//! - **Fields**:
//!   - `items[]`: Array of registration pages
//!   - `items[].items[]`: Array of version entries (may require fetching page)
//!   - `catalogEntry.version`: Version string
//!   - `catalogEntry.description`: Package description
//!   - `catalogEntry.projectUrl`: Project homepage
//!   - `catalogEntry.licenseExpression`: SPDX license
//!   - `catalogEntry.listed`: Whether version is listed (unlisted = hidden)
//!   - `catalogEntry.deprecation`: Deprecation info if deprecated
//!   - `catalogEntry.published`: RFC 3339 publish timestamp
//!
//! ## Response Parsing
//!
//! - **Version format**: Semver with optional prerelease (`1.0.0`, `2.0.0-preview.1`)
//! - **Date format**: RFC 3339 (`2024-01-15T10:30:00+00:00`)
//! - **Unlisted packages**: `listed: false` (hidden from search but downloadable)
//! - **Deprecated packages**: `deprecation` object present
//!
//! ## Edge Cases and Quirks
//!
//! - **Package ID case**: IDs are case-insensitive but URLs use lowercase
//! - **Paged responses**: Large packages may have items in separate pages
//! - **Version ranges**: Uses NuGet version range syntax `[1.0.0,2.0.0)`
//! - **Framework targeting**: Packages may target multiple .NET versions
//! - **Dependency groups**: Dependencies organized by target framework
//! - **Unlisted vs deprecated**: Unlisted hides from search; deprecated shows warning
//! - **License**: Either `licenseExpression` (SPDX) or `licenseUrl` (legacy)
//!
//! ## Error Handling
//!
//! - **Network errors**: Returned as `anyhow::Error`
//! - **API errors**: 404 for not found
//! - **Timeouts**: 10 second default timeout
//!
//! ## External References
//!
//! - [NuGet Server API](https://learn.microsoft.com/en-us/nuget/api/overview)
//! - [Package Metadata Resource](https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource)
//! - [NuGet Versioning](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning)
//! - [Version Ranges](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges)

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::Deserialize;

use super::http_client::create_shared_client;
use super::version_utils::is_prerelease_nuget;
use super::{Registry, VersionInfo};

/// Client for the NuGet registry
pub struct NuGetRegistry {
    client: Arc<Client>,
    base_url: String,
}

impl NuGetRegistry {
    /// Constructs a NuGetRegistry configured to use the NuGet v3 API with the provided shared HTTP client.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use depsy_lsp::registries::nuget::NuGetRegistry;
    ///
    /// let client = Arc::new(reqwest::Client::new());
    /// let _registry = NuGetRegistry::with_client(client);
    /// ```
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            base_url: "https://api.nuget.org/v3".to_string(),
        }
    }
}

impl Default for NuGetRegistry {
    /// Creates a `NuGetRegistry` configured with a shared HTTP client targeting the NuGet v3 API.
    ///
    /// Panics if creating the shared HTTP client fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use depsy_lsp::registries::nuget::NuGetRegistry;
    ///
    /// let _reg = NuGetRegistry::default();
    /// ```
    fn default() -> Self {
        Self::with_client(create_shared_client().expect("Failed to create HTTP client"))
    }
}

// NuGet API response structures
#[derive(Debug, Deserialize)]
struct NuGetRegistrationResponse {
    items: Vec<NuGetRegistrationPage>,
}

#[derive(Debug, Deserialize)]
struct NuGetRegistrationPage {
    items: Option<Vec<NuGetRegistrationLeaf>>,
    #[serde(rename = "@id")]
    id: String,
}

#[derive(Debug, Deserialize, Clone)]
struct NuGetRegistrationLeaf {
    #[serde(rename = "catalogEntry")]
    catalog_entry: NuGetCatalogEntry,
}

#[derive(Debug, Deserialize, Clone)]
struct NuGetCatalogEntry {
    version: String,
    description: Option<String>,
    #[serde(rename = "projectUrl")]
    project_url: Option<String>,
    #[serde(rename = "licenseExpression")]
    license_expression: Option<String>,
    #[serde(rename = "licenseUrl")]
    license_url: Option<String>,
    #[serde(default)]
    listed: Option<bool>,
    #[serde(default)]
    deprecation: Option<NuGetDeprecation>,
    published: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct NuGetDeprecation {
    #[serde(rename = "message")]
    _message: Option<String>,
    #[serde(rename = "reasons")]
    _reasons: Option<Vec<String>>,
}

impl Registry for NuGetRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        // NuGet uses lowercase package IDs in URLs
        let package_id = package_name.to_lowercase();

        // Get registration index
        let url = format!(
            "{}/registration5-semver1/{package_id}/index.json",
            self.base_url
        );

        let response = self.client.get(&url).send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch package info for {package_name}: {}",
            response.status(),
        );

        let registration: NuGetRegistrationResponse = response.json().await?;

        // Collect all versions from all pages
        let mut all_versions: Vec<NuGetCatalogEntry> = Vec::new();

        for page in &registration.items {
            if let Some(items) = &page.items {
                for leaf in items {
                    all_versions.push(leaf.catalog_entry.clone());
                }
            } else {
                // Need to fetch the page content
                let page_response = self.client.get(&page.id).send().await?;
                if page_response.status().is_success() {
                    let page_data: NuGetRegistrationPage = page_response.json().await?;
                    if let Some(items) = page_data.items {
                        for leaf in items {
                            all_versions.push(leaf.catalog_entry.clone());
                        }
                    }
                }
            }
        }

        // Sort versions descending
        all_versions.sort_by(|a, b| {
            match (
                semver::Version::parse(&a.version),
                semver::Version::parse(&b.version),
            ) {
                (Ok(va), Ok(vb)) => vb.cmp(&va),
                _ => b.version.cmp(&a.version),
            }
        });

        // Filter listed versions
        let versions: Vec<String> = all_versions
            .iter()
            .filter(|entry| entry.listed.unwrap_or(true))
            .map(|entry| entry.version.clone())
            .collect();

        // Find latest stable version
        let latest_stable = versions.iter().find(|v| !is_prerelease_nuget(v)).cloned();

        // Find latest prerelease
        let latest_prerelease = versions.iter().find(|v| is_prerelease_nuget(v)).cloned();

        // Get metadata from latest version
        let latest_entry = all_versions.first();

        // Check deprecation
        let deprecated = latest_entry.and_then(|e| e.deprecation.as_ref()).is_some();

        // Collect release dates
        let release_dates: HashMap<String, DateTime<Utc>> = all_versions
            .iter()
            .filter_map(|e| {
                e.published.as_ref().and_then(|time_str| {
                    DateTime::parse_from_rfc3339(time_str)
                        .ok()
                        .map(|dt| (e.version.clone(), dt.with_timezone(&Utc)))
                })
            })
            .collect();

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease,
            versions,
            description: latest_entry.and_then(|e| e.description.clone()),
            homepage: latest_entry.and_then(|e| e.project_url.clone()),
            repository: None, // NuGet doesn't expose repository URL directly
            license: latest_entry
                .and_then(|e| e.license_expression.clone().or(e.license_url.clone())),
            vulnerabilities: vec![], // Will be filled by OSV
            deprecated,
            yanked: false,
            yanked_versions: vec![], // Not applicable to NuGet
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
        assert!(is_prerelease_nuget("1.0.0-alpha"));
        assert!(is_prerelease_nuget("1.0.0-beta.1"));
        assert!(is_prerelease_nuget("1.0.0-preview"));
        assert!(is_prerelease_nuget("1.0.0-rc.1"));
        assert!(is_prerelease_nuget("1.0.0-Alpha"));
        assert!(!is_prerelease_nuget("1.0.0"));
        assert!(!is_prerelease_nuget("2.0.0"));
    }
}
