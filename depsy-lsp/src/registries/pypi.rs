//! # PyPI Registry Client
//!
//! This module implements a client for [PyPI](https://pypi.org) (Python Package Index),
//! the official third-party software repository for Python packages.
//!
//! ## API Details
//!
//! - **Base URL**: `https://pypi.org/pypi`
//! - **API Version**: JSON API (stable)
//! - **Authentication**: Not required for public packages
//! - **CORS**: Enabled for browser-based access
//!
//! ## Rate Limiting
//!
//! PyPI enforces rate limits to protect the service:
//!
//! - **Standard limit**: ~20 requests per second per IP
//! - **Blocking**: Aggressive crawlers may be blocked
//! - **Best practice**: Use `If-Modified-Since` headers for caching
//! - **CDN**: Responses are served via Fastly CDN
//!
//! ## API Endpoints Used
//!
//! ### Fetch Package Info
//!
//! - **Endpoint**: `GET /pypi/{package-name}/json`
//! - **Response**: JSON with project metadata and all releases
//! - **Fields**:
//!   - `info.version`: Latest version
//!   - `info.summary`: Package description
//!   - `info.home_page`: Homepage URL
//!   - `info.license`: License string
//!   - `info.project_urls`: Map of URL types to URLs
//!   - `info.classifiers`: Trove classifiers for categorization
//!   - `releases{}`: Map of version string to release files
//!
//! ## Response Parsing
//!
//! - **Version format**: PEP 440 compliant (`1.0.0`, `1.0.0a1`, `1.0.0.dev1`)
//! - **Date format**: ISO 8601 without timezone (`2024-01-15T10:30:00`)
//! - **Yanked releases**: `yanked: true` in release file info
//! - **Deprecated projects**: `Development Status :: 7 - Inactive` classifier
//!
//! ## Edge Cases and Quirks
//!
//! - **Name normalization**: Case-insensitive; underscores, hyphens, and dots
//!   are all equivalent per [PEP 503](https://peps.python.org/pep-0503/)
//!   (`Flask` = `flask` = `FLASK`, `typing_extensions` = `typing-extensions`)
//! - **Project vs release metadata**: Some fields are project-level, others per-release
//! - **Classifiers**: Used for deprecation status, Python version support, etc.
//! - **requires_python**: Version constraint for Python interpreter (not exposed)
//! - **Yanked releases**: Still downloadable but with warning
//! - **Version ordering**: Uses PEP 440 ordering, not simple semver
//!
//! ## Error Handling
//!
//! - **Network errors**: Returned as `anyhow::Error`
//! - **API errors**: 404 for not found
//! - **Timeouts**: 10 second default timeout
//!
//! ## External References
//!
//! - [PyPI JSON API](https://docs.pypi.org/api/json/)
//! - [PEP 503 - Simple Repository API](https://peps.python.org/pep-0503/)
//! - [PEP 440 - Version Identification](https://peps.python.org/pep-0440/)
//! - [Trove Classifiers](https://pypi.org/classifiers/)

use std::sync::Arc;

use chrono::{DateTime, NaiveDateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::Deserialize;

use super::http_client::create_shared_client;
use super::version_utils::is_prerelease_python;
use super::{Registry, VersionInfo};

/// Client for the PyPI registry
pub struct PyPiRegistry {
    client: Arc<Client>,
    base_url: String,
}

impl PyPiRegistry {
    /// Constructs a PyPiRegistry using the provided shared HTTP client.
    ///
    /// The returned registry is configured with the default PyPI API base URL (`https://pypi.org/pypi`).
    ///
    /// # Parameters
    ///
    /// - `client` — shared HTTP client used for performing requests to the PyPI API.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use depsy_lsp::registries::pypi::PyPiRegistry;
    /// use depsy_lsp::registries::http_client::create_shared_client;
    ///
    /// let client = create_shared_client().expect("failed to create client");
    /// let registry = PyPiRegistry::with_client(client);
    /// ```
    pub fn with_client(client: Arc<Client>) -> Self {
        Self {
            client,
            base_url: "https://pypi.org/pypi".to_string(),
        }
    }
}

impl Default for PyPiRegistry {
    /// Creates a PyPiRegistry configured with a shared HTTP client and the default PyPI base URL.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use depsy_lsp::registries::pypi::PyPiRegistry;
    ///
    /// let _registry = PyPiRegistry::default();
    /// ```
    fn default() -> Self {
        Self::with_client(create_shared_client().expect("Failed to create HTTP client"))
    }
}

// PyPI API response structures
#[derive(Debug, Deserialize)]
struct PyPiResponse {
    info: PackageInfo,
    releases: HashMap<String, Vec<ReleaseFile>>,
}

#[derive(Debug, Deserialize)]
struct PackageInfo {
    /// Latest version
    version: String,
    /// Package description
    summary: Option<String>,
    /// Homepage URL
    home_page: Option<String>,
    /// License string
    license: Option<String>,
    /// Project URLs (may contain Repository, Homepage, etc.)
    project_urls: Option<HashMap<String, String>>,
    /// Classifiers (can be used to detect deprecated packages)
    classifiers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ReleaseFile {
    /// Whether this file has been yanked
    yanked: Option<bool>,
    /// Upload time for this file (ISO 8601 format without timezone)
    upload_time: Option<String>,
}

impl Registry for PyPiRegistry {
    fn http_client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo> {
        // Normalize package name (PyPI is case-insensitive, uses lowercase)
        let normalized_name = normalize_package_name(package_name);

        let url = format!("{}/{normalized_name}/json", self.base_url);

        let response = self.client.get(&url).send().await?;

        anyhow::ensure!(
            response.status().is_success(),
            "Failed to fetch package info for {package_name}: {}",
            response.status()
        );

        let pypi_response: PyPiResponse = response.json().await?;

        // Get all versions sorted by semver (newest first)
        let mut versions: Vec<String> = pypi_response
            .releases
            .iter()
            .filter(|(_, files)| {
                // Filter out yanked versions
                !files.iter().any(|f| f.yanked.unwrap_or(false))
            })
            .map(|(version, _)| version.clone())
            .collect();

        // Sort versions in descending order
        versions.sort_by(|a, b| compare_python_versions(b, a));

        // Find latest stable version (non-prerelease)
        let latest_stable = versions
            .iter()
            .find(|v| !is_prerelease_python(v))
            .cloned()
            .or_else(|| Some(pypi_response.info.version.clone()));

        // Find latest prerelease
        let latest_prerelease = versions.iter().find(|v| is_prerelease_python(v)).cloned();

        // Extract repository URL from project_urls
        let repository = pypi_response.info.project_urls.as_ref().and_then(|urls| {
            urls.get("Repository")
                .or_else(|| urls.get("Source"))
                .or_else(|| urls.get("Source Code"))
                .or_else(|| urls.get("GitHub"))
                .cloned()
        });

        // Extract homepage
        let homepage = pypi_response.info.home_page.clone().or_else(|| {
            pypi_response
                .info
                .project_urls
                .as_ref()
                .and_then(|urls| urls.get("Homepage").cloned())
        });

        // Check if deprecated (via classifiers)
        let deprecated = pypi_response
            .info
            .classifiers
            .as_ref()
            .is_some_and(|classifiers| {
                classifiers
                    .iter()
                    .any(|c| c.contains("Development Status :: 7 - Inactive"))
            });

        // Extract release dates from releases (use the first file's upload_time for each version)
        let release_dates: HashMap<String, DateTime<Utc>> = pypi_response
            .releases
            .iter()
            .filter_map(|(version, files)| {
                files
                    .first()
                    .and_then(|f| f.upload_time.as_ref())
                    .and_then(|time_str| parse_pypi_datetime(time_str))
                    .map(|dt| (version.clone(), dt))
            })
            .collect();

        Ok(VersionInfo {
            latest: latest_stable,
            latest_prerelease,
            versions,
            description: pypi_response.info.summary,
            homepage,
            repository,
            license: pypi_response.info.license,
            vulnerabilities: vec![], // TODO: Integrate Safety/OSV
            deprecated,
            yanked: false,
            yanked_versions: vec![], // Not applicable to PyPI
            release_dates,
            transitive_vulnerabilities: vec![],
        })
    }
}

/// Parse PyPI datetime format (ISO 8601 without timezone, assumed UTC)
fn parse_pypi_datetime(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
        .ok()
        .map(|naive| naive.and_utc())
}

/// Normalize Python package name according to PEP 503
/// - Lowercase
/// - Replace underscores and dots with hyphens
fn normalize_package_name(name: &str) -> String {
    name.to_lowercase().replace(['_', '.'], "-")
}

/// Compare Python versions for sorting
/// Returns Ordering for descending sort (newer versions first)
fn compare_python_versions(a: &str, b: &str) -> std::cmp::Ordering {
    // Try parsing as semver first
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(va), Ok(vb)) => va.cmp(&vb),
        _ => {
            // Fallback to simple string comparison with version-aware logic
            compare_version_strings(a, b)
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
    fn test_normalize_package_name() {
        assert_eq!(normalize_package_name("Flask"), "flask");
        assert_eq!(normalize_package_name("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(
            normalize_package_name("typing_extensions"),
            "typing-extensions"
        );
        assert_eq!(normalize_package_name("Pillow"), "pillow");
    }

    #[test]
    fn test_is_prerelease() {
        assert!(is_prerelease_python("1.0.0a1"));
        assert!(is_prerelease_python("1.0.0b2"));
        assert!(is_prerelease_python("1.0.0rc1"));
        assert!(is_prerelease_python("1.0.0.dev1"));
        assert!(is_prerelease_python("2.0.0alpha"));
        assert!(is_prerelease_python("2.0.0beta"));
        assert!(!is_prerelease_python("1.0.0"));
        assert!(!is_prerelease_python("2.3.4"));
    }

    #[test]
    fn test_compare_python_versions() {
        use std::cmp::Ordering;

        assert_eq!(compare_python_versions("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(compare_python_versions("2.0.0", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_python_versions("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(
            compare_python_versions("1.10.0", "1.9.0"),
            Ordering::Greater
        );
    }
}
