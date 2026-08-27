//! # Package Registry Clients
//!
//! This module provides clients for fetching package version information from
//! various package registries across different programming ecosystems.
//!
//! ## Supported Registries
//!
//! | Registry | Ecosystem | Module |
//! |----------|-----------|--------|
//! | [crates.io](https://crates.io) | Rust | [`crates_io`] |
//! | [npm](https://www.npmjs.com) | Node.js/JavaScript | [`npm`] |
//! | [PyPI](https://pypi.org) | Python | [`pypi`] |
//! | [Go Proxy](https://proxy.golang.org) | Go | [`go_proxy`] |
//! | [Packagist](https://packagist.org) | PHP/Composer | [`packagist`] |
//! | [pub.dev](https://pub.dev) | Dart/Flutter | [`pub_dev`] |
//! | [NuGet](https://www.nuget.org) | .NET | [`nuget`] |
//! | [RubyGems](https://rubygems.org) | Ruby | [`rubygems`] |
//! | [Maven Central](https://repo1.maven.org/maven2) | Java/Maven | [`maven_central`] |
//!
//! ## Architecture
//!
//! All registry clients implement the [`Registry`] trait, providing a unified
//! interface for fetching package metadata:
//!
//! ```ignore
//! pub trait Registry: Send + Sync {
//!     async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo>;
//!     fn http_client(&self) -> Arc<Client>;
//! }
//! ```
//!
//! ## Shared HTTP Client
//!
//! Registry clients share a single HTTP client via [`http_client::create_shared_client`]
//! for connection pooling, HTTP/2 multiplexing, and reduced memory footprint.
//!
//! ## Common Return Type
//!
//! All registries return [`VersionInfo`] containing:
//!
//! - **Latest stable version**: The most recent non-prerelease version
//! - **Latest prerelease**: The most recent prerelease version (if any)
//! - **All versions**: Complete list of available versions
//! - **Metadata**: Description, homepage, repository, license
//! - **Status**: Deprecated, yanked flags
//! - **Release dates**: Publish timestamps for each version
//!
//! ## Vulnerability Detection
//!
//! Vulnerability information is populated separately via the OSV API
//! (see `vulnerabilities` module), not by the registry clients themselves.
//!
//! ## Rate Limiting
//!
//! Each registry has different rate limiting policies:
//!
//! | Registry | Rate Limit | Notes |
//! |----------|------------|-------|
//! | crates.io | 1 req/s | **Strict** - client-side enforced |
//! | npm | ≤1 req/s recommended | No official limit; IP blocking for abuse |
//! | PyPI | No official limit | CDN-cached; be respectful |
//! | Go Proxy | Fair use | No hard limit |
//! | Packagist | ~60/min | CDN-cached |
//! | pub.dev | ~100/min | CDN-cached |
//! | NuGet | Fair use | CDN-cached |
//! | RubyGems | Varies by endpoint | ~10 req/s typical; blocking for abuse |
//!
//! ## Usage
//!
//! ```ignore
//! use depsy_lsp::registries::{Registry, crates_io::CratesIoRegistry};
//!
//! let registry = CratesIoRegistry::default();
//! let info = registry.get_version_info("serde").await?;
//! println!("Latest: {:?}", info.latest);
//! ```

use std::sync::Arc;

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// A vulnerability discovered in a transitive dependency reached through a direct package.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransitiveVuln {
    #[serde(rename = "package")]
    pub package_name: String,
    #[serde(rename = "version")]
    pub package_version: String,
    pub vulnerability: Vulnerability,
}

/// Information about a package version from a registry
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VersionInfo {
    /// Latest stable version
    pub latest: Option<String>,
    /// Latest prerelease version
    pub latest_prerelease: Option<String>,
    /// All available versions
    pub versions: Vec<String>,
    /// Package description
    pub description: Option<String>,
    /// Homepage URL
    pub homepage: Option<String>,
    /// Repository URL (GitHub, etc.)
    pub repository: Option<String>,
    /// SPDX license identifier
    pub license: Option<String>,
    /// Known vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
    /// Whether the package is deprecated
    pub deprecated: bool,
    /// Whether the version is yanked (Rust specific) - deprecated, use yanked_versions instead
    pub yanked: bool,
    /// List of yanked version numbers (Rust specific)
    pub yanked_versions: Vec<String>,
    /// Release dates for each version (version string -> DateTime)
    #[serde(default)]
    pub release_dates: HashMap<String, DateTime<Utc>>,
    /// Vulnerabilities discovered in transitive dependencies reached through this package.
    #[serde(default)]
    pub transitive_vulnerabilities: Vec<TransitiveVuln>,
}

impl VersionInfo {
    /// Check if a specific version is yanked
    pub fn is_version_yanked(&self, version: &str) -> bool {
        let normalized = normalize_version_for_yanked_check(version);
        self.yanked_versions
            .iter()
            .any(|v| normalize_version_for_yanked_check(v) == normalized)
    }

    /// Get the release date for a specific version
    pub fn get_release_date(&self, version: &str) -> Option<DateTime<Utc>> {
        self.release_dates.get(version).copied()
    }
}

/// Normalize version for yanked check comparison
/// Removes common prefixes like ^, ~, >=, etc.
fn normalize_version_for_yanked_check(version: &str) -> String {
    let version = version.trim();
    version
        .strip_prefix('^')
        .or_else(|| version.strip_prefix('~'))
        .or_else(|| version.strip_prefix(">="))
        .or_else(|| version.strip_prefix("<="))
        .or_else(|| version.strip_prefix('>'))
        .or_else(|| version.strip_prefix('<'))
        .or_else(|| version.strip_prefix('='))
        .unwrap_or(version)
        .split(',')
        .next()
        .unwrap_or(version)
        .trim()
        .to_string()
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE or advisory ID
    pub id: String,
    /// Severity level
    pub severity: VulnerabilitySeverity,
    /// Description of the vulnerability
    pub description: String,
    /// URL for more information
    pub url: Option<String>,
}

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl VulnerabilitySeverity {
    /// Get numeric rank for severity comparison (higher = more severe)
    pub fn rank(&self) -> u8 {
        match self {
            VulnerabilitySeverity::Low => 1,
            VulnerabilitySeverity::Medium => 2,
            VulnerabilitySeverity::High => 3,
            VulnerabilitySeverity::Critical => 4,
        }
    }

    /// Check if this severity meets or exceeds a minimum threshold
    pub fn meets_threshold(&self, min: &Self) -> bool {
        self.rank() >= min.rank()
    }

    /// Parse severity from string (case-insensitive)
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => VulnerabilitySeverity::Critical,
            "high" => VulnerabilitySeverity::High,
            "medium" => VulnerabilitySeverity::Medium,
            _ => VulnerabilitySeverity::Low,
        }
    }

    /// Get lowercase string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnerabilitySeverity::Low => "low",
            VulnerabilitySeverity::Medium => "medium",
            VulnerabilitySeverity::High => "high",
            VulnerabilitySeverity::Critical => "critical",
        }
    }
}

/// Trait for registry clients
/// Note: async_fn_in_trait is allowed because this trait is internal and already bounds Send + Sync
#[allow(async_fn_in_trait)]
pub trait Registry: Send + Sync {
    /// Get version information for a package
    async fn get_version_info(&self, package_name: &str) -> anyhow::Result<VersionInfo>;

    /// Get a reference to the HTTP client used by this registry
    fn http_client(&self) -> Arc<Client>;
}

pub mod cargo_sparse;
pub mod crates_io;
pub mod go_proxy;
pub mod http_client;
pub mod maven_central;
pub mod npm;
pub mod nuget;
pub mod packagist;
pub mod pub_dev;
pub mod pypi;
pub mod rubygems;
pub(crate) mod url_sanitizer;
pub mod version_utils;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_rank() {
        assert_eq!(VulnerabilitySeverity::Low.rank(), 1);
        assert_eq!(VulnerabilitySeverity::Medium.rank(), 2);
        assert_eq!(VulnerabilitySeverity::High.rank(), 3);
        assert_eq!(VulnerabilitySeverity::Critical.rank(), 4);
    }

    #[test]
    fn test_severity_meets_threshold() {
        // Critical meets all thresholds
        assert!(VulnerabilitySeverity::Critical.meets_threshold(&VulnerabilitySeverity::Low));
        assert!(VulnerabilitySeverity::Critical.meets_threshold(&VulnerabilitySeverity::Medium));
        assert!(VulnerabilitySeverity::Critical.meets_threshold(&VulnerabilitySeverity::High));
        assert!(VulnerabilitySeverity::Critical.meets_threshold(&VulnerabilitySeverity::Critical));

        // Low only meets Low threshold
        assert!(VulnerabilitySeverity::Low.meets_threshold(&VulnerabilitySeverity::Low));
        assert!(!VulnerabilitySeverity::Low.meets_threshold(&VulnerabilitySeverity::Medium));
        assert!(!VulnerabilitySeverity::Low.meets_threshold(&VulnerabilitySeverity::High));
        assert!(!VulnerabilitySeverity::Low.meets_threshold(&VulnerabilitySeverity::Critical));

        // High meets Low, Medium, and High thresholds
        assert!(VulnerabilitySeverity::High.meets_threshold(&VulnerabilitySeverity::Low));
        assert!(VulnerabilitySeverity::High.meets_threshold(&VulnerabilitySeverity::Medium));
        assert!(VulnerabilitySeverity::High.meets_threshold(&VulnerabilitySeverity::High));
        assert!(!VulnerabilitySeverity::High.meets_threshold(&VulnerabilitySeverity::Critical));
    }

    #[test]
    fn test_severity_from_str_loose() {
        assert_eq!(
            VulnerabilitySeverity::from_str_loose("critical"),
            VulnerabilitySeverity::Critical
        );
        assert_eq!(
            VulnerabilitySeverity::from_str_loose("CRITICAL"),
            VulnerabilitySeverity::Critical
        );
        assert_eq!(
            VulnerabilitySeverity::from_str_loose("high"),
            VulnerabilitySeverity::High
        );
        assert_eq!(
            VulnerabilitySeverity::from_str_loose("HIGH"),
            VulnerabilitySeverity::High
        );
        assert_eq!(
            VulnerabilitySeverity::from_str_loose("medium"),
            VulnerabilitySeverity::Medium
        );
        assert_eq!(
            VulnerabilitySeverity::from_str_loose("low"),
            VulnerabilitySeverity::Low
        );
        // Unknown strings default to Low
        assert_eq!(
            VulnerabilitySeverity::from_str_loose("unknown"),
            VulnerabilitySeverity::Low
        );
        assert_eq!(
            VulnerabilitySeverity::from_str_loose(""),
            VulnerabilitySeverity::Low
        );
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(VulnerabilitySeverity::Low.as_str(), "low");
        assert_eq!(VulnerabilitySeverity::Medium.as_str(), "medium");
        assert_eq!(VulnerabilitySeverity::High.as_str(), "high");
        assert_eq!(VulnerabilitySeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_is_version_yanked() {
        let info = VersionInfo {
            yanked_versions: vec!["1.0.0".to_string(), "1.0.1".to_string()],
            ..Default::default()
        };

        assert!(info.is_version_yanked("1.0.0"));
        assert!(info.is_version_yanked("1.0.1"));
        assert!(!info.is_version_yanked("1.0.2"));
        assert!(!info.is_version_yanked("2.0.0"));
    }

    #[test]
    fn test_is_version_yanked_with_prefixes() {
        let info = VersionInfo {
            yanked_versions: vec!["1.0.0".to_string()],
            ..Default::default()
        };

        assert!(info.is_version_yanked("^1.0.0"));
        assert!(info.is_version_yanked("~1.0.0"));
        assert!(info.is_version_yanked(">=1.0.0"));
        assert!(info.is_version_yanked("=1.0.0"));
    }

    #[test]
    fn test_is_version_yanked_empty() {
        let info = VersionInfo::default();

        assert!(!info.is_version_yanked("1.0.0"));
    }
}

#[cfg(test)]
mod transitive_vuln_tests {
    use super::*;

    #[test]
    fn test_version_info_default_has_empty_transitive_vulns() {
        let info = VersionInfo::default();
        assert!(info.transitive_vulnerabilities.is_empty());
    }

    #[test]
    fn test_transitive_vuln_serializes_with_package_and_version() {
        let v = TransitiveVuln {
            package_name: "scheduler".to_string(),
            package_version: "1.2.3".to_string(),
            vulnerability: Vulnerability {
                id: "CVE-XXX".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "desc".to_string(),
                url: None,
            },
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"package\":\"scheduler\""));
        assert!(json.contains("\"version\":\"1.2.3\""));
    }
}
