//! Vulnerability scanning for dependencies
//!
//! This module provides vulnerability detection using OSV.dev API
//! as the primary source for all ecosystems.

pub mod cache;
pub mod osv;

use crate::cache::ReadCache;
use crate::parsers::Dependency;
use crate::registries::VersionInfo;
use cache::{VulnCacheKey, VulnerabilityCache};

/// Ecosystem identifiers for vulnerability sources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    /// Rust crates (crates.io)
    CratesIo,
    /// JavaScript/Node packages (npm)
    Npm,
    /// Python packages (PyPI)
    PyPI,
    /// Go modules
    Go,
    /// PHP packages (Packagist)
    Packagist,
    /// Dart/Flutter packages (pub.dev)
    Pub,
    /// .NET packages (NuGet)
    NuGet,
    /// Ruby gems (RubyGems.org)
    RubyGems,
    /// Java packages (Maven Central)
    Maven,
}

impl Ecosystem {
    /// Convert to OSV.dev ecosystem string
    pub fn as_osv_str(&self) -> &'static str {
        match self {
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Go => "Go",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::Pub => "Pub",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Maven => "Maven",
        }
    }
}

/// Query for vulnerability lookup
#[derive(Debug, Clone)]
pub struct VulnerabilityQuery {
    /// Package name
    pub package_name: String,
    /// Package version (normalized, without ^ or ~ prefixes)
    pub version: String,
    /// Target ecosystem
    pub ecosystem: Ecosystem,
}

/// Normalize a version string for use with the OSV.dev API.
///
/// Strips version operators (e.g. `>=`, `^`, `~`) and prefixes (e.g. `v`)
/// so that OSV receives a bare version number like `1.23.0`.
///
/// If normalization would produce an empty string (e.g. operator-only input),
/// the original trimmed input is returned unchanged.
pub fn normalize_version_for_osv(version: &str) -> String {
    // Step 1: trim surrounding whitespace
    let trimmed = version.trim();

    if trimmed.is_empty() {
        return trimmed.to_string();
    }

    // Step 2: handle comma-separated constraints — take only the first part
    let part = match trimmed.split(',').next() {
        Some(v) => v.trim(),
        None => trimmed,
    };

    // Step 3: strip version operators (longest first to avoid partial matches)
    let operators = [
        "===", "==", ">=", "<=", "!=", "~=", "~>", "^", "~", ">", "<", "=",
    ];
    let stripped = {
        let mut v = part;
        for op in &operators {
            if let Some(s) = v.strip_prefix(op) {
                v = s;
                break;
            }
        }
        v
    };

    // Step 4: strip 'v' or 'V' prefix only if followed by a digit (Go versions)
    let result = if stripped.starts_with('v') || stripped.starts_with('V') {
        let rest = &stripped[1..];
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            rest
        } else {
            stripped
        }
    } else {
        stripped
    };

    // Step 5: trim again; if empty after stripping, return original to avoid sending
    // an empty version to OSV (better to send the raw string than nothing)
    let result = result.trim();
    if result.is_empty() {
        trimmed.to_string()
    } else {
        result.to_string()
    }
}

/// Overlays the OSV result for `dep`'s resolved version onto `info`.
///
/// The version cache is keyed by package name only, so it cannot tell two
/// declarations of the same package at different versions apart. OSV results
/// live in `osv_results`, keyed by (ecosystem, name, version), and each reader
/// applies the one matching its own dependency.
///
/// Vulnerabilities come only from OSV, so they are cleared when that version
/// has no live result. This also drops advisories that older releases stored
/// in the persistent version cache. `deprecated` is shared with the registry:
/// OSV can set it but never clears it.
pub fn apply_osv_result(
    info: &mut VersionInfo,
    osv_results: &VulnerabilityCache,
    ecosystem: Ecosystem,
    dep: &Dependency,
) {
    match osv_results.get(&VulnCacheKey::for_dependency(ecosystem, dep)) {
        Some(result) => {
            info.vulnerabilities = result.vulnerabilities;
            info.deprecated |= result.deprecated;
        }
        None => info.vulnerabilities.clear(),
    }
}

/// Reads `dep`'s cached version info with its OSV result applied.
///
/// Readers of `vulnerabilities` or `deprecated` go through this helper or
/// [`apply_osv_result`], so none of them can skip the overlay.
pub async fn cached_version_info(
    cache: &impl ReadCache,
    cache_key: &str,
    osv_results: &VulnerabilityCache,
    ecosystem: Ecosystem,
    dep: &Dependency,
) -> Option<VersionInfo> {
    let mut info = cache.get(cache_key).await?;
    apply_osv_result(&mut info, osv_results, ecosystem, dep);
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::cache::{VulnCacheKey, VulnerabilityCache};
    use super::osv::QueryResult;
    use super::{Ecosystem, apply_osv_result, cached_version_info, normalize_version_for_osv};
    use crate::cache::{MemoryCache, WriteCache};
    use crate::parsers::{Dependency, Span};
    use crate::registries::{VersionInfo, Vulnerability, VulnerabilitySeverity};

    const SPAN: Span = Span {
        line: 0,
        line_start: 0,
        line_end: 0,
    };

    fn dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.to_string(),
            name_span: SPAN,
            version_span: SPAN,
            dev: false,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        }
    }

    fn advisory(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_string(),
            severity: VulnerabilitySeverity::High,
            description: String::new(),
            url: None,
        }
    }

    fn osv_results_with(dep: &Dependency, result: QueryResult) -> VulnerabilityCache {
        let cache = VulnerabilityCache::with_ttl(3600);
        cache.insert(VulnCacheKey::for_dependency(Ecosystem::Npm, dep), result);
        cache
    }

    #[test]
    fn clean_result_replaces_advisories_and_keeps_registry_deprecation() {
        let patched = dep("minimist", "^1.2.8");
        let osv_results = osv_results_with(&patched, QueryResult::default());
        let mut info = VersionInfo {
            vulnerabilities: vec![advisory("GHSA-xvch-5gv4-984h")],
            deprecated: true,
            ..VersionInfo::default()
        };

        apply_osv_result(&mut info, &osv_results, Ecosystem::Npm, &patched);

        assert!(info.vulnerabilities.is_empty());
        assert!(info.deprecated);
    }

    #[test]
    fn osv_deprecation_applies_only_to_its_version() {
        let unmaintained = dep("minimist", "1.2.5");
        let osv_results = osv_results_with(
            &unmaintained,
            QueryResult {
                deprecated: true,
                ..QueryResult::default()
            },
        );
        let mut matching = VersionInfo::default();
        let mut other = VersionInfo::default();

        apply_osv_result(&mut matching, &osv_results, Ecosystem::Npm, &unmaintained);
        apply_osv_result(
            &mut other,
            &osv_results,
            Ecosystem::Npm,
            &dep("minimist", "1.2.8"),
        );

        assert!(matching.deprecated);
        assert!(!other.deprecated);
    }

    #[test]
    fn missing_result_clears_stale_advisories_only() {
        let mut info = VersionInfo {
            vulnerabilities: vec![advisory("GHSA-xvch-5gv4-984h")],
            deprecated: true,
            ..VersionInfo::default()
        };

        apply_osv_result(
            &mut info,
            &VulnerabilityCache::with_ttl(3600),
            Ecosystem::Npm,
            &dep("minimist", "1.2.8"),
        );

        assert!(info.vulnerabilities.is_empty());
        assert!(info.deprecated);
    }

    #[tokio::test]
    async fn cached_version_info_applies_the_overlay() {
        let vulnerable = dep("minimist", "1.2.5");
        let osv_results = osv_results_with(
            &vulnerable,
            QueryResult {
                vulnerabilities: vec![advisory("GHSA-xvch-5gv4-984h")],
                deprecated: false,
            },
        );
        let cache = MemoryCache::new();
        cache
            .insert("npm:minimist".to_string(), VersionInfo::default())
            .await;

        let info = cached_version_info(
            &cache,
            "npm:minimist",
            &osv_results,
            Ecosystem::Npm,
            &vulnerable,
        )
        .await;
        let missing = cached_version_info(
            &cache,
            "npm:absent",
            &osv_results,
            Ecosystem::Npm,
            &vulnerable,
        )
        .await;

        assert_eq!(
            info.map(|info| info.vulnerabilities.len()),
            Some(1),
            "the matching advisory must be applied"
        );
        assert!(missing.is_none());
    }

    #[test]
    fn test_python_operators() {
        assert_eq!(normalize_version_for_osv(">=1.23.0"), "1.23.0");
        assert_eq!(normalize_version_for_osv("==2.0.0"), "2.0.0");
        assert_eq!(normalize_version_for_osv("~=4.0"), "4.0");
        assert_eq!(normalize_version_for_osv("!=1.0"), "1.0");
        assert_eq!(normalize_version_for_osv("===1.0.0"), "1.0.0");
    }

    #[test]
    fn test_cargo_npm_operators() {
        assert_eq!(normalize_version_for_osv("^1.0.0"), "1.0.0");
        assert_eq!(normalize_version_for_osv("~1.0.0"), "1.0.0");
    }

    #[test]
    fn test_ruby_operator() {
        assert_eq!(normalize_version_for_osv("~>1.0"), "1.0");
    }

    #[test]
    fn test_go_prefix() {
        assert_eq!(normalize_version_for_osv("v1.0.0"), "1.0.0");
        assert_eq!(normalize_version_for_osv("V1.0.0"), "1.0.0");
    }

    #[test]
    fn test_plain_version() {
        assert_eq!(normalize_version_for_osv("1.23.0"), "1.23.0");
    }

    #[test]
    fn test_comma_separated() {
        assert_eq!(normalize_version_for_osv(">=1.0,<2.0"), "1.0");
    }

    #[test]
    fn test_whitespace() {
        assert_eq!(normalize_version_for_osv(" >=1.0 "), "1.0");
    }

    #[test]
    fn test_greater_less() {
        assert_eq!(normalize_version_for_osv(">1.0"), "1.0");
        assert_eq!(normalize_version_for_osv("<2.0"), "2.0");
    }

    #[test]
    fn test_bare_equals() {
        assert_eq!(normalize_version_for_osv("=1.0"), "1.0");
    }

    #[test]
    fn test_edge_cases() {
        // Empty string stays empty
        assert_eq!(normalize_version_for_osv(""), "");
        // Whitespace-only becomes empty
        assert_eq!(normalize_version_for_osv("   "), "");
        // Operator-only: returns original (not empty) to avoid bad OSV queries
        assert_eq!(normalize_version_for_osv("==="), "===");
        assert_eq!(normalize_version_for_osv(">="), ">=");
        // Double operator: strips first match, leaves remainder
        assert_eq!(normalize_version_for_osv(">>1.0"), ">1.0");
        // Multiple commas: takes first constraint
        assert_eq!(normalize_version_for_osv(">=1.0,<2.0,>1.5"), "1.0");
    }

    #[test]
    fn test_ecosystem_maven_as_osv_str() {
        use super::Ecosystem;
        assert_eq!(Ecosystem::Maven.as_osv_str(), "Maven");
    }
}
