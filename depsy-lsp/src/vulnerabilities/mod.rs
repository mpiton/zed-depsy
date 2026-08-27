//! Vulnerability scanning for dependencies
//!
//! This module provides vulnerability detection using OSV.dev API
//! as the primary source for all ecosystems.

pub mod cache;
pub mod osv;

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

#[cfg(test)]
mod tests {
    use super::normalize_version_for_osv;

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
