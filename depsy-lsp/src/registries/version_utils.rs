//! Version parsing and comparison utilities for registry clients.
//!
//! This module provides common version-related functions used across
//! different package registries, with support for registry-specific
//! behavior where needed.

/// Checks if a Rust crate version is a prerelease.
///
/// Uses semver-compatible prerelease detection. A version is considered
/// a prerelease if it contains a hyphen (prerelease separator) or common
/// prerelease identifiers.
pub fn is_prerelease_rust(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains('-') || v.contains("alpha") || v.contains("beta") || v.contains("rc")
}

/// Checks if an npm package version is a prerelease.
///
/// npm-specific prerelease identifiers include `canary` and `next` tags
/// in addition to common patterns.
pub fn is_prerelease_npm(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains('-')
        || v.contains("alpha")
        || v.contains("beta")
        || v.contains("rc")
        || v.contains("canary")
        || v.contains("next")
}

/// Checks if a PyPI package version is a prerelease.
///
/// Python-specific prerelease identifiers per PEP 440, including
/// shorthand notation like `a1` for alpha and `b2` for beta.
/// Note: Post-releases (`.postN`) are stable releases per PEP 440.
pub fn is_prerelease_python(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains("dev")
        || v.contains("alpha")
        || v.contains("beta")
        || v.contains("rc")
        || (v.contains('a') && v.chars().last().is_some_and(|c| c.is_ascii_digit()))
        || (v.contains('b') && v.chars().last().is_some_and(|c| c.is_ascii_digit()))
        || v.contains(".dev")
}

/// Checks if a Go module version is a prerelease.
///
/// Go uses semver-like versions with hyphenated prerelease suffixes.
pub fn is_prerelease_go(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains("-rc") || v.contains("-alpha") || v.contains("-beta") || v.contains("-pre")
}

/// Checks if a PHP Composer package version is a prerelease.
///
/// Composer-specific stability flags including `dev` and common
/// prerelease identifiers.
pub fn is_prerelease_php(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains("alpha")
        || v.contains("beta")
        || v.contains("rc")
        || v.contains("-rc")
        || v.contains("dev")
}

/// Checks if a Dart/Flutter package version is a prerelease.
///
/// Dart uses semver with hyphenated prerelease suffixes and common
/// prerelease identifiers.
pub fn is_prerelease_dart(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains('-')
        || v.contains("dev")
        || v.contains("alpha")
        || v.contains("beta")
        || v.contains("rc")
}

/// Checks if a NuGet package version is a prerelease.
///
/// NuGet-specific prerelease identifiers include `preview` in addition
/// to common patterns.
pub fn is_prerelease_nuget(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains('-')
        || v.contains("alpha")
        || v.contains("beta")
        || v.contains("preview")
        || v.contains("rc")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_prerelease_rust() {
        assert!(is_prerelease_rust("1.0.0-alpha"));
        assert!(is_prerelease_rust("1.0.0-beta.1"));
        assert!(is_prerelease_rust("1.0.0-rc1"));
        assert!(is_prerelease_rust("1.0.0-ALPHA"));
        assert!(!is_prerelease_rust("1.0.0"));
        assert!(!is_prerelease_rust("2.3.4"));
    }

    #[test]
    fn test_is_prerelease_npm() {
        assert!(is_prerelease_npm("1.0.0-alpha"));
        assert!(is_prerelease_npm("1.0.0-beta.1"));
        assert!(is_prerelease_npm("1.0.0-rc.1"));
        assert!(is_prerelease_npm("18.3.0-canary"));
        assert!(is_prerelease_npm("1.0.0-next.0"));
        assert!(!is_prerelease_npm("1.0.0"));
        assert!(!is_prerelease_npm("2.3.4"));
    }

    #[test]
    fn test_is_prerelease_python() {
        assert!(is_prerelease_python("1.0.0a1"));
        assert!(is_prerelease_python("1.0.0b2"));
        assert!(is_prerelease_python("1.0.0rc1"));
        assert!(is_prerelease_python("1.0.0.dev1"));
        assert!(is_prerelease_python("2.0.0alpha"));
        assert!(is_prerelease_python("2.0.0beta"));
        assert!(!is_prerelease_python("1.0.0.post1")); // post-releases are stable per PEP 440
        assert!(!is_prerelease_python("1.0.0"));
        assert!(!is_prerelease_python("2.3.4"));
    }

    #[test]
    fn test_is_prerelease_go() {
        assert!(is_prerelease_go("v1.0.0-rc1"));
        assert!(is_prerelease_go("v2.0.0-beta.1"));
        assert!(is_prerelease_go("v3.0.0-alpha"));
        assert!(is_prerelease_go("v1.0.0-pre.1"));
        assert!(!is_prerelease_go("v1.0.0"));
        assert!(!is_prerelease_go("v2.3.4"));
    }

    #[test]
    fn test_is_prerelease_php() {
        assert!(is_prerelease_php("1.0.0-alpha"));
        assert!(is_prerelease_php("1.0.0-beta.1"));
        assert!(is_prerelease_php("1.0.0-RC1"));
        assert!(is_prerelease_php("dev-master"));
        assert!(!is_prerelease_php("1.0.0"));
        assert!(!is_prerelease_php("v2.3.4"));
    }

    #[test]
    fn test_is_prerelease_dart() {
        assert!(is_prerelease_dart("1.0.0-dev.1"));
        assert!(is_prerelease_dart("1.0.0-alpha"));
        assert!(is_prerelease_dart("1.0.0-beta.1"));
        assert!(is_prerelease_dart("1.0.0-rc.1"));
        assert!(!is_prerelease_dart("1.0.0"));
        assert!(!is_prerelease_dart("2.0.0"));
    }

    #[test]
    fn test_is_prerelease_nuget() {
        assert!(is_prerelease_nuget("1.0.0-alpha"));
        assert!(is_prerelease_nuget("1.0.0-beta.1"));
        assert!(is_prerelease_nuget("1.0.0-preview"));
        assert!(is_prerelease_nuget("1.0.0-rc.1"));
        assert!(is_prerelease_nuget("1.0.0-Alpha"));
        assert!(!is_prerelease_nuget("1.0.0"));
        assert!(!is_prerelease_nuget("2.0.0"));
    }
}
