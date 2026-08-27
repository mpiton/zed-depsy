//! Parser for pubspec.lock files — resolves exact locked versions for Dart (pub) dependencies.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
use crate::parsers::lockfile_resolver::LockfileResolver;

/// Parse a `pubspec.lock` file and return a map of package name → resolved version.
///
/// `pubspec.lock` is a YAML file with a `packages:` top-level section.
/// Each package name appears at 2-space indent, ending with `:`.
/// The version is at 4-space indent: `    version: "X.Y.Z"`.
/// Quotes around version values are stripped.
/// Dart package names are case-sensitive — no normalization is applied.
/// When a package appears multiple times, the first entry is kept.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::pubspec_lock::parse_pubspec_lock;
///
/// let lock = "packages:\n  http:\n    source: hosted\n    version: \"1.2.0\"\n";
/// let map = parse_pubspec_lock(lock);
/// assert_eq!(map.get("http").map(String::as_str), Some("1.2.0"));
/// ```
pub fn parse_pubspec_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut in_packages = false;
    let mut current_package: Option<String> = None;

    for line in content.lines() {
        // Top-level key (no leading whitespace): switch section tracking
        if !line.starts_with(' ') {
            in_packages = line.starts_with("packages:");
            current_package = None;
            continue;
        }

        if !in_packages {
            continue;
        }

        // Package name at exactly 2-space indent: "  <name>:"
        if line.starts_with("  ") && !line.starts_with("   ") {
            let trimmed = line.trim();
            if let Some(name) = trimmed.strip_suffix(':') {
                current_package = Some(name.to_string());
            }
            continue;
        }

        // Version at exactly 4-space indent: "    version: ..."
        if line.starts_with("    ")
            && !line.starts_with("     ")
            && let Some(pkg) = current_package.as_deref()
            && let Some(rest) = line.trim().strip_prefix("version:")
        {
            let version = rest.trim().trim_matches('"');
            if !version.is_empty() {
                map.entry_ref(pkg).or_insert_with(|| version.to_owned());
            }
        }
    }

    map
}

/// Find the pubspec.lock file co-located with a pubspec.yaml manifest.
///
/// Unlike Composer or npm, Dart's `pub` tool always places `pubspec.lock` in the
/// same directory as `pubspec.yaml`. Each Dart package has its own independent
/// lockfile, so walking up parent directories would risk resolving versions from
/// a different package in a monorepo layout.
/// Uses async I/O to avoid blocking the Tokio executor on slow or networked filesystems.
pub async fn find_pubspec_lock(manifest_path: &Path) -> Option<PathBuf> {
    let candidate = manifest_path.parent()?.join("pubspec.lock");
    if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
        Some(candidate)
    } else {
        None
    }
}

/// Resolves versions from `pubspec.lock` for Dart projects.
/// pubspec.lock uses identity normalization (case-sensitive package names).
/// No graph parser exists for Dart; `parse_graph` builds a flat graph
/// (no edges, no is_root) — transitive analysis is a no-op until a real
/// graph parser lands. Matches pre-refactor behavior.
pub struct DartResolver;

#[async_trait]
impl LockfileResolver for DartResolver {
    async fn find_lockfile(&self, manifest_path: &Path) -> Option<PathBuf> {
        find_pubspec_lock(manifest_path).await
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        let lock_versions = parse_pubspec_lock(lock_content);
        LockfileGraph {
            packages: lock_versions
                .into_iter()
                .map(|(name, version)| LockfilePackage {
                    name,
                    version,
                    dependencies: Vec::new(),
                    is_root: false,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dart_resolver_resolves_simple_pubspec_lock() {
        use crate::parsers::lockfile_resolver::LockfileResolver;
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = tmp.path().join("pubspec.yaml");
        let lock = tmp.path().join("pubspec.lock");
        std::fs::write(&manifest, "name: demo\nversion: 0.1.0\n").unwrap();
        std::fs::write(
            &lock,
            r#"packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
"#,
        )
        .unwrap();
        let resolver = super::DartResolver;
        assert_eq!(
            resolver.find_lockfile(&manifest).await.as_deref(),
            Some(lock.as_path())
        );
        let content = std::fs::read_to_string(&lock).unwrap();
        let graph = resolver.parse_graph(&content);
        let dep = crate::parsers::Dependency {
            name: "http".to_string(),
            version: "^1.0.0".to_string(),
            name_span: crate::parsers::Span {
                line: 0,
                line_start: 0,
                line_end: 0,
            },
            version_span: crate::parsers::Span {
                line: 0,
                line_start: 0,
                line_end: 0,
            },
            dev: false,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        };
        assert_eq!(
            resolver.resolve_version(&dep, &graph),
            Some("1.2.0".to_string())
        );
    }

    #[test]
    fn test_parse_simple_pubspec_lock() {
        let content = r#"packages:
  http:
    dependency: direct main
    description:
      name: http
      sha256: "abc123"
      url: "https://pub.dev"
    source: hosted
    version: "1.1.0"
  path:
    dependency: direct main
    description:
      name: path
      sha256: "def456"
      url: "https://pub.dev"
    source: hosted
    version: "1.9.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
"#;
        let map = parse_pubspec_lock(content);
        assert_eq!(map.get("http").map(|s| s.as_str()), Some("1.1.0"));
        assert_eq!(map.get("path").map(|s| s.as_str()), Some("1.9.0"));
        assert!(!map.contains_key("dart"));
    }

    #[test]
    fn test_parse_sdk_source() {
        let content = r#"packages:
  flutter:
    dependency: direct main
    description: flutter
    source: sdk
    version: "0.0.0"
"#;
        let map = parse_pubspec_lock(content);
        assert_eq!(map.get("flutter").map(|s| s.as_str()), Some("0.0.0"));
    }

    #[test]
    fn test_parse_git_source() {
        let content = r#"packages:
  my_package:
    dependency: direct main
    description:
      path: "."
      ref: main
      resolved-ref: "abc123def456"
      url: "https://github.com/example/my_package.git"
    source: git
    version: "2.0.0"
"#;
        let map = parse_pubspec_lock(content);
        assert_eq!(map.get("my_package").map(|s| s.as_str()), Some("2.0.0"));
    }

    #[test]
    fn test_parse_path_source() {
        let content = r#"packages:
  local_lib:
    dependency: direct main
    description:
      path: "../local_lib"
      relative: true
    source: path
    version: "0.1.0"
"#;
        let map = parse_pubspec_lock(content);
        assert_eq!(map.get("local_lib").map(|s| s.as_str()), Some("0.1.0"));
    }

    #[test]
    fn test_parse_empty_content() {
        let map = parse_pubspec_lock("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_malformed_content() {
        let map = parse_pubspec_lock("}{not valid content at all}}{{");
        assert!(map.is_empty());
    }

    #[test]
    fn test_version_at_wrong_indent_ignored() {
        let content = r#"packages:
  http:
    dependency: direct main
    source: hosted
     version: "1.0.0"
"#;
        // version at 5-space indent (wrong) should be ignored
        let map = parse_pubspec_lock(content);
        assert!(map.is_empty());
    }

    #[test]
    fn test_package_without_version_omitted() {
        let content = r#"packages:
  incomplete_pkg:
    dependency: direct main
    source: hosted
  complete_pkg:
    dependency: direct main
    source: hosted
    version: "1.0.0"
"#;
        let map = parse_pubspec_lock(content);
        assert!(!map.contains_key("incomplete_pkg"));
        assert_eq!(map.get("complete_pkg").map(|s| s.as_str()), Some("1.0.0"));
    }

    #[test]
    fn test_duplicate_package_keeps_first() {
        let content = r#"packages:
  http:
    dependency: direct main
    source: hosted
    version: "1.0.0"
  http:
    dependency: transitive
    source: hosted
    version: "2.0.0"
"#;
        let map = parse_pubspec_lock(content);
        assert_eq!(map.get("http").map(|s| s.as_str()), Some("1.0.0"));
    }

    #[test]
    fn test_various_version_formats() {
        let content = r#"packages:
  stable_pkg:
    dependency: direct main
    source: hosted
    version: "1.2.3"
  prerelease_pkg:
    dependency: direct main
    source: hosted
    version: "2.0.0-beta.1"
  dev_pkg:
    dependency: direct dev
    source: hosted
    version: "0.0.1+hotfix.1"
"#;
        let map = parse_pubspec_lock(content);
        assert_eq!(map.get("stable_pkg").map(|s| s.as_str()), Some("1.2.3"));
        assert_eq!(
            map.get("prerelease_pkg").map(|s| s.as_str()),
            Some("2.0.0-beta.1")
        );
        assert_eq!(
            map.get("dev_pkg").map(|s| s.as_str()),
            Some("0.0.1+hotfix.1")
        );
    }
}
