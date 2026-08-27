//! Parser for composer.lock files — resolves exact locked versions for PHP (Composer) dependencies.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
use crate::parsers::lockfile_resolver::LockfileResolver;

/// Normalize a Composer package name to lowercase.
///
/// Composer package names are case-insensitive
/// (e.g., `"Vendor/Package"` == `"vendor/package"`).
/// This function ensures consistent lookup between manifest and lockfile entries.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::composer_lock::normalize_composer_name;
/// assert_eq!(normalize_composer_name("Vendor/Package"), "vendor/package");
/// assert_eq!(normalize_composer_name("symfony/console"), "symfony/console");
/// ```
pub fn normalize_composer_name(name: &str) -> String {
    name.to_lowercase()
}

/// Parse a `composer.lock` file and return a map of package name → resolved version.
///
/// `composer.lock` is a JSON file with `"packages"` and `"packages-dev"` arrays.
/// Each entry has `"name"` and `"version"` fields.
/// Names are normalized to lowercase since Composer is case-insensitive.
/// Versions with a `v` prefix (e.g., `"v3.2.0"`) are stored as-is since both
/// the Packagist API and `composer.lock` use the same format per package.
/// When a package appears multiple times, the first entry is kept.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::composer_lock::parse_composer_lock;
///
/// let lock = r#"{"packages":[{"name":"symfony/console","version":"v6.0.0"}],"packages-dev":[]}"#;
/// let map = parse_composer_lock(lock);
/// assert_eq!(map.get("symfony/console").map(String::as_str), Some("v6.0.0"));
/// ```
pub fn parse_composer_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return map,
    };

    for key in &["packages", "packages-dev"] {
        let packages = match value.get(*key).and_then(|p| p.as_array()) {
            Some(pkgs) => pkgs,
            None => continue,
        };

        for pkg in packages {
            let name = match pkg.get("name").and_then(|n| n.as_str()) {
                Some(n) => normalize_composer_name(n),
                None => continue,
            };
            let version = match pkg.get("version").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => continue,
            };

            #[expect(
                clippy::disallowed_methods,
                reason = "`name` is an owned String; `entry_ref` would still allocate on insert"
            )]
            map.entry(name).or_insert(version);
        }
    }

    map
}

/// Parse composer.lock into a full dependency graph. Includes both `packages` and `packages-dev`.
/// Skips platform requires (`php`, `ext-*`).
pub fn parse_composer_lock_graph(content: &str) -> LockfileGraph {
    let mut graph = LockfileGraph::default();
    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return graph,
    };

    for key in &["packages", "packages-dev"] {
        let Some(arr) = value.get(key).and_then(|p| p.as_array()) else {
            continue;
        };
        for entry in arr {
            let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let mut deps: Vec<String> = Vec::new();
            if let Some(req) = entry.get("require").and_then(|r| r.as_object()) {
                for dep_name in req.keys() {
                    if dep_name != "php" && !dep_name.starts_with("ext-") {
                        deps.push(normalize_composer_name(dep_name));
                    }
                }
            }
            graph.packages.push(LockfilePackage {
                name: normalize_composer_name(name),
                version: version.to_string(),
                dependencies: deps,
                is_root: false,
            });
        }
    }

    graph
}

/// Find the composer.lock file by walking up from a composer.json path.
///
/// Handles both single-project and monorepo layouts by searching parent directories.
/// Uses async I/O to avoid blocking the Tokio executor on slow or networked filesystems.
/// Stops after 10 levels to prevent infinite traversal on unusual file systems.
pub async fn find_composer_lock(manifest_path: &Path) -> Option<PathBuf> {
    let start_dir = manifest_path.parent()?;

    let mut current = start_dir.to_path_buf();
    let mut depth = 0;
    const MAX_DEPTH: usize = 10;

    loop {
        let candidate = current.join("composer.lock");
        if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
            return Some(candidate);
        }

        depth += 1;
        if depth >= MAX_DEPTH {
            return None;
        }

        current = current.parent()?.to_path_buf();
    }
}

/// Resolves versions from `composer.lock` for PHP projects.
/// Composer normalizes package names to lowercase (Vendor/Package → vendor/package).
/// `parse_composer_lock_graph` already normalizes internally, so the default
/// `resolve_version` (which compares normalized dep name against stored names) works correctly.
pub struct PhpResolver;

#[async_trait]
impl LockfileResolver for PhpResolver {
    async fn find_lockfile(&self, manifest_path: &Path) -> Option<PathBuf> {
        find_composer_lock(manifest_path).await
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        parse_composer_lock_graph(lock_content)
    }

    fn normalize_name(&self, name: &str) -> String {
        normalize_composer_name(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_composer_lock() {
        let content = r#"{
            "packages": [
                {"name": "vendor/package-a", "version": "1.2.3"},
                {"name": "vendor/package-b", "version": "4.5.6"}
            ],
            "packages-dev": []
        }"#;
        let map = parse_composer_lock(content);
        assert_eq!(
            map.get("vendor/package-a").map(|s| s.as_str()),
            Some("1.2.3")
        );
        assert_eq!(
            map.get("vendor/package-b").map(|s| s.as_str()),
            Some("4.5.6")
        );
    }

    #[test]
    fn test_parse_packages_dev() {
        let content = r#"{
            "packages": [
                {"name": "vendor/package-a", "version": "1.0.0"}
            ],
            "packages-dev": [
                {"name": "vendor/dev-tool", "version": "2.0.0"}
            ]
        }"#;
        let map = parse_composer_lock(content);
        assert_eq!(
            map.get("vendor/package-a").map(|s| s.as_str()),
            Some("1.0.0")
        );
        assert_eq!(
            map.get("vendor/dev-tool").map(|s| s.as_str()),
            Some("2.0.0")
        );
    }

    #[test]
    fn test_parse_empty_content() {
        let map = parse_composer_lock("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_empty_arrays() {
        let content = r#"{"packages":[],"packages-dev":[]}"#;
        let map = parse_composer_lock(content);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_invalid_json() {
        let map = parse_composer_lock("not valid json {[");
        assert!(map.is_empty());
    }

    #[test]
    fn test_duplicate_package_keeps_first() {
        let content = r#"{
            "packages": [
                {"name": "vendor/package", "version": "1.0.0"},
                {"name": "vendor/package", "version": "2.0.0"}
            ],
            "packages-dev": []
        }"#;
        let map = parse_composer_lock(content);
        assert_eq!(map.get("vendor/package").map(|s| s.as_str()), Some("1.0.0"));
    }

    #[test]
    fn test_case_insensitive_names() {
        let content = r#"{
            "packages": [
                {"name": "Vendor/Package", "version": "1.0.0"}
            ],
            "packages-dev": []
        }"#;
        let map = parse_composer_lock(content);
        assert!(map.contains_key("vendor/package"));
        assert!(!map.contains_key("Vendor/Package"));
    }

    #[test]
    fn test_various_version_formats() {
        let content = r#"{
            "packages": [
                {"name": "vendor/stable", "version": "1.2.3"},
                {"name": "vendor/prefixed", "version": "v3.2.0"},
                {"name": "vendor/dev", "version": "dev-master"}
            ],
            "packages-dev": []
        }"#;
        let map = parse_composer_lock(content);
        assert_eq!(map.get("vendor/stable").map(|s| s.as_str()), Some("1.2.3"));
        assert_eq!(
            map.get("vendor/prefixed").map(|s| s.as_str()),
            Some("v3.2.0")
        );
        assert_eq!(
            map.get("vendor/dev").map(|s| s.as_str()),
            Some("dev-master")
        );
    }

    #[test]
    fn test_parse_composer_lock_graph() {
        let content = r#"{
  "packages": [
    {
      "name": "symfony/console",
      "version": "v6.0.0",
      "require": { "symfony/polyfill-php80": "^1.16", "php": ">=8.0" }
    },
    { "name": "symfony/polyfill-php80", "version": "v1.27.0", "require": { "ext-mbstring": "*" } }
  ],
  "packages-dev": []
}"#;
        let graph = parse_composer_lock_graph(content);
        assert_eq!(graph.packages.len(), 2);
        let console = graph
            .packages
            .iter()
            .find(|p| p.name == "symfony/console")
            .unwrap();
        assert!(
            console
                .dependencies
                .contains(&"symfony/polyfill-php80".to_string())
        );
        assert!(!console.dependencies.iter().any(|d| d == "php"));
        let polyfill = graph
            .packages
            .iter()
            .find(|p| p.name == "symfony/polyfill-php80")
            .unwrap();
        assert!(!polyfill.dependencies.iter().any(|d| d.starts_with("ext-")));
    }

    #[tokio::test]
    async fn php_resolver_normalizes_composer_names() {
        use crate::parsers::lockfile_resolver::LockfileResolver;
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = tmp.path().join("composer.json");
        let lock = tmp.path().join("composer.lock");
        std::fs::write(&manifest, "{}").unwrap();
        std::fs::write(
            &lock,
            r#"{
          "packages": [
            { "name": "Vendor/Package", "version": "1.2.3" }
          ]
        }"#,
        )
        .unwrap();
        let resolver = super::PhpResolver;
        assert_eq!(
            resolver.find_lockfile(&manifest).await.as_deref(),
            Some(lock.as_path())
        );
        let content = std::fs::read_to_string(&lock).unwrap();
        let graph = resolver.parse_graph(&content);
        let dep = crate::parsers::Dependency {
            name: "VENDOR/Package".to_string(),
            version: "*".to_string(),
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
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn test_parse_composer_lock_graph_normalizes_names() {
        let content = r#"{
  "packages": [
    {
      "name": "Vendor/Package",
      "version": "1.0.0",
      "require": { "Dep/Other": "^1.0" }
    },
    { "name": "Dep/Other", "version": "1.2.3" }
  ],
  "packages-dev": []
}"#;
        let graph = parse_composer_lock_graph(content);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(
            names.contains(&"vendor/package"),
            "main name should be lowercased, got {names:?}"
        );
        assert!(names.contains(&"dep/other"));
        let vp = graph
            .packages
            .iter()
            .find(|p| p.name == "vendor/package")
            .unwrap();
        assert!(
            vp.dependencies.contains(&"dep/other".to_string()),
            "require names must also be normalized, got {:?}",
            vp.dependencies
        );
    }
}
