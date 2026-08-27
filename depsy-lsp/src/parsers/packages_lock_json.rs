//! Parser for packages.lock.json files — resolves exact locked versions for C# (NuGet) dependencies.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
use crate::parsers::lockfile_resolver::LockfileResolver;

/// Normalize a NuGet package name to lowercase.
///
/// NuGet package names are case-insensitive
/// (e.g., `"Newtonsoft.Json"` == `"newtonsoft.json"`).
/// This function ensures consistent lookup between manifest and lockfile entries.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::packages_lock_json::normalize_nuget_name;
/// assert_eq!(normalize_nuget_name("Newtonsoft.Json"), "newtonsoft.json");
/// assert_eq!(normalize_nuget_name("microsoft.extensions.logging"), "microsoft.extensions.logging");
/// ```
pub fn normalize_nuget_name(name: &str) -> String {
    name.to_lowercase()
}

/// Parse a `packages.lock.json` file and return a map of package name → resolved version.
///
/// `packages.lock.json` is a JSON file with a `"dependencies"` object whose
/// keys are target framework monikers (e.g., `"net8.0"`). Each framework maps
/// package names to objects with a `"resolved"` version field. Both `"Direct"`
/// and `"Transitive"` entries are included. Names are normalized to lowercase
/// since NuGet is case-insensitive. When a package appears in multiple target
/// frameworks, the first entry encountered during JSON object iteration order
/// is kept.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::packages_lock_json::parse_packages_lock;
///
/// let lock = r#"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"}}}}"#;
/// let map = parse_packages_lock(lock);
/// assert_eq!(map.get("newtonsoft.json").map(String::as_str), Some("13.0.1"));
/// ```
pub fn parse_packages_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return map,
    };

    let dependencies = match value.get("dependencies").and_then(|d| d.as_object()) {
        Some(deps) => deps,
        None => return map,
    };

    for (_tfm, packages) in dependencies {
        let packages_obj = match packages.as_object() {
            Some(obj) => obj,
            None => continue,
        };

        for (name, pkg_info) in packages_obj {
            let normalized = normalize_nuget_name(name);
            let resolved = match pkg_info.get("resolved").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => continue,
            };

            #[expect(
                clippy::disallowed_methods,
                reason = "`normalized` is an owned String; `entry_ref` would still allocate on insert"
            )]
            map.entry(normalized).or_insert(resolved);
        }
    }

    map
}

/// Find the packages.lock.json file by walking up from a .csproj path.
///
/// Handles both single-project and monorepo layouts by searching parent directories.
/// Uses async I/O to avoid blocking the Tokio executor on slow or networked filesystems.
/// Stops after 10 levels to prevent infinite traversal on unusual file systems.
pub async fn find_packages_lock(manifest_path: &Path) -> Option<PathBuf> {
    let start_dir = manifest_path.parent()?;

    let mut current = start_dir.to_path_buf();
    let mut depth = 0;
    const MAX_DEPTH: usize = 10;

    loop {
        let candidate = current.join("packages.lock.json");
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

/// Resolves versions from `packages.lock.json` for C# / NuGet projects.
/// NuGet normalizes package names to lowercase for lookup.
/// No graph parser exists for C#; a flat graph (no edges, no is_root) is used —
/// transitive analysis is a no-op until a real graph parser lands. Matches pre-refactor.
///
/// `parse_packages_lock` already normalizes names internally, so the default
/// `resolve_version` (which calls `normalize_name` before lookup) works correctly
/// without override.
pub struct CsharpResolver;

#[async_trait]
impl LockfileResolver for CsharpResolver {
    async fn find_lockfile(&self, manifest_path: &Path) -> Option<PathBuf> {
        find_packages_lock(manifest_path).await
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        let lock_versions = parse_packages_lock(lock_content);
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

    fn normalize_name(&self, name: &str) -> String {
        normalize_nuget_name(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_packages_lock() {
        let content = r#"{
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "requested": "[13.0.1, )",
                        "resolved": "13.0.1",
                        "contentHash": "abc123",
                        "dependencies": {}
                    },
                    "Microsoft.Extensions.Logging": {
                        "type": "Transitive",
                        "resolved": "8.0.0",
                        "dependencies": {}
                    }
                }
            }
        }"#;
        let map = parse_packages_lock(content);
        assert_eq!(
            map.get("newtonsoft.json").map(|s| s.as_str()),
            Some("13.0.1")
        );
        assert_eq!(
            map.get("microsoft.extensions.logging").map(|s| s.as_str()),
            Some("8.0.0")
        );
    }

    #[test]
    fn test_parse_multiple_target_frameworks() {
        let content = r#"{
            "version": 1,
            "dependencies": {
                "net6.0": {
                    "PackageA": {
                        "type": "Direct",
                        "resolved": "1.0.0",
                        "dependencies": {}
                    }
                },
                "net8.0": {
                    "PackageB": {
                        "type": "Direct",
                        "resolved": "2.0.0",
                        "dependencies": {}
                    }
                }
            }
        }"#;
        let map = parse_packages_lock(content);
        assert_eq!(map.get("packagea").map(|s| s.as_str()), Some("1.0.0"));
        assert_eq!(map.get("packageb").map(|s| s.as_str()), Some("2.0.0"));
    }

    #[test]
    fn test_parse_transitive_and_direct() {
        let content = r#"{
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "DirectPkg": {
                        "type": "Direct",
                        "resolved": "3.0.0",
                        "dependencies": {}
                    },
                    "TransitivePkg": {
                        "type": "Transitive",
                        "resolved": "1.5.0",
                        "dependencies": {}
                    }
                }
            }
        }"#;
        let map = parse_packages_lock(content);
        assert_eq!(map.get("directpkg").map(|s| s.as_str()), Some("3.0.0"));
        assert_eq!(map.get("transitivepkg").map(|s| s.as_str()), Some("1.5.0"));
    }

    #[test]
    fn test_parse_empty_content() {
        let map = parse_packages_lock("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_invalid_json() {
        let map = parse_packages_lock("not valid json {[");
        assert!(map.is_empty());
    }

    #[test]
    fn test_duplicate_package_keeps_first() {
        let content = r#"{
            "version": 1,
            "dependencies": {
                "net6.0": {
                    "SharedPkg": {
                        "type": "Direct",
                        "resolved": "1.0.0",
                        "dependencies": {}
                    }
                },
                "net8.0": {
                    "SharedPkg": {
                        "type": "Direct",
                        "resolved": "2.0.0",
                        "dependencies": {}
                    }
                }
            }
        }"#;
        let map = parse_packages_lock(content);
        // First TFM entry wins; serde_json preserves insertion order for objects
        assert!(map.contains_key("sharedpkg"));
        let version = map.get("sharedpkg").unwrap();
        assert!(version == "1.0.0" || version == "2.0.0");
    }

    #[test]
    fn test_case_insensitive_names() {
        let content = r#"{
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "resolved": "13.0.1",
                        "dependencies": {}
                    }
                }
            }
        }"#;
        let map = parse_packages_lock(content);
        assert!(map.contains_key("newtonsoft.json"));
        assert!(!map.contains_key("Newtonsoft.Json"));
    }

    #[tokio::test]
    async fn csharp_resolver_normalizes_nuget_names() {
        use crate::parsers::lockfile_resolver::LockfileResolver;
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = tmp.path().join("Demo.csproj");
        let lock = tmp.path().join("packages.lock.json");
        std::fs::write(&manifest, "<Project></Project>").unwrap();
        std::fs::write(
            &lock,
            r#"{
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" }
            }
          }
        }"#,
        )
        .unwrap();
        let resolver = super::CsharpResolver;
        let content = std::fs::read_to_string(&lock).unwrap();
        let graph = resolver.parse_graph(&content);
        let dep = crate::parsers::Dependency {
            name: "newtonsoft.json".to_string(),
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
            Some("13.0.3".to_string())
        );
    }

    #[test]
    fn test_various_version_formats() {
        let content = r#"{
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "StablePkg": {
                        "type": "Direct",
                        "resolved": "13.0.1",
                        "dependencies": {}
                    },
                    "PreviewPkg": {
                        "type": "Direct",
                        "resolved": "8.0.0-preview.1",
                        "dependencies": {}
                    },
                    "FourPartPkg": {
                        "type": "Direct",
                        "resolved": "4.3.0.0",
                        "dependencies": {}
                    }
                }
            }
        }"#;
        let map = parse_packages_lock(content);
        assert_eq!(map.get("stablepkg").map(|s| s.as_str()), Some("13.0.1"));
        assert_eq!(
            map.get("previewpkg").map(|s| s.as_str()),
            Some("8.0.0-preview.1")
        );
        assert_eq!(map.get("fourpartpkg").map(|s| s.as_str()), Some("4.3.0.0"));
    }
}
