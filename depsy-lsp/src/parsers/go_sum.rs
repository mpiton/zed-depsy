//! Parser for Go sum files (go.sum) — resolves exact locked versions for Go dependencies.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::parsers::Dependency;
use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
use crate::parsers::lockfile_resolver::LockfileResolver;

/// Parse a `go.sum` file and return a map of module path → all observed versions.
///
/// `go.sum` format: `<module> <version>[/go.mod] <hash>`
///
/// Lines whose version string ends with `/go.mod` are skipped to avoid
/// duplicates with the matching tree-hash line; every other entry contributes
/// a version regardless of its hash prefix (typically `h1:`, but the parser
/// does not inspect or validate the hash type).
///
/// Go 1.17+ with lazy module loading may record multiple versions of the same
/// module (direct + transitive at different versions). All non-`/go.mod`
/// versions are collected so the caller can choose the right one.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::go_sum::parse_go_sum;
///
/// let sum = "github.com/pkg/errors v0.9.1 h1:abc=\n\
///            github.com/pkg/errors v0.9.1/go.mod h1:def=\n";
/// let map = parse_go_sum(sum);
/// // /go.mod line is skipped; the tree-hash line contributes the version.
/// assert_eq!(map.get("github.com/pkg/errors").unwrap().as_slice(), &["v0.9.1"]);
/// ```
pub fn parse_go_sum(content: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Split: module version hash
        let mut parts = trimmed.splitn(3, ' ');
        let module = match parts.next() {
            Some(m) if !m.is_empty() => m,
            _ => continue,
        };
        let version = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        // Skip /go.mod entries (duplicate of the module entry)
        if version.ends_with("/go.mod") {
            continue;
        }

        map.entry_ref(module).or_default().push(version.to_string());
    }

    map
}

/// Find the go.sum file co-located with a go.mod path.
///
/// Unlike Cargo workspaces (where Cargo.lock lives at the workspace root above member
/// Cargo.toml files), Go modules always place go.sum in the same directory as go.mod.
/// Therefore we only check the immediate directory — no upward traversal needed.
///
/// Uses async I/O to avoid blocking the Tokio executor.
pub async fn find_go_sum(go_mod_path: &Path) -> Option<PathBuf> {
    let candidate = go_mod_path.parent()?.join("go.sum");
    if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
        Some(candidate)
    } else {
        None
    }
}

/// Resolves versions from `go.sum` for Go modules. Unlike other ecosystems,
/// `go.sum` may list multiple versions for the same module (test deps, transitive
/// versions). `resolve_version` is overridden to honor that semantic:
/// prefer `dep.version` if present among candidates, fall back to the sole
/// candidate when only one exists, otherwise leave unresolved (avoid guessing).
pub struct GoResolver;

#[async_trait]
impl LockfileResolver for GoResolver {
    async fn find_lockfile(&self, manifest_path: &Path) -> Option<PathBuf> {
        find_go_sum(manifest_path).await
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        let lock_versions = parse_go_sum(lock_content);
        let mut packages = Vec::new();
        for (name, versions) in &lock_versions {
            for version in versions {
                packages.push(LockfilePackage {
                    name: name.clone(),
                    version: version.clone(),
                    dependencies: Vec::new(),
                    is_root: false,
                });
            }
        }
        LockfileGraph { packages }
    }

    fn resolve_version(&self, dep: &Dependency, graph: &LockfileGraph) -> Option<String> {
        // Deduplicate so identical version strings (e.g., the same module listed
        // twice in go.sum because of separate /go.mod and h1: entries handled
        // upstream, or upstream parsing quirks) do not inflate the candidate
        // count and force the "ambiguous" branch when only one unique version
        // actually exists.
        let mut unique: Vec<&str> = Vec::new();
        for p in graph.packages.iter().filter(|p| p.name == dep.name) {
            let v = p.version.as_str();
            if !unique.contains(&v) {
                unique.push(v);
            }
        }
        if unique.iter().any(|v| *v == dep.version) {
            Some(dep.version.clone())
        } else if unique.len() == 1 {
            Some(unique[0].to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_go_sum() {
        let content = "\
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=
golang.org/x/text v0.14.0/go.mod h1:18ZOQIKpY8NJVqYksKHtTdi31H5itFRjB5/qKTNYzSU=
";
        let map = parse_go_sum(content);
        assert_eq!(map.get("github.com/pkg/errors").unwrap(), &["v0.9.1"]);
        assert_eq!(map.get("golang.org/x/text").unwrap(), &["v0.14.0"]);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_skips_go_mod_entries() {
        let content = "\
github.com/foo/bar v1.2.3/go.mod h1:abc=
";
        let map = parse_go_sum(content);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_empty_content() {
        let map = parse_go_sum("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_blank_lines() {
        let content =
            "\ngithub.com/pkg/errors v0.9.1 h1:abc=\n\ngolang.org/x/text v0.14.0 h1:def=\n\n";
        let map = parse_go_sum(content);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("github.com/pkg/errors").unwrap(), &["v0.9.1"]);
        assert_eq!(map.get("golang.org/x/text").unwrap(), &["v0.14.0"]);
    }

    #[test]
    fn test_parse_malformed_lines() {
        let content = "\
onlymodule
github.com/valid/module v1.0.0 h1:abc=
";
        let map = parse_go_sum(content);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("github.com/valid/module").unwrap(), &["v1.0.0"]);
    }

    #[test]
    fn test_parse_single_module() {
        let content = "github.com/stretchr/testify v1.8.4 h1:xyz=\n";
        let map = parse_go_sum(content);
        assert_eq!(map.get("github.com/stretchr/testify").unwrap(), &["v1.8.4"]);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_duplicate_module_collects_all_versions() {
        let content = "\
github.com/foo/bar v1.0.0 h1:abc=
github.com/foo/bar v1.1.0 h1:def=
";
        let map = parse_go_sum(content);
        assert_eq!(
            map.get("github.com/foo/bar").unwrap(),
            &["v1.0.0", "v1.1.0"]
        );
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_parse_gopkg_in_module() {
        let content = "\
gopkg.in/yaml.v3 v3.0.1 h1:abc=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:def=
";
        let map = parse_go_sum(content);
        assert_eq!(map.get("gopkg.in/yaml.v3").unwrap(), &["v3.0.1"]);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_parse_go_uber_org() {
        let content = "\
go.uber.org/zap v1.27.0 h1:abc=
go.uber.org/zap v1.27.0/go.mod h1:def=
";
        let map = parse_go_sum(content);
        assert_eq!(map.get("go.uber.org/zap").unwrap(), &["v1.27.0"]);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_parse_prerelease_version() {
        let content = "\
golang.org/x/sys v0.0.0-20230101000000-abcdef012345 h1:abc=
golang.org/x/sys v0.0.0-20230101000000-abcdef012345/go.mod h1:def=
";
        let map = parse_go_sum(content);
        assert_eq!(
            map.get("golang.org/x/sys").unwrap(),
            &["v0.0.0-20230101000000-abcdef012345"]
        );
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_parse_module_only_go_mod_line() {
        // Module with ONLY /go.mod entry should NOT appear in the map
        let content = "\
github.com/only/gomod v1.0.0/go.mod h1:abc=
";
        let map = parse_go_sum(content);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_no_hash() {
        // go.sum requires 3 fields (module version hash), but the parser is lenient:
        // lines with only module and version are accepted rather than rejected,
        // since the hash is not used for version resolution.
        let content = "\
github.com/foo/bar v1.0.0
";
        let map = parse_go_sum(content);
        assert_eq!(map.get("github.com/foo/bar").unwrap(), &["v1.0.0"]);
    }

    #[tokio::test]
    async fn go_resolver_prefers_dep_version_when_present_in_candidates() {
        use crate::parsers::lockfile_resolver::LockfileResolver;
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = tmp.path().join("go.mod");
        let lock = tmp.path().join("go.sum");
        std::fs::write(&manifest, "module example.com/demo\n").unwrap();
        std::fs::write(
            &lock,
            "github.com/foo/bar v1.0.0 h1:hash1=\n\
             github.com/foo/bar v1.1.0 h1:hash2=\n\
             github.com/baz/qux v0.5.0 h1:hash3=\n",
        )
        .unwrap();
        let resolver = super::GoResolver;
        assert_eq!(
            resolver.find_lockfile(&manifest).await.as_deref(),
            Some(lock.as_path())
        );
        let content = std::fs::read_to_string(&lock).unwrap();
        let graph = resolver.parse_graph(&content);

        // Case 1: dep.version matches one of the candidates → prefer it
        let dep_with_match = crate::parsers::Dependency {
            name: "github.com/foo/bar".to_string(),
            version: "v1.1.0".to_string(),
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
            resolver.resolve_version(&dep_with_match, &graph),
            Some("v1.1.0".to_string())
        );

        // Case 2: single candidate, dep.version differs → auto-select sole candidate
        let dep_single = crate::parsers::Dependency {
            name: "github.com/baz/qux".to_string(),
            version: "v0.4.0".to_string(),
            ..dep_with_match.clone()
        };
        assert_eq!(
            resolver.resolve_version(&dep_single, &graph),
            Some("v0.5.0".to_string())
        );

        // Case 3: ambiguous candidates without exact match → None
        let dep_ambiguous = crate::parsers::Dependency {
            name: "github.com/foo/bar".to_string(),
            version: "v0.0.1".to_string(),
            ..dep_with_match
        };
        assert_eq!(resolver.resolve_version(&dep_ambiguous, &graph), None);
    }

    /// Regression: identical duplicate versions in go.sum (e.g., from /go.mod
    /// echoes parsed twice or repeated h1: hash lines) must not inflate the
    /// candidate count and force the "ambiguous → None" branch when the unique
    /// version count is in fact 1.
    #[tokio::test]
    async fn go_resolver_dedupes_identical_candidates_before_ambiguity_check() {
        let graph = LockfileGraph {
            packages: vec![
                LockfilePackage {
                    name: "github.com/foo/bar".to_string(),
                    version: "v1.0.0".to_string(),
                    dependencies: Vec::new(),
                    is_root: false,
                },
                LockfilePackage {
                    name: "github.com/foo/bar".to_string(),
                    version: "v1.0.0".to_string(),
                    dependencies: Vec::new(),
                    is_root: false,
                },
            ],
        };
        let dep = crate::parsers::Dependency {
            name: "github.com/foo/bar".to_string(),
            version: "v0.9.0".to_string(),
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
        // Two identical entries collapse to one unique candidate → return it.
        assert_eq!(
            super::GoResolver.resolve_version(&dep, &graph),
            Some("v1.0.0".to_string())
        );
    }
}
