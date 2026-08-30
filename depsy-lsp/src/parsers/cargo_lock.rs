//! Parser for Cargo.lock files — resolves exact locked versions for Cargo dependencies.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::parsers::Dependency;
use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
use crate::parsers::lockfile_resolver::LockfileResolver;

/// Parse a Cargo.lock file and return a map of package name → resolved version.
///
/// Cargo.lock uses `[[package]]` TOML array-of-tables entries with `name` and
/// `version` fields. When multiple versions of the same package exist, the
/// first entry is kept by default.
///
/// If `root_package` is provided, the root package's `dependencies` list is
/// used to disambiguate: Cargo writes `"crate_name version"` (with version)
/// in the dependencies array when multiple versions exist, so the version
/// referenced by the root package takes precedence over the first-found entry.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::cargo_lock::parse_cargo_lock;
///
/// let lock = r#"
/// [[package]]
/// name = "serde"
/// version = "1.0.195"
///
/// [[package]]
/// name = "tokio"
/// version = "1.36.0"
/// "#;
/// let map = parse_cargo_lock(lock, None);
/// assert_eq!(map.get("serde").map(String::as_str), Some("1.0.195"));
/// assert_eq!(map.get("tokio").map(String::as_str), Some("1.36.0"));
/// ```
pub fn parse_cargo_lock(content: &str, root_package: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let value: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(_) => return map,
    };

    let packages = match value.get("package").and_then(|p| p.as_array()) {
        Some(pkgs) => pkgs,
        None => return map,
    };

    for pkg in packages {
        let name = match pkg.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let version = match pkg.get("version").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => continue,
        };

        // Keep the first entry when multiple versions exist
        #[expect(
            clippy::disallowed_methods,
            reason = "`name` is an owned String; `entry_ref` would still allocate on insert"
        )]
        map.entry(name).or_insert(version);
    }

    // Disambiguate multi-version deps using the root package's dependency list.
    // When multiple versions exist, Cargo writes "crate_name version" (with a space) in the
    // dependencies array, allowing us to override the first-found version with the correct one.
    // Old Cargo.lock v1 may use "crate_name version (source_url)" — we strip the source suffix.
    if let Some(root_name) = root_package
        && let Some(root_pkg) = packages
            .iter()
            .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(root_name))
        && let Some(deps) = root_pkg.get("dependencies").and_then(|d| d.as_array())
    {
        for dep_entry in deps {
            if let Some(dep_str) = dep_entry.as_str() {
                let mut parts = dep_str.splitn(2, ' ');
                if let (Some(crate_name), Some(version_part)) = (parts.next(), parts.next()) {
                    // Strip v1 source suffix: "1.0.0 (registry+...)" → "1.0.0"
                    let version = version_part.split(' ').next().unwrap_or(version_part);
                    map.insert(crate_name.to_string(), version.to_string());
                }
            }
        }
    }

    map
}

/// Parse `Cargo.lock` into a full [`LockfileGraph`].
///
/// Dependency strings are stored as-is (e.g. `"serde"` or `"serde 1.0.195"`).
/// Cargo writes the version suffix when multiple versions of the same crate
/// are locked; preserving it allows correct transitive attribution. Graph-walk
/// code strips the version suffix when resolving edges.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::cargo_lock::parse_cargo_lock_graph;
///
/// let lock = r#"
/// [[package]]
/// name = "demo"
/// version = "0.1.0"
/// dependencies = ["serde"]
///
/// [[package]]
/// name = "serde"
/// version = "1.0.195"
/// "#;
/// let graph = parse_cargo_lock_graph(lock);
/// assert_eq!(graph.packages.len(), 2);
/// assert!(graph.packages.iter().any(|p| p.name == "serde"));
/// ```
pub fn parse_cargo_lock_graph(content: &str) -> LockfileGraph {
    let mut graph = LockfileGraph::default();

    let value: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(_) => return graph,
    };

    let packages = match value.get("package").and_then(|p| p.as_array()) {
        Some(pkgs) => pkgs,
        None => return graph,
    };

    for pkg in packages {
        let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        let deps = pkg
            .get("dependencies")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        graph.packages.push(LockfilePackage {
            name: name.to_string(),
            version: version.to_string(),
            dependencies: deps,
            is_root: false,
        });
    }

    graph
}

/// Find the `Cargo.lock` file by walking up from a `Cargo.toml` path.
///
/// Handles both single-crate and workspace layouts by searching parent
/// directories. Stops after 10 levels to prevent unbounded traversal.
///
/// Uses async I/O to avoid blocking the Tokio executor on slow or networked
/// filesystems.
///
/// # Returns
///
/// `Some(path)` pointing to the first `Cargo.lock` found, or `None` when
/// no lockfile exists within 10 directory levels.
pub async fn find_cargo_lock(cargo_toml_path: &Path) -> Option<PathBuf> {
    let start_dir = cargo_toml_path.parent()?;

    let mut current = start_dir.to_path_buf();
    let mut depth = 0;
    const MAX_DEPTH: usize = 10;

    loop {
        let candidate = current.join("Cargo.lock");
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

/// True when `v` satisfies `req`, treating a pre-release as its release core.
/// Used as a fallback only: `semver` excludes pre-releases from a range whose
/// comparators carry none, but a lockfile pinning one is still ground truth
fn satisfies(req: &semver::VersionReq, v: &semver::Version) -> bool {
    req.matches(v)
        || (!v.pre.is_empty() && req.matches(&semver::Version::new(v.major, v.minor, v.patch)))
}

/// Choose which `Cargo.lock` entry to use when the lockfile pins several
/// versions of the same crate
fn select_locked_version<'a>(
    declared: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    let candidates: Vec<&'a str> = candidates.into_iter().collect();
    let Ok(req) = semver::VersionReq::parse(declared.trim()) else {
        return candidates.first().copied();
    };
    let parsed: Vec<(semver::Version, &'a str)> = candidates
        .iter()
        .filter_map(|c| semver::Version::parse(c).ok().map(|v| (v, *c)))
        .collect();

    if parsed.len() != candidates.len() {
        return candidates.first().copied();
    }

    // Strict match first: a stable release present in the lockfile must win
    // over a pre-release of the same version. Only when nothing matches
    // strictly does the pre-release fallback apply
    parsed
        .iter()
        .find(|(v, _)| req.matches(v))
        .or_else(|| parsed.iter().find(|(v, _)| satisfies(&req, v)))
        .map(|(_, c)| *c)
}

/// Resolves versions from `Cargo.lock` for a Rust project.
pub struct CargoResolver {
    /// Captured at selection time from the manifest's `[package].name`.
    /// Used by `resolve_version` to disambiguate multi-version crates: when the
    /// root package depends on a specific version of a crate (Cargo writes
    /// `"crate_name version"` in its dependencies array), that version takes
    /// precedence over the first-found entry.
    pub(crate) root_package: Option<String>,
}

#[async_trait]
impl LockfileResolver for CargoResolver {
    async fn find_lockfile(&self, manifest_path: &Path) -> Option<PathBuf> {
        find_cargo_lock(manifest_path).await
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        parse_cargo_lock_graph(lock_content)
    }

    fn resolve_version(&self, dep: &Dependency, graph: &LockfileGraph) -> Option<String> {
        // Root-package disambiguation (matches `parse_cargo_lock` semantics):
        // when the root depends on a specific version of a multi-version crate,
        // its dependencies array has `"crate_name version"` entries (Cargo
        // appends the version when ambiguity exists). Old Cargo.lock v1 may
        // also include a source suffix like `"1.0.0 (registry+...)"`.
        if let Some(root_name) = self.root_package.as_deref()
            && let Some(root_pkg) = graph.packages.iter().find(|p| p.name == root_name)
        {
            for dep_entry in &root_pkg.dependencies {
                let mut parts = dep_entry.splitn(2, ' ');
                if let (Some(crate_name), Some(version_part)) = (parts.next(), parts.next())
                    && crate_name == dep.name
                {
                    let version = version_part.split(' ').next().unwrap_or(version_part);
                    // The root pin still has to satisfy the manifest: a stale
                    // lockfile may name a version the declared range forbids
                    // `select_locked_version` keeps the tolerant behaviour for
                    // unparseable requirements/versions
                    if select_locked_version(&dep.version, [version]).is_some() {
                        return Some(version.to_string());
                    }
                    // Names are unique in the root's dependency array; fall
                    // through to the whole-graph lookup below
                    break;
                }
            }
        }
        // Fallback: pick the locked entry matching the declared requirement
        // (a lockfile may carry several versions of the same crate)
        select_locked_version(
            &dep.version,
            graph
                .packages
                .iter()
                .filter(|p| p.name == dep.name)
                .map(|p| p.version.as_str()),
        )
        .map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_cargo_lock() {
        let content = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.195"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.36.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let map = parse_cargo_lock(content, None);
        assert_eq!(map.get("serde").map(|s| s.as_str()), Some("1.0.195"));
        assert_eq!(map.get("tokio").map(|s| s.as_str()), Some("1.36.0"));
    }

    #[test]
    fn test_parse_empty_file() {
        let map = parse_cargo_lock("", None);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_no_packages() {
        let content = "version = 3\n";
        let map = parse_cargo_lock(content, None);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_invalid_toml() {
        let map = parse_cargo_lock("not valid toml ][", None);
        assert!(map.is_empty());
    }

    #[test]
    fn test_duplicate_package_keeps_first() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.100"

[[package]]
name = "serde"
version = "1.0.195"
"#;
        let map = parse_cargo_lock(content, None);
        assert_eq!(map.get("serde").map(|s| s.as_str()), Some("1.0.100"));
    }

    #[test]
    fn test_multi_version_resolves_root_dependency() {
        let content = r#"
[[package]]
name = "hashbrown"
version = "0.15.5"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "hashbrown"
version = "0.16.1"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "testing"
version = "0.1.0"
dependencies = [
    "hashbrown 0.16.1",
    "wasip3",
]

[[package]]
name = "wasip3"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
    "hashbrown 0.15.5",
]
"#;
        let map = parse_cargo_lock(content, Some("testing"));
        assert_eq!(map.get("hashbrown").map(|s| s.as_str()), Some("0.16.1"));
        assert_eq!(map.get("wasip3").map(|s| s.as_str()), Some("0.4.0"));
    }

    #[test]
    fn test_multi_version_without_root_package_keeps_first() {
        let content = r#"
[[package]]
name = "hashbrown"
version = "0.15.5"

[[package]]
name = "hashbrown"
version = "0.16.1"
"#;
        let map = parse_cargo_lock(content, None);
        assert_eq!(map.get("hashbrown").map(|s| s.as_str()), Some("0.15.5"));
    }

    #[test]
    fn test_root_package_not_found_keeps_first() {
        let content = r#"
[[package]]
name = "hashbrown"
version = "0.15.5"

[[package]]
name = "hashbrown"
version = "0.16.1"
"#;
        let map = parse_cargo_lock(content, Some("nonexistent"));
        assert_eq!(map.get("hashbrown").map(|s| s.as_str()), Some("0.15.5"));
    }

    #[test]
    fn test_unambiguous_dep_not_overridden() {
        let content = r#"
[[package]]
name = "my-crate"
version = "1.0.0"
dependencies = [
    "serde",
]

[[package]]
name = "serde"
version = "1.0.195"
"#;
        let map = parse_cargo_lock(content, Some("my-crate"));
        assert_eq!(map.get("serde").map(|s| s.as_str()), Some("1.0.195"));
    }

    #[test]
    fn test_v1_source_suffix_stripped() {
        let content = r#"
[[package]]
name = "my-crate"
version = "1.0.0"
dependencies = [
    "serde 1.0.195 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.195"
"#;
        let map = parse_cargo_lock(content, Some("my-crate"));
        assert_eq!(map.get("serde").map(|s| s.as_str()), Some("1.0.195"));
    }

    #[test]
    fn test_parse_graph_captures_dependencies() {
        let content = r#"
[[package]]
name = "root"
version = "0.1.0"
dependencies = ["serde", "tokio 1.36.0"]

[[package]]
name = "serde"
version = "1.0.195"

[[package]]
name = "tokio"
version = "1.36.0"
dependencies = ["mio"]

[[package]]
name = "mio"
version = "0.8.10"
"#;
        let graph = parse_cargo_lock_graph(content);
        assert_eq!(graph.packages.len(), 4);
        let root = graph.packages.iter().find(|p| p.name == "root").unwrap();
        // Dependencies are stored as-is; "serde" has no version, "tokio 1.36.0" keeps it.
        assert!(root.dependencies.contains(&"serde".to_string()));
        assert!(root.dependencies.contains(&"tokio 1.36.0".to_string()));
        let tokio = graph.packages.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio.dependencies, vec!["mio".to_string()]);
    }

    #[test]
    fn test_parse_cargo_lock_graph_preserves_dep_version_tokens() {
        let content = r#"
[[package]]
name = "root"
version = "0.1.0"
dependencies = ["hashbrown 0.15.5", "hashbrown 0.16.1"]

[[package]]
name = "hashbrown"
version = "0.15.5"

[[package]]
name = "hashbrown"
version = "0.16.1"
"#;
        let graph = parse_cargo_lock_graph(content);
        let root = graph.packages.iter().find(|p| p.name == "root").unwrap();
        assert!(root.dependencies.iter().any(|d| d == "hashbrown 0.15.5"));
        assert!(root.dependencies.iter().any(|d| d == "hashbrown 0.16.1"));
    }

    #[test]
    fn test_parse_graph_empty() {
        let graph = parse_cargo_lock_graph("");
        assert!(graph.packages.is_empty());
    }

    #[test]
    fn test_parse_graph_invalid_toml() {
        let graph = parse_cargo_lock_graph("not valid ][ toml");
        assert!(graph.packages.is_empty());
    }

    #[tokio::test]
    async fn cargo_resolver_finds_and_parses_cargo_lock() {
        use crate::parsers::lockfile_resolver::LockfileResolver;
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest_path = tmp.path().join("Cargo.toml");
        let lock_path = tmp.path().join("Cargo.lock");
        std::fs::write(
            &manifest_path,
            r#"[package]
name = "demo"
version = "0.1.0"
"#,
        )
        .expect("manifest");
        std::fs::write(
            &lock_path,
            r#"
[[package]]
name = "serde"
version = "1.0.230"

[[package]]
name = "tokio"
version = "1.50.0"
"#,
        )
        .expect("lockfile");
        let resolver = super::CargoResolver {
            root_package: Some("demo".to_string()),
        };
        let found = resolver.find_lockfile(&manifest_path).await;
        assert_eq!(found.as_deref(), Some(lock_path.as_path()));
        let content = std::fs::read_to_string(&lock_path).expect("read");
        let graph = resolver.parse_graph(&content);
        assert!(
            graph
                .packages
                .iter()
                .any(|p| p.name == "serde" && p.version == "1.0.230")
        );
        assert!(
            graph
                .packages
                .iter()
                .any(|p| p.name == "tokio" && p.version == "1.50.0")
        );
    }

    #[test]
    fn cargo_resolver_disambiguates_multi_version_via_root_package() {
        use crate::parsers::Dependency;
        use crate::parsers::Span;
        use crate::parsers::lockfile_resolver::LockfileResolver;

        // Cargo.lock with two versions of `multi`; root depends on the older one.
        let content = r#"
version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = [
 "multi 1.0.0",
]

[[package]]
name = "multi"
version = "2.0.0"

[[package]]
name = "multi"
version = "1.0.0"
"#;
        let resolver = super::CargoResolver {
            root_package: Some("demo".to_string()),
        };
        let graph = resolver.parse_graph(content);
        let dep = Dependency {
            name: "multi".to_string(),
            version: "*".to_string(),
            name_span: Span {
                line: 0,
                line_start: 0,
                line_end: 0,
            },
            version_span: Span {
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
        // Root package's dependency string `"multi 1.0.0"` should override
        // the first-wins `"2.0.0"` from the graph order.
        assert_eq!(
            resolver.resolve_version(&dep, &graph),
            Some("1.0.0".to_string())
        );
    }

    /// Builds a dependency with only the fields `resolve_version` reads
    fn dep(name: &str, version: &str) -> crate::parsers::Dependency {
        crate::parsers::Dependency {
            name: name.to_string(),
            version: version.to_string(),
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
        }
    }

    #[test]
    fn select_locked_version_picks_the_compatible_entry() {
        // The case this PR is about: a lone pin the manifest forbids
        assert_eq!(select_locked_version("~1.1", ["1.2.0"]), None);
        assert_eq!(select_locked_version("~1.1", ["1.1.9"]), Some("1.1.9"));
        assert_eq!(
            select_locked_version("0.52", ["0.52.0", "0.59.0"]),
            Some("0.52.0")
        );
        assert_eq!(
            select_locked_version("0.59", ["0.52.0", "0.59.0"]),
            Some("0.59.0")
        );
        // Ties keep lockfile order rather than jumping to the newest entry:
        // the question is which one Cargo installed, not which one is highest
        assert_eq!(
            select_locked_version("1", ["1.2.0", "1.9.0"]),
            Some("1.2.0")
        );
        // Pre-release pins are kept: `semver` would exclude them from `^1.3`
        assert_eq!(
            select_locked_version("1.3", ["1.3.0-rc.1"]),
            Some("1.3.0-rc.1")
        );
        // ...but only as a fallback: a stable entry that matches strictly wins
        // over a pre-release of the same version, whatever the lockfile order
        assert_eq!(
            select_locked_version("4.0.0", ["4.0.0-rc.1", "4.0.0"]),
            Some("4.0.0")
        );
        assert_eq!(
            select_locked_version("^4.0.0", ["4.0.0-rc.1", "4.0.0"]),
            Some("4.0.0")
        );
        // Tolerant fallbacks
        assert_eq!(select_locked_version("not a req", ["1.0.0"]), Some("1.0.0"));
        assert_eq!(select_locked_version("^1.0", ["oops"]), Some("oops"));
        assert_eq!(
            select_locked_version("^1.0", std::iter::empty::<&str>()),
            None
        );
    }

    #[test]
    fn cargo_resolver_rejects_a_root_pin_the_manifest_forbids() {
        use crate::parsers::lockfile_resolver::LockfileResolver;

        // Stale lockfile: the root still points at 2.0.0 while the manifest
        // has been narrowed to `~1.1`
        let content = r#"
    version = 3

    [[package]]
    name = "demo"
    version = "0.1.0"
    dependencies = [
     "multi 2.0.0",
    ]

    [[package]]
    name = "multi"
    version = "2.0.0"

    [[package]]
    name = "multi"
    version = "1.1.3"
    "#;
        let resolver = super::CargoResolver {
            root_package: Some("demo".to_string()),
        };
        let graph = resolver.parse_graph(content);
        // Root pin is incompatible: resolution continues into the graph
        assert_eq!(
            resolver.resolve_version(&dep("multi", "~1.1"), &graph),
            Some("1.1.3".to_string()),
            "an incompatible root pin must not shadow the compatible entry"
        );
        // Nothing satisfies the requirement: leave it unresolved rather than
        // reporting 2.0.0 as installed
        assert_eq!(
            resolver.resolve_version(&dep("multi", "~1.5"), &graph),
            None
        );
    }

    #[test]
    fn cargo_resolver_falls_back_to_first_wins_without_root_disambiguation() {
        use crate::parsers::Dependency;
        use crate::parsers::Span;
        use crate::parsers::lockfile_resolver::LockfileResolver;

        // No root_package set — fallback should pick first-found version.
        let content = r#"
version = 3

[[package]]
name = "lonely"
version = "5.5.5"
"#;
        let resolver = super::CargoResolver { root_package: None };
        let graph = resolver.parse_graph(content);
        let dep = Dependency {
            name: "lonely".to_string(),
            version: "*".to_string(),
            name_span: Span {
                line: 0,
                line_start: 0,
                line_end: 0,
            },
            version_span: Span {
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
            Some("5.5.5".to_string())
        );
    }
}
