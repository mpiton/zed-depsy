//! Vulnerability scanning for dependencies
//!
//! This module provides vulnerability detection using OSV.dev API
//! as the primary source for all ecosystems.

pub mod cache;
pub mod osv;

use crate::cache::ReadCache;
use crate::parsers::Dependency;
use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
use crate::parsers::npm_lock::npm_alias_target;
use crate::registries::VersionInfo;
use cache::{VulnCacheKey, VulnerabilityCache};
use hashbrown::{HashMap, HashSet};

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

/// Real package behind `dep` when it is an npm alias.
pub fn npm_alias_package(ecosystem: Ecosystem, dep: &Dependency) -> Option<&str> {
    if ecosystem != Ecosystem::Npm {
        return None;
    }
    npm_alias_target(dep.declared_spec()).map(|(package, _)| package)
}

/// Name `graph` lists `dep` under when it is an npm alias with another name there.
///
/// `yarn.lock` and `pnpm-lock.yaml` record the alias spec and list the real
/// package. `package-lock.json` records no spec and lists an alias under its
/// local name, and a stale alias has no spec either, so both get `None`.
pub fn npm_alias_graph_name<'a>(
    ecosystem: Ecosystem,
    dep: &'a Dependency,
    graph: &LockfileGraph,
) -> Option<&'a str> {
    npm_alias_package(ecosystem, dep).filter(|package| {
        *package != dep.name
            && graph.records_spec(&format!("{}@{}", dep.name, dep.declared_spec().trim()))
    })
}

/// How the dependencies of a manifest appear in its lockfile graph.
#[derive(Debug, Default)]
pub struct DirectRoots {
    /// Graph name of each dependency, where a walk of the graph starts.
    pub names: Vec<String>,
    /// Manifest names behind each graph name, a direct declaration first.
    pub manifest_names: HashMap<String, Vec<String>>,
    /// Graph names declared in the manifest under their own name.
    declared: HashSet<String>,
    /// Locked versions an alias selects, for each real package.
    alias_versions: HashMap<String, Vec<String>>,
}

impl DirectRoots {
    /// Reads the roots of `dependencies`, resolved against `graph`.
    ///
    /// `canonical` normalizes a manifest name to its form in the graph.
    pub fn new(
        dependencies: &[Dependency],
        ecosystem: Ecosystem,
        graph: Option<&LockfileGraph>,
        canonical: impl Fn(&str) -> String,
    ) -> Self {
        let mut roots = Self::default();
        for dep in dependencies {
            let alias = graph.and_then(|graph| npm_alias_graph_name(ecosystem, dep, graph));
            let name = alias.map_or_else(|| canonical(&dep.name), str::to_string);
            if alias.is_none() {
                roots.declared.insert(name.clone());
            } else if let Some(version) = &dep.resolved_version {
                roots
                    .alias_versions
                    .entry_ref(name.as_str())
                    .or_default()
                    .push(version.clone());
            }
            let manifest_names = roots.manifest_names.entry_ref(name.as_str()).or_default();
            if !manifest_names.contains(&dep.name) {
                let position = if alias.is_none() {
                    0
                } else {
                    manifest_names.len()
                };
                manifest_names.insert(position, dep.name.clone());
            }
            roots.names.push(name);
        }
        roots
    }

    /// Packages of `graph` reachable from the roots that the manifest does not declare.
    ///
    /// A package declared under its own name is direct at all its versions. An
    /// alias is direct only at the version it selects, so another version of its
    /// real package, reached through another dependency, stays transitive.
    pub fn transitives<'g>(&self, graph: &'g LockfileGraph) -> Vec<&'g LockfilePackage> {
        graph.transitives_excluding(&self.names, |pkg| {
            self.declared.contains(&pkg.name)
                || self
                    .alias_versions
                    .get(&pkg.name)
                    .is_some_and(|versions| versions.contains(&pkg.version))
        })
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
/// [`apply_osv_result`], so none of them can skip the overlay. An npm alias to
/// another package has its OSV result only: the cache entry under its local name
/// describes something else. An alias to its own name keeps that entry.
pub async fn cached_version_info(
    cache: &impl ReadCache,
    cache_key: &str,
    osv_results: &VulnerabilityCache,
    ecosystem: Ecosystem,
    dep: &Dependency,
) -> Option<VersionInfo> {
    let alias = npm_alias_package(ecosystem, dep);
    let cached = if alias.is_some_and(|package| package != dep.name) {
        None
    } else {
        cache.get_stale(cache_key).await
    };
    let mut info = match cached {
        Some(info) => info,
        None if alias.is_some() => VersionInfo::default(),
        None => return None,
    };
    apply_osv_result(&mut info, osv_results, ecosystem, dep);
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::cache::{VulnCacheKey, VulnerabilityCache};
    use super::osv::QueryResult;
    use super::{
        DirectRoots, Ecosystem, apply_osv_result, cached_version_info, normalize_version_for_osv,
        npm_alias_graph_name, npm_alias_package,
    };
    use crate::cache::{MemoryCache, WriteCache};
    use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
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
            catalog_spec: None,
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

    #[tokio::test]
    async fn alias_to_its_own_name_keeps_the_registry_entry() {
        let alias = dep("foo", "npm:foo@1.2.0");
        let cache = MemoryCache::new();
        cache
            .insert(
                "npm:foo".to_string(),
                VersionInfo {
                    latest: Some("9.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;
        let osv_results = osv_results_with(
            &alias,
            QueryResult {
                vulnerabilities: vec![advisory("GHSA-foo")],
                deprecated: false,
            },
        );

        let info = cached_version_info(&cache, "npm:foo", &osv_results, Ecosystem::Npm, &alias)
            .await
            .expect("the entry exists");
        assert_eq!(info.latest.as_deref(), Some("9.0.0"));
        assert_eq!(info.vulnerabilities.len(), 1);

        let info = cached_version_info(&cache, "npm:other", &osv_results, Ecosystem::Npm, &alias)
            .await
            .expect("an alias needs no registry entry");
        assert_eq!(info.vulnerabilities.len(), 1);
    }

    fn package(name: &str, version: &str, dependencies: &[&str]) -> LockfilePackage {
        LockfilePackage {
            name: name.to_string(),
            version: version.to_string(),
            dependencies: dependencies.iter().map(ToString::to_string).collect(),
            is_root: false,
        }
    }

    #[test]
    fn alias_uses_the_graph_name_only_when_its_spec_is_recorded() {
        let alias = dep("foo", "npm:bar@^1.0.0");
        let graph_name = |graph: &LockfileGraph| {
            npm_alias_graph_name(Ecosystem::Npm, &alias, graph).map(str::to_string)
        };

        // package-lock.json records no spec
        assert_eq!(graph_name(&LockfileGraph::default()), None);

        // A stale alias: the lockfile records other specs
        let mut stale = LockfileGraph::default();
        stale
            .locked_specs
            .insert("foo@npm:bar@^0.9.0".to_string(), "0.9.0".to_string());
        assert_eq!(graph_name(&stale), None);

        let mut locked = LockfileGraph::default();
        locked
            .locked_specs
            .insert("foo@npm:bar@^1.0.0".to_string(), "1.2.0".to_string());
        assert_eq!(graph_name(&locked).as_deref(), Some("bar"));

        // A spec locked at several versions still names the real package
        let mut conflicting = LockfileGraph::default();
        conflicting
            .ambiguous_specs
            .insert("foo@npm:bar@^1.0.0".to_string());
        assert_eq!(graph_name(&conflicting).as_deref(), Some("bar"));
    }

    #[test]
    fn alias_to_its_own_name_has_no_other_graph_name() {
        let alias = dep("foo", "npm:foo@1.2.0");
        let mut graph = LockfileGraph::default();
        graph
            .locked_specs
            .insert("foo@npm:foo@1.2.0".to_string(), "1.2.0".to_string());
        assert_eq!(npm_alias_graph_name(Ecosystem::Npm, &alias, &graph), None);
    }

    #[test]
    fn catalog_alias_is_found_in_the_graph_by_its_catalog_spec() {
        let mut alias = dep("foo", "catalog:");
        alias.catalog_spec = Some("npm:bar@^1.0.0".to_string());
        let mut graph = LockfileGraph::default();
        graph
            .locked_specs
            .insert("foo@npm:bar@^1.0.0".to_string(), "1.2.0".to_string());

        assert_eq!(npm_alias_package(Ecosystem::Npm, &alias), Some("bar"));
        assert_eq!(
            npm_alias_graph_name(Ecosystem::Npm, &alias, &graph),
            Some("bar")
        );
    }

    #[test]
    fn alias_and_direct_entry_of_one_package_keep_both_manifest_names() {
        let deps = [dep("foo", "npm:bar@^1.0.0"), dep("bar", "^1.0.0")];
        let mut graph = LockfileGraph::default();
        graph
            .locked_specs
            .insert("foo@npm:bar@^1.0.0".to_string(), "1.2.0".to_string());

        let roots = DirectRoots::new(&deps, Ecosystem::Npm, Some(&graph), str::to_string);

        assert_eq!(roots.names, ["bar", "bar"]);
        assert_eq!(roots.manifest_names["bar"], ["bar", "foo"]);
    }

    #[test]
    fn alias_leaves_other_versions_of_its_package_transitive() {
        let mut alias = dep("foo", "npm:bar@^1.0.0");
        alias.resolved_version = Some("1.2.0".to_string());
        let deps = [alias, dep("baz", "^1.0.0")];
        let mut graph = LockfileGraph {
            packages: vec![
                package("bar", "1.2.0", &["qux"]),
                package("bar", "2.0.0", &[]),
                package("baz", "1.0.0", &["bar"]),
                package("qux", "1.0.0", &[]),
            ],
            ..Default::default()
        };
        graph
            .locked_specs
            .insert("foo@npm:bar@^1.0.0".to_string(), "1.2.0".to_string());

        let roots = DirectRoots::new(&deps, Ecosystem::Npm, Some(&graph), str::to_string);
        let mut found: Vec<(&str, &str)> = roots
            .transitives(&graph)
            .iter()
            .map(|pkg| (pkg.name.as_str(), pkg.version.as_str()))
            .collect();
        found.sort_unstable();

        assert_eq!(found, [("bar", "2.0.0"), ("qux", "1.0.0")]);
    }

    /// The cache entry under an alias's local name describes another package.
    #[tokio::test]
    async fn alias_reads_only_its_osv_result() {
        let alias = dep("foo", "npm:bar@1.2.0");
        let cache = MemoryCache::new();
        cache
            .insert(
                "npm:foo".to_string(),
                VersionInfo {
                    latest: Some("9.0.0".to_string()),
                    ..Default::default()
                },
            )
            .await;
        let osv_results = osv_results_with(
            &alias,
            QueryResult {
                vulnerabilities: vec![advisory("GHSA-bar")],
                deprecated: false,
            },
        );

        for key in ["npm:foo", "npm:unpublished"] {
            let info = cached_version_info(&cache, key, &osv_results, Ecosystem::Npm, &alias)
                .await
                .expect("an alias needs no registry entry");
            assert_eq!(info.latest, None);
            assert_eq!(info.vulnerabilities.len(), 1);
        }
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

    #[tokio::test]
    async fn cached_version_info_serves_expired_data_with_the_overlay() {
        // Given version data past its TTL and a live OSV result
        let vulnerable = dep("minimist", "1.2.5");
        let osv_results = osv_results_with(
            &vulnerable,
            QueryResult {
                vulnerabilities: vec![advisory("GHSA-xvch-5gv4-984h")],
                deprecated: false,
            },
        );
        let cache = MemoryCache::with_ttl_and_stale(
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(3600),
        );
        cache
            .insert("npm:minimist".to_string(), VersionInfo::default())
            .await;

        // When it is read
        let info = cached_version_info(
            &cache,
            "npm:minimist",
            &osv_results,
            Ecosystem::Npm,
            &vulnerable,
        )
        .await;

        // Then the expired entry is served, with its advisory
        assert_eq!(info.map(|info| info.vulnerabilities.len()), Some(1));
    }
}
