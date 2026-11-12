//! Parser for Node.js lockfiles — resolves exact locked versions for npm dependencies.
//!
//! Supports:
//! - `package-lock.json` (npm lockfileVersion 1, 2, and 3)
//! - `yarn.lock` (Yarn Classic v1 and Yarn Berry v2+)
//! - `pnpm-lock.yaml` (pnpm v6 and v9)
//! - `bun.lock` (Bun text format / JSONC)

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::parsers::Dependency;
use crate::parsers::lockfile_graph::{LockfileGraph, LockfilePackage};
use crate::parsers::lockfile_resolver::LockfileResolver;

/// Type of Node.js lockfile detected.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NpmLockfileType {
    /// npm's `package-lock.json`
    PackageLock,
    /// Yarn's `yarn.lock` (Classic v1 or Berry v2+)
    YarnLock,
    /// pnpm's `pnpm-lock.yaml`
    PnpmLock,
    /// Bun's `bun.lock` (text JSONC format)
    BunLock,
}

/// Lockfile candidates in priority order.
const LOCKFILE_CANDIDATES: &[(&str, NpmLockfileType)] = &[
    ("package-lock.json", NpmLockfileType::PackageLock),
    ("yarn.lock", NpmLockfileType::YarnLock),
    ("pnpm-lock.yaml", NpmLockfileType::PnpmLock),
    ("bun.lock", NpmLockfileType::BunLock),
];

/// Find the Node.js lockfile by walking up from a package.json path.
///
/// Checks for lockfiles in priority order: package-lock.json > yarn.lock > pnpm-lock.yaml > bun.lock.
/// Uses async I/O to avoid blocking the Tokio executor on slow or networked filesystems.
/// Stops after 10 levels to prevent infinite traversal on unusual file systems.
pub async fn find_npm_lockfile(package_json_path: &Path) -> Option<(PathBuf, NpmLockfileType)> {
    let start_dir = package_json_path.parent()?;

    let mut current = start_dir.to_path_buf();
    let mut depth = 0;
    const MAX_DEPTH: usize = 10;

    loop {
        for &(filename, lockfile_type) in LOCKFILE_CANDIDATES {
            let candidate = current.join(filename);
            if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
                return Some((candidate, lockfile_type));
            }
        }

        depth += 1;
        if depth >= MAX_DEPTH {
            return None;
        }

        current = current.parent()?.to_path_buf();
    }
}

/// Parse a Node.js lockfile and return a map of package name → resolved version.
///
/// Dispatches to the appropriate sub-parser based on `lockfile_type`.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::npm_lock::{parse_npm_lockfile, NpmLockfileType};
///
/// let lock = r#"{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.18.2"}}}"#;
/// let map = parse_npm_lockfile(lock, NpmLockfileType::PackageLock);
/// assert_eq!(map.get("express").map(String::as_str), Some("4.18.2"));
/// ```
pub fn parse_npm_lockfile(
    content: &str,
    lockfile_type: NpmLockfileType,
) -> HashMap<String, String> {
    match lockfile_type {
        NpmLockfileType::PackageLock => parse_package_lock(content),
        NpmLockfileType::YarnLock => parse_yarn_lock(content),
        NpmLockfileType::PnpmLock => parse_pnpm_lock(content),
        NpmLockfileType::BunLock => parse_bun_lock(content),
    }
}

// ---------------------------------------------------------------------------
// package-lock.json (npm)
// ---------------------------------------------------------------------------

/// Parse npm's `package-lock.json` (supports lockfileVersion 1, 2, and 3).
fn parse_package_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return map,
    };

    // Try v2/v3 format first — packages object with node_modules/ paths
    if let Some(packages) = value.get("packages").and_then(|p| p.as_object()) {
        for (key, pkg) in packages {
            if let Some(name) = extract_name_from_node_modules_path(key)
                && let Some(version) = pkg.get("version").and_then(|v| v.as_str())
            {
                map.entry_ref(name).or_insert_with(|| version.to_string());
            }
        }
        return map;
    }

    // Fallback to v1 format — flat dependencies object
    if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
        for (name, dep) in deps {
            if let Some(version) = dep.get("version").and_then(|v| v.as_str()) {
                map.entry_ref(name).or_insert_with(|| version.to_string());
            }
        }
    }

    map
}

/// Extract package name from a `node_modules/` path key.
///
/// - `node_modules/express` → `Some("express")`
/// - `node_modules/@scope/name` → `Some("@scope/name")`
/// - `node_modules/a/node_modules/b` → `None` (nested transitive dep, skip)
/// - `""` (root package) → `None`
fn extract_name_from_node_modules_path(path: &str) -> Option<&str> {
    let stripped = path.strip_prefix("node_modules/")?;

    // Skip nested node_modules (transitive dependencies)
    if stripped.contains("node_modules/") {
        return None;
    }

    if stripped.is_empty() {
        return None;
    }

    Some(stripped)
}

// ---------------------------------------------------------------------------
// yarn.lock (Yarn Classic v1 and Yarn Berry v2+)
// ---------------------------------------------------------------------------

/// Parse Yarn's `yarn.lock` file.
///
/// Handles both Classic v1 format (`version "X.Y.Z"`) and
/// Berry v2+ format (`version: X.Y.Z`).
fn parse_yarn_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut current_names: Vec<&str> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Non-indented line ending with ':' is a package spec block header
        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            current_names.clear();
            extract_yarn_package_names(trimmed, &mut current_names);
            continue;
        }

        // Indented version line — assign to all current package names
        if !current_names.is_empty()
            && line.starts_with([' ', '\t'])
            && let Some(version) = extract_yarn_version(trimmed)
        {
            for &name in &current_names {
                map.entry_ref(name).or_insert_with(|| version.clone());
            }
            current_names.clear();
        }
    }

    map
}

/// Extract package names from a yarn.lock block header line.
///
/// Handles formats like:
/// - `express@^4.18.0:`
/// - `"@types/node@^20.0.0":`
/// - `express@^4.17.0, express@^4.18.0:`
/// - `"express@npm:^4.18.0":` (Berry)
fn extract_yarn_package_names<'a>(line: &'a str, names: &mut Vec<&'a str>) {
    let spec_line = line.trim_end_matches(':');

    for spec in spec_line.split(", ") {
        let spec = spec.trim().trim_matches('"');
        if let Some((name, _)) = split_name_version(spec)
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
}

/// Extract resolved version from a yarn.lock version line.
///
/// - Yarn v1: `version "4.18.2"`
/// - Yarn Berry: `version: 4.18.2` or `version: "4.18.2"`
fn extract_yarn_version(trimmed: &str) -> Option<String> {
    // Yarn v1: version "4.18.2"
    if let Some(rest) = trimmed.strip_prefix("version \"") {
        return rest.strip_suffix('"').map(|v| v.to_string());
    }

    // Yarn Berry: version: 4.18.2
    if let Some(rest) = trimmed.strip_prefix("version: ") {
        return Some(rest.trim().trim_matches('"').to_string());
    }

    None
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml
// ---------------------------------------------------------------------------

/// Parse pnpm's `pnpm-lock.yaml` file.
///
/// Handles both v6 format (`/name@version:`) and v9 format (`name@version:`).
fn parse_pnpm_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut in_packages = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }

        // A new top-level key ends the packages section
        if in_packages && !trimmed.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
            break;
        }

        if !in_packages || trimmed.is_empty() {
            continue;
        }

        // Package entries are indented and end with ':'
        if trimmed.ends_with(':') {
            let key = trimmed.trim_end_matches(':');
            // Remove surrounding quotes (v9 scoped packages)
            let key = key.trim_matches('\'').trim_matches('"');
            // Remove leading '/' (v6 format)
            let key = key.strip_prefix('/').unwrap_or(key);

            if let Some((name, version)) = split_pnpm_name_version(key) {
                map.entry_ref(name).or_insert_with(|| version.to_string());
            }
        }
    }

    map
}

/// Split a pnpm package key into (name, version), stripping peer dep info.
///
/// - `express@4.18.2` → `("express", "4.18.2")`
/// - `@types/node@20.11.5` → `("@types/node", "20.11.5")`
/// - `pkg@1.0.0(peer@2.0.0)` → `("pkg", "1.0.0")`
fn split_pnpm_name_version(key: &str) -> Option<(&str, &str)> {
    let (name, version) = split_name_version(key)?;

    // Strip peer dependency info: 1.0.0(peer@2.0.0) → 1.0.0
    let version = version.split('(').next().unwrap_or(version);

    if version.is_empty() {
        return None;
    }

    Some((name, version))
}

// ---------------------------------------------------------------------------
// bun.lock (JSONC)
// ---------------------------------------------------------------------------

/// Parse Bun's `bun.lock` text lockfile (JSONC format).
///
/// The `packages` object maps package names to arrays where the first
/// element is the `name@version` specifier.
fn parse_bun_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let cleaned = clean_jsonc(content);

    let value: serde_json::Value = match serde_json::from_str(&cleaned) {
        Ok(v) => v,
        Err(_) => return map,
    };

    let packages = match value.get("packages").and_then(|p| p.as_object()) {
        Some(pkgs) => pkgs,
        None => return map,
    };

    for (_key, entry) in packages {
        // Entry is an array; first element is "name@version"
        let spec = entry
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str());

        if let Some(spec) = spec
            && let Some((name, version)) = split_name_version(spec)
        {
            map.entry_ref(name).or_insert_with(|| version.to_string());
        }
    }

    map
}

/// Clean JSONC content: strip `//` line comments and trailing commas.
///
/// Handles both features in a single pass, respecting JSON string boundaries.
/// Operates on `char` indices to correctly handle multi-byte UTF-8 content.
fn clean_jsonc(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    let mut in_string = false;
    let mut escape_next = false;

    while let Some(ch) = chars.next() {
        if escape_next {
            result.push(ch);
            escape_next = false;
            continue;
        }

        if in_string {
            result.push(ch);
            if ch == '\\' {
                escape_next = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                result.push('"');
            }
            '/' if chars.peek() == Some(&'/') => {
                // Line comment — skip to end of line
                for c in chars.by_ref() {
                    if c == '\n' {
                        result.push('\n');
                        break;
                    }
                }
            }
            ',' => {
                // Check if this is a trailing comma (only whitespace before ] or })
                // Peek ahead without consuming
                let remaining = chars.clone();
                let mut is_trailing = false;
                for c in remaining {
                    if c.is_ascii_whitespace() {
                        continue;
                    }
                    if c == ']' || c == '}' {
                        is_trailing = true;
                    }
                    break;
                }
                if !is_trailing {
                    result.push(',');
                }
            }
            _ => {
                result.push(ch);
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Graph extraction — package-lock.json, pnpm-lock.yaml, yarn.lock v1
// ---------------------------------------------------------------------------

/// Parse a `package-lock.json` (lockfile v2/v3 flat `packages` format) into a [`LockfileGraph`].
///
/// v1 nested-`dependencies` format is intentionally not supported (superseded since npm 7, 2020).
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::npm_lock::parse_package_lock_graph;
///
/// let lock = r#"{"lockfileVersion":3,"packages":{"node_modules/react":{"version":"18.2.0"}}}"#;
/// let graph = parse_package_lock_graph(lock);
/// assert!(graph.packages.iter().any(|p| p.name == "react" && p.version == "18.2.0"));
/// ```
pub fn parse_package_lock_graph(content: &str) -> LockfileGraph {
    let mut graph = LockfileGraph::default();
    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return graph,
    };

    let Some(packages) = value.get("packages").and_then(|p| p.as_object()) else {
        return graph;
    };

    for (key, entry) in packages {
        if key.is_empty() {
            continue; // root entry represents the manifest itself
        }
        // Skip nested node_modules entries (transitive dependencies of dependencies).
        // Surfacing them lets resolve_version pick a transitive copy over the
        // top-level one, regressing direct-dep version reporting.
        let Some(name) = extract_name_from_node_modules_path(key) else {
            continue;
        };
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        let dependencies: Vec<String> = entry
            .get("dependencies")
            .and_then(|d| d.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();

        graph.packages.push(LockfilePackage {
            name: name.to_string(),
            version: version.to_string(),
            dependencies,
            is_root: false,
        });
    }

    graph
}

/// Parse a `pnpm-lock.yaml` into a [`LockfileGraph`].
///
/// Uses a minimal line-based walker (no YAML parser dependency). Handles both
/// v6 (`/name@ver:`) and v9 (`name@ver:`) key formats, including quoted scoped
/// package names.
///
/// Edges sit under `packages:` in v6 and under `snapshots:` in v9. pnpm writes one
/// key per peer set in either section, so entries of the same name and version
/// merge into one package. An alias edge such as `foo: bar@1.2.0` names `bar`.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::npm_lock::parse_pnpm_lock_graph;
///
/// let lock = "lockfileVersion: '9.0'\npackages:\n  react@18.2.0:\n    resolution: {}\n";
/// let graph = parse_pnpm_lock_graph(lock);
/// assert!(graph.packages.iter().any(|p| p.name == "react" && p.version == "18.2.0"));
/// ```
pub fn parse_pnpm_lock_graph(content: &str) -> LockfileGraph {
    let mut graph = LockfileGraph::default();
    let mut in_entries = false;
    let mut current: Option<LockfilePackage> = None;
    let mut in_deps = false;

    for line in content.lines() {
        // A lockfile with a `packageManager` entry writes pnpm's own environment as a first
        // document. Only the last document describes the project.
        if line == "---" {
            graph.packages.clear();
            current = None;
            in_entries = false;
            in_deps = false;
            continue;
        }

        // Any top-level key ends the current section (e.g. "settings:", "importers:", etc.)
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(finish) = current.take() {
                graph.packages.push(finish);
            }
            in_entries = matches!(line, "packages:" | "snapshots:");
            in_deps = false;
            continue;
        }
        if !in_entries {
            continue;
        }
        // A snapshot without dependencies is written "  name@ver: {}"
        let entry_line = line.trim_end();
        let entry_line = entry_line.strip_suffix(" {}").unwrap_or(entry_line);
        // Package entry: "  /name@ver:" (v6) or "  name@ver:" (v9)
        let entry_key = if let Some(rest) = entry_line.strip_prefix("  /") {
            Some(rest)
        } else if entry_line.starts_with("  ")
            && !entry_line.starts_with("   ")
            && entry_line.contains('@')
            && entry_line.ends_with(':')
        {
            Some(&entry_line[2..])
        } else {
            None
        };

        if let Some(rest) = entry_key {
            if let Some(finish) = current.take() {
                graph.packages.push(finish);
            }
            let key = rest.trim_end_matches(':').trim();
            // Strip optional surrounding quotes (pnpm v9 may quote scoped names).
            let key = key.trim_matches('\'').trim_matches('"');
            if let Some((name, version)) = split_pnpm_key(key) {
                current = Some(LockfilePackage {
                    name,
                    version,
                    dependencies: Vec::new(),
                    is_root: false,
                });
            }
            in_deps = false;
            continue;
        }
        if matches!(line.trim(), "dependencies:" | "optionalDependencies:") {
            in_deps = true;
            continue;
        }
        if in_deps && line.starts_with("      ") {
            let trimmed = line.trim_start();
            let (dep_name_raw, dep_value) = trimmed
                .split_once(':')
                .map_or((trimmed.trim(), ""), |(n, v)| (n.trim(), v));
            // pnpm v9 quotes scoped names like '@emotion/cache'
            let dep_name = dep_name_raw.trim_matches('\'').trim_matches('"');
            if !dep_name.is_empty()
                && let Some(cur) = current.as_mut()
            {
                cur.dependencies
                    .push(pnpm_edge_target(dep_name, dep_value).to_string());
            }
        } else if !line.starts_with("      ") {
            in_deps = false;
        }
    }

    if let Some(finish) = current {
        graph.packages.push(finish);
    }
    graph.packages = merge_pnpm_entries(std::mem::take(&mut graph.packages));
    store_locked_specs(&mut graph, parse_pnpm_locked_specs(content));
    graph
}

/// Name the package a pnpm edge `name: value` points at.
///
/// `value` names another package for an alias: `bar@1.2.0`, or `/bar@1.2.0` in v6.
/// Versions, peer suffixes (`1.0.0(peer@1.0.0)`) and URL or local sources such as
/// `git+ssh://git@github.com/o/r.git` keep `name`.
fn pnpm_edge_target<'a>(name: &'a str, value: &'a str) -> &'a str {
    let value = value.trim().trim_matches(['\'', '"']);
    let base = value.split('(').next().unwrap_or(value);
    let base = base.strip_prefix('/').unwrap_or(base);
    match split_name_version(base) {
        Some((target, _)) if target.starts_with('@') || !target.contains(['/', ':']) => target,
        _ => name,
    }
}

/// Merge entries of the same name and version, keeping first-seen order.
fn merge_pnpm_entries(entries: Vec<LockfilePackage>) -> Vec<LockfilePackage> {
    let mut merged: Vec<LockfilePackage> = Vec::with_capacity(entries.len());
    let mut positions: HashMap<String, usize> = HashMap::with_capacity(entries.len());

    for mut entry in entries {
        let key = format!("{}@{}", entry.name, entry.version);
        let position = *positions.entry_ref(key.as_str()).or_insert(merged.len());
        let dependencies = std::mem::take(&mut entry.dependencies);
        if position == merged.len() {
            merged.push(entry);
        }
        let edges = &mut merged[position].dependencies;
        for dependency in dependencies {
            if !edges.contains(&dependency) {
                edges.push(dependency);
            }
        }
    }
    merged
}

/// Map each `name@specifier` of a `pnpm-lock.yaml` to its locked version.
///
/// Reads the `specifier:`/`version:` pairs of the last YAML document, written
/// before its `packages:` section. If two importers lock the same spec
/// differently, the spec maps to `None`: the name alone cannot tell them apart.
fn parse_pnpm_locked_specs(content: &str) -> HashMap<String, Option<String>> {
    let mut locked_specs = HashMap::new();
    let mut name = "";
    let mut specifier = None;
    let mut past_importers = false;

    for line in content.lines() {
        if line == "---" {
            locked_specs.clear();
            specifier = None;
            past_importers = false;
            continue;
        }
        if matches!(line, "packages:" | "snapshots:") {
            past_importers = true;
        }
        if past_importers {
            continue;
        }
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("specifier: ") {
            specifier = Some(value.trim_matches(['\'', '"']));
        } else if let Some(value) = trimmed.strip_prefix("version: ") {
            if let (Some(spec), Some(version)) = (specifier.take(), pnpm_locked_version(value)) {
                record_locked_spec(&mut locked_specs, &format!("{name}@{spec}"), version);
            }
        } else if let Some(key) = trimmed.strip_suffix(':') {
            name = key.trim_matches(['\'', '"']);
        }
    }
    locked_specs
}

/// Record `version` for the spec `key`, or `None` once versions disagree.
fn record_locked_spec(specs: &mut HashMap<String, Option<String>>, key: &str, version: &str) {
    specs
        .entry_ref(key)
        .and_modify(|locked| {
            if locked.as_deref() != Some(version) {
                *locked = None;
            }
        })
        .or_insert_with(|| Some(version.to_string()));
}

/// Store what [`record_locked_spec`] saw, keeping specs at several versions apart.
fn store_locked_specs(graph: &mut LockfileGraph, specs: HashMap<String, Option<String>>) {
    for (key, version) in specs {
        match version {
            Some(version) => {
                graph.locked_specs.insert(key, version);
            }
            None => {
                graph.ambiguous_specs.insert(key);
            }
        }
    }
}

/// Read the version from a pnpm dependency's `version:` value.
///
/// Handles a peer suffix (`1.2.0(peer@1.0.0)`) and an alias target (`bar@1.2.0`,
/// `/bar@1.2.0`). Returns `None` for local and URL values such as `link:../foo`.
pub(crate) fn pnpm_locked_version(value: &str) -> Option<&str> {
    let base = value.trim_matches(['\'', '"']).split('(').next()?;
    let version = base.rsplit('@').next()?;
    semver::Version::parse(version).is_ok().then_some(version)
}

/// Split a pnpm key like "react@18.2.0" or "@babel/core@7.0.0" into (name, version).
///
/// Strips peer-dep suffix before splitting: "react-dom@18.2.0(react@18.2.0)" → ("react-dom", "18.2.0").
fn split_pnpm_key(key: &str) -> Option<(String, String)> {
    // Peer-dep suffix in pnpm v9: "name@ver(peer@ver)(other@ver)" — trim at the first '('
    // that isn't part of the name. Package names can't contain '(' so this is safe.
    let base = match key.find('(') {
        Some(idx) => &key[..idx],
        None => key,
    };
    // The separator is the first '@' after a scope: a source such as
    // `git+ssh://git@github.com/o/r.git` can hold another one.
    let (name, version) = split_name_version(base)?;
    Some((name.to_string(), version.to_string()))
}

/// Parse a `yarn.lock` into a [`LockfileGraph`].
///
/// Handles both Classic v1 format (`version "X.Y.Z"`) and
/// Berry v2+ format (`version: X.Y.Z`).
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::npm_lock::parse_yarn_lock_graph;
///
/// let lock = "\"react@^18.0.0\":\n  version \"18.2.0\"\n";
/// let graph = parse_yarn_lock_graph(lock);
/// assert!(graph.packages.iter().any(|p| p.name == "react" && p.version == "18.2.0"));
/// ```
pub fn parse_yarn_lock_graph(content: &str) -> LockfileGraph {
    let mut graph = LockfileGraph::default();
    let mut current: Option<LockfilePackage> = None;
    let mut specs: Vec<&str> = Vec::new();
    let mut locked_specs = HashMap::new();
    let mut in_deps = false;

    for line in content.lines() {
        let trimmed = line.trim_start();

        // Berry writes a key over 1024 characters as `? key`, with `:` on the next line.
        if !line.starts_with(' ')
            && !line.starts_with('#')
            && line.contains('@')
            && let Some(header) = line.strip_prefix("? ").or_else(|| line.strip_suffix(':'))
        {
            if let Some(finished) = current.take() {
                push_yarn_entry(&mut graph, &mut locked_specs, finished, &specs);
            }
            specs = header
                .split(',')
                .map(|spec| spec.trim().trim_matches('"'))
                .collect();
            if let Some(name) = yarn_header_name(header) {
                current = Some(LockfilePackage {
                    name: name.to_string(),
                    version: String::new(),
                    dependencies: Vec::new(),
                    is_root: false,
                });
            }
            in_deps = false;
            continue;
        }

        if let Some(cur) = current.as_mut() {
            // Deeper lines belong to a nested block such as `dependencies:` or `bin:`.
            if line.starts_with("    ") {
                if in_deps {
                    let (key, value) = trimmed
                        .split_once(char::is_whitespace)
                        .unwrap_or((trimmed, ""));
                    let name = key.trim_end_matches(':').trim_matches('"');
                    if !name.is_empty() {
                        // An aliased package is listed under its real name, so the edge
                        // must use it too.
                        let target = npm_alias_with_range(value.trim().trim_matches('"'))
                            .map_or(name, |(real_name, _)| real_name);
                        cur.dependencies.push(target.to_string());
                    }
                }
                continue;
            }
            in_deps = matches!(trimmed, "dependencies:" | "optionalDependencies:");
            if let Some(v) = extract_yarn_version(trimmed) {
                cur.version = v;
            }
            // Berry only: the key can be an alias, and only this line names the real
            // package. Local packages must not reach registry or OSV lookups.
            if let Some(resolution) = trimmed.strip_prefix("resolution: ")
                && let Some((name, locator)) = split_name_version(resolution.trim_matches('"'))
            {
                if ["workspace:", "portal:", "link:", "file:", "exec:"]
                    .iter()
                    .any(|protocol| locator.starts_with(protocol))
                {
                    current = None;
                } else {
                    cur.name = name.to_string();
                }
            }
        }
    }

    if let Some(finished) = current {
        push_yarn_entry(&mut graph, &mut locked_specs, finished, &specs);
    }
    store_locked_specs(&mut graph, locked_specs);
    graph
}

/// Add a finished `yarn.lock` entry to `graph` and record the specs of its header.
fn push_yarn_entry(
    graph: &mut LockfileGraph,
    locked_specs: &mut HashMap<String, Option<String>>,
    package: LockfilePackage,
    specs: &[&str],
) {
    for spec in specs {
        record_locked_spec(locked_specs, spec, &package.version);
    }
    graph.packages.push(package);
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Read the package name from the first key of a `yarn.lock` entry header.
///
/// An alias key gives the real package: `"alias@npm:real@^1.0.0"` → `real`.
/// Classic has no `resolution:` line to correct it later.
fn yarn_header_name(header: &str) -> Option<&str> {
    let header = header.trim();
    // Multiple keys comma-separated; take the first
    let first_key_raw = header.split(',').next().unwrap_or(header).trim();
    let first_key = first_key_raw.trim_matches('"');
    // Classic writes `foo@:` for an empty range.
    first_key.strip_suffix('@').or_else(|| {
        let (name, range) = split_name_version(first_key)?;
        let real_name = npm_alias_with_range(range).map(|(real_name, _)| real_name);
        Some(real_name.unwrap_or(name))
    })
}

/// Real package and range behind an `npm:` alias in a manifest, or `None` for any other spec.
///
/// An alias with no range accepts any version, so it reads as `*`. A range or
/// version after `npm:` names no other package, and neither does an empty target
/// or `latest`, the tag Yarn Berry reads there. Any other bare word reads as a
/// package, as npm and pnpm do, since it cannot be told apart from a custom tag.
///
/// - `npm:bar@^1.0.0` → `Some(("bar", "^1.0.0"))`
/// - `npm:@scope/bar` → `Some(("@scope/bar", "*"))`
/// - `npm:7zip-bin` → `Some(("7zip-bin", "*"))`
/// - `npm:^1.0.0` → `None`
/// - `npm:latest` → `None`
pub fn npm_alias_target(spec: &str) -> Option<(&str, &str)> {
    if let Some(alias) = npm_alias_with_range(spec.trim()) {
        return Some(alias);
    }
    let target = spec.trim().strip_prefix("npm:")?;
    (!target.is_empty() && target != "latest" && !is_version_range(target)).then_some((target, "*"))
}

/// Version range or tag an `npm:` spec carries, or `spec` itself without that prefix.
///
/// Surrounding whitespace is dropped either way.
///
/// - `npm:^1.0.0` → `^1.0.0`
/// - `npm:bar@^1.0.0` → `^1.0.0`
/// - `npm:bar` → `*`
/// - `^1.0.0` → `^1.0.0`
pub fn npm_spec_range(spec: &str) -> &str {
    let spec = spec.trim();
    match npm_alias_target(spec) {
        Some((_, range)) => range,
        None => spec.strip_prefix("npm:").unwrap_or(spec),
    }
}

/// Whether the text after `npm:` is a version or range rather than a package name.
///
/// A package name may start with a digit, as `7zip-bin` does. A version holds
/// only digits, dots and wildcards up to its first separator, and a prerelease
/// or build suffix needs all three numbers before it.
fn is_version_range(target: &str) -> bool {
    if target.starts_with(['^', '~', '<', '>', '=', '*']) {
        return true;
    }
    if !target.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let end = target.find(['-', '+', ' ', '|']).unwrap_or(target.len());
    let (core, rest) = target.split_at(end);
    core.chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'x' | 'X' | '*'))
        && (!rest.starts_with(['-', '+']) || core.split('.').count() == 3)
}

/// Real package and range of an `npm:name@range` spec.
///
/// Lockfile parsers use this form only: Yarn Berry reads `npm:latest` as a tag
/// of the package itself, not as an alias.
fn npm_alias_with_range(spec: &str) -> Option<(&str, &str)> {
    split_name_version(spec.strip_prefix("npm:")?)
}

/// Split a `name@version` spec into `(name, version)`, handling scoped packages.
///
/// - `express@4.18.2` → `Some(("express", "4.18.2"))`
/// - `@types/node@20.11.5` → `Some(("@types/node", "20.11.5"))`
/// - `express@npm:^4.18.0` → `Some(("express", "npm:^4.18.0"))`
fn split_name_version(spec: &str) -> Option<(&str, &str)> {
    let at_pos = if let Some(after_scope) = spec.strip_prefix('@') {
        // Scoped package: find the second '@'
        after_scope.find('@').map(|p| p + 1)?
    } else {
        spec.find('@')?
    };

    let name = &spec[..at_pos];
    let version = &spec[at_pos + 1..];

    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some((name, version))
}

/// Choose the locked version of `dep`.
///
/// Reads the version the lockfile records for the declared range, then accepts
/// an exact pin or the only version locked for the name. Returns `None` when
/// several versions are locked and none matches, as in a stale lockfile: picking
/// one would be a guess. A stale alias also gets `None` when the graph lists real
/// names, because the entries under its local name are another package.
pub fn select_npm_version(dep: &Dependency, graph: &LockfileGraph) -> Option<String> {
    let manifest_spec = dep.version.trim();
    // A `catalog:` marker holds no range: the catalog's own spec is in `catalog_spec`.
    // pnpm records the marker as the specifier, Yarn records the range in its key.
    let declared = dep.declared_spec().trim();
    let aliases_another_package =
        npm_alias_target(declared).is_some_and(|(package, _)| package != dep.name);

    for spec in [manifest_spec, declared] {
        // The marker stays recorded after the catalog entry changes, so it cannot
        // vouch for an alias. pnpm's `catalogs` section records the alias spec itself.
        if aliases_another_package && spec != declared {
            continue;
        }
        let locked = [
            format!("{}@{spec}", dep.name),
            format!("{}@npm:{spec}", dep.name),
        ]
        .iter()
        .find_map(|key| graph.locked_specs.get(key.as_str()).cloned());
        if locked.is_some() {
            return locked;
        }
    }

    if aliases_another_package && graph.records_specs() {
        return None;
    }

    let candidates = graph.find_all(&dep.name);
    let (first, rest) = candidates.split_first()?;
    if rest.iter().all(|p| p.version == first.version) {
        return Some(first.version.clone());
    }
    candidates
        .iter()
        .find(|p| p.version == declared)
        .map(|p| p.version.clone())
}

/// Resolves versions from npm/yarn/pnpm/bun lockfiles. Sub-format is captured at selection time.
pub struct NpmResolver {
    pub(crate) lock_path: PathBuf,
    pub(crate) sub: NpmLockfileType,
}

#[async_trait]
impl LockfileResolver for NpmResolver {
    async fn find_lockfile(&self, _manifest_path: &Path) -> Option<PathBuf> {
        // Path was probed at selection time; return the cached value.
        Some(self.lock_path.clone())
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        match self.sub {
            NpmLockfileType::PackageLock => parse_package_lock_graph(lock_content),
            NpmLockfileType::PnpmLock => parse_pnpm_lock_graph(lock_content),
            NpmLockfileType::YarnLock => parse_yarn_lock_graph(lock_content),
            NpmLockfileType::BunLock => {
                // No dedicated graph parser for bun.lock yet — build a flat
                // graph (no edges, no is_root) from the name→version map.
                // Transitive analysis is therefore a no-op for Bun until a
                // real graph parser lands. Matches pre-refactor behavior.
                let lock_versions = parse_npm_lockfile(lock_content, self.sub);
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
                    ..Default::default()
                }
            }
        }
    }

    fn resolve_version(&self, dep: &Dependency, graph: &LockfileGraph) -> Option<String> {
        select_npm_version(dep, graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Parser;
    use crate::parsers::lockfile_resolver::resolve_versions_from_lockfile;
    use crate::parsers::npm::NpmParser;

    // -----------------------------------------------------------------------
    // split_name_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_name_version_simple() {
        assert_eq!(
            split_name_version("express@4.18.2"),
            Some(("express", "4.18.2"))
        );
    }

    #[test]
    fn test_split_name_version_scoped() {
        assert_eq!(
            split_name_version("@types/node@20.11.5"),
            Some(("@types/node", "20.11.5"))
        );
    }

    #[test]
    fn test_split_name_version_with_protocol() {
        assert_eq!(
            split_name_version("express@npm:^4.18.0"),
            Some(("express", "npm:^4.18.0"))
        );
    }

    #[test]
    fn test_split_name_version_invalid() {
        assert_eq!(split_name_version("express"), None);
        assert_eq!(split_name_version("@scope/name"), None);
        assert_eq!(split_name_version(""), None);
    }

    // -----------------------------------------------------------------------
    // package-lock.json
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_package_lock_v3() {
        let content = r#"{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2"
    },
    "node_modules/@types/node": {
      "version": "20.11.5"
    }
  }
}"#;
        let map = parse_package_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        assert_eq!(map.get("@types/node").map(|s| s.as_str()), Some("20.11.5"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_package_lock_v1() {
        let content = r#"{
  "name": "my-app",
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    },
    "lodash": {
      "version": "4.17.21"
    }
  }
}"#;
        let map = parse_package_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        assert_eq!(map.get("lodash").map(|s| s.as_str()), Some("4.17.21"));
    }

    #[test]
    fn test_parse_package_lock_nested_deps_ignored() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/express": {
      "version": "4.18.2"
    },
    "node_modules/express/node_modules/qs": {
      "version": "6.11.0"
    }
  }
}"#;
        let map = parse_package_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        // Nested dep should not appear as top-level
        assert!(!map.contains_key("qs"));
    }

    #[test]
    fn test_parse_package_lock_empty() {
        assert!(parse_package_lock("{}").is_empty());
        assert!(parse_package_lock("").is_empty());
        assert!(parse_package_lock("invalid json").is_empty());
    }

    // -----------------------------------------------------------------------
    // yarn.lock
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_yarn_lock_v1() {
        let content = r#"# yarn lockfile v1

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
  integrity sha512-abc

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"#;
        let map = parse_yarn_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        assert_eq!(map.get("lodash").map(|s| s.as_str()), Some("4.17.21"));
    }

    #[test]
    fn test_parse_yarn_lock_berry() {
        let content = r#"__metadata:
  version: 8
  cacheKey: 10c0

"express@npm:^4.18.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"

"@types/node@npm:^20.0.0":
  version: 20.11.5
  resolution: "@types/node@npm:20.11.5"
"#;
        let map = parse_yarn_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        assert_eq!(map.get("@types/node").map(|s| s.as_str()), Some("20.11.5"));
    }

    #[test]
    fn test_parse_yarn_lock_scoped() {
        let content = r#"# yarn lockfile v1

"@babel/core@^7.22.0":
  version "7.23.7"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.7.tgz"

"@types/node@^20.0.0":
  version "20.11.5"
"#;
        let map = parse_yarn_lock(content);
        assert_eq!(map.get("@babel/core").map(|s| s.as_str()), Some("7.23.7"));
        assert_eq!(map.get("@types/node").map(|s| s.as_str()), Some("20.11.5"));
    }

    #[test]
    fn test_parse_yarn_lock_multi_range() {
        let content = r#"# yarn lockfile v1

express@^4.17.0, express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
"#;
        let map = parse_yarn_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        assert_eq!(map.len(), 1); // Deduplicated
    }

    #[test]
    fn test_parse_yarn_lock_empty() {
        assert!(parse_yarn_lock("").is_empty());
        assert!(parse_yarn_lock("# yarn lockfile v1\n").is_empty());
    }

    // -----------------------------------------------------------------------
    // pnpm-lock.yaml
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pnpm_lock_v9() {
        let content = r#"lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

packages:

  express@4.18.2:
    resolution: {integrity: sha512-abc}

  '@types/node@20.11.5':
    resolution: {integrity: sha512-def}

snapshots:
  express@4.18.2: {}
"#;
        let map = parse_pnpm_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        assert_eq!(map.get("@types/node").map(|s| s.as_str()), Some("20.11.5"));
        // Should not include entries from snapshots section
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_pnpm_lock_v6() {
        let content = r#"lockfileVersion: '6.0'

packages:

  /express@4.18.2:
    resolution: {integrity: sha512-abc}
    dependencies:
      accepts: 1.3.8

  /@types/node@20.11.5:
    resolution: {integrity: sha512-def}
"#;
        let map = parse_pnpm_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.18.2"));
        assert_eq!(map.get("@types/node").map(|s| s.as_str()), Some("20.11.5"));
    }

    #[test]
    fn test_parse_pnpm_lock_with_peer_deps() {
        let content = r#"lockfileVersion: '9.0'

packages:

  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-abc}

  react@18.2.0:
    resolution: {integrity: sha512-def}
"#;
        let map = parse_pnpm_lock(content);
        assert_eq!(map.get("react-dom").map(|s| s.as_str()), Some("18.2.0"));
        assert_eq!(map.get("react").map(|s| s.as_str()), Some("18.2.0"));
    }

    #[test]
    fn test_parse_pnpm_lock_empty() {
        assert!(parse_pnpm_lock("").is_empty());
        assert!(parse_pnpm_lock("lockfileVersion: '9.0'\n").is_empty());
    }

    // -----------------------------------------------------------------------
    // bun.lock
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_bun_lock() {
        let content = r#"{
  "lockfileVersion": 0,
  "packages": {
    "express": ["express@4.21.2", ""],
    "@types/node": ["@types/node@22.10.5", ""]
  }
}"#;
        let map = parse_bun_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.21.2"));
        assert_eq!(map.get("@types/node").map(|s| s.as_str()), Some("22.10.5"));
    }

    #[test]
    fn test_parse_bun_lock_with_comments_and_trailing_commas() {
        let content = r#"{
  // This is a bun lockfile
  "lockfileVersion": 0,
  "packages": {
    "express": ["express@4.21.2", ""], // trailing
    "@types/node": ["@types/node@22.10.5", ""],
  },
}"#;
        let map = parse_bun_lock(content);
        assert_eq!(map.get("express").map(|s| s.as_str()), Some("4.21.2"));
        assert_eq!(map.get("@types/node").map(|s| s.as_str()), Some("22.10.5"));
    }

    #[test]
    fn test_parse_bun_lock_empty() {
        assert!(parse_bun_lock("{}").is_empty());
        assert!(parse_bun_lock("").is_empty());
        assert!(parse_bun_lock("invalid").is_empty());
    }

    // -----------------------------------------------------------------------
    // clean_jsonc
    // -----------------------------------------------------------------------

    #[test]
    fn test_clean_jsonc_strips_comments() {
        let input = r#"{
  // comment
  "key": "value" // inline
}"#;
        let cleaned = clean_jsonc(input);
        assert!(!cleaned.contains("comment"));
        assert!(!cleaned.contains("inline"));
        assert!(cleaned.contains("\"key\": \"value\""));
    }

    #[test]
    fn test_clean_jsonc_strips_trailing_commas() {
        let input = r#"{"a": [1, 2, 3,], "b": {"x": 1,},}"#;
        let cleaned = clean_jsonc(input);
        let parsed: serde_json::Value = serde_json::from_str(&cleaned).unwrap();
        assert_eq!(parsed["a"][2], 3);
        assert_eq!(parsed["b"]["x"], 1);
    }

    #[test]
    fn test_clean_jsonc_preserves_slashes_in_strings() {
        let input = r#"{"url": "https://example.com"}"#;
        let cleaned = clean_jsonc(input);
        assert_eq!(cleaned, input);
    }

    #[test]
    fn test_clean_jsonc_preserves_non_ascii() {
        let input = r#"{"description": "Bibliothèque géniale", "author": "日本語"}"#;
        let cleaned = clean_jsonc(input);
        let parsed: serde_json::Value = serde_json::from_str(&cleaned).unwrap();
        assert_eq!(parsed["description"], "Bibliothèque géniale");
        assert_eq!(parsed["author"], "日本語");
    }

    // -----------------------------------------------------------------------
    // extract_name_from_node_modules_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_name_simple() {
        assert_eq!(
            extract_name_from_node_modules_path("node_modules/express"),
            Some("express")
        );
    }

    #[test]
    fn test_extract_name_scoped() {
        assert_eq!(
            extract_name_from_node_modules_path("node_modules/@types/node"),
            Some("@types/node")
        );
    }

    #[test]
    fn test_extract_name_nested_ignored() {
        assert_eq!(
            extract_name_from_node_modules_path("node_modules/a/node_modules/b"),
            None
        );
    }

    #[test]
    fn test_extract_name_root_ignored() {
        assert_eq!(extract_name_from_node_modules_path(""), None);
    }

    // -----------------------------------------------------------------------
    // parse_npm_lockfile dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_dispatch_package_lock() {
        let content =
            r#"{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}}}"#;
        let map = parse_npm_lockfile(content, NpmLockfileType::PackageLock);
        assert_eq!(map.get("a").map(|s| s.as_str()), Some("1.0.0"));
    }

    #[test]
    fn test_dispatch_yarn_lock() {
        let content = "a@^1.0.0:\n  version \"1.2.3\"\n";
        let map = parse_npm_lockfile(content, NpmLockfileType::YarnLock);
        assert_eq!(map.get("a").map(|s| s.as_str()), Some("1.2.3"));
    }

    #[test]
    fn test_dispatch_pnpm_lock() {
        let content = "packages:\n\n  a@1.2.3:\n    resolution: {}\n";
        let map = parse_npm_lockfile(content, NpmLockfileType::PnpmLock);
        assert_eq!(map.get("a").map(|s| s.as_str()), Some("1.2.3"));
    }

    #[test]
    fn test_dispatch_bun_lock() {
        let content = r#"{"packages": {"a": ["a@1.2.3"]}}"#;
        let map = parse_npm_lockfile(content, NpmLockfileType::BunLock);
        assert_eq!(map.get("a").map(|s| s.as_str()), Some("1.2.3"));
    }

    // -----------------------------------------------------------------------
    // parse_package_lock_graph
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_package_lock_graph_v3() {
        let content = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0", "dependencies": { "react": "^18.0.0" } },
    "node_modules/react": { "version": "18.2.0", "dependencies": { "scheduler": "^0.23.0" } },
    "node_modules/scheduler": { "version": "0.23.0" }
  }
}"#;
        let graph = parse_package_lock_graph(content);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"scheduler"));
        let react = graph.packages.iter().find(|p| p.name == "react").unwrap();
        assert_eq!(react.version, "18.2.0");
        assert_eq!(react.dependencies, vec!["scheduler".to_string()]);
    }

    // -----------------------------------------------------------------------
    // parse_pnpm_lock_graph
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pnpm_lock_graph() {
        let content = r#"
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      react:
        specifier: ^18.0.0
        version: 18.2.0

packages:
  /react@18.2.0:
    resolution: {integrity: sha512-xxx}
    dependencies:
      scheduler: 0.23.0
  /scheduler@0.23.0:
    resolution: {integrity: sha512-yyy}
"#;
        let graph = parse_pnpm_lock_graph(content);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"scheduler"));
        let react = graph.packages.iter().find(|p| p.name == "react").unwrap();
        assert_eq!(react.version, "18.2.0");
        assert_eq!(react.dependencies, vec!["scheduler".to_string()]);
    }

    #[test]
    fn test_parse_pnpm_lock_graph_v9() {
        let content = r#"
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      react: 18.2.0

packages:
  react@18.2.0:
    resolution: {integrity: sha512-xxx}
    dependencies:
      scheduler: 0.23.0
  scheduler@0.23.0:
    resolution: {integrity: sha512-yyy}
"#;
        let graph = parse_pnpm_lock_graph(content);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"scheduler"));
        let react = graph.packages.iter().find(|p| p.name == "react").unwrap();
        assert_eq!(react.version, "18.2.0");
        assert_eq!(react.dependencies, vec!["scheduler".to_string()]);
    }

    // -----------------------------------------------------------------------
    // parse_yarn_lock_graph
    // -----------------------------------------------------------------------

    /// pnpm v9 keeps `resolution:` under `packages:` and the edges under `snapshots:`.
    #[test]
    fn test_parse_pnpm_lock_graph_reads_edges_from_snapshots() {
        let content = r#"
lockfileVersion: '9.0'

packages:

  react-dom@18.2.0:
    resolution: {integrity: sha512-xxx}

  react@18.2.0:
    resolution: {integrity: sha512-yyy}

snapshots:

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0

  react@18.2.0: {}
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert_eq!(graph.packages.len(), 2);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(
            !names.iter().any(|n| n.contains('(')),
            "no entry name should contain a peer-suffix paren, got {names:?}"
        );
        assert_eq!(pnpm_edges(&graph, "react-dom", "18.2.0"), ["react"]);
        assert!(pnpm_edges(&graph, "react", "18.2.0").is_empty());
    }

    fn pnpm_edges<'a>(graph: &'a LockfileGraph, name: &str, version: &str) -> Vec<&'a str> {
        graph
            .packages
            .iter()
            .find(|p| p.name == name && p.version == version)
            .map(|p| p.dependencies.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    #[test]
    fn test_parse_pnpm_lock_graph_merges_snapshots_of_peer_variants() {
        let content = r#"
lockfileVersion: '9.0'

packages:

  '@a/b@1.0.0':
    resolution: {integrity: sha512-a}

snapshots:

  '@a/b@1.0.0(c@1.0.0)':
    dependencies:
      c: 1.0.0
      shared: 1.0.0

  '@a/b@1.0.0(c@2.0.0)':
    dependencies:
      c: 2.0.0
      only-here: 1.0.0
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(
            pnpm_edges(&graph, "@a/b", "1.0.0"),
            ["c", "shared", "only-here"]
        );
    }

    #[test]
    fn test_parse_pnpm_lock_graph_keeps_versions_apart_when_merging() {
        let content = r#"
lockfileVersion: '9.0'

snapshots:

  a@1.0.0:
    dependencies:
      old: 1.0.0

  a@2.0.0:
    dependencies:
      new: 1.0.0
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert_eq!(pnpm_edges(&graph, "a", "1.0.0"), ["old"]);
        assert_eq!(pnpm_edges(&graph, "a", "2.0.0"), ["new"]);
    }

    /// A leaf written as `name@ver: {}` is an entry of its own, and only
    /// `dependencies:` blocks hold edges.
    #[test]
    fn test_parse_pnpm_lock_graph_leaf_snapshot_ends_the_previous_entry() {
        let content = r#"
lockfileVersion: '9.0'

snapshots:

  a@1.0.0:
    dependencies:
      leaf: 1.0.0

  leaf@1.0.0: {}

  z@1.0.0:
    transitivePeerDependencies:
      - not-an-edge
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert_eq!(graph.packages.len(), 3);
        assert_eq!(pnpm_edges(&graph, "a", "1.0.0"), ["leaf"]);
        assert!(pnpm_edges(&graph, "leaf", "1.0.0").is_empty());
        assert!(pnpm_edges(&graph, "z", "1.0.0").is_empty());
    }

    #[test]
    fn test_parse_pnpm_lock_graph_reads_optional_edges_of_snapshots() {
        let content = r#"
lockfileVersion: '9.0'

snapshots:

  chokidar@3.6.0:
    dependencies:
      braces: 3.0.2
    optionalDependencies:
      fsevents: 2.3.3
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert_eq!(
            pnpm_edges(&graph, "chokidar", "3.6.0"),
            ["braces", "fsevents"]
        );
    }

    #[test]
    fn test_parse_pnpm_lock_graph_alias_edge_points_at_the_real_package() {
        let content = r#"
lockfileVersion: '9.0'

snapshots:

  a@1.0.0:
    dependencies:
      foo: bar@1.2.0
      '@x/scoped': '@y/real@2.0.0'
      peered: target@3.0.0(peer@1.0.0)
      plain: 1.0.0
      with-peer: 1.0.0(peer@1.0.0)
      from-url: https://codeload.github.com/o/r/tar.gz/abc
      from-ssh: git+ssh://git@github.com/o/r.git
      from-link: link:../@local/pkg
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert_eq!(
            pnpm_edges(&graph, "a", "1.0.0"),
            [
                "bar",
                "@y/real",
                "target",
                "plain",
                "with-peer",
                "from-url",
                "from-ssh",
                "from-link"
            ]
        );
    }

    #[test]
    fn test_parse_pnpm_lock_graph_v6_keeps_edges_under_packages() {
        let content = r#"
lockfileVersion: '6.0'

packages:

  /a@1.0.0(peer@1.0.0):
    resolution: {integrity: sha512-a}
    dependencies:
      foo: /bar@1.2.0
      '@x/scoped': /@y/real@2.0.0(peer@1.0.0)
      peer: 1.0.0

  /a@1.0.0(peer@2.0.0):
    resolution: {integrity: sha512-a}
    dependencies:
      peer: 2.0.0
      other: 1.0.0

  /bar@1.2.0:
    resolution: {integrity: sha512-b}
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert_eq!(graph.packages.len(), 2);
        assert_eq!(
            pnpm_edges(&graph, "a", "1.0.0"),
            ["bar", "@y/real", "peer", "other"]
        );
    }

    #[test]
    fn test_split_pnpm_key_keeps_the_name_of_a_source_holding_an_at_sign() {
        let content = r#"
lockfileVersion: '9.0'
packages:
  vendor@git+ssh://git@github.com/o/r.git#abc:
    resolution: {commit: abc}
  '@acme/lib@file:packages/lib':
    resolution: {directory: packages/lib}
"#;
        let graph = parse_pnpm_lock_graph(content);
        let packages: Vec<(&str, &str)> = graph
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(
            packages,
            vec![
                ("vendor", "git+ssh://git@github.com/o/r.git#abc"),
                ("@acme/lib", "file:packages/lib"),
            ]
        );
    }

    #[test]
    fn test_split_pnpm_key_handles_peer_suffix() {
        // Only run if split_pnpm_key is accessible; otherwise test through parse_pnpm_lock_graph
        let content = r#"
lockfileVersion: '9.0'
packages:
  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-xxx}
"#;
        let graph = parse_pnpm_lock_graph(content);
        assert!(
            graph
                .packages
                .iter()
                .any(|p| p.name == "react-dom" && p.version == "18.2.0")
        );
    }

    #[test]
    fn test_parse_pnpm_lock_graph_strips_quoted_keys() {
        let content = r#"
lockfileVersion: '9.0'

packages:

  '@types/node@20.11.5':
    resolution: {integrity: sha512-xxx}
"#;
        let graph = parse_pnpm_lock_graph(content);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(
            names.contains(&"@types/node"),
            "quoted key should yield unquoted name, got {names:?}"
        );
        let ty = graph
            .packages
            .iter()
            .find(|p| p.name == "@types/node")
            .unwrap();
        assert_eq!(ty.version, "20.11.5");
    }

    #[test]
    fn test_parse_pnpm_lock_graph_unquotes_scoped_dep_names() {
        let content = r#"
lockfileVersion: '9.0'

packages:

  react@18.2.0:
    resolution: {integrity: sha512-xxx}
    dependencies:
      '@emotion/cache': 11.11.0
      react-dom: 18.2.0

  '@emotion/cache@11.11.0':
    resolution: {integrity: sha512-yyy}
"#;
        let graph = parse_pnpm_lock_graph(content);
        let react = graph.packages.iter().find(|p| p.name == "react").unwrap();
        assert!(
            react.dependencies.contains(&"@emotion/cache".to_string()),
            "scoped dep name should be unquoted, got {:?}",
            react.dependencies
        );
        assert!(react.dependencies.contains(&"react-dom".to_string()));
    }

    #[tokio::test]
    async fn npm_resolver_handles_package_lock() {
        use crate::parsers::lockfile_resolver::LockfileResolver;
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = tmp.path().join("package.json");
        let lock = tmp.path().join("package-lock.json");
        std::fs::write(&manifest, r#"{"name":"demo","version":"0.0.1"}"#).unwrap();
        std::fs::write(
            &lock,
            r#"{
          "name": "demo",
          "version": "0.0.1",
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "0.0.1" },
            "node_modules/lodash": { "version": "4.17.21" }
          }
        }"#,
        )
        .unwrap();
        let resolver = super::NpmResolver {
            lock_path: lock.clone(),
            sub: super::NpmLockfileType::PackageLock,
        };
        assert_eq!(
            resolver.find_lockfile(&manifest).await.as_deref(),
            Some(lock.as_path())
        );
        let content = std::fs::read_to_string(&lock).unwrap();
        let graph = resolver.parse_graph(&content);
        assert!(
            graph
                .packages
                .iter()
                .any(|p| p.name == "lodash" && p.version == "4.17.21")
        );
    }

    #[test]
    fn test_parse_yarn_lock_graph_v1() {
        let content = r#"
# THIS IS AN AUTOGENERATED FILE

"react@^18.0.0":
  version "18.2.0"
  dependencies:
    scheduler "^0.23.0"

"scheduler@^0.23.0":
  version "0.23.0"
"#;
        let graph = parse_yarn_lock_graph(content);
        assert!(
            graph
                .packages
                .iter()
                .any(|p| p.name == "react" && p.version == "18.2.0")
        );
        let react = graph.packages.iter().find(|p| p.name == "react").unwrap();
        assert!(react.dependencies.contains(&"scheduler".to_string()));
    }

    /// Excerpt of a real Yarn 4 lockfile (Michsior14/ngrx-addons).
    const YARN_BERRY_LOCK: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 10
  cacheKey: 10c0

"@ampproject/remapping@npm:2.3.0, @ampproject/remapping@npm:^2.3.0":
  version: 2.3.0
  resolution: "@ampproject/remapping@npm:2.3.0"
  dependencies:
    "@jridgewell/gen-mapping": "npm:^0.3.5"
    "@jridgewell/trace-mapping": "npm:^0.3.24"
  checksum: 10c0/81d63cca
  languageName: node
  linkType: hard

"@angular-devkit/architect@npm:0.2202.5, @angular-devkit/architect@npm:>= 0.2200.0 < 0.2300.0":
  version: 0.2202.5
  resolution: "@angular-devkit/architect@npm:0.2202.5"
  dependencies:
    "@angular-devkit/core": "npm:22.2.5"
    rxjs: "npm:7.8.2"
  bin:
    architect: bin/cli.js
  checksum: 10c0/9803e0f5
  languageName: node
  linkType: hard
"#;

    /// Regression (#424): Berry writes `version: X`, Classic writes `version "X"`.
    #[test]
    fn test_parse_yarn_lock_graph_berry_reads_versions() {
        let graph = parse_yarn_lock_graph(YARN_BERRY_LOCK);
        let version_of = |name: &str| {
            graph
                .packages
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.version.as_str())
        };
        assert_eq!(version_of("@ampproject/remapping"), Some("2.3.0"));
        assert_eq!(version_of("@angular-devkit/architect"), Some("0.2202.5"));
    }

    /// Berry keys are `name: "npm:range"`; `bin:` entries are not dependencies.
    #[test]
    fn test_parse_yarn_lock_graph_berry_reads_dependency_names() {
        let graph = parse_yarn_lock_graph(YARN_BERRY_LOCK);
        let deps_of = |name: &str| {
            graph
                .packages
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.dependencies.clone())
        };
        assert_eq!(
            deps_of("@angular-devkit/architect"),
            Some(vec!["@angular-devkit/core".to_string(), "rxjs".to_string()])
        );
        assert_eq!(
            deps_of("@ampproject/remapping"),
            Some(vec![
                "@jridgewell/gen-mapping".to_string(),
                "@jridgewell/trace-mapping".to_string()
            ])
        );
    }

    /// Classic lists optional dependencies in a block of their own: the scanner must walk them.
    #[test]
    fn test_parse_yarn_lock_graph_classic_keeps_optional_dependencies() {
        let lock = "foo@^1.0.0:\n  version \"1.2.3\"\n  dependencies:\n    bar \"^1.0.0\"\n  optionalDependencies:\n    baz \"^2.0.0\"\n";
        let graph = parse_yarn_lock_graph(lock);
        assert_eq!(graph.packages[0].dependencies, vec!["bar", "baz"]);
    }

    /// A dependency called `version` must not overwrite the package version.
    #[test]
    fn test_parse_yarn_lock_graph_dependency_named_version() {
        let berry =
            "\"foo@npm:^1.0.0\":\n  version: 1.2.3\n  dependencies:\n    version: \"npm:^9.0.0\"\n";
        let classic = "foo@^1.0.0:\n  version \"1.2.3\"\n  dependencies:\n    version \"^9.0.0\"\n";
        for lock in [berry, classic] {
            let graph = parse_yarn_lock_graph(lock);
            assert_eq!(graph.packages.len(), 1);
            assert_eq!(graph.packages[0].version, "1.2.3");
            assert_eq!(graph.packages[0].dependencies, vec!["version".to_string()]);
        }
    }

    /// Workspace entries are local packages: they must not reach registry or OSV lookups.
    #[test]
    fn test_parse_yarn_lock_graph_berry_skips_workspace_entries() {
        let lock = r#""@acme/root@workspace:.":
  version: 0.0.0-use.local
  resolution: "@acme/root@workspace:."
  dependencies:
    rxjs: "npm:~7.8.2"
  languageName: unknown
  linkType: soft

"rxjs@npm:~7.8.2":
  version: 7.8.2
  resolution: "rxjs@npm:7.8.2"
"#;
        let graph = parse_yarn_lock_graph(lock);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["rxjs"]);
    }

    /// Patch and alias keys can hide the real package: `resolution:` names it.
    #[test]
    fn test_parse_yarn_lock_graph_berry_patch_and_alias_names() {
        let lock = r#""typescript@patch:typescript@npm%3A~5.8.0#optional!builtin<compat/typescript>":
  version: 5.8.3
  resolution: "typescript@patch:typescript@npm%3A5.8.3#optional!builtin<compat/typescript>::version=5.8.3&hash=5786d5"

"my-alias@npm:lodash@^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
"#;
        let graph = parse_yarn_lock_graph(lock);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["typescript", "lodash"]);
    }

    /// A local package stays out even when its first header key looks like a registry one.
    #[test]
    fn test_parse_yarn_lock_graph_berry_skips_local_entries_under_any_key() {
        let lock = r#""@acme/lib@npm:^1.0.0, @acme/lib@workspace:packages/lib":
  version: 0.0.0-use.local
  resolution: "@acme/lib@workspace:packages/lib"

"@acme/portal@portal:../portal::locator=root%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "@acme/portal@portal:../portal::locator=root%40workspace%3A."

"rxjs@npm:~7.8.2":
  version: 7.8.2
  resolution: "rxjs@npm:7.8.2"
"#;
        let graph = parse_yarn_lock_graph(lock);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["rxjs"]);
    }

    /// `file:` and `exec:` packages are local too, whatever name they carry.
    #[test]
    fn test_parse_yarn_lock_graph_berry_skips_file_and_exec_entries() {
        let lock = r#""lodash@file:./vendor/lodash::locator=root%40workspace%3A.":
  version: 4.17.21
  resolution: "lodash@file:./vendor/lodash#./vendor/lodash::hash=abc123&locator=root%40workspace%3A."

"generated@exec:./gen.js::locator=root%40workspace%3A.":
  version: 1.0.0
  resolution: "generated@exec:./gen.js#./gen.js::hash=def456&locator=root%40workspace%3A."

"rxjs@npm:~7.8.2":
  version: 7.8.2
  resolution: "rxjs@npm:7.8.2"
"#;
        let graph = parse_yarn_lock_graph(lock);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["rxjs"]);
    }

    /// Berry lists an aliased package under its real name, so an edge through the
    /// alias has to reach it. Scoped targets and plain ranges are covered too.
    #[test]
    fn test_parse_yarn_lock_graph_berry_follows_alias_edges() {
        let lock = r#""@isaacs/cliui@npm:^8.0.2":
  version: 8.0.2
  resolution: "@isaacs/cliui@npm:8.0.2"
  dependencies:
    string-width: "npm:^5.1.2"
    string-width-cjs: "npm:string-width@^4.2.0"
    types-alias: "npm:@types/node@^20.0.0"

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"

"string-width@npm:^5.1.2":
  version: 5.1.2
  resolution: "string-width@npm:5.1.2"

"types-alias@npm:@types/node@^20.0.0":
  version: 20.11.5
  resolution: "@types/node@npm:20.11.5"
"#;
        let graph = parse_yarn_lock_graph(lock);
        assert_eq!(
            graph.packages[0].dependencies,
            vec!["string-width", "string-width", "@types/node"]
        );
        let reached: Vec<(&str, &str)> = graph
            .transitive_deps_of("@isaacs/cliui")
            .into_iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert!(reached.contains(&("string-width", "4.2.3")));
        assert!(reached.contains(&("@types/node", "20.11.5")));
    }

    /// Classic has no `resolution:` line and sorts an alias key first when it shares
    /// an entry with the real package, so the key and the edge must give the real name.
    #[test]
    fn test_parse_yarn_lock_graph_classic_uses_real_name_for_aliases() {
        let lock = r#""@isaacs/cliui@^8.0.2":
  version "8.0.2"
  dependencies:
    string-width-cjs "npm:string-width@^4.2.0"
    types-alias "npm:@types/node@^20.0.0"

"string-width-cjs@npm:string-width@^4.2.0", string-width@^4.1.0, string-width@^4.2.3:
  version "4.2.3"

"types-alias@npm:@types/node@^20.0.0":
  version "20.11.5"
"#;
        let graph = parse_yarn_lock_graph(lock);
        assert_eq!(
            graph.packages[0].dependencies,
            vec!["string-width", "@types/node"]
        );
        assert_eq!(graph.packages[1].name, "string-width");
        assert_eq!(graph.packages[2].name, "@types/node");
        let reached: Vec<(&str, &str)> = graph
            .transitive_deps_of("@isaacs/cliui")
            .into_iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert!(reached.contains(&("string-width", "4.2.3")));
        assert!(reached.contains(&("@types/node", "20.11.5")));
    }

    /// Berry writes a key over 1024 characters as `? key`, with `:` on its own line.
    /// Such an entry must not write into the package before it.
    #[test]
    fn test_parse_yarn_lock_graph_berry_long_key_entry() {
        let lock = r#""first@npm:^1.0.0":
  version: 1.0.0
  resolution: "first@npm:1.0.0"
  dependencies:
    tslib: "npm:^2.0.0"

? "lodash@npm:^4.0.0, lodash@npm:^4.1.0, lodash@npm:^4.2.0"
:
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  dependencies:
    rxjs: "npm:^7.0.0"

"tslib@npm:^2.0.0":
  version: 2.6.2
  resolution: "tslib@npm:2.6.2"
"#;
        let graph = parse_yarn_lock_graph(lock);
        let packages: Vec<(&str, &str, Vec<&str>)> = graph
            .packages
            .iter()
            .map(|p| {
                (
                    p.name.as_str(),
                    p.version.as_str(),
                    p.dependencies.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            packages,
            vec![
                ("first", "1.0.0", vec!["tslib"]),
                ("lodash", "4.17.21", vec!["rxjs"]),
                ("tslib", "2.6.2", vec![]),
            ]
        );
    }

    /// A local package under a long key is dropped without touching the entry before it.
    #[test]
    fn test_parse_yarn_lock_graph_berry_long_key_local_entry() {
        let lock = r#""first@npm:^1.0.0":
  version: 1.0.0
  resolution: "first@npm:1.0.0"

? "@acme/lib@workspace:*, @acme/lib@workspace:packages/lib"
:
  version: 0.0.0-use.local
  resolution: "@acme/lib@workspace:packages/lib"
"#;
        let graph = parse_yarn_lock_graph(lock);
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.packages[0].name, "first");
        assert_eq!(graph.packages[0].version, "1.0.0");
    }

    /// Classic writes `foo@:` for a dependency declared with an empty range.
    #[test]
    fn test_parse_yarn_lock_graph_classic_empty_range_key() {
        let graph = parse_yarn_lock_graph("foo@:\n  version \"1.2.3\"\n");
        assert_eq!(graph.packages[0].name, "foo");
        assert_eq!(graph.packages[0].version, "1.2.3");
    }

    /// Issue #424 end to end: a Berry lockfile feeds `resolved_version`.
    #[tokio::test]
    async fn test_npm_resolver_resolves_berry_versions() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let lock_path = dir.path().join("yarn.lock");
        tokio::fs::write(&lock_path, YARN_BERRY_LOCK).await?;
        let resolver = Box::new(NpmResolver {
            lock_path,
            sub: NpmLockfileType::YarnLock,
        });
        let manifest = r#"{"dependencies": {"@ampproject/remapping": "^2.3.0"}}"#;
        let mut deps = NpmParser::new().parse(manifest);
        resolve_versions_from_lockfile(&mut deps, resolver, &dir.path().join("package.json")).await;
        assert_eq!(deps[0].resolved_version.as_deref(), Some("2.3.0"));
        Ok(())
    }

    /// Resolve `spec` for `name` against a lockfile locking several versions of it.
    fn resolve_among_versions(name: &str, spec: &str, versions: &[&str]) -> Option<String> {
        let packages = versions
            .iter()
            .map(|version| LockfilePackage {
                name: name.to_string(),
                version: (*version).to_string(),
                dependencies: Vec::new(),
                is_root: false,
            })
            .collect();
        let resolver = NpmResolver {
            lock_path: PathBuf::from("yarn.lock"),
            sub: NpmLockfileType::YarnLock,
        };
        let manifest = format!(r#"{{"dependencies": {{"{name}": "{spec}"}}}}"#);
        let deps = NpmParser::new().parse(&manifest);
        resolver.resolve_version(
            &deps[0],
            &LockfileGraph {
                packages,
                ..Default::default()
            },
        )
    }

    /// Resolve `spec` for `name` through `NpmResolver`, from lockfile text.
    fn resolve_from_lock(
        sub: NpmLockfileType,
        lock: &str,
        name: &str,
        spec: &str,
    ) -> Option<String> {
        let resolver = NpmResolver {
            lock_path: PathBuf::from("lockfile"),
            sub,
        };
        let manifest = format!(r#"{{"dependencies": {{"{name}": "{spec}"}}}}"#);
        let deps = NpmParser::new().parse(&manifest);
        resolver.resolve_version(&deps[0], &resolver.parse_graph(lock))
    }

    /// Lock one `foo` version per range, in both yarn.lock formats, then resolve `spec`.
    fn resolve_in_both_yarn_formats(ranges: &[(&str, &str)], spec: &str) -> [Option<String>; 2] {
        let mut classic = String::from("# yarn lockfile v1\n\n");
        let mut berry = String::from("__metadata:\n  version: 8\n\n");
        for (range, version) in ranges {
            classic.push_str(&format!("\"foo@{range}\":\n  version \"{version}\"\n\n"));
            berry.push_str(&format!(
                "\"foo@npm:{range}\":\n  version: {version}\n  resolution: \"foo@npm:{version}\"\n\n"
            ));
        }
        [classic, berry]
            .map(|lock| resolve_from_lock(NpmLockfileType::YarnLock, &lock, "foo", spec))
    }

    fn both_yarn_formats_lock(version: &str) -> [Option<String>; 2] {
        [Some(version.to_string()), Some(version.to_string())]
    }

    /// npm reads `1.2` as `1.2.x`, where the `semver` crate reads it as `^1.2`.
    #[test]
    fn test_yarn_partial_version_is_not_a_caret_range() {
        assert_eq!(
            resolve_in_both_yarn_formats(&[("1.2", "1.2.5"), ("^1.3.0", "1.3.0")], "1.2"),
            both_yarn_formats_lock("1.2.5")
        );
    }

    /// Another dependent's newer version in the range must not hide an update.
    #[test]
    fn test_yarn_ignores_newer_version_locked_for_another_range() {
        assert_eq!(
            resolve_in_both_yarn_formats(&[("^1.5.0", "1.6.0"), ("^1.0.0", "1.2.0")], "^1.0.0"),
            both_yarn_formats_lock("1.2.0")
        );
    }

    #[test]
    fn test_yarn_space_separated_range_is_not_the_first_entry() {
        assert_eq!(
            resolve_in_both_yarn_formats(&[("^3.0.0", "3.0.0"), (">=1 <2", "1.5.0")], ">=1 <2"),
            both_yarn_formats_lock("1.5.0")
        );
    }

    #[test]
    fn test_yarn_or_range_is_not_the_first_entry() {
        assert_eq!(
            resolve_in_both_yarn_formats(
                &[("^3.0.0", "3.0.0"), ("^1.0.0 || ^2.0.0", "2.4.0")],
                "^1.0.0 || ^2.0.0"
            ),
            both_yarn_formats_lock("2.4.0")
        );
    }

    /// Every range of a multi-range key maps to the entry's version.
    #[test]
    fn test_yarn_multi_range_key_maps_every_range() {
        let classic = "\"foo@^3.0.0\":\n  version \"3.0.0\"\n\nfoo@^1.0.0, foo@^1.1.0:\n  version \"1.2.0\"\n";
        let berry = "\"foo@npm:^3.0.0\":\n  version: 3.0.0\n  resolution: \"foo@npm:3.0.0\"\n\n\"foo@npm:^1.0.0, foo@npm:^1.1.0\":\n  version: 1.2.0\n  resolution: \"foo@npm:1.2.0\"\n";
        for lock in [classic, berry] {
            for spec in ["^1.0.0", "^1.1.0"] {
                assert_eq!(
                    resolve_from_lock(NpmLockfileType::YarnLock, lock, "foo", spec).as_deref(),
                    Some("1.2.0"),
                    "{spec} in {lock}"
                );
            }
        }
    }

    #[test]
    fn test_yarn_berry_explicit_npm_protocol_and_scoped_name() {
        let lock = "\"@scope/foo@npm:^2.0.0\":\n  version: 2.1.0\n  resolution: \"@scope/foo@npm:2.1.0\"\n\n\"@scope/foo@npm:^1.0.0\":\n  version: 1.2.0\n  resolution: \"@scope/foo@npm:1.2.0\"\n";
        for spec in ["^1.0.0", "npm:^1.0.0"] {
            assert_eq!(
                resolve_from_lock(NpmLockfileType::YarnLock, lock, "@scope/foo", spec).as_deref(),
                Some("1.2.0"),
                "{spec}"
            );
        }
    }

    #[test]
    fn test_yarn_berry_long_key_maps_its_ranges() {
        let lock = "\"foo@npm:^3.0.0\":\n  version: 3.0.0\n  resolution: \"foo@npm:3.0.0\"\n\n? \"foo@npm:^1.0.0, foo@npm:^1.1.0\"\n:\n  version: 1.2.0\n  resolution: \"foo@npm:1.2.0\"\n";
        assert_eq!(
            resolve_from_lock(NpmLockfileType::YarnLock, lock, "foo", "^1.1.0").as_deref(),
            Some("1.2.0")
        );
    }

    /// The graph lists an aliased package under its real name; only the key
    /// ties it to the name in the manifest.
    #[test]
    fn test_yarn_alias_resolves_through_its_key() {
        let classic = "\"bar@^2.0.0\":\n  version \"2.0.0\"\n\n\"foo@npm:bar@^1.0.0\":\n  version \"1.2.0\"\n";
        let berry = "\"bar@npm:^2.0.0\":\n  version: 2.0.0\n  resolution: \"bar@npm:2.0.0\"\n\n\"foo@npm:bar@^1.0.0\":\n  version: 1.2.0\n  resolution: \"bar@npm:1.2.0\"\n";
        for lock in [classic, berry] {
            assert_eq!(
                resolve_from_lock(NpmLockfileType::YarnLock, lock, "foo", "npm:bar@^1.0.0")
                    .as_deref(),
                Some("1.2.0"),
                "{lock}"
            );
        }
    }

    /// The lockfile's `foo` is a real package with that name, not the alias.
    #[test]
    fn test_stale_alias_to_its_own_name_takes_the_only_version() {
        let lock = "\"foo@npm:^1.0.0\":\n  version: 1.2.0\n";
        let version = resolve_from_lock(NpmLockfileType::YarnLock, lock, "foo", "npm:foo@^2.0.0");
        assert_eq!(version.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn test_yarn_keeps_a_conflicting_spec_as_ambiguous() {
        let lock = concat!(
            "\"foo@npm:bar@^1.0.0\":\n  version: 1.0.0\n\n",
            "\"foo@npm:bar@^1.0.0\", \"baz@^1.0.0\":\n  version: 1.1.0\n",
        );
        let graph = parse_yarn_lock_graph(lock);
        assert!(!graph.locked_specs.contains_key("foo@npm:bar@^1.0.0"));
        assert!(graph.records_spec("foo@npm:bar@^1.0.0"));
    }

    #[test]
    fn test_stale_yarn_alias_does_not_take_the_local_name_version() {
        let classic =
            "foo@^3.0.0:\n  version \"3.0.0\"\n\n\"foo@npm:bar@^1.0.0\":\n  version \"1.2.0\"\n";
        let berry = "\"foo@npm:^3.0.0\":\n  version: 3.0.0\n  resolution: \"foo@npm:3.0.0\"\n\n\"foo@npm:bar@^1.0.0\":\n  version: 1.2.0\n  resolution: \"bar@npm:1.2.0\"\n";
        for lock in [classic, berry] {
            assert_eq!(
                resolve_from_lock(NpmLockfileType::YarnLock, lock, "foo", "npm:bar@^2.0.0"),
                None,
                "{lock}"
            );
        }
    }

    #[test]
    fn test_npm_alias_target_tells_packages_from_ranges() {
        for (spec, expected) in [
            ("npm:7zip-bin", Some(("7zip-bin", "*"))),
            ("npm:2-thumbs", Some(("2-thumbs", "*"))),
            ("npm:1", None),
            ("npm:1.x", None),
            ("npm:1.2.3-beta.1", None),
            ("npm:1 - 2", None),
            ("npm:1 || 2", None),
            ("npm:bar@^1.0.0", Some(("bar", "^1.0.0"))),
            ("npm:@scope/bar@1.2.0", Some(("@scope/bar", "1.2.0"))),
            ("npm:bar", Some(("bar", "*"))),
            ("npm:@scope/bar", Some(("@scope/bar", "*"))),
            ("npm:^1.0.0", None),
            ("npm:~1.0.0", None),
            ("npm:>=1.0.0", None),
            ("npm:*", None),
            ("npm:1.2.3", None),
            ("npm:", None),
            ("npm:latest", None),
            ("^1.0.0", None),
        ] {
            assert_eq!(npm_alias_target(spec), expected, "{spec}");
        }
    }

    /// Berry's `npm:latest` is a tag of the package itself, so the edge keeps its name.
    #[test]
    fn test_yarn_berry_tag_edge_is_not_an_alias() {
        let lock = "\"x@npm:^1.0.0\":\n  version: 1.0.0\n  resolution: \"x@npm:1.0.0\"\n  dependencies:\n    foo: \"npm:latest\"\n    baz: \"npm:real@^2.0.0\"\n";
        let graph = parse_yarn_lock_graph(lock);
        assert_eq!(graph.packages[0].dependencies, ["foo", "real"]);
    }

    /// A `patch:` entry repeats the version of the entry it patches.
    #[test]
    fn test_yarn_berry_patch_entry_counts_as_one_locked_version() {
        let lock = "\"typescript@npm:^5.3.3\":\n  version: 5.3.3\n  resolution: \"typescript@npm:5.3.3\"\n\n\"typescript@patch:typescript@^5.3.3#builtin\":\n  version: 5.3.3\n  resolution: \"typescript@patch:typescript@npm%3A5.3.3#builtin\"\n";
        assert_eq!(
            resolve_from_lock(NpmLockfileType::YarnLock, lock, "typescript", "^5.4.0").as_deref(),
            Some("5.3.3")
        );
    }

    /// pnpm keeps one entry per peer set, all at the same version.
    #[test]
    fn test_pnpm_peer_variants_count_as_one_locked_version() {
        let lock = r#"lockfileVersion: '6.0'

packages:

  /foo@1.2.0(peer@1.0.0):
    resolution: {integrity: sha512-a}

  /foo@1.2.0(peer@2.0.0):
    resolution: {integrity: sha512-a}
"#;
        assert_eq!(
            resolve_from_lock(NpmLockfileType::PnpmLock, lock, "foo", "^1.5.0").as_deref(),
            Some("1.2.0")
        );
    }

    /// Local packages are dropped from the graph; their keys must go with them.
    #[test]
    fn test_yarn_berry_local_entry_keys_do_not_resolve() {
        let lock = "\"foo@workspace:packages/foo\":\n  version: 0.0.0-use.local\n  resolution: \"foo@workspace:packages/foo\"\n";
        assert_eq!(
            resolve_from_lock(
                NpmLockfileType::YarnLock,
                lock,
                "foo",
                "workspace:packages/foo"
            ),
            None
        );
    }

    /// A range no key holds means a stale lockfile: choosing a version would be a guess.
    #[test]
    fn test_stale_yarn_lock_does_not_guess_among_versions() {
        assert_eq!(
            resolve_in_both_yarn_formats(&[("^1.0.0", "1.2.0"), ("^2.0.0", "2.1.0")], "^2.5.0"),
            [None, None]
        );
    }

    #[test]
    fn test_stale_yarn_lock_keeps_the_only_locked_version() {
        assert_eq!(
            resolve_in_both_yarn_formats(&[("^1.0.0", "1.2.0")], "^1.1.0"),
            both_yarn_formats_lock("1.2.0")
        );
    }

    /// `main.rs` calls `select_npm_version` directly with the parsed graph.
    #[test]
    fn test_select_npm_version_reads_yarn_keys() {
        let lock = "\"foo@npm:^1.5.0\":\n  version: 1.6.0\n  resolution: \"foo@npm:1.6.0\"\n\n\"foo@npm:^1.0.0\":\n  version: 1.2.0\n  resolution: \"foo@npm:1.2.0\"\n";
        let deps = NpmParser::new().parse(r#"{"dependencies": {"foo": "^1.0.0"}}"#);
        assert_eq!(
            select_npm_version(&deps[0], &parse_yarn_lock_graph(lock)).as_deref(),
            Some("1.2.0")
        );
    }

    /// A pnpm lockfile holding the catalog entry `foo: npm:bar@^1.0.0`.
    const PNPM_CATALOG_ALIAS_LOCK: &str = r#"lockfileVersion: '9.0'

catalogs:
  default:
    foo:
      specifier: npm:bar@^1.0.0
      version: 1.2.0
  legacy:
    foo:
      specifier: npm:bar@^0.9.0
      version: 0.9.5

importers:

  .:
    dependencies:
      foo:
        specifier: 'catalog:'
        version: bar@1.2.0

packages:

  bar@0.9.5:
    resolution: {integrity: sha512-a}

  bar@1.2.0:
    resolution: {integrity: sha512-b}
"#;

    fn catalog_dep(reference: &str, workspace: &str) -> Dependency {
        let manifest = format!(r#"{{"dependencies": {{"foo": "{reference}"}}}}"#);
        let mut deps = crate::parsers::pnpm_workspace::resolve_catalog_references(
            NpmParser::new().parse(&manifest),
            Some(workspace),
        );
        deps.remove(0)
    }

    #[test]
    fn test_select_npm_version_reads_a_catalog_alias_from_the_pnpm_catalogs_section() {
        let workspace =
            "catalog:\n  foo: npm:bar@^1.0.0\ncatalogs:\n  legacy:\n    foo: npm:bar@^0.9.0\n";
        let graph = parse_pnpm_lock_graph(PNPM_CATALOG_ALIAS_LOCK);

        assert_eq!(
            select_npm_version(&catalog_dep("catalog:", workspace), &graph).as_deref(),
            Some("1.2.0")
        );
        assert_eq!(
            select_npm_version(&catalog_dep("catalog:legacy", workspace), &graph).as_deref(),
            Some("0.9.5")
        );
    }

    /// `foo@catalog:` stays recorded after the catalog entry changes, so it says
    /// nothing about the alias now declared.
    #[test]
    fn test_select_npm_version_rejects_a_catalog_alias_the_lockfile_predates() {
        let dep = catalog_dep("catalog:", "catalog:\n  foo: npm:baz@^2.0.0\n");

        assert_eq!(
            select_npm_version(&dep, &parse_pnpm_lock_graph(PNPM_CATALOG_ALIAS_LOCK)),
            None
        );
    }

    #[test]
    fn test_select_npm_version_reads_a_catalog_alias_from_yarn_keys() {
        let lock = "\"foo@npm:bar@^1.0.0\":\n  version: 1.2.0\n  resolution: \"bar@npm:1.2.0\"\n";
        let dep = catalog_dep("catalog:", "catalog:\n  foo: npm:bar@^1.0.0\n");

        assert_eq!(
            select_npm_version(&dep, &parse_yarn_lock_graph(lock)).as_deref(),
            Some("1.2.0")
        );
    }

    /// Yarn catalogs write the catalog's range in the key, not the `catalog:` marker.
    #[test]
    fn test_select_npm_version_uses_the_catalog_range_in_yarn_keys() {
        let lock = "\"react@npm:^17.0.0\":\n  version: 17.0.2\n  resolution: \"react@npm:17.0.2\"\n\n\"react@npm:^18.2.0\":\n  version: 18.3.1\n  resolution: \"react@npm:18.3.1\"\n";
        let deps = crate::parsers::pnpm_workspace::resolve_catalog_references(
            NpmParser::new().parse(r#"{"dependencies": {"react": "catalog:"}}"#),
            Some("catalog:\n  react: ^18.2.0\n"),
        );
        assert_eq!(
            select_npm_version(&deps[0], &parse_yarn_lock_graph(lock)).as_deref(),
            Some("18.3.1")
        );
    }

    const PNPM_V9_LOCK: &str = r#"lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@scope/foo':
        specifier: ^1.0.0
        version: 1.2.0
      foo:
        specifier: '>=1 <2'
        version: 1.2.0(react@18.2.0)
      aliased:
        specifier: npm:foo@^1.0.0
        version: foo@1.2.0
      react:
        specifier: 'catalog:'
        version: 18.3.1
      local:
        specifier: workspace:*
        version: link:../local

packages:

  '@scope/foo@1.2.0':
    resolution: {integrity: sha512-a}

  '@scope/foo@1.6.0':
    resolution: {integrity: sha512-b}

  foo@1.2.0:
    resolution: {integrity: sha512-c}

  foo@1.6.0:
    resolution: {integrity: sha512-d}

  react@17.0.2:
    resolution: {integrity: sha512-e}

  react@18.3.1:
    resolution: {integrity: sha512-f}
"#;

    #[test]
    fn test_pnpm_v9_importers_map_specifiers_to_versions() {
        for (name, spec, expected) in [
            ("@scope/foo", "^1.0.0", Some("1.2.0")),
            ("foo", ">=1 <2", Some("1.2.0")),
            ("aliased", "npm:foo@^1.0.0", Some("1.2.0")),
            ("local", "workspace:*", None),
        ] {
            assert_eq!(
                resolve_from_lock(NpmLockfileType::PnpmLock, PNPM_V9_LOCK, name, spec).as_deref(),
                expected,
                "{name}@{spec}"
            );
        }
    }

    /// Keeps the importers of `foo` for the conflict tests, each locking `^1.0.0`.
    fn pnpm_lock_with_importer_versions(versions: &[&str]) -> String {
        let mut lock = String::from("lockfileVersion: '9.0'\n\nimporters:\n\n");
        for (index, version) in versions.iter().enumerate() {
            lock.push_str(&format!(
                "  packages/p{index}:\n    dependencies:\n      foo:\n        specifier: ^1.0.0\n        version: {version}\n\n"
            ));
        }
        lock.push_str(
            "packages:\n\n  foo@1.2.0:\n    resolution: {integrity: sha512-a}\n\n  foo@1.6.0:\n    resolution: {integrity: sha512-b}\n",
        );
        lock
    }

    /// The resolver does not know which importer a manifest belongs to, so a
    /// spec its importers lock differently has no single answer.
    #[test]
    fn test_pnpm_importers_locking_a_spec_differently_choose_no_version() {
        for versions in [["1.2.0", "1.6.0", "1.6.0"], ["1.2.0", "1.6.0", "1.2.0"]] {
            let lock = pnpm_lock_with_importer_versions(&versions);
            assert_eq!(
                resolve_from_lock(NpmLockfileType::PnpmLock, &lock, "foo", "^1.0.0"),
                None,
                "{versions:?}"
            );
        }
    }

    #[test]
    fn test_pnpm_importers_agreeing_on_a_spec_keep_its_version() {
        let lock = pnpm_lock_with_importer_versions(&["1.6.0", "1.6.0(react@18.3.1)"]);
        assert_eq!(
            resolve_from_lock(NpmLockfileType::PnpmLock, &lock, "foo", "^1.0.0").as_deref(),
            Some("1.6.0")
        );
    }

    /// pnpm writes an environment document before the main one. Only the main
    /// document describes the project: its own `pnpm` entry must not be mixed
    /// with the one that runs the package manager.
    #[test]
    fn test_pnpm_multi_document_lock_reads_the_main_document() {
        let lock = r#"---
lockfileVersion: '9.0'

importers:

  .:
    packageManagerDependencies:
      pnpm:
        specifier: ^10.0.0
        version: 10.5.0

packages:

  pnpm@10.5.0:
    resolution: {integrity: sha512-a}

snapshots:

  pnpm@10.5.0: {}

---
lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      pnpm:
        specifier: ^10.0.0
        version: 10.4.0

packages:

  pnpm@10.4.0:
    resolution: {integrity: sha512-b}

snapshots:

  pnpm@10.4.0: {}
"#;
        assert_eq!(
            resolve_from_lock(NpmLockfileType::PnpmLock, lock, "pnpm", "^10.0.0").as_deref(),
            Some("10.4.0")
        );
        let graph = parse_pnpm_lock_graph(lock);
        assert_eq!(graph.find_all("pnpm").len(), 1);
    }

    #[test]
    fn test_yarn_duplicate_descriptors_keep_a_version_only_when_they_agree() {
        for (second, third, expected) in [
            ("1.6.0", "1.6.0", None),
            ("1.6.0", "1.2.0", None),
            ("1.2.0", "1.2.0", Some("1.2.0")),
        ] {
            let lock = format!(
                "foo@^1.0.0:\n  version \"1.2.0\"\n\nfoo@^1.0.0:\n  version \"{second}\"\n\nfoo@^1.0.0:\n  version \"{third}\"\n\nfoo@^1.5.0:\n  version \"1.6.0\"\n"
            );
            assert_eq!(
                resolve_from_lock(NpmLockfileType::YarnLock, &lock, "foo", "^1.0.0").as_deref(),
                expected,
                "{second}, {third}"
            );
        }
    }

    /// pnpm v6 writes the sections at the top level for a single project, and
    /// a `/` before an aliased version.
    #[test]
    fn test_pnpm_v6_top_level_sections_map_specifiers_to_versions() {
        let lock = r#"lockfileVersion: '6.0'

dependencies:
  foo:
    specifier: ^1.0.0
    version: 1.2.0

devDependencies:
  aliased:
    specifier: npm:foo@^1.5.0
    version: /foo@1.6.0

packages:

  /foo@1.2.0:
    resolution: {integrity: sha512-a}
    dev: false

  /foo@1.6.0:
    resolution: {integrity: sha512-b}
    dev: true
"#;
        for (name, spec, expected) in [
            ("foo", "^1.0.0", "1.2.0"),
            ("aliased", "npm:foo@^1.5.0", "1.6.0"),
        ] {
            assert_eq!(
                resolve_from_lock(NpmLockfileType::PnpmLock, lock, name, spec).as_deref(),
                Some(expected),
                "{name}@{spec}"
            );
        }
    }

    /// `catalog:` holds no range: pnpm records the marker as the specifier.
    #[test]
    fn test_select_npm_version_uses_the_catalog_specifier() {
        let manifest = r#"{"dependencies": {"react": "catalog:"}}"#;
        let deps = crate::parsers::pnpm_workspace::resolve_catalog_references(
            NpmParser::new().parse(manifest),
            Some("catalog:\n  react: ^18.2.0\n"),
        );

        assert_eq!(
            select_npm_version(&deps[0], &parse_pnpm_lock_graph(PNPM_V9_LOCK)).as_deref(),
            Some("18.3.1")
        );
    }

    /// package-lock keeps one top-level copy per name, whatever the range says:
    /// other versions sit under nested `node_modules` paths.
    #[test]
    fn test_package_lock_uses_the_top_level_copy() {
        let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"foo": "^1.0.0", "aliased": "npm:foo@^1.5.0"}},
    "node_modules/foo": {"version": "1.2.0"},
    "node_modules/aliased": {"name": "foo", "version": "1.6.0"},
    "node_modules/other/node_modules/foo": {"version": "1.9.0"}
  }
}"#;
        for (name, spec, expected) in [
            ("foo", "^1.0.0", "1.2.0"),
            ("aliased", "npm:foo@^1.5.0", "1.6.0"),
        ] {
            assert_eq!(
                resolve_from_lock(NpmLockfileType::PackageLock, lock, name, spec).as_deref(),
                Some(expected),
                "{name}@{spec}"
            );
        }
    }

    /// A bare npm version is an exact pin, unlike a bare semver requirement.
    #[test]
    fn test_npm_resolver_honors_exact_pin() {
        assert_eq!(
            resolve_among_versions("autoprefixer", "10.6.0", &["10.6.0", "10.6.1"]).as_deref(),
            Some("10.6.0")
        );
    }

    /// Bun's flat graph holds one version per name and no ranges.
    #[test]
    fn test_npm_resolver_keeps_the_only_candidate_without_ranges() {
        assert_eq!(
            resolve_among_versions("foo", "^1.0.0", &["1.2.0"]).as_deref(),
            Some("1.2.0")
        );
    }

    #[test]
    fn test_npm_resolver_does_not_guess_without_ranges() {
        assert_eq!(
            resolve_among_versions("foo", "^1.0.0", &["1.2.0", "1.6.0"]),
            None
        );
    }

    /// Regression: parse_package_lock_graph must not surface nested node_modules
    /// copies. resolve_version-by-name on a graph that includes a transitive
    /// (nested) version would otherwise return the wrong version for the
    /// top-level dependency.
    #[test]
    fn test_parse_package_lock_graph_skips_nested_node_modules() {
        let content = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/foo": { "version": "2.0.0" },
    "node_modules/bar": { "version": "1.0.0", "dependencies": { "foo": "^1.0.0" } },
    "node_modules/bar/node_modules/foo": { "version": "1.0.0" }
  }
}"#;
        let graph = parse_package_lock_graph(content);
        let foo_entries: Vec<&LockfilePackage> =
            graph.packages.iter().filter(|p| p.name == "foo").collect();
        assert_eq!(
            foo_entries.len(),
            1,
            "nested node_modules/foo must not be added a second time"
        );
        assert_eq!(
            foo_entries[0].version, "2.0.0",
            "top-level foo (2.0.0) wins over nested copy (1.0.0)"
        );
    }
}
