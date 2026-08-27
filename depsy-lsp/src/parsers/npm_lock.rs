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
    let mut in_packages = false;
    let mut current: Option<LockfilePackage> = None;
    let mut in_deps = false;

    for line in content.lines() {
        // Exit packages section on any new top-level key (e.g. "snapshots:", "settings:", etc.)
        if in_packages
            && !line.is_empty()
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && line != "packages:"
        {
            in_packages = false;
            if let Some(finish) = current.take() {
                graph.packages.push(finish);
            }
            continue;
        }

        if line == "packages:" {
            in_packages = true;
            continue;
        }
        if !in_packages {
            continue;
        }
        // Package entry: "  /name@ver:" (v6) or "  name@ver:" (v9)
        let entry_key = if let Some(rest) = line.strip_prefix("  /") {
            Some(rest)
        } else if line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim().contains('@')
            && line.trim_end().ends_with(':')
        {
            Some(&line[2..])
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
        if line.trim() == "dependencies:" {
            in_deps = true;
            continue;
        }
        if in_deps && line.starts_with("      ") {
            let trimmed = line.trim_start();
            let dep_name_raw = trimmed
                .split_once(':')
                .map(|(n, _)| n.trim())
                .unwrap_or(trimmed.trim());
            // pnpm v9 quotes scoped names like '@emotion/cache'
            let dep_name = dep_name_raw.trim_matches('\'').trim_matches('"');
            if !dep_name.is_empty()
                && let Some(cur) = current.as_mut()
            {
                cur.dependencies.push(dep_name.to_string());
            }
        } else if !line.starts_with("      ") {
            in_deps = false;
        }
    }

    if let Some(finish) = current {
        graph.packages.push(finish);
    }
    graph
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
    let at = base.rfind('@')?;
    if at == 0 {
        return None; // scoped name starts with '@' — first '@' is not the separator
    }
    Some((base[..at].to_string(), base[at + 1..].to_string()))
}

/// Parse a `yarn.lock` (Yarn Classic v1 format) into a [`LockfileGraph`].
///
/// Yarn Berry v2+ uses a different YAML-based format and is not handled by
/// this entry point.
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
    let mut in_deps = false;

    for line in content.lines() {
        let trimmed = line.trim_start();

        if !line.starts_with(' ')
            && line.contains('@')
            && line.ends_with(':')
            && !line.starts_with('#')
        {
            if let Some(finished) = current.take() {
                graph.packages.push(finished);
            }
            let header = line.trim_end_matches(':').trim();
            // Multiple keys comma-separated; take the first
            let first_key_raw = header.split(',').next().unwrap_or(header).trim();
            let first_key = first_key_raw.trim_matches('"');
            if let Some(at_pos) = first_key.rfind('@')
                && at_pos != 0
            {
                current = Some(LockfilePackage {
                    name: first_key[..at_pos].to_string(),
                    version: String::new(),
                    dependencies: Vec::new(),
                    is_root: false,
                });
            }
            in_deps = false;
            continue;
        }

        if let Some(cur) = current.as_mut() {
            if let Some(v) = trimmed.strip_prefix("version ") {
                cur.version = v.trim().trim_matches('"').to_string();
                in_deps = false;
                continue;
            }
            if trimmed == "dependencies:" {
                in_deps = true;
                continue;
            }
            if in_deps && line.starts_with("    ") {
                let name = trimmed
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches('"');
                if !name.is_empty() {
                    cur.dependencies.push(name.to_string());
                }
            } else if !line.starts_with("  ") {
                in_deps = false;
            }
        }
    }

    if let Some(finished) = current {
        graph.packages.push(finished);
    }
    graph
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_parse_pnpm_lock_graph_exits_packages_section_on_snapshots() {
        let content = r#"
lockfileVersion: '9.0'

packages:

  react@18.2.0:
    resolution: {integrity: sha512-xxx}

snapshots:

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
"#;
        let graph = parse_pnpm_lock_graph(content);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        // Should include react but NOT react-dom (which lives under snapshots:)
        assert!(names.contains(&"react"));
        assert!(
            !names.iter().any(|n| n.contains('(')),
            "no entry name should contain a peer-suffix paren, got {names:?}"
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
