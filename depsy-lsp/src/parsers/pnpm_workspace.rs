//! Parser for pnpm `pnpm-workspace.yaml` catalog dependencies.

use async_trait::async_trait;
use hashbrown::HashMap;
use std::path::{Path, PathBuf};

use super::lockfile_graph::{LockfileGraph, read_lockfile_capped};
use super::lockfile_resolver::LockfileResolver;
use super::npm_lock::{npm_alias_target, parse_pnpm_lock_graph, pnpm_locked_version};
use super::{Dependency, Parser, Span};
use crate::file_types::PNPM_WORKSPACE_FILENAME;

/// File name of the lockfile pnpm writes in the workspace root.
const PNPM_LOCKFILE_FILENAME: &str = "pnpm-lock.yaml";

/// Parser for pnpm workspace catalog dependency files.
#[derive(Debug, Default)]
pub struct PnpmWorkspaceParser;

#[derive(Debug)]
struct NamedCatalog {
    name: String,
    dependencies: Vec<Dependency>,
}

impl PnpmWorkspaceParser {
    /// Creates a new [`PnpmWorkspaceParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for PnpmWorkspaceParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        parse_catalog_entries(content)
            .into_iter()
            .map(|(_, dependency)| dependency)
            .collect()
    }
}

/// Resolve npm `catalog:` dependency references against a pnpm workspace file.
pub fn resolve_catalog_references(
    dependencies: Vec<Dependency>,
    workspace_content: Option<&str>,
) -> Vec<Dependency> {
    let Some(workspace_content) = workspace_content else {
        return dependencies;
    };

    let catalog_dependencies = parse_default_catalog(workspace_content);
    let named_catalogs = parse_named_catalog_collections(workspace_content);

    dependencies
        .into_iter()
        .map(|mut dependency| {
            if dependency.version == "catalog:"
                && let Some(catalog_dependency) = catalog_dependencies
                    .iter()
                    .find(|catalog_dependency| catalog_dependency.name == dependency.name)
            {
                apply_catalog_entry(&mut dependency, &catalog_dependency.version);
            } else if let Some(catalog_name) = dependency.version.strip_prefix("catalog:")
                && let Some(named_catalog) = named_catalogs
                    .iter()
                    .find(|named_catalog| named_catalog.name == catalog_name)
                && let Some(catalog_dependency) = named_catalog
                    .dependencies
                    .iter()
                    .find(|catalog_dependency| catalog_dependency.name == dependency.name)
            {
                apply_catalog_entry(&mut dependency, &catalog_dependency.version);
            }
            dependency
        })
        .collect()
}

/// Record what a catalog entry declares on the `catalog:` reference to it.
///
/// An entry holding an npm alias resolves to the alias's range: the name it
/// targets stays readable through [`Dependency::declared_spec`].
fn apply_catalog_entry(dependency: &mut Dependency, entry_spec: &str) {
    let range = npm_alias_target(entry_spec).map_or(entry_spec, |(_, range)| range);
    dependency.resolved_version = Some(range.to_string());
    dependency.catalog_spec = Some(entry_spec.to_string());
}

/// Name pnpm gives the catalog declared under the top-level `catalog` key.
const DEFAULT_CATALOG_NAME: &str = "default";

/// Version pnpm locked for one catalog entry.
#[derive(Debug)]
struct LockedCatalogEntry {
    specifier: String,
    version: String,
}

/// The `catalogs` section of a `pnpm-lock.yaml`: catalog name, then package
/// name, to the locked entry.
///
/// pnpm records there the version it resolved for every catalog entry that a
/// workspace project references. Entries no project references are absent.
#[derive(Debug, Default)]
struct LockedCatalogs(HashMap<String, HashMap<String, LockedCatalogEntry>>);

impl LockedCatalogs {
    /// Parse the `catalogs` section of a `pnpm-lock.yaml`.
    ///
    /// Uses a minimal line-based walker. A lockfile without that section
    /// yields no entries.
    fn parse(lock_content: &str) -> Self {
        let mut catalogs: HashMap<String, HashMap<String, LockedCatalogEntry>> = HashMap::new();
        let mut in_catalogs = false;
        let mut catalog = String::new();
        let mut package = String::new();
        let mut specifier: Option<String> = None;

        for line in lock_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent == 0 {
                in_catalogs = trimmed == "catalogs:";
                continue;
            }
            if !in_catalogs {
                continue;
            }
            let Some(delimiter) = find_top_level_colon(trimmed) else {
                continue;
            };
            let key = trim_quotes(trimmed[..delimiter].trim());
            let value = trim_quotes(trimmed[delimiter + 1..].trim());
            match indent {
                2 => catalog = key.to_string(),
                4 => {
                    package = key.to_string();
                    specifier = None;
                }
                _ if key == "specifier" => specifier = Some(value.to_string()),
                _ if key == "version" => {
                    if let Some(specifier) = specifier.take() {
                        catalogs.entry_ref(catalog.as_str()).or_default().insert(
                            package.clone(),
                            LockedCatalogEntry {
                                specifier,
                                version: value.to_string(),
                            },
                        );
                    }
                }
                _ => {}
            }
        }

        Self(catalogs)
    }

    /// Version locked for `dependency` as an entry of `catalog`.
    ///
    /// Returns `None` when no project references the entry, or when the
    /// lockfile was written for another range than the one now declared. An
    /// alias entry can record its version as `bar@1.2.0`, so the package name
    /// is dropped here.
    fn version_for(&self, catalog: &str, dependency: &Dependency) -> Option<String> {
        let entry = self.0.get(catalog)?.get(&dependency.name)?;
        if entry.specifier != dependency.version {
            return None;
        }
        Some(
            pnpm_locked_version(&entry.version)
                .map_or_else(|| entry.version.clone(), str::to_string),
        )
    }
}

/// Every catalog entry of a workspace file with the name of its catalog,
/// default catalog first.
fn parse_catalog_entries(content: &str) -> Vec<(String, Dependency)> {
    let default_entries = parse_default_catalog(content)
        .into_iter()
        .map(|dependency| (DEFAULT_CATALOG_NAME.to_string(), dependency));
    let named_entries = parse_named_catalog_collections(content)
        .into_iter()
        .flat_map(|catalog| {
            catalog
                .dependencies
                .into_iter()
                .map(move |dependency| (catalog.name.clone(), dependency))
        });
    default_entries.chain(named_entries).collect()
}

/// Identifies a catalog entry by the position of its package name
/// (line, byte offset in the line).
fn entry_key(dependency: &Dependency) -> (u32, u32) {
    (dependency.name_span.line, dependency.name_span.line_start)
}

/// Resolves the catalog entries of a `pnpm-workspace.yaml` from the
/// `pnpm-lock.yaml` next to it.
///
/// Each entry gets the version recorded for its own catalog in the `catalogs`
/// section of the lockfile. Lockfiles of other package managers are never
/// used: catalogs are a pnpm feature and pnpm writes its lockfile in the
/// workspace root.
pub struct PnpmWorkspaceResolver {
    lock_path: PathBuf,
    catalog_names: HashMap<(u32, u32), String>,
    locked: LockedCatalogs,
}

impl PnpmWorkspaceResolver {
    /// Creates the resolver for the workspace file at `workspace_path`.
    ///
    /// Returns `None` when the workspace file declares no catalog entry, or
    /// when no readable `pnpm-lock.yaml` sits next to it.
    pub async fn for_workspace(workspace_path: &Path, workspace_content: &str) -> Option<Self> {
        let catalog_names: HashMap<(u32, u32), String> = parse_catalog_entries(workspace_content)
            .into_iter()
            .map(|(catalog, dependency)| (entry_key(&dependency), catalog))
            .collect();
        if catalog_names.is_empty() {
            return None;
        }
        let lock_path = workspace_path.parent()?.join(PNPM_LOCKFILE_FILENAME);
        let lock_content = read_lockfile_capped(&lock_path).await.ok()?;
        Some(Self {
            lock_path,
            catalog_names,
            locked: LockedCatalogs::parse(&lock_content),
        })
    }
}

#[async_trait]
impl LockfileResolver for PnpmWorkspaceResolver {
    async fn find_lockfile(&self, _manifest_path: &Path) -> Option<PathBuf> {
        Some(self.lock_path.clone())
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        parse_pnpm_lock_graph(lock_content)
    }

    fn resolve_version(&self, dep: &Dependency, _graph: &LockfileGraph) -> Option<String> {
        let catalog = self.catalog_names.get(&entry_key(dep))?;
        self.locked.version_for(catalog, dep)
    }
}

/// Find the nearest `pnpm-workspace.yaml` for a package manifest.
pub async fn find_pnpm_workspace(package_json_path: &Path) -> Option<PathBuf> {
    let mut directory = package_json_path.parent()?.to_path_buf();

    loop {
        let candidate = directory.join(PNPM_WORKSPACE_FILENAME);
        if tokio::fs::metadata(&candidate).await.is_ok() {
            return Some(candidate);
        }

        if !directory.pop() {
            return None;
        }
    }
}

/// Read the nearest `pnpm-workspace.yaml` for a package manifest.
pub async fn read_pnpm_workspace_for_package(package_json_path: &Path) -> Option<String> {
    let workspace_path = find_pnpm_workspace(package_json_path).await?;
    super::lockfile_graph::read_lockfile_capped(&workspace_path)
        .await
        .ok()
}

fn parse_default_catalog(content: &str) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    let mut in_catalog = false;
    let mut catalog_indent = 0usize;

    for (line_number, line) in content.lines().enumerate() {
        let without_comment = strip_inline_comment(line);
        let trimmed = without_comment.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let trimmed_start = without_comment.len() - without_comment.trim_start().len();
        let indent = line.len() - line.trim_start().len();
        if in_catalog && indent <= catalog_indent {
            in_catalog = false;
        }

        if !in_catalog {
            if trimmed == "catalog:" {
                in_catalog = true;
                catalog_indent = indent;
            } else if let Some(flow_dependencies) =
                parse_inline_default_catalog(line_number as u32, trimmed, trimmed_start)
            {
                dependencies.extend(flow_dependencies);
            }
            continue;
        }

        if let Some(dependency) = parse_catalog_entry(line_number as u32, line) {
            dependencies.push(dependency);
        }
    }

    dependencies
}

fn parse_named_catalog_collections(content: &str) -> Vec<NamedCatalog> {
    let mut catalogs = Vec::new();
    let mut current_catalog: Option<NamedCatalog> = None;
    let mut in_catalogs = false;
    let mut catalogs_indent = 0usize;
    let mut named_catalog_indent = 0usize;

    for (line_number, line) in content.lines().enumerate() {
        let without_comment = strip_inline_comment(line);
        let trimmed = without_comment.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let trimmed_start = without_comment.len() - without_comment.trim_start().len();
        let indent = line.len() - line.trim_start().len();
        if in_catalogs && indent <= catalogs_indent {
            in_catalogs = false;
            if let Some(catalog) = current_catalog.take() {
                catalogs.push(catalog);
            }
        }

        if !in_catalogs {
            if trimmed == "catalogs:" {
                in_catalogs = true;
                catalogs_indent = indent;
            } else if let Some(flow_catalogs) =
                parse_inline_named_catalogs(line_number as u32, trimmed, trimmed_start)
            {
                catalogs.extend(flow_catalogs);
            }
            continue;
        }

        if indent <= named_catalog_indent
            && let Some(catalog) = current_catalog.take()
        {
            catalogs.push(catalog);
        }

        if current_catalog.is_none() {
            if let Some(catalog) =
                parse_inline_named_catalog(line_number as u32, trimmed, trimmed_start)
            {
                catalogs.push(catalog);
                continue;
            }

            if let Some(name) = parse_named_catalog_header(trimmed) {
                current_catalog = Some(NamedCatalog {
                    name: name.to_string(),
                    dependencies: Vec::new(),
                });
                named_catalog_indent = indent;
            }
            continue;
        }

        if let Some(dependency) = parse_catalog_entry(line_number as u32, line) {
            current_catalog
                .as_mut()
                .expect("current named catalog")
                .dependencies
                .push(dependency);
        }
    }

    if let Some(catalog) = current_catalog {
        catalogs.push(catalog);
    }

    catalogs
}

fn parse_inline_default_catalog(
    line_number: u32,
    trimmed: &str,
    trimmed_start: usize,
) -> Option<Vec<Dependency>> {
    let value = trimmed.strip_prefix("catalog:")?;
    let value_start = trimmed_start + "catalog:".len();
    parse_flow_catalog_dependencies(line_number, value, value_start)
}

fn parse_inline_named_catalogs(
    line_number: u32,
    trimmed: &str,
    trimmed_start: usize,
) -> Option<Vec<NamedCatalog>> {
    let value = trimmed.strip_prefix("catalogs:")?;
    let value_start = trimmed_start + "catalogs:".len();
    parse_flow_named_catalogs(line_number, value, value_start)
}

fn parse_inline_named_catalog(
    line_number: u32,
    trimmed: &str,
    trimmed_start: usize,
) -> Option<NamedCatalog> {
    let delimiter = find_top_level_colon(trimmed)?;
    let name_part = &trimmed[..delimiter];
    let value_part = &trimmed[delimiter + 1..];
    let name = trim_quotes(name_part.trim());
    if name.is_empty() {
        return None;
    }

    let value_start = trimmed_start + delimiter + 1;
    let dependencies = parse_flow_catalog_dependencies(line_number, value_part, value_start)?;

    Some(NamedCatalog {
        name: name.to_string(),
        dependencies,
    })
}

fn parse_flow_named_catalogs(
    line_number: u32,
    value: &str,
    value_start: usize,
) -> Option<Vec<NamedCatalog>> {
    let (body, body_start) = flow_map_body(value, value_start)?;
    let catalogs = split_flow_segments(body)
        .into_iter()
        .filter_map(|segment| {
            let delimiter = find_top_level_colon(segment.text)?;
            let name_part = &segment.text[..delimiter];
            let value_part = &segment.text[delimiter + 1..];
            let name = trim_quotes(name_part.trim());
            if name.is_empty() {
                return None;
            }

            let dependencies = parse_flow_catalog_dependencies(
                line_number,
                value_part,
                body_start + segment.start + delimiter + 1,
            )?;

            Some(NamedCatalog {
                name: name.to_string(),
                dependencies,
            })
        })
        .collect();

    Some(catalogs)
}

fn parse_flow_catalog_dependencies(
    line_number: u32,
    value: &str,
    value_start: usize,
) -> Option<Vec<Dependency>> {
    let (body, body_start) = flow_map_body(value, value_start)?;
    Some(
        split_flow_segments(body)
            .into_iter()
            .filter_map(|segment| {
                parse_flow_catalog_entry(line_number, segment.text, body_start + segment.start)
            })
            .collect(),
    )
}

fn flow_map_body(value: &str, value_start: usize) -> Option<(&str, usize)> {
    let leading = value.len() - value.trim_start().len();
    let trimmed = value.trim();
    let body = trimmed.strip_prefix('{')?.strip_suffix('}')?;
    Some((body, value_start + leading + 1))
}

#[derive(Debug, Clone, Copy)]
struct FlowSegment<'a> {
    text: &'a str,
    start: usize,
}

fn split_flow_segments(value: &str) -> Vec<FlowSegment<'_>> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;

    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match character {
            '\\' => escaped = true,
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            '{' if !in_single_quote && !in_double_quote => depth += 1,
            '}' if !in_single_quote && !in_double_quote && depth > 0 => depth -= 1,
            ',' if !in_single_quote && !in_double_quote && depth == 0 => {
                push_flow_segment(&mut segments, value, start, index);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }

    push_flow_segment(&mut segments, value, start, value.len());
    segments
}

fn push_flow_segment<'a>(
    segments: &mut Vec<FlowSegment<'a>>,
    value: &'a str,
    start: usize,
    end: usize,
) {
    if !value[start..end].trim().is_empty() {
        segments.push(FlowSegment {
            text: &value[start..end],
            start,
        });
    }
}

fn find_top_level_colon(value: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;

    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match character {
            '\\' => escaped = true,
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            '{' if !in_single_quote && !in_double_quote => depth += 1,
            '}' if !in_single_quote && !in_double_quote && depth > 0 => depth -= 1,
            ':' if !in_single_quote && !in_double_quote && depth == 0 => return Some(index),
            _ => {}
        }
    }

    None
}

fn parse_named_catalog_header(line: &str) -> Option<&str> {
    let (name, value) = line.split_once(':')?;
    let name = trim_quotes(name.trim());

    (!name.is_empty() && value.trim().is_empty()).then_some(name)
}

fn parse_catalog_entry(line_number: u32, line: &str) -> Option<Dependency> {
    let indent = line.len() - line.trim_start().len();
    let without_comment = strip_inline_comment(line);
    let trimmed = without_comment.trim();
    let (name, version) = trimmed.split_once(':')?;
    let raw_name = name.trim();
    let name = trim_quotes(raw_name);
    let raw_version = version.trim();
    let version = trim_quotes(raw_version);
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let raw_name_start = indent + trimmed.find(raw_name)?;
    let name_quote_offset = raw_name.len() - raw_name.trim_start_matches(['"', '\'']).len();
    let name_start = raw_name_start + name_quote_offset;
    let delimiter_start = line.find(':')?;
    let raw_version_start = line[delimiter_start + 1..].find(raw_version)? + delimiter_start + 1;
    let quote_offset = raw_version.len() - raw_version.trim_start_matches(['"', '\'']).len();
    let version_start = raw_version_start + quote_offset;

    Some(Dependency {
        name: name.to_string(),
        version: version.to_string(),
        name_span: Span {
            line: line_number,
            line_start: name_start as u32,
            line_end: (name_start + name.len()) as u32,
        },
        version_span: Span {
            line: line_number,
            line_start: version_start as u32,
            line_end: (version_start + version.len()) as u32,
        },
        dev: false,
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: false,
        catalog_spec: None,
    })
}

fn parse_flow_catalog_entry(
    line_number: u32,
    segment: &str,
    segment_start: usize,
) -> Option<Dependency> {
    let delimiter = find_top_level_colon(segment)?;
    let name_part = &segment[..delimiter];
    let raw_version_part = &segment[delimiter + 1..];
    let raw_name = name_part.trim();
    let name = trim_quotes(raw_name);
    let raw_version = raw_version_part.trim();
    let version = trim_quotes(raw_version);
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let raw_name_start = segment_start + (name_part.len() - name_part.trim_start().len());
    let name_quote_offset = raw_name.len() - raw_name.trim_start_matches(['"', '\'']).len();
    let name_start = raw_name_start + name_quote_offset;
    let raw_version_start = segment_start
        + delimiter
        + 1
        + (raw_version_part.len() - raw_version_part.trim_start().len());
    let quote_offset = raw_version.len() - raw_version.trim_start_matches(['"', '\'']).len();
    let version_start = raw_version_start + quote_offset;

    Some(Dependency {
        name: name.to_string(),
        version: version.to_string(),
        name_span: Span {
            line: line_number,
            line_start: name_start as u32,
            line_end: (name_start + name.len()) as u32,
        },
        version_span: Span {
            line: line_number,
            line_start: version_start as u32,
            line_end: (version_start + version.len()) as u32,
        },
        dev: false,
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: false,
        catalog_spec: None,
    })
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;

    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match character {
            '\\' => escaped = true,
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            '#' if !in_single_quote && !in_double_quote && starts_yaml_comment(line, index) => {
                return &line[..index];
            }
            _ => {}
        }
    }

    line
}

fn starts_yaml_comment(line: &str, index: usize) -> bool {
    index == 0
        || line[..index]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace)
}

fn trim_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|unquoted| unquoted.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|unquoted| unquoted.strip_suffix('\''))
        })
        .unwrap_or(value)
}
