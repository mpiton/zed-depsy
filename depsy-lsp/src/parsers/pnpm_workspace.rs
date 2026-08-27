//! Parser for pnpm `pnpm-workspace.yaml` catalog dependencies.

use std::path::{Path, PathBuf};

use super::{Dependency, Parser, Span};

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
        let mut dependencies = parse_default_catalog(content);
        dependencies.extend(parse_named_catalogs(content));
        dependencies
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
                dependency.resolved_version = Some(catalog_dependency.version.clone());
            } else if let Some(catalog_name) = dependency.version.strip_prefix("catalog:")
                && let Some(named_catalog) = named_catalogs
                    .iter()
                    .find(|named_catalog| named_catalog.name == catalog_name)
                && let Some(catalog_dependency) = named_catalog
                    .dependencies
                    .iter()
                    .find(|catalog_dependency| catalog_dependency.name == dependency.name)
            {
                dependency.resolved_version = Some(catalog_dependency.version.clone());
            }
            dependency
        })
        .collect()
}

/// Find the nearest `pnpm-workspace.yaml` for a package manifest.
pub async fn find_pnpm_workspace(package_json_path: &Path) -> Option<PathBuf> {
    let mut directory = package_json_path.parent()?.to_path_buf();

    loop {
        let candidate = directory.join("pnpm-workspace.yaml");
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

fn parse_named_catalogs(content: &str) -> Vec<Dependency> {
    parse_named_catalog_collections(content)
        .into_iter()
        .flat_map(|catalog| catalog.dependencies)
        .collect()
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
