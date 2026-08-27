//! Parser for Python dependency files.
//!
//! Supports four file formats detected heuristically from content:
//!
//! | Format | Detection | Key spec |
//! |--------|-----------|----------|
//! | `pyproject.toml` | `[project]`, `[tool.poetry]`, `[dependency-groups]`, `[tool.hatch]` headers | PEP 621, Poetry, PEP 735, Hatch |
//! | `hatch.toml` | `[envs.<name>]` top-level header | Hatch standalone config |
//! | `requirements.txt` / `constraints.txt` | default | PEP 508 one-package-per-line |
//!
//! Detection is content-based (line-anchored section headers) so that packages
//! whose *extras* resemble section headers (e.g. `mypkg[project]==1.2`) are never
//! misrouted to the TOML parsers.
//!
//! Parsing is performed with `taplo` for TOML formats, giving byte-accurate
//! [`Span`] values that let LSP quick-fix `TextEdit`s replace only the version
//! literal inside the surrounding quotes.

use taplo::dom::Node;
use taplo::dom::node::DomNode;
use taplo::rowan::{TextRange, TextSize};
use taplo::syntax::SyntaxElement;

use super::{Dependency, Parser, Span};

/// Parser for Python dependency files.
///
/// Dispatches to one of three sub-parsers based on content detection:
/// `parse_pyproject_toml`, `parse_hatch_toml`, or `parse_requirements_txt`.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::python::PythonParser;
/// let parser = PythonParser::new();
/// let deps = parser.parse("flask==2.0.0\nrequests>=2.25.0\n");
/// assert_eq!(deps.len(), 2);
/// assert_eq!(deps[0].name, "flask");
/// assert_eq!(deps[0].version, "==2.0.0");
/// ```
#[derive(Debug, Default)]
pub struct PythonParser;

impl PythonParser {
    /// Creates a new [`PythonParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for PythonParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        // Detect file type based on content.
        // Only parse as TOML if it contains valid pyproject.toml section headers.
        // Use line-anchored detection to avoid false positives like "mypkg[project]==1.2".
        // is_pyproject_toml is checked first so that a pyproject.toml that also uses
        // [tool.hatch.envs.*] is routed through parse_pyproject_toml (which handles both).
        if is_pyproject_toml(content) {
            parse_pyproject_toml(content)
        } else if is_hatch_toml(content) {
            parse_hatch_toml(content)
        } else {
            parse_requirements_txt(content)
        }
    }
}

/// Check if content is a pyproject.toml file by looking for line-anchored section headers
fn is_pyproject_toml(content: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();

        // Match [project...] section headers (e.g., [project], [project.dependencies])
        // Also allow inline comments: [project] # comment
        if trimmed.starts_with("[project") && is_valid_section_header(trimmed, "[project") {
            return true;
        }

        // Match [tool.poetry...] section headers (e.g., [tool.poetry], [tool.poetry.dependencies])
        if trimmed.starts_with("[tool.poetry") && is_valid_section_header(trimmed, "[tool.poetry") {
            return true;
        }

        // Match [dependency-groups] section header (PEP 735)
        if trimmed.starts_with("[dependency-groups")
            && is_valid_section_header(trimmed, "[dependency-groups")
        {
            return true;
        }
        // Match [tool.hatch...] section headers (e.g., [tool.hatch.envs.test])
        if trimmed.starts_with("[tool.hatch") && is_valid_section_header(trimmed, "[tool.hatch") {
            return true;
        }
    }
    false
}

/// Detect a standalone hatch.toml file.
///
/// The project-level Hatch config is always stored in a file named `hatch.toml`;
/// the filename cannot be changed. `file_types.rs` therefore gates entry to this
/// code path via a filename check, making content-based false positives impossible
/// in practice. Detection requires a top-level `[envs.<NAME>]` section header
/// with a mandatory dot-separated env name (bare `[envs]` is not a valid hatch section).
fn is_hatch_toml(content: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();
        // Require "[envs." (dot included) so that a bare "[envs]" is never matched.
        if trimmed.starts_with("[envs.")
            && let Some(close) = trimmed.find(']')
        {
            let after = trimmed[close + 1..].trim_start();
            if after.is_empty() || after.starts_with('#') {
                return true;
            }
        }
    }
    false
}

/// Check if a line is a valid TOML section header starting with the given prefix
/// Requires: starts with prefix, followed by either ']' or '.' then more chars ending with ']'
/// Allows optional whitespace and comments after the closing ']'
fn is_valid_section_header(line: &str, prefix: &str) -> bool {
    let after_prefix = &line[prefix.len()..];

    // Find the closing bracket
    let Some(bracket_pos) = after_prefix.find(']') else {
        return false;
    };

    // Check what's between prefix and ']': must be empty or start with '.'
    let inner = &after_prefix[..bracket_pos];
    if !inner.is_empty() && !inner.starts_with('.') {
        return false;
    }

    // Check what's after ']': must be only whitespace or a comment
    let after_bracket = after_prefix[bracket_pos + 1..].trim_start();
    after_bracket.is_empty() || after_bracket.starts_with('#')
}

/// Parse requirements.txt / constraints.txt format
/// Format: package==1.0.0, package>=1.0.0, package~=1.0.0, etc.
fn parse_requirements_txt(content: &str) -> Vec<Dependency> {
    let mut dependencies = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx as u32;
        let trimmed = line.trim();

        // Skip empty lines, comments, and special directives
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('-')  // -r, -e, -c, etc.
            || trimmed.starts_with("--")
        // --index-url, etc.
        {
            continue;
        }

        // Skip URL dependencies (package @ https://...)
        if trimmed.contains(" @ ") {
            continue;
        }

        if let Some(dep) = parse_requirement_line(line, line_num, false) {
            dependencies.push(dep);
        }
    }

    dependencies
}

/// Parse a single requirement line
fn parse_requirement_line(line: &str, line_num: u32, dev: bool) -> Option<Dependency> {
    let without_comment = line
        .split_once('#')
        .map_or(line, |(before_comment, _)| before_comment)
        .trim_end();
    let parsed = parse_pep508_dependency(without_comment)?;
    let name_start = u32::try_from(parsed.name_byte_range.0).ok()?;
    let name_end = u32::try_from(parsed.name_byte_range.1).ok()?;
    let version_start = u32::try_from(parsed.version_byte_range.0).ok()?;
    let version_end = u32::try_from(parsed.version_byte_range.1).ok()?;

    Some(Dependency {
        name: parsed.name,
        version: parsed.version,
        name_span: Span {
            line: line_num,
            line_start: name_start,
            line_end: name_end,
        },
        version_span: Span {
            line: line_num,
            line_start: version_start,
            line_end: version_end,
        },
        dev,
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: parsed.has_additional_version_constraints,
    })
}

/// Pre-compute the byte offsets of every line in `content`.
///
/// Returned ranges are end-exclusive, ordered, and the union covers the entire
/// content. Used as a lookup table to convert byte-offset ranges from taplo
/// nodes into 0-indexed `(line, column)` `Span`s.
fn compute_line_ranges(content: &str) -> Box<[TextRange]> {
    content
        .split_inclusive('\n')
        .map({
            let mut offset: usize = 0;
            move |line| {
                let range = TextRange::at((offset as u32).into(), (line.len() as u32).into());
                offset += line.len();
                range
            }
        })
        .collect::<Box<[_]>>()
}

/// Convert an arbitrary `TextRange` to a `Span`. Used for raw key ranges.
fn range_to_span(range: TextRange, line_ranges: &[TextRange]) -> Option<Span> {
    let line_idx = line_ranges
        .binary_search_by(|line_range| line_range.ordering(range))
        .ok()?;
    let line_range = line_ranges[line_idx];
    // Guard: range must be fully contained within the found line range.
    // binary_search_by may return Ok for a range that straddles two adjacent
    // line ranges (multi-line nodes); without this check the subtraction
    // below would underflow on debug (panic) or wrap on release (bogus span).
    if range.start() < line_range.start() || range.end() > line_range.end() {
        return None;
    }
    Some(Span {
        line: line_idx as u32,
        line_start: (range.start() - line_range.start()).into(),
        line_end: (range.end() - line_range.start()).into(),
    })
}

/// Return the byte range covering the *content* of a string node, i.e. the
/// range minus the surrounding quote characters.
///
/// Assumes single-character delimiters (`"..."` or `'...'`), which is the only
/// form PEP 508 / Poetry version literals ever take in practice. Returns `None`
/// when the node lacks syntax info or its range is shorter than 2 bytes.
///
/// This is the workhorse for narrow `version_span` / `name_span`: callers slice
/// inside the inner range so quick-fix edits replace text *between* the quotes
/// instead of clobbering them.
fn string_inner_range(node: &Node) -> Option<TextRange> {
    let range = node.syntax().map(SyntaxElement::text_range)?;
    if range.len() < TextSize::from(2) {
        return None;
    }
    let one = TextSize::from(1);
    Some(TextRange::new(range.start() + one, range.end() - one))
}

/// Map PEP 508 byte ranges (relative to `dep_str`) onto the source `Span`s
/// for the name and version literals inside the array item's string node.
///
/// `(name_span, version_span)` are anchored to the *content* of the string
/// (between the quotes) so that LSP quick-fix `TextEdit`s replace just the
/// inner text and leave the surrounding quotes intact.
fn pep508_spans(
    item: &Node,
    parsed: &Pep508Parsed,
    line_ranges: &[TextRange],
) -> Option<(Span, Span)> {
    let inner = string_inner_range(item)?;
    let to_range = |(start, end): (usize, usize)| {
        TextRange::new(
            inner.start() + TextSize::from(start as u32),
            inner.start() + TextSize::from(end as u32),
        )
    };
    let name_span = range_to_span(to_range(parsed.name_byte_range), line_ranges)?;
    let version_span = range_to_span(to_range(parsed.version_byte_range), line_ranges)?;
    Some((name_span, version_span))
}

/// Parse pyproject.toml format (PEP 621 + Poetry + Hatch)
fn parse_pyproject_toml(content: &str) -> Vec<Dependency> {
    let mut dependencies = Vec::new();

    // Use taplo for parsing as it's more lenient and doesn't panic on malformed input
    let parsed = taplo::parser::parse(content);

    // If there are errors, skip this file
    if !parsed.errors.is_empty() {
        return dependencies;
    }

    let dom = parsed.into_dom();
    let line_ranges = compute_line_ranges(content);

    // PEP 621: [project.dependencies] array of strings
    let project = dom.get("project");
    if project.as_table().is_some() {
        // [project.dependencies]
        parse_pep621_deps(&dom, &line_ranges, &mut dependencies);
        parse_pep621_optional(&dom, &line_ranges, &mut dependencies);
    }

    // Poetry: [tool.poetry.dependencies] table
    let tool = dom.get("tool");
    let poetry = tool.get("poetry");
    if poetry.as_table().is_some() {
        parse_poetry_main(&dom, &line_ranges, &mut dependencies);

        parse_poetry_dev_legacy(&dom, &line_ranges, &mut dependencies);

        parse_poetry_groups(&dom, &line_ranges, &mut dependencies);
    }

    parse_pep735_groups(&dom, &line_ranges, &mut dependencies);

    // Hatch: [tool.hatch.envs.<ENV_NAME>]
    // Both `dependencies` and `extra-dependencies` are PEP 508 string arrays.
    // Matrix overrides (e.g. [tool.hatch.envs.test.overrides.matrix.*.dependencies])
    // use a different inline-table value format and are out of scope.
    let hatch_envs = dom.get("tool").get("hatch").get("envs");
    parse_hatch_envs(&hatch_envs, &line_ranges, &mut dependencies);

    dependencies
}

/// Parse `[project.dependencies]` (PEP 621): an array of PEP 508 strings.
fn parse_pep621_deps(dom: &Node, line_ranges: &[TextRange], deps: &mut Vec<Dependency>) {
    let project = dom.get("project");
    let deps_node = project.get("dependencies");
    let Some(deps_array) = deps_node.as_array() else {
        return;
    };
    let items = deps_array.items().read();
    for item in items.iter() {
        let Some(dep_str_node) = item.as_str() else {
            continue;
        };
        let dep_str = dep_str_node.value();
        let Some(parsed) = parse_pep508_dependency(dep_str) else {
            continue;
        };
        let Some((name_span, version_span)) = pep508_spans(item, &parsed, line_ranges) else {
            continue;
        };
        let has_additional_version_constraints = parsed.has_additional_version_constraints;
        deps.push(Dependency {
            name: parsed.name,
            version: parsed.version,
            name_span,
            version_span,
            dev: false,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints,
        });
    }
}

/// Parse `[project.optional-dependencies]` (PEP 621): table of group_name -> array of PEP 508 strings.
/// Each emitted Dependency has dev=true and optional=true.
fn parse_pep621_optional(dom: &Node, line_ranges: &[TextRange], deps: &mut Vec<Dependency>) {
    let project = dom.get("project");
    let optional_node = project.get("optional-dependencies");
    let Some(optional_deps) = optional_node.as_table() else {
        return;
    };
    let entries = optional_deps.entries().read();
    for (_group, deps_node) in entries.iter() {
        let Some(deps_array) = deps_node.as_array() else {
            continue;
        };
        let items = deps_array.items().read();
        for item in items.iter() {
            let Some(dep_str_node) = item.as_str() else {
                continue;
            };
            let dep_str = dep_str_node.value();
            let Some(parsed) = parse_pep508_dependency(dep_str) else {
                continue;
            };
            let Some((name_span, version_span)) = pep508_spans(item, &parsed, line_ranges) else {
                continue;
            };
            let has_additional_version_constraints = parsed.has_additional_version_constraints;
            deps.push(Dependency {
                name: parsed.name,
                version: parsed.version,
                name_span,
                version_span,
                dev: true,
                optional: true,
                registry: None,
                resolved_version: None,
                has_additional_version_constraints,
            });
        }
    }
}

/// Parse `[tool.poetry.dependencies]` table.
/// Skips the `python` key (Python interpreter constraint, not a dependency).
fn parse_poetry_main(dom: &Node, line_ranges: &[TextRange], deps: &mut Vec<Dependency>) {
    let deps_node = dom.get("tool").get("poetry").get("dependencies");
    let Some(deps_table) = deps_node.as_table() else {
        return;
    };
    let entries = deps_table.entries().read();
    for (key, value) in entries.iter() {
        let name = key.value().to_string();
        if name == "python" {
            continue;
        }
        let Some((version, optional, version_range)) = extract_poetry_version_taplo(value) else {
            continue;
        };
        let Some(name_span) = key
            .syntax()
            .map(SyntaxElement::text_range)
            .and_then(|r| range_to_span(r, line_ranges))
        else {
            continue;
        };
        let Some(version_span) = range_to_span(version_range, line_ranges) else {
            continue;
        };
        deps.push(Dependency {
            name,
            version,
            name_span,
            version_span,
            dev: false,
            optional,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        });
    }
}

/// Parse legacy `[tool.poetry.dev-dependencies]` (Poetry < 1.2). Sets dev=true.
fn parse_poetry_dev_legacy(dom: &Node, line_ranges: &[TextRange], deps: &mut Vec<Dependency>) {
    let deps_node = dom.get("tool").get("poetry").get("dev-dependencies");
    let Some(deps_table) = deps_node.as_table() else {
        return;
    };
    let entries = deps_table.entries().read();
    for (key, value) in entries.iter() {
        let name = key.value().to_string();
        let Some((version, optional, version_range)) = extract_poetry_version_taplo(value) else {
            continue;
        };
        let Some(name_span) = key
            .syntax()
            .map(SyntaxElement::text_range)
            .and_then(|r| range_to_span(r, line_ranges))
        else {
            continue;
        };
        let Some(version_span) = range_to_span(version_range, line_ranges) else {
            continue;
        };
        deps.push(Dependency {
            name,
            version,
            name_span,
            version_span,
            dev: true,
            optional,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        });
    }
}

/// Parse `[tool.poetry.group.<NAME>.dependencies]` (Poetry >= 1.2).
/// Group named `dev` or `test` produces dev=true; otherwise dev=false.
fn parse_poetry_groups(dom: &Node, line_ranges: &[TextRange], deps: &mut Vec<Dependency>) {
    let groups_node = dom.get("tool").get("poetry").get("group");
    let Some(groups) = groups_node.as_table() else {
        return;
    };
    let group_entries = groups.entries().read();
    for (group_key, group_value) in group_entries.iter() {
        let group_name = group_key.value();
        let is_dev = group_name == "dev" || group_name == "test";
        // Skip group entries that aren't tables (defensive — taplo lenient parsing).
        let Some(_group_table) = group_value.as_table() else {
            continue;
        };
        let deps_node = group_value.get("dependencies");
        let Some(deps_table) = deps_node.as_table() else {
            continue;
        };
        let entries = deps_table.entries().read();
        for (key, value) in entries.iter() {
            let name = key.value().to_string();
            let Some((version, optional, version_range)) = extract_poetry_version_taplo(value)
            else {
                continue;
            };
            let Some(name_span) = key
                .syntax()
                .map(SyntaxElement::text_range)
                .and_then(|r| range_to_span(r, line_ranges))
            else {
                continue;
            };
            let Some(version_span) = range_to_span(version_range, line_ranges) else {
                continue;
            };
            deps.push(Dependency {
                name,
                version,
                name_span,
                version_span,
                dev: is_dev,
                optional,
                registry: None,
                resolved_version: None,
                has_additional_version_constraints: false,
            });
        }
    }
}

/// Parse `[dependency-groups]` (PEP 735): table of group_name -> array of items.
/// Each item is either a PEP 508 string or `{include-group = "..."}` table; tables
/// are skipped (referenced groups are emitted when their own group is iterated).
fn parse_pep735_groups(dom: &Node, line_ranges: &[TextRange], deps: &mut Vec<Dependency>) {
    let dep_groups_node = dom.get("dependency-groups");
    let Some(dep_groups_table) = dep_groups_node.as_table() else {
        return;
    };
    let group_entries = dep_groups_table.entries().read();
    for (_group_name, group_value) in group_entries.iter() {
        let Some(items_array) = group_value.as_array() else {
            continue;
        };
        let items = items_array.items().read();
        for item in items.iter() {
            let Some(dep_str_node) = item.as_str() else {
                continue;
            };
            let dep_str = dep_str_node.value();
            let Some(parsed) = parse_pep508_dependency(dep_str) else {
                continue;
            };
            let Some((name_span, version_span)) = pep508_spans(item, &parsed, line_ranges) else {
                continue;
            };
            let has_additional_version_constraints = parsed.has_additional_version_constraints;
            deps.push(Dependency {
                name: parsed.name,
                version: parsed.version,
                name_span,
                version_span,
                dev: false,
                optional: false,
                registry: None,
                resolved_version: None,
                has_additional_version_constraints,
            });
        }
    }
}

/// Parse `[tool.hatch.envs.<ENV_NAME>]` blocks for `dependencies` and
/// `extra-dependencies` (PEP 508 string arrays). Always sets dev=true,
/// optional=false (hatch envs are dev/test tooling).
///
/// `envs_node` may be either `dom["tool"]["hatch"]["envs"]` (pyproject) or
/// `dom["envs"]` (standalone hatch.toml). Caller passes the appropriate node.
fn parse_hatch_envs(envs_node: &Node, line_ranges: &[TextRange], deps: &mut Vec<Dependency>) {
    let Some(envs_table) = envs_node.as_table() else {
        return;
    };
    let env_entries = envs_table.entries().read();
    for (_env_name, env_value) in env_entries.iter() {
        for key in ["dependencies", "extra-dependencies"] {
            let arr_node = env_value.get(key);
            let Some(deps_array) = arr_node.as_array() else {
                continue;
            };
            let items = deps_array.items().read();
            for item in items.iter() {
                let Some(dep_str_node) = item.as_str() else {
                    continue;
                };
                let dep_str = dep_str_node.value();
                let Some(parsed) = parse_pep508_dependency(dep_str) else {
                    continue;
                };
                let Some((name_span, version_span)) = pep508_spans(item, &parsed, line_ranges)
                else {
                    continue;
                };
                let has_additional_version_constraints = parsed.has_additional_version_constraints;
                deps.push(Dependency {
                    name: parsed.name,
                    version: parsed.version,
                    name_span,
                    version_span,
                    dev: true,
                    optional: false,
                    registry: None,
                    resolved_version: None,
                    has_additional_version_constraints,
                });
            }
        }
    }
}

/// Parse a standalone `hatch.toml` file.
///
/// The project-level Hatch config is always stored in a file named `hatch.toml`.
/// In this format the envs table lives at the top level under `envs`
/// (no `tool.hatch` prefix as in pyproject.toml).
fn parse_hatch_toml(content: &str) -> Vec<Dependency> {
    let mut dependencies = Vec::new();

    let parsed = taplo::parser::parse(content);
    if !parsed.errors.is_empty() {
        return dependencies;
    }

    let dom = parsed.into_dom();
    let line_ranges = compute_line_ranges(content);
    let envs_node = dom.get("envs");
    parse_hatch_envs(&envs_node, &line_ranges, &mut dependencies);

    dependencies
}

/// Result of parsing a PEP 508 dependency string.
///
/// Carries byte ranges (in `dep_str`) for the package name and the
/// operator+version literal, so callers can map them onto their string node's
/// inner range and produce narrow `name_span` / `version_span` values that
/// LSP quick-fixes can edit safely.
struct Pep508Parsed {
    name: String,
    /// Operator + first version anchor with source whitespace preserved.
    version: String,
    /// Byte range in `dep_str` covering the package name (excludes extras like `[security]`).
    name_byte_range: (usize, usize),
    /// Byte range in `dep_str` covering operator + version (whitespace inside is preserved).
    version_byte_range: (usize, usize),
    /// Whether later comma-separated constraints exist outside `version_byte_range`.
    has_additional_version_constraints: bool,
}

/// Parse PEP 508 dependency string: "package>=1.0.0" or "package[extra]>=1.0.0"
fn parse_pep508_dependency(dep_str: &str) -> Option<Pep508Parsed> {
    // Compute the offset of the trimmed slice within `dep_str` so byte ranges
    // we return are anchored to the original (untrimmed) input.
    let trim_start = dep_str.trim_start();
    let leading_ws = dep_str.len() - trim_start.len();
    let trimmed = trim_start.trim_end();

    // Remove environment markers (`; python_version<3.10`, etc.)
    let pre_marker = if let Some(semi_pos) = trimmed.find(';') {
        &trimmed[..semi_pos]
    } else {
        trimmed
    };
    // `pre_marker` may have trailing space before the `;`; trim it before
    // searching for the version operator.
    let pm_trim_start = pre_marker.trim_start();
    let pm_leading = pre_marker.len() - pm_trim_start.len();
    let without_markers = pm_trim_start.trim_end();
    let wm_offset = leading_ws + pm_leading;

    // Find version operator. Longest operators come first so `===` wins over `==`.
    let operators = ["===", "==", ">=", "<=", "!=", "~=", ">", "<"];
    let mut op_pos = None;
    let mut op_len = 0;
    for op in &operators {
        if let Some(pos) = without_markers.find(op)
            && (op_pos.is_none() || pos < op_pos.unwrap())
        {
            op_pos = Some(pos);
            op_len = op.len();
        }
    }
    let op_pos = op_pos?;

    // Extract name (handle extras like `requests[security]`).
    let name_part = &without_markers[..op_pos];
    let name_substr = if let Some(bracket_pos) = name_part.find('[') {
        &name_part[..bracket_pos]
    } else {
        name_part
    };
    let name_trimmed = name_substr.trim();
    if name_trimmed.is_empty() {
        return None;
    }
    // Offset of the trimmed name within `name_substr`.
    let name_inner_offset = name_substr.len() - name_substr.trim_start().len();
    let name_start = wm_offset + name_inner_offset;
    let name_end = name_start + name_trimmed.len();

    // Extract version (operator + numeric part, taking only the first constraint).
    let version_part = &without_markers[op_pos + op_len..];
    let version_num_substr = if let Some(comma_pos) = version_part.find(',') {
        &version_part[..comma_pos]
    } else {
        version_part
    };
    let version_num = version_num_substr.trim();
    if version_num.is_empty() {
        return None;
    }
    // version_byte_range covers `operator..end_of_version_num` in `dep_str`.
    // Trim only the trailing side: any leading space between operator and number
    // (e.g., `>= 2.0`) stays inside the span — replacing it with `>=2.1` is fine
    // and keeps the range tight against the literal.
    let version_num_end_in_part = version_num_substr.trim_end().len();
    let v_start = wm_offset + op_pos;
    let v_end = wm_offset + op_pos + op_len + version_num_end_in_part;
    let version = dep_str.get(v_start..v_end)?.to_string();

    Some(Pep508Parsed {
        name: name_trimmed.to_string(),
        version,
        name_byte_range: (name_start, name_end),
        version_byte_range: (v_start, v_end),
        has_additional_version_constraints: version_part.contains(','),
    })
}

/// Extract version, optional flag, and the inner byte range of the version
/// literal from a Poetry dependency value.
///
/// The returned `TextRange` covers only the *content* of the version string
/// (no surrounding quotes), so callers can convert it to a `Span` and use it
/// directly as `version_span`. For inline-tables we point at the nested
/// `version = "..."` literal rather than the whole `{ ... }` table — that's
/// what makes "Update to X.Y.Z" quick-fixes safe (they replace just the
/// version, not the surrounding metadata).
fn extract_poetry_version_taplo(value: &taplo::dom::Node) -> Option<(String, bool, TextRange)> {
    // Simple string value: flask = "^2.0.0"
    if let Some(s) = value.as_str() {
        let inner = string_inner_range(value)?;
        return Some((s.value().to_string(), false, inner));
    }

    // Table value: flask = { version = "^2.0.0", optional = true, ... }
    if let Some(t) = value.as_table()
        && let Some(version_node) = t.get("version")
        && let Some(version_str) = version_node.as_str()
    {
        let version = version_str.value().to_string();
        let optional = t
            .get("optional")
            .as_ref()
            .and_then(Node::as_bool)
            .map(|b| b.value())
            .unwrap_or(false);
        let inner = string_inner_range(&version_node)?;
        return Some((version, optional, inner));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_requirements_simple() {
        let parser = PythonParser::new();
        let content = r#"
flask==2.0.0
requests>=2.25.0
django~=4.0
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3);

        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version, "==2.0.0");

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version, ">=2.25.0");

        let django = deps.iter().find(|d| d.name == "django").unwrap();
        assert_eq!(django.version, "~=4.0");
    }

    #[test]
    fn test_requirements_with_extras() {
        let parser = PythonParser::new();
        let content = "uvicorn[standard]>=0.20.0";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "uvicorn");
        assert_eq!(deps[0].version, ">=0.20.0");
    }

    #[test]
    fn test_requirements_with_comments() {
        let parser = PythonParser::new();
        let content = r#"
# This is a comment
flask==2.0.0  # inline comment
# Another comment
requests>=2.25.0
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_requirements_skip_special() {
        let parser = PythonParser::new();
        let content = r#"
-r other.txt
-e git+https://github.com/user/repo.git
--index-url https://pypi.org/simple
flask==2.0.0
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
    }

    #[test]
    fn test_pyproject_pep621() {
        let parser = PythonParser::new();
        let content = r#"
[project]
name = "myproject"
dependencies = [
    "flask>=2.0.0",
    "requests~=2.25.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3);

        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version, ">=2.0.0");
        assert!(!flask.dev);

        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        assert_eq!(pytest.version, ">=7.0.0");
        assert!(pytest.dev);
    }

    #[test]
    fn test_pyproject_poetry() {
        let parser = PythonParser::new();
        let content = r#"
[tool.poetry]
name = "myproject"

[tool.poetry.dependencies]
python = "^3.9"
flask = "^2.0.0"
requests = { version = "^2.25.0", optional = true }

[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
"#;
        let deps = parser.parse(content);
        // Should have flask, requests, pytest (python is skipped)
        assert_eq!(deps.len(), 3);

        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version, "^2.0.0");
        assert!(!flask.dev);

        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        assert_eq!(pytest.version, "^7.0.0");
        assert!(pytest.dev);
    }

    #[test]
    fn test_version_position() {
        let parser = PythonParser::new();
        let content = "flask==2.0.0";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);

        let dep = &deps[0];
        assert_eq!(dep.version, "==2.0.0");
        assert_eq!(dep.name_span.line, 0);
        assert_eq!(dep.name_span.line_start, 0);
        assert_eq!(dep.name_span.line_end, 5);
        // version_start now includes the operator "=="
        assert_eq!(dep.version_span.line, 0);
        assert_eq!(dep.version_span.line_start, 5);
        assert_eq!(dep.version_span.line_end, 12);
    }

    #[test]
    fn test_requirements_with_project_extra_not_toml() {
        // Ensure packages with [project] as extras don't trigger TOML parsing
        let parser = PythonParser::new();
        let content = r#"
mypkg[project]==1.2.0
otherpkg[tool.poetry]>=2.0
flask>=2.0.0
"#;
        let deps = parser.parse(content);
        // Should be parsed as requirements.txt, not pyproject.toml
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "mypkg"));
        assert!(deps.iter().any(|d| d.name == "otherpkg"));
        assert!(deps.iter().any(|d| d.name == "flask"));
    }

    #[test]
    fn test_is_pyproject_toml_detection() {
        // Valid pyproject.toml patterns - [project] and subsections
        assert!(is_pyproject_toml("[project]\nname = \"test\""));
        assert!(is_pyproject_toml("  [project]  \nname = \"test\""));
        assert!(is_pyproject_toml(
            "[project.dependencies]\nflask = \">=2.0\""
        ));
        assert!(is_pyproject_toml(
            "[project.optional-dependencies]\ndev = []"
        ));

        // Valid patterns with inline comments
        assert!(is_pyproject_toml(
            "[project] # main section\nname = \"test\""
        ));
        assert!(is_pyproject_toml(
            "[project.dependencies]  # deps\nflask = \"1.0\""
        ));

        // Valid [tool.poetry] patterns
        assert!(is_pyproject_toml("[tool.poetry]\nname = \"test\""));
        assert!(is_pyproject_toml(
            "[tool.poetry.dependencies]\npython = \"^3.9\""
        ));
        assert!(is_pyproject_toml(
            "[tool.poetry] # comment\nname = \"test\""
        ));

        // Valid [dependency-groups] patterns (PEP 735)
        assert!(is_pyproject_toml(
            "[dependency-groups]\ntest = [\"pytest\"]"
        ));
        assert!(is_pyproject_toml(
            "[dependency-groups] # comment\ntest = []"
        ));
        assert!(is_pyproject_toml("  [dependency-groups]  \ntest = []"));
        // Valid [tool.hatch] patterns
        assert!(is_pyproject_toml(
            "[tool.hatch.envs.test]\ndependencies = []"
        ));
        assert!(is_pyproject_toml(
            "[tool.hatch.envs.default]\ndependencies = []"
        ));
        assert!(is_pyproject_toml("[tool.hatch] # comment\nversion = {}"));
        assert!(is_pyproject_toml(
            "[tool.hatch.envs.test.scripts]\ntest = \"pytest\""
        ));

        // Invalid patterns (should not trigger TOML parsing)
        assert!(!is_pyproject_toml("mypkg[project]==1.2"));
        assert!(!is_pyproject_toml("pkg[tool.poetry]>=1.0"));
        assert!(!is_pyproject_toml("pkg[tool.hatch]>=1.0"));
        assert!(!is_pyproject_toml("[projects]\nname = \"test\"")); // not [project]
        assert!(!is_pyproject_toml("[projectx]\nname = \"test\"")); // not [project] or [project.*]
        assert!(!is_pyproject_toml("[tool.poetryextra]\nname = \"test\"")); // not [tool.poetry...]
        assert!(!is_pyproject_toml("[tool.hatchextra]\nname = \"test\"")); // not [tool.hatch...]
        assert!(!is_pyproject_toml("flask>=2.0.0\nrequests>=2.25.0"));
        assert!(!is_pyproject_toml("[dependency-groupsx]\ntest = []")); // not [dependency-groups]
    }

    #[test]
    fn test_pyproject_dependency_groups() {
        // Covers:
        //   - file with ONLY [dependency-groups] (non-package project, no [project] block)
        //   - multiple groups, multiple versioned deps per group
        //   - {include-group = "..."} table items are silently skipped (all groups are
        //     iterated directly, so no package is ever missed via this skip)
        //   - unversioned items ("bare-package" without operator) produce no Dependency
        //   - dev = false for all groups (spec assigns no dev semantics to group names)
        let parser = PythonParser::new();
        let content = r#"
[dependency-groups]
test = ["pytest>=7.0.0", "coverage>=7.0.0"]
typing = ["mypy>=1.0.0", {include-group = "test"}, "types-requests>=2.0.0"]
typing-test = [{include-group = "typing"}, {include-group = "test"}, "useful-types>=1.0.0"]
unversioned = ["bare-package"]
"#;
        let deps = parser.parse(content);

        // test: 2, typing: 2 (include-group skipped), typing-test: 1 (both include-groups skipped)
        // unversioned: 0 (no version operator → parse_pep508_dependency returns None)
        assert_eq!(deps.len(), 5);

        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        assert_eq!(pytest.version, ">=7.0.0");
        assert!(!pytest.dev);

        let coverage = deps.iter().find(|d| d.name == "coverage").unwrap();
        assert_eq!(coverage.version, ">=7.0.0");
        assert!(!coverage.dev);

        let mypy = deps.iter().find(|d| d.name == "mypy").unwrap();
        assert_eq!(mypy.version, ">=1.0.0");
        assert!(!mypy.dev);

        let types_requests = deps.iter().find(|d| d.name == "types-requests").unwrap();
        assert_eq!(types_requests.version, ">=2.0.0");
        assert!(!types_requests.dev);

        let useful_types = deps.iter().find(|d| d.name == "useful-types").unwrap();
        assert_eq!(useful_types.version, ">=1.0.0");
        assert!(!useful_types.dev);

        // bare-package has no version operator → must not appear
        assert!(!deps.iter().any(|d| d.name == "bare-package"));
    }

    #[test]
    fn test_is_hatch_toml_detection() {
        // Valid: top-level [envs.<name>] section
        assert!(is_hatch_toml("[envs.test]\ndependencies = []"));
        assert!(is_hatch_toml("[envs.default]\ndependencies = []"));
        // Sub-tables of an env are also valid triggers
        assert!(is_hatch_toml("[envs.test.scripts]\ntest = \"pytest\""));
        // Inline comment after closing bracket
        assert!(is_hatch_toml(
            "[envs.test] # my test env\ndependencies = []"
        ));
        // Leading whitespace on header line
        assert!(is_hatch_toml("  [envs.test]  \ndependencies = []"));

        // Invalid: bare [envs] without a name
        assert!(!is_hatch_toml("[envs]\ndependencies = []"));
        // Invalid: different top-level key
        assert!(!is_hatch_toml("[envsx.test]\ndependencies = []"));
        // Invalid: content that would be pyproject.toml
        assert!(!is_hatch_toml("[project]\nname = \"test\""));
        // Invalid: requirements.txt style
        assert!(!is_hatch_toml("flask>=2.0.0\nrequests>=2.25.0"));
        // Invalid: env name is part of a value, not a section header
        assert!(!is_hatch_toml("template = \"[envs.default]\""));
    }

    #[test]
    fn test_pyproject_hatch_deps() {
        // Basic [tool.hatch.envs.*] with dependencies
        let parser = PythonParser::new();
        let content = r#"
[project]
name = "myproject"
version = "1.0.0"

[tool.hatch.envs.test]
dependencies = [
    "pytest>=7.0.0",
    "coverage>=6.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        assert_eq!(pytest.version, ">=7.0.0");
        assert!(pytest.dev);
        assert!(!pytest.optional);

        let coverage = deps.iter().find(|d| d.name == "coverage").unwrap();
        assert_eq!(coverage.version, ">=6.0");
        assert!(coverage.dev);
        assert!(!coverage.optional);
    }

    #[test]
    fn test_pyproject_hatch_extra_deps() {
        // extra-dependencies in a hatch env
        let parser = PythonParser::new();
        let content = r#"
[project]
name = "myproject"

[tool.hatch.envs.default]
dependencies = [
    "foo>=1.0",
]

[tool.hatch.envs.experimental]
extra-dependencies = [
    "baz>=2.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let foo = deps.iter().find(|d| d.name == "foo").unwrap();
        assert_eq!(foo.version, ">=1.0");
        assert!(foo.dev);
        assert!(!foo.optional);

        let baz = deps.iter().find(|d| d.name == "baz").unwrap();
        assert_eq!(baz.version, ">=2.0");
        assert!(baz.dev);
        assert!(!baz.optional);
    }

    #[test]
    fn test_pyproject_hatch_multiple_envs() {
        // Several named envs each contributing deps; all dev=true, optional=false
        let parser = PythonParser::new();
        let content = r#"
[project]
name = "myproject"

[tool.hatch.envs.default]
dependencies = ["requests>=2.28.0"]

[tool.hatch.envs.test]
dependencies = [
    "pytest>=7.0.0",
    "coverage[toml]>=6.0",
]

[tool.hatch.envs.lint]
dependencies = [
    "ruff>=0.1.0",
    "mypy>=1.0.0",
]
extra-dependencies = [
    "types-requests>=2.28.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 6);
        assert!(deps.iter().all(|d| d.dev));
        assert!(deps.iter().all(|d| !d.optional));

        assert!(deps.iter().any(|d| d.name == "requests"));
        assert!(deps.iter().any(|d| d.name == "pytest"));
        assert!(deps.iter().any(|d| d.name == "coverage"));
        assert!(deps.iter().any(|d| d.name == "ruff"));
        assert!(deps.iter().any(|d| d.name == "mypy"));
        assert!(deps.iter().any(|d| d.name == "types-requests"));
    }

    #[test]
    fn test_pyproject_hatch_no_version() {
        // Bare package name without a version operator is silently dropped
        let parser = PythonParser::new();
        let content = r#"
[tool.hatch.envs.test]
dependencies = [
    "bare-package",
    "pytest>=7.0.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "pytest");
        assert!(!deps.iter().any(|d| d.name == "bare-package"));
    }

    #[test]
    fn test_pyproject_hatch_context_formatted() {
        // Context-formatted strings (hatch-specific, no PEP 508 version operator) are
        // silently skipped.  A versioned dep on the same env is still collected.
        let parser = PythonParser::new();
        let content = r#"
[tool.hatch.envs.test]
dependencies = [
    "example-project @ {root:parent:parent:uri}/example-project",
    "pytest>=7.0.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "pytest");
    }

    #[test]
    fn test_pyproject_hatch_combined_pep621() {
        // pyproject.toml with [project.dependencies] (dev=false) and
        // [tool.hatch.envs.*] (dev=true, optional=false) in the same file.
        let parser = PythonParser::new();
        let content = r#"
[project]
name = "myproject"
dependencies = [
    "flask>=2.0.0",
    "requests~=2.25.0",
]

[project.optional-dependencies]
extras = [
    "redis>=4.0.0",
]

[tool.hatch.envs.test]
dependencies = [
    "pytest>=7.0.0",
    "coverage>=6.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 5);

        // Project deps: dev=false, optional=false
        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert!(!flask.dev);
        assert!(!flask.optional);

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert!(!requests.dev);
        assert!(!requests.optional);

        // Optional dep: dev=true, optional=true
        let redis = deps.iter().find(|d| d.name == "redis").unwrap();
        assert!(redis.dev);
        assert!(redis.optional);

        // Hatch env deps: dev=true, optional=false
        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        assert!(pytest.dev);
        assert!(!pytest.optional);

        let coverage = deps.iter().find(|d| d.name == "coverage").unwrap();
        assert!(coverage.dev);
        assert!(!coverage.optional);
    }

    #[test]
    fn test_hatch_toml_basic() {
        // Standalone hatch.toml — envs at top level under [envs.*]
        let parser = PythonParser::new();
        let content = r#"
[envs.default]
dependencies = [
    "mypy>=1.0.0",
]

[envs.test]
dependencies = [
    "pytest>=7.0.0",
    "coverage>=6.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().all(|d| d.dev));
        assert!(deps.iter().all(|d| !d.optional));

        assert!(deps.iter().any(|d| d.name == "mypy"));
        assert!(deps.iter().any(|d| d.name == "pytest"));
        assert!(deps.iter().any(|d| d.name == "coverage"));
    }

    #[test]
    fn test_hatch_toml_extra_deps() {
        // extra-dependencies in standalone hatch.toml
        let parser = PythonParser::new();
        let content = r#"
[envs.default]
dependencies = [
    "foo>=1.0",
    "bar>=2.0",
]

[envs.experimental]
extra-dependencies = [
    "baz>=3.0",
]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "foo"));
        assert!(deps.iter().any(|d| d.name == "bar"));
        assert!(deps.iter().any(|d| d.name == "baz"));
        assert!(deps.iter().all(|d| d.dev));
        assert!(deps.iter().all(|d| !d.optional));
    }

    #[test]
    fn test_pyproject_poetry_groups_dev() {
        let content = r#"
[tool.poetry]
name = "x"
version = "0.1.0"

[tool.poetry.group.dev.dependencies]
black = "^23.0.0"
ruff = "^0.1.0"
"#;
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2, "expected 2 deps, got {deps:?}");
        let black = deps
            .iter()
            .find(|d| d.name == "black")
            .expect("black missing");
        assert!(black.dev, "black in [group.dev] must be dev=true");
        assert!(!black.optional);
        let ruff = deps
            .iter()
            .find(|d| d.name == "ruff")
            .expect("ruff missing");
        assert!(ruff.dev);
        assert!(!ruff.optional);
    }

    #[test]
    fn test_pyproject_poetry_groups_test() {
        let content = r#"
[tool.poetry]
name = "x"
version = "0.1.0"

[tool.poetry.group.test.dependencies]
pytest = "^7.0.0"
"#;
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        let pytest = deps
            .iter()
            .find(|d| d.name == "pytest")
            .expect("pytest missing");
        assert!(pytest.dev, "pytest in [group.test] must be dev=true");
    }

    #[test]
    fn test_pyproject_poetry_groups_custom() {
        let content = r#"
[tool.poetry]
name = "x"
version = "0.1.0"

[tool.poetry.group.docs.dependencies]
mkdocs = "^1.5.0"
"#;
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        let mkdocs = deps
            .iter()
            .find(|d| d.name == "mkdocs")
            .expect("mkdocs missing");
        assert!(!mkdocs.dev, "mkdocs in [group.docs] must be dev=false");
        assert!(!mkdocs.optional);
    }

    #[test]
    fn test_pyproject_poetry_table_format() {
        let content = r#"
[tool.poetry.dependencies]
python = "^3.9"
requests = { version = "^2.28.0", optional = true }
"#;
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        let req = deps
            .iter()
            .find(|d| d.name == "requests")
            .expect("requests missing");
        assert_eq!(req.version, "^2.28.0");
        assert!(
            req.optional,
            "optional=true must be propagated from inline table"
        );
    }

    #[test]
    fn test_pyproject_pep621_dynamic_safe() {
        let content = r#"
[project]
name = "x"
version = "0.1.0"
dynamic = ["dependencies"]
"#;
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(
            deps.len(),
            0,
            "dynamic deps should yield no Dependency items"
        );
    }

    #[test]
    fn test_pyproject_environment_markers() {
        let content = r#"
[project]
name = "x"
version = "0.1.0"
dependencies = [
    "pytest>=7.0;python_version>='3.8'",
]
"#;
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        let pytest = deps
            .iter()
            .find(|d| d.name == "pytest")
            .expect("pytest missing");
        assert_eq!(pytest.version, ">=7.0", "marker must be stripped");
    }

    #[test]
    fn test_pyproject_mixed_all_sections() {
        let content = r#"
[project]
name = "x"
version = "0.1.0"
dependencies = ["requests>=2.28.0"]

[project.optional-dependencies]
docs = ["mkdocs>=1.5.0"]

[dependency-groups]
test = ["pytest>=7.0.0"]

[tool.hatch.envs.lint]
dependencies = ["ruff>=0.1.0"]
"#;
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert!(deps.iter().any(|d| d.name == "requests"));
        assert!(deps.iter().any(|d| d.name == "mkdocs" && d.optional));
        assert!(deps.iter().any(|d| d.name == "pytest"));
        assert!(deps.iter().any(|d| d.name == "ruff" && d.dev));
        assert_eq!(deps.len(), 4, "expected 4 deps total, got {deps:?}");
    }

    #[test]
    fn test_pyproject_pep621_position_accuracy() {
        let content = "[project]\nname = \"x\"\nversion = \"0.1.0\"\ndependencies = [\n    \"requests>=2.28.0\",\n]\n";
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.name, "requests");
        assert_eq!(dep.version, ">=2.28.0");
        // Content layout (0-indexed): 0=[project], 1=name, 2=version, 3=dependencies = [, 4=    "requests>=2.28.0",, 5=]
        assert_eq!(
            dep.name_span.line, 4,
            "name should be on the line containing the array item"
        );
        assert_eq!(dep.version_span.line, 4);
        // column checks: end > start is enough; exact offsets depend on taplo quote resolution
        assert!(dep.name_span.line_end > dep.name_span.line_start);
        assert!(dep.version_span.line_end > dep.version_span.line_start);
    }

    #[test]
    fn test_pyproject_poetry_position_accuracy() {
        let content = "[tool.poetry.dependencies]\npython = \"^3.9\"\nrequests = \"^2.28.0\"\n";
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1, "only requests, python is skipped");
        let dep = &deps[0];
        assert_eq!(dep.name, "requests");
        assert_eq!(dep.version, "^2.28.0");
        // Content layout (0-indexed): 0=[tool.poetry.dependencies], 1=python = "^3.9", 2=requests = "^2.28.0"
        assert_eq!(dep.name_span.line, 2);
        assert_eq!(dep.version_span.line, 2);
        // column checks: end > start is enough; exact offsets depend on taplo quote resolution
        assert!(dep.name_span.line_end > dep.name_span.line_start);
        assert!(dep.version_span.line_end > dep.version_span.line_start);
    }

    #[test]
    fn test_compute_line_ranges_basic() {
        let content = "abc\nde\nfghi";
        let ranges = compute_line_ranges(content);
        assert_eq!(ranges.len(), 3);
        assert_eq!(u32::from(ranges[0].start()), 0);
        assert_eq!(u32::from(ranges[0].end()), 4); // "abc\n" = 4 bytes
        assert_eq!(u32::from(ranges[1].start()), 4);
        assert_eq!(u32::from(ranges[1].end()), 7); // "de\n" = 3 bytes
        assert_eq!(u32::from(ranges[2].start()), 7);
        assert_eq!(u32::from(ranges[2].end()), 11); // "fghi" = 4 bytes
    }

    #[test]
    fn test_range_to_span_returns_none_for_multiline_range() {
        let content = "abc\ndef\nghi";
        let line_ranges = compute_line_ranges(content);
        // Build a range that straddles line 0 and line 1: bytes [2..6) covers
        // "c\nde" — crosses the newline at byte 3.
        let straddle = TextRange::new(2u32.into(), 6u32.into());
        assert!(
            range_to_span(straddle, &line_ranges).is_none(),
            "multi-line range must yield None to prevent underflow"
        );
    }

    /// Helper: extract the substring `content[span]` for a single-line span.
    fn slice_span<'a>(content: &'a str, span: &Span) -> &'a str {
        let line = content.lines().nth(span.line as usize).expect("line");
        &line[span.line_start as usize..span.line_end as usize]
    }

    #[test]
    fn test_pep621_version_span_covers_only_version_literal() {
        // Quick-fix replacement targets `version_span`, so the span MUST cover
        // only `>=2.28.0` — never the package name or the surrounding quotes.
        // Otherwise an "Update to 2.28.1" edit would clobber `requests` or
        // produce `2.28.1` (no quotes) and break the TOML.
        let content = "[project]\ndependencies = [\"requests>=2.28.0\"]\n";
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.version, ">=2.28.0");
        assert_eq!(
            slice_span(content, &dep.version_span),
            ">=2.28.0",
            "version_span must cover only the operator + version, not the whole quoted spec"
        );
        assert_eq!(
            slice_span(content, &dep.name_span),
            "requests",
            "name_span must cover only the package name, not the whole quoted spec"
        );
    }

    #[test]
    fn test_poetry_simple_string_version_span_excludes_quotes() {
        // For `flask = "^2.0.0"`, version_span must cover only `^2.0.0`
        // (no quotes). Replacing with `^2.0.1` must yield valid TOML.
        let content = "[tool.poetry.dependencies]\nflask = \"^2.0.0\"\n";
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.version, "^2.0.0");
        assert_eq!(
            slice_span(content, &dep.version_span),
            "^2.0.0",
            "Poetry simple-string version_span must exclude surrounding quotes"
        );
    }

    #[test]
    fn test_poetry_inline_table_version_span_targets_inner_string() {
        // For `requests = { version = "^2.28.0", optional = true }`,
        // version_span must cover only `^2.28.0` so that quick-fix replacement
        // does not clobber the rest of the inline-table metadata.
        let content =
            "[tool.poetry.dependencies]\nrequests = { version = \"^2.28.0\", optional = true }\n";
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.version, "^2.28.0");
        assert!(dep.optional);
        assert_eq!(
            slice_span(content, &dep.version_span),
            "^2.28.0",
            "Poetry inline-table version_span must point at the nested version literal, \
             not the whole inline table"
        );
    }

    #[test]
    fn test_pep735_version_span_covers_only_version_literal() {
        let content = "[dependency-groups]\ntest = [\"pytest>=7.0.0\"]\n";
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.version, ">=7.0.0");
        assert_eq!(slice_span(content, &dep.version_span), ">=7.0.0");
        assert_eq!(slice_span(content, &dep.name_span), "pytest");
    }

    #[test]
    fn test_hatch_envs_version_span_covers_only_version_literal() {
        let content = "[tool.hatch.envs.lint]\ndependencies = [\"ruff>=0.1.0\"]\n";
        let parser = PythonParser::new();
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.version, ">=0.1.0");
        assert_eq!(slice_span(content, &dep.version_span), ">=0.1.0");
        assert_eq!(slice_span(content, &dep.name_span), "ruff");
    }

    #[test]
    fn requirements_preserve_spacing_and_track_additional_constraints() {
        let content = "single>= 1.0\ncompound>= 1.0, < 2.0\n";
        let deps = PythonParser::new().parse(content);

        let single = deps.iter().find(|dep| dep.name == "single").unwrap();
        assert_eq!(single.version, ">= 1.0");
        assert_eq!(slice_span(content, &single.version_span), ">= 1.0");
        assert!(!single.has_additional_version_constraints);

        let compound = deps.iter().find(|dep| dep.name == "compound").unwrap();
        assert_eq!(compound.version, ">= 1.0");
        assert_eq!(slice_span(content, &compound.version_span), ">= 1.0");
        assert!(compound.has_additional_version_constraints);
    }

    #[test]
    fn pep508_arrays_preserve_spacing_and_track_additional_constraints() {
        let content = concat!(
            "[project]\n",
            "dependencies = [\"single>= 1.0\", \"compound>= 1.0, < 2.0\"]\n"
        );
        let deps = PythonParser::new().parse(content);

        let single = deps.iter().find(|dep| dep.name == "single").unwrap();
        assert_eq!(single.version, ">= 1.0");
        assert_eq!(slice_span(content, &single.version_span), ">= 1.0");
        assert!(!single.has_additional_version_constraints);

        let compound = deps.iter().find(|dep| dep.name == "compound").unwrap();
        assert_eq!(compound.version, ">= 1.0");
        assert_eq!(slice_span(content, &compound.version_span), ">= 1.0");
        assert!(compound.has_additional_version_constraints);
    }
}
