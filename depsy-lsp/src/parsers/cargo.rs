//! Parser for Cargo.toml files using structured TOML parsing.
//!
//! Handles all dependency declaration styles supported by Cargo:
//!
//! - Simple version string: `serde = "1.0"`
//! - Inline table: `serde = { version = "1.0", features = ["derive"] }`
//! - Section table: `[dependencies.serde]` / `version = "1.0"`
//! - Package alias: `serde1 = { package = "serde", version = "1.0" }`
//! - Workspace dependencies: `[workspace.dependencies]`
//! - All three scopes: `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`
//! - Target-specific scopes: `[target.'cfg(unix)'.dependencies]` and friends
//!
//! Parsing is performed with `taplo` so that byte-accurate [`Span`] values are
//! available for every token; this allows LSP quick-fix `TextEdit`s to replace
//! only the version literal without touching surrounding TOML syntax.

use taplo::dom::Node;
use taplo::dom::node::{Bool, DomNode, Key, Str};
use taplo::parser::parse;
use taplo::rowan::TextRange;
use taplo::rowan::TextSize;
use taplo::syntax::SyntaxElement;

use super::{Dependency, Parser, Span};

/// Extracts the `[package].name` field from a `Cargo.toml` manifest.
///
/// Returns `None` when:
///
/// - The TOML is malformed and cannot be parsed.
/// - The manifest is a virtual workspace (no `[package]` section).
/// - `[package]` exists but `name` is missing.
/// - `[package].name` is present but not a string (e.g. an array).
///
/// The value is forwarded to the lock-file resolver for multi-version
/// disambiguation.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::cargo::cargo_root_package_name;
/// let manifest = "[package]\nname = \"my-crate\"\nversion = \"0.1.0\"\n";
/// assert_eq!(cargo_root_package_name(manifest).as_deref(), Some("my-crate"));
/// ```
///
/// Virtual workspaces (no `[package]` section) return `None`:
///
/// ```
/// use depsy_lsp::parsers::cargo::cargo_root_package_name;
/// let manifest = "[workspace]\nmembers = [\"crate-a\"]\n";
/// assert!(cargo_root_package_name(manifest).is_none());
/// ```
pub fn cargo_root_package_name(manifest_content: &str) -> Option<String> {
    let value: toml::Value = toml::from_str(manifest_content).ok()?;
    value
        .get("package")?
        .get("name")?
        .as_str()
        .map(|s| s.to_string())
}

/// Parser for Rust `Cargo.toml` dependency files.
///
/// Delegates to the `taplo` TOML parser for robust span tracking.
/// All three standard dependency scopes (`dependencies`, `dev-dependencies`,
/// `build-dependencies`), their target-specific counterparts
/// (`[target.<cfg>.dependencies]`), and `workspace.dependencies` are parsed in
/// a single pass.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::cargo::CargoParser;
/// let parser = CargoParser::new();
/// let deps = parser.parse("[dependencies]\ntokio = { version = \"1.0\", features = [\"full\"] }\n");
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "tokio");
/// assert_eq!(deps[0].version, "1.0");
/// ```
#[derive(Debug, Default)]
pub struct CargoParser;

impl CargoParser {
    /// Creates a new [`CargoParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for CargoParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        let parsed = parse(content);

        // If there are critical parse errors, return empty
        if parsed.errors.iter().any(|e| e.message.contains("expected")) {
            return Vec::new();
        }

        let line_ranges = content
            .split_inclusive('\n')
            .map({
                let mut offset: usize = 0;
                move |line| {
                    let content_len = line.trim_end_matches('\n').trim_end_matches('\r').len();
                    let range = TextRange::at((offset as u32).into(), (content_len as u32).into());
                    offset += line.len();
                    range
                }
            })
            .collect::<Box<[_]>>();
        let dom = parsed.into_dom();

        let mut dependencies = Vec::new();

        // Define dependency sections to parse: (section_name, is_dev)
        let sections = [
            ("dependencies", false),
            ("dev-dependencies", true),
            ("build-dependencies", false),
        ];

        for (section_name, is_dev) in sections {
            // Parse regular section dependencies (e.g., [dependencies])
            let section_node = dom.get(section_name);
            let Some(section) = section_node.as_table() else {
                continue;
            };
            let entries = section.entries().read();
            let deps = entries
                .iter()
                .filter_map(|(name, value)| parse_dependency(name, value, &line_ranges, is_dev));
            dependencies.extend(deps);
        }

        // Parse target-specific sections (e.g. [target.'cfg(unix)'.dependencies])
        let target_node = dom.get("target");
        if let Some(target_table) = target_node.as_table() {
            let targets = target_table.entries().read();
            for (_, cfg_node) in targets.iter() {
                for (section_name, is_dev) in sections {
                    let section_node = cfg_node.get(section_name);
                    let Some(section) = section_node.as_table() else {
                        continue;
                    };
                    let entries = section.entries().read();
                    let deps = entries.iter().filter_map(|(name, value)| {
                        parse_dependency(name, value, &line_ranges, is_dev)
                    });
                    dependencies.extend(deps);
                }
            }
        }

        // Parse workspace.dependencies section
        if let Some(workspace_table) = dom.get("workspace").as_table()
            && let Some(deps_node) = workspace_table.get("dependencies")
            && let Some(deps_table) = deps_node.as_table()
        {
            let entries = deps_table.entries().read();
            let workspace_deps = entries
                .iter()
                .filter_map(|(name, value)| parse_dependency(name, value, &line_ranges, false));
            dependencies.extend(workspace_deps);
        }

        dependencies
    }
}

/// Parse a single dependency from a TOML node
fn parse_dependency(
    name: &Key,
    node: &Node,
    line_spans: &[TextRange],
    is_dev: bool,
) -> Option<Dependency> {
    match node {
        Node::Str(version) => {
            // Simple dependency: name = "1.0.0"
            let TablePositions {
                name_span,
                version_span,
            } = find_dependency_positions(line_spans, name, None, version)?;

            Some(Dependency {
                name: name.value().to_owned(),
                version: version.value().to_owned(),
                name_span,
                version_span,
                dev: is_dev,
                optional: false,
                registry: None,
                resolved_version: None,
                has_additional_version_constraints: false,
            })
        }
        Node::Table(table) => {
            let package_node = table.get("package");
            let package_str = package_node.as_ref().and_then(Node::as_str);

            // Inline table: name = { version = "1.0.0", ... }
            let version_node = table.get("version")?;
            let version_str = version_node.as_str()?;

            let optional = table
                .get("optional")
                .as_ref()
                .and_then(Node::as_bool)
                .map(Bool::value)
                .unwrap_or(false);

            let registry = table
                .get("registry")
                .as_ref()
                .and_then(Node::as_str)
                .map(|s| s.value().to_owned());

            let TablePositions {
                name_span,
                version_span,
            } = find_dependency_positions(line_spans, name, package_str, version_str)?;

            Some(Dependency {
                name: package_str
                    .map(Str::value)
                    .unwrap_or_else(|| name.value())
                    .to_owned(),
                version: version_str.value().to_owned(),
                name_span,
                version_span,
                dev: is_dev,
                optional,
                registry,
                resolved_version: None,
                has_additional_version_constraints: false,
            })
        }
        _ => None,
    }
}

struct TablePositions {
    name_span: Span,
    version_span: Span,
}

/// Find positions for a dependency
/// - simple: `name = "version"`
/// - inline: `name = { version = "1.0.0", package = "...", ... }`
/// - table: `[dependencies.name]` with `version = "x.y.z"` & `package = "..."`
fn find_dependency_positions(
    line_ranges: &[TextRange],
    name: &Key,
    package: Option<&Str>,
    version: &Str,
) -> Option<TablePositions> {
    let name_range = package
        .and_then(str_content_range)
        .or_else(|| name.syntax().map(SyntaxElement::text_range))?;
    let version_range = str_content_range(version)?;

    let name_span = find_range_span(line_ranges, name_range)?;
    let version_span = find_range_span(line_ranges, version_range)?;

    Some(TablePositions {
        name_span,
        version_span,
    })
}

fn str_content_range(s: &Str) -> Option<TextRange> {
    let quoted_range = s.syntax()?.text_range();
    let one = TextSize::from(1);
    let inner_start = quoted_range.start().checked_add(one)?;
    let inner_end = quoted_range.end().checked_sub(one)?;
    if inner_start > inner_end {
        return None;
    }
    Some(TextRange::new(inner_start, inner_end))
}

fn find_range_span(haystack: &[TextRange], needle: TextRange) -> Option<Span> {
    let line_idx = line_range_position(haystack, needle)?;
    let line_range = haystack[line_idx];
    if needle.start() < line_range.start() || needle.end() > line_range.end() {
        return None;
    }
    let base = line_range.start();
    Some(Span {
        line: line_idx as u32,
        line_start: (needle.start() - base).into(),
        line_end: (needle.end() - base).into(),
    })
}

fn line_range_position(haystack: &[TextRange], needle: TextRange) -> Option<usize> {
    haystack
        .binary_search_by(|line_range| line_range.ordering(needle))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_dependency() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies]
serde = "1.0.0"
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.0");
        assert!(!deps[0].dev);
    }

    #[test]
    fn test_inline_table_dependency() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies]
serde = { version = "1.0.0", features = ["derive"] }
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].name_span.line_start, 0);
        assert_eq!(deps[0].version, "1.0.0");
    }

    #[test]
    fn test_inline_table_alias_dependency() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies]
serde1 = { package = "serde", version = "1.0.0", features = ["derive"] }
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].name_span.line_start, 22);
        assert_eq!(deps[0].name_span.line_end, 27);
        assert_eq!(deps[0].version, "1.0.0");
    }

    #[test]
    fn test_dev_dependencies() {
        let parser = CargoParser::new();
        let content = r#"
[dev-dependencies]
tokio-test = "0.4"
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "tokio-test");
        assert!(deps[0].dev);
    }

    #[test]
    fn test_multiple_sections() {
        let parser = CargoParser::new();
        let content = r#"
[package]
name = "test"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3, "{deps:#?}");

        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.version, "1.0");
        assert!(!serde.dev);

        let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
        assert_eq!(tokio.version, "1.0");
        assert!(!tokio.dev);

        let criterion = deps.iter().find(|d| d.name == "criterion").unwrap();
        assert_eq!(criterion.version, "0.5");
        assert!(criterion.dev);
    }

    #[test]
    fn test_table_dependency() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies.reqwest]
version = "0.12"
features = ["json"]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "reqwest");
        assert_eq!(deps[0].name_span.line, 1);
        assert_eq!(deps[0].version, "0.12");
    }

    #[test]
    fn test_table_alias_dependency() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies.reqwest1]
package = "reqwest"
version = "0.12"
features = ["json"]
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "reqwest");
        assert_eq!(deps[0].name_span.line, 2);
        assert_eq!(deps[0].name_span.line_start, 11);
        assert_eq!(deps[0].name_span.line_end, 18);
        assert_eq!(deps[0].version, "0.12");
    }

    #[test]
    fn test_optional_dependency() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies]
optional-dep = { version = "1.0", optional = true }
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].optional);
    }

    #[test]
    fn test_workspace_dependencies_simple() {
        let parser = CargoParser::new();
        let content = r#"
[workspace]
members = ["crate-a"]

[workspace.dependencies]
serde = "1.0.0"
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.0");
    }

    #[test]
    fn test_workspace_dependencies_inline_table() {
        let parser = CargoParser::new();
        let content = r#"
[workspace]
members = ["crate-a"]

[workspace.dependencies]
tokio = { version = "1.0", features = ["full"] }
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "tokio");
        assert_eq!(deps[0].version, "1.0");
    }

    #[test]
    fn test_workspace_and_regular_dependencies() {
        let parser = CargoParser::new();
        let content = r#"
[package]
name = "test"
version = "0.1.0"

[workspace]
members = ["crate-a"]

[workspace.dependencies]
serde = "1.0"

[dependencies]
anyhow = "1.0"
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "serde"));
        assert!(deps.iter().any(|d| d.name == "anyhow"));
    }

    #[test]
    fn test_dependency_with_registry() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies]
my-crate = { version = "0.1.0", registry = "kellnr" }
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-crate");
        assert_eq!(deps[0].version, "0.1.0");
        assert_eq!(deps[0].registry.as_deref(), Some("kellnr"));
    }

    #[test]
    fn test_dependency_without_registry() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies]
serde = { version = "1.0.0", features = ["derive"] }
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert!(deps[0].registry.is_none());
    }

    #[test]
    fn test_cargo_root_package_name_returns_package_name() {
        let manifest = r#"
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
        assert_eq!(
            cargo_root_package_name(manifest),
            Some("my-crate".to_string())
        );
    }

    #[test]
    fn test_cargo_root_package_name_returns_none_for_workspace_only() {
        let manifest = r#"
[workspace]
members = ["crate-a"]
"#;
        assert_eq!(cargo_root_package_name(manifest), None);
    }

    #[test]
    fn test_cargo_root_package_name_returns_none_for_invalid_toml() {
        assert_eq!(cargo_root_package_name("not [valid toml ="), None);
    }

    #[test]
    fn test_target_specific_dependencies() {
        let parser = CargoParser::new();
        let content = r#"
[dependencies]
serde = "1.0"

[target.'cfg(unix)'.dependencies]
nix = "0.29.0"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59.0", features = ["Win32_Foundation"] }

[target.x86_64-unknown-linux-gnu.dev-dependencies]
criterion = "0.5"

[target.'cfg(target_os = "macos")'.build-dependencies]
cc = "1.0"
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 5, "{deps:#?}");

        let nix = deps.iter().find(|d| d.name == "nix").unwrap();
        assert_eq!(nix.version, "0.29.0");
        assert!(!nix.dev);
        assert_eq!(nix.name_span.line, 5);

        let win = deps.iter().find(|d| d.name == "windows-sys").unwrap();
        assert_eq!(win.version, "0.59.0");

        let criterion = deps.iter().find(|d| d.name == "criterion").unwrap();
        assert!(criterion.dev);

        assert!(deps.iter().any(|d| d.name == "cc"));
    }
}
