//! Parser for Dart/Flutter `pubspec.yaml` files.
//!
//! Recognises three top-level sections:
//!
//! | YAML key | `dev` |
//! |----------|-------|
//! | `dependencies` | `false` |
//! | `dev_dependencies` | `true` |
//! | `dependency_overrides` | `false` |
//!
//! Complex dependency forms (git, path, SDK, hosted) are silently skipped.
//! Flutter SDK packages (`flutter`, `flutter_test`, etc.) are also excluded.
//! Inline YAML comments after a version string are stripped before the version
//! is recorded.

use super::{Dependency, Parser, Span};

/// Parser for Dart `pubspec.yaml` dependency files.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::dart::DartParser;
/// let parser = DartParser::new();
/// let content = "dependencies:\n  http: ^1.0.0\n";
/// let deps = parser.parse(content);
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "http");
/// assert_eq!(deps[0].version, "^1.0.0");
/// ```
#[derive(Debug, Default)]
pub struct DartParser;

impl DartParser {
    /// Creates a new [`DartParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for DartParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        let mut dependencies = Vec::new();
        let mut current_section: Option<DependencySection> = None;
        let mut in_nested_block = false;

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx as u32;
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check for section headers (no indentation, ends with :)
            if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
                let section_name = trimmed.trim_end_matches(':');
                current_section = match section_name {
                    "dependencies" => Some(DependencySection::Dependencies),
                    "dev_dependencies" => Some(DependencySection::DevDependencies),
                    "dependency_overrides" => Some(DependencySection::DependencyOverrides),
                    _ => None,
                };
                in_nested_block = false;
                continue;
            }

            // Only process if we're in a dependency section
            let Some(section) = &current_section else {
                continue;
            };

            // Check if we're exiting the section (new top-level key)
            if !line.starts_with(' ') && !line.starts_with('\t') {
                current_section = None;
                continue;
            }

            // Skip if we're in a nested block (git, path, sdk dependencies)
            if in_nested_block {
                // Check if this line is less indented than before (exit nested)
                let indent = line.len() - line.trim_start().len();
                if indent <= 2 {
                    in_nested_block = false;
                } else {
                    continue;
                }
            }

            // Parse dependency line
            if let Some(dep) = parse_dart_dependency_line(line, line_num, section.is_dev()) {
                // Check if this is a complex dependency (sdk, git, path)
                if is_complex_dependency(trimmed) {
                    in_nested_block = true;
                    continue;
                }

                // Skip Flutter SDK dependencies
                if is_flutter_sdk_dependency(&dep.name) {
                    continue;
                }

                dependencies.push(dep);
            } else if trimmed.ends_with(':') && !trimmed.contains(' ') {
                // This is a package name without version on same line
                // Could be a complex dependency
                in_nested_block = true;
            }
        }

        dependencies
    }
}

/// Tracks which top-level YAML section is currently being parsed.
#[derive(Debug, Clone, Copy)]
enum DependencySection {
    Dependencies,
    DevDependencies,
    DependencyOverrides,
}

impl DependencySection {
    fn is_dev(&self) -> bool {
        matches!(self, DependencySection::DevDependencies)
    }
}

/// Parses a single indented YAML dependency line.
///
/// Returns `None` for lines without a version (complex dependencies handled
/// by the caller as nested blocks), for complex inline forms (`sdk:`, `git:`,
/// etc.), and for path/absolute-path version values.
fn parse_dart_dependency_line(line: &str, line_num: u32, dev: bool) -> Option<Dependency> {
    let trimmed = line.trim();

    // Skip if it doesn't contain a colon
    if !trimmed.contains(':') {
        return None;
    }

    let colon_pos = trimmed.find(':')?;
    let name = trimmed[..colon_pos].trim();
    let version_part = trimmed[colon_pos + 1..].trim();

    // Skip if no version (could be a complex dependency)
    if version_part.is_empty() {
        return None;
    }

    // Skip if it's a complex dependency (starts with { or contains special keys)
    if version_part.starts_with('{') || !version_part.starts_with('^') && version_part.contains(':')
    {
        return None;
    }

    // Strip inline YAML comments (e.g. "^3.2.2 # From Google" -> "^3.2.2")
    // Only strip if # is outside quoted strings
    let version_part = if version_part.starts_with('"') || version_part.starts_with('\'') {
        let quote = version_part.as_bytes()[0];
        match version_part[1..].find(quote as char) {
            Some(end) => version_part[..end + 2].trim(),
            None => version_part,
        }
    } else {
        match version_part.find('#') {
            Some(hash_pos) => version_part[..hash_pos].trim(),
            None => version_part,
        }
    };

    // Clean the version (remove quotes if present)
    let version = version_part
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();

    // Skip if version is empty or looks like a path/git/sdk reference
    if version.is_empty() || version.starts_with('/') || version.starts_with('.') {
        return None;
    }

    // Calculate positions
    let name_start = line.find(name)? as u32;
    let name_end = name_start + name.len() as u32;
    let version_start = line.find(&version)? as u32;
    let version_end = version_start + version.len() as u32;

    Some(Dependency {
        name: name.to_string(),
        version,
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
        has_additional_version_constraints: false,
    })
}

/// Returns `true` when `line` indicates a complex dependency form (git, path, sdk, hosted).
fn is_complex_dependency(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.ends_with(':') && !trimmed.contains(' ')
        || trimmed.contains("sdk:")
        || trimmed.contains("git:")
        || trimmed.contains("path:")
        || trimmed.contains("hosted:")
}

/// Returns `true` for packages that are part of the Flutter SDK and therefore
/// have no pub.dev entry.
fn is_flutter_sdk_dependency(name: &str) -> bool {
    matches!(
        name,
        "flutter"
            | "flutter_test"
            | "flutter_localizations"
            | "flutter_driver"
            | "flutter_web_plugins"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_dependencies() {
        let content = r#"
name: my_app
version: 1.0.0

dependencies:
  http: ^1.0.0
  provider: ^6.0.0

dev_dependencies:
  mockito: ^5.4.0
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 3);

        let http = deps.iter().find(|d| d.name == "http").unwrap();
        assert_eq!(http.version, "^1.0.0");
        assert!(!http.dev);

        let mockito = deps.iter().find(|d| d.name == "mockito").unwrap();
        assert!(mockito.dev);
    }

    #[test]
    fn test_skip_flutter_sdk() {
        let content = r#"
dependencies:
  flutter:
    sdk: flutter
  http: ^1.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.0
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        // Should only find http and mockito, not flutter or flutter_test
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "http"));
        assert!(deps.iter().any(|d| d.name == "mockito"));
        assert!(!deps.iter().any(|d| d.name == "flutter"));
        assert!(!deps.iter().any(|d| d.name == "flutter_test"));
    }

    #[test]
    fn test_skip_git_dependencies() {
        let content = r#"
dependencies:
  http: ^1.0.0
  custom_pkg:
    git:
      url: https://github.com/user/repo.git
      ref: main
  provider: ^6.0.0
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        // Should only find http and provider
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "http"));
        assert!(deps.iter().any(|d| d.name == "provider"));
    }

    #[test]
    fn test_version_positions() {
        let content = r#"
dependencies:
  http: ^1.0.0
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 1);
        let http = &deps[0];
        assert_eq!(http.name, "http");
        assert!(http.version_span.line_start > http.name_span.line_end);
    }

    #[test]
    fn test_quoted_versions() {
        let content = r#"
dependencies:
  http: "^1.0.0"
  provider: '^6.0.0'
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].version, "^1.0.0");
        assert_eq!(deps[1].version, "^6.0.0");
    }

    #[test]
    fn test_inline_comments_stripped() {
        let content = r#"
dependencies:
  quiver: ^3.2.2 # From Google
  http: ^1.0.0 # important lib
  provider: ^6.0.0
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 3);

        let quiver = deps.iter().find(|d| d.name == "quiver").unwrap();
        assert_eq!(quiver.version, "^3.2.2");

        let http = deps.iter().find(|d| d.name == "http").unwrap();
        assert_eq!(http.version, "^1.0.0");
    }

    #[test]
    fn test_quoted_version_with_inline_comment() {
        let content = r#"
dependencies:
  http: "^1.0.0" # pinned version
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "^1.0.0");
    }

    #[test]
    fn test_dependency_overrides() {
        let content = r#"
dependencies:
  http: ^1.0.0

dependency_overrides:
  http: ^1.1.0
"#;
        let parser = DartParser::new();
        let deps = parser.parse(content);

        // Should find both (override and regular)
        assert_eq!(deps.len(), 2);
    }
}
