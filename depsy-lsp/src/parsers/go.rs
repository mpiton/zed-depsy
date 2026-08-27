//! Parser for Go module files (`go.mod`).
//!
//! Recognises both single-line and block `require` directives:
//!
//! ```text
//! require github.com/pkg/errors v0.9.1
//!
//! require (
//!     github.com/gin-gonic/gin v1.9.1
//!     golang.org/x/text v0.14.0 // indirect
//! )
//! ```
//!
//! Indirect dependencies are surfaced with `optional = true`.
//! `replace` directives and comment-only lines are silently skipped.
//! Optimised for performance with pre-allocation and a single byte scan per line.

use super::{Dependency, Parser, Span};

/// Parser for Go `go.mod` dependency files.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::go::GoParser;
/// let parser = GoParser::new();
/// let content = "require github.com/pkg/errors v0.9.1\n";
/// let deps = parser.parse(content);
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "github.com/pkg/errors");
/// assert_eq!(deps[0].version, "v0.9.1");
/// ```
#[derive(Debug, Default)]
pub struct GoParser;

impl GoParser {
    /// Creates a new [`GoParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for GoParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        // Pre-allocate with reasonable capacity
        let mut dependencies = Vec::with_capacity(32);
        let mut in_require_block = false;

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx as u32;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            // Check for require block start
            if trimmed == "require (" {
                in_require_block = true;
                continue;
            }

            // Check for block end
            if trimmed == ")" {
                in_require_block = false;
                continue;
            }

            // Parse single-line require: require github.com/pkg/errors v0.9.1
            if let Some(rest) = trimmed.strip_prefix("require ") {
                if !rest.starts_with('(')
                    && let Some(dep) = parse_require_line(line, rest, line_num)
                {
                    dependencies.push(dep);
                }
                continue;
            }

            // Parse lines inside require block
            if in_require_block && let Some(dep) = parse_require_line(line, trimmed, line_num) {
                dependencies.push(dep);
            }
        }

        dependencies
    }
}

/// Parses a single `require` entry (standalone or inside a block).
///
/// Expected format: `module/path v1.2.3 [// indirect]`
///
/// Returns `None` for comments, blank lines, and `replace` directives.
fn parse_require_line(line: &str, content: &str, line_num: u32) -> Option<Dependency> {
    // Skip empty lines, comments, and replace directives
    if content.is_empty() || content.starts_with("//") || content.starts_with("replace") {
        return None;
    }

    // Check for indirect comment
    let is_indirect = content.contains("// indirect");

    // Remove inline comment (// indirect or other comments)
    let without_comment = match content.find("//") {
        Some(pos) => content[..pos].trim_end(),
        None => content,
    };

    // Split into module path and version using byte positions
    let bytes = without_comment.as_bytes();
    let mut space_pos = None;

    for (i, &b) in bytes.iter().enumerate() {
        if b == b' ' || b == b'\t' {
            space_pos = Some(i);
            break;
        }
    }

    let space_pos = space_pos?;

    let module_path = &without_comment[..space_pos];
    let version = without_comment[space_pos..].trim_start();

    // Validate version format (must start with 'v')
    if !version.starts_with('v') || version.contains(' ') {
        // If version contains spaces, it's not a valid single version
        let version = version.split_whitespace().next()?;
        if !version.starts_with('v') {
            return None;
        }
        // Use the first whitespace-delimited token as version
        return parse_require_with_positions(line, module_path, version, line_num, is_indirect);
    }

    parse_require_with_positions(line, module_path, version, line_num, is_indirect)
}

/// Resolves byte positions for `module_path` and `version` within `line` and
/// constructs the [`Dependency`].
fn parse_require_with_positions(
    line: &str,
    module_path: &str,
    version: &str,
    line_num: u32,
    is_indirect: bool,
) -> Option<Dependency> {
    // Find module path position (only need one search)
    let name_start = line.find(module_path)? as u32;
    let name_end = name_start + module_path.len() as u32;

    // Version follows the module path, search from after it
    let search_start = name_end as usize;
    let version_rel_start = line[search_start..].find(version)?;
    let version_start = (search_start + version_rel_start) as u32;
    let version_end = version_start + version.len() as u32;

    Some(Dependency {
        name: module_path.to_string(),
        version: version.to_string(),
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
        dev: false,
        optional: is_indirect,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_require() {
        let parser = GoParser::new();
        let content = r#"
module example.com/mymodule

go 1.21

require github.com/pkg/errors v0.9.1
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/pkg/errors");
        assert_eq!(deps[0].version, "v0.9.1");
        assert!(!deps[0].optional);
    }

    #[test]
    fn test_require_block() {
        let parser = GoParser::new();
        let content = r#"
module example.com/mymodule

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/text v0.14.0
)
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let gin = deps.iter().find(|d| d.name.contains("gin")).unwrap();
        assert_eq!(gin.version, "v1.9.1");

        let text = deps.iter().find(|d| d.name.contains("text")).unwrap();
        assert_eq!(text.version, "v0.14.0");
    }

    #[test]
    fn test_indirect_dependency() {
        let parser = GoParser::new();
        let content = r#"
require (
    github.com/direct/dep v1.0.0
    github.com/indirect/dep v2.0.0 // indirect
)
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let direct = deps.iter().find(|d| d.name.contains("direct")).unwrap();
        assert!(!direct.optional);

        let indirect = deps.iter().find(|d| d.name.contains("indirect")).unwrap();
        assert!(indirect.optional);
    }

    #[test]
    fn test_multiple_require_blocks() {
        let parser = GoParser::new();
        let content = r#"
require (
    github.com/pkg/a v1.0.0
)

require (
    github.com/pkg/b v2.0.0
)

require github.com/pkg/c v3.0.0
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn test_version_position() {
        let parser = GoParser::new();
        let content = "require github.com/pkg/errors v0.9.1";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);

        let dep = &deps[0];
        assert_eq!(dep.name_span.line, 0);
        assert_eq!(dep.name_span.line_start, 8);
        assert_eq!(dep.name_span.line_end, 29);
        assert_eq!(dep.version_span.line, 0);
        assert_eq!(dep.version_span.line_start, 30);
        assert_eq!(dep.version_span.line_end, 36);
    }

    #[test]
    fn test_skip_replace_directives() {
        let parser = GoParser::new();
        let content = r#"
require github.com/old/pkg v1.0.0

replace github.com/old/pkg => github.com/new/pkg v2.0.0
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/old/pkg");
    }

    #[test]
    fn test_empty_file() {
        let parser = GoParser::new();
        let content = "";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_require_block_with_comments() {
        let parser = GoParser::new();
        let content = r#"
require (
    // this is a comment
    github.com/pkg/errors v0.9.1
)
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
    }
}
