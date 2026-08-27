//! Parser for Ruby `Gemfile` files (Bundler format).
//!
//! Supports:
//! - `gem 'name', 'version'` and `gem "name", "version"` declarations.
//! - Parenthesised form: `gem('name', 'version')`.
//! - `group :development, :test do … end` blocks — gems inside `dev`/`test`
//!   groups are emitted with `dev = true`.
//!
//! Gems with non-string second arguments (e.g. `git:`, `path:` options) are
//! silently skipped.  Optimised for reduced allocations with a single byte scan
//! per token.

use super::{Dependency, Parser, Span};

/// Parser for Ruby `Gemfile` dependency files.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::ruby::RubyParser;
/// let parser = RubyParser::new();
/// let content = "gem 'rails', '~> 7.0'\n";
/// let deps = parser.parse(content);
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "rails");
/// assert_eq!(deps[0].version, "~> 7.0");
/// ```
#[derive(Debug, Default)]
pub struct RubyParser;

impl RubyParser {
    /// Creates a new [`RubyParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for RubyParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        // Pre-allocate with reasonable capacity
        let mut dependencies = Vec::with_capacity(32);
        let mut in_dev_group = false;
        let mut group_depth = 0;

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx as u32;
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Track group blocks for dev dependencies
            if trimmed.starts_with("group") {
                let is_dev = trimmed.contains(":development")
                    || trimmed.contains(":test")
                    || trimmed.contains("'development'")
                    || trimmed.contains("\"development\"")
                    || trimmed.contains("'test'")
                    || trimmed.contains("\"test\"");

                if trimmed.contains("do") {
                    group_depth += 1;
                    if is_dev {
                        in_dev_group = true;
                    }
                }
                continue;
            }

            // Track end of blocks
            if trimmed == "end" {
                if group_depth > 0 {
                    group_depth -= 1;
                    if group_depth == 0 {
                        in_dev_group = false;
                    }
                }
                continue;
            }

            // Parse gem declarations
            if let Some(dep) = parse_gem_declaration(line, line_num, in_dev_group) {
                dependencies.push(dep);
            }
        }

        dependencies
    }
}

/// Parses a `gem` declaration line and returns the corresponding [`Dependency`].
///
/// Single-line declarations only: the line must start (after trimming) with
/// the exact prefix `gem(` or `gem ` (one ASCII space). Variants such as
/// `gem ('name', ...)` (space before `(`) or `gem\t'name'` (tab after `gem`)
/// are not recognised. The argument list is then parsed by
/// [`parse_gem_args`] / [`parse_quoted_string`].
///
/// Returns `None` when the line does not match either prefix or has no
/// version string.
fn parse_gem_declaration(line: &str, line_num: u32, dev: bool) -> Option<Dependency> {
    let trimmed = line.trim();

    // Must start with 'gem'
    let after_gem = if let Some(rest) = trimmed.strip_prefix("gem(") {
        // Use strip_suffix to remove at most one trailing ')'
        rest.strip_suffix(')').unwrap_or(rest)
    } else {
        trimmed.strip_prefix("gem ")?
    };

    // Parse the arguments
    let parsed = parse_gem_args(line, after_gem)?;

    Some(Dependency {
        name: parsed.name,
        version: parsed.version,
        name_span: Span {
            line: line_num,
            line_start: parsed.name_start,
            line_end: parsed.name_end,
        },
        version_span: Span {
            line: line_num,
            line_start: parsed.version_start,
            line_end: parsed.version_end,
        },
        dev,
        optional: false,
        registry: None,
        resolved_version: None,
        has_additional_version_constraints: parsed.has_additional_version_constraints,
    })
}

struct ParsedGemArgs {
    name: String,
    version: String,
    name_start: u32,
    name_end: u32,
    version_start: u32,
    version_end: u32,
    has_additional_version_constraints: bool,
}

/// Parses the argument list of a `gem` declaration.
///
/// Both single-quoted and double-quoted strings are accepted.
/// Returns `None` when the second argument is absent, unquoted (e.g. a hash
/// key), or contains a colon (version-as-symbol form).
fn parse_gem_args(line: &str, args_str: &str) -> Option<ParsedGemArgs> {
    let bytes = args_str.as_bytes();
    let len = bytes.len();

    // Parse first argument (name)
    let (name, name_end_idx) = parse_quoted_string(bytes, 0)?;

    // Find comma after name
    let mut idx = name_end_idx;
    while idx < len && bytes[idx] != b',' {
        idx += 1;
    }
    if idx >= len {
        return None; // No version
    }
    idx += 1; // Skip comma

    // Skip whitespace
    while idx < len && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
        idx += 1;
    }
    if idx >= len {
        return None;
    }

    // Check if this looks like a hash option (contains : but not quoted)
    let next_byte = bytes[idx];
    if next_byte != b'\'' && next_byte != b'"' {
        // Not a quoted string, likely a hash option like git:
        return None;
    }

    // Parse second argument (version)
    let (version, version_end_idx) = parse_quoted_string(bytes, idx)?;

    // Skip if version looks like a hash key
    if version.is_empty() || version.contains(':') {
        return None;
    }

    // Find positions in the original line
    let (name_start, name_end) = find_quoted_position(line, &name)?;
    let (version_start, version_end) = find_quoted_position(line, &version)?;
    let has_additional_version_constraints = has_unproven_trailing_argument(bytes, version_end_idx);

    Some(ParsedGemArgs {
        name,
        version,
        name_start,
        name_end,
        version_start,
        version_end,
        has_additional_version_constraints,
    })
}

fn has_unproven_trailing_argument(bytes: &[u8], mut index: usize) -> bool {
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    if bytes.get(index) != Some(&b',') {
        return false;
    }
    index += 1;
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }

    let Some(tail) = bytes.get(index..) else {
        return true;
    };
    tail.is_empty() || !is_options_argument(tail)
}

fn is_options_argument(bytes: &[u8]) -> bool {
    let Ok(argument) = std::str::from_utf8(bytes) else {
        return false;
    };
    let argument = argument.trim_start();
    if argument.starts_with('{') {
        return true;
    }
    if let Some(symbol) = argument.strip_prefix(':') {
        let key_end = symbol
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(symbol.len());
        return key_end > 0 && symbol[key_end..].trim_start().starts_with("=>");
    }

    let key_end = argument
        .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .unwrap_or(argument.len());
    key_end > 0 && argument[key_end..].starts_with(':')
}

/// Parses a single- or double-quoted string from `bytes` starting at `start`.
///
/// Returns `(content, index_after_closing_quote)` on success, or `None`
/// when `bytes[start]` is not a quote character or the string is unterminated.
fn parse_quoted_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let len = bytes.len();
    let mut idx = start;

    // Skip whitespace
    while idx < len && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
        idx += 1;
    }
    if idx >= len {
        return None;
    }

    let quote = bytes[idx];
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    idx += 1;

    let string_start = idx;
    while idx < len && bytes[idx] != quote {
        idx += 1;
    }
    if idx >= len {
        return None;
    }

    let s = std::str::from_utf8(&bytes[string_start..idx]).ok()?;
    Some((s.to_string(), idx + 1))
}

/// Finds the byte position of `needle` within its surrounding quotes in `line`.
///
/// Tries single-quoted form first (`'needle'`), then double-quoted (`"needle"`),
/// then falls back to a direct substring search.  Returns `(start, end)` as
/// 0-indexed byte offsets covering the inner text (no quotes).
fn find_quoted_position(line: &str, needle: &str) -> Option<(u32, u32)> {
    // Look for the string within single quotes first (more common in Ruby)
    let single_quoted = format!("'{needle}'");
    if let Some(pos) = line.find(&single_quoted) {
        let start = (pos + 1) as u32;
        return Some((start, start + needle.len() as u32));
    }

    // Try double quotes
    let double_quoted = format!(r#""{needle}""#);
    if let Some(pos) = line.find(&double_quoted) {
        let start = (pos + 1) as u32;
        return Some((start, start + needle.len() as u32));
    }

    // Fallback to direct search
    let pos = line.find(needle)? as u32;
    Some((pos, pos + needle.len() as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_gem() {
        let parser = RubyParser::new();
        let content = r#"
source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'pg', '~> 1.4'
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "rails");
        assert_eq!(deps[0].version, "~> 7.0");
        assert!(!deps[0].dev);
        assert_eq!(deps[1].name, "pg");
        assert_eq!(deps[1].version, "~> 1.4");
    }

    #[test]
    fn test_gem_with_version_operators() {
        let parser = RubyParser::new();
        let content = r#"
gem 'devise', '>= 4.0'
gem 'rspec', '~> 3.0'
gem 'rails', '~> 7.0.0'
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "devise");
        assert_eq!(deps[0].version, ">= 4.0");
        assert_eq!(deps[1].name, "rspec");
        assert_eq!(deps[1].version, "~> 3.0");
        assert_eq!(deps[2].name, "rails");
        assert_eq!(deps[2].version, "~> 7.0.0");
    }

    #[test]
    fn test_dev_dependencies_in_group() {
        let parser = RubyParser::new();
        let content = r#"
source 'https://rubygems.org'

gem 'rails', '~> 7.0'

group :development, :test do
  gem 'rspec-rails', '~> 6.0'
  gem 'factory_bot_rails', '~> 6.2'
end

gem 'pg', '~> 1.4'
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 4);

        let rails = deps.iter().find(|d| d.name == "rails").unwrap();
        assert!(!rails.dev);

        let rspec = deps.iter().find(|d| d.name == "rspec-rails").unwrap();
        assert!(rspec.dev);

        let factory_bot = deps.iter().find(|d| d.name == "factory_bot_rails").unwrap();
        assert!(factory_bot.dev);

        let pg = deps.iter().find(|d| d.name == "pg").unwrap();
        assert!(!pg.dev);
    }

    #[test]
    fn test_skip_git_and_path_gems() {
        let parser = RubyParser::new();
        let content = r#"
gem 'rails', '~> 7.0'
gem 'my_gem', git: 'https://github.com/user/my_gem.git'
gem 'local_gem', path: '../local_gem'
gem 'pg', '~> 1.4'
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "rails");
        assert_eq!(deps[1].name, "pg");
    }

    #[test]
    fn test_skip_comments_and_empty_lines() {
        let parser = RubyParser::new();
        let content = r#"
# This is a comment
source 'https://rubygems.org'

# Another comment
gem 'rails', '~> 7.0'

# gem 'old_gem', '1.0'
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
    }

    #[test]
    fn test_gem_with_require_option() {
        let parser = RubyParser::new();
        let content = r#"
gem 'rails', '~> 7.0'
gem 'bootsnap', '~> 1.16', require: false
gem 'pg', '~> 1.4'
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "rails");
        assert_eq!(deps[1].name, "bootsnap");
        assert_eq!(deps[1].version, "~> 1.16");
        assert_eq!(deps[2].name, "pg");
    }

    #[test]
    fn test_double_quoted_gems() {
        let parser = RubyParser::new();
        let content = r#"
gem "rails", "~> 7.0"
gem "pg", "~> 1.4"
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "rails");
        assert_eq!(deps[0].version, "~> 7.0");
    }

    #[test]
    fn test_version_positions() {
        let parser = RubyParser::new();
        let content = "gem 'rails', '~> 7.0'\n";
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];

        // Verify positions are valid
        assert!(dep.name_span.line_start < dep.name_span.line_end);
        assert!(dep.version_span.line_start < dep.version_span.line_end);
        assert!(dep.name_span.line_end < dep.version_span.line_start);

        // Verify name position
        let name_slice =
            &content[dep.name_span.line_start as usize..dep.name_span.line_end as usize];
        assert_eq!(name_slice, "rails");

        // Verify version position
        let version_slice =
            &content[dep.version_span.line_start as usize..dep.version_span.line_end as usize];
        assert_eq!(version_slice, "~> 7.0");
    }

    #[test]
    fn test_exact_version() {
        let parser = RubyParser::new();
        let content = "gem 'nokogiri', '1.15.4'\n";
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "nokogiri");
        assert_eq!(deps[0].version, "1.15.4");
    }

    #[test]
    fn test_test_group() {
        let parser = RubyParser::new();
        let content = r#"
gem 'rails', '~> 7.0'

group :test do
  gem 'rspec', '~> 3.12'
end
"#;
        let deps = parser.parse(content);

        assert_eq!(deps.len(), 2);

        let rspec = deps.iter().find(|d| d.name == "rspec").unwrap();
        assert!(rspec.dev);
    }

    #[test]
    fn test_empty_file() {
        let parser = RubyParser::new();
        let content = "";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_parenthesized_gem() {
        let parser = RubyParser::new();
        let content = "gem('rails', '~> 7.0')";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
        assert_eq!(deps[0].version, "~> 7.0");
    }

    #[test]
    fn tracks_additional_positional_constraints_but_not_options() {
        let content = concat!(
            "gem \"single\", \">= 1\", require: false\n",
            "gem \"hash-option\", \">= 1\", { require: false }\n",
            "gem \"legacy-option\", \">= 1\", :require => false\n",
            "gem \"compound\", \">= 1\", \"< 2\"\n",
            "gem \"variable-bound\", \">= 1\", UPPER_BOUND\n",
            "gem(\"multiline-bound\", \">= 1\",\n",
            "  \"< 2\")\n"
        );
        let deps = RubyParser::new().parse(content);

        let single = deps.iter().find(|dep| dep.name == "single").unwrap();
        assert!(!single.has_additional_version_constraints);
        let hash_option = deps.iter().find(|dep| dep.name == "hash-option").unwrap();
        assert!(!hash_option.has_additional_version_constraints);
        let legacy_option = deps.iter().find(|dep| dep.name == "legacy-option").unwrap();
        assert!(!legacy_option.has_additional_version_constraints);

        let compound = deps.iter().find(|dep| dep.name == "compound").unwrap();
        assert_eq!(compound.version, ">= 1");
        assert!(compound.has_additional_version_constraints);
        let variable_bound = deps
            .iter()
            .find(|dep| dep.name == "variable-bound")
            .unwrap();
        assert!(variable_bound.has_additional_version_constraints);
        let multiline_bound = deps
            .iter()
            .find(|dep| dep.name == "multiline-bound")
            .unwrap();
        assert!(multiline_bound.has_additional_version_constraints);
    }
}
