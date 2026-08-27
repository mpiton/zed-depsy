//! Parser for PHP Composer files (`composer.json`).
//!
//! Uses `json-spanned-value` for span tracking; the PHP-specific filter rules
//! (skip `php` and `ext-*` keys) are applied before any work is done with the
//! span info.
//!
//! The following sections are recognised:
//!
//! | JSON key | `dev` |
//! |----------|-------|
//! | `require` | `false` |
//! | `require-dev` | `true` |
//!
//! Platform requirements (`"php"` key and any key starting with `"ext-"`) are
//! silently ignored as they do not correspond to Packagist packages.

use json_spanned_value as jsv;
use json_spanned_value::spanned;

use super::json_spans::{LineIndex, string_inner_to_span};
use super::{Dependency, Parser};

/// Parser for PHP `composer.json` dependency files.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::php::PhpParser;
/// let parser = PhpParser::new();
/// let content = r#"{"require": {"laravel/framework": "^10.0"}}"#;
/// let deps = parser.parse(content);
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "laravel/framework");
/// assert_eq!(deps[0].version, "^10.0");
/// ```
#[derive(Debug, Default)]
pub struct PhpParser;

impl PhpParser {
    /// Creates a new [`PhpParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for PhpParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        let Ok(root) = jsv::from_str::<spanned::Object>(content) else {
            return Vec::new();
        };

        let line_index = LineIndex::new(content);
        let mut dependencies = Vec::with_capacity(32);

        parse_section(&root, "require", false, &line_index, &mut dependencies);
        parse_section(&root, "require-dev", true, &line_index, &mut dependencies);

        dependencies
    }
}

/// Looks up `section_name` in `root` and appends each entry to `dependencies`.
///
/// Keys equal to `"php"` or starting with `"ext-"` are skipped.
/// Entries whose version is not a JSON string are skipped.
/// Entries whose name and version spans fall on different lines are also skipped.
fn parse_section(
    root: &spanned::Object,
    section_name: &str,
    dev: bool,
    line_index: &LineIndex,
    dependencies: &mut Vec<Dependency>,
) {
    let Some(section_value) = root.get_ref().get(section_name) else {
        return;
    };
    let Some(section_obj) = section_value.as_span_object() else {
        return;
    };

    for (name_spanned, value_spanned) in section_obj.get_ref().iter() {
        let name = name_spanned.get_ref();
        if name == "php" || name.starts_with("ext-") {
            continue;
        }

        let Some(version_spanned) = value_spanned.as_span_string() else {
            continue;
        };

        let Some(name_span) =
            string_inner_to_span(line_index, name_spanned.start(), name_spanned.end())
        else {
            continue;
        };
        let Some(version_span) =
            string_inner_to_span(line_index, version_spanned.start(), version_spanned.end())
        else {
            continue;
        };
        if name_span.line != version_span.line {
            continue;
        }

        dependencies.push(Dependency {
            name: name.clone(),
            version: version_spanned.get_ref().to_string(),
            name_span,
            version_span,
            dev,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_dependencies() {
        let parser = PhpParser::new();
        let content = r#"
{
    "name": "myproject",
    "require": {
        "php": ">=8.1",
        "laravel/framework": "^10.0",
        "guzzlehttp/guzzle": "^7.0"
    }
}
"#;
        let deps = parser.parse(content);
        // Should have laravel and guzzle, not php
        assert_eq!(deps.len(), 2);

        let laravel = deps.iter().find(|d| d.name.contains("laravel")).unwrap();
        assert_eq!(laravel.version, "^10.0");
        assert!(!laravel.dev);
    }

    #[test]
    fn test_dev_dependencies() {
        let parser = PhpParser::new();
        let content = r#"
{
    "require": {
        "laravel/framework": "^10.0"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.0",
        "mockery/mockery": "^1.5"
    }
}
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3);

        let laravel = deps.iter().find(|d| d.name.contains("laravel")).unwrap();
        assert!(!laravel.dev);

        let phpunit = deps.iter().find(|d| d.name.contains("phpunit")).unwrap();
        assert!(phpunit.dev);

        let mockery = deps.iter().find(|d| d.name.contains("mockery")).unwrap();
        assert!(mockery.dev);
    }

    #[test]
    fn test_skip_extensions() {
        let parser = PhpParser::new();
        let content = r#"
{
    "require": {
        "php": ">=8.1",
        "ext-json": "*",
        "ext-mbstring": "*",
        "laravel/framework": "^10.0"
    }
}
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "laravel/framework");
    }

    #[test]
    fn test_version_constraints() {
        let parser = PhpParser::new();
        let content = r#"
{
    "require": {
        "vendor/exact": "1.0.0",
        "vendor/caret": "^1.0",
        "vendor/tilde": "~1.0",
        "vendor/range": ">=1.0 <2.0"
    }
}
"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 4);

        let exact = deps.iter().find(|d| d.name.contains("exact")).unwrap();
        assert_eq!(exact.version, "1.0.0");

        let caret = deps.iter().find(|d| d.name.contains("caret")).unwrap();
        assert_eq!(caret.version, "^1.0");
    }

    #[test]
    fn test_version_position() {
        let parser = PhpParser::new();
        let content = r#"{
    "require": {
        "vendor/pkg": "^1.0.0"
    }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);

        let dep = &deps[0];
        assert_eq!(dep.name, "vendor/pkg");
        assert_eq!(dep.version, "^1.0.0");
    }

    #[test]
    fn test_empty_require() {
        let parser = PhpParser::new();
        let content = r#"{
    "require": {}
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_invalid_json() {
        let parser = PhpParser::new();
        let content = "not valid json";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_inline_format() {
        let parser = PhpParser::new();
        let content = r#"{"require": {"vendor/pkg": "1.0.0"}}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "vendor/pkg");
        assert_eq!(deps[0].version, "1.0.0");
    }

    #[test]
    fn test_same_name_in_require_and_require_dev() {
        let parser = PhpParser::new();
        // Same name AND same version pinned in both sections — worst case
        // for the legacy string scan: version-based disambiguation cannot
        // tell the two entries apart when both versions match. Span-aware
        // parsing must still place each entry on its own line.
        let content = r#"{
  "require": {
    "vendor/foo": "1.0.0"
  },
  "require-dev": {
    "vendor/foo": "1.0.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let prod = deps.iter().find(|d| !d.dev).unwrap();
        let dev = deps.iter().find(|d| d.dev).unwrap();
        assert_eq!(prod.version, "1.0.0");
        assert_eq!(dev.version, "1.0.0");
        assert_ne!(prod.name_span.line, dev.name_span.line);
        assert_ne!(prod.version_span.line, dev.version_span.line);
        assert_eq!(prod.name_span.line, prod.version_span.line);
        assert_eq!(dev.name_span.line, dev.version_span.line);
    }

    #[test]
    fn test_substring_false_match_in_value() {
        let parser = PhpParser::new();
        let content = r#"{
  "description": "contains \"vendor/fake\": \"99.0\" inside a string",
  "require": {
    "vendor/real": "^1.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "vendor/real");
    }

    #[test]
    fn test_skip_php_and_ext_when_duplicates_present() {
        let parser = PhpParser::new();
        let content = r#"{
  "require": {
    "php": ">=8.1",
    "ext-json": "*",
    "ext-mbstring": "*",
    "vendor/lib": "^1.0"
  },
  "require-dev": {
    "php": ">=8.1",
    "ext-json": "*",
    "vendor/dev": "^1.0"
  }
}"#;
        let deps = parser.parse(content);
        // Only the two real packages, not php or ext-* in either section.
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "vendor/lib" && !d.dev));
        assert!(deps.iter().any(|d| d.name == "vendor/dev" && d.dev));
    }
}
