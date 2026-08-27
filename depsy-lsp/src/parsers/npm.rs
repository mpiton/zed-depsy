//! Parser for npm `package.json` files.
//!
//! Uses `json-spanned-value` to obtain dependency name/version spans directly
//! from the parser output, removing the need for a manual string scan.
//! This approach correctly handles packages whose name or version appears more
//! than once in the file (e.g. a package pinned to the same version in both
//! `dependencies` and `devDependencies`).
//!
//! The following sections are recognised:
//!
//! | JSON key | `dev` | `optional` |
//! |----------|-------|------------|
//! | `dependencies` | `false` | `false` |
//! | `devDependencies` | `true` | `false` |
//! | `peerDependencies` | `false` | `true` |
//! | `optionalDependencies` | `false` | `true` |
//!
//! Both plain string values (`"^1.0"`) and single-field object values
//! (`{ "version": "^1.0" }`) are supported as long as the `"version"` key
//! appears on the same line as the surrounding package-name key.

use json_spanned_value as jsv;
use json_spanned_value::spanned;

use super::json_spans::{LineIndex, string_inner_to_span};
use super::{Dependency, Parser, Span};

/// Parser for npm `package.json` dependency files.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::npm::NpmParser;
/// let parser = NpmParser::new();
/// let pkg = r#"{"dependencies": {"lodash": "^4.0.0"}}"#;
/// let deps = parser.parse(pkg);
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "lodash");
/// assert_eq!(deps[0].version, "^4.0.0");
/// ```
#[derive(Debug, Default)]
pub struct NpmParser;

impl NpmParser {
    /// Creates a new [`NpmParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for NpmParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        let Ok(root) = jsv::from_str::<spanned::Object>(content) else {
            return Vec::new();
        };

        let line_index = LineIndex::new(content);
        let mut dependencies = Vec::with_capacity(64);

        parse_section(
            &root,
            "dependencies",
            false,
            false,
            &line_index,
            &mut dependencies,
        );
        parse_section(
            &root,
            "devDependencies",
            true,
            false,
            &line_index,
            &mut dependencies,
        );
        parse_section(
            &root,
            "peerDependencies",
            false,
            true,
            &line_index,
            &mut dependencies,
        );
        parse_section(
            &root,
            "optionalDependencies",
            false,
            true,
            &line_index,
            &mut dependencies,
        );

        dependencies
    }
}

/// Looks up a section in the root object and appends each entry to `dependencies`.
///
/// Entries whose name and version spans fall on different lines are silently
/// skipped (multi-line object values that cannot be attributed to a single
/// source line are out of scope for quick-fix editing).
fn parse_section(
    root: &spanned::Object,
    section_name: &str,
    dev: bool,
    optional: bool,
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
        let Some(name_span) =
            string_inner_to_span(line_index, name_spanned.start(), name_spanned.end())
        else {
            continue;
        };

        let Some((version, version_span)) = extract_version(value_spanned, line_index) else {
            continue;
        };

        if name_span.line != version_span.line {
            continue;
        }

        dependencies.push(Dependency {
            name: name_spanned.get_ref().clone(),
            version,
            name_span,
            version_span,
            dev,
            optional,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        });
    }
}

/// Extract a version string and its inner-content span from a value that is
/// either a JSON string or an object containing `"version": <string>`.
///
/// For object values (e.g. `{ "version": "1.0.0", ... }`) the version's inner
/// span must lie on the same line as the surrounding key for the dependency
/// to register; multi-line nested forms are silently skipped.
fn extract_version(value: &spanned::Value, line_index: &LineIndex) -> Option<(String, Span)> {
    if let Some(s) = value.as_span_string() {
        let span = string_inner_to_span(line_index, s.start(), s.end())?;
        return Some((s.get_ref().to_string(), span));
    }
    if let Some(obj) = value.as_span_object() {
        let version_value = obj.get_ref().get("version")?;
        let version_str = version_value.as_span_string()?;
        let span = string_inner_to_span(line_index, version_str.start(), version_str.end())?;
        return Some((version_str.get_ref().to_string(), span));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_dependencies() {
        let parser = NpmParser::new();
        let content = r#"{
  "name": "my-app",
  "dependencies": {
    "react": "^18.2.0",
    "lodash": "4.17.21"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let react = deps.iter().find(|d| d.name == "react").unwrap();
        assert_eq!(react.version, "^18.2.0");
        assert!(!react.dev);

        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");
    }

    #[test]
    fn test_dev_dependencies() {
        let parser = NpmParser::new();
        let content = r#"{
  "devDependencies": {
    "typescript": "^5.0.0",
    "jest": "^29.0.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        for dep in &deps {
            assert!(dep.dev);
        }
    }

    #[test]
    fn test_multiple_sections() {
        let parser = NpmParser::new();
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express": "^4.18.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.0"
  },
  "peerDependencies": {
    "react": "^18.0.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 3);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert!(!express.dev);
        assert!(!express.optional);

        let nodemon = deps.iter().find(|d| d.name == "nodemon").unwrap();
        assert!(nodemon.dev);

        let react = deps.iter().find(|d| d.name == "react").unwrap();
        assert!(react.optional); // peer deps marked as optional
    }

    #[test]
    fn test_scoped_packages() {
        let parser = NpmParser::new();
        let content = r#"{
  "dependencies": {
    "@types/node": "^20.0.0",
    "@babel/core": "^7.22.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let types_node = deps.iter().find(|d| d.name == "@types/node").unwrap();
        assert_eq!(types_node.version, "^20.0.0");

        let babel = deps.iter().find(|d| d.name == "@babel/core").unwrap();
        assert_eq!(babel.version, "^7.22.0");
    }

    #[test]
    fn test_version_ranges() {
        let parser = NpmParser::new();
        let content = r#"{
  "dependencies": {
    "pkg1": "^1.0.0",
    "pkg2": "~2.0.0",
    "pkg3": ">=3.0.0 <4.0.0",
    "pkg4": "1.0.0 - 2.0.0",
    "pkg5": "*"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 5);

        assert_eq!(
            deps.iter().find(|d| d.name == "pkg1").unwrap().version,
            "^1.0.0"
        );
        assert_eq!(
            deps.iter().find(|d| d.name == "pkg3").unwrap().version,
            ">=3.0.0 <4.0.0"
        );
        assert_eq!(deps.iter().find(|d| d.name == "pkg5").unwrap().version, "*");
    }

    #[test]
    fn test_inline_format() {
        let parser = NpmParser::new();
        let content = r#"{"dependencies": {"pkg": "1.0.0"}}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "pkg");
        assert_eq!(deps[0].version, "1.0.0");
    }

    #[test]
    fn test_position_tracking() {
        let parser = NpmParser::new();
        let content = r#"{
  "dependencies": {
    "react": "^18.0.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);

        let react = &deps[0];
        assert_eq!(react.name, "react");
        assert_eq!(react.name_span.line, 2); // 0-indexed, so line 3 is index 2
        assert_eq!(react.version_span.line, 2); // 0-indexed, so line 3 is index 2
        // Verify positions are within reasonable bounds
        assert!(react.name_span.line_start < react.name_span.line_end);
        assert!(react.version_span.line_start < react.version_span.line_end);
    }

    #[test]
    fn test_optional_dependencies() {
        let parser = NpmParser::new();
        let content = r#"{
  "optionalDependencies": {
    "fsevents": "^2.3.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].optional);
        assert!(!deps[0].dev);
    }

    #[test]
    fn test_complex_version_object() {
        let parser = NpmParser::new();
        let content = r#"{
  "dependencies": {
    "simple": "1.0.0",
    "complex": { "version": "2.0.0" }
  }
}"#;
        let deps = parser.parse(content);
        // Both string versions and object versions with a "version" field are supported
        assert_eq!(deps.len(), 2);

        let simple = deps.iter().find(|d| d.name == "simple").unwrap();
        assert_eq!(simple.version, "1.0.0");

        let complex = deps.iter().find(|d| d.name == "complex").unwrap();
        assert_eq!(complex.version, "2.0.0");
    }

    #[test]
    fn test_empty_dependencies() {
        let parser = NpmParser::new();
        let content = r#"{
  "name": "my-app",
  "dependencies": {}
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_invalid_json() {
        let parser = NpmParser::new();
        let content = "not valid json";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_same_name_in_two_sections() {
        let parser = NpmParser::new();
        // Same name AND same version pinned in both sections — this is the
        // worst-case for the legacy string scan: the version-disambiguation
        // trick that handles distinct versions cannot disambiguate when both
        // versions match. Span-aware parsing must still place each entry on
        // its own line.
        let content = r#"{
  "dependencies": {
    "foo": "1.0.0"
  },
  "devDependencies": {
    "foo": "1.0.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);

        let prod = deps.iter().find(|d| !d.dev).unwrap();
        let dev = deps.iter().find(|d| d.dev).unwrap();
        assert_eq!(prod.version, "1.0.0");
        assert_eq!(dev.version, "1.0.0");
        // Spans must be on different lines (the bug we are fixing: string
        // search may match the same line for both).
        assert_ne!(prod.name_span.line, dev.name_span.line);
        assert_ne!(prod.version_span.line, dev.version_span.line);
        assert_eq!(prod.name_span.line, prod.version_span.line);
        assert_eq!(dev.name_span.line, dev.version_span.line);
    }

    #[test]
    fn test_substring_false_match_in_value() {
        // The "description" field contains a literal that looks like a
        // dependency entry. The parser must not pick it up as a dep.
        let parser = NpmParser::new();
        let content = r#"{
  "description": "looks like \"react\": \"99.0.0\" but is text",
  "dependencies": {
    "react": "1.0.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "1.0.0");
    }

    #[test]
    fn test_whitespace_variations() {
        let parser = NpmParser::new();
        let content =
            "{\n  \"dependencies\": {\n    \"a\":\t\t\"1.0.0\",\n    \"b\"  :   \"2.0.0\"\n  }\n}";
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 2);
        let a = deps.iter().find(|d| d.name == "a").unwrap();
        let b = deps.iter().find(|d| d.name == "b").unwrap();
        assert_eq!(a.version, "1.0.0");
        assert_eq!(b.version, "2.0.0");
        // Tab-separated entry: `    "a":\t\t"1.0.0",` — `a` at col 5, `1.0.0` at col 11.
        assert_eq!(a.name_span.line_start, 5);
        assert_eq!(a.name_span.line_end, 6);
        assert_eq!(a.version_span.line_start, 11);
        assert_eq!(a.version_span.line_end, 16);
        // Multi-space entry: `    "b"  :   "2.0.0"` — `b` at col 5, `2.0.0` at col 14.
        assert_eq!(b.name_span.line_start, 5);
        assert_eq!(b.name_span.line_end, 6);
        assert_eq!(b.version_span.line_start, 14);
        assert_eq!(b.version_span.line_end, 19);
    }

    #[test]
    fn test_large_file_smoke() {
        let mut content = String::from("{\n  \"dependencies\": {\n");
        for i in 0..1000 {
            let comma = if i == 999 { "" } else { "," };
            content.push_str(&format!("    \"pkg{i}\": \"1.0.{i}\"{comma}\n"));
        }
        content.push_str("  }\n}");
        let parser = NpmParser::new();
        let deps = parser.parse(&content);
        assert_eq!(deps.len(), 1000);
        // Position checks: each entry on its own line, monotonically increasing.
        let first = deps.iter().find(|d| d.name == "pkg0").unwrap();
        let last = deps.iter().find(|d| d.name == "pkg999").unwrap();
        assert_eq!(first.name_span.line, 2);
        assert_eq!(last.name_span.line, 1001);
    }

    #[test]
    fn test_multiline_object_value_skipped() {
        // A complex `{ "version": "..." }` form spread across multiple lines:
        // because the inner `"version"` literal sits on a different line than
        // the surrounding key, the same-line invariant skips the entry rather
        // than reporting an out-of-line span.
        let parser = NpmParser::new();
        let content = r#"{
  "dependencies": {
    "complex": {
      "version": "2.0.0"
    },
    "simple": "1.0.0"
  }
}"#;
        let deps = parser.parse(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "simple");
    }
}
