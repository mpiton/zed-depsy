//! Maven (pom.xml) parser for Java projects.
//!
//! Parses direct dependencies declared in `pom.xml` files, including
//! `<dependencyManagement>`, with two passes:
//! 1. Collect `<properties>` for variable substitution (`${...}`).
//! 2. Extract dependencies and substitute property references.
//!
//! The dependency `name` uses the Maven convention `groupId:artifactId`
//! (matching OSV.dev and the mvnrepository.com URL scheme).
//!
//! Unsupported in this MVP (detected but not resolved):
//! - Parent POM inheritance
//! - BOM (`<scope>import</scope>`) resolution from remote POMs
//! - Plugin dependencies

use hashbrown::HashMap;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::parsers::{Dependency, Parser, Span};

/// Parser for Maven `pom.xml` files.
///
/// Performs two sequential passes over the XML:
/// 1. Collect `<properties>` for `${...}` substitution (`extract_properties`).
/// 2. Extract `<dependency>` blocks from `<dependencies>` and
///    `<dependencyManagement>`, substituting property references
///    (`extract_dependencies`).
///
/// The dependency `name` uses the Maven `groupId:artifactId` convention.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::Parser;
/// use depsy_lsp::parsers::maven::MavenParser;
/// let parser = MavenParser::new();
/// let pom = r#"<?xml version="1.0"?>
/// <project>
///   <dependencies>
///     <dependency>
///       <groupId>org.slf4j</groupId>
///       <artifactId>slf4j-api</artifactId>
///       <version>1.7.30</version>
///     </dependency>
///   </dependencies>
/// </project>"#;
/// let deps = parser.parse(pom);
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "org.slf4j:slf4j-api");
/// assert_eq!(deps[0].version, "1.7.30");
/// ```
#[derive(Debug, Default)]
pub struct MavenParser;

impl MavenParser {
    /// Creates a new [`MavenParser`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Parser for MavenParser {
    fn parse(&self, content: &str) -> Vec<Dependency> {
        let properties = extract_properties(content);
        extract_dependencies(content, &properties)
    }
}

/// Builds a sorted list of byte offsets where each new line begins.
///
/// The first element is always `0`.  Used as a lookup table by
/// [`offset_to_position`] to convert flat byte offsets into `(line, column)`
/// pairs without scanning from the start each time.
fn line_offsets(content: &str) -> Vec<usize> {
    let mut offsets = vec![0usize];
    for (i, b) in content.bytes().enumerate() {
        if b == b'\n' {
            offsets.push(i + 1);
        }
    }
    offsets
}

/// Converts a flat `byte_offset` to `(line, column)`, both 0-indexed.
///
/// Uses a binary search over the `offsets` table produced by [`line_offsets`].
///
/// **Precondition:** `offsets` must be non-empty and `byte_offset` must be a
/// valid index into the same buffer that produced `offsets` (i.e. `0 ..=
/// content.len()`). Out-of-bounds offsets are clamped via `saturating_sub` and
/// will return the last known line, but the resulting column is meaningless.
fn offset_to_position(offsets: &[usize], byte_offset: usize) -> (u32, u32) {
    let line_idx = match offsets.binary_search(&byte_offset) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    };
    let line_start = offsets[line_idx];
    let col = byte_offset.saturating_sub(line_start);
    (line_idx as u32, col as u32)
}

/// Pass 1: collect `<properties>` entries (name → value) from the pom.
///
/// Also captures the built-in placeholders `project.version`, `project.groupId`,
/// and `project.artifactId` from direct children of `<project>`, matching the
/// subset of Maven's built-in property resolution that the MVP supports.
fn extract_properties(content: &str) -> HashMap<String, String> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut out = HashMap::new();
    let mut depth_stack: Vec<String> = Vec::new();
    let mut current_key: Option<String> = None;

    loop {
        match reader.read_event() {
            Err(_) => return HashMap::new(),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = e.local_name().as_ref().to_string();
                let parent = depth_stack.last().map(String::as_str);
                // Properties map: project > properties > <key>
                if parent == Some("properties")
                    && depth_stack.len() >= 2
                    && depth_stack[depth_stack.len() - 2] == "project"
                {
                    current_key = Some(name.clone());
                }
                // Built-in project properties: project > (version|groupId|artifactId)
                if parent == Some("project")
                    && matches!(name.as_str(), "version" | "groupId" | "artifactId")
                {
                    current_key = Some(format!("project.{name}"));
                }
                depth_stack.push(name);
            }
            Ok(Event::Text(e)) => {
                if let Some(ref key) = current_key
                    && !out.contains_key(key)
                {
                    // First occurrence wins to avoid overwriting project.version
                    // with a nested <dependency><version>.
                    out.insert(key.clone(), e.to_string());
                }
            }
            Ok(Event::End(_)) => {
                depth_stack.pop();
                current_key = None;
            }
            _ => {}
        }
    }

    out
}

/// Pass 2: extract dependencies from `<dependencies>` and
/// `<dependencyManagement><dependencies>`, substituting `${property}` placeholders.
fn extract_dependencies(content: &str, properties: &HashMap<String, String>) -> Vec<Dependency> {
    // Keep raw text (no trim) so that byte offsets reported by the reader match
    // positions in the original source. We trim manually where needed.
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(false);

    let offsets = line_offsets(content);
    let bytes = content.as_bytes();
    let mut out = Vec::new();

    // State: track which element we're inside.
    let mut in_dependencies = false;
    let mut in_dep_mgmt = false;
    let mut in_plugins = false;
    let mut in_dependency = false;
    let mut has_parent = false;
    let mut current_tag: Option<String> = None;

    // Current dependency accumulator
    let mut cur_group: Option<String> = None;
    let mut cur_artifact: Option<String> = None;
    let mut cur_artifact_span: Option<(usize, usize)> = None;
    let mut cur_version: Option<String> = None;
    let mut cur_version_span: Option<(usize, usize)> = None;
    let mut cur_scope: Option<String> = None;
    let mut cur_optional = false;

    loop {
        match reader.read_event() {
            Err(_) => return vec![], // invalid XML → empty result
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = e.local_name().as_ref().to_string();
                match name.as_str() {
                    "dependencies" if !in_plugins => in_dependencies = true,
                    "dependencyManagement" => in_dep_mgmt = true,
                    "plugins" | "pluginManagement" => in_plugins = true,
                    "parent" => has_parent = true,
                    "dependency" if (in_dependencies || in_dep_mgmt) && !in_plugins => {
                        in_dependency = true;
                        cur_group = None;
                        cur_artifact = None;
                        cur_artifact_span = None;
                        cur_version = None;
                        cur_version_span = None;
                        cur_scope = None;
                        cur_optional = false;
                    }
                    _ => {}
                }
                current_tag = Some(name);
            }
            Ok(Event::End(e)) => {
                let name = e.local_name().as_ref().to_string();
                match name.as_str() {
                    "dependencies" => in_dependencies = false,
                    "dependencyManagement" => in_dep_mgmt = false,
                    "plugins" | "pluginManagement" => in_plugins = false,
                    "dependency" if in_dependency => {
                        in_dependency = false;
                        let g_opt = cur_group.take();
                        let a_opt = cur_artifact.take();
                        let raw_version = cur_version.take().unwrap_or_default();
                        let scope = cur_scope.take().unwrap_or_default();
                        let optional = cur_optional;
                        let artifact_span = cur_artifact_span.take();
                        let version_span_raw = cur_version_span.take();

                        // Skip dependencies that lack a `<version>` (typically inherited
                        // from a parent POM's `<dependencyManagement>`, which the MVP
                        // doesn't resolve) — emitting them with empty positions would
                        // surface diagnostics on line 0.
                        if let (Some(g), Some(a), Some((vs, ve))) = (g_opt, a_opt, version_span_raw)
                            && !g.is_empty()
                            && !a.is_empty()
                        {
                            let dev = scope == "test" || scope == "provided";
                            let resolved = substitute(&raw_version, properties);

                            // Preserve property placeholders (`${prop}`) verbatim in
                            // `version` so the code-action layer can detect them and skip
                            // the "update version" quick-fix — replacing the placeholder
                            // text with a literal would silently break the property
                            // indirection for every other artifact sharing the same
                            // property. The substituted value is cached in
                            // `resolved_version` for hover and registry comparisons via
                            // `Dependency::effective_version()`.
                            let (version, resolved_version) =
                                if raw_version != resolved && !resolved.contains("${") {
                                    (raw_version, Some(resolved))
                                } else {
                                    (resolved, None)
                                };

                            let (line, line_start) = offset_to_position(&offsets, vs);
                            let (_, line_end) = offset_to_position(&offsets, ve);
                            let version_span = Span {
                                line,
                                line_start,
                                line_end,
                            };

                            let name_span = match artifact_span {
                                Some((s, e_)) => {
                                    let (line, line_start) = offset_to_position(&offsets, s);
                                    let (_, line_end) = offset_to_position(&offsets, e_);
                                    Span {
                                        line,
                                        line_start,
                                        line_end,
                                    }
                                }
                                None => Span {
                                    line: 0,
                                    line_start: 0,
                                    line_end: 0,
                                },
                            };

                            out.push(Dependency {
                                name: format!("{g}:{a}"),
                                version,
                                name_span,
                                version_span,
                                dev,
                                optional,
                                registry: None,
                                resolved_version,
                                has_additional_version_constraints: false,
                            });
                        }
                    }
                    _ => {}
                }
                current_tag = None;
            }
            Ok(Event::Text(e)) if in_dependency => {
                let raw = e.to_string();
                let text = raw.trim().to_string();
                match current_tag.as_deref() {
                    Some("groupId") => cur_group = Some(text),
                    Some("artifactId") => {
                        let (s, e_) = trimmed_span(bytes, &reader, raw.len());
                        cur_artifact_span = Some((s, e_));
                        cur_artifact = Some(text);
                    }
                    Some("version") => {
                        let (s, e_) = trimmed_span(bytes, &reader, raw.len());
                        cur_version_span = Some((s, e_));
                        cur_version = Some(text);
                    }
                    Some("scope") => cur_scope = Some(text),
                    Some("optional") => cur_optional = text == "true",
                    _ => {}
                }
            }
            _ => {}
        }
    }

    if has_parent {
        tracing::debug!(
            "pom.xml has <parent> block — parent POM resolution is not supported in this MVP; \
             versions inherited from the parent will appear unresolved"
        );
    }
    out
}

/// Given the raw buffer position after a `Text` event and the raw text length,
/// return the byte span of the trimmed content (leading + trailing whitespace removed).
fn trimmed_span(bytes: &[u8], reader: &Reader<&[u8]>, raw_len: usize) -> (usize, usize) {
    let raw_end = reader.buffer_position() as usize;
    let raw_start = raw_end.saturating_sub(raw_len);
    let mut start = raw_start.min(bytes.len());
    let mut end = raw_end.min(bytes.len());
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

/// Substitute `${property}` placeholders in a version string with values from `properties`.
/// Unresolved placeholders are preserved verbatim.
///
/// Resolves nested references like `<revision>${project.version}</revision>` by
/// re-running substitution until the result stabilises. Bounded at 8 iterations
/// to bail out safely on circular references (`${a}=${b}`, `${b}=${a}`).
fn substitute(raw: &str, properties: &HashMap<String, String>) -> String {
    if !raw.contains("${") || properties.is_empty() {
        return raw.to_string();
    }
    let mut current = raw.to_string();
    for _ in 0..8 {
        let next = substitute_once(&current, properties);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

/// Single pass of placeholder resolution. Caller iterates to fixed point.
fn substitute_once(raw: &str, properties: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            let key = &after[..end];
            match properties.get(key) {
                Some(v) => out.push_str(v),
                None => {
                    // Preserve the original `${key}` placeholder.
                    out.push_str("${");
                    out.push_str(key);
                    out.push('}');
                }
            }
            rest = &after[end + 1..];
        } else {
            // Unterminated `${`; bail out as literal.
            out.push_str("${");
            out.push_str(after);
            return out;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_dependency() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>1.7.30</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1, "should parse one dependency");
        assert_eq!(deps[0].name, "org.slf4j:slf4j-api");
        assert_eq!(deps[0].version, "1.7.30");
        assert!(!deps[0].dev);
        assert!(!deps[0].optional);
    }

    #[test]
    fn test_parse_with_properties() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <properties>
        <spring.version>6.1.0</spring.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${spring.version}</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        // `version` keeps the source placeholder so the code-action layer can skip
        // the "update version" quick-fix; the resolved value is exposed via
        // `effective_version()` for hover and registry comparisons.
        assert_eq!(deps[0].version, "${spring.version}");
        assert_eq!(deps[0].resolved_version.as_deref(), Some("6.1.0"));
        assert_eq!(deps[0].effective_version(), "6.1.0");
    }

    #[test]
    fn test_parse_nested_properties_resolved() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <properties>
        <revision>${spring.version}</revision>
        <spring.version>6.1.0</spring.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${revision}</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].effective_version(), "6.1.0");
    }

    #[test]
    fn test_parse_dependency_without_version_is_skipped() {
        // Dependencies omitting <version> typically inherit from a parent POM's
        // <dependencyManagement>; the MVP does not resolve parents, so emitting
        // them with empty positions would surface diagnostics on line 0.
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_unresolved_property_preserved() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>g</groupId>
            <artifactId>a</artifactId>
            <version>${not.defined}</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "${not.defined}");
    }

    #[test]
    fn test_parse_scope_test_marked_as_dev() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].dev);
    }

    #[test]
    fn test_parse_scope_provided_marked_as_dev() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>servlet-api</artifactId>
            <version>2.5</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].dev);
    }

    #[test]
    fn test_parse_optional() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>g</groupId>
            <artifactId>a</artifactId>
            <version>1.0</version>
            <optional>true</optional>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].optional);
    }

    #[test]
    fn test_parse_snapshot_version() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>g</groupId>
            <artifactId>a</artifactId>
            <version>2.0-SNAPSHOT</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "2.0-SNAPSHOT");
    }

    #[test]
    fn test_parse_dependency_management() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>g</groupId>
                <artifactId>a</artifactId>
                <version>3.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1, "depMgmt deps with versions should be parsed");
        assert_eq!(deps[0].version, "3.0");
    }

    #[test]
    fn test_parse_plugin_dependencies_ignored() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <dependencies>
                    <dependency>
                        <groupId>ignored</groupId>
                        <artifactId>ignored</artifactId>
                        <version>0.1</version>
                    </dependency>
                </dependencies>
            </plugin>
        </plugins>
    </build>
    <dependencies>
        <dependency>
            <groupId>g</groupId>
            <artifactId>a</artifactId>
            <version>1.0</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        // Only the top-level <dependencies>/<dependency> should be captured.
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "g:a");
    }

    #[test]
    fn test_parse_invalid_xml_returns_empty() {
        let parser = MavenParser::new();
        let bad = "<project><dependencies><dependency>";
        let deps = parser.parse(bad);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_position_tracking() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>g</groupId>
            <artifactId>a</artifactId>
            <version>1.2.3</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        // The version line should be zero-indexed; the exact line varies with the raw string,
        // so we just sanity-check it is non-zero and the span is reasonable.
        assert!(
            deps[0].version_span.line > 0,
            "line should be tracked (got {})",
            deps[0].version_span.line
        );
        assert!(
            deps[0].version_span.line_end > deps[0].version_span.line_start,
            "version span should be non-empty"
        );
    }

    #[test]
    fn test_parse_default_namespace() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>1.7.30</version>
        </dependency>
    </dependencies>
</project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1, "default xmlns should parse one dependency");
        assert_eq!(deps[0].name, "org.slf4j:slf4j-api");
        assert_eq!(deps[0].version, "1.7.30");
    }

    #[test]
    fn test_parse_prefixed_namespace() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<m:project xmlns:m="http://maven.apache.org/POM/4.0.0">
    <m:modelVersion>4.0.0</m:modelVersion>
    <m:groupId>com.example</m:groupId>
    <m:artifactId>app</m:artifactId>
    <m:version>1.0.0</m:version>
    <m:dependencies>
        <m:dependency>
            <m:groupId>org.slf4j</m:groupId>
            <m:artifactId>slf4j-api</m:artifactId>
            <m:version>1.7.30</m:version>
        </m:dependency>
    </m:dependencies>
</m:project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(
            deps.len(),
            1,
            "prefixed namespace should parse one dependency"
        );
        assert_eq!(deps[0].name, "org.slf4j:slf4j-api");
        assert_eq!(deps[0].version, "1.7.30");
    }

    #[test]
    fn test_parse_prefixed_namespace_with_property_substitution() {
        let parser = MavenParser::new();
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<m:project xmlns:m="http://maven.apache.org/POM/4.0.0">
    <m:modelVersion>4.0.0</m:modelVersion>
    <m:properties>
        <m:slf4j.version>1.7.30</m:slf4j.version>
    </m:properties>
    <m:dependencies>
        <m:dependency>
            <m:groupId>org.slf4j</m:groupId>
            <m:artifactId>slf4j-api</m:artifactId>
            <m:version>${slf4j.version}</m:version>
        </m:dependency>
    </m:dependencies>
</m:project>
"#;
        let deps = parser.parse(pom);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "${slf4j.version}");
        assert_eq!(
            deps[0].resolved_version.as_deref(),
            Some("1.7.30"),
            "property substitution should work under prefixed namespace"
        );
    }
}
