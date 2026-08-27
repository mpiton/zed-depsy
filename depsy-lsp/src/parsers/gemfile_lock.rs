//! Parser for Ruby lockfiles (Gemfile.lock) — resolves exact locked versions for Ruby gems.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hashbrown::HashMap;

use crate::parsers::lockfile_graph::LockfileGraph;
use crate::parsers::lockfile_resolver::LockfileResolver;

/// Platform architecture keywords used to detect platform suffixes in gem versions.
const PLATFORM_KEYWORDS: &[&str] = &[
    "x86_64",
    "x86",
    "arm64",
    "aarch64",
    "darwin",
    "linux",
    "mingw",
    "mswin",
    "java",
    "jruby",
    "universal",
];

/// Strip platform suffix from a gem version string.
///
/// RubyGems platform-specific gems append a platform suffix separated by `-`,
/// e.g. `1.15.4-x86_64-linux`. The actual version is the part before the first `-`
/// that is followed by a platform keyword.
///
/// Pre-release Ruby versions use dots, not hyphens (e.g. `1.0.0.pre.1`), so they
/// are returned unchanged.
fn strip_platform_suffix(version: &str) -> &str {
    if let Some(dash_pos) = version.find('-') {
        let after_dash = &version[dash_pos + 1..];
        // Check if the part after the first dash looks like a platform suffix
        let is_platform = PLATFORM_KEYWORDS.iter().any(|kw| {
            after_dash.starts_with(kw)
                && after_dash[kw.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| c == '-' || c.is_ascii_digit())
        });
        if is_platform {
            return &version[..dash_pos];
        }
    }
    version
}

/// Normalize a Ruby gem name to lowercase for case-insensitive matching.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::gemfile_lock::normalize_gem_name;
/// assert_eq!(normalize_gem_name("ActiveRecord"), "activerecord");
/// assert_eq!(normalize_gem_name("rails"), "rails");
/// ```
pub fn normalize_gem_name(name: &str) -> String {
    name.to_lowercase()
}

/// Parse a `Gemfile.lock` file and return a map of gem name → resolved version.
///
/// Only `GEM` (registry) sections are resolved. `PATH` and `GIT` sourced
/// gems are intentionally excluded — they are also skipped by the Gemfile
/// manifest parser and do not need version resolution against a registry.
///
/// Extracts versions from the `GEM specs:` section where each gem appears as
/// `    gem_name (VERSION)` with exactly 4 spaces of indentation.
///
/// Gem names are stored in lowercase for case-insensitive matching.
/// Platform suffixes (e.g., `-x86_64-linux`) are stripped from versions.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::gemfile_lock::parse_gemfile_lock;
///
/// let lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n\nPLATFORMS\n  ruby\n";
/// let map = parse_gemfile_lock(lock);
/// assert_eq!(map.get("rails").map(String::as_str), Some("7.0.4"));
/// ```
pub fn parse_gemfile_lock(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    #[derive(PartialEq)]
    enum State {
        Searching,
        InGem,
        InSpecs,
    }

    let mut state = State::Searching;

    for line in content.lines() {
        match state {
            State::Searching => {
                if line == "GEM" {
                    state = State::InGem;
                }
            }
            State::InGem => {
                if line == "  specs:" {
                    state = State::InSpecs;
                } else if !line.starts_with(' ') && !line.is_empty() {
                    // New top-level section, not in GEM anymore
                    state = State::Searching;
                    // Re-check if this is another GEM section
                    if line == "GEM" {
                        state = State::InGem;
                    }
                }
            }
            State::InSpecs => {
                // A new top-level section (no leading spaces) ends the specs block
                if !line.is_empty() && !line.starts_with(' ') {
                    state = State::Searching;
                    if line == "GEM" {
                        state = State::InGem;
                    }
                    continue;
                }

                // Count leading spaces to determine indentation level
                let leading_spaces = line.len() - line.trim_start().len();

                // Exactly 4 spaces = direct gem entry
                if leading_spaces == 4 {
                    let trimmed = line.trim();
                    if let Some((name, rest)) = trimmed.split_once(' ') {
                        // rest should be like "(1.2.3)" or "(1.2.3-x86_64-linux)"
                        if rest.starts_with('(') && rest.ends_with(')') {
                            let raw_version = &rest[1..rest.len() - 1];
                            let version = strip_platform_suffix(raw_version).to_string();
                            let key = normalize_gem_name(name);

                            #[expect(
                                clippy::disallowed_methods,
                                reason = "`key` is an owned String; `entry_ref` would still allocate on insert"
                            )]
                            map.entry(key).or_insert(version);
                        }
                    }
                }
                // Lines with 6+ spaces are sub-dependencies — skip them
            }
        }
    }

    map
}

use crate::parsers::lockfile_graph::LockfilePackage;

#[derive(PartialEq)]
enum GemSection {
    None,
    Gem,
    Other,
}

/// Parse Gemfile.lock into a dependency graph.
/// Only the GEM section (RubyGems.org) is included. PATH and GIT sections are excluded.
/// The GEM/specs section uses 4-space indent for top-level gems (name + version)
/// and 6-space indent for their dependency list (name + constraint).
pub fn parse_gemfile_lock_graph(content: &str) -> LockfileGraph {
    let mut graph = LockfileGraph::default();
    let mut section = GemSection::None;
    let mut in_specs = false;
    let mut current: Option<LockfilePackage> = None;

    for line in content.lines() {
        let trimmed = line.trim_end();

        // Section headers are at column 0 (no leading spaces, non-empty)
        if !trimmed.is_empty() && !trimmed.starts_with(' ') {
            if let Some(done) = current.take() {
                graph.packages.push(done);
            }
            section = match trimmed.trim() {
                "GEM" => GemSection::Gem,
                _ => GemSection::Other,
            };
            in_specs = false;
            continue;
        }

        if section != GemSection::Gem {
            continue;
        }

        if trimmed.trim() == "specs:" {
            in_specs = true;
            continue;
        }

        if !in_specs {
            continue;
        }

        if trimmed.is_empty() || !trimmed.starts_with("    ") {
            if let Some(done) = current.take() {
                graph.packages.push(done);
            }
            if !trimmed.starts_with("    ") {
                in_specs = false;
            }
            continue;
        }

        // Level-1 gem: "    name (version)"
        if trimmed.starts_with("    ") && !trimmed.starts_with("      ") {
            if let Some(done) = current.take() {
                graph.packages.push(done);
            }
            let s = trimmed.trim();
            if let Some((name, rest)) = s.split_once(' ') {
                let raw_version = rest.trim().trim_matches(|c| c == '(' || c == ')');
                let version = strip_platform_suffix(raw_version).to_string();
                current = Some(LockfilePackage {
                    name: normalize_gem_name(name),
                    version,
                    dependencies: Vec::new(),
                    is_root: false,
                });
            }
        } else if let Some(cur) = current.as_mut() {
            // Level-2 sub-dep: "      name (constraint)"
            let s = trimmed.trim();
            let dep_name = s.split_whitespace().next().unwrap_or("");
            if !dep_name.is_empty() {
                cur.dependencies.push(normalize_gem_name(dep_name));
            }
        }
    }

    if let Some(done) = current {
        graph.packages.push(done);
    }
    graph
}

/// Find the Gemfile.lock file co-located with a Gemfile.
///
/// Bundler always places Gemfile.lock in the same directory as Gemfile,
/// so we only check the immediate directory — no upward traversal needed.
pub async fn find_gemfile_lock(gemfile_path: &Path) -> Option<PathBuf> {
    let candidate = gemfile_path.parent()?.join("Gemfile.lock");
    if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
        Some(candidate)
    } else {
        None
    }
}

/// Resolves versions from `Gemfile.lock` for Ruby projects.
/// RubyGems normalizes gem names to lowercase via `normalize_gem_name`.
/// `parse_gemfile_lock_graph` already normalizes names internally, so the default
/// `resolve_version` (first-wins by normalized name) works without override.
pub struct RubyResolver;

#[async_trait]
impl LockfileResolver for RubyResolver {
    async fn find_lockfile(&self, manifest_path: &Path) -> Option<PathBuf> {
        find_gemfile_lock(manifest_path).await
    }

    fn parse_graph(&self, lock_content: &str) -> LockfileGraph {
        parse_gemfile_lock_graph(lock_content)
    }

    fn normalize_name(&self, name: &str) -> String {
        normalize_gem_name(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.3.1)
      actioncable (= 7.0.3.1)
    nokogiri (1.15.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0.3)

BUNDLED WITH
  2.3.14
";
        let map = parse_gemfile_lock(content);
        assert_eq!(map.get("rails").map(|s| s.as_str()), Some("7.0.3.1"));
        assert_eq!(map.get("nokogiri").map(|s| s.as_str()), Some("1.15.4"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_empty() {
        let map = parse_gemfile_lock("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_skips_sub_dependencies() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.3.1)
      actionpack (= 7.0.3.1)
      activesupport (= 7.0.3.1)
    rails (7.0.3.1)
      actioncable (= 7.0.3.1)
";
        let map = parse_gemfile_lock(content);
        // Only direct gems (4-space indent) should be included
        assert!(map.contains_key("actioncable"));
        assert!(map.contains_key("rails"));
        // Sub-dependencies like "actionpack" should NOT appear as top-level entries
        assert!(!map.contains_key("actionpack"));
        assert!(!map.contains_key("activesupport"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_multiple_gem_remotes() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.3.1)

GEM
  remote: https://my.private.registry/
  specs:
    my_gem (1.0.0)

PLATFORMS
  ruby
";
        let map = parse_gemfile_lock(content);
        assert_eq!(map.get("rails").map(|s| s.as_str()), Some("7.0.3.1"));
        assert_eq!(map.get("my_gem").map(|s| s.as_str()), Some("1.0.0"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_platform_gem() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-x86_64-linux)
    grpc (1.59.0-x86_64-linux)
";
        let map = parse_gemfile_lock(content);
        assert_eq!(map.get("nokogiri").map(|s| s.as_str()), Some("1.15.4"));
        assert_eq!(map.get("grpc").map(|s| s.as_str()), Some("1.59.0"));
    }

    #[test]
    fn test_parse_stops_at_platforms() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.3.1)

PLATFORMS
  x86_64-linux
  ruby

DEPENDENCIES
  rails (~> 7.0.3)
";
        let map = parse_gemfile_lock(content);
        // Should not accidentally parse PLATFORMS section content as gems
        assert!(map.contains_key("rails"));
        assert!(!map.contains_key("x86_64-linux"));
        assert!(!map.contains_key("ruby"));
    }

    #[test]
    fn test_parse_case_insensitive_names() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    ActiveRecord (7.0.3.1)
    JSON (2.6.3)
";
        let map = parse_gemfile_lock(content);
        // Names stored in lowercase
        assert!(map.contains_key("activerecord"));
        assert!(map.contains_key("json"));
        assert!(!map.contains_key("ActiveRecord"));
        assert!(!map.contains_key("JSON"));
    }

    #[test]
    fn test_parse_prerelease_version() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    my_gem (1.0.0.pre.1)
    another_gem (2.0.0.beta.2)
";
        let map = parse_gemfile_lock(content);
        // Pre-release versions use dots, not hyphens — kept as-is
        assert_eq!(map.get("my_gem").map(|s| s.as_str()), Some("1.0.0.pre.1"));
        assert_eq!(
            map.get("another_gem").map(|s| s.as_str()),
            Some("2.0.0.beta.2")
        );
    }

    #[test]
    fn test_parse_malformed_lines() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    valid_gem (1.0.0)
    no_version_gem
    bad_parens (
    also_bad )
";
        let map = parse_gemfile_lock(content);
        // Only properly formatted lines should be parsed
        assert_eq!(map.get("valid_gem").map(|s| s.as_str()), Some("1.0.0"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_strip_platform_suffix_arm64() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-arm64-darwin)
";
        let map = parse_gemfile_lock(content);
        assert_eq!(map.get("nokogiri").map(|s| s.as_str()), Some("1.15.4"));
    }

    #[test]
    fn test_parse_gemfile_lock_graph() {
        let content = r#"
GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.0)
    rails (7.0.4)
      rack (~> 3.0)
      actioncable (= 7.0.4)
    actioncable (7.0.4)
      actionpack (= 7.0.4)
    actionpack (7.0.4)
"#;
        let graph = parse_gemfile_lock_graph(content);
        let rails = graph.packages.iter().find(|p| p.name == "rails").unwrap();
        assert_eq!(rails.version, "7.0.4");
        assert!(rails.dependencies.contains(&"rack".to_string()));
        assert!(rails.dependencies.contains(&"actioncable".to_string()));
        let rack = graph.packages.iter().find(|p| p.name == "rack").unwrap();
        assert!(rack.dependencies.is_empty());
    }

    #[test]
    fn test_parse_gemfile_lock_graph_ignores_path_and_git_sections() {
        let content = r#"
PATH
  remote: .
  specs:
    local_gem (0.1.0)
      rack (~> 3.0)

GIT
  remote: https://github.com/rails/rails.git
  specs:
    rails_fork (7.0.4)

GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.0)
    rails (7.0.4)
      rack (~> 3.0)
"#;
        let graph = parse_gemfile_lock_graph(content);
        let names: Vec<&str> = graph.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"rack"));
        assert!(names.contains(&"rails"));
        assert!(!names.contains(&"local_gem"), "PATH gems must be excluded");
        assert!(!names.contains(&"rails_fork"), "GIT gems must be excluded");
    }

    #[test]
    fn test_parse_gemfile_lock_graph_normalizes_names() {
        let content = r#"
GEM
  specs:
    ActiveRecord (7.0.0)
      active_support (= 7.0.0)
    active_support (7.0.0)
"#;
        let graph = parse_gemfile_lock_graph(content);
        // normalize_gem_name lowercases names
        assert!(graph.packages.iter().any(|p| p.name == "activerecord"));
        assert!(graph.packages.iter().any(|p| p.name == "active_support"));
    }

    #[test]
    fn test_parse_gemfile_lock_graph_strips_platform_suffix() {
        let content = r#"
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-x86_64-linux)
    rack (3.0.0)
"#;
        let graph = parse_gemfile_lock_graph(content);
        let nokogiri = graph
            .packages
            .iter()
            .find(|p| p.name == "nokogiri")
            .unwrap();
        assert_eq!(
            nokogiri.version, "1.15.4",
            "platform suffix must be stripped, got {:?}",
            nokogiri.version
        );
        let rack = graph.packages.iter().find(|p| p.name == "rack").unwrap();
        assert_eq!(rack.version, "3.0.0");
    }

    #[test]
    fn test_duplicate_gem_keeps_first() {
        let content = "\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.3.1)
    rails (6.0.0)
";
        let map = parse_gemfile_lock(content);
        assert_eq!(map.get("rails").map(|s| s.as_str()), Some("7.0.3.1"));
        assert_eq!(map.len(), 1);
    }

    #[tokio::test]
    async fn ruby_resolver_normalizes_gem_names() {
        use crate::parsers::lockfile_resolver::LockfileResolver;
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = tmp.path().join("Gemfile");
        let lock = tmp.path().join("Gemfile.lock");
        std::fs::write(&manifest, "source 'https://rubygems.org'\ngem 'rails'\n").unwrap();
        std::fs::write(
            &lock,
            r#"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.4.0
"#,
        )
        .unwrap();
        let resolver = super::RubyResolver;
        let content = std::fs::read_to_string(&lock).unwrap();
        let graph = resolver.parse_graph(&content);
        let dep = crate::parsers::Dependency {
            name: "Rails".to_string(),
            version: "*".to_string(),
            name_span: crate::parsers::Span {
                line: 0,
                line_start: 0,
                line_end: 0,
            },
            version_span: crate::parsers::Span {
                line: 0,
                line_start: 0,
                line_end: 0,
            },
            dev: false,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        };
        assert_eq!(
            resolver.resolve_version(&dep, &graph),
            Some("7.1.0".to_string())
        );
    }

    #[test]
    fn test_parse_ignores_path_and_git_sections() {
        let content = "\
PATH
  remote: ../my_engine
  specs:
    my_engine (0.1.0)
      rails (>= 7.0)

GIT
  remote: https://github.com/user/repo.git
  revision: abc123
  specs:
    some_gem (2.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.3.1)

PLATFORMS
  ruby
";
        let map = parse_gemfile_lock(content);
        assert_eq!(map.get("rails").map(|s| s.as_str()), Some("7.0.3.1"));
        assert!(!map.contains_key("my_engine"));
        assert!(!map.contains_key("some_gem"));
        assert_eq!(map.len(), 1);
    }
}
