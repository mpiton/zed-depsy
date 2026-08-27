//! Document link provider — returns clickable links on dependency names.
//!
//! [`crate::providers::document_links::create_document_links`] maps each
//! parsed [`crate::parsers::Dependency`] to an LSP
//! [`tower_lsp::lsp_types::DocumentLink`] whose target URL points to the
//! package page on the appropriate registry (crates.io, npm, PyPI, etc.).
//! Dependencies from alternative/private registries are skipped because their
//! registry URL is not reliably known.

use tower_lsp::lsp_types::{DocumentLink, Position, Range, Url};

use crate::file_types::FileType;
use crate::parsers::Dependency;

/// Build LSP document links for the given dependencies.
///
/// Each link covers the name-span of the package declaration and points to
/// the corresponding registry page determined by `file_type`.  Dependencies
/// that carry a `registry` field (alternative/private registries) are skipped
/// because their registry URL is not known.
///
/// A tooltip of the form `"Open <name> on <registry>"` is attached to each link.
///
/// # Returns
///
/// A [`Vec<DocumentLink>`] with one entry per eligible dependency.  May be
/// empty when `deps` is empty or all entries belong to alternative registries.
pub fn create_document_links(deps: &[Dependency], file_type: &FileType) -> Vec<DocumentLink> {
    deps.iter()
        .filter_map(|dep| {
            // Skip deps from alternative registries (e.g., private Cargo registries)
            if dep.registry.is_some() {
                return None;
            }
            let dep_name = &*dep.name;
            let url_str = file_type.fmt_registry_package_url(dep_name).to_string();
            let url = match Url::parse(&url_str) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!("Failed to parse registry URL for '{dep_name}': {e}");
                    return None;
                }
            };
            Some(DocumentLink {
                range: Range {
                    start: Position {
                        line: dep.name_span.line,
                        character: dep.name_span.line_start,
                    },
                    end: Position {
                        line: dep.name_span.line,
                        character: dep.name_span.line_end,
                    },
                },
                target: Some(url),
                tooltip: Some(format!("Open {dep_name} on {}", file_type.registry_name())),
                data: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::parsers::Span;

    use super::*;

    fn make_dep(name: &str, line: u32, name_start: u32, name_end: u32) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            name_span: Span {
                line,
                line_start: name_start,
                line_end: name_end,
            },
            version_span: Span {
                line,
                line_start: name_end + 2,
                line_end: name_end + 7,
            },
            dev: false,
            optional: false,
            registry: None,
            resolved_version: None,
            has_additional_version_constraints: false,
        }
    }

    #[test]
    fn test_creates_links_for_dart_deps() {
        let deps = vec![make_dep("http", 5, 2, 6)];
        let links = create_document_links(&deps, &FileType::Dart);
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].target.as_ref().unwrap().as_str(),
            "https://pub.dev/packages/http"
        );
        assert_eq!(links[0].range.start.line, 5);
        assert_eq!(links[0].range.start.character, 2);
        assert_eq!(links[0].range.end.character, 6);
    }

    #[test]
    fn test_creates_links_for_cargo_deps() {
        let deps = vec![make_dep("serde", 10, 0, 5)];
        let links = create_document_links(&deps, &FileType::Cargo);
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].target.as_ref().unwrap().as_str(),
            "https://crates.io/crates/serde"
        );
    }

    #[test]
    fn test_tooltip_format() {
        let deps = vec![make_dep("express", 0, 0, 7)];
        let links = create_document_links(&deps, &FileType::Npm);
        assert_eq!(links[0].tooltip.as_deref(), Some("Open express on npm"));
    }

    #[test]
    fn test_empty_deps_returns_empty() {
        let links = create_document_links(&[], &FileType::Dart);
        assert!(links.is_empty());
    }

    #[test]
    fn test_npm_scoped_package() {
        let deps = vec![make_dep("@babel/core", 3, 4, 15)];
        let links = create_document_links(&deps, &FileType::Npm);
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].target.as_ref().unwrap().as_str(),
            "https://www.npmjs.com/package/@babel/core"
        );
    }

    #[test]
    fn test_go_module_path() {
        let deps = vec![make_dep("github.com/gin-gonic/gin", 5, 1, 25)];
        let links = create_document_links(&deps, &FileType::Go);
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].target.as_ref().unwrap().as_str(),
            "https://pkg.go.dev/github.com/gin-gonic/gin"
        );
    }

    #[test]
    fn test_php_namespaced_package() {
        let deps = vec![make_dep("laravel/framework", 8, 8, 25)];
        let links = create_document_links(&deps, &FileType::Php);
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0].target.as_ref().unwrap().as_str(),
            "https://packagist.org/packages/laravel/framework"
        );
    }
}
