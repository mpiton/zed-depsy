//! Shared types and the [`crate::parsers::Parser`] trait used by all manifest parsers.
//!
//! Each ecosystem parser lives in its own sub-module and produces a
//! `Vec<`[`crate::parsers::Dependency`]`>` from the raw file content.  Span
//! information (`name_span` / `version_span`) is always anchored to the *inner*
//! text of each token so that LSP quick-fix
//! [`tower_lsp::lsp_types::TextEdit`]s replace just the package name or
//! version literal without touching surrounding quotes or syntax.
//!
//! # Supported ecosystems
//!
//! | Module | File | Registry |
//! |--------|------|----------|
//! | [`crate::parsers::cargo`] | `Cargo.toml` | crates.io |
//! | [`crate::parsers::npm`] | `package.json` | npm |
//! | [`crate::parsers::python`] | `requirements.txt`, `pyproject.toml`, `hatch.toml` | PyPI |
//! | [`crate::parsers::go`] | `go.mod` | proxy.golang.org |
//! | [`crate::parsers::php`] | `composer.json` | Packagist |
//! | [`crate::parsers::dart`] | `pubspec.yaml` | pub.dev |
//! | [`crate::parsers::csharp`] | `*.csproj` | NuGet |
//! | [`crate::parsers::ruby`] | `Gemfile` | RubyGems |
//! | [`crate::parsers::maven`] | `pom.xml` | Maven Central |

use tower_lsp::lsp_types;

/// A single dependency extracted from a manifest file.
///
/// Both `name_span` and `version_span` cover the *inner* content of the token
/// (no surrounding quotes), so LSP quick-fix edits can safely replace just
/// the text they target.
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Package name as declared in the manifest.
    pub name: String,
    /// Version specifier as declared (e.g. `"^1.0"`, `">=1,<2"`).
    ///
    /// For Maven `pom.xml` files that use `${property}` placeholders, this
    /// field preserves the raw placeholder text so the code-action layer can
    /// detect and skip the "update version" quick-fix.  The resolved value is
    /// available via [`Self::effective_version`].
    pub version: String,
    /// Source span covering the package name token (inner text, no quotes).
    pub name_span: Span,
    /// Source span covering the version token (inner text, no quotes).
    pub version_span: Span,
    /// Whether this dependency belongs to a dev / test group.
    pub dev: bool,
    /// Whether this dependency is optional (peer, optional, or indirect).
    pub optional: bool,
    /// Custom registry name (Cargo only, e.g. `"kellnr"`).
    pub registry: Option<String>,
    /// Version resolved from the lock file (e.g. `Cargo.lock`), if available.
    ///
    /// When set, [`Self::effective_version`] returns this value instead of
    /// [`Self::version`] for registry comparisons and hover text.
    pub resolved_version: Option<String>,
    /// Whether source syntax contains additional version constraints outside
    /// [`Self::version`] and [`Self::version_span`].
    ///
    /// Providers use this source-shape metadata to avoid edits that would
    /// update only one anchor of a compound declaration.
    pub has_additional_version_constraints: bool,
}

/// A half-open byte range within a single source line.
///
/// `line_start` and `line_end` are 0-indexed **byte** offsets measured from the
/// beginning of the line (not the file). The range is end-exclusive:
/// `line[line_start..line_end]` yields the covered text. ASCII input therefore
/// maps 1:1 to LSP UTF-16 character offsets, but non-ASCII content is not
/// transcoded — callers that need exact LSP character columns must convert.
#[derive(Debug, Clone, Copy)]
pub struct Span {
    /// 0-indexed line number within the file.
    pub line: u32,
    /// 0-indexed byte offset of the first byte (inclusive).
    pub line_start: u32,
    /// 0-indexed byte offset one past the last byte (exclusive).
    pub line_end: u32,
}

impl Span {
    /// Returns `true` when `position` falls within this span.
    ///
    /// Both the line and the column must match: the column is checked against
    /// the half-open range `[line_start, line_end)`.
    pub fn contains_lsp_position(&self, position: &lsp_types::Position) -> bool {
        self.line == position.line && (self.line_start..self.line_end).contains(&position.character)
    }
}

impl Dependency {
    /// Returns the resolved version (from lock file) if available,
    /// otherwise falls back to the declared version from the manifest.
    ///
    /// Use this method whenever a concrete version number is needed for
    /// registry look-ups or hover text, as it transparently handles both
    /// lock-file pinned versions and Maven `${property}` substitutions stored
    /// in [`Self::resolved_version`].
    ///
    /// # Examples
    ///
    /// ```
    /// use depsy_lsp::parsers::{Dependency, Span};
    /// let dep = Dependency {
    ///     name: "serde".into(),
    ///     version: "^1.0".into(),
    ///     name_span: Span { line: 0, line_start: 0, line_end: 5 },
    ///     version_span: Span { line: 0, line_start: 8, line_end: 12 },
    ///     dev: false,
    ///     optional: false,
    ///     registry: None,
    ///     resolved_version: Some("1.0.196".into()),
    ///     has_additional_version_constraints: false,
    /// };
    /// assert_eq!(dep.effective_version(), "1.0.196");
    /// ```
    pub fn effective_version(&self) -> &str {
        self.resolved_version.as_deref().unwrap_or(&self.version)
    }
}

/// Trait implemented by every ecosystem-specific manifest parser.
///
/// Implementors must be both [`Send`] and [`Sync`] so that parsers can be
/// shared across async tasks in the LSP backend.
///
/// # Examples
///
/// ```
/// use depsy_lsp::parsers::{Parser, cargo::CargoParser};
/// let parser = CargoParser::new();
/// let deps = parser.parse("[dependencies]\nserde = \"1.0\"\n");
/// assert_eq!(deps.len(), 1);
/// assert_eq!(deps[0].name, "serde");
/// ```
pub trait Parser: Send + Sync {
    /// Parse `content` and return every dependency found.
    ///
    /// Malformed or unrecognised input should be silently ignored rather than
    /// panicking — return an empty `Vec` when nothing can be extracted.
    fn parse(&self, content: &str) -> Vec<Dependency>;
}

pub mod cargo;
pub mod cargo_lock;
pub mod composer_lock;
pub mod csharp;
pub mod dart;
pub mod gemfile_lock;
pub mod go;
pub mod go_sum;
pub mod json_spans;
pub mod lockfile_graph;
pub mod lockfile_resolver;
pub mod maven;
pub mod npm;
pub mod npm_lock;
pub mod packages_lock_json;
pub mod php;
pub mod pnpm_workspace;
pub mod pubspec_lock;
pub mod python;
pub mod python_lock;
pub mod ruby;
