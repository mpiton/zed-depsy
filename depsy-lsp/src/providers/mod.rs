//! LSP feature providers (inlay hints, diagnostics, code actions, completions, and document links).
//!
//! Each sub-module handles one LSP capability.  The backend wires them together
//! by forwarding parsed [`crate::parsers::Dependency`] slices and cache handles
//! to the appropriate provider function.

/// Code action provider (quick-fix: upgrade to latest, ignore package, etc.).
pub mod code_actions;

/// Completion provider for dependency names and versions.
pub mod completion;

/// Diagnostic provider (outdated dependencies, vulnerabilities, deprecated packages).
pub mod diagnostics;

/// Document link provider (clickable links to registry pages).
pub mod document_links;

/// Inlay hint provider (latest version shown next to the declared version).
pub mod inlay_hints;

pub(crate) mod version_edit;
