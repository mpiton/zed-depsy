//! Document state and parsing logic
//!
//! This module handles document state management and dependency parsing
//! for different file types.

use crate::file_types::FileType;
use crate::parsers::Dependency;

/// State of a parsed dependency document.
///
/// Stores the parsed dependencies and detected file type for a document
/// that has been opened in the editor.
pub struct DocumentState {
    /// List of dependencies extracted from the document.
    pub dependencies: Vec<Dependency>,
    /// The detected file type (determines which parser/registry to use).
    pub file_type: FileType,
    /// Full dependency graph from the lockfile, if one was found.
    /// Used to enumerate transitive dependencies for vulnerability scanning.
    pub lockfile_graph: Option<std::sync::Arc<crate::parsers::lockfile_graph::LockfileGraph>>,
    /// Per-document transitive vulnerability attribution. Keyed by the DIRECT
    /// dependency name in the current manifest. Not shared with other documents
    /// because the attribution depends on this document's lockfile graph.
    pub transitive_vulns_by_direct:
        hashbrown::HashMap<String, Vec<crate::registries::TransitiveVuln>>,
}
