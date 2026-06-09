//! tianguis `index.kdl` reader (RFC §4.1; registry-protocol.md). Named-dep
//! resolution: identity + provenance + version set per package. The four-state
//! index cache (fresh / stale-refetch / offline-fallback / no-cache-error) and
//! the `TNG-*` validators land in S8.
//!
//! S1 (scaffold): the `Index` type + read signature exist.

use crate::error::CoreError;
use milpa_types::Provenance;

/// One published version of a package in the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub version: String,
    pub content_hash: String,
    pub provenance: Provenance,
}

/// The parsed registry index: package name → its published versions.
/// Insertion-ordered to keep iteration deterministic (RFC §3 determinism rule).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    /// `(package_name, entries)` pairs, in index order.
    pub packages: Vec<(String, Vec<IndexEntry>)>,
}

impl Index {
    /// Parse an `index.kdl` document into an `Index` (S8).
    pub fn parse(_text: &str) -> Result<Index, CoreError> {
        unimplemented!("Index::parse lands in S8")
    }
}
