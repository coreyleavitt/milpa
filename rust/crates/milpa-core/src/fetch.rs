//! Fetcher trait + registry (RFC §4.6).
//!
//! `fetch` returns a **receipt, never an identity** — the registry computes
//! identity by walking the materialized tree, so no fake (or buggy real)
//! fetcher can lie about content. Dispatch is by matching the closed
//! `Provenance` enum (defined in `milpa-types`).
//!
//! S1 (scaffold): trait + types compile; real fetchers (git/tarball/oci/local)
//! and the dispatching registry land in S8/S14, the fake fetcher in S2.

use std::path::Path;

use milpa_types::Provenance;

/// What a fetcher reports after materializing bytes into `dest`. Deliberately
/// not an identity — identity is computed by the caller from the bytes on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Resolved concrete reference (e.g. the commit SHA a ref pinned to).
    pub resolved_ref: Option<String>,
}

/// Fetch errors. Carries a stable catalog `code()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The transport could not retrieve the source (`FETCH-FAILED`).
    Failed(String),
    /// Archive extraction failed / unsafe (`EXTRACT-*`).
    Extract(&'static str, String),
}

impl FetchError {
    pub fn code(&self) -> &'static str {
        match self {
            FetchError::Failed(_) => "FETCH-FAILED",
            FetchError::Extract(c, _) => c,
        }
    }
}

/// One transport implementation. The registry picks the impl by matching the
/// `Provenance` variant.
pub trait Fetcher {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError>;
}

/// Resolves a `Provenance` to its `Fetcher` and drives materialization.
/// Dispatch errors (no handler / ambiguous) are uncoded programmer-invariants
/// (plugin-contract §5.1), not catalog codes.
pub trait FetcherRegistry {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_error_code_is_stable() {
        assert_eq!(FetchError::Failed("x".into()).code(), "FETCH-FAILED");
    }
}
