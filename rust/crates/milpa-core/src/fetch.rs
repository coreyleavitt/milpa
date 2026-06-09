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

/// Fetch errors.
///
/// S1/S2 skeleton. The real transport-specific catalog codes (`FETCH-GIT-FAILED`,
/// `FETCH-DOWNLOAD-FAILED`, `FETCH-SHA256-MISMATCH`, the `EXTRACT-*` family, …)
/// are wired in S14 when the real fetchers land; `docs/spec/errors.md` has no
/// generic `FETCH-FAILED` slug. Until then `Failed` is a non-catalog placeholder
/// used only for *harness-level* failures (e.g. the fake fetcher's "no mock for
/// this URL"), which never reach a fixture's `expected/error` assertion — so
/// `all_codes()` reports none, keeping the parity check honest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// Placeholder transport failure (see type docs). Carries no catalog code.
    Failed(String),
    /// Archive extraction failed / unsafe (`EXTRACT-*`), wired in S14.
    Extract(&'static str, String),
}

impl FetchError {
    pub fn code(&self) -> &'static str {
        match self {
            // Non-catalog placeholder until S14 (see type docs).
            FetchError::Failed(_) => "FETCH-FAILED",
            FetchError::Extract(c, _) => c,
        }
    }

    /// Every *catalog* code this domain can emit (parity companion to `code()`).
    /// Empty until S14 wires the real `FETCH-*`/`EXTRACT-*` codes — every entry
    /// added then MUST be a real spec slug.
    pub fn all_codes() -> &'static [&'static str] {
        &[]
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
