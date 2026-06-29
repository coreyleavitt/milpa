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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Receipt {
    /// Resolved concrete reference (e.g. the commit SHA a ref pinned to).
    pub resolved_ref: Option<String>,
    /// sha256 of the downloaded archive bytes (transport receipt, NOT identity).
    /// `Some` only for the tarball transport, where it is the value recorded as
    /// the TOFU pin (`lockfile-schema.md §5`); `None` for git/local/oci.
    pub archive_sha256: Option<String>,
    /// R1-04: submodule path → 40-hex gitlink SHA, path-sorted.
    /// Populated by the git fetcher from `materialize_git_tree`'s return value.
    /// Empty for non-git transports or repos with no submodules.
    /// Used by `transport_to_record` / `resolver.rs` to populate
    /// `ProvenanceRecord::Git { submodule_shas, .. }` in the lockfile.
    pub submodule_shas: Vec<(String, String)>,
    /// Content identity (`sha256:<hex>`) computed by [`DefaultRegistry::fetch`]
    /// after materialising the tree for CAS-admissible provenances (git, tarball,
    /// OCI). `None` for local/editable sources and for fetchers that do not
    /// compute identity (e.g. `MockedFetcher`, `FakeFetcher`).
    ///
    /// A0 architectural pin: `milpa hash` MUST read identity from this field —
    /// it must NOT call `compute_content_hash` directly. This is the single
    /// field that proves the hash subcommand and the real fetch path use the
    /// same identity derivation (spec/cli-contract.md §5.11 NORMATIVE).
    pub identity: Option<String>,
}

/// Fetch errors.
///
/// S1/S2 skeleton. The real transport-specific catalog codes (`FETCH-GIT-FAILED`,
/// `FETCH-DOWNLOAD-FAILED`, `FETCH-SHA256-MISMATCH`, the `EXTRACT-*` family, …)
/// are wired in S14 when the real fetchers land; `spec/errors.md` has no
/// generic `FETCH-FAILED` slug. Until then `Failed` is a non-catalog placeholder
/// used only for *harness-level* failures (e.g. the fake fetcher's "no mock for
/// this URL"), which never reach a fixture's `expected/error` assertion — so
/// `all_codes()` reports none, keeping the parity check honest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// Placeholder transport failure (see type docs). Carries no catalog code.
    Failed(String),
    /// Every mirror candidate transport-failed — dep cannot be fetched.
    /// (`FETCH-ALL-FAILED`, resolver-semantics §8a). Raised by the resolver
    /// (S7b), which owns the candidate-list construction.  Identity divergence
    /// (`FETCH-PROVENANCE-DIVERGENCE`) is a separate, distinct error and is
    /// never folded into this variant.
    AllFailed(String),
    /// A candidate provenance fetched successfully but its content hash does
    /// not match the locked identity — a supply-chain signal.
    /// (`FETCH-PROVENANCE-DIVERGENCE`, RFC Phase D item 3).  Raised immediately
    /// and loudly; MUST NOT fall through to the next candidate.
    ProvenanceDivergence(String),
    /// Archive extraction failed / unsafe (`EXTRACT-*`), wired in S14.
    Extract(&'static str, String),
    /// A coded transport failure from a real fetcher (`FETCH-LOCAL-*` /
    /// `FETCH-GIT-*` / `FETCH-DOWNLOAD-FAILED` / `FETCH-SHA256-MISMATCH` /
    /// `FETCH-OCI-*`), wired per-transport in S14c.
    Transport(&'static str, String),
}

impl FetchError {
    pub fn code(&self) -> &'static str {
        match self {
            // Non-catalog placeholder (see type docs); never satisfies a fixture.
            FetchError::Failed(_) => "FETCH-FAILED",
            FetchError::AllFailed(_) => "FETCH-ALL-FAILED",
            FetchError::ProvenanceDivergence(_) => "FETCH-PROVENANCE-DIVERGENCE",
            FetchError::Extract(c, _) | FetchError::Transport(c, _) => c,
        }
    }

    /// Every *catalog* code this domain can emit (parity companion to `code()`).
    /// `FETCH-ALL-FAILED` is wired at S7b (mirror fallback); the rest of the
    /// `FETCH-*`/`EXTRACT-*` transport codes land in S14 — every entry added
    /// MUST be a real spec slug.
    pub fn all_codes() -> &'static [&'static str] {
        &[
            "FETCH-ALL-FAILED",
            // D-fallback: supply-chain signal (RFC Phase D item 3).
            "FETCH-PROVENANCE-DIVERGENCE",
            // safe tar extraction (S14b) — carried by the Extract variant.
            "EXTRACT-ZIP-SLIP",
            "EXTRACT-SYMLINK-ESCAPE",
            "EXTRACT-SIZE-LIMIT",
            // genuine filesystem I/O failure during extraction (not a security-escape
            // slug): hardlink-target read, and write/mkdir I/O errors.
            "EXTRACT-IO-ERROR",
            // real transport fetchers (S14c). Local + Git land first (offline-
            // testable); tarball/oci codes are added as those fetchers wire.
            "FETCH-LOCAL-PATH-NOT-FOUND",
            "FETCH-LOCAL-PATH-NOT-DIR",
            "FETCH-GIT-FAILED",
            "FETCH-GIT-COMMIT-ABSENT",
            // H3c: object-store materialization detects LFS pointer blobs (first-line
            // exact match) and raises this rather than hashing the pointer text
            // (which would make content_hash cover incomplete content).
            "FETCH-GIT-LFS-POINTER",
            // H5: a .gitmodules submodule entry could not be resolved or fetched.
            // Carries submodule_path= and submodule_url= context fields.
            "FETCH-GIT-SUBMODULE-FAILED",
            // tarball + oci (S14c-2).
            "FETCH-DOWNLOAD-FAILED",
            // H1: security-distinct slug for compressed-body cap breach; distinct from
            // FETCH-DOWNLOAD-FAILED (network error) so a consumer can tell the difference.
            "FETCH-DOWNLOAD-SIZE-EXCEEDED",
            "FETCH-EXTRACT-FAILED",
            "FETCH-SHA256-MISMATCH",
            "FETCH-OCI-PULL-FAILED",
            "FETCH-OCI-NO-TARBALL",
            "FETCH-OCI-AMBIGUOUS-TARBALL",
            // mocked transport (issue #2 / differential-conformance-harness RFC):
            // the env-var-activated mocked fetcher (`MILPA_MOCKED_FETCHES`) found
            // no fixture directory for the requested `(url, ref)` key.
            "FETCH-MOCK-MISSING",
            // ref auto-discovery failure (cli-contract §5.6): `milpa add` without
            // `--ref` failed to discover the remote's default branch (real or mocked).
            "FETCH-REF-DISCOVERY-FAILED",
        ]
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
