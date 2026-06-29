//! `milpa-core` — the integration crate (RFC §4.1/§4.6). It is the only lib
//! crate that sees `Index` / `CaStore` / `MilpaError` together, so it owns:
//! the resolver glue, lockfile parse+emit, the identity algorithm + CAS, the
//! `nim.cfg` emitter, the registry/`Index` reader, the `Fetcher` trait + its
//! registry, the boundary `MilpaError`, and the three resolver traits.
//!
//! S1 (scaffold): every type and trait below is a compiling skeleton. The
//! `From<DomainError> for MilpaError` impls live here (the only crate that can
//! write them without a dependency cycle); the harness asserts on `.code()`
//! only, so the wrapper is per-*domain*, not per-*code*.

use std::path::Path;

use milpa_manifest::{Manifest, Workspace};
pub use milpa_types::{ActivationSource, LockedDep, Lockfile, ProvenanceRecord};
use milpa_types::ResolvedGraph;

pub mod dag_identity;
pub mod dep_decl;
pub mod dep_decl_store;
pub mod discovery;
pub mod edge_sources;
pub mod error;
pub mod fetch;
pub mod fetchers;
pub mod frozen;
pub mod identity;
pub mod index_cache;
pub mod lockfile;
pub mod manifest_writer;
pub mod nimcfg;
pub mod registry;
pub mod resolver;
pub mod safe_extract;
pub mod source_spec;
pub mod store;
pub mod workspace;

pub use dag_identity::{compute_dag_identity, MaterializedEntry};
pub use dep_decl::{dep_decl_hash, parse_dep_decl, MAX_DEP_DECL_SCHEMA_VERSION};
pub use dep_decl_store::{
    index_base_url, make_dep_decl_store, verify as verify_dep_decl_hash, DepDeclStore,
    FileDepDeclStore, HttpDepDeclStore,
};
pub use discovery::{discover_manifest, load_manifest};
pub use error::{CoreError, MilpaError};
pub use index_cache::{index_url_from_env, load_index, DEFAULT_INDEX_URL, DEFAULT_TTL_SECONDS};
pub use lockfile::{
    format_lockfile, from_graph, load_lockfile, parse_lockfile, strip_dep_pin,
    verify_against_graph, verify_lockfile_against_deps, write_lockfile,
};
pub use manifest_writer::{
    add_mirror, apply_workspace_manifest_change, mutate_manifest_file,
    mutate_workspace_manifest_file, write_manifest, WriteResult,
};
pub use workspace::load_workspace_from_manifest;
pub use milpa_manifest::{format_manifest, format_workspace_manifest};
// The manifest parse entry point + role discriminant, re-exported so the
// conformance harness (and the CLI, S13) reach them through the integration
// crate rather than depending on `milpa-manifest` directly. `MilpaError`'s
// `From<ManifestError>` impl lives here, so `?` lifts parse errors at this
// boundary.
pub use fetch::{FetchError, Fetcher, FetcherRegistry, Receipt};
pub use source_spec::parse_source_spec;
pub use fetchers::{
    mocked_default_branch, resolve_mock_key, stage_mock_content, url_key, CasAdmittingFetcher,
    DefaultRegistry, MockedFetcher,
};
pub use frozen::{rebuild_deps_view, resolve_frozen, resolve_workspace_frozen};
pub use identity::{
    compute_content_hash, enumerate_local_entries, parse_identity, SUPPORTED_ALGORITHMS,
};
pub use milpa_manifest::{parse_document, AttestationPolicy, ManifestDoc, Profile};
pub use milpa_solver::{parse_version, Strategy};
pub use nimcfg::build_flag_defines;
pub use nimcfg::format_nimcfg;
pub use nimcfg::format_workspace_nimcfgs;
pub use registry::Index;
pub use resolver::{
    check_frozen_active_flags_mismatch, check_workspace_frozen_active_flags_mismatch,
    compute_dep_active_flags, effective_strict_policy,
    filter_manifest, parse_env_bool, resolve, resolve_with_cert, resolve_with_features,
    resolve_workspace, resolve_workspace_with_cert, resolve_workspace_with_features,
    workspace_any_member_strict, FailureCert, FilterCtx, SuccessCert, WitnessEntry,
};
pub use milpa_solver::RefutationEntry;
pub use safe_extract::{extract_tar, ExtractionResult, Limits};
pub use store::{default_store, CaStore};
pub use workspace::{load_workspace, LoadedMember, LoadedWorkspace};

/// The union of every error code the Rust implementation can currently emit,
/// across all domains. The single boundary the conformance parity check reads:
/// `milpa-core` is the only crate that sees every domain enum, so it owns the
/// union (the per-domain `all_codes()` are the SSOT; this just gathers them).
///
/// The set of codes emittable *now*. The S12 bijection lint
/// (`milpa-conformance` corpus test) partitions every `spec/errors.md` code
/// into this set, a `DEFERRED` set (tagged with the slice that will wire it), or
/// an `EXEMPT` set (never emitted) — pairwise disjoint, union == spec. A code
/// here absent from the spec is a defect (typo / orphan slug); a spec code in no
/// bucket fails the lint. The pure bijection (implemented ∪ exempt == spec) is
/// reached when the deferred set empties (after S13/S14).
pub fn implemented_error_codes() -> Vec<&'static str> {
    let mut codes: Vec<&'static str> = Vec::new();
    codes.extend_from_slice(milpa_manifest::ManifestError::all_codes());
    codes.extend_from_slice(milpa_solver::SolverError::all_codes());
    codes.extend_from_slice(fetch::FetchError::all_codes());
    codes.extend_from_slice(error::CoreError::all_codes());
    codes
}

// ---------------------------------------------------------------------------
// The three resolver traits (RFC §4.6). All defined here; a partially-
// implemented impl is a compile error, not a silent gap.
// ---------------------------------------------------------------------------

/// Parse a `milpa.lock` (the `cmd=parse-lockfile` path).
pub trait LockfileParser {
    fn parse_lockfile(&self, text: &str) -> Result<Lockfile, MilpaError>;
}

/// The reference implementation of the resolver traits. A zero-sized handle that
/// the CLI (S13) and conformance harness drive. `LockfileParser` lands here at
/// S5a; `Resolver` (S7) and `FrozenResolver` (S10) follow on the same type, so
/// the three `cmd` paths share one entry point.
#[derive(Debug, Default, Clone, Copy)]
pub struct Milpa;

impl LockfileParser for Milpa {
    fn parse_lockfile(&self, text: &str) -> Result<Lockfile, MilpaError> {
        Ok(lockfile::parse_lockfile(text)?)
    }
}

impl Resolver for Milpa {
    fn resolve(
        &self,
        m: &Manifest,
        idx: Option<&Index>,
        f: &dyn FetcherRegistry,
        p: Option<&Profile>,
        prior: Option<&Lockfile>,
        deps_dir: &Path,
        store: &CaStore,
    ) -> Result<ResolvedGraph, MilpaError> {
        resolver::resolve_default_strategy(m, idx, f, p, prior, deps_dir, store)
    }

    fn resolve_workspace(
        &self,
        _w: &Workspace,
        params: ResolveParams<'_>,
        deps_dir: &Path,
        store: &CaStore,
    ) -> Result<ResolvedGraph, MilpaError> {
        // The trait carries the *parsed* workspace, but the union resolve needs
        // each member's loaded manifest + directory. In a real project layout the
        // workspace root is the deps_dir's parent; load from there. (The
        // conformance harness, whose scratch `_deps/` is detached from the fixture
        // inputs, calls the free `load_workspace` + `resolve_workspace` directly.)
        let root = deps_dir.parent().unwrap_or_else(|| Path::new("."));
        let loaded = workspace::load_workspace(root)?;
        resolver::resolve_workspace(
            &loaded,
            params.index,
            params.fetcher,
            params.profile,
            params.prior,
            milpa_solver::Strategy::default(),
            deps_dir,
            params.require_attested_metadata,
            store,
        )
    }
}

impl FrozenResolver for Milpa {
    fn resolve_frozen(
        &self,
        m: &Manifest,
        lock: &Lockfile,
        store: &CaStore,
        deps_dir: &Path,
    ) -> Result<ResolvedGraph, MilpaError> {
        frozen::resolve_frozen(m, lock, store, deps_dir)
    }

    fn resolve_workspace_frozen(
        &self,
        _w: &Workspace,
        lock: &Lockfile,
        store: &CaStore,
        deps_dir: &Path,
    ) -> Result<ResolvedGraph, MilpaError> {
        // As with resolve_workspace: load members from the deps_dir's parent (the
        // real project layout). The harness calls the free functions directly.
        let root = deps_dir.parent().unwrap_or_else(|| Path::new("."));
        let loaded = workspace::load_workspace(root)?;
        frozen::resolve_workspace_frozen(&loaded, lock, store, deps_dir)
    }
}

/// Inputs that configure a workspace resolution run (mirrors Python `ResolveParams`).
///
/// Bundles the index, fetcher, profile, prior lockfile, and attestation policy
/// flag so that [`Resolver::resolve_workspace`] stays under the 7-arg arity limit.
/// The workspace itself and `deps_dir` are passed as separate positional arguments
/// because they are "what to resolve" and "where", not resolution options.
pub struct ResolveParams<'a> {
    /// Tianguis index for named-dep resolution; `None` ⇒ empty index (valid only
    /// when no un-overridden named deps exist in any member, else `RES-WS-NO-INDEX`).
    pub index: Option<&'a Index>,
    /// Fetcher registry that materializes each dep's bytes.
    pub fetcher: &'a dyn FetcherRegistry,
    /// Active profile for conditional dep filtering (§6); `None` disables filtering.
    pub profile: Option<&'a milpa_manifest::Profile>,
    /// Prior lockfile for pin reuse (resolver-semantics §8); `None` means no pins.
    pub prior: Option<&'a Lockfile>,
    /// Enforces strict attestation policy (S5, §13.1) when `true`. Effective policy
    /// is the OR of this flag and any member's `attestation-policy "strict"`.
    pub require_attested_metadata: bool,
    // S9 (RFC #23 §3.4): CLI feature-selection. Mirrors Python ResolveParams.
    /// Explicit feature names to activate on the root manifest (``--features``).
    pub features: std::collections::BTreeSet<String>,
    /// When true, suppresses all default-true root flags (``--no-default-features``).
    pub no_default_features: bool,
    /// When true, activates all declared root flags (``--all-features``).
    pub all_features: bool,
}

/// Full resolution (the `cmd=resolve` path). `prior` carries the previous
/// lockfile for pin reuse (resolver-semantics §8); fixtures that don't test
/// pin reuse pass `None`.
///
/// `store` is the content-addressed store used to rebuild `_deps/` after
/// resolution completes (B-nimcfg SSOT: alias symlinks + stale-entry removal).
pub trait Resolver {
    fn resolve(
        &self,
        m: &Manifest,
        idx: Option<&Index>,
        f: &dyn FetcherRegistry,
        p: Option<&Profile>,
        prior: Option<&Lockfile>,
        deps_dir: &Path,
        store: &CaStore,
    ) -> Result<ResolvedGraph, MilpaError>;

    fn resolve_workspace(
        &self,
        w: &Workspace,
        params: ResolveParams<'_>,
        deps_dir: &Path,
        store: &CaStore,
    ) -> Result<ResolvedGraph, MilpaError>;
}

/// Frozen resolution (the `cmd=frozen` path): bypasses the solver, so it needs
/// neither an index nor a fetcher — only the lockfile and the CAS.
pub trait FrozenResolver {
    fn resolve_frozen(
        &self,
        m: &Manifest,
        lock: &Lockfile,
        store: &CaStore,
        deps_dir: &Path,
    ) -> Result<ResolvedGraph, MilpaError>;

    fn resolve_workspace_frozen(
        &self,
        w: &Workspace,
        lock: &Lockfile,
        store: &CaStore,
        deps_dir: &Path,
    ) -> Result<ResolvedGraph, MilpaError>;
}

#[cfg(test)]
mod parser_fuzz_tests;
