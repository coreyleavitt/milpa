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
pub use milpa_types::{
    ActivationSource, AttestationKind, EntryAttestation, LockAttestation, LockedDep, Lockfile,
    ProvenanceRecord, RekorRef, Version,
};
use milpa_types::ResolvedGraph;

pub mod atomic_cache;
pub mod binding;
pub mod bounded_http;
pub mod dag_identity;
pub mod dep_decl;
pub mod dep_decl_store;
pub mod discovery;
pub mod edge_sources;
pub mod entry_bundle_store;
pub mod entry_trust;
pub mod epoch_commitment;
pub mod error;
pub mod fetch;
pub mod fetchers;
pub mod frozen;
pub mod gated_index;
pub mod identity;
pub mod import_slot;
pub mod index_cache;
pub mod index_ratchet_seam;
pub mod index_trust;
pub mod lockfile;
pub mod manifest_writer;
pub mod nimcfg;
pub mod oci_client;
pub mod ratchet;
pub mod registry;
// Offline Rekor inclusion adapter (S2). `pub(crate)` API; consumed by `index_trust`'s
// `SigstoreVerifier`.
mod rekor_adapter;
pub mod resolver;
pub mod safe_extract;
pub mod source_id;
pub mod source_spec;
pub mod store;
// Standard trusted_root.json → ManualTrustRoot mapper (S1.5); consumed by `index_trust`.
mod trust_root;
pub mod workspace;

pub use binding::{BindOutcome, BindingDecision, BindingResolver, Claim};
pub use dag_identity::{compute_dag_identity, MaterializedEntry};
pub use dep_decl::{dep_decl_hash, parse_dep_decl, MAX_DEP_DECL_SCHEMA_VERSION};
pub use dep_decl_store::{
    index_base_url, make_dep_decl_store, verify as verify_dep_decl_hash, DepDeclStore,
    FileDepDeclStore, HttpDepDeclStore,
};
pub use discovery::{discover_manifest, load_manifest};
pub use entry_bundle_store::{
    entry_bundle_store_from_paths, BundleStoreBackend, EntryBundleStore, FileEntryBundleStore,
    HttpEntryBundleStore,
};
pub use entry_trust::{
    build_entry_subject, classify_epoch_membership, effective_epoch_policy, enforce_entry_trust,
    evaluate_entry_attestation, EntryBundleVerifier, EntryGateOutcome, EntrySubject,
    EntryTrustConfig, EntryVerificationResult, EpochMembership, MockEntryVerifier,
    SigstoreEntryVerifier, VerifierOutcome,
};
pub use error::{CoreError, MilpaError};
pub use gated_index::GatedIndex;
pub use index_cache::{
    baseline_sidecar_paths, derive_bundle_url, fetch_verified_candidate_text, get_bundle_url,
    index_url_from_env, load_index, load_index_with_history, write_baseline_pair, BundleError,
    BundleHttpGet, EpochCommitmentInputs, DEFAULT_INDEX_URL, DEFAULT_TTL_SECONDS,
};
pub use index_ratchet_seam::{
    build_index_state, evaluate_gate, iso_timestamp, parse_baseline, parse_baseline_meta,
    print_yank_notice, raw_attestation_epoch_commitment, BaselineMeta, GateDecision,
};
pub use ratchet::{canonical_digest, Baseline, EntryKey, RatchetOutcome, Violation};
pub use lockfile::{
    check_locked_drift, collapse_notes, format_dep_origin, format_lockfile, from_graph,
    load_lockfile, parse_lockfile, strip_dep_pin, verify_against_graph,
    verify_lockfile_against_deps, write_lockfile, AliasedDep,
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
pub use source_id::{canonical as source_id_canonical, format_source_id, normalize_source};
pub use source_spec::{parse_source_spec, split_oci_target};
pub use fetchers::{
    mocked_default_branch, oci_key, resolve_mock_key, stage_mock_content, url_key,
    CasAdmittingFetcher, DefaultRegistry, MockedFetcher,
};
pub use frozen::{
    check_source_id_preconditions_standalone, check_source_id_preconditions_workspace,
    rebuild_deps_view, resolve_frozen, resolve_workspace_frozen,
};
pub use identity::{
    compute_content_hash, enumerate_local_entries, parse_identity, SUPPORTED_ALGORITHMS,
};
pub use milpa_manifest::{parse_document, ManifestDoc, Profile, TrustPolicy};
pub use milpa_solver::{parse_version, Strategy};
pub use nimcfg::build_flag_defines;
pub use nimcfg::format_nimcfg;
pub use nimcfg::format_workspace_nimcfgs;
pub use registry::Index;
pub use resolver::{
    check_frozen_active_flags_mismatch, check_workspace_frozen_active_flags_mismatch,
    compute_dep_active_flags, effective_trust_policy,
    filter_manifest, parse_env_bool, resolve, resolve_with_cert, resolve_with_features,
    resolve_workspace, resolve_workspace_with_cert, resolve_workspace_with_features,
    workspace_any_member_strict, FailureCert, FilterCtx, SuccessCert, WitnessEntry,
};
pub use milpa_solver::RefutationEntry;
pub use safe_extract::{extract_tar, ExtractionResult, Limits};
pub use store::{default_store, CaStore};
pub use workspace::{
    check_member_entry_trust_declarations, check_member_index_trust_declarations, load_workspace,
    load_workspace_with_member_override, LoadedMember, LoadedWorkspace,
};

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
// The resolver traits (RFC §4.6). All defined here; a partially-implemented
// impl is a compile error, not a silent gap.
//
// `Resolver` / `ResolveParams` (the `cmd=resolve` trait surface) were DELETED
// here (RFC trusted-index-invariant.md §2.1 fork resolution): confirmed
// genuinely dead — `impl Resolver` existed nowhere but `Milpa`, and no
// `.resolve(`/`.resolve_workspace(` trait-object call exists anywhere in the
// workspace (only `Milpa::resolve_frozen`, via `FrozenResolver`, is actually
// exercised — `runner.rs:832`, `main.rs:1641`). Leaving it `&Index` would
// either break the whole-crate-compiles invariant once `resolver::resolve*`
// flips to `&GatedIndex`, or survive as an unaudited raw-`Index` bypass that
// falsifies "no public path skips the gate" (§2.1) — deleting the dead trait
// closes the hole outright rather than migrating a surface nothing calls.
// ---------------------------------------------------------------------------

/// Parse a `milpa.lock` (the `cmd=parse-lockfile` path).
pub trait LockfileParser {
    fn parse_lockfile(&self, text: &str) -> Result<Lockfile, MilpaError>;
}

/// The reference implementation of the resolver traits. A zero-sized handle that
/// the CLI (S13) and conformance harness drive.
#[derive(Debug, Default, Clone, Copy)]
pub struct Milpa;

impl LockfileParser for Milpa {
    fn parse_lockfile(&self, text: &str) -> Result<Lockfile, MilpaError> {
        Ok(lockfile::parse_lockfile(text)?)
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
