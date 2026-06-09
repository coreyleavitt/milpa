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

use milpa_manifest::{Manifest, Profile, Workspace};
use milpa_types::{Lockfile, ResolvedGraph};

pub mod error;
pub mod fetch;
pub mod frozen;
pub mod identity;
pub mod lockfile;
pub mod nimcfg;
pub mod registry;
pub mod resolver;
pub mod store;

pub use error::{CoreError, MilpaError};
pub use lockfile::{format_lockfile, from_graph, load_lockfile, parse_lockfile, write_lockfile};
// The manifest parse entry point + role discriminant, re-exported so the
// conformance harness (and the CLI, S13) reach them through the integration
// crate rather than depending on `milpa-manifest` directly. `MilpaError`'s
// `From<ManifestError>` impl lives here, so `?` lifts parse errors at this
// boundary.
pub use fetch::{FetchError, Fetcher, FetcherRegistry, Receipt};
pub use frozen::resolve_frozen;
pub use identity::{compute_content_hash, parse_identity, SUPPORTED_ALGORITHMS};
pub use milpa_manifest::{parse_document, ManifestDoc};
pub use nimcfg::format_nimcfg;
pub use registry::Index;
pub use resolver::resolve;
pub use store::{default_store, CaStore};

/// The union of every error code the Rust implementation can currently emit,
/// across all domains. The single boundary the conformance parity check reads:
/// `milpa-core` is the only crate that sees every domain enum, so it owns the
/// union (the per-domain `all_codes()` are the SSOT; this just gathers them).
///
/// At S2 the catalog is intentionally a *subset* of `docs/spec/errors.md` (only
/// the codes whose slices have wired real raises). The parity test asserts
/// `implemented ⊆ spec` now; S12 completes every domain's `all_codes()` and the
/// test flips to a full bijection. A code here that is *not* in the spec is
/// always a defect (a typo or an orphaned slug), which the subset check catches.
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
    ) -> Result<ResolvedGraph, MilpaError> {
        resolver::resolve_default_strategy(m, idx, f, p, prior, deps_dir)
    }

    fn resolve_workspace(
        &self,
        _w: &Workspace,
        _idx: Option<&Index>,
        _f: &dyn FetcherRegistry,
        _p: Option<&Profile>,
        _prior: Option<&Lockfile>,
        _deps_dir: &Path,
    ) -> Result<ResolvedGraph, MilpaError> {
        // Workspace resolution (multi-member union, per-member nim.cfg) lands in
        // S11; the single-package path is the S7b deliverable.
        unimplemented!("resolve_workspace lands in S11")
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
        _lock: &Lockfile,
        _store: &CaStore,
        _deps_dir: &Path,
    ) -> Result<ResolvedGraph, MilpaError> {
        // Needs the workspace member loader (per-member manifest + on-disk
        // identity check). Lands in S11 with FROZEN-MEMBER-NOT-IN-WORKSPACE /
        // FROZEN-MEMBER-IDENTITY-DRIFT.
        unimplemented!("resolve_workspace_frozen lands in S11")
    }
}

/// Full resolution (the `cmd=resolve` path). `prior` carries the previous
/// lockfile for pin reuse (resolver-semantics §8); fixtures that don't test
/// pin reuse pass `None`.
pub trait Resolver {
    fn resolve(
        &self,
        m: &Manifest,
        idx: Option<&Index>,
        f: &dyn FetcherRegistry,
        p: Option<&Profile>,
        prior: Option<&Lockfile>,
        deps_dir: &Path,
    ) -> Result<ResolvedGraph, MilpaError>;

    fn resolve_workspace(
        &self,
        w: &Workspace,
        idx: Option<&Index>,
        f: &dyn FetcherRegistry,
        p: Option<&Profile>,
        prior: Option<&Lockfile>,
        deps_dir: &Path,
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
