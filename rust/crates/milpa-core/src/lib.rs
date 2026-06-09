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
pub mod identity;
pub mod registry;
pub mod store;

pub use error::{CoreError, MilpaError};
pub use fetch::{FetchError, Fetcher, FetcherRegistry, Receipt};
pub use registry::Index;
pub use store::CaStore;

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
