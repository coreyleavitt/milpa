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
use milpa_types::{Lockfile, ResolvedGraph};

pub mod discovery;
pub mod error;
pub mod fetch;
pub mod frozen;
pub mod identity;
pub mod lockfile;
pub mod manifest_writer;
pub mod nimcfg;
pub mod registry;
pub mod resolver;
pub mod store;
pub mod workspace;

pub use discovery::{discover_manifest, load_manifest};
pub use error::{CoreError, MilpaError};
pub use lockfile::{
    format_lockfile, from_graph, load_lockfile, parse_lockfile, verify_against_graph,
    verify_lockfile_against_deps, write_lockfile,
};
pub use manifest_writer::{mutate_manifest_file, write_manifest, WriteResult};
pub use milpa_manifest::format_manifest;
// The manifest parse entry point + role discriminant, re-exported so the
// conformance harness (and the CLI, S13) reach them through the integration
// crate rather than depending on `milpa-manifest` directly. `MilpaError`'s
// `From<ManifestError>` impl lives here, so `?` lifts parse errors at this
// boundary.
pub use fetch::{FetchError, Fetcher, FetcherRegistry, Receipt};
pub use frozen::{resolve_frozen, resolve_workspace_frozen};
pub use identity::{compute_content_hash, parse_identity, SUPPORTED_ALGORITHMS};
pub use milpa_manifest::{parse_document, ManifestDoc, Profile};
pub use milpa_solver::{parse_version, Strategy};
pub use nimcfg::format_nimcfg;
pub use nimcfg::format_workspace_nimcfgs;
pub use registry::Index;
pub use resolver::{resolve, resolve_workspace};
pub use store::{default_store, CaStore};
pub use workspace::{load_workspace, LoadedWorkspace};

/// The union of every error code the Rust implementation can currently emit,
/// across all domains. The single boundary the conformance parity check reads:
/// `milpa-core` is the only crate that sees every domain enum, so it owns the
/// union (the per-domain `all_codes()` are the SSOT; this just gathers them).
///
/// The set of codes emittable *now*. The S12 bijection lint
/// (`milpa-conformance` corpus test) partitions every `docs/spec/errors.md` code
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
    ) -> Result<ResolvedGraph, MilpaError> {
        resolver::resolve_default_strategy(m, idx, f, p, prior, deps_dir)
    }

    fn resolve_workspace(
        &self,
        _w: &Workspace,
        idx: Option<&Index>,
        f: &dyn FetcherRegistry,
        p: Option<&Profile>,
        prior: Option<&Lockfile>,
        deps_dir: &Path,
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
            idx,
            f,
            p,
            prior,
            milpa_solver::Strategy::default(),
            deps_dir,
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
