//! Lockfile-driven frozen resolve (RFC §6 S10; `milpa/frozen.py`).
//!
//! When `milpa.lock` pins every dep's identity and the CAS already holds those
//! bytes, the whole fetch + parse + solve cycle is skipped: symlink
//! `_deps/<name>` → the store and rebuild a [`ResolvedGraph`] from the lockfile.
//! Any precondition failure is a coded `FROZEN-*` disqualification.
//!
//! Both the single-package [`resolve_frozen`] and the [`resolve_workspace_frozen`]
//! paths live here; the latter adds the workspace-member disqualifications
//! (`FROZEN-MEMBER-NOT-IN-WORKSPACE` / `FROZEN-MEMBER-IDENTITY-DRIFT`).
//! `FROZEN-LEGACY-REGISTRY-PROVENANCE` is raised from both — a legacy registry
//! record has no fetchable URL, so the frozen path cannot honor it.

use std::path::Path;

use milpa_manifest::{Dep, Manifest};
use milpa_solver::{parse_version, Strategy, VersionSet};
use milpa_types::{LockedDep, Lockfile, ProvenanceRecord, ResolvedDep, ResolvedGraph};

use crate::error::{CoreError, MilpaError};
use crate::store::CaStore;

fn frozen(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::Frozen(code, message.into()))
}

/// Reconstruct a [`ResolvedGraph`] from `manifest` + `lock` + `store` — no
/// network, no fetcher. The requested strategy is the default (`maxver`); the
/// `Resolver`/`FrozenResolver` trait surface carries no strategy override (that
/// is the CLI's concern, S13). Returns a coded `FROZEN-*` error on any
/// precondition failure.
pub fn resolve_frozen(
    manifest: &Manifest,
    lock: &Lockfile,
    store: &CaStore,
    deps_dir: &Path,
) -> Result<ResolvedGraph, MilpaError> {
    check_strategy(Strategy::default(), lock)?;
    check_manifest_alignment(manifest, lock)?;

    std::fs::create_dir_all(deps_dir).map_err(|e| {
        frozen(
            "FROZEN-IDENTITY-NOT-IN-STORE",
            format!("cannot create deps dir {}: {e}", deps_dir.display()),
        )
    })?;

    let mut resolved: Vec<ResolvedDep> = Vec::new();
    for locked in &lock.deps {
        // In single-package mode, a member or local provenance is "editable,
        // always re-resolve" — the frozen fast path bails (the slow path or a
        // workspace resolve handles it).
        match locked.provenances.first() {
            Some(ProvenanceRecord::Member { .. }) => {
                return Err(frozen(
                    "FROZEN-MEMBER-DEP",
                    format!(
                        "dep {:?} is a workspace member — members always re-resolve",
                        locked.name
                    ),
                ));
            }
            Some(ProvenanceRecord::Local { .. }) => {
                return Err(frozen(
                    "FROZEN-LOCAL-DEP",
                    format!(
                        "dep {:?} has a local provenance — editable trees always re-resolve",
                        locked.name
                    ),
                ));
            }
            _ => {}
        }
        link_external(locked, deps_dir, store)?;
        resolved.push(resolved_from_locked(locked)?);
    }
    Ok(ResolvedGraph { deps: resolved })
}

/// Workspace analog of [`resolve_frozen`] (mirrors `frozen.py:resolve_workspace_frozen`).
///
/// External deps come from the CAS (symlinked into `deps_dir`); members are
/// verified against their on-disk `content_hash` and stay in place (no `_deps`
/// symlink). Disqualifications: strategy mismatch, per-member manifest drift,
/// a member in the lock not in the workspace (`FROZEN-MEMBER-NOT-IN-WORKSPACE`),
/// member identity drift (`FROZEN-MEMBER-IDENTITY-DRIFT`), a non-member local
/// provenance, an external CAS miss, or a legacy registry record.
pub fn resolve_workspace_frozen(
    workspace: &crate::workspace::LoadedWorkspace,
    lock: &Lockfile,
    store: &CaStore,
    deps_dir: &Path,
) -> Result<ResolvedGraph, MilpaError> {
    check_strategy(Strategy::default(), lock)?;
    for member in &workspace.members {
        check_manifest_alignment(&member.manifest, lock)?;
    }
    std::fs::create_dir_all(deps_dir).map_err(|e| {
        frozen(
            "FROZEN-IDENTITY-NOT-IN-STORE",
            format!("cannot create deps dir {}: {e}", deps_dir.display()),
        )
    })?;

    let mut resolved: Vec<ResolvedDep> = Vec::new();
    for locked in &lock.deps {
        match locked.provenances.first() {
            Some(ProvenanceRecord::Member { name }) => {
                let Some(member) = workspace.members.iter().find(|m| &m.name == name) else {
                    return Err(frozen(
                        "FROZEN-MEMBER-NOT-IN-WORKSPACE",
                        format!("lockfile references workspace member {name:?} not in the current workspace"),
                    ));
                };
                let actual = crate::compute_content_hash(&member.directory)?;
                if Some(actual.as_str()) != locked.identity.as_deref() {
                    return Err(frozen(
                        "FROZEN-MEMBER-IDENTITY-DRIFT",
                        format!("member {name:?}: on-disk identity differs from the lockfile pin"),
                    ));
                }
                resolved.push(resolved_from_locked(locked)?);
            }
            Some(ProvenanceRecord::Local { .. }) => {
                return Err(frozen(
                    "FROZEN-LOCAL-DEP",
                    format!(
                        "dep {:?} has a local provenance — editable trees always re-resolve",
                        locked.name
                    ),
                ));
            }
            _ => {
                link_external(locked, deps_dir, store)?;
                resolved.push(resolved_from_locked(locked)?);
            }
        }
    }
    Ok(ResolvedGraph { deps: resolved })
}

// ---------------------------------------------------------------------------
// Precondition helpers
// ---------------------------------------------------------------------------

fn check_strategy(strategy: Strategy, lock: &Lockfile) -> Result<(), MilpaError> {
    if strategy.as_str() != lock.strategy {
        return Err(frozen(
            "FROZEN-STRATEGY-MISMATCH",
            format!(
                "strategy mismatch: lockfile built with {:?}, requested {:?}",
                lock.strategy,
                strategy.as_str()
            ),
        ));
    }
    Ok(())
}

/// Every manifest dep must have a lockfile entry; a `Named` dep's constraint
/// must still be satisfied by the locked version.
fn check_manifest_alignment(manifest: &Manifest, lock: &Lockfile) -> Result<(), MilpaError> {
    for mdep in &manifest.deps {
        let name = mdep.name();
        let Some(locked) = lock.deps.iter().find(|d| d.name == name) else {
            return Err(frozen(
                "FROZEN-MANIFEST-DEP-NOT-IN-LOCK",
                format!("manifest dep {name:?} has no lockfile entry (re-run `milpa fetch`)"),
            ));
        };
        if let Dep::Named(n) = mdep {
            if let Some(constraint) = n.constraint.as_deref() {
                let Some(locked_version) = parse_version(&locked.version) else {
                    return Err(frozen(
                        "FROZEN-LOCKED-VERSION-UNPARSEABLE",
                        format!(
                            "dep {name:?}: locked version {:?} is not a parseable X.Y.Z version",
                            locked.version
                        ),
                    ));
                };
                let vset = VersionSet::from_constraint(Some(constraint)).map_err(|e| {
                    // A malformed manifest constraint (should have been caught at
                    // parse) surfaces as the manifest's coded error, not a FROZEN-*.
                    MilpaError::Manifest(milpa_manifest::ManifestError::new(
                        "MAN-NIMBLE-CONSTRAINT",
                        format!("malformed constraint {constraint:?}: {e}"),
                    ))
                })?;
                if !vset.contains(&locked_version) {
                    return Err(frozen(
                        "FROZEN-CONSTRAINT-UNSATISFIED",
                        format!(
                            "dep {name:?}: locked version {} no longer satisfies manifest constraint {constraint:?}",
                            locked.version
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Link a CAS-resident external dep into `deps_dir/<name>`. `FROZEN-IDENTITY-NOT-IN-STORE`
/// if its identity is absent or unknown to the store.
fn link_external(locked: &LockedDep, deps_dir: &Path, store: &CaStore) -> Result<(), MilpaError> {
    let in_store = match &locked.identity {
        Some(id) if !id.is_empty() => store.contains(id).unwrap_or(false),
        _ => false,
    };
    if !in_store {
        return Err(frozen(
            "FROZEN-IDENTITY-NOT-IN-STORE",
            format!(
                "dep {:?} identity {} not in store",
                locked.name,
                locked.identity.as_deref().unwrap_or("<none>")
            ),
        ));
    }
    let identity = locked.identity.as_deref().unwrap();
    store
        .link(identity, &deps_dir.join(&locked.name))
        .map_err(MilpaError::from)
}

/// Rebuild a [`ResolvedDep`] from a [`LockedDep`], deriving the transport
/// provenance from the first record. A `Registry` record is the legacy
/// disqualification; `Member`/`Local` are unreachable here (they bail above).
fn resolved_from_locked(locked: &LockedDep) -> Result<ResolvedDep, MilpaError> {
    let Some(version) = parse_version(&locked.version) else {
        return Err(frozen(
            "FROZEN-LOCKED-VERSION-UNPARSEABLE",
            format!(
                "dep {:?}: locked version {:?} is not a parseable X.Y.Z version",
                locked.name, locked.version
            ),
        ));
    };
    let provenance = provenance_from_record(locked.provenances.first(), &locked.name)?;
    Ok(ResolvedDep {
        name: locked.name.clone(),
        identity: locked.identity.clone().unwrap_or_default(),
        version,
        src_dir: locked.src_dir.clone(),
        requires: locked.requires.clone(),
        provenance,
    })
}

/// The emission-level provenance record for a resolved dep — `ResolvedDep` now
/// carries the record directly, so this is the lockfile record itself, with two
/// guards: a `Registry` record is the legacy disqualification
/// (`FROZEN-LEGACY-REGISTRY-PROVENANCE` — no fetchable URL), and a missing record
/// is a malformed lockfile dep. `Member` passes through (workspace-frozen members
/// keep their member record); single-package `Local`/`Member` bail before here.
fn provenance_from_record(
    record: Option<&ProvenanceRecord>,
    name: &str,
) -> Result<ProvenanceRecord, MilpaError> {
    match record {
        Some(ProvenanceRecord::Registry { .. }) => Err(frozen(
            "FROZEN-LEGACY-REGISTRY-PROVENANCE",
            format!(
                "lock entry {name:?} uses the legacy registry provenance; \
                 run `milpa update {name}` to re-resolve via the tianguis index"
            ),
        )),
        Some(rec) => Ok(rec.clone()),
        None => Err(frozen(
            "FROZEN-IDENTITY-NOT-IN-STORE",
            format!("dep {name:?}: lockfile entry has no provenance record"),
        )),
    }
}

#[cfg(test)]
#[path = "frozen_tests.rs"]
mod frozen_tests;
