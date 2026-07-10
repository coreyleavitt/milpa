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

use std::path::Path;

use milpa_manifest::{Dep, Manifest};
use milpa_solver::{parse_version, Strategy};
use milpa_types::{EntryAttestation, LockedDep, Lockfile, ProvenanceRecord, ResolvedDep, ResolvedGraph};

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
            _ => {
                // Pre-validate CAS presence for each dep before rebuilding.
                // This ensures FROZEN-IDENTITY-NOT-IN-STORE is raised eagerly.
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
            }
        }
        resolved.push(resolved_from_locked(locked)?);
    }
    // B-nimcfg: use rebuild_deps_view (SSOT) to create canonical + alias symlinks
    // and remove stale entries atomically.
    let graph = ResolvedGraph { deps: resolved };
    rebuild_deps_view(&graph, deps_dir, store);
    Ok(graph)
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
            Some(ProvenanceRecord::Member { name, .. }) => {
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
                // Pre-validate CAS presence before rebuilding.
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
                resolved.push(resolved_from_locked(locked)?);
            }
        }
    }
    // B-nimcfg: use rebuild_deps_view (SSOT) for atomic _deps/ rebuild.
    let graph = ResolvedGraph { deps: resolved };
    rebuild_deps_view(&graph, deps_dir, store);
    Ok(graph)
}

// ---------------------------------------------------------------------------
// B-nimcfg: atomic _deps/ view rebuild (Phase B, rfc-content-addressed-identity.md)
// ---------------------------------------------------------------------------

/// Rebuild `_deps/` as a pure function of `graph` (B-nimcfg slice).
///
/// This is the SINGLE SOURCE OF TRUTH for `_deps/` contents in the Rust impl.
/// Called from both `resolve_frozen` / `resolve_workspace_frozen` (frozen paths)
/// AND from the resolver's `resolve()` / `resolve_workspace()` (live paths).
///
/// Algorithm:
/// 1. Compute the expected entry set: for each dep in `graph.deps` that has
///    a non-empty CAS identity, record `{canonical_name: identity}` PLUS
///    `{alias: identity}` for each alias. Member/local deps are excluded
///    (they don't live in `_deps/`).
/// 2. Remove any `_deps/<x>` NOT in the expected set (symlinks via `remove_file`,
///    real dirs via `remove_dir_all`).
/// 3. Create/refresh each expected entry as a relative CAS symlink via
///    `store.link(identity, deps_dir/<name>)`. `link()` is idempotent
///    (clears any existing entry before re-linking).
///
/// "Atomic" here = end state is exactly the expected set with no partial/stale
/// residue. Cross-process transactional atomicity is NOT guaranteed (out of scope).
pub fn rebuild_deps_view(
    graph: &milpa_types::ResolvedGraph,
    deps_dir: &Path,
    store: &CaStore,
) {
    use milpa_types::{dep_dir_name, ProvenanceRecord};

    if !deps_dir.is_dir() {
        return;
    }

    // Step 1: compute expected entry set (dir_entry → identity) for CAS entries only.
    // C1: use dep_dir_name so qualified deps map to "@ns/name" (not "ns::name").
    // Also collect local dep dir_entries to PRESERVE in _deps/ (fetch_local created
    // their symlinks; rebuild_deps_view must not remove them as stale).
    let mut expected: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut local_names: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for dep in &graph.deps {
        // Skip member deps (they live in the workspace tree, not _deps/).
        // Check the observed (first) provenance — declared mirrors do not change kind.
        if dep.provenances.first().map_or(false, |p| matches!(p, ProvenanceRecord::Member { .. })) {
            continue;
        }
        // Local deps have no CAS identity (cas_admissible=false); fetch_local
        // creates their _deps/<name> symlink.  Add to local_names so Step 2
        // does NOT remove them as stale entries.
        if dep.provenances.first().map_or(false, |p| matches!(p, ProvenanceRecord::Local { .. })) {
            local_names.insert(dep.name.clone());
            continue;
        }
        if dep.identity.is_empty() {
            continue;
        }
        // C1: dep_dir_name gives "@ns/name" for qualified deps, "name" for bare.
        let dir_entry = dep_dir_name(&dep.name, dep.namespace.as_deref());
        expected.insert(dir_entry, dep.identity.clone());
        for alias in &dep.aliases {
            expected.insert(alias.clone(), dep.identity.clone());
        }
    }

    // Step 2: remove stale entries (not in expected set, and not a preserved local dep).
    // C1: namespace dirs ("@<ns>/") may contain multiple entries; check their
    // children (as "@ns/child") rather than the dir itself.
    if let Ok(read_dir) = std::fs::read_dir(deps_dir) {
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('@') && entry.path().is_dir() {
                // Namespace directory: check each child independently.
                let mut any_kept = false;
                if let Ok(children) = std::fs::read_dir(entry.path()) {
                    for child in children.flatten() {
                        let child_name = child.file_name().to_string_lossy().into_owned();
                        let compound = format!("{}/{}", name, child_name);
                        if expected.contains_key(&compound) {
                            any_kept = true;
                        } else {
                            let child_path = child.path();
                            let meta = std::fs::symlink_metadata(&child_path);
                            if let Ok(m) = meta {
                                let ft = m.file_type();
                                let _ = if ft.is_symlink() || ft.is_file() {
                                    std::fs::remove_file(&child_path)
                                } else {
                                    std::fs::remove_dir_all(&child_path)
                                };
                            }
                        }
                    }
                }
                // Remove the namespace dir itself if now empty.
                if !any_kept {
                    let _ = std::fs::remove_dir(entry.path());
                }
            } else if !expected.contains_key(&name) && !local_names.contains(&name) {
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path);
                if let Ok(m) = meta {
                    let ft = m.file_type();
                    let _ = if ft.is_symlink() || ft.is_file() {
                        std::fs::remove_file(&path)
                    } else {
                        std::fs::remove_dir_all(&path)
                    };
                }
            }
        }
    }

    // Step 3: create/refresh expected CAS symlinks.
    // C1: for qualified deps, create the "@ns/" parent directory first.
    // store.link() clears any existing entry before creating the new symlink.
    for (dir_entry, identity) in &expected {
        let target = deps_dir.join(dir_entry);
        // Ensure parent directory exists (needed for "@ns/name" paths).
        if let Some(parent) = target.parent() {
            if !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let _ = store.link(identity, &target);
    }
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

/// Every manifest dep (including `dev_deps`) must have a lockfile entry;
/// a `Named` dep's constraint must still be satisfied by the locked version.
///
/// S1 (#142 + #178): uses an alias-aware lookup (checks `d.aliases` too) and
/// iterates both `manifest.deps` AND `manifest.dev_deps` — mirrors Python's
/// `frozen.py:199` (`list(manifest.deps) + list(manifest.dev_deps)`).
/// Previously this function iterated only `manifest.deps`, causing a live
/// divergence with the Python impl for any manifest with a dev-dep absent
/// from the lockfile (#178).
fn check_manifest_alignment(manifest: &Manifest, lock: &Lockfile) -> Result<(), MilpaError> {
    use milpa_types::dep_dir_name;
    // C1 + S1 (#142): alias-aware, namespace-aware lookup.
    // For qualified named deps, match on (name, namespace) not just bare name.
    // A dep present only as a lockfile alias must not fire FROZEN-MANIFEST-DEP-NOT-IN-LOCK.
    let find_locked = |name: &str, namespace: Option<&str>| -> Option<&LockedDep> {
        // For qualified deps: find the lock entry with matching (name, namespace).
        // For bare deps: fall back to alias lookup.
        if namespace.is_some() {
            lock.deps.iter().find(|d| {
                d.name == name && d.namespace.as_deref() == namespace
            })
        } else {
            lock.deps.iter().find(|d| {
                (d.name == name && d.namespace.is_none())
                    || d.aliases.iter().any(|a| a == name)
            })
        }
    };

    // S1 (#178): iterate BOTH deps and dev_deps — mirrors Python frozen.py:199.
    for mdep in manifest.deps.iter().chain(manifest.dev_deps.iter()) {
        let name = mdep.name();
        // C1: extract namespace for qualified named deps.
        let namespace = if let milpa_manifest::Dep::Named(n) = mdep {
            n.namespace.as_deref()
        } else {
            None
        };
        let Some(locked) = find_locked(name, namespace) else {
            let key = dep_dir_name(name, namespace);
            return Err(frozen(
                "FROZEN-MANIFEST-DEP-NOT-IN-LOCK",
                format!("manifest dep {key:?} has no lockfile entry (re-run `milpa fetch`)"),
            ));
        };
        if let Dep::Named(n) = mdep {
            if let Some(vset) = &n.parsed_constraint {
                // Constraint was validated at parse time (MAN-DEP-NAMED-CONSTRAINT).
                // Use the pre-parsed VersionSet directly — no re-parse needed.
                let Some(locked_version) = parse_version(&locked.version) else {
                    return Err(frozen(
                        "FROZEN-LOCKED-VERSION-UNPARSEABLE",
                        format!(
                            "dep {name:?}: locked version {:?} is not a parseable X.Y.Z version",
                            locked.version
                        ),
                    ));
                };
                if !vset.contains(&locked_version) {
                    return Err(frozen(
                        "FROZEN-CONSTRAINT-UNSATISFIED",
                        format!(
                            "dep {name:?}: locked version {} no longer satisfies manifest constraint {:?}",
                            locked.version,
                            n.constraint.as_deref().unwrap_or("any")
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Rebuild a [`ResolvedDep`] from a [`LockedDep`], deriving the transport
/// provenance from the first record. `Member`/`Local` are unreachable here (they bail above).
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
    // D-lifecycle: validate the first provenance (observed), then carry ALL provenances.
    // The first provenance is checked for missing guard; all are carried.
    let _check = provenance_from_record(locked.provenances.first(), &locked.name)?;
    Ok(ResolvedDep {
        name: locked.name.clone(),
        namespace: locked.namespace.clone(), // C1: carry namespace for qualified deps
        identity: locked.identity.clone().unwrap_or_default(),
        version,
        src_dir: locked.src_dir.clone(),
        requires: locked.requires.clone(),
        // D-lifecycle: carry all provenances (observed + declared mirrors) through
        // the frozen path so D-frozen can use the plural model without data-model change.
        provenances: locked.provenances.clone(),
        dep_decl: locked.dep_decl.clone(), // S6: carry dep_decl pin through frozen path
        // S4: frozen path reconstructs from lockfile; cond_requires are lockfile
        // annotations only — not needed for frozen graph reconstruction.
        cond_requires: Vec::new(),
        // Phase B: frozen path carries aliases from the lockfile for verification.
        // The aliases are read back from LockedDep.aliases during verify.
        aliases: locked.aliases.clone(),
        // S5: frozen path carries active_flags from the lockfile.
        active_flags: locked.active_flags.clone(),
        // RFC per-entry-attestation.md P2 (§8 Command Coverage): the frozen
        // path carries the lockfile's attestation CLAIM through, nothing
        // re-checked. Widen LockAttestation (no bundle_pin) back to the
        // EntryAttestation shape ResolvedDep carries; bundle_pin is always
        // None here since it was never persisted to the lockfile (§3.9).
        attestation: locked.attestation.as_ref().map(|a| EntryAttestation {
            kind: a.kind.clone(),
            rekor: a.rekor.clone(),
            bundle_pin: None,
        }),
    })
}

/// The emission-level provenance record for a resolved dep — `ResolvedDep` now
/// carries the record directly, so this is the lockfile record itself. A missing
/// record is a malformed lockfile dep. `Member` passes through (workspace-frozen
/// members keep their member record); single-package `Local`/`Member` bail before here.
fn provenance_from_record(
    record: Option<&ProvenanceRecord>,
    name: &str,
) -> Result<ProvenanceRecord, MilpaError> {
    match record {
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
