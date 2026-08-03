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

use milpa_manifest::{Dep, Manifest, Override, OverrideTarget, Resolution};
use milpa_solver::{parse_version, Strategy};
use milpa_types::{
    DepKey, EntryAttestation, FetchableOrigin, LockedDep, Lockfile, ProvenanceRecord, ResolvedDep,
    ResolvedGraph, SourceId, Timestamp,
};

use crate::error::{CoreError, MilpaError};
use crate::registry::Index;
use crate::source_id::format_source_id;
use crate::store::CaStore;
use crate::workspace::LoadedWorkspace;

fn frozen(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::Frozen(code, message.into()))
}

/// Reconstruct a [`ResolvedGraph`] from `manifest` + `lock` + `store` — no
/// network, no fetcher. The requested strategy is the manifest's EFFECTIVE
/// `resolution { strategy }` (C3b — [`frozen_baseline_strategy`]), default
/// `maxver` when absent; the `Resolver`/`FrozenResolver` trait surface
/// carries no CLI strategy override (that is the CLI's concern, S13).
/// Returns a coded `FROZEN-*` error on any precondition failure.
pub fn resolve_frozen(
    manifest: &Manifest,
    lock: &Lockfile,
    store: &CaStore,
    deps_dir: &Path,
) -> Result<ResolvedGraph, MilpaError> {
    check_strategy(frozen_baseline_strategy(manifest.resolution), lock)?;
    check_exclude_newer(frozen_baseline_exclude_newer(manifest.resolution), lock)?;
    check_manifest_alignment(manifest, lock)?;
    // RFC origin-as-identity.md §7.1 D2/D3 (S5): FROZEN-REGISTRY-ALIAS-
    // UNRESOLVED (checked first) + FROZEN-SOURCE-ID-MISMATCH (declared-
    // AFTER-override). SSOT wrapper also used by `milpa verify` (main.rs).
    check_source_id_preconditions_standalone(manifest, &lock.deps)?;

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
            Some(ProvenanceRecord::Root { .. }) => {
                // §14.5: the root-self entry is never fetched and carries no
                // separate identity (None) — the CAS-presence check does not
                // apply to it (it is never IN the store to begin with, by
                // design). Skip straight to reconstruction, same as a
                // workspace member skips it in `resolve_workspace_frozen` below.
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
    // RFC origin-as-identity.md §4.6 (S6, "F4" frozen-path reachability): the
    // directory-slot import floor runs here too — no BindingResolver protects
    // a lockfile reconstructed straight off disk, so this check must not wait
    // for a later slice's structured on-disk source. See
    // lockfile::check_directory_slot_collisions's doc comment for why it
    // needs no new source_id plumbing to cover this path today.
    let graph = ResolvedGraph { deps: resolved };
    // S7 (rfc-origin-as-identity.md §4.6): the complete, symbol-level check —
    // runs the S6 directory-slot floor internally as its own pre-filter.
    // live_symbol_provider() is manifest_declared fidelity ONLY — see its
    // own doc comment for the v1 scope rationale.
    crate::import_slot::check_import_slot_collisions(&graph, &crate::import_slot::live_symbol_provider(), Some(store))?;
    // B-nimcfg: use rebuild_deps_view (SSOT) to create canonical + alias symlinks
    // and remove stale entries atomically.
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
    check_strategy(frozen_baseline_strategy(workspace.resolution), lock)?;
    check_exclude_newer(frozen_baseline_exclude_newer(workspace.resolution), lock)?;
    for member in &workspace.members {
        check_manifest_alignment(&member.manifest, lock)?;
    }
    // RFC origin-as-identity.md §7.1 D2/D3 (S5): FROZEN-REGISTRY-ALIAS-
    // UNRESOLVED (checked first) + FROZEN-SOURCE-ID-MISMATCH (declared-
    // AFTER-override). SSOT wrapper also used by `milpa verify` (main.rs).
    check_source_id_preconditions_workspace(workspace, &lock.deps)?;

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
            Some(ProvenanceRecord::Root { .. }) => {
                // §14.5: a root-self entry is a standalone-only concept and
                // is not expected in a workspace lockfile, but if present it
                // is never fetched and carries no identity — skip the
                // CAS-presence check the same way as the single-package path.
                resolved.push(resolved_from_locked(locked)?);
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
    // RFC origin-as-identity.md §4.6 (S6, "F4"): see resolve_frozen's
    // identical hook above. S7: check_import_slot_collisions runs the S6
    // floor internally; live_symbol_provider() is manifest_declared fidelity
    // ONLY — see its own doc comment for the v1 scope rationale.
    let graph = ResolvedGraph { deps: resolved };
    crate::import_slot::check_import_slot_collisions(&graph, &crate::import_slot::live_symbol_provider(), Some(store))?;
    // B-nimcfg: use rebuild_deps_view (SSOT) for atomic _deps/ rebuild.
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

/// C3b (resolution-semantics RFC §3 Axis C / §6 D-C2, §7 C3b): the
/// `FROZEN-STRATEGY-MISMATCH` baseline.
///
/// NOT a hardcoded `Strategy::default()` (`maxver`) — the manifest's
/// *effective* `resolution { strategy }` (default `maxver` when the block
/// is absent or declared without a `strategy` child). This deliberately
/// mirrors only tiers 2 (manifest) + 3 (global default) of the CLI's
/// `resolve_effective_strategy` precedence chain (`milpa-cli/src/main.rs`)
/// — there is no CLI `--strategy` tier here (the frozen path has no such
/// surface). R9 (resolution-semantics RFC §3 Axis C NORMATIVE): the CLI's
/// `resolve_effective_strategy` has no lockfile-prior tier at all anymore
/// (the lockfile-recorded strategy is diagnostic/frozen-parity only, never
/// a live input) — which is exactly what this baseline always needed: the
/// frozen path's "prior" IS the very lockfile this baseline gets compared
/// against, so a lockfile-prior tier would have made the mismatch check
/// compare the lockfile's strategy to itself and never fire.
fn frozen_baseline_strategy(resolution: Option<Resolution>) -> Strategy {
    resolution.and_then(|r| r.strategy).unwrap_or_default()
}

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

/// D5 (resolution-semantics RFC §3 Axis D / §7 D5): the
/// `FROZEN-EXCLUDE-NEWER-MISMATCH` baseline. Mirrors
/// [`frozen_baseline_strategy`] EXACTLY — built manifest-sourced from the
/// start (the manifest's effective `resolution { exclude-newer }`, default
/// `None` when absent), never a hardcoded literal. The frozen path has no
/// CLI `--exclude-newer` surface (that flag is fetch/lock-only, §3 Axis D
/// "Verb reach") and no third (lockfile) precedence tier — the very
/// lockfile this baseline gets compared against IS the "prior" here, so
/// there is nothing to fall back to beyond the manifest.
fn frozen_baseline_exclude_newer(resolution: Option<Resolution>) -> Option<Timestamp> {
    resolution.and_then(|r| r.exclude_newer)
}

/// D5: compare the lockfile's recorded `exclude_newer` against the
/// manifest-sourced baseline. Mismatch (in either direction — a newly
/// unset manifest bound with a lock still recording one, a newly set
/// manifest bound with no matching lock record, or two genuinely
/// different timestamps) raises `FROZEN-EXCLUDE-NEWER-MISMATCH`.
fn check_exclude_newer(baseline: Option<Timestamp>, lock: &Lockfile) -> Result<(), MilpaError> {
    if baseline != lock.exclude_newer {
        return Err(frozen(
            "FROZEN-EXCLUDE-NEWER-MISMATCH",
            format!(
                "exclude-newer mismatch: lockfile recorded {:?}, requested {:?}; \
                 re-run 'milpa fetch' with the desired exclude-newer to regenerate \
                 the lockfile",
                lock.exclude_newer, baseline
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

// ---------------------------------------------------------------------------
// S5 — FROZEN-SOURCE-ID-MISMATCH / FROZEN-REGISTRY-ALIAS-UNRESOLVED
// (rfc-origin-as-identity.md §7.1 D2/D3). Mirrors Python's `frozen.py`
// `_source_id_matches_declared` / `_check_source_id_preconditions` /
// `check_source_id_preconditions_standalone` / `check_source_id_preconditions_workspace`.
// ---------------------------------------------------------------------------

/// Field-wise comparison for `FROZEN-SOURCE-ID-MISMATCH` (RFC
/// origin-as-identity.md §7.1 D2).
///
/// Plain equality for every kind EXCEPT `Registry` with an unqualified
/// (bare) manifest declaration: the frozen path has no live tianguis index
/// to resolve a bare name's real namespace (unlike a live resolve, which
/// calls `resolved_registry_namespace`), so the *namespace* component is
/// not compared when the manifest declaration itself carried no explicit
/// qualifier — only the registry alias and name (both knowable without an
/// index). An EXPLICITLY-qualified declaration still gets a full
/// three-field comparison.
fn source_id_matches_declared(declared: &SourceId, locked: &SourceId) -> bool {
    if let (
        SourceId::Fetchable(FetchableOrigin::Registry { registry: dr, namespace: dns, name: dn }),
        SourceId::Fetchable(FetchableOrigin::Registry { registry: lr, namespace: lns, name: ln }),
    ) = (declared, locked)
    {
        if dr != lr || dn != ln {
            return false;
        }
        return match dns {
            Some(ns) => Some(ns) == lns.as_ref(),
            None => true,
        };
    }
    declared == locked
}

/// `FROZEN-REGISTRY-ALIAS-UNRESOLVED` (checked FIRST, short-circuits) +
/// `FROZEN-SOURCE-ID-MISMATCH` (declared-AFTER-override) — RFC
/// origin-as-identity.md §7.1 D2/D3.
///
/// Scope (normative): only locked deps that correspond to a
/// ROOT-authoritative claim (an ordinary manifest dep declaration, or an
/// `overrides {}` target) are checked — a purely transitive dep's "real"
/// declaration lives inside another dep's fetched manifest, which the
/// frozen path never re-reads. Workspace-member and standalone-root-self
/// entries (`SourceId::Member`) are likewise skipped — W1-W5
/// conflict-free-by-construction, no manifest "declared origin" concept
/// applies.
///
/// Reuses `binding::reconcile_root_claims` — the SAME override-application
/// helper `BindingResolver::new` uses — so an `overrides {}`-redirected dep
/// is compared against its override TARGET, never its raw declaration. No
/// live tianguis index is needed (or used) here: an empty `Index::default()`
/// makes a bare name's `resolved_registry_namespace` lookup return `None`,
/// and `source_id_matches_declared` skips that ONE component for an
/// unqualified declaration rather than requiring a real index (the frozen
/// path never fetches / never loads one).
fn check_source_id_preconditions(
    declared_deps: &[Dep],
    overrides: &[Override],
    lockfile_deps: &[LockedDep],
) -> Result<(), MilpaError> {
    let index = Index::default();
    let declared_claims = crate::binding::reconcile_root_claims(declared_deps, overrides, &index)?;
    let mut declared_by_key: std::collections::BTreeMap<DepKey, SourceId> =
        std::collections::BTreeMap::new();
    for c in &declared_claims {
        declared_by_key.insert(DepKey::from_solver_var(&c.name), c.source_id.clone());
    }

    for locked in lockfile_deps {
        let Some(locked_sid) = &locked.source_id else {
            continue; // pre-S5 lockfile — nothing to check (forward-compat)
        };

        // D3: FROZEN-REGISTRY-ALIAS-UNRESOLVED is checked FIRST and
        // short-circuits — an unresolved alias must never be misreported as
        // a coordinate mismatch (the comparison below is not even attempted).
        if let SourceId::Fetchable(FetchableOrigin::Registry { registry, .. }) = locked_sid {
            if registry != crate::binding::DEFAULT_REGISTRY_ALIAS {
                return Err(frozen(
                    "FROZEN-REGISTRY-ALIAS-UNRESOLVED",
                    format!(
                        "dep {:?}: lockfile references registry alias {registry:?}, which is \
                         not configured on this machine (known: {:?}); the source-id \
                         coordinate cannot be verified — configure the alias or re-run \
                         'milpa fetch'",
                        locked.name,
                        crate::binding::DEFAULT_REGISTRY_ALIAS
                    ),
                ));
            }
        }

        let key = DepKey { name: locked.name.clone(), namespace: locked.namespace.clone() };
        let Some(declared_sid) = declared_by_key.get(&key) else {
            continue; // not a root-authoritative claim at this scope — skip
        };

        if !source_id_matches_declared(declared_sid, locked_sid) {
            return Err(frozen(
                "FROZEN-SOURCE-ID-MISMATCH",
                format!(
                    "dep {:?}: manifest declares {} but the lockfile records {} — the \
                     declared origin was edited without re-fetching; run 'milpa fetch' to \
                     regenerate the lockfile",
                    locked.name,
                    format_source_id(declared_sid),
                    format_source_id(locked_sid),
                ),
            ));
        }
    }
    Ok(())
}

/// Public SSOT wrapper for a standalone (single-package) project — used by
/// both [`resolve_frozen`] and `milpa verify` (`main.rs`'s `cmd_verify`), so
/// the two entry points cannot structurally drift on this check. Mirrors
/// Python's `frozen.check_source_id_preconditions_standalone`.
pub fn check_source_id_preconditions_standalone(
    manifest: &Manifest,
    lockfile_deps: &[LockedDep],
) -> Result<(), MilpaError> {
    let all_deps: Vec<Dep> = manifest.deps.iter().chain(manifest.dev_deps.iter()).cloned().collect();
    let overrides: Vec<Override> = manifest
        .overrides
        .iter()
        .filter(|ov| !matches!(ov.target, OverrideTarget::Member { .. }))
        .cloned()
        .collect();
    check_source_id_preconditions(&all_deps, &overrides, lockfile_deps)
}

/// Public SSOT wrapper for a workspace — used by both
/// [`resolve_workspace_frozen`] and `milpa verify` (`main.rs`'s
/// `cmd_verify`). Mirrors Python's
/// `frozen.check_source_id_preconditions_workspace`.
pub fn check_source_id_preconditions_workspace(
    workspace: &LoadedWorkspace,
    lockfile_deps: &[LockedDep],
) -> Result<(), MilpaError> {
    let members_by_name: std::collections::BTreeSet<&str> =
        workspace.members.iter().map(|m| m.name.as_str()).collect();
    let mut ws_declared_deps: Vec<Dep> = Vec::new();
    for member in &workspace.members {
        for wsd in member.manifest.deps.iter().chain(member.manifest.dev_deps.iter()) {
            if members_by_name.contains(wsd.name()) || matches!(wsd, Dep::Member(_)) {
                continue;
            }
            ws_declared_deps.push(wsd.clone());
        }
    }
    check_source_id_preconditions(&ws_declared_deps, &workspace.overrides, lockfile_deps)
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
        // re-checked (no gate runs here — §8 command-coverage table). P3a:
        // bundle_pin round-trips too (lockfile-schema §3.9 addition) since
        // milpa verify's offline re-verification needs it downstream of a
        // frozen resolve too. Widen LockAttestation back to the
        // EntryAttestation shape ResolvedDep carries.
        attestation: locked.attestation.as_ref().map(|a| EntryAttestation {
            kind: a.kind.clone(),
            rekor: a.rekor.clone(),
            bundle_pin: a.bundle_pin.clone(),
        }),
        // A5: carry the sibling declared-version source straight through —
        // frozen reconstruction re-derives nothing (no solve, no re-fetch).
        declared_version_source: locked.declared_version_source.clone(),
        // RFC origin-as-identity §4.1/§4.4/§7 (S5): the frozen path now
        // threads the lockfile's own structured `source_id` straight onto
        // the reconstructed ResolvedDep — no re-derivation, no parsing, just
        // a direct passthrough of the typed value already on LockedDep. This
        // is what lets check_directory_slot_collisions and milpa verify's
        // offline attestation-subject reconstruction use format_source_id
        // (the typed formatter) on the frozen path too, not just fresh
        // resolves.
        source_id: locked.source_id.clone(),
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
