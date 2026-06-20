//! Resolver orchestration (RFC §6 S7b; spec `spec/resolver-semantics.md`).
//!
//! [`resolve`] is the top-level glue: it walks the manifest's deps, fetches each
//! into `_deps/<name>/`, parses every fetched dep's `milpa.kdl` (or `.nimble`)
//! for transitive requires, hands a [`PackageProvider`] to the solver, and maps
//! the solver's `{name: version}` solution back into a [`ResolvedGraph`].
//!
//! Mirrors `milpa/resolver.py`'s *contract*, not its mechanics. The Python
//! reference fetches in a thread pool; the spec (resolver-semantics §4.4) makes
//! output independent of `-j`, so this reference is **serial** — a strictly more
//! deterministic conformant producer. URL/local/tarball deps are materialized
//! eagerly during BFS; named (index) deps are enumerated as lightweight
//! *stubs* and fetched lazily the first time the solver selects a version (the
//! "two-phase materializing provider"), so per-strategy version selection
//! (resolver-semantics §4.3) fetches only the chosen version.
//!
//! Honored spec rules: identity-singleton convention for URL/local deps (§3),
//! prior-lockfile pin reuse (§8), ordered mirror-fallback / `fetch_any` (§8a),
//! provenance precedence + transitive-override suppression (§10), dev-deps
//! context — root enrolls, transitives exclude (§9), and content-hash
//! dedup/alias (Phase B, #32). Canonical *emission* ordering (lexicographic by
//! name, §4.4) is S7c, applied at the lockfile/nim.cfg boundary; [`resolve`]'s
//! graph is topologically ordered (deps before dependents), matching the Python
//! `_build_graph`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use milpa_manifest::{Dep, LocalDep, Manifest, Override, OverrideTarget, Predicate, Profile, TarballDep, UrlDep};
use milpa_solver::{
    parse_version, solve, solve_with_refutation, vs_to_constraint_str, Dep as SolverDep,
    PackageProvider, RefutationEntry, Strategy, VersionSet,
};
use milpa_types::{EdgeSet, FlagRequest, Lockfile, Provenance, ProvenanceRecord, ResolvedDep, ResolvedGraph, Version};

use crate::edge_sources::{EdgeSourceCtx, NimbleEdgeSource};
use crate::error::{CoreError, MilpaError};
use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::frozen::rebuild_deps_view;
use crate::identity::compute_content_hash;
use crate::lockfile::cond_require_sort_key;
use crate::registry::{Index, IndexVersion};
use crate::store::CaStore;
use crate::workspace::LoadedWorkspace;

/// Canonical version for URL/local/tarball/member deps (resolver-semantics §3):
/// such deps are version-unique by identity, so they enter the solver as a
/// fixed singleton. The exact value is an implementation detail (§3 NOTE).
fn url_dep_version() -> Version {
    Version::release(0, 0, 1)
}

/// The synthetic root candidate's version.
fn root_version() -> Version {
    Version::release(0, 0, 0)
}

/// The synthetic root package name.
const ROOT: &str = "__root__";

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Resolve `manifest` into a topologically-ordered [`ResolvedGraph`].
///
/// `index` is the tianguis index for named-dep resolution (`None` ⇒ an empty
/// index, valid only when the manifest has no un-overridden named deps, else
/// `RES-NO-INDEX`). `fetcher` materializes each dep's bytes; `profile` (when
/// `Some`) filters conditional deps before the solver runs (§6); `prior` enables
/// pin reuse (§8). `strategy` governs per-package version selection (§4.3).
/// `require_attested_metadata` enforces strict attestation policy (S5):
/// when `true` (or when `manifest.attestation_policy == Strict`), any resolved
/// dep sourced from un-attested `.nimble` metadata raises `RES-UNATTESTED-METADATA`.
///
/// `store` is the content-addressed store used to rebuild `_deps/` after
/// resolution completes (B-nimcfg SSOT: alias symlinks + stale-entry removal).
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    manifest: &Manifest,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &Path,
    dep_decl_store: Option<&dyn crate::dep_decl_store::DepDeclStore>,
    require_attested_metadata: bool,
    store: &CaStore,
) -> Result<ResolvedGraph, MilpaError> {
    resolve_with_features(
        manifest, index, fetcher, profile, prior, strategy, deps_dir,
        dep_decl_store, require_attested_metadata, store,
        &std::collections::BTreeSet::new(), false, false,
    )
}

/// Internal: full resolution with optional S9 CLI feature-selection inputs.
///
/// S9 (RFC #23 §3.4): `features` / `no_default_features` / `all_features`
/// compute the root active-flag seed that overrides the default-flag seed when
/// any CLI selection is present.
#[allow(clippy::too_many_arguments)]
pub fn resolve_with_features(
    manifest: &Manifest,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &Path,
    dep_decl_store: Option<&dyn crate::dep_decl_store::DepDeclStore>,
    require_attested_metadata: bool,
    store: &CaStore,
    features: &std::collections::BTreeSet<String>,
    no_default_features: bool,
    all_features: bool,
) -> Result<ResolvedGraph, MilpaError> {
    // S9 (RFC #23 §3.4): compute root CLI active-flag seed when any CLI
    // feature-selection is present. Mirrors Python's _compute_root_active_seed.
    let has_cli_features = !features.is_empty() || no_default_features || all_features;
    let cli_seed: std::collections::HashSet<String> = if has_cli_features {
        let all_declared: std::collections::BTreeSet<String> =
            manifest.flags.iter().map(|f| f.name.clone()).collect();
        // C2 / S9 (spec/cli-contract.md §3.4): validate --features names on the
        // LIVE path too. Mirrors check_frozen_active_flags_mismatch lines 329-336.
        // An undeclared flag name raises FROZEN-ACTIVE-FLAGS-MISMATCH regardless
        // of whether --frozen is set (Python _compute_root_active_seed does this).
        for feat in features.iter() {
            if !all_declared.contains(feat.as_str()) {
                return Err(crate::error::CoreError::Frozen(
                    "FROZEN-ACTIVE-FLAGS-MISMATCH",
                    format!("feature {feat:?} not declared in root manifest's flags block"),
                )
                .into());
            }
        }
        if all_features {
            all_declared.into_iter().collect()
        } else if no_default_features {
            features.iter().cloned().collect()
        } else {
            // defaults ∪ explicit features
            let mut seed: std::collections::HashSet<String> = manifest
                .flags
                .iter()
                .filter(|f| f.default)
                .map(|f| f.name.clone())
                .collect();
            seed.extend(features.iter().cloned());
            seed
        }
    } else {
        std::collections::HashSet::new()
    };

    // C1b-completion: root CLI-selected flags participate in conflict detection
    // (RFC #23 §3.1.4).  The root has no fetched identity so it bypasses the
    // dep_active_flags machinery; use raise_if_flag_conflicts directly with a
    // synthetic active_map where every CLI-active flag has source Cli.  Mirrors
    // Python's root-level check in resolver.py immediately after _cli_active_seed.
    //
    // R2-M C1b fix: apply same-package enables-closure BEFORE the conflict check
    // so that flags enabled transitively by CLI-active root flags are included.
    // Without this, a CLI-active flag A that enables B where B conflicts C
    // (also CLI-active) would be silently missed.  Mirrors Python fix.
    if has_cli_features && !cli_seed.is_empty() && !manifest.flags.is_empty() {
        use milpa_manifest::flag_enables_closure;
        use milpa_types::ActivationSource;
        // Expand cli_seed via same-package enables-closure.
        let cli_closed = flag_enables_closure(&manifest.flags, &cli_seed);
        let mut root_cli_active_map: BTreeMap<String, BTreeSet<ActivationSource>> = cli_seed
            .iter()
            .map(|f| (f.clone(), [ActivationSource::Cli].into_iter().collect()))
            .collect();
        // Flags added only by enables-closure get source EnablesRule.
        for ec_flag in &cli_closed {
            if !cli_seed.contains(ec_flag.as_str()) {
                root_cli_active_map
                    .entry(ec_flag.clone())
                    .or_default()
                    .insert(ActivationSource::EnablesRule);
            }
        }
        let root_name = manifest.name.as_deref().unwrap_or("__root__");
        raise_if_flag_conflicts(root_name, &manifest.flags, &root_cli_active_map)?;
    }

    // §6: filter conditional deps by the active profile before anything else.
    // An absent profile disables filtering entirely (§6 absent-profile rule).
    //
    // S7 (RFC #23 §3.2 + §3.1.2): before filtering, expand `profile.flags`
    // by running flag_enables_closure over the manifest's default-true flags.
    // This ensures optional deps activated via `enables` are visible to the
    // profile's flag predicate check — mirrors Python's _filter_manifest_by_profile.
    let filtered;
    let enriched_profile_storage;
    let manifest = match profile {
        Some(p) => {
            use milpa_manifest::flag_enables_closure;
            use std::collections::HashSet;
            // S9: when CLI features present, override the default seed.
            let seed: HashSet<String> = if has_cli_features {
                cli_seed.clone()
            } else {
                manifest
                    .flags
                    .iter()
                    .filter(|f| f.default)
                    .map(|f| f.name.clone())
                    .collect()
            };
            let active = flag_enables_closure(&manifest.flags, &seed);
            // Merge existing profile.flags with the closure result.
            let mut merged_flags: Vec<String> = p.flags.clone();
            for flag in &active {
                if !merged_flags.contains(flag) {
                    merged_flags.push(flag.clone());
                }
            }
            let mut ep = p.clone();
            ep.flags = merged_flags;
            enriched_profile_storage = ep;
            filtered = filter_manifest_by_profile(manifest, &enriched_profile_storage);
            &filtered
        }
        None if has_cli_features => {
            // resolver-semantics §470 NORMATIVE: when NO profile is supplied,
            // platform/arch/nim/milpa-predicate filtering is DISABLED — every dep
            // is included regardless of those predicates.  Flag predicates are a
            // SEPARATE axis (§489): they still apply based on the active flag set.
            //
            // Previous code synthesised a Profile{platform:None,...} and called
            // filter_manifest_by_profile; predicate_satisfied returns false for
            // platform/arch/nim/milpa when the axis is None ("an absent axis
            // matches nothing"), which PRUNES those deps — a §470 violation.
            //
            // Correct fix: use dep_passes_flag_predicates (SSOT) directly.
            // Non-flag predicates are not evaluated (absent profile = include all).
            // Mirrors Python's _filter_manifest_by_flags_only.
            use milpa_manifest::flag_enables_closure;
            use std::collections::BTreeSet;
            let active_set = flag_enables_closure(&manifest.flags, &cli_seed);
            let active: BTreeSet<&str> = active_set.iter().map(|s| s.as_str()).collect();
            let mut m = manifest.clone();
            m.deps.retain(|d| dep_passes_flag_predicates(d, &active));
            m.dev_deps.retain(|d| dep_passes_flag_predicates(d, &active));
            filtered = m;
            &filtered
        }
        None => manifest,
    };

    // Anchor lifetime for the Index::default() fallback (build_single_provider
    // borrows it; the provider must not outlive this frame).
    let empty_index = Index::default();
    let (mut provider, _strict) = build_single_provider(
        manifest,
        index,
        fetcher,
        deps_dir,
        ProviderOpts { prior, dep_decl_store, require_attested_metadata },
        &empty_index,
    )?;

    // M7: warn early about member= overrides in a single-package manifest.
    // These silently no-op (member overrides require a workspace context); warn
    // before the BFS so the user gets feedback even if resolution fails.
    {
        use milpa_manifest::OverrideTarget as OT;
        let member_override_names: Vec<&str> = manifest
            .overrides
            .iter()
            .filter(|ov| matches!(ov.target, OT::Member { .. }))
            .map(|ov| ov.name.as_str())
            .collect();
        if !member_override_names.is_empty() {
            eprintln!(
                "[milpa] warning: member override(s) {:?} have no effect in a \
                 single-package manifest (member= overrides require a workspace context)",
                member_override_names
            );
        }
    }

    // Build the synthetic root candidate (requires every manifest dep) and the
    // BFS queue. dev_deps for the ROOT are enrolled here alongside deps (§9);
    // transitive deps never read dev_deps.
    let queue = provider.seed_root(manifest)?;
    provider.process_items(queue)?;

    // S4a (RFC #23 §3.1.2 + §7 S4a): outer dep×flag fixpoint.
    // Iterates until neither the dep set nor active_flags grows.
    // PubGrub runs exactly ONCE, after convergence (§3.1.2 NORMATIVE).
    provider.run_s4a_fixpoint()?;

    // S4c (RFC #23 §3.1.4): post-fixpoint flag-conflict validation.
    // Runs AFTER the fixpoint converges, BEFORE finalize/solver entry.
    // Only reads the converged dep_active_flags — never retracts.
    // Raises RESOLVE-FLAG-CONFLICT if any dep has two mutually-exclusive
    // flags co-active in the final converged set.
    provider.check_s4c_flag_conflicts(deps_dir)?;

    // Content-hash dedup/alias for eagerly-materialized candidates (Phase B, #32).
    // Returns canonical → sorted-aliases map for populating ResolvedDep.aliases.
    let canonical_aliases = provider.finalize();

    // Solve over the materialized + stubbed candidate universe.
    let solution = solve(&provider, ROOT, root_version(), strategy)?;

    // A lazy fetch failure during solve is captured (the provider's queries are
    // infallible); surface it in preference to any downstream solver outcome.
    if let Some(e) = provider.take_error() {
        return Err(e);
    }

    // S5: attestation-policy enforcement. Effective policy is the OR of the
    // manifest-declared `attestation-policy "strict"` and the
    // `--require-attested-metadata` CLI flag (flag cannot weaken manifest-strict).
    enforce_attestation_policy(&provider, manifest, require_attested_metadata)?;

    let graph = provider.build_graph(&solution, &canonical_aliases);

    // S8a: non-reproducible override warning (RFC #23 §3.3 reproducibility carve-out).
    // A local= override produces a LocalProvenanceRecord for a dep that was declared
    // as git/named — non-reproducible for anyone without the same sibling checkout.
    {
        use milpa_manifest::OverrideTarget as OT;
        let local_override_names: Vec<&str> = manifest
            .overrides
            .iter()
            .filter(|ov| matches!(ov.target, OT::Local { .. }))
            .filter(|ov| graph.deps.iter().any(|d| d.name == ov.name))
            .map(|ov| ov.name.as_str())
            .collect();
        if !local_override_names.is_empty() {
            eprintln!(
                "[milpa] warning: non-reproducible local override(s): {} — \
                 lockfile will not reproduce on machines without the same local \
                 checkouts at the declared relative paths (RFC #23 §3.3 reproducibility carve-out)",
                local_override_names.join(", ")
            );
        }
    }

    // M6: warn about overrides that name a dep not in the resolved graph.
    // A typo in an override name silently no-ops without this check.
    {
        let resolved_dep_names: std::collections::BTreeSet<&str> =
            graph.deps.iter().map(|d| d.name.as_str()).collect();
        let dead_override_names: Vec<&str> = manifest
            .overrides
            .iter()
            .filter(|ov| !resolved_dep_names.contains(ov.name.as_str()))
            .map(|ov| ov.name.as_str())
            .collect();
        if !dead_override_names.is_empty() {
            eprintln!(
                "[milpa] warning: override(s) {:?} name dep(s) not present in the \
                 resolved graph — check for typos in override names",
                dead_override_names
            );
        }
    }

    // B-nimcfg SSOT: rebuild _deps/ view (alias symlinks + stale-entry removal).
    // Mirrors resolve_frozen (frozen.rs:96) — the live path now owns the rebuild
    // internally, symmetric with the frozen path and Python's resolver.resolve().
    rebuild_deps_view(&graph, deps_dir, store);
    Ok(graph)
}

/// The reference [`Resolver`](crate::Resolver) entry point delegates here with
/// the default strategy (resolver-semantics §4.3 — `maxver`). The strategy
/// override surface (CLI flag / env) lands with the CLI (S13).
pub(crate) fn resolve_default_strategy(
    manifest: &Manifest,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    deps_dir: &Path,
    store: &CaStore,
) -> Result<ResolvedGraph, MilpaError> {
    resolve(
        manifest,
        index,
        fetcher,
        profile,
        prior,
        Strategy::default(),
        deps_dir,
        None, // dep_decl_store: None (trait path, no dep-decl support)
        false, // require_attested_metadata: false (trait path, no S5 flag)
        store,
    )
}

/// S9 (RFC #23 §3.4): FROZEN-ACTIVE-FLAGS-MISMATCH check.
///
/// Recomputes the root active-flag closure from `manifest` + CLI inputs
/// (`features`, `no_default_features`, `all_features`).  Then checks whether
/// any flag-gated root dep is admitted by the computed closure but absent from
/// the lockfile, or vice-versa.  Raises `FROZEN-ACTIVE-FLAGS-MISMATCH` on
/// mismatch or when a `--features` name is not declared in the manifest.
///
/// Mirrors Python `cli._check_frozen_active_flags_mismatch`.
///
/// Computes the active-flag closure from `manifest` + CLI inputs and compares it
/// against the lockfile: if a flag-gated root dep is admitted by the computed
/// closure but absent from the lock (or vice versa), returns
/// `FROZEN-ACTIVE-FLAGS-MISMATCH`.
///
/// When no CLI features are supplied (empty `features`, `no_default_features=false`,
/// `all_features=false`), the default-true flag set is used as the seed — this
/// catches the case where manifest defaults changed since the lock was written.
/// The flag-admission decision is routed through `dep_passes_flag_predicates`
/// (the SSOT for flag-predicate evaluation).
pub fn check_frozen_active_flags_mismatch(
    manifest: &Manifest,
    lock: &Lockfile,
    features: &std::collections::BTreeSet<String>,
    no_default_features: bool,
    all_features: bool,
) -> Result<(), MilpaError> {
    use milpa_manifest::flag_enables_closure;
    use std::collections::{BTreeSet, HashSet};

    // Compute the CLI active-flag seed (same logic as _compute_root_active_seed).
    let all_declared: HashSet<String> = manifest.flags.iter().map(|f| f.name.clone()).collect();

    // Validate that every explicit feature name is declared in the manifest.
    for feat in features.iter() {
        if !all_declared.contains(feat) {
            return Err(crate::error::CoreError::Frozen(
                "FROZEN-ACTIVE-FLAGS-MISMATCH",
                format!("feature {feat:?} not declared in root manifest's flags block"),
            ).into());
        }
    }

    // Compute the seed: CLI-supplied features override defaults; absent CLI
    // selection falls back to default-true flags (catches manifest-default changes).
    let seed: HashSet<String> = if all_features {
        all_declared.clone()
    } else if no_default_features {
        features.iter().cloned().collect()
    } else {
        // Default seed: default-true flags ∪ explicit CLI features.
        let mut s: HashSet<String> = manifest
            .flags
            .iter()
            .filter(|f| f.default)
            .map(|f| f.name.clone())
            .collect();
        s.extend(features.iter().cloned());
        s
    };

    let active_set: HashSet<String> = flag_enables_closure(&manifest.flags, &seed);
    // Convert to BTreeSet<&str> for dep_passes_flag_predicates (SSOT).
    let active: BTreeSet<&str> = active_set.iter().map(|s| s.as_str()).collect();

    // Build the set of names in the lockfile.
    let locked_names: HashSet<String> = lock.deps.iter().map(|d| d.name.clone()).collect();

    // Check each root dep — route admission decision through the SSOT.
    for dep in &manifest.deps {
        // dep_passes_flag_predicates skips non-flag predicates; deps with no
        // flag predicates always pass (vacuously true conjunction).
        let has_flag_pred = dep.predicates().iter().any(|p| p.name == "flag");
        if !has_flag_pred {
            continue;
        }
        let admitted = dep_passes_flag_predicates(dep, &active);
        let in_lock = locked_names.contains(dep.name());
        if admitted != in_lock {
            return Err(crate::error::CoreError::Frozen(
                "FROZEN-ACTIVE-FLAGS-MISMATCH",
                format!(
                    "frozen: lockfile active-flags mismatch for dep {:?}: \
                     the lock was produced under a different feature selection \
                     — re-run 'milpa fetch' with the same --features / \
                     --no-default-features / --all-features flags that were used \
                     to write the lock",
                    dep.name()
                ),
            ).into());
        }
    }
    Ok(())
}

/// S2 (RFC: workspace-completion §3.A / Breadth-P1b): workspace analog of
/// [`check_frozen_active_flags_mismatch`].
///
/// For each member in the workspace, recomputes the active-flag closure using
/// the member's own flags + the workspace-root CLI seed.  If a flag-gated member
/// dep's admission status disagrees with the lockfile (admitted-but-absent or
/// excluded-but-present), raises `FROZEN-ACTIVE-FLAGS-MISMATCH`.
///
/// Called from the conformance runner's workspace-frozen path BEFORE
/// `resolve_workspace_frozen` so the correct slug fires rather than
/// `FROZEN-MANIFEST-DEP-NOT-IN-LOCK`.  Per `cli-contract.md:318-325`,
/// workspaces are NOT exempt from this check.
pub fn check_workspace_frozen_active_flags_mismatch(
    workspace: &crate::workspace::LoadedWorkspace,
    lock: &crate::Lockfile,
    features: &std::collections::BTreeSet<String>,
    no_default_features: bool,
    all_features: bool,
) -> Result<(), MilpaError> {
    use milpa_manifest::flag_enables_closure;
    use std::collections::HashSet;

    // Compute the workspace-root cli_seed (same logic as resolve_workspace_with_features).
    let has_ws_cli_features = !features.is_empty() || no_default_features || all_features;
    let ws_cli_seed: Option<HashSet<String>> = if has_ws_cli_features {
        let all_declared: HashSet<String> = workspace.flags.iter().map(|f| f.name.clone()).collect();
        for feat in features.iter() {
            if !all_declared.contains(feat.as_str()) {
                return Err(crate::error::CoreError::Frozen(
                    "FROZEN-ACTIVE-FLAGS-MISMATCH",
                    format!("feature {feat:?} not declared in workspace root flags block"),
                ).into());
            }
        }
        let seed: HashSet<String> = if all_features {
            all_declared
        } else if no_default_features {
            features.iter().cloned().collect()
        } else {
            let mut s: HashSet<String> = workspace.flags.iter().filter(|f| f.default).map(|f| f.name.clone()).collect();
            s.extend(features.iter().cloned());
            s
        };
        Some(seed)
    } else {
        // No CLI features — use workspace root defaults as seed.
        let default_seed: HashSet<String> = workspace.flags.iter().filter(|f| f.default).map(|f| f.name.clone()).collect();
        if default_seed.is_empty() { None } else { Some(default_seed) }
    };

    let locked_names: HashSet<String> = lock.deps.iter().map(|d| d.name.clone()).collect();

    for member in &workspace.members {
        // Compute per-member active set from member's own flags + ws_cli_seed.
        let member_active: HashSet<String> = if let Some(ref seed) = ws_cli_seed {
            flag_enables_closure(&member.manifest.flags, seed)
        } else {
            HashSet::new()
        };
        let member_active_set: std::collections::BTreeSet<&str> =
            member_active.iter().map(|s| s.as_str()).collect();

        for dep in member.manifest.deps.iter().chain(member.manifest.dev_deps.iter()) {
            let has_flag_pred = dep.predicates().iter().any(|p| p.name == "flag");
            if !has_flag_pred {
                continue;
            }
            let dep_name = dep.name();
            let admitted = dep_passes_flag_predicates(dep, &member_active_set);
            let in_lock = locked_names.contains(dep_name);
            if admitted != in_lock {
                return Err(crate::error::CoreError::Frozen(
                    "FROZEN-ACTIVE-FLAGS-MISMATCH",
                    format!(
                        "workspace member {:?}: frozen lockfile active-flags mismatch \
                         for dep {dep_name:?}: the lock was produced under a different \
                         feature selection — re-run 'milpa fetch' with the same \
                         --features flags that were used to write the lock",
                        member.name,
                    ),
                ).into());
            }
        }
    }
    Ok(())
}

/// Resolve a loaded workspace into one shared [`ResolvedGraph`] (resolver §11).
///
/// Members appear as `ProvenanceRecord::Member` deps whose identity is the
/// content hash of their on-disk directory (never fetched); external deps from
/// all members resolve once each through the same machinery as [`resolve`]. A
/// member-named dep (direct `member "X"` or a bare named dep matching a member)
/// auto-coerces to the in-tree member. Workspace-level checks: `RES-WS-NO-INDEX`,
/// `RES-WS-OVERRIDE-MEMBER-COLLISION`, `RES-WS-MEMBER-REF-UNKNOWN`.
///
/// `require_attested_metadata` activates strict attestation policy (S5, §13.1).
/// Effective workspace policy = logical OR of `require_attested_metadata` and any
/// member manifest's `attestation-policy "strict"` declaration (§13.1 workspace rule).
///
/// `store` is the content-addressed store used to rebuild `_deps/` after
/// resolution completes (B-nimcfg SSOT: alias symlinks + stale-entry removal).
#[allow(clippy::too_many_arguments)]
/// Resolve a workspace with optional S9 CLI feature-selection inputs.
///
/// S1 (RFC: workspace-completion §3.A): `features` / `no_default_features` /
/// `all_features` compute the workspace-root active-flag seed that will be
/// threaded into `seed_workspace`.  Today (S1) these are plumbed through the
/// call chain to make the workspace seed-path arm reachable; S2 wires the arm
/// into the member-dep filter.
#[allow(clippy::too_many_arguments)]
pub fn resolve_workspace_with_features(
    workspace: &LoadedWorkspace,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &Path,
    require_attested_metadata: bool,
    store: &CaStore,
    features: &std::collections::BTreeSet<String>,
    no_default_features: bool,
    all_features: bool,
) -> Result<ResolvedGraph, MilpaError> {
    // Compute workspace-root cli_seed (mirrors resolve_with_features logic).
    use std::collections::HashSet;
    let has_ws_cli_features = !features.is_empty() || no_default_features || all_features;
    let ws_cli_seed: Option<HashSet<String>> = if has_ws_cli_features {
        let all_declared: HashSet<String> = workspace
            .flags
            .iter()
            .map(|f| f.name.clone())
            .collect();
        // Validate feature names against workspace root flags.
        for feat in features.iter() {
            if !all_declared.contains(feat.as_str()) {
                return Err(crate::error::CoreError::Frozen(
                    "FROZEN-ACTIVE-FLAGS-MISMATCH",
                    format!("feature {feat:?} not declared in workspace root flags block"),
                )
                .into());
            }
        }
        let seed: HashSet<String> = if all_features {
            all_declared
        } else if no_default_features {
            features.iter().cloned().collect()
        } else {
            let mut s: HashSet<String> = workspace
                .flags
                .iter()
                .filter(|f| f.default)
                .map(|f| f.name.clone())
                .collect();
            s.extend(features.iter().cloned());
            s
        };
        Some(seed)
    } else {
        None
    };

    resolve_workspace_inner(
        workspace, index, fetcher, profile, prior, strategy, deps_dir,
        require_attested_metadata, store, ws_cli_seed.as_ref(),
    )
}

/// `resolve_workspace` without feature-selection inputs (backward-compat wrapper).
///
/// Delegates to [`resolve_workspace_with_features`] with all feature inputs zeroed.
#[allow(clippy::too_many_arguments)]
pub fn resolve_workspace(
    workspace: &LoadedWorkspace,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &Path,
    require_attested_metadata: bool,
    store: &CaStore,
) -> Result<ResolvedGraph, MilpaError> {
    resolve_workspace_inner(
        workspace, index, fetcher, profile, prior, strategy, deps_dir,
        require_attested_metadata, store,
        None, // ws_cli_seed: no feature selection inputs
    )
}

/// Resolve a workspace and also build a §5 result certificate (S8,
/// RFC: workspace-completion §3.E).
///
/// Mirrors [`resolve_workspace_with_features`] exactly, but uses
/// `solve_with_refutation` so both success and `SOLVE-CONFLICT` paths
/// produce the appropriate certificate (matching the single-package
/// [`resolve_with_cert`] pattern).
///
/// On success returns `Ok((graph, cert))`.
/// On `SOLVE-CONFLICT` returns `Err((err, failure_cert))`.
/// On any other error (seed/fetch/index/attestation) returns
/// `Err((err, FailureCert { empty }))` — the cert is only written when the
/// resolver ran far enough to produce one.
#[allow(clippy::too_many_arguments)]
pub fn resolve_workspace_with_cert(
    workspace: &LoadedWorkspace,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &Path,
    require_attested_metadata: bool,
    store: &CaStore,
    features: &std::collections::BTreeSet<String>,
    no_default_features: bool,
    all_features: bool,
) -> Result<(ResolvedGraph, SuccessCert), (MilpaError, FailureCert)> {
    // Macro: wrap a plain MilpaError in the cert-failure pair with an empty
    // FailureCert (the cert only carries meaning for SOLVE-CONFLICT).
    macro_rules! lift_err {
        ($e:expr) => {
            return Err(($e, FailureCert { message: String::new(), refutation: Vec::new() }))
        };
    }

    // Compute workspace-root cli_seed (same as resolve_workspace_with_features).
    use std::collections::HashSet;
    let has_ws_cli_features = !features.is_empty() || no_default_features || all_features;
    let ws_cli_seed: Option<HashSet<String>> = if has_ws_cli_features {
        let all_declared: HashSet<String> = workspace
            .flags
            .iter()
            .map(|f| f.name.clone())
            .collect();
        for feat in features.iter() {
            if !all_declared.contains(feat.as_str()) {
                lift_err!(crate::error::CoreError::Frozen(
                    "FROZEN-ACTIVE-FLAGS-MISMATCH",
                    format!("feature {feat:?} not declared in workspace root flags block"),
                ).into());
            }
        }
        let seed: HashSet<String> = if all_features {
            all_declared
        } else if no_default_features {
            features.iter().cloned().collect()
        } else {
            let mut s: HashSet<String> = workspace
                .flags
                .iter()
                .filter(|f| f.default)
                .map(|f| f.name.clone())
                .collect();
            s.extend(features.iter().cloned());
            s
        };
        Some(seed)
    } else {
        None
    };

    let overrides: BTreeMap<String, Override> = workspace
        .overrides
        .iter()
        .map(|o| (o.name.clone(), o.clone()))
        .collect();
    let members_by_name: BTreeSet<String> =
        workspace.members.iter().map(|m| m.name.clone()).collect();

    // Pre-solve workspace validation (same as resolve_workspace_inner).
    let mut collisions: Vec<&str> = overrides
        .iter()
        .filter(|(n, ov)| {
            members_by_name.contains(n.as_str())
                && !matches!(ov.target, OverrideTarget::Member { .. })
        })
        .map(|(n, _)| n.as_str())
        .collect();
    if !collisions.is_empty() {
        collisions.sort();
        lift_err!(res_err(
            "RES-WS-OVERRIDE-MEMBER-COLLISION",
            format!(
                "workspace override name(s) {collisions:?} also appear as workspace member(s) \
                 — remove either the override or the member; cannot have both"
            ),
        ));
    }

    for member in &workspace.members {
        for dep in member.manifest.deps.iter().chain(member.manifest.dev_deps.iter()) {
            if let Dep::Member(md) = dep {
                if !members_by_name.contains(&md.name) {
                    lift_err!(res_err(
                        "RES-WS-MEMBER-REF-UNKNOWN",
                        format!(
                            "workspace member {:?} references `member {:?}` but no such member exists",
                            member.name, md.name
                        ),
                    ));
                }
            }
        }
    }

    let empty_index = Index::default();
    let index_ref: &Index = match index {
        Some(i) => i,
        None => {
            let unresolvable: Vec<&str> = workspace
                .members
                .iter()
                .flat_map(|m| m.manifest.deps.iter().chain(m.manifest.dev_deps.iter()))
                .filter(|d| {
                    matches!(d, Dep::Named(_))
                        && !overrides.contains_key(d.name())
                        && !members_by_name.contains(d.name())
                })
                .map(Dep::name)
                .collect();
            if !unresolvable.is_empty() {
                lift_err!(res_err(
                    "RES-WS-NO-INDEX",
                    format!(
                        "workspace has named dep(s) {unresolvable:?} but no tianguis index \
                         was provided"
                    ),
                ));
            }
            &empty_index
        }
    };

    if let Err(e) = std::fs::create_dir_all(deps_dir).map_err(io_err) {
        lift_err!(e);
    }

    let ws_is_strict = workspace_any_member_strict(workspace) || require_attested_metadata;

    let mut provider = ResolveProvider::new(
        fetcher,
        index_ref,
        deps_dir.to_path_buf(),
        overrides,
        prior,
        None,
        ws_is_strict,
    );

    match provider.seed_workspace(workspace, profile, ws_cli_seed.as_ref()) {
        Ok(queue) => {
            if let Err(e) = provider.process_items(queue) { lift_err!(e); }
        }
        Err(e) => lift_err!(e),
    }
    if let Err(e) = provider.run_s4a_fixpoint() { lift_err!(e); }
    if let Err(e) = provider.check_s4c_flag_conflicts(deps_dir) { lift_err!(e); }
    let canonical_aliases_ws = provider.finalize();

    // Use solve_with_refutation so SOLVE-CONFLICT yields a populated FailureCert.
    match solve_with_refutation(&provider, ROOT, root_version(), strategy) {
        Ok(solution) => {
            if let Some(e) = provider.take_error() { lift_err!(e); }
            if let Err(e) = enforce_attestation_policy_strict(&provider, ws_is_strict) {
                lift_err!(e);
            }
            let cert = provider.build_success_cert(&solution);
            let graph = provider.build_graph(&solution, &canonical_aliases_ws);
            rebuild_deps_view(&graph, deps_dir, store);
            Ok((graph, cert))
        }
        Err((solver_err, refutation)) => {
            let message = solver_err.to_string();
            Err((
                MilpaError::Solver(solver_err),
                FailureCert { message, refutation },
            ))
        }
    }
}

/// Inner implementation for both `resolve_workspace` and
/// `resolve_workspace_with_features`.
///
/// `ws_cli_seed`: workspace-root active-flag seed (pre-computed by the
/// `_with_features` wrapper from CLI inputs); `None` = no CLI features.
/// Threaded into `seed_workspace` so S2 can wire the flag-only arm.
#[allow(clippy::too_many_arguments)]
fn resolve_workspace_inner(
    workspace: &LoadedWorkspace,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &Path,
    require_attested_metadata: bool,
    store: &CaStore,
    ws_cli_seed: Option<&std::collections::HashSet<String>>,
) -> Result<ResolvedGraph, MilpaError> {
    let overrides: BTreeMap<String, Override> = workspace
        .overrides
        .iter()
        .map(|o| (o.name.clone(), o.clone()))
        .collect();
    let members_by_name: BTreeSet<String> =
        workspace.members.iter().map(|m| m.name.clone()).collect();

    // RES-WS-OVERRIDE-MEMBER-COLLISION: a non-member-target override name cannot
    // also be a member name.  MemberTarget overrides (pkg "X" { member "X" }) are
    // the intended S8b patch form and are explicitly exempted — they redirect a
    // transitive dep to the pre-registered member candidate.
    let mut collisions: Vec<&str> = overrides
        .iter()
        .filter(|(n, ov)| {
            members_by_name.contains(n.as_str())
                && !matches!(ov.target, OverrideTarget::Member { .. })
        })
        .map(|(n, _)| n.as_str())
        .collect();
    if !collisions.is_empty() {
        collisions.sort();
        return Err(res_err(
            "RES-WS-OVERRIDE-MEMBER-COLLISION",
            format!(
                "workspace override name(s) {collisions:?} also appear as workspace member(s) \
                 — remove either the override or the member; cannot have both"
            ),
        ));
    }

    // RES-WS-MEMBER-REF-UNKNOWN: a `member "X"` dep with no such member.
    // Must check BOTH deps AND dev_deps — a dangling member ref in dev_deps is
    // equally invalid (Depth-F3, S5 fix).
    for member in &workspace.members {
        for dep in member.manifest.deps.iter().chain(member.manifest.dev_deps.iter()) {
            if let Dep::Member(md) = dep {
                if !members_by_name.contains(&md.name) {
                    return Err(res_err(
                        "RES-WS-MEMBER-REF-UNKNOWN",
                        format!(
                            "workspace member {:?} references `member {:?}` but no such member exists",
                            member.name, md.name
                        ),
                    ));
                }
            }
        }
    }

    // RES-WS-NO-INDEX: a member's named dep with neither an index, an override,
    // nor a matching member is unresolvable.
    let empty_index = Index::default();
    let index: &Index = match index {
        Some(i) => i,
        None => {
            let unresolvable: Vec<&str> = workspace
                .members
                .iter()
                .flat_map(|m| m.manifest.deps.iter().chain(m.manifest.dev_deps.iter()))
                .filter(|d| {
                    matches!(d, Dep::Named(_))
                        && !overrides.contains_key(d.name())
                        && !members_by_name.contains(d.name())
                })
                .map(Dep::name)
                .collect();
            if !unresolvable.is_empty() {
                return Err(res_err(
                    "RES-WS-NO-INDEX",
                    format!(
                        "workspace has named dep(s) {unresolvable:?} but no tianguis index \
                         was provided"
                    ),
                ));
            }
            &empty_index
        }
    };

    std::fs::create_dir_all(deps_dir).map_err(io_err)?;

    // S5 workspace: effective strict = OR of flag/env and any member's
    // attestation-policy "strict" (§13.1 workspace rule). Computed ONCE via the
    // SSOT helpers (Finding 1) and reused for both the provider and enforcement.
    let ws_is_strict = workspace_any_member_strict(workspace) || require_attested_metadata;

    let mut provider = ResolveProvider::new(
        fetcher,
        index,
        deps_dir.to_path_buf(),
        overrides,
        prior,
        None, // dep_decl_store: workspace path does not support DepDecl (S3b not yet wired for workspace)
        ws_is_strict,
    );
    let queue = provider.seed_workspace(workspace, profile, ws_cli_seed)?;
    provider.process_items(queue)?;
    // S4a fixpoint for workspace resolve (same algorithm as single-package).
    provider.run_s4a_fixpoint()?;
    // S4c post-fixpoint flag-conflict validation (same algorithm as single-package).
    provider.check_s4c_flag_conflicts(deps_dir)?;
    let canonical_aliases_ws = provider.finalize();
    let solution = solve(&provider, ROOT, root_version(), strategy)?;
    if let Some(e) = provider.take_error() {
        return Err(e);
    }

    // §13.1 workspace attestation policy enforcement — reuse the pre-computed
    // ws_is_strict (single computation, no duplicate any_member_strict loop).
    enforce_attestation_policy_strict(&provider, ws_is_strict)?;

    let graph = provider.build_graph(&solution, &canonical_aliases_ws);
    // B-nimcfg SSOT: rebuild _deps/ view (alias symlinks + stale-entry removal).
    // Mirrors resolve_workspace_frozen (frozen.rs:175) — the live path now owns
    // the rebuild internally, symmetric with the frozen path.
    rebuild_deps_view(&graph, deps_dir, store);
    Ok(graph)
}

// ---------------------------------------------------------------------------
// Queue items + provenance keys
// ---------------------------------------------------------------------------

/// One unit of fetch work discovered during BFS.
#[derive(Debug, Clone)]
enum Item {
    Url(UrlDep),
    /// A named (index-resolved) dep. `constraint` carries the pre-parsed
    /// `VersionSet`: validated at the manifest-parse boundary for milpa.kdl deps
    /// (`MAN-DEP-NAMED-CONSTRAINT`) or at the nimble-parse boundary for .nimble
    /// deps (`MAN-NIMBLE-CONSTRAINT`). The `VersionSet` is never re-parsed at
    /// dispatch time; `process_named` receives it directly.
    Named {
        name: String,
        constraint: VersionSet,
    },
    Local(LocalDep),
    Tarball(TarballDep),
}

impl Item {
    fn name(&self) -> &str {
        match self {
            Item::Url(d) => &d.name,
            Item::Named { name, .. } => name,
            Item::Local(d) => &d.name,
            Item::Tarball(d) => &d.name,
        }
    }

    /// The canonical provenance key for the cross-name precedence gate (§10).
    /// Two items with the same key are interchangeable (dedup); different keys
    /// for one name are a precedence decision.
    fn pkey(&self) -> PKey {
        match self {
            Item::Url(d) => PKey::Url(d.git.clone(), d.git_ref.clone()),
            Item::Named { name, .. } => PKey::Named(name.clone()),
            Item::Local(d) => PKey::Local(d.path.clone()),
            Item::Tarball(d) => PKey::Tarball(d.url.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PKey {
    Url(String, String),
    Named(String),
    Local(String),
    Tarball(String),
    /// S8b: sentinel for a MemberTarget override — the dep is satisfied by a
    /// pre-registered workspace member candidate, no external fetch.
    Member(String),
}

/// What `extract_requires` returns after converting an `EdgeSet` to solver
/// edges, require names, src_dir, and sub-items.  Carries the full `EdgeSet`
/// so callers can inspect `edge_set.source` (e.g. to gate the DepDecl pin at
/// the use-site rather than via a lossy `bool`).
///
/// Replaces the previous `(Vec<SolverDep>, Vec<String>, String, Vec<Item>, bool)`
/// 5-tuple: the `bool` was `matches!(es.source, EdgeSource::DepDecl)` — lossy
/// and positional.  The struct lets each field be named and the `EdgeSource`
/// preserved.
struct Extracted {
    deps: Vec<SolverDep>,
    requires_names: Vec<String>,
    src_dir: String,
    sub_items: Vec<Item>,
    /// The full `EdgeSet` produced by `edgeset_to_extracted` (memoised in
    /// `edge_cache`).  The dep_decl pin is derived from
    /// `edge_set.source == EdgeSource::DepDecl` at the call-site.
    edge_set: EdgeSet,
    /// S4: advisory predicate metadata (RFC cond-requires §3.4.3 option a).
    /// Maps dep-name → ALL predicate-vecs collected across ALL occurrences.
    /// A dep appearing in ≥2 `when` branches yields ≥2 inner `Vec<Predicate>`
    /// entries (C1 fix — accumulate, not overwrite).
    requires_predicates: std::collections::BTreeMap<String, Vec<Vec<milpa_types::Predicate>>>,
}

// ---------------------------------------------------------------------------
// Materialized candidate
// ---------------------------------------------------------------------------

/// One concrete resolved candidate. `version` is the singleton for non-indexed
/// deps (§3) or the index version for named deps.
#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    version: Version,
    /// `sha256:…`; empty only for the synthetic root (excluded from the graph).
    identity: String,
    src_dir: String,
    requires_names: Vec<String>,
    deps: Vec<SolverDep>,
    /// Emission-level record. `None` for the synthetic root; `Some` for every
    /// fetched dep + workspace member. The resolver maps its internal transport
    /// [`Provenance`] → [`ProvenanceRecord`] here so the graph is emission-ready.
    provenance: Option<ProvenanceRecord>,
    /// D-lifecycle: declared mirror URLs (manifest mirrors + prior declared) that
    /// were NOT the observed candidate. Stored so `build_graph` can assemble the
    /// full provenances tuple (observed + declared). Empty for non-git deps.
    declared_mirror_urls: Vec<String>,
    /// S6: dep_decl pin — the `sha256:<hex>` hash of the DepDecl artifact used
    /// during resolution. Set only when the edge was sourced from a DepDecl
    /// artifact (`EdgeSource::DepDecl`). `None` for milpa.kdl / nimble fallback.
    dep_decl: Option<String>,
    /// S4: advisory predicate metadata from `edgeset_to_extracted` (RFC §3.4.3 option a).
    /// Maps dep-name → ALL predicate-vecs across ALL occurrences (C1 fix).
    /// Never consulted for selection/solving. Empty for root/synthetic candidates.
    requires_predicates: std::collections::BTreeMap<String, Vec<Vec<milpa_types::Predicate>>>,
}

// ---------------------------------------------------------------------------
// The two-phase provider
// ---------------------------------------------------------------------------

/// Backs the solver's [`PackageProvider`] queries. Eager candidates land in
/// `candidates` during BFS; named stubs in `stubs` are fetched lazily. All
/// mutable state is `RefCell`-guarded because the solver calls the queries via
/// `&self` and lazy materialization mutates.
struct ResolveProvider<'a> {
    fetcher: &'a dyn FetcherRegistry,
    index: &'a Index,
    deps_dir: PathBuf,
    project_root: PathBuf,
    overrides: BTreeMap<String, Override>,
    prior: Option<&'a Lockfile>,
    root_authority: BTreeSet<String>,
    /// Workspace member names — pre-registered candidates that are never fetched
    /// and never index-resolved (a member-named transitive dep is satisfied by
    /// the in-tree member). Empty in single-package mode.
    member_names: BTreeSet<String>,

    candidates: RefCell<BTreeMap<String, BTreeMap<Version, Candidate>>>,
    stubs: RefCell<BTreeMap<String, BTreeMap<Version, IndexVersion>>>,

    /// Resolver-scoped edge memo (§4.2.1 clause a): sealed once per
    /// `(name, version)` — parent-independent (diamond deps get identical
    /// `EdgeSet`). Only modified from transport workers (eager) and
    /// `materialize_named` (lazy); never from solver callbacks.
    edge_cache: RefCell<BTreeMap<(String, Version), EdgeSet>>,

    seen_url: RefCell<BTreeSet<(String, String)>>,
    seen_named: RefCell<BTreeSet<String>>,
    seen_local: RefCell<BTreeSet<String>>,
    seen_tarball: RefCell<BTreeSet<String>>,
    seen_by_name: RefCell<BTreeMap<String, (PKey, bool)>>,

    /// S3 RFC #23: resolver-scoped map of dep_name → flag_requests from the ROOT
    /// manifest's named dep declarations. Populated during `seed_root`; consumed
    /// in `materialize_named` to pass `active_flags` to `extract_requires`.
    /// Mirrors Python `_Provider._flag_requests_by_name`.
    flag_requests_by_name: RefCell<BTreeMap<String, Vec<FlagRequest>>>,

    /// Phase B: BFS-insertion discovery order — dep names in the order they are
    /// first enqueued (root deps in declaration order, then transitives in first-
    /// occurrence order). Used by `finalize()` to pick the canonical name in each
    /// dedup group (earliest-discovered wins over lex-min).
    discovery_order: RefCell<Vec<String>>,

    error: RefCell<Option<MilpaError>>,

    /// S3b: DepDecl store for index-attested metadata. `None` disables the
    /// DepDecl mainline path (falls through to MilpaKdl/Nimble — S4-i compat).
    dep_decl_store: Option<&'a dyn crate::dep_decl_store::DepDeclStore>,

    /// S5 effective strict attestation policy: logical OR of
    /// `manifest.attestation_policy == Strict` and `--require-attested-metadata`
    /// flag/env. Pre-computed at construction so `extract_requires` can gate
    /// `TNG-DEPDECL-FETCH-FAILED` fallback without re-reading the manifest
    /// (spec §13.1; Python: `edge_sources.py` `strict_attestation` param).
    strict_attestation: bool,

    /// S4a (RFC #23 §3.1.2): resolver-scoped dep_active_flags map.
    /// Maps identity (content_hash) → (flag_name → BTreeSet<ActivationSource>).
    /// Mirrors Python `_Provider.dep_active_flags` — keying by identity is NORMATIVE
    /// per spec/identity.md §3.1.2 ("Keying (normative)").
    /// Populated during `process_url`/`materialize_named` and extended by `run_s4a_fixpoint`.
    dep_active_flags: RefCell<BTreeMap<String, BTreeMap<String, BTreeSet<milpa_types::ActivationSource>>>>,
}

/// The cross-name gate's verdict for an item (§10).
enum Gate {
    Proceed,
    Suppress,
    Conflict(PKey, PKey),
}

impl<'a> ResolveProvider<'a> {
    /// `project_root` is always `deps_dir.parent()` — callers need not compute it.
    fn new(
        fetcher: &'a dyn FetcherRegistry,
        index: &'a Index,
        deps_dir: PathBuf,
        overrides: BTreeMap<String, Override>,
        prior: Option<&'a Lockfile>,
        dep_decl_store: Option<&'a dyn crate::dep_decl_store::DepDeclStore>,
        strict_attestation: bool,
    ) -> Self {
        let project_root = deps_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        ResolveProvider {
            fetcher,
            index,
            deps_dir,
            project_root,
            overrides,
            prior,
            root_authority: BTreeSet::new(),
            member_names: BTreeSet::new(),
            candidates: RefCell::new(BTreeMap::new()),
            stubs: RefCell::new(BTreeMap::new()),
            edge_cache: RefCell::new(BTreeMap::new()),
            seen_url: RefCell::new(BTreeSet::new()),
            seen_named: RefCell::new(BTreeSet::new()),
            seen_local: RefCell::new(BTreeSet::new()),
            seen_tarball: RefCell::new(BTreeSet::new()),
            seen_by_name: RefCell::new(BTreeMap::new()),
            discovery_order: RefCell::new(Vec::new()),
            error: RefCell::new(None),
            dep_decl_store,
            strict_attestation,
            flag_requests_by_name: RefCell::new(BTreeMap::new()),
            dep_active_flags: RefCell::new(BTreeMap::new()),
        }
    }

    /// Build the synthetic root candidate from `manifest.deps + dev_deps` (§9)
    /// and seed the precedence gate with root authority (§10.1). Returns the
    /// initial BFS queue.
    fn seed_root(&mut self, manifest: &Manifest) -> Result<Vec<Item>, MilpaError> {
        let mut root_deps: Vec<SolverDep> = Vec::new();
        let mut root_requires: Vec<String> = Vec::new();
        let mut queue: Vec<Item> = Vec::new();
        let mut seen_by_name: BTreeMap<String, (PKey, bool)> = BTreeMap::new();
        let mut authority: BTreeSet<String> = BTreeSet::new();

        let all_deps = manifest.deps.iter().chain(manifest.dev_deps.iter());
        for dep in all_deps {
            let name = dep.name().to_string();
            authority.insert(name.clone());
            match dep {
                Dep::Tarball(t) => {
                    root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                    root_requires.push(name.clone());
                    seen_by_name.insert(name.clone(), (PKey::Tarball(t.url.clone()), true));
                    self.discovery_order.borrow_mut().push(name); // Phase B: root deps in declaration order
                    queue.push(Item::Tarball(t.clone()));
                }
                Dep::Local(l) => {
                    root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                    root_requires.push(name.clone());
                    seen_by_name.insert(name.clone(), (PKey::Local(l.path.clone()), true));
                    self.discovery_order.borrow_mut().push(name); // Phase B: root deps in declaration order
                    queue.push(Item::Local(l.clone()));
                }
                Dep::Url(u) => {
                    root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                    root_requires.push(name.clone());
                    // S8a: LocalTarget override on root UrlDep → local pkey + local item.
                    if let Some(ov) = self.overrides.get(&name) {
                        if let OverrideTarget::Local { path } = &ov.target {
                            seen_by_name.insert(name.clone(), (PKey::Local(path.clone()), true));
                            self.discovery_order.borrow_mut().push(name.clone());
                            queue.push(Item::Local(LocalDep { name, path: path.clone(), predicates: vec![] }));
                            continue;
                        }
                        // S8b: MemberTarget on a root UrlDep in single-package manifest is a
                        // no-op (no workspace member to resolve to); treat as the original URL.
                        if let OverrideTarget::Member { member_name } = &ov.target {
                            let _ = member_name;
                            let pkey = PKey::Url(u.git.clone(), u.git_ref.clone());
                            seen_by_name.insert(name.clone(), (pkey, true));
                            self.discovery_order.borrow_mut().push(name);
                            queue.push(Item::Url(u.clone()));
                            continue;
                        }
                    }
                    let pkey = match self.overrides.get(&name) {
                        Some(ov) => {
                            let (url, r) = override_git_url_ref(ov);
                            PKey::Url(url.to_owned(), r.to_owned())
                        }
                        None => PKey::Url(u.git.clone(), u.git_ref.clone()),
                    };
                    seen_by_name.insert(name.clone(), (pkey, true));
                    self.discovery_order.borrow_mut().push(name); // Phase B: root deps in declaration order
                    queue.push(Item::Url(u.clone()));
                }
                Dep::Named(n) => {
                    // Manifest-parsed: use the pre-validated VersionSet
                    // (MAN-DEP-NAMED-CONSTRAINT raised at parse time).
                    let vs = n
                        .parsed_constraint
                        .clone()
                        .unwrap_or_else(VersionSet::full);
                    // S3: store flag_requests for use during materialize_named.
                    if !n.flag_requests.is_empty() {
                        self.flag_requests_by_name
                            .borrow_mut()
                            .insert(name.clone(), n.flag_requests.clone());
                    }
                    if self.overrides.contains_key(&name) {
                        // Override routes a named dep to a URL/local fetch → singleton.
                        let ov = &self.overrides[&name];
                        root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                        match &ov.target {
                            // S8a: LocalTarget override on root NamedDep → local pkey + item.
                            OverrideTarget::Local { path } => {
                                seen_by_name.insert(
                                    name.clone(),
                                    (PKey::Local(path.clone()), true),
                                );
                                root_requires.push(name.clone());
                                self.discovery_order.borrow_mut().push(name.clone());
                                queue.push(Item::Local(LocalDep { name, path: path.clone(), predicates: vec![] }));
                                continue;
                            }
                            OverrideTarget::Member { .. } => {
                                // S8b: MemberTarget in a single-package manifest is a no-op
                                // (no workspace context; no member candidate pre-registered).
                                // Treat as if the override were absent: resolve as named dep.
                                // Revert to named-dep solver term (already pushed as sentinel above).
                                // We drop the sentinel we pushed and push the real constraint term.
                                root_deps.pop(); // undo the sentinel push
                                root_deps.push(SolverDep::new(name.clone(), vs.clone()));
                                seen_by_name.insert(name.clone(), (PKey::Named(name.clone()), true));
                            }
                            OverrideTarget::Git { url, git_ref } => {
                                seen_by_name.insert(
                                    name.clone(),
                                    (PKey::Url(url.clone(), git_ref.clone()), true),
                                );
                            }
                        }
                    } else {
                        root_deps.push(SolverDep::new(name.clone(), vs.clone()));
                        seen_by_name.insert(name.clone(), (PKey::Named(name.clone()), true));
                    }
                    root_requires.push(name.clone());
                    self.discovery_order.borrow_mut().push(name.clone()); // Phase B: root deps in declaration order
                    queue.push(Item::Named {
                        name,
                        constraint: vs,
                    });
                }
                Dep::Member(_) => {
                    // A workspace-member reference is meaningful only in a
                    // workspace resolve (S11). In a single-package manifest it
                    // has no candidate; require the singleton so the solver
                    // surfaces the unsatisfiable edge rather than silently
                    // dropping it.
                    root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                    root_requires.push(name);
                    // Members are never fetched → no dedup participation; no discovery record needed.
                }
            }
        }

        for ov in &manifest.overrides {
            authority.insert(ov.name.clone());
            // S8: pre-seed the gate for each override kind via the SSOT helper.
            // S8a: LocalTarget → PKey::Local; S8b: MemberTarget → PKey::Member
            // (no-op in single-package context, but gate is pre-seeded for consistency).
            let pk = override_target_to_pkey(&ov.target);
            seen_by_name
                .entry(ov.name.clone())
                .or_insert_with(|| (pk, true));
        }

        self.root_authority = authority;
        *self.seen_by_name.borrow_mut() = seen_by_name;

        let root = Candidate {
            name: ROOT.to_string(),
            version: root_version(),
            identity: String::new(),
            src_dir: String::new(),
            requires_names: root_requires,
            deps: root_deps,
            provenance: None,
            declared_mirror_urls: Vec::new(),
            dep_decl: None,
            requires_predicates: std::collections::BTreeMap::new(),
        };
        self.store_candidate(root);
        Ok(queue)
    }

    /// Pre-register every workspace member as a (never-fetched) candidate and
    /// build the synthetic root requiring each member. Members' external deps
    /// seed the BFS queue; member-named deps coerce to the in-tree member.
    /// Returns the initial external-dep queue.
    /// S1 (RFC: workspace-completion §3.A): `ws_cli_seed` is the workspace-root
    /// active-flag seed from CLI inputs (pre-computed by `resolve_workspace_inner`).
    /// `None` = no CLI feature selection.  The parameter is accepted here to make
    /// S2's flag-only arm reachable; the arm itself is wired in S2.
    fn seed_workspace(
        &mut self,
        workspace: &LoadedWorkspace,
        profile: Option<&Profile>,
        ws_cli_seed: Option<&std::collections::HashSet<String>>,
    ) -> Result<Vec<Item>, MilpaError> {
        let members_by_name: BTreeSet<String> =
            workspace.members.iter().map(|m| m.name.clone()).collect();
        self.member_names = members_by_name.clone();

        let mut root_deps: Vec<SolverDep> = Vec::new();
        let mut root_requires: Vec<String> = Vec::new();
        let mut queue: Vec<Item> = Vec::new();
        let mut seen_by_name: BTreeMap<String, (PKey, bool)> = BTreeMap::new();
        let mut authority: BTreeSet<String> = members_by_name.clone();

        for ov in &workspace.overrides {
            authority.insert(ov.name.clone());
            // S8: pre-seed the gate for each override kind via the SSOT helper.
            // S8a: LocalTarget → PKey::Local; S8b: MemberTarget → PKey::Member.
            // Pre-seeding with is_root=true means any transitive dep claiming this
            // name via a different pkey is suppressed by the gate (root wins).
            let pk = override_target_to_pkey(&ov.target);
            seen_by_name.insert(ov.name.clone(), (pk, true));
        }

        for member in &workspace.members {
            // S2 (RFC: workspace-completion §3.A): apply FilterCtx to the member
            // manifest before building solver terms and seeding the BFS queue.
            // This wires the flag-only arm into the workspace seed path: when
            // ws_cli_seed is Some, FilterCtx::build runs flag_enables_closure
            // against the *member's own* flags (Design-F1).
            // The two application sites (solver terms + BFS queue) are fused here
            // in seed_workspace (unlike Python which has two separate loops).
            let filtered_storage;
            let manifest = {
                let ctx = FilterCtx::build(
                    &member.manifest,
                    profile.cloned(),
                    ws_cli_seed,
                );
                if ctx.profile.is_none() && ctx.active_flags.is_empty() {
                    &member.manifest
                } else {
                    filtered_storage = filter_manifest(&member.manifest, &ctx);
                    &filtered_storage
                }
            };

            let mut terms: Vec<SolverDep> = Vec::new();
            let mut requires: Vec<String> = Vec::new();
            for dep in manifest.deps.iter().chain(manifest.dev_deps.iter()) {
                let name = dep.name().to_string();
                authority.insert(name.clone());

                // Member ref / member-named auto-coercion: satisfied by the
                // in-tree member candidate, no fetch, no queue.
                if matches!(dep, Dep::Member(_)) || members_by_name.contains(&name) {
                    // Breadth-P1c (S5): when a NamedDep auto-coerces to a member,
                    // verify the declared constraint is satisfied by the member's
                    // sentinel version.  Silently discarding the constraint is a
                    // correctness hole — e.g. ">= 2.0.0" vs sentinel 0.0.1.
                    if let Dep::Named(nd) = dep {
                        if let Some(ref vs) = nd.parsed_constraint {
                            if !vs.contains(&url_dep_version()) {
                                return Err(res_err(
                                    "RES-WS-MEMBER-VERSION-CONSTRAINT",
                                    format!(
                                        "named dep {:?} auto-coerces to workspace member {:?} \
                                         but the declared constraint {:?} is not satisfied by \
                                         the member's sentinel version {} \
                                         (member deps carry version {}; \
                                         declared constraint must match)",
                                        name, name,
                                        nd.constraint.as_deref().unwrap_or(""),
                                        url_dep_version(),
                                        url_dep_version(),
                                    ),
                                ));
                            }
                        }
                    }
                    terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                    requires.push(name);
                    continue;
                }

                if self.overrides.contains_key(&name) {
                    let ov = &self.overrides[&name];
                    terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                    requires.push(name.clone());
                    // S8a: LocalTarget override → local item; S8b: MemberTarget → no-op
                    // (member already pre-registered; gate was pre-seeded above); git → url.
                    match &ov.target {
                        OverrideTarget::Local { path } => {
                            let pkey = PKey::Local(path.clone());
                            seen_by_name.entry(name.clone()).or_insert((pkey, true));
                            if !self.discovery_order.borrow().contains(&name) {
                                self.discovery_order.borrow_mut().push(name.clone());
                            }
                            queue.push(Item::Local(LocalDep { name: name.clone(), path: path.clone(), predicates: vec![] }));
                        }
                        OverrideTarget::Member { member_name } => {
                            // S8b: member already pre-registered; gate pre-seeded with
                            // PKey::Member in the overrides loop above.  No external queue
                            // entry needed; do NOT add to discovery_order (member is not an
                            // external dep subject to content-hash dedup).
                            let _ = member_name; // name used only for gate; no fetch
                        }
                        OverrideTarget::Git { url, git_ref } => {
                            seen_by_name
                                .entry(name.clone())
                                .or_insert((PKey::Url(url.clone(), git_ref.clone()), true));
                            // Override converts Named→Url at dispatch; constraint is unused.
                            queue.push(Item::Named {
                                name: name.clone(),
                                constraint: VersionSet::full(),
                            });
                        }
                    }
                    let _ = name; // suppress move-after-use warning (consumed in match arms above)
                    continue;
                }

                match dep {
                    Dep::Url(u) => {
                        terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                        requires.push(name.clone());
                        let entry = seen_by_name
                            .entry(name.clone())
                            .or_insert((PKey::Url(u.git.clone(), u.git_ref.clone()), true));
                        // Phase B: record first-insertion in discovery order (workspace deps).
                        let _ = entry; // or_insert returns &mut; just track first-time by checking the queue
                        if !self.discovery_order.borrow().contains(&name) {
                            self.discovery_order.borrow_mut().push(name.clone());
                        }
                        queue.push(Item::Url(u.clone()));
                    }
                    Dep::Local(l) => {
                        terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                        requires.push(name.clone());
                        seen_by_name
                            .entry(name.clone())
                            .or_insert((PKey::Local(l.path.clone()), true));
                        if !self.discovery_order.borrow().contains(&name) {
                            self.discovery_order.borrow_mut().push(name.clone());
                        }
                        queue.push(Item::Local(l.clone()));
                    }
                    Dep::Tarball(t) => {
                        terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                        requires.push(name.clone());
                        seen_by_name
                            .entry(name.clone())
                            .or_insert((PKey::Tarball(t.url.clone()), true));
                        if !self.discovery_order.borrow().contains(&name) {
                            self.discovery_order.borrow_mut().push(name.clone());
                        }
                        queue.push(Item::Tarball(t.clone()));
                    }
                    Dep::Named(n) => {
                        // Manifest-parsed: use the pre-validated VersionSet
                        // (MAN-DEP-NAMED-CONSTRAINT raised at parse time).
                        let vs = n
                            .parsed_constraint
                            .clone()
                            .unwrap_or_else(VersionSet::full);
                        terms.push(SolverDep::new(name.clone(), vs.clone()));
                        requires.push(name.clone());
                        seen_by_name
                            .entry(name.clone())
                            .or_insert((PKey::Named(name.clone()), true));
                        if !self.discovery_order.borrow().contains(&name) {
                            self.discovery_order.borrow_mut().push(name.clone());
                        }
                        // S11 (RFC #23 §3.8): accumulate flag_requests from ALL members
                        // (workspace-wide union). Union via extend — monotone; duplicate
                        // positive requests are idempotent for union semantics.
                        if !n.flag_requests.is_empty() {
                            self.flag_requests_by_name
                                .borrow_mut()
                                .entry(name.clone())
                                .or_default()
                                .extend(n.flag_requests.iter().cloned());
                        }
                        queue.push(Item::Named {
                            name,
                            constraint: vs,
                        });
                    }
                    Dep::Member(_) => unreachable!("handled by the coercion branch above"),
                }
            }

            let identity = compute_content_hash(&member.directory)?;
            self.store_candidate(Candidate {
                name: member.name.clone(),
                version: url_dep_version(),
                identity,
                src_dir: member.manifest.src_dir.clone(),
                requires_names: requires,
                deps: terms,
                provenance: Some(ProvenanceRecord::Member {
                    name: member.name.clone(),
                    origin: "observed".to_string(),
                }),
                declared_mirror_urls: Vec::new(), // workspace members have no mirrors
                dep_decl: None, // workspace members never resolved via DepDecl
                requires_predicates: std::collections::BTreeMap::new(),
            });
            root_deps.push(SolverDep::new(member.name.clone(), eq_sentinel()));
            root_requires.push(member.name.clone());
        }

        // S11 (RFC #23 §3.8): workspace-root flags {} — seed workspace-wide active
        // flags from workspace-root default-true flags.  Compute the enables-closure
        // (same-package closure via flag_enables_closure) then extract cross-pkg
        // enables and pre-seed flag_requests_by_name.
        if !workspace.flags.is_empty() {
            use std::collections::HashSet as HSet;
            use milpa_manifest::flag_enables_closure;
            let ws_root_flags = &workspace.flags;
            // Compute which workspace-root flags are default-active.
            let ws_root_active_seed: HSet<String> = ws_root_flags
                .iter()
                .filter(|f| f.default)
                .map(|f| f.name.clone())
                .collect();
            let ws_root_active = flag_enables_closure(ws_root_flags, &ws_root_active_seed);
            // Build flag-name → FlagDecl lookup.
            let ws_flag_by_name: std::collections::HashMap<&str, &milpa_manifest::FlagDecl> =
                ws_root_flags.iter().map(|f| (f.name.as_str(), f)).collect();
            // Extract cross-pkg enables from root-active flags.
            for flag_name in &ws_root_active {
                if let Some(fd) = ws_flag_by_name.get(flag_name.as_str()) {
                    for cpe in &fd.enables_cross_pkg {
                        // Accumulate (union) into flag_requests_by_name.
                        self.flag_requests_by_name
                            .borrow_mut()
                            .entry(cpe.dep.clone())
                            .or_default()
                            .extend(cpe.flag_requests.iter().cloned());
                    }
                }
            }
        }

        self.root_authority = authority;
        *self.seen_by_name.borrow_mut() = seen_by_name;

        let root = Candidate {
            name: ROOT.to_string(),
            version: root_version(),
            identity: String::new(),
            src_dir: String::new(),
            requires_names: root_requires,
            deps: root_deps,
            provenance: None,
            declared_mirror_urls: Vec::new(),
            dep_decl: None,
            requires_predicates: std::collections::BTreeMap::new(),
        };
        self.store_candidate(root);
        Ok(queue)
    }

    /// Apply overrides, run the precedence gate, and dispatch one item.
    /// Process a batch of newly-discovered items: **gate every item first** —
    /// so a provenance conflict between two sibling items (e.g. a parent that
    /// `requires` the same name from two different URLs) raises
    /// `RES-PROVENANCE-CONFLICT` *before* any fetch is attempted — then dispatch
    /// the survivors. Gating before fetching is what makes the conflict win over
    /// an unrelated fetch failure of the first sibling (resolver-semantics §10).
    fn process_items(&self, items: Vec<Item>) -> Result<(), MilpaError> {
        let mut survivors: Vec<Item> = Vec::new();
        for item in items {
            if let Some(gated) = self.gate_only(item)? {
                survivors.push(gated);
            }
        }
        for item in survivors {
            self.dispatch(item)?;
        }
        Ok(())
    }

    /// Apply overrides then the precedence gate to one item. Returns the
    /// (override-rewritten) item to dispatch, `None` if suppressed, or
    /// `RES-PROVENANCE-CONFLICT`.
    fn gate_only(&self, item: Item) -> Result<Option<Item>, MilpaError> {
        let item = self.apply_override(item);
        match self.gate(&item) {
            Gate::Suppress => Ok(None),
            Gate::Conflict(a, b) => Err(res_err(
                "RES-PROVENANCE-CONFLICT",
                format!(
                    "provenance conflict for package {:?}: one transitive dep claims {a:?} \
                     and another claims {b:?}; the root manifest does not override it. \
                     Add an override to resolve which source to use.",
                    item.name()
                ),
            )),
            Gate::Proceed => Ok(Some(item)),
        }
    }

    /// Dispatch an already-gated item to its transport worker (no re-gating).
    fn dispatch(&self, item: Item) -> Result<(), MilpaError> {
        match item {
            Item::Url(dep) => self.process_url(dep),
            Item::Local(dep) => self.process_local(dep),
            Item::Tarball(dep) => self.process_tarball(dep),
            Item::Named { name, constraint } => self.process_named(&name, constraint),
        }
    }

    /// The cross-name precedence gate (§10). First claim on a name wins when it
    /// has root authority; two non-root claims with different provenance
    /// conflict; the same key falls through to transport dedup.
    fn gate(&self, item: &Item) -> Gate {
        let name = item.name();
        if name == "nim" {
            return Gate::Proceed;
        }
        let pkey = item.pkey();
        let mut seen = self.seen_by_name.borrow_mut();
        match seen.get(name) {
            None => {
                seen.insert(name.to_string(), (pkey, false));
                // Phase B: record transitive dep first-enqueue (BFS-insertion order).
                // Root deps are recorded in seed_root(); transitive deps land here.
                self.discovery_order.borrow_mut().push(name.to_string());
                Gate::Proceed
            }
            Some((prior_key, is_root)) => {
                if *prior_key == pkey {
                    Gate::Proceed
                } else if *is_root || self.root_authority.contains(name) {
                    Gate::Suppress
                } else {
                    Gate::Conflict(prior_key.clone(), pkey)
                }
            }
        }
    }

    fn apply_override(&self, item: Item) -> Item {
        match &item {
            Item::Url(d) => match self.overrides.get(&d.name) {
                Some(ov) => match &ov.target {
                    // S8a: LocalTarget override → route to local transport.
                    OverrideTarget::Local { path } => {
                        Item::Local(LocalDep { name: d.name.clone(), path: path.clone(), predicates: vec![] })
                    }
                    // S8b: MemberTarget — member already pre-registered; gate was pre-seeded
                    // with PKey::Member(member_name) + is_root=true in seed_workspace.
                    // Return the item unchanged; the gate will suppress it (root wins over
                    // any non-matching pkey).
                    OverrideTarget::Member { .. } => item,
                    // Existing git path.
                    OverrideTarget::Git { url, git_ref } => {
                        Item::Url(url_dep(&d.name, url, git_ref))
                    }
                },
                None => item,
            },
            Item::Named { name, .. } => match self.overrides.get(name) {
                Some(ov) => match &ov.target {
                    // S8a: LocalTarget override → route to local transport.
                    OverrideTarget::Local { path } => {
                        Item::Local(LocalDep { name: name.clone(), path: path.clone(), predicates: vec![] })
                    }
                    // S8b: MemberTarget — member already pre-registered; gate was pre-seeded
                    // with PKey::Member(member_name) + is_root=true in seed_workspace.
                    // Return the item unchanged; the gate will suppress it (root wins over
                    // any non-matching pkey).
                    OverrideTarget::Member { .. } => item,
                    // Existing git path.
                    OverrideTarget::Git { url, git_ref } => {
                        Item::Url(url_dep(name, url, git_ref))
                    }
                },
                None => item,
            },
            // `local`/`tarball` are themselves explicit transport specs;
            // manifest overrides do not apply.
            Item::Local(_) | Item::Tarball(_) => item,
        }
    }

    // --- transport workers -------------------------------------------------

    fn process_url(&self, dep: UrlDep) -> Result<(), MilpaError> {
        let key = (dep.git.clone(), dep.git_ref.clone());
        if !self.seen_url.borrow_mut().insert(key) {
            // S4b: multi-consumer union (RFC #23 §3.1.3).
            // A second (or later) consumer of the same URL dep — same (git, ref) key.
            // The dep has already been fetched and its candidate registered.  Any
            // positive flag_requests from THIS consumer must be unioned into the dep's
            // active_flags (monotone — never subtract).  Negative requests (opt-out,
            // §3.1.3) contribute nothing; `compute_dep_active_flags` ignores them.
            //
            // If the union admits new flags, fire the same newly-admitted-dep logic
            // as S4a fixpoint steps 4-5: extend the candidate's deps/requires_names
            // and enqueue sub-deps for fetch (if not already seen).
            let positive_reqs: Vec<FlagRequest> = dep
                .flag_requests
                .iter()
                .filter(|fr| fr.enabled)
                .cloned()
                .collect();
            if !positive_reqs.is_empty() {
                let dest = self.deps_dir.join(&dep.name);
                let kdl_path = dest.join("milpa.kdl");
                if kdl_path.is_file() {
                    if let Ok(text) = std::fs::read_to_string(&kdl_path) {
                        if let Ok(manifest) = milpa_manifest::parse_manifest(&text) {
                            // Compute new active flags from this consumer's requests.
                            let new_active = compute_dep_active_flags(&manifest.flags, &positive_reqs);
                            // Resolve identity for this dep (H3: key by identity, not dep_name).
                            let dep_identity: String = self.candidates.borrow()
                                .get(&dep.name)
                                .and_then(|m| m.values().next())
                                .map(|c| c.identity.clone())
                                .unwrap_or_default();
                            if !new_active.is_empty() && !dep_identity.is_empty() {
                                let old_flag_names: BTreeSet<String> = self
                                    .dep_active_flags
                                    .borrow()
                                    .get(&dep_identity)
                                    .map(|m| m.keys().cloned().collect())
                                    .unwrap_or_default();

                                // Union into dep_active_flags (monotone).
                                {
                                    let mut daf = self.dep_active_flags.borrow_mut();
                                    let entry = daf.entry(dep_identity.clone()).or_default();
                                    for (flag_name, sources) in &new_active {
                                        entry
                                            .entry(flag_name.clone())
                                            .or_default()
                                            .extend(sources.iter().cloned());
                                    }
                                }

                                let new_flag_names: BTreeSet<String> = self
                                    .dep_active_flags
                                    .borrow()
                                    .get(&dep_identity)
                                    .map(|m| m.keys().cloned().collect())
                                    .unwrap_or_default();

                                if new_flag_names != old_flag_names {
                                    // Find newly admitted deps and process them (S4b steps 4-5).
                                    let old_active_set: BTreeSet<&str> =
                                        old_flag_names.iter().map(|s| s.as_str()).collect();
                                    let new_active_set: BTreeSet<&str> =
                                        new_flag_names.iter().map(|s| s.as_str()).collect();
                                    let mut new_items: Vec<Item> = Vec::new();

                                    for sub_dep in &manifest.deps {
                                        let was_admitted = dep_passes_flag_predicates(sub_dep, &old_active_set);
                                        let is_admitted = dep_passes_flag_predicates(sub_dep, &new_active_set);
                                        if is_admitted && !was_admitted {
                                            // Extend the parent candidate's deps/requires_names.
                                            let sub_name = sub_dep.name().to_string();
                                            {
                                                let mut cands = self.candidates.borrow_mut();
                                                if let Some(version_map) = cands.get_mut(&dep.name) {
                                                    if let Some(cand) = version_map.values_mut().next() {
                                                        if !cand.requires_names.contains(&sub_name) {
                                                            let vs = match sub_dep {
                                                                Dep::Url(_) | Dep::Local(_) | Dep::Tarball(_) | Dep::Member(_) => eq_sentinel(),
                                                                Dep::Named(n) => {
                                                                    if self.overrides.contains_key(&n.name) {
                                                                        eq_sentinel()
                                                                    } else {
                                                                        let c = n.constraint.as_deref().filter(|s| !s.is_empty());
                                                                        VersionSet::from_constraint(c).unwrap_or_else(|_| VersionSet::full())
                                                                    }
                                                                }
                                                            };
                                                            cand.deps.push(SolverDep::new(sub_name.clone(), vs));
                                                            cand.requires_names.push(sub_name.clone());
                                                        }
                                                    }
                                                }
                                            }
                                            // Enqueue for fetch if not already seen.
                                            match sub_dep {
                                                Dep::Url(u) => {
                                                    let k = (u.git.clone(), u.git_ref.clone());
                                                    if !self.seen_url.borrow().contains(&k) {
                                                        new_items.push(Item::Url(u.clone()));
                                                    }
                                                }
                                                Dep::Named(n) => {
                                                    if !self.seen_named.borrow().contains(&n.name) {
                                                        let constraint = if self.overrides.contains_key(&n.name) {
                                                            eq_sentinel()
                                                        } else {
                                                            let c = n.constraint.as_deref().filter(|s| !s.is_empty());
                                                            VersionSet::from_constraint(c).unwrap_or_else(|_| VersionSet::full())
                                                        };
                                                        new_items.push(Item::Named {
                                                            name: n.name.clone(),
                                                            constraint,
                                                        });
                                                    }
                                                }
                                                Dep::Local(l) => {
                                                    if !self.seen_local.borrow().contains(&l.path) {
                                                        new_items.push(Item::Local(l.clone()));
                                                    }
                                                }
                                                Dep::Tarball(t) => {
                                                    if !self.seen_tarball.borrow().contains(&t.url) {
                                                        new_items.push(Item::Tarball(t.clone()));
                                                    }
                                                }
                                                Dep::Member(_) => {}
                                            }
                                        }
                                    }

                                    if !new_items.is_empty() {
                                        self.process_items(new_items)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        let (expected_identity, pinned_sha) = self.git_pin(&dep);

        // D-lifecycle: collect ALL candidate URLs (primary + manifest mirrors + prior
        // declared) in order, deduped. Whichever succeeds becomes "observed";
        // the rest become "declared" provenances in the lockfile.
        //
        // D-update-remove (Phase D item 5): filter prior declared URLs to only
        // those still present in the manifest mirror set. URLs removed from
        // milpa.kdl are dropped ("drop only those whose URL left the manifest").
        let manifest_mirror_set: std::collections::HashSet<&str> =
            dep.mirrors.iter().map(|s| s.as_str()).collect();
        let prior_declared_raw = self.prior_declared_mirror_urls(&dep.name);
        let prior_declared: Vec<String> = prior_declared_raw
            .into_iter()
            .filter(|u| manifest_mirror_set.contains(u.as_str()))
            .collect();
        let mut seen_urls: BTreeSet<String> = BTreeSet::new();
        let mut all_candidate_urls: Vec<String> = Vec::new();
        for url in std::iter::once(dep.git.as_str())
            .chain(dep.mirrors.iter().map(|s| s.as_str()))
            .chain(prior_declared.iter().map(|s| s.as_str()))
        {
            if seen_urls.insert(url.to_string()) {
                all_candidate_urls.push(url.to_string());
            }
        }

        let provs: Vec<Provenance> = all_candidate_urls
            .iter()
            .map(|url| git_prov(url, &dep.git_ref, pinned_sha.clone()))
            .collect();

        let dest = self.deps_dir.join(&dep.name);
        let (identity, receipt, observed_idx) =
            self.fetch_any_tracked(&dep.name, &provs, &dest, expected_identity.as_deref())?;

        let observed_url = &all_candidate_urls[observed_idx];
        let declared_mirror_urls: Vec<String> = all_candidate_urls
            .iter()
            .filter(|u| *u != observed_url)
            .cloned()
            .collect();

        // S3 RFC #23: collect positive flag requests from the dep declaration.
        // These activate flags in the fetched dep's milpa.kdl (single-hop only).
        let requested_flags: BTreeSet<String> = dep
            .flag_requests
            .iter()
            .filter(|fr| fr.enabled)
            .map(|fr| fr.name.clone())
            .collect();
        let ex =
            self.extract_requires(&dest, &dep.name, &url_dep_version(), false, None, None, requested_flags.clone())?;

        // Record the observed provenance with the resolved commit SHA.
        // (preferring the freshly-resolved SHA over a pin) for emission.
        let commit = receipt.resolved_ref.or(pinned_sha);
        let identity_str = identity.clone(); // save before move into Candidate
        self.store_candidate(Candidate {
            name: dep.name.clone(),
            version: url_dep_version(),
            identity,
            src_dir: ex.src_dir,
            requires_names: ex.requires_names,
            deps: ex.deps,
            provenance: Some(ProvenanceRecord::Git {
                url: observed_url.clone(),
                ref_spec: opt(&dep.git_ref),
                commit_sha: commit,
                origin: "observed".to_string(),
            }),
            // D-lifecycle: all candidate URLs except the observed one.
            declared_mirror_urls,
            dep_decl: None, // URL deps not in the index; no DepDecl pin
            requires_predicates: ex.requires_predicates,
        });

        // S3 / S4a / C1: unconditionally seed dep_active_flags for this URL dep so that
        // default-true flags are visible to the S4a fixpoint even when no consumer
        // flag_requests exist.  Keyed by identity (content_hash) — NORMATIVE per
        // spec/identity.md §3.1.2.
        if !identity_str.is_empty() {
            let kdl_path = dest.join("milpa.kdl");
            if kdl_path.is_file() {
                if let Ok(text) = std::fs::read_to_string(&kdl_path) {
                    if let Ok(manifest) = milpa_manifest::parse_manifest(&text) {
                        let frs: Vec<FlagRequest> = dep
                            .flag_requests
                            .iter()
                            .cloned()
                            .collect();
                        let active = compute_dep_active_flags(&manifest.flags, &frs);
                        if !active.is_empty() {
                            self.dep_active_flags
                                .borrow_mut()
                                .insert(identity_str.clone(), active);
                        }
                    }
                }
            }
        }

        self.process_items(ex.sub_items)?;
        Ok(())
    }

    fn process_local(&self, dep: LocalDep) -> Result<(), MilpaError> {
        if !self.seen_local.borrow_mut().insert(dep.path.clone()) {
            return Ok(());
        }
        let abs = self.project_root.join(&dep.path);
        let dest = self.deps_dir.join(&dep.name);
        // clear_dir uses exists() which does not follow dangling symlinks; use
        // clear_dest-equivalent logic (symlink-aware) by letting the fetcher
        // handle stale cleanup via clear_dest inside fetch_local.
        // Still need to ensure parent dir exists before fetching.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let prov = Provenance::Local {
            // The fetcher symlinks from the absolute path; the recorded
            // provenance keeps the *declared* relative path (portable).
            path: abs.to_string_lossy().into_owned(),
        };
        self.fetcher
            .fetch(&dep.name, &prov, &dest)
            .map_err(MilpaError::from)?;
        // LOCAL deps carry NO identity (cas_admissible = false, lockfile-schema
        // §4.3 NORMATIVE). The empty string is the "no identity" sentinel in
        // Candidate (same as the synthetic root). finalize() and build_graph()
        // both skip empty-identity entries, so local deps bypass content-hash
        // dedup (which is CAS-only). Mirrors Python FetcherRegistry → identity=None.
        let identity = String::new();
        let ex =
            self.extract_requires(&dest, &dep.name, &url_dep_version(), false, None, None, BTreeSet::new())?;
        self.store_candidate(Candidate {
            name: dep.name.clone(),
            version: url_dep_version(),
            identity,
            src_dir: ex.src_dir,
            requires_names: ex.requires_names,
            deps: ex.deps,
            provenance: Some(ProvenanceRecord::Local {
                // The recorded path is the *declared relative* path (portable),
                // not the absolute fetch path.
                path: dep.path.clone(),
                origin: "observed".to_string(),
            }),
            declared_mirror_urls: Vec::new(), // local deps have no mirrors
            dep_decl: None, // local deps not in the index; no DepDecl pin
            requires_predicates: ex.requires_predicates,
        });
        self.process_items(ex.sub_items)?;
        Ok(())
    }

    fn process_tarball(&self, dep: TarballDep) -> Result<(), MilpaError> {
        if !self.seen_tarball.borrow_mut().insert(dep.url.clone()) {
            return Ok(());
        }
        let (expected_identity, locked_sha256) = self.tarball_pin(&dep);
        // §5 (TOFU): re-assert the archive-level pin on refetch. A manifest
        // `sha256=` is authoritative; otherwise reuse the locked TOFU pin so a
        // substituted archive is rejected at the archive boundary, not just the
        // tree-hash boundary.
        let expected_sha256 = dep.sha256.clone().or_else(|| locked_sha256.clone());
        let prov = Provenance::Tarball {
            url: dep.url.clone(),
            expected_sha256,
            strip_components: dep.strip_components,
        };
        let dest = self.deps_dir.join(&dep.name);
        let (identity, receipt) = self.fetch_any(
            &dep.name,
            std::slice::from_ref(&prov),
            &dest,
            expected_identity.as_deref(),
        )?;
        let ex =
            self.extract_requires(&dest, &dep.name, &url_dep_version(), false, None, None, BTreeSet::new())?;
        // §5: record the TOFU pin. A manifest `sha256=` is authoritative; else
        // capture the digest the fetcher just computed (first fetch), falling
        // back to the prior lock's pin (refetch preserves it).
        let recorded_sha256 = dep
            .sha256
            .clone()
            .or(receipt.archive_sha256)
            .or(locked_sha256);
        self.store_candidate(Candidate {
            name: dep.name.clone(),
            version: url_dep_version(),
            identity,
            src_dir: ex.src_dir,
            requires_names: ex.requires_names,
            deps: ex.deps,
            dep_decl: None, // tarball deps not in the index; no DepDecl pin
            provenance: Some(ProvenanceRecord::Tarball {
                url: dep.url.clone(),
                sha256: recorded_sha256,
                origin: "observed".to_string(),
            }),
            declared_mirror_urls: Vec::new(), // tarball deps have no mirrors
            requires_predicates: ex.requires_predicates,
        });
        self.process_items(ex.sub_items)?;
        Ok(())
    }

    /// Phase A: enumerate index versions for a named dep as stubs (no fetch).
    /// `constraint` is a pre-parsed `VersionSet` — validated at the parse
    /// boundary (manifest: `MAN-DEP-NAMED-CONSTRAINT`; nimble:
    /// `MAN-NIMBLE-CONSTRAINT`). No re-parsing occurs here.
    fn process_named(&self, name: &str, constraint: VersionSet) -> Result<(), MilpaError> {
        if name == "nim" {
            self.seen_named.borrow_mut().insert(name.to_string());
            return Ok(());
        }
        // A member-named transitive dep is already satisfied by the in-tree
        // workspace member candidate — never index-resolve it.
        if self.member_names.contains(name) {
            return Ok(());
        }
        if !self.seen_named.borrow_mut().insert(name.to_string()) {
            return Ok(());
        }
        // Phase A enumerate: enumerate ALL versions from the index (enumerate-all
        // normative per resolver-semantics §2.1).  The solver owns satisfiability
        // via Term::require/incompatibility accumulation; the enumerator MUST NOT
        // pre-filter by the declared constraint.  Pre-filtering produces the
        // correct selected version on the happy path but emits TNG-NO-SATISFYING-VERSION
        // instead of the canonical SOLVE-CONFLICT on the error path.
        // TNG-NOT-FOUND / TNG-AMBIGUOUS-NAME / TNG-NO-PROVENANCE can still fire
        // (package absent, ambiguous namespace, or all versions lack provenance).
        let enumerate_all = VersionSet::full();
        let raw_str: Option<&str> = None;
        let versions = self
            .index
            .resolve_named_all(name, &enumerate_all, raw_str)
            .map_err(MilpaError::from)?;
        let mut by_ver: BTreeMap<Version, IndexVersion> = BTreeMap::new();
        for e in versions {
            if let Some(v) = parse_version(&e.version) {
                by_ver.insert(v, e);
            }
        }
        if !by_ver.is_empty() {
            self.stubs
                .borrow_mut()
                .entry(name.to_string())
                .or_default()
                .extend(by_ver);
        }
        Ok(())
    }

    /// Phase B: fetch + parse a named dep for the solver-selected version.
    fn materialize_named(
        &self,
        name: &str,
        version: &Version,
        entry: &IndexVersion,
    ) -> Result<Vec<SolverDep>, MilpaError> {
        // Identity gate (registry-protocol §4): the index content_hash is the
        // trust root for a named dep. A version with no identity cannot have its
        // fetched bytes verified, so it is refused before any fetch is attempted.
        if entry.content_hash.is_empty() {
            return Err(MilpaError::Core(CoreError::Tianguis(
                "TNG-NO-IDENTITY",
                format!(
                    "index entry for {name:?} version {:?} carries no content_hash \
                     — cannot verify fetched bytes (malformed index entry)",
                    entry.version
                ),
            )));
        }
        let dest = self.deps_dir.join(name);
        // The index provenances are preference-ordered (canonical, then mirrors);
        // fetch_any tries them in order, identity-gated on the content_hash.
        let (identity, _ref) = self.fetch_any(
            name,
            &entry.provenances,
            &dest,
            Some(entry.content_hash.as_str()),
        )?;
        // S3: look up flag_requests stored during seed_root for this named dep.
        let named_active_flags: BTreeSet<String> = self
            .flag_requests_by_name
            .borrow()
            .get(name)
            .map(|frs| {
                frs.iter()
                    .filter(|fr| fr.enabled)
                    .map(|fr| fr.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let ex = self.extract_requires(&dest, name, version, false,
                entry.dep_decl.as_deref(),
                entry.dep_decl_schema_version,
                named_active_flags)?;
        // S6: dep_decl pin records the artifact hash only when DepDeclEdgeSource was
        // actually used (edge_set.source == DepDecl). If we fell back to milpa.kdl or
        // nimble (e.g. non-strict FETCH-FAILED), the pin is None — matching Python:
        // `iv.dep_decl if es.source == EdgeSource.DEP_DECL else None`.
        let dep_decl_pin = if matches!(ex.edge_set.source, milpa_types::EdgeSource::DepDecl) {
            entry.dep_decl.clone()
        } else {
            None
        };
        let identity_str = identity.clone(); // save before move into Candidate (H3 key)
        let candidate = Candidate {
            name: name.to_string(),
            version: version.clone(),
            identity,
            src_dir: ex.src_dir,
            requires_names: ex.requires_names,
            deps: ex.deps.clone(),
            // Record the canonical (first) provenance for emission, mapped to
            // the emission-level record.
            provenance: entry.provenances.first().map(transport_to_record),
            // Named deps resolved via the index: declared mirror URLs are not
            // tracked here (D-lifecycle covers URL/git deps with manifest mirrors).
            declared_mirror_urls: Vec::new(),
            dep_decl: dep_decl_pin,
            requires_predicates: ex.requires_predicates,
        };
        self.store_candidate(candidate);
        self.stubs
            .borrow_mut()
            .get_mut(name)
            .map(|m| m.remove(version));

        // S3 / S11 / C1: unconditionally seed dep_active_flags for this named dep so
        // that default-true flags are visible to the S4a fixpoint even when no
        // consumer flag_requests exist.  Keyed by identity (content_hash) — NORMATIVE
        // per spec/identity.md §3.1.2.  Mirrors Python _materialize_candidate_named
        // lines 578-581 (which already seeds unconditionally via flag_requests_by_name
        // returning () when absent).
        if !identity_str.is_empty() {
            let kdl_path = dest.join("milpa.kdl");
            if kdl_path.is_file() {
                if let Ok(txt) = std::fs::read_to_string(&kdl_path) {
                    if let Ok(mf) = milpa_manifest::parse_manifest(&txt) {
                        let frs_guard = self.flag_requests_by_name.borrow();
                        let reqs: &[FlagRequest] =
                            frs_guard.get(name).map(|v| v.as_slice()).unwrap_or(&[]);
                        let active = compute_dep_active_flags(&mf.flags, reqs);
                        if !active.is_empty() {
                            self.dep_active_flags
                                .borrow_mut()
                                .insert(identity_str.clone(), active);
                        }
                    }
                }
            }
        }

        // Enroll transitives discovered in this named dep (URL fetched eagerly;
        // named enrolled as stubs) so the solver can continue without a restart.
        self.process_items(ex.sub_items)?;
        Ok(ex.deps)
    }

    // --- fetch + extract ---------------------------------------------------

    /// Try each candidate provenance in order, materializing into `dest` and
    /// gating on `expected_identity` when a pin exists (§8a). Returns the
    /// `(identity, resolved_ref)` of the first candidate that passes the gate;
    /// `FETCH-ALL-FAILED` if every candidate fails (network or identity).
    fn fetch_any(
        &self,
        name: &str,
        candidates: &[Provenance],
        dest: &Path,
        expected_identity: Option<&str>,
    ) -> Result<(String, Receipt), MilpaError> {
        let (identity, receipt, _idx) =
            self.fetch_any_tracked(name, candidates, dest, expected_identity)?;
        Ok((identity, receipt))
    }

    /// D-lifecycle variant of [`fetch_any`]: also returns the index of the
    /// successful candidate so the caller can identify the observed URL.
    ///
    /// Distinguishes two failure modes (RFC Phase D item 3):
    /// - **Transport failure** (network error, git non-zero, dead mirror): record
    ///   and try the next candidate.  `FETCH-ALL-FAILED` when every candidate fails.
    /// - **Fetch succeeds but identity ≠ locked pin**: supply-chain signal — raise
    ///   `FETCH-PROVENANCE-DIVERGENCE` **immediately**.  Must NOT fall through to the
    ///   next candidate; a mirror serving different bytes than the lock pinned must
    ///   not be silently worked around.
    fn fetch_any_tracked(
        &self,
        name: &str,
        candidates: &[Provenance],
        dest: &Path,
        expected_identity: Option<&str>,
    ) -> Result<(String, Receipt, usize), MilpaError> {
        let mut last_transport_err: Option<String> = None;
        for (idx, prov) in candidates.iter().enumerate() {
            clear_dir(dest)?;
            let receipt = match self.fetcher.fetch(name, prov, dest) {
                Ok(r) => r,
                Err(e) => {
                    // Transport failure: record and try the next candidate.
                    last_transport_err = Some(format!("{}: {}", e.code(), fetch_msg(&e)));
                    continue;
                }
            };
            // Fetch succeeded — validate identity gate when prior pin is set.
            let identity = compute_content_hash(dest)?;
            if let Some(exp) = expected_identity {
                if exp != identity {
                    // Supply-chain signal: raise loudly, do NOT try next candidate.
                    let prov_url = prov_url_str(prov);
                    return Err(MilpaError::Fetch(FetchError::ProvenanceDivergence(
                        format!(
                            "{name:?}: provenance {prov_url:?} succeeded but delivered \
                             divergent bytes — expected {exp}, got {identity}"
                        ),
                    )));
                }
            }
            return Ok((identity, receipt, idx));
        }
        clear_dir(dest)?;
        Err(MilpaError::Fetch(FetchError::AllFailed(format!(
            "all {} candidate(s) transport-failed for {name:?}: {}",
            candidates.len(),
            last_transport_err.unwrap_or_else(|| "no candidates".into())
        ))))
    }

    /// Read a fetched dep's transitive requires via the `EdgeSource` seam
    /// (§4.2.1). Implements the priority-ordered sourcing decision and memoizes
    /// the result in `edge_cache` (clause a). `version` is the solver-facing
    /// version (`url_dep_version()` for eager URL/local/tarball deps; the index
    /// version for named deps). `is_overridden` suppresses DepDecl (clause b).
    ///
    /// `dep_decl` and `dep_decl_schema_version` carry the index-attested DepDecl
    /// pointer for named deps (S3b clause c). Both are `None` for URL/local/tarball
    /// deps (not in the index).
    ///
    /// Returns `(solver deps, requires names, src_dir, sub-items)`.
    fn extract_requires(
        &self,
        dest: &Path,
        name: &str,
        version: &Version,
        is_overridden: bool,
        dep_decl: Option<&str>,
        dep_decl_schema_version: Option<i64>,
        // S3 RFC #23: active flags from the consumer's flag_requests. Non-empty
        // only for direct (root) URL deps — transitive hops pass `BTreeSet::new()`.
        // When non-empty, the edge_cache is bypassed (flag-parameterized EdgeSets
        // are not cached; S4a multi-hop fixpoint will handle caching).
        active_flags: BTreeSet<String>,
    ) -> Result<Extracted, MilpaError> {
        let has_milpa_kdl = dest.join("milpa.kdl").is_file();

        // Clause (a): cache hit → reconstruct Extracted from cached EdgeSet.
        // Bypass when active_flags is non-empty (S3: consumer-specific, not sharable).
        let cache_key = (name.to_string(), version.clone());
        if active_flags.is_empty() {
            let cache = self.edge_cache.borrow();
            if let Some(es) = cache.get(&cache_key) {
                return self.edgeset_to_extracted(es, name);
            }
        }

        // Cache miss (or active_flags bypass): dispatch to appropriate source (clauses b/c/d).
        let es: EdgeSet = if is_overridden {
            // Clause (b): is_overridden suppresses DepDecl — use milpa.kdl or nimble.
            if has_milpa_kdl {
                let text =
                    std::fs::read_to_string(dest.join("milpa.kdl")).map_err(io_err)?;
                let manifest = milpa_manifest::parse_manifest(&text)?;
                self.build_edgeset_from_manifest(&manifest, &BTreeSet::new())
            } else {
                let ctx = EdgeSourceCtx {
                    dep_path: Some(dest),
                    dep_name: name,
                    dep_decl: None,
                    is_overridden,
                    has_milpa_kdl: false,
                    dep_decl_schema_version: None,
                    overrides_by_name: &self.overrides,
                    active_flags: BTreeSet::new(),
                };
                let src = NimbleEdgeSource;
                src.edges_for(name, version, &ctx)?
            }
        } else if dep_decl.is_some() {
            if let Some(store) = self.dep_decl_store {
                // Clause (c): index-attested DepDecl mainline (S3b).
                //
                // S5 policy gate (spec §6 / resolver-semantics §13; Python edge_sources.py:488-500):
                //   TNG-DEPDECL-FETCH-FAILED: policy-gated.
                //     Non-strict → fall through to milpa.kdl / nimble (NimbleFallback).
                //     Strict     → hard error (propagate).
                //   Integrity failures (HASH-MISMATCH, PARSE-ERROR, SCHEMA-*):
                //     ALWAYS hard regardless of policy — supply-chain invariant.
                let source = crate::edge_sources::DepDeclEdgeSource::new(store);
                let ctx = EdgeSourceCtx {
                    dep_path: Some(dest),
                    dep_name: name,
                    dep_decl,
                    is_overridden: false,
                    has_milpa_kdl,
                    dep_decl_schema_version,
                    overrides_by_name: &self.overrides,
                    active_flags: BTreeSet::new(),
                };
                match source.edges_for_result(name, &ctx) {
                    Ok(es) => es,
                    Err(ref e) if e.code() == "TNG-DEPDECL-FETCH-FAILED" && !self.strict_attestation => {
                        // Non-strict: artifact unreachable → fall through to milpa.kdl / nimble.
                        // The attestation-policy summary warning fires after solve() via
                        // enforce_attestation_policy (same path as any NimbleFallback dep).
                        if has_milpa_kdl {
                            let text =
                                std::fs::read_to_string(dest.join("milpa.kdl")).map_err(io_err)?;
                            let manifest = milpa_manifest::parse_manifest(&text)?;
                            self.build_edgeset_from_manifest(&manifest, &BTreeSet::new())
                        } else {
                            let fallback_ctx = EdgeSourceCtx {
                                dep_path: Some(dest),
                                dep_name: name,
                                dep_decl: None,
                                is_overridden: false,
                                has_milpa_kdl: false,
                                dep_decl_schema_version: None,
                                overrides_by_name: &self.overrides,
                                active_flags: BTreeSet::new(),
                            };
                            let src = NimbleEdgeSource;
                            src.edges_for(name, version, &fallback_ctx)?
                        }
                    }
                    Err(e) => return Err(e),
                }
            } else {
                // dep_decl_store=None (S4-i compat): fall through to milpa.kdl / nimble.
                if has_milpa_kdl {
                    let text =
                        std::fs::read_to_string(dest.join("milpa.kdl")).map_err(io_err)?;
                    let manifest = milpa_manifest::parse_manifest(&text)?;
                    self.build_edgeset_from_manifest(&manifest, &BTreeSet::new())
                } else {
                    let ctx = EdgeSourceCtx {
                        dep_path: Some(dest),
                        dep_name: name,
                        dep_decl,
                        is_overridden: false,
                        has_milpa_kdl: false,
                        dep_decl_schema_version,
                        overrides_by_name: &self.overrides,
                        active_flags: BTreeSet::new(),
                    };
                    let src = NimbleEdgeSource;
                    src.edges_for(name, version, &ctx)?
                }
            }
        } else if has_milpa_kdl {
            // Clause (d): milpa.kdl present — parse with flag-predicate filtering.
            // For milpa.kdl, parse the manifest here so we can apply flag-predicate
            // filtering (§6 transitive: each dep evaluates against its own default
            // flags, merged with S3 active_flags from the consumer's flag_requests).
            // Flag filtering is resolver-local and not part of the EdgeSource
            // seam's normative projection; it happens before constructing the EdgeSet.
            let text = std::fs::read_to_string(dest.join("milpa.kdl")).map_err(io_err)?;
            let manifest = milpa_manifest::parse_manifest(&text)?;
            self.build_edgeset_from_manifest(&manifest, &active_flags)
        } else {
            // Clause (d/else): nimble fallback.
            let ctx = EdgeSourceCtx {
                dep_path: Some(dest),
                dep_name: name,
                dep_decl: None,
                is_overridden: false,
                has_milpa_kdl: false,
                dep_decl_schema_version: None,
                overrides_by_name: &self.overrides,
                active_flags: BTreeSet::new(),
            };
            let src = NimbleEdgeSource;
            src.edges_for(name, version, &ctx)?
        };

        // Seal cache (clause a) — skip when active_flags was non-empty (S3 bypass).
        let extracted = self.edgeset_to_extracted(&es, name)?;
        if active_flags.is_empty() {
            self.edge_cache.borrow_mut().insert(cache_key, es);
        }
        Ok(extracted)
    }

    /// Build an `EdgeSet` from a parsed `milpa.kdl` manifest, applying flag-
    /// predicate filtering (§6 transitive: each dep evaluates against its own
    /// default flags, merged with `active_flags` from S3 consumer requests).
    /// Only `manifest.deps` is included — **never** `dev_deps` (§9) — and
    /// `overrides` are dropped entirely (§10.2).
    ///
    /// `active_flags`: S3 RFC #23 cross-package requests from the consumer's dep
    /// declaration. Merged with the manifest's own defaults before filtering.
    /// Pass `&BTreeSet::new()` for transitive hops (single-hop S3 scope).
    ///
    /// Flag filtering is applied here (resolver-local) rather than in
    /// `edge_sources::manifest_to_edgeset` (which is the pure normative
    /// projection used by tests that don't need flag filtering).
    fn build_edgeset_from_manifest(&self, manifest: &Manifest, active_flags: &BTreeSet<String>) -> EdgeSet {
        use milpa_types::{NamedRequire, RequireEntry, UrlRequire};
        // Merge manifest defaults with S3 consumer requests.
        let mut active: BTreeSet<&str> = manifest
            .flags
            .iter()
            .filter(|f| f.default)
            .map(|f| f.name.as_str())
            .collect();
        for flag in active_flags {
            active.insert(flag.as_str());
        }
        let mut requires = Vec::new();
        for d in &manifest.deps {
            if !dep_passes_flag_predicates(d, &active) {
                continue;
            }
            match d {
                Dep::Url(u) => {
                    // S4b: carry flag_requests from the dep declaration so that
                    // `edgeset_to_extracted` can reconstruct them in the Item::Url.
                    // This is the only UrlRequire construction site where flag_requests
                    // may be non-empty (direct milpa.kdl dep entries with `flag` children).
                    // FlagRequest is the SSOT (milpa-types); no conversion needed.
                    requires.push(RequireEntry::Url(UrlRequire {
                        url: u.git.clone(),
                        ref_: u.git_ref.clone(),
                        predicates: Vec::new(),
                        flag_requests: u.flag_requests.clone(),
                    }));
                }
                Dep::Named(n) => {
                    if n.name == "nim" {
                        continue;
                    }
                    requires.push(RequireEntry::Named(NamedRequire {
                        name: n.name.clone(),
                        constraint_str: n.constraint.clone().unwrap_or_default(),
                        predicates: Vec::new(),
                    }));
                }
                Dep::Local(_) | Dep::Tarball(_) | Dep::Member(_) => {}
            }
        }
        // §10.2: manifest.overrides dropped entirely — NOT included in EdgeSet
        EdgeSet {
            requires,
            src_dir: manifest.src_dir.clone(),
            source: milpa_types::EdgeSource::MilpaKdl,
        }
    }

    /// Convert an `EdgeSet` → `Extracted` (solver deps, names, src_dir, sub-items).
    /// Override-aware: named transitive deps that are themselves overridden enter
    /// as `eq_sentinel()` (§10); named deps without override use their constraint.
    /// The original `EdgeSet` is preserved on the struct so callers can inspect
    /// `edge_set.source` (e.g. `EdgeSource::DepDecl`) at the use-site.
    fn edgeset_to_extracted(&self, es: &EdgeSet, _name: &str) -> Result<Extracted, MilpaError> {
        use milpa_types::RequireEntry;
        let mut deps: Vec<SolverDep> = Vec::new();
        let mut requires_names: Vec<String> = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        // S4 (C1 fix): accumulate all predicate-vecs per name; do NOT overwrite.
        let mut requires_predicates: std::collections::BTreeMap<String, Vec<Vec<milpa_types::Predicate>>> =
            std::collections::BTreeMap::new();
        // Dedup for solver terms (dep name must appear exactly once as a Term).
        let mut seen_dep_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for entry in &es.requires {
            match entry {
                RequireEntry::Url(u) => {
                    let dep_name = name_from_url(&u.url)?;
                    if !seen_dep_names.contains(&dep_name) {
                        deps.push(SolverDep::new(dep_name.clone(), eq_sentinel()));
                        requires_names.push(dep_name.clone());
                        // S4b: reconstruct flag_requests from UrlRequire so
                        // process_url sees them for multi-consumer union (§3.1.3).
                        // FlagRequest is the SSOT (milpa-types); no conversion needed.
                        let mut url_d = url_dep(&dep_name, &u.url, &u.ref_);
                        url_d.flag_requests = u.flag_requests.clone();
                        items.push(Item::Url(url_d));
                        seen_dep_names.insert(dep_name.clone());
                    }
                    // S4: accumulate predicates if non-empty (do not overwrite).
                    if !u.predicates.is_empty() {
                        requires_predicates.entry(dep_name).or_default().push(u.predicates.clone());
                    }
                }
                RequireEntry::Named(n) => {
                    if !seen_dep_names.contains(&n.name) {
                        // Override check: a named transitive dep that is itself overridden
                        // enters as eq_sentinel() so the resolver routes it through the
                        // override URL fetch (§10).
                        let vs = if self.overrides.contains_key(&n.name) {
                            eq_sentinel()
                        } else {
                            // Constraint validation: milpa.kdl constraints are validated
                            // at the manifest-parse boundary (MAN-DEP-NAMED-CONSTRAINT) and
                            // are already valid here. Nimble constraints are validated here
                            // for the first time → MAN-NIMBLE-CONSTRAINT on failure.
                            let constraint_opt = if n.constraint_str.is_empty() {
                                None
                            } else {
                                Some(n.constraint_str.as_str())
                            };
                            match VersionSet::from_constraint(constraint_opt) {
                                Ok(vs) => vs,
                                Err(e) => {
                                    if matches!(es.source, milpa_types::EdgeSource::NimbleFallback) {
                                        return Err(MilpaError::Manifest(
                                            milpa_manifest::ManifestError::new(
                                                "MAN-NIMBLE-CONSTRAINT",
                                                format!(
                                                    "malformed version constraint {:?}: {e}",
                                                    n.constraint_str
                                                ),
                                            ),
                                        ));
                                    }
                                    VersionSet::full()
                                }
                            }
                        };
                        deps.push(SolverDep::new(n.name.clone(), vs.clone()));
                        requires_names.push(n.name.clone());
                        items.push(Item::Named {
                            name: n.name.clone(),
                            constraint: vs,
                        });
                        seen_dep_names.insert(n.name.clone());
                    }
                    // S4: accumulate predicates if non-empty (do not overwrite).
                    if !n.predicates.is_empty() {
                        requires_predicates.entry(n.name.clone()).or_default().push(n.predicates.clone());
                    }
                }
            }
        }

        // Carry the full EdgeSet so callers can inspect edge_set.source
        // at the use-site (e.g. `EdgeSource::DepDecl` for the dep_decl pin).
        // The previous lossy `bool dep_decl_used` is gone — derive it at
        // the call-site with `matches!(x.edge_set.source, EdgeSource::DepDecl)`.
        Ok(Extracted {
            deps,
            requires_names,
            src_dir: es.src_dir.clone(),
            sub_items: items,
            edge_set: es.clone(),
            requires_predicates,
        })
    }

    // --- pin reuse (§8) ----------------------------------------------------

    /// `(expected_identity, pinned_commit)` for a URL dep whose manifest `(git,
    /// ref)` still matches the prior lockfile's git record. Both come from the
    /// same matched record (single source of truth).
    fn git_pin(&self, dep: &UrlDep) -> (Option<String>, Option<String>) {
        let Some(prior) = self.prior else {
            return (None, None);
        };
        let Some(locked) = prior.deps.iter().find(|d| d.name == dep.name) else {
            return (None, None);
        };
        let Some(identity) = locked.identity.clone().filter(|s| !s.is_empty()) else {
            return (None, None);
        };
        // Search ALL GitProvenanceRecords for one matching (url, ref) so that
        // a declared mirror record appearing before the observed record in the
        // sorted provenances list does not shadow it (§8 pin-reuse,
        // D-provenance ordering — mirrors Python _git_pin_for_url_dep fix).
        for p in &locked.provenances {
            if let ProvenanceRecord::Git {
                url,
                ref_spec,
                commit_sha,
                ..
            } = p
            {
                if url == &dep.git && ref_spec.as_deref() == Some(dep.git_ref.as_str()) {
                    return (Some(identity), commit_sha.clone());
                }
            }
        }
        (None, None)
    }

    /// `(expected_identity, locked_sha256)` for a tarball dep whose manifest URL
    /// still matches the prior lockfile's tarball record. Both come from the same
    /// matched record (single source of truth — mirrors [`Self::git_pin`]).
    fn tarball_pin(&self, dep: &TarballDep) -> (Option<String>, Option<String>) {
        let Some(prior) = self.prior else {
            return (None, None);
        };
        let Some(locked) = prior.deps.iter().find(|d| d.name == dep.name) else {
            return (None, None);
        };
        let Some(identity) = locked.identity.clone().filter(|s| !s.is_empty()) else {
            return (None, None);
        };
        for p in &locked.provenances {
            if let ProvenanceRecord::Tarball { url, sha256, .. } = p {
                if url == &dep.url {
                    return (Some(identity), sha256.clone());
                }
            }
        }
        (None, None)
    }

    /// D-provenance: extract URLs from prior lockfile's declared-origin
    /// GitProvenanceRecords for `name`. These feed the fallback candidate list
    /// during fetch (same role as the old `self_mirrors` field).
    fn prior_declared_mirror_urls(&self, name: &str) -> Vec<String> {
        self.prior
            .and_then(|p| p.deps.iter().find(|d| d.name == name))
            .map(|d| {
                d.provenances
                    .iter()
                    .filter_map(|p| {
                        if let milpa_types::ProvenanceRecord::Git { url, origin, .. } = p {
                            if origin == "declared" {
                                return Some(url.clone());
                            }
                        }
                        None
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // --- finalize / graph --------------------------------------------------

    /// Content-hash dedup/alias (Phase B, #32): eagerly-materialized candidates
    /// sharing an identity collapse to ONE canonical node. The canonical name is
    /// the group member discovered EARLIEST in BFS-insertion order (NOT the
    /// lexicographically-smallest name — BFS-first beats lex-min so that root-
    /// declared names win over alphabetically-earlier transitive aliases).
    ///
    /// Duplicates' `_deps/<name>` dirs are removed and every surviving
    /// candidate's deps + requires_names are rewritten to the canonical name.
    /// Named candidates are materialized after this point and bypass dedup.
    ///
    /// Returns a map from canonical name → sorted list of aliases, for
    /// `build_graph` to populate `ResolvedDep.aliases` / lockfile emission.
    fn finalize(&self) -> BTreeMap<String, Vec<String>> {
        let mut cands = self.candidates.borrow_mut();
        let mut by_hash: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, versions) in cands.iter() {
            for c in versions.values() {
                if c.identity.is_empty() {
                    continue; // the synthetic root
                }
                by_hash
                    .entry(c.identity.clone())
                    .or_default()
                    .push(name.clone());
            }
        }

        // Build a discovery-order index for fast lookup.
        let discovery_index: BTreeMap<String, usize>;
        let large: usize;
        {
            let discovery = self.discovery_order.borrow();
            large = discovery.len(); // sentinel for names not in discovery_order
            discovery_index = discovery
                .iter()
                .enumerate()
                .map(|(i, n)| (n.clone(), i))
                .collect();
        }

        // aliases_map: non-canonical → canonical name.
        let mut aliases_map: BTreeMap<String, String> = BTreeMap::new();
        // canonical_aliases: canonical → sorted list of non-canonical aliases.
        let mut canonical_aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for (_hash, mut group) in by_hash {
            if group.len() < 2 {
                continue;
            }
            // Pick canonical = group member with smallest BFS-insertion index.
            // Ties (not expected in practice) fall back to lex order for determinism.
            group.sort_by(|a, b| {
                let ia = discovery_index.get(a).copied().unwrap_or(large);
                let ib = discovery_index.get(b).copied().unwrap_or(large);
                ia.cmp(&ib).then_with(|| a.cmp(b))
            });
            let canonical = group[0].clone();
            let mut aliases: Vec<String> = group[1..].to_vec();
            aliases.sort(); // lex-sort the alias list for deterministic output
            for other in &aliases {
                aliases_map.insert(other.clone(), canonical.clone());
                cands.remove(other);
                // NOTE: _deps/<other> cleanup is intentionally OMITTED here.
                // rebuild_deps_view (B-nimcfg SSOT) owns _deps/ contents and will
                // remove stale non-canonical dirs and create alias symlinks atomically.
            }
            canonical_aliases.insert(canonical, aliases);
        }

        if aliases_map.is_empty() {
            return canonical_aliases; // empty
        }
        for versions in cands.values_mut() {
            for c in versions.values_mut() {
                for d in &mut c.deps {
                    if let Some(can) = aliases_map.get(&d.package) {
                        d.package = can.clone();
                    }
                }
                for r in &mut c.requires_names {
                    if let Some(can) = aliases_map.get(r) {
                        *r = can.clone();
                    }
                }
            }
        }

        canonical_aliases
    }

    /// Map the solver solution → a topologically-ordered [`ResolvedGraph`]
    /// (deps before dependents), excluding the synthetic root. Canonical
    /// lexicographic *emission* order is applied later (S7c).
    ///
    /// `canonical_aliases` maps canonical name → lex-sorted list of aliases
    /// (from the Phase B dedup pass); used to populate `ResolvedDep.aliases`.
    fn build_graph(
        &self,
        solution: &BTreeMap<String, Version>,
        canonical_aliases: &BTreeMap<String, Vec<String>>,
    ) -> ResolvedGraph {
        let cands = self.candidates.borrow();
        let mut chosen: BTreeMap<String, Candidate> = BTreeMap::new();
        for (name, version) in solution {
            if name == ROOT {
                continue;
            }
            if let Some(c) = cands.get(name).and_then(|m| m.get(version)) {
                chosen.insert(name.clone(), c.clone());
            }
        }

        let mut ordered: Vec<String> = Vec::new();
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut visiting: BTreeSet<String> = BTreeSet::new();
        // Deterministic traversal seed order (the solution map is already sorted).
        let names: Vec<String> = chosen.keys().cloned().collect();
        for n in &names {
            topo_visit(n, &chosen, &mut ordered, &mut visited, &mut visiting);
        }

        let deps = ordered
            .into_iter()
            .filter_map(|n| chosen.get(&n))
            .map(|c| {
                // S4: build cond_requires from requires_predicates.
                // Each (name, pred_vecs) entry may have ≥1 inner Vec<Predicate>
                // (one per when-branch occurrence — C1 fix).  Emit one CondRequire
                // per inner entry.  Sort by (name, canonical-predicate-string) for
                // a total order that is byte-deterministic across impls (§2.4).
                let mut cond_requires: Vec<milpa_types::CondRequire> = c
                    .requires_predicates
                    .iter()
                    .flat_map(|(rname, pred_vecs)| {
                        pred_vecs.iter().filter(|pv| !pv.is_empty()).map(move |preds| {
                            milpa_types::CondRequire {
                                name: rname.clone(),
                                predicates: preds.clone(),
                            }
                        })
                    })
                    .collect();
                // Delegates to lockfile::cond_require_sort_key (SSOT) so
                // escaping is shared with the emitter — cannot drift (C1 fix).
                cond_requires.sort_by_key(|cr| cond_require_sort_key(cr));
                ResolvedDep {
                    name: c.name.clone(),
                    identity: c.identity.clone(),
                    version: c.version.clone(),
                    src_dir: c.src_dir.clone(),
                    requires: c.requires_names.clone(),
                    // D-lifecycle: assemble provenances = observed + declared mirrors.
                    // The observed record is the one that was fetched+verified.
                    // Declared records are all candidate URLs that were NOT the
                    // observed one (manifest mirrors + prior declared).
                    provenances: {
                        let observed = c.provenance.clone().unwrap_or(ProvenanceRecord::Local {
                            path: String::new(),
                            origin: "observed".to_string(),
                        });
                        // Derive ref from the observed record for declared records.
                        let ref_spec: Option<String> = match &observed {
                            ProvenanceRecord::Git { ref_spec, .. } => ref_spec.clone(),
                            _ => None,
                        };
                        let mut provs = vec![observed];
                        // Add one declared GitProvenanceRecord per declared mirror URL.
                        for mirror_url in &c.declared_mirror_urls {
                            provs.push(ProvenanceRecord::Git {
                                url: mirror_url.clone(),
                                ref_spec: ref_spec.clone(),
                                commit_sha: None, // declared = unverified
                                origin: "declared".to_string(),
                            });
                        }
                        provs
                    },
                    dep_decl: c.dep_decl.clone(),
                    cond_requires,
                    // Phase B: lex-sorted alias list for this canonical dep.
                    // Empty for non-deduped deps.
                    aliases: canonical_aliases
                        .get(&c.name)
                        .cloned()
                        .unwrap_or_default(),
                    // S5 (RFC #23 §4): populate active_flags from the converged
                    // dep_active_flags map, keyed by identity (content_hash) — NORMATIVE
                    // per spec/identity.md §3.1.2.  For deps with no consumer flag
                    // requests, fall back to computing defaults-only active set from
                    // the dep's manifest.  Lexicographically sorted (normative).
                    active_flags: {
                        use milpa_manifest::parse_manifest as parse_mf;
                        let active_map: std::collections::BTreeMap<String, _> = {
                            let daf = self.dep_active_flags.borrow();
                            // H3: key by identity, not dep_name.
                            match daf.get(c.identity.as_str()).filter(|m| !m.is_empty()) {
                                Some(m) => m.clone(),
                                None => {
                                    // No entry — compute defaults-only from manifest.
                                    drop(daf);
                                    let kdl_path = self.deps_dir.join(&c.name).join("milpa.kdl");
                                    if let Ok(txt) = std::fs::read_to_string(&kdl_path) {
                                        if let Ok(mf) = parse_mf(&txt) {
                                            compute_dep_active_flags(&mf.flags, &[])
                                        } else {
                                            Default::default()
                                        }
                                    } else {
                                        Default::default()
                                    }
                                }
                            }
                        };
                        // Lex-sorted — BTreeMap keys are already sorted.
                        active_map.into_keys().collect()
                    },
                }
            })
            .collect();
        ResolvedGraph { deps }
    }

    // --- shared helpers ----------------------------------------------------

    fn store_candidate(&self, c: Candidate) {
        self.candidates
            .borrow_mut()
            .entry(c.name.clone())
            .or_default()
            .insert(c.version.clone(), c);
    }

    fn capture(&self, e: MilpaError) {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(e);
        }
    }

    fn take_error(&self) -> Option<MilpaError> {
        self.error.borrow_mut().take()
    }

    /// S4a (RFC #23 §3.1.2 + §7 S4a): outer dep×flag fixpoint.
    ///
    /// Iterates until neither `dep_active_flags` nor the admitted dep set grows:
    ///   1. Scan all known candidate dep names and load their milpa.kdl manifests.
    ///   2. For each dep with active flags, fire `enables_cross_pkg` to generate
    ///      new `FlagRequest`s for target deps.
    ///   3. Recompute `active(target)` for each target; detect changes (monotone).
    ///   4. For deps with updated active_flags, find newly-admitted edges.
    ///   5. Extend the parent candidate's `deps`/`requires_names`; enqueue new items.
    ///   6. Re-run `process_items` for newly-admitted deps.
    ///   7. Repeat until stable.
    ///
    /// **PubGrub runs exactly once**, after this fixpoint converges.
    /// **Termination**: bounded by finite (deps × flags per dep) universe.
    fn run_s4a_fixpoint(&self) -> Result<(), MilpaError> {
        const MAX_ITERS: usize = 50; // safety belt; termination rests on monotonicity
        // R2-M DoS hardening: absolute bound on total (dep,flag) activations across
        // the whole fixpoint.  10_000 is far above any realistic graph and far below a
        // crafted-wide DoS attempt.  Must match Python _MAX_TOTAL_ACTIVATIONS.
        const MAX_TOTAL_ACTIVATIONS: usize = 10_000;
        let mut total_activations: usize = 0;
        let mut converged = false;

        for _ in 0..MAX_ITERS {
            // ----------------------------------------------------------------
            // Step 1: collect known dep names and their manifests.
            // ----------------------------------------------------------------
            let dep_names: Vec<String> = self.candidates
                .borrow()
                .keys()
                .filter(|n| n.as_str() != "__root__")
                .cloned()
                .collect();

            // dep_name → parsed Manifest
            let mut dep_manifests: BTreeMap<String, milpa_manifest::Manifest> = BTreeMap::new();
            for name in &dep_names {
                let kdl_path = self.deps_dir.join(name).join("milpa.kdl");
                if kdl_path.is_file() {
                    if let Ok(text) = std::fs::read_to_string(&kdl_path) {
                        if let Ok(manifest) = milpa_manifest::parse_manifest(&text) {
                            dep_manifests.insert(name.clone(), manifest);
                        }
                    }
                }
            }

            // ----------------------------------------------------------------
            // Step 2: compute cross-pkg enables from all active flags.
            // ----------------------------------------------------------------
            // Maps target_dep_name → Vec<FlagRequest> to merge into active(target).
            let mut additional_requests: BTreeMap<String, Vec<FlagRequest>> =
                BTreeMap::new();

            {
                // H3: build dep_name → identity map for identity-keyed lookups.
                let dep_identities: BTreeMap<String, String> = {
                    let cands = self.candidates.borrow();
                    dep_names.iter()
                        .filter_map(|n| {
                            cands.get(n)
                                .and_then(|m| m.values().next())
                                .map(|c| (n.clone(), c.identity.clone()))
                        })
                        .filter(|(_, id)| !id.is_empty())
                        .collect()
                };
                let daf = self.dep_active_flags.borrow();
                for (dep_name, manifest) in &dep_manifests {
                    // H3: look up by identity, not dep_name.
                    let identity = match dep_identities.get(dep_name) {
                        Some(id) => id,
                        None => continue,
                    };
                    let active_now = match daf.get(identity) {
                        Some(m) => m,
                        None => continue,
                    };
                    // For each active flag, fire its enables_cross_pkg.
                    for flag_decl in &manifest.flags {
                        if !active_now.contains_key(&flag_decl.name) {
                            continue;
                        }
                        for cpe in &flag_decl.enables_cross_pkg {
                            additional_requests
                                .entry(cpe.dep.clone())
                                .or_default()
                                .extend(cpe.flag_requests.iter().cloned());
                        }
                    }
                }
            }

            if additional_requests.is_empty() {
                converged = true;
                break; // No cross-pkg enables fired — stable.
            }

            // ----------------------------------------------------------------
            // Step 3: recompute active(target) for each target dep.
            // ----------------------------------------------------------------
            let mut any_change = false;
            let mut new_items: Vec<Item> = Vec::new();

            for (target_name, new_reqs) in &additional_requests {
                let target_manifest = match dep_manifests.get(target_name) {
                    Some(m) => m,
                    None => continue, // target not yet fetched
                };

                // H3: look up target identity for identity-keyed dep_active_flags access.
                let target_identity: String = self.candidates.borrow()
                    .get(target_name)
                    .and_then(|m| m.values().next())
                    .map(|c| c.identity.clone())
                    .unwrap_or_default();
                if target_identity.is_empty() {
                    continue; // no identity (local dep) — skip
                }

                // Previous active_flags (keyed by identity).
                let old_flag_names: BTreeSet<String> = self
                    .dep_active_flags
                    .borrow()
                    .get(&target_identity)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default();

                // Recompute active via SSOT.
                let new_active = compute_dep_active_flags(&target_manifest.flags, new_reqs);

                // R3-C fix: compute the UNION of old flags and this iteration's
                // new flags LOCALLY (mirrors Python: `merged = dict(prev_active);
                // merged.update(new_active); new_flag_names = frozenset(merged.keys())`).
                // Using new_active.keys() alone for convergence was wrong: when old
                // flags come from an S3 seed (e.g. {feat-x}) and the current
                // iteration only contributes {feat-y}, new_active.keys()={feat-y}
                // never equals old_flag_names={feat-x, feat-y} → infinite loop.
                // This also removes the R2 read-back-from-store smell (Finding-5):
                // the locally-computed union serves both convergence check AND edge
                // admission, with no need to re-borrow dep_active_flags after write.
                let merged_flag_names: BTreeSet<String> = old_flag_names
                    .iter()
                    .cloned()
                    .chain(new_active.keys().cloned())
                    .collect();

                if merged_flag_names == old_flag_names {
                    continue; // No change — union equals old set; already converged.
                }
                any_change = true;

                // R2-M DoS hardening: count newly-added (dep,flag) activations
                // (union-minus-old, consistent with Python's len(new_flag_names - old_flag_names)).
                let newly_added_count = merged_flag_names.difference(&old_flag_names).count();
                total_activations = total_activations.saturating_add(newly_added_count);
                if total_activations > MAX_TOTAL_ACTIVATIONS {
                    return Err(MilpaError::Core(CoreError::Resolver(
                        "MILPA-INTERNAL",
                        format!(
                            "S4a flag fixpoint exceeded {} total (dep,flag) activations — \
                             this is an internal milpa bug or a pathologically wide manifest; \
                             please report it",
                            MAX_TOTAL_ACTIVATIONS
                        ),
                    )));
                }

                // Union with previous (monotone — never subtract), keyed by identity.
                {
                    let mut daf = self.dep_active_flags.borrow_mut();
                    let entry = daf.entry(target_identity.clone()).or_default();
                    for (flag_name, sources) in &new_active {
                        entry
                            .entry(flag_name.clone())
                            .or_default()
                            .extend(sources.iter().cloned());
                    }
                }

                // ----------------------------------------------------------------
                // Step 4: find newly-admitted deps for the target.
                // ----------------------------------------------------------------
                // Use the locally-computed union (merged_flag_names) for edge
                // admission — same value used for convergence above.  This avoids
                // the Finding-5 read-back-from-store: no second borrow of
                // dep_active_flags needed; the union is already in hand.
                let old_active_set: BTreeSet<&str> =
                    old_flag_names.iter().map(|s| s.as_str()).collect();
                let new_active_set: BTreeSet<&str> =
                    merged_flag_names.iter().map(|s| s.as_str()).collect();

                for dep in &target_manifest.deps {
                    let was_admitted = dep_passes_flag_predicates(dep, &old_active_set);
                    let is_admitted = dep_passes_flag_predicates(dep, &new_active_set);
                    if is_admitted && !was_admitted {
                        // ----------------------------------------------------------------
                        // Step 5a: extend the parent (target) candidate's deps/requires_names.
                        // ----------------------------------------------------------------
                        let sub_name = dep.name().to_string();
                        {
                            let mut cands = self.candidates.borrow_mut();
                            if let Some(version_map) = cands.get_mut(target_name) {
                                if let Some(cand) = version_map.values_mut().next() {
                                    if !cand.requires_names.contains(&sub_name) {
                                        let vs = match dep {
                                            Dep::Url(_) | Dep::Local(_) | Dep::Tarball(_) | Dep::Member(_) => eq_sentinel(),
                                            Dep::Named(n) => {
                                                if self.overrides.contains_key(&n.name) {
                                                    eq_sentinel()
                                                } else {
                                                    let constraint_opt = n.constraint.as_deref().filter(|s| !s.is_empty());
                                                    VersionSet::from_constraint(constraint_opt).unwrap_or_else(|_| VersionSet::full())
                                                }
                                            }
                                        };
                                        cand.deps.push(SolverDep::new(sub_name.clone(), vs));
                                        cand.requires_names.push(sub_name.clone());
                                    }
                                }
                            }
                        }

                        // ----------------------------------------------------------------
                        // Step 5b: enqueue for fetch if not already seen.
                        // ----------------------------------------------------------------
                        match dep {
                            Dep::Url(u) => {
                                let key = (u.git.clone(), u.git_ref.clone());
                                if !self.seen_url.borrow().contains(&key) {
                                    new_items.push(Item::Url(u.clone()));
                                }
                            }
                            Dep::Named(n) => {
                                if !self.seen_named.borrow().contains(&n.name) {
                                    let constraint = if self.overrides.contains_key(&n.name) {
                                        eq_sentinel()
                                    } else {
                                        let c = n.constraint.as_deref().filter(|s| !s.is_empty());
                                        VersionSet::from_constraint(c).unwrap_or_else(|_| VersionSet::full())
                                    };
                                    new_items.push(Item::Named {
                                        name: n.name.clone(),
                                        constraint,
                                    });
                                }
                            }
                            Dep::Local(l) => {
                                if !self.seen_local.borrow().contains(&l.path) {
                                    new_items.push(Item::Local(l.clone()));
                                }
                            }
                            Dep::Tarball(t) => {
                                if !self.seen_tarball.borrow().contains(&t.url) {
                                    new_items.push(Item::Tarball(t.clone()));
                                }
                            }
                            Dep::Member(_) => {} // not handled in fixpoint
                        }
                    }
                }
            }

            if !any_change {
                converged = true;
                break;
            }

            // ----------------------------------------------------------------
            // Step 6: process newly-enqueued items.
            // ----------------------------------------------------------------
            if !new_items.is_empty() {
                self.process_items(new_items)?;
            }
        }

        // M3: cap exhaustion is a bug — fail loud rather than silently truncating.
        // Monotonicity guarantees convergence in O(|deps|×max_flags) well under MAX_ITERS.
        if !converged {
            return Err(MilpaError::Core(CoreError::Resolver(
                "MILPA-INTERNAL",
                format!(
                    "S4a flag fixpoint did not converge in {} iterations — \
                     this is an internal milpa bug; please report it",
                    MAX_ITERS
                ),
            )));
        }

        Ok(())
    }

    /// S4c (RFC #23 §3.1.4): post-fixpoint flag-conflict validation.
    ///
    /// Runs AFTER the dep×flag fixpoint (`run_s4a_fixpoint`) fully converges,
    /// BEFORE `finalize()` and solver entry. Only *reads* the converged
    /// `dep_active_flags` — never retracts, so monotonicity is untouched and
    /// the check is order-independent (both impls see the same converged set).
    ///
    /// Algorithm (normative):
    ///   for each dep D,
    ///   for each flag f ∈ active(D),
    ///   for each g in f.conflicts:
    ///       if g ∈ active(D): raise RESOLVE-FLAG-CONFLICT.
    ///
    /// Same-package only — cross-package conflicts deferred (#151).
    /// Mirrors `resolver.py:_s4c_check_flag_conflicts` (SSOT pair).
    fn check_s4c_flag_conflicts(&self, deps_dir: &Path) -> Result<(), MilpaError> {
        use milpa_manifest::parse_manifest;
        use milpa_types::ActivationSource;

        let candidate_names: Vec<String> = self
            .candidates
            .borrow()
            .keys()
            .filter(|n| n.as_str() != ROOT)
            .cloned()
            .collect();

        for dep_name in &candidate_names {
            // Ensure we have a materialized candidate (not just a stub).
            if self.candidates.borrow().get(dep_name).map_or(true, |m| m.is_empty()) {
                continue;
            }

            // Load the dep's manifest to get flag declarations (conflicts field).
            let kdl_path = deps_dir.join(dep_name).join("milpa.kdl");
            if !kdl_path.exists() {
                continue;
            }
            let kdl_text = match std::fs::read_to_string(&kdl_path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let manifest = match parse_manifest(&kdl_text) {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Skip if the manifest declares no flags (nothing to conflict).
            if manifest.flags.is_empty() {
                continue;
            }

            // Get or derive the active_map.
            // H3: look up dep_active_flags by identity (content_hash), not dep_name.
            // dep_active_flags may not have an entry if the dep had no consumer
            // flag requests (no one requested flags on it) and no default-true flags;
            // in that case derive active from defaults only (§3.1.2 rule 1).
            let dep_identity: String = self.candidates.borrow()
                .get(dep_name)
                .and_then(|m| m.values().next())
                .map(|c| c.identity.clone())
                .unwrap_or_default();
            let active_map: BTreeMap<String, BTreeSet<ActivationSource>> = {
                let daf = self.dep_active_flags.borrow();
                match daf.get(&dep_identity).filter(|m| !m.is_empty()) {
                    Some(m) => m.clone(),
                    None => {
                        // No entry (or empty) — compute defaults-only active set.
                        drop(daf);
                        compute_dep_active_flags(&manifest.flags, &[])
                    }
                }
            };

            if active_map.is_empty() {
                continue; // no active flags — nothing to check
            }

            // Delegate to the SSOT helper (also used for root CLI flag check).
            raise_if_flag_conflicts(dep_name, &manifest.flags, &active_map)?;
        }

        Ok(())
    }
}

impl PackageProvider for ResolveProvider<'_> {
    fn versions(&self, package: &str) -> Vec<Version> {
        let mut out: BTreeSet<Version> = BTreeSet::new();
        if let Some(m) = self.candidates.borrow().get(package) {
            out.extend(m.keys().cloned());
        }
        if let Some(m) = self.stubs.borrow().get(package) {
            out.extend(m.keys().cloned());
        }
        out.into_iter().collect()
    }

    fn dependencies(&self, package: &str, version: &Version) -> Vec<SolverDep> {
        // Fast path: already materialized.
        if let Some(c) = self
            .candidates
            .borrow()
            .get(package)
            .and_then(|m| m.get(version))
        {
            return c.deps.clone();
        }
        // Lazy path: a named stub the solver just selected.
        let entry = self
            .stubs
            .borrow()
            .get(package)
            .and_then(|m| m.get(version))
            .cloned();
        if let Some(entry) = entry {
            match self.materialize_named(package, version, &entry) {
                Ok(deps) => return deps,
                Err(e) => {
                    self.capture(e);
                    return Vec::new();
                }
            }
        }
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn topo_visit(
    name: &str,
    chosen: &BTreeMap<String, Candidate>,
    ordered: &mut Vec<String>,
    visited: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) {
    if visited.contains(name) || !chosen.contains_key(name) {
        return;
    }
    if visiting.contains(name) {
        return; // cycle — break here; the order stays consistent
    }
    visiting.insert(name.to_string());
    if let Some(c) = chosen.get(name) {
        for req in &c.requires_names {
            topo_visit(req, chosen, ordered, visited, visiting);
        }
    }
    visiting.remove(name);
    visited.insert(name.to_string());
    ordered.push(name.to_string());
}

fn eq_sentinel() -> VersionSet {
    VersionSet::eq(url_dep_version())
}

fn git_prov(url: &str, git_ref: &str, commit_sha: Option<String>) -> Provenance {
    Provenance::Git {
        url: url.to_string(),
        ref_spec: git_ref.to_string(),
        commit_sha,
    }
}

/// Map a transport [`Provenance`] (what the fetcher dispatches on) to its
/// emission-level [`ProvenanceRecord`] (what the lockfile records). A git
/// `ref_spec` of `""` becomes `None` (the record's "omitted, never empty"
/// convention). The non-transport `Member`/`Registry` records have no transport
/// source, so they are produced directly (workspace resolve / lockfile read),
/// never through this map.
fn transport_to_record(p: &Provenance) -> ProvenanceRecord {
    match p {
        Provenance::Git {
            url,
            ref_spec,
            commit_sha,
        } => ProvenanceRecord::Git {
            url: url.clone(),
            ref_spec: opt(ref_spec),
            commit_sha: commit_sha.clone(),
            origin: "observed".to_string(),
        },
        Provenance::Tarball {
            url,
            expected_sha256,
            ..
        } => ProvenanceRecord::Tarball {
            url: url.clone(),
            sha256: expected_sha256.clone(),
            origin: "observed".to_string(),
        },
        Provenance::Local { path } => ProvenanceRecord::Local {
            path: path.clone(),
            origin: "observed".to_string(),
        },
        Provenance::Oci {
            registry,
            repository,
            digest,
        } => ProvenanceRecord::Oci {
            registry: registry.clone(),
            repository: repository.clone(),
            digest: digest.clone(),
            origin: "observed".to_string(),
        },
    }
}

/// `""` → `None`, else `Some` (the record's optional-field convention).
fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn url_dep(name: &str, git: &str, git_ref: &str) -> UrlDep {
    UrlDep {
        name: name.to_string(),
        git: git.to_string(),
        git_ref: git_ref.to_string(),
        mirrors: Vec::new(),
        predicates: Vec::new(),
        flag_requests: Vec::new(),
        optional: false,
    }
}

/// Extract the git URL and ref from a git-form override target (S8).
///
/// Panics with `todo!()` for `LocalTarget` / `MemberTarget` —
/// the resolver interception sites for those kinds are wired in S8a / S8b.
/// This keeps the existing git override path intact while non-git kinds are
/// unreachable (no conformance fixture exercises them at resolve time yet).
fn override_git_url_ref(ov: &Override) -> (&str, &str) {
    match &ov.target {
        OverrideTarget::Git { url, git_ref } => (url.as_str(), git_ref.as_str()),
        OverrideTarget::Local { .. } => {
            todo!(
                "LocalTarget override for {:?} is not yet wired \
                 (S8a — resolver interception sites for local= targets)",
                ov.name
            )
        }
        OverrideTarget::Member { .. } => {
            todo!(
                "MemberTarget override for {:?} is not yet wired \
                 (S8b — resolver interception sites for member targets)",
                ov.name
            )
        }
    }
}

/// SSOT inner conflict check: raise `RESOLVE-FLAG-CONFLICT` if any pair conflicts.
///
/// Algorithm (normative, RFC §3.1.4):
///   for each flag f ∈ active_map,
///   for each g in f.conflicts:
///       if g ∈ active_map: raise RESOLVE-FLAG-CONFLICT.
///
/// Used by both `check_s4c_flag_conflicts` (transitive deps) and the root
/// CLI-flag conflict check (C1b-completion).  The error payload is byte-identical
/// regardless of call site.  Mirrors Python's `_raise_if_flag_conflicts`.
fn raise_if_flag_conflicts(
    dep_name: &str,
    flag_decls: &[milpa_manifest::FlagDecl],
    active_map: &BTreeMap<String, BTreeSet<milpa_types::ActivationSource>>,
) -> Result<(), MilpaError> {
    use milpa_types::ActivationSource;

    fn serialize_sources(s: &BTreeSet<ActivationSource>) -> Vec<String> {
        s.iter()
            .map(|src| match src {
                ActivationSource::Default => "default",
                ActivationSource::EdgeRequest => "edge_request",
                ActivationSource::EnablesRule => "enables_rule",
                ActivationSource::Cli => "cli",
            })
            .map(String::from)
            .collect()
    }

    let flag_by_name: std::collections::BTreeMap<&str, &milpa_manifest::FlagDecl> =
        flag_decls.iter().map(|fd| (fd.name.as_str(), fd)).collect();
    let active_flag_names: BTreeSet<&str> =
        active_map.keys().map(|s| s.as_str()).collect();

    for (flag_name, _sources) in active_map.iter() {
        let fd = match flag_by_name.get(flag_name.as_str()) {
            Some(fd) => fd,
            None => continue,
        };
        for conflict_name in &fd.conflicts {
            if !active_flag_names.contains(conflict_name.as_str()) {
                continue; // conflict partner not active
            }

            // Both flags are active — raise RESOLVE-FLAG-CONFLICT.
            // Canonical ordering: lexicographic on flag names.
            let (fa, fb) = if flag_name.as_str() <= conflict_name.as_str() {
                (flag_name.as_str(), conflict_name.as_str())
            } else {
                (conflict_name.as_str(), flag_name.as_str())
            };

            let sources_a = active_map.get(fa).cloned().unwrap_or_default();
            let sources_b = active_map.get(fb).cloned().unwrap_or_default();
            let sa = serialize_sources(&sources_a);
            let sb = serialize_sources(&sources_b);

            return Err(MilpaError::Core(CoreError::FlagConflict {
                dep: dep_name.to_string(),
                flag_a: fa.to_string(),
                flag_b: fb.to_string(),
                sources_a: sa,
                sources_b: sb,
            }));
        }
    }

    Ok(())
}

/// Map an `OverrideTarget` to the `PKey` used for gate pre-seeding (S8).
///
/// Centralises the one-to-one mapping so `seed_root` and `seed_workspace`
/// do not each inline an identical `match` block.  Mirrors Python's
/// `_provenance_key_for_url_dep` / `_apply_override` dispatch.
fn override_target_to_pkey(target: &OverrideTarget) -> PKey {
    match target {
        OverrideTarget::Git { url, git_ref } => PKey::Url(url.clone(), git_ref.clone()),
        OverrideTarget::Local { path } => PKey::Local(path.clone()),
        OverrideTarget::Member { member_name } => PKey::Member(member_name.clone()),
    }
}

/// Derive a package name from a git URL (`…/foo.git` → `foo`), rejecting
/// path-traversal tails. Mirrors `_name_from_url` (the SSOT safe-name predicate
/// lands with the tianguis reader in S8; inlined minimally here).
fn name_from_url(url: &str) -> Result<String, MilpaError> {
    let trimmed = url.trim_end_matches('/');
    let tail = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let name = tail.strip_suffix(".git").unwrap_or(tail);
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(res_err(
            "RES-NO-INDEX",
            format!("unsafe package name {name:?} derived from URL {url:?}"),
        ));
    }
    Ok(name.to_string())
}

// ---------------------------------------------------------------------------
// S1 (RFC: workspace-completion §3.A): FilterCtx + filter_manifest
//
// Two independent predicates encoded as a value type, matching Python's
// FilterContext.  The profile gate evaluates platform/arch/nim/milpa predicates
// only (Depth-F7: skips flag predicates).  The flag gate evaluates flag
// predicates via dep_passes_flag_predicates.
//
// Passthrough: profile=None AND active_flags empty → both gates are no-ops.
// Flag gate runs when: profile is Some (Row-1 parity) OR active_flags nonempty
// (Row-2 flag-only path).  Same semantics as Python filter_manifest.
// ---------------------------------------------------------------------------

/// Value type encoding the two independent filter predicates (resolver-semantics §3.A).
///
/// Mirror of Python `FilterContext`.  Always construct via [`FilterCtx::build`]
/// in production code; the raw struct fields are public for Rust symmetry with
/// Python.
#[derive(Clone, Debug)]
pub struct FilterCtx {
    /// `None` ⟺ platform/arch/nim/milpa-predicate filtering disabled (§470).
    pub profile: Option<Profile>,
    /// Already-closed flag set.  Empty means "no flag filtering unless profile
    /// is present" (see passthrough condition above).
    pub active_flags: BTreeSet<String>,
}

impl FilterCtx {
    /// Smart constructor — computes the flag closure from *manifest's* flags.
    ///
    /// Design-F1: the closure runs against `manifest.flags` (the manifest being
    /// filtered), NOT any root manifest's flags.  At a workspace member site the
    /// caller passes the member's manifest so the member's flags block determines
    /// which enables-chains fire.
    ///
    /// `cli_seed`: `None` ⟺ use manifest's default-true flags as seed.
    pub fn build(
        manifest: &Manifest,
        profile: Option<Profile>,
        cli_seed: Option<&std::collections::HashSet<String>>,
    ) -> Self {
        use milpa_manifest::flag_enables_closure;
        use std::collections::HashSet;

        let seed: HashSet<String> = match cli_seed {
            Some(s) => s.clone(),
            None => manifest
                .flags
                .iter()
                .filter(|f| f.default)
                .map(|f| f.name.clone())
                .collect(),
        };
        let active_flags: BTreeSet<String> = if seed.is_empty() {
            BTreeSet::new()
        } else {
            flag_enables_closure(&manifest.flags, &seed)
                .into_iter()
                .collect()
        };
        FilterCtx { profile, active_flags }
    }
}

/// Return a filtered copy of `manifest` applying the two independent predicates.
///
/// Mirror of Python `filter_manifest` (resolver-semantics §3.A).
///
/// - **Profile gate** (iff `ctx.profile is Some`): keeps deps whose non-flag
///   predicates match the profile.  Flag predicates are SKIPPED (Depth-F7).
/// - **Flag gate**: keeps deps whose flag predicates are satisfied by
///   `ctx.active_flags`.  Runs when profile is Some (Row-1 parity) OR when
///   active_flags is nonempty (Row-2 flag-only path).
/// - **Passthrough**: profile=None AND active_flags empty → all deps retained.
pub fn filter_manifest(manifest: &Manifest, ctx: &FilterCtx) -> Manifest {
    // Fast path: neither gate is active.
    if ctx.profile.is_none() && ctx.active_flags.is_empty() {
        return manifest.clone();
    }

    let active_refs: BTreeSet<&str> = ctx.active_flags.iter().map(|s| s.as_str()).collect();
    // Flag gate runs when profile is Some (Row-1) OR active_flags nonempty (Row-2).
    let run_flag_gate = true; // reached only after the fast-path check above

    let dep_passes = |dep: &Dep| -> bool {
        let preds = dep.predicates();

        // Profile gate: evaluate non-flag predicates only.
        if let Some(ref profile) = ctx.profile {
            for pred in preds.iter() {
                if pred.name == "flag" {
                    // Depth-F7: flag predicates owned by flag gate; skip here.
                    continue;
                }
                if !predicate_satisfied_profile_only(pred, profile) {
                    return false;
                }
            }
        }

        // Flag gate: evaluate flag predicates.
        if run_flag_gate && !dep_passes_flag_predicates(dep, &active_refs) {
            return false;
        }

        true
    };

    let mut out = manifest.clone();
    out.deps.retain(|d| dep_passes(d));
    out.dev_deps.retain(|d| dep_passes(d));
    out
}

/// Evaluate a single NON-FLAG predicate against `profile`.
///
/// Called exclusively from the profile gate in [`filter_manifest`].
/// Callers MUST NOT pass flag predicates here (Depth-F7).
fn predicate_satisfied_profile_only(pred: &Predicate, profile: &Profile) -> bool {
    // §3.C / §6: an absent axis is indeterminate → the predicate evaluates to false
    // regardless of negation.  Check for absence BEFORE applying negation so that
    // `when arch != "arm64"` with arch=None yields false, not true.
    let axis_present = match pred.name.as_str() {
        "platform" => profile.platform.is_some(),
        "arch" => profile.arch.is_some(),
        "nim" => profile.nim_version.is_some(),
        "milpa" => profile.milpa_version.is_some(),
        _ => false, // Unknown axis (e.g., "flag" — should never reach here)
    };
    if !axis_present {
        return false;
    }
    let any_match = match pred.name.as_str() {
        "platform" => match &profile.platform {
            Some(actual) => pred.values.iter().any(|v| v == actual),
            None => false,
        },
        "arch" => match &profile.arch {
            Some(actual) => pred.values.iter().any(|v| v == actual),
            None => false,
        },
        "nim" => match &profile.nim_version {
            Some(actual) => pred.values.iter().any(|v| version_satisfies(actual, v)),
            None => false,
        },
        "milpa" => match &profile.milpa_version {
            Some(actual) => pred.values.iter().any(|v| version_satisfies(actual, v)),
            None => false,
        },
        _ => false,
    };
    if pred.negated { !any_match } else { any_match }
}

/// Filter conditional deps by the active profile (§6). Flag predicates evaluate
/// against `profile.flags`; `nim` predicates against `profile.nim_version`.
///
/// Legacy helper: kept for [`seed_workspace`] call-sites not yet migrated to
/// [`FilterCtx`] + [`filter_manifest`] (S2 wires those).  New call-sites should
/// use [`filter_manifest`] instead.
fn filter_manifest_by_profile(manifest: &Manifest, profile: &Profile) -> Manifest {
    let mut out = manifest.clone();
    out.deps.retain(|d| dep_matches_profile(d, profile));
    out.dev_deps.retain(|d| dep_matches_profile(d, profile));
    out
}

fn dep_matches_profile(dep: &Dep, profile: &Profile) -> bool {
    dep.predicates()
        .iter()
        .all(|p| predicate_satisfied(p, profile))
}

fn predicate_satisfied(pred: &Predicate, profile: &Profile) -> bool {
    // §3.C / §6: an absent axis is indeterminate → the predicate evaluates to false
    // regardless of negation.  Check for absence BEFORE applying negation so that
    // `when arch != "arm64"` with arch=None yields false, not true.
    // (Flag predicates are never "absent" — an empty flag set means no flag is active,
    // which is handled below as any_match=false with negated=false ⟹ false.)
    let axis_present = match pred.name.as_str() {
        "flag" => true, // flags are always "present" (an empty set is valid)
        "platform" => profile.platform.is_some(),
        "arch" => profile.arch.is_some(),
        "nim" => profile.nim_version.is_some(),
        "milpa" => profile.milpa_version.is_some(),
        _ => false,
    };
    if !axis_present {
        return false;
    }
    let any_match = match pred.name.as_str() {
        "flag" => pred.values.iter().any(|v| profile.flags.contains(v)),
        // platform / arch are plain string-equality axes (Nim's hostOS / hostCPU
        // vocabulary); an absent axis matches nothing.
        "platform" => match &profile.platform {
            Some(actual) => pred.values.iter().any(|v| v == actual),
            None => false,
        },
        "arch" => match &profile.arch {
            Some(actual) => pred.values.iter().any(|v| v == actual),
            None => false,
        },
        // nim / milpa are version-constraint (or plain-equality) axes.
        "nim" => match &profile.nim_version {
            Some(actual) => pred.values.iter().any(|v| version_satisfies(actual, v)),
            None => false,
        },
        "milpa" => match &profile.milpa_version {
            Some(actual) => pred.values.iter().any(|v| version_satisfies(actual, v)),
            None => false,
        },
        _ => false,
    };
    if pred.negated {
        !any_match
    } else {
        any_match
    }
}

/// True if `actual` satisfies a `nim`/`milpa` predicate value — a version
/// constraint (leading comparison operator) or a plain-equality string.
fn version_satisfies(actual: &Version, declared: &str) -> bool {
    let is_constraint = declared.starts_with(['>', '<', '=', '!', '~', '^']);
    if !is_constraint {
        return parse_version(declared).is_some_and(|v| &v == actual);
    }
    match VersionSet::from_constraint(Some(&normalize_constraint(declared))) {
        Ok(vs) => vs.contains(actual),
        Err(_) => false,
    }
}

/// Insert a space after a leading comparison operator so the solver's
/// `from_constraint` (which expects `>= 1.2.0`) accepts `>=1.2.0`.
fn normalize_constraint(s: &str) -> String {
    for op in [">=", "<=", "==", "!=", ">", "<", "~", "^"] {
        if let Some(rest) = s.strip_prefix(op) {
            return format!("{op} {}", rest.trim_start());
        }
    }
    s.to_string()
}

fn dep_passes_flag_predicates(dep: &Dep, active: &BTreeSet<&str>) -> bool {
    for p in dep.predicates() {
        if p.name != "flag" {
            continue;
        }
        let any_match = p.values.iter().any(|v| active.contains(v.as_str()));
        let satisfied = if p.negated { !any_match } else { any_match };
        if !satisfied {
            return false;
        }
    }
    true
}

/// Compute the set of active flags for a dep, given its declared flags and the
/// consumer's flag requests (S3 RFC #23 §3.1.1).
///
/// Rules (in order):
/// 1. `DEFAULT`:      flags with `default=#true` in the dep's `flags` block.
/// 2. `EDGE_REQUEST`: positive `flag "x"` requests from the consumer's dep
///    declaration, but ONLY for flags that are declared in the dep's `flags`
///    block (unknown flag names are silently ignored per §3.1.1
///    RESOLVE-FLAG-UNKNOWN-ON-TARGET).  Negative requests (`flag "x" #false`)
///    are absence-of-request — they do NOT remove DEFAULT-activated flags
///    (§3.1.3 opt-out semantics).
/// 3. `ENABLES_RULE`: same-package `enables` closure (S2 monotone closure):
///    for each newly-active flag, if its `enables_same_pkg` list contains flags
///    not yet active, those are added with `ENABLES_RULE`.
///
/// Returns a map `flag_name → BTreeSet<ActivationSource>`.
/// Mirrors `resolver.py:compute_dep_active_flags` (SSOT pair).
pub fn compute_dep_active_flags(
    flags: &[milpa_manifest::FlagDecl],
    requested: &[FlagRequest],
) -> BTreeMap<String, BTreeSet<milpa_types::ActivationSource>> {
    use milpa_types::ActivationSource;

    let mut active: BTreeMap<String, BTreeSet<ActivationSource>> = BTreeMap::new();

    // Rule 1: defaults.
    for fd in flags {
        if fd.default {
            active
                .entry(fd.name.clone())
                .or_default()
                .insert(ActivationSource::Default);
        }
    }

    // Build name→FlagDecl for lookup.
    let flag_by_name: BTreeMap<&str, &milpa_manifest::FlagDecl> =
        flags.iter().map(|f| (f.name.as_str(), f)).collect();

    // Rule 2: positive edge requests (unknown flags silently ignored).
    for fr in requested {
        if !fr.enabled {
            continue; // negative request = absence-of-request (§3.1.3)
        }
        if flag_by_name.contains_key(fr.name.as_str()) {
            active
                .entry(fr.name.clone())
                .or_default()
                .insert(ActivationSource::EdgeRequest);
        }
    }

    // Rule 3: same-package enables closure (S2 monotone, fixed-point).
    loop {
        let currently_active: Vec<String> = active.keys().cloned().collect();
        let mut added = false;
        for name in &currently_active {
            if let Some(fd) = flag_by_name.get(name.as_str()) {
                for enabled_name in &fd.enables_same_pkg {
                    if !active.contains_key(enabled_name.as_str()) {
                        active
                            .entry(enabled_name.clone())
                            .or_default()
                            .insert(ActivationSource::EnablesRule);
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }

    active
}

fn res_err(code: &'static str, msg: String) -> MilpaError {
    MilpaError::Core(CoreError::Resolver(code, msg))
}

// ---------------------------------------------------------------------------
// Attestation-policy SSOT helpers (Finding 1)
// ---------------------------------------------------------------------------

/// Compute the effective strict attestation policy (S5, §13.1).
///
/// The rule is the logical OR of:
///   - `manifest_policy == AttestationPolicy::Strict` (project-wide)
///   - `flag` (CLI `--require-attested-metadata` / `MILPA_REQUIRE_ATTESTED_METADATA`)
///
/// The flag CANNOT weaken a manifest-declared strict policy (OR semantics).
///
/// This is the single source of truth for the effective-policy predicate.
/// Mirrors `attestation.py::effective_strict_policy`.
pub fn effective_strict_policy(manifest_policy: &milpa_manifest::AttestationPolicy, flag: bool) -> bool {
    use milpa_manifest::AttestationPolicy;
    *manifest_policy == AttestationPolicy::Strict || flag
}

/// Parse a truthy env-var value (D-F3 SSOT).
///
/// Mirrors the conventional shell/CI interpretation: a variable is "set to true"
/// when it is non-empty AND is not `"0"` or `"false"`. The complement values
/// (`""`, `"0"`, `"false"`) are all treated as false/unset. Used by both the CLI
/// and the conformance runner for `MILPA_REQUIRE_ATTESTED_METADATA`.
pub fn parse_env_bool(value: &str) -> bool {
    !value.is_empty() && value != "0" && value != "false"
}

/// Compute whether any workspace member declares `attestation-policy "strict"`
/// (§13.1 workspace rule).
///
/// Returns `true` iff at least one member manifest has a strict policy.
/// Combine with the CLI flag via OR:
/// `workspace_any_member_strict(ws) || flag`.
pub fn workspace_any_member_strict(workspace: &LoadedWorkspace) -> bool {
    use milpa_manifest::AttestationPolicy;
    workspace
        .members
        .iter()
        .any(|m| m.manifest.attestation_policy == AttestationPolicy::Strict)
}

/// S5: attestation-policy enforcement (spec/resolver-semantics.md §S5).
///
/// Called once after `solve()` completes. Effective strict policy = logical OR of:
///   - `manifest.attestation_policy == AttestationPolicy::Strict` (project-wide)
///   - `require_attested_metadata` flag (CLI `--require-attested-metadata`)
///
/// Non-strict: emit ONE summary warning to stderr for all NimbleFallback deps.
/// Strict: return `Err(RES-UNATTESTED-METADATA)` if any dep used NimbleFallback.
///
/// The flag CANNOT weaken a manifest-declared strict policy (OR semantics).
/// Integrity failures (TNG-DEPDECL-HASH-MISMATCH etc.) are hard errors wired
/// at the DepDecl source — not here; they are never policy-gated.
fn enforce_attestation_policy(
    provider: &ResolveProvider<'_>,
    manifest: &Manifest,
    require_attested_metadata: bool,
) -> Result<(), MilpaError> {
    let is_strict = effective_strict_policy(&manifest.attestation_policy, require_attested_metadata);
    enforce_attestation_policy_strict(provider, is_strict)
}

/// Core enforcement logic shared by single-package and workspace paths.
///
/// `is_strict` is the pre-computed effective policy (OR of all sources per §13.1).
/// For single-package mode, compute `is_strict` from manifest + flag before calling.
/// For workspace mode (§13.1 workspace rule), compute `is_strict` as the OR of the
/// flag/env and any member manifest's `attestation-policy "strict"` declaration.
fn enforce_attestation_policy_strict(
    provider: &ResolveProvider<'_>,
    is_strict: bool,
) -> Result<(), MilpaError> {
    use milpa_types::EdgeSource;

    // Collect NimbleFallback dep names from the edge_cache (excluding __root__).
    let edge_cache = provider.edge_cache.borrow();
    let mut nimble_fallback_names: Vec<String> = edge_cache
        .iter()
        .filter(|((name, _ver), es)| {
            name != ROOT && es.source == EdgeSource::NimbleFallback
        })
        .map(|((name, _ver), _es)| name.clone())
        .collect();
    nimble_fallback_names.sort();
    nimble_fallback_names.dedup();

    if nimble_fallback_names.is_empty() {
        return Ok(());
    }

    if is_strict {
        return Err(MilpaError::Core(CoreError::Resolver(
            "RES-UNATTESTED-METADATA",
            format!(
                "strict attestation policy: {} dep(s) resolved from un-attested \
                 .nimble metadata: {}. Ensure all deps are indexed with a dep_decl \
                 pointer, or relax 'attestation-policy' to 'permissive' in milpa.kdl.",
                nimble_fallback_names.len(),
                nimble_fallback_names
                    .iter()
                    .map(|n| format!("{n:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )));
    }

    // Non-strict: single summary warning to stderr.
    eprintln!(
        "[milpa] warning: {} dep(s) resolved from un-attested .nimble metadata: {}; \
         see spec §4.1 (attestation-policy / --require-attested-metadata).",
        nimble_fallback_names.len(),
        nimble_fallback_names.join(", "),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared single-package setup helper (D-F2 SSOT)
// ---------------------------------------------------------------------------

/// Optional resolve knobs bundled to stay within clippy's argument-count limit.
///
/// `prior` enables §8 pin reuse; `dep_decl_store` drives S3b DepDecl; `require_attested_metadata`
/// is the CLI/env strict-attestation flag (combined with the manifest policy via
/// `effective_strict_policy` — §13.1 OR rule).
struct ProviderOpts<'a> {
    prior: Option<&'a Lockfile>,
    dep_decl_store: Option<&'a dyn crate::dep_decl_store::DepDeclStore>,
    require_attested_metadata: bool,
}

/// Build the [`ResolveProvider`] for a single-package resolve (both the
/// non-cert and cert paths share identical setup; they diverge only at the
/// solve dispatch and error-wrapping).
///
/// `manifest` must already be profile-filtered (callers own the
/// `filter_manifest_by_profile` step because the filtered value needs to
/// outlive this call). `empty_index` is a caller-owned `Index::default()`
/// whose lifetime anchors the borrow in the returned provider.
///
/// Returns `(provider, strict_attestation)` on success.
/// Returns `Err(MilpaError)` on `RES-NO-INDEX` or `create_dir_all` failure.
///
/// SSOT notes:
///   - All three inline OR expressions (`resolve`, `resolve_with_cert`,
///     `enforce_attestation_policy`) are now replaced by `effective_strict_policy`.
///   - The `overrides` collection, named-dep/no-index check, `create_dir_all`,
///     strict computation, and `ResolveProvider::new` live here exactly once.
fn build_single_provider<'a>(
    manifest: &'a Manifest,
    index: Option<&'a Index>,
    fetcher: &'a dyn FetcherRegistry,
    deps_dir: &Path,
    opts: ProviderOpts<'a>,
    empty_index: &'a Index,
) -> Result<(ResolveProvider<'a>, bool), MilpaError> {
    let ProviderOpts { prior, dep_decl_store, require_attested_metadata } = opts;
    let overrides: BTreeMap<String, Override> = manifest
        .overrides
        .iter()
        .map(|ov| (ov.name.clone(), ov.clone()))
        .collect();

    // Index presence: a named dep with neither an index nor an override is
    // unresolvable (resolver-semantics — RES-NO-INDEX).
    let index: &'a Index = match index {
        Some(i) => i,
        None => {
            let unresolvable: Vec<&str> = manifest
                .deps
                .iter()
                .chain(manifest.dev_deps.iter())
                .filter(|d| matches!(d, Dep::Named(_)) && !overrides.contains_key(d.name()))
                .map(|d| d.name())
                .collect();
            if !unresolvable.is_empty() {
                return Err(res_err(
                    "RES-NO-INDEX",
                    format!(
                        "manifest has named dep(s) {unresolvable:?} but no tianguis index \
                         was provided — pass an index to resolve named deps"
                    ),
                ));
            }
            empty_index
        }
    };

    std::fs::create_dir_all(deps_dir).map_err(io_err)?;

    // S5: effective strict policy is the SSOT OR of manifest policy and the
    // CLI flag (resolver-semantics §13.1; OR semantics — flag cannot weaken
    // manifest-strict).
    let strict_attestation =
        effective_strict_policy(&manifest.attestation_policy, require_attested_metadata);

    let provider = ResolveProvider::new(
        fetcher,
        index,
        deps_dir.to_path_buf(),
        overrides,
        prior,
        dep_decl_store,
        strict_attestation,
    );

    Ok((provider, strict_attestation))
}

/// Filesystem failures during resolution are uncoded in the spec (§5 leaves
/// them to the host), rendered as the non-catalog `MILPA-INTERNAL-IO` sentinel
/// (kept out of `all_codes()`, same as the identity/CAS I/O sentinel).
fn io_err(e: std::io::Error) -> MilpaError {
    MilpaError::Core(CoreError::Resolver("MILPA-INTERNAL-IO", e.to_string()))
}

fn fetch_msg(e: &FetchError) -> String {
    match e {
        FetchError::Failed(m)
        | FetchError::AllFailed(m)
        | FetchError::ProvenanceDivergence(m)
        | FetchError::Extract(_, m)
        | FetchError::Transport(_, m) => m.clone(),
    }
}

/// Extract a human-readable identifier from a `Provenance` for diagnostics.
fn prov_url_str(p: &Provenance) -> &str {
    match p {
        Provenance::Git { url, .. } => url,
        Provenance::Tarball { url, .. } => url,
        Provenance::Local { path } => path,
        Provenance::Oci { registry, .. } => registry,
    }
}

/// Remove `dir` (and contents) if it exists, so a failed fetch candidate's
/// partial bytes never pollute the next attempt.
fn clear_dir(dir: &Path) -> Result<(), MilpaError> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(io_err)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Result certificate (resolver-semantics §5 + cli-contract §2.5)
// ---------------------------------------------------------------------------

/// One entry in the §5.1 success-certificate witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessEntry {
    pub package: String,
    pub version: String,
    pub constraint: String,
    pub satisfied_by: String,
}

/// §5.1 success certificate data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessCert {
    /// Lexicographic by package name, root included.
    pub resolved: Vec<(String, String)>,
    /// Lexicographic by (package, satisfied_by).
    pub witness: Vec<WitnessEntry>,
}

/// §5.2 failure certificate data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureCert {
    /// Human-readable prose (any text; not byte-normative per spec).
    pub message: String,
    /// Weak UNSAT core — set-equality comparison by the harness.
    pub refutation: Vec<RefutationEntry>,
}

/// Resolve and also build a §5 result certificate.
///
/// Mirrors `resolve` exactly — same `dep_decl_store` and `require_attested_metadata`
/// wiring, same `enforce_attestation_policy` call after the solve — with the addition
/// that every outcome (success, SOLVE-CONFLICT, strict-attestation failure, or any other
/// error) also produces the appropriate certificate so §2.5 "cert written regardless of
/// success/failure" is honoured.
///
/// On success returns `Ok((graph, cert))`.
/// On SOLVE-CONFLICT returns `Err((err, failure_cert))` with a populated refutation.
/// On strict-attestation failure returns `Err((err, failure_cert))` with empty refutation.
/// On any other error (manifest/fetch/index) returns `Err((err, failure_cert))` with
/// an empty refutation (the certificate is only written when the resolver ran).
///
/// `store` is the content-addressed store used to rebuild `_deps/` after
/// resolution completes (B-nimcfg SSOT: alias symlinks + stale-entry removal).
#[allow(clippy::too_many_arguments)]
pub fn resolve_with_cert(
    manifest: &milpa_manifest::Manifest,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&milpa_manifest::Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &std::path::Path,
    dep_decl_store: Option<&dyn crate::dep_decl_store::DepDeclStore>,
    require_attested_metadata: bool,
    store: &CaStore,
) -> Result<(ResolvedGraph, SuccessCert), (MilpaError, FailureCert)> {
    // Delegates to `solve_with_refutation` instead of `solve`; all setup is
    // identical to `resolve` — factored through `build_single_provider` (D-F2).
    //
    // S1 (RFC: workspace-completion §3.A): route through the shared FilterCtx +
    // filter_manifest so resolve_with_cert cannot develop a divergent filter
    // path (Feasibility-F9).  No feature-selection params on this entry point
    // today; cli_seed=None uses manifest default flags.
    let cert_filter_ctx = FilterCtx::build(manifest, profile.cloned(), None);
    let filtered_cert = filter_manifest(manifest, &cert_filter_ctx);
    let manifest = &filtered_cert;

    let empty_index = Index::default();
    let (mut provider, _strict) = match build_single_provider(
        manifest,
        index,
        fetcher,
        deps_dir,
        ProviderOpts { prior, dep_decl_store, require_attested_metadata },
        &empty_index,
    ) {
        Ok(r) => r,
        Err(e) => return Err((e, FailureCert { message: String::new(), refutation: Vec::new() })),
    };

    let queue = match provider.seed_root(manifest) {
        Ok(q) => q,
        Err(e) => return Err((e, FailureCert { message: String::new(), refutation: Vec::new() })),
    };
    if let Err(e) = provider.process_items(queue) {
        return Err((e, FailureCert { message: String::new(), refutation: Vec::new() }));
    }
    // S4a fixpoint (cert path mirrors the resolve path).
    if let Err(e) = provider.run_s4a_fixpoint() {
        return Err((e, FailureCert { message: String::new(), refutation: Vec::new() }));
    }
    // S4c post-fixpoint flag-conflict validation (cert path mirrors resolve path).
    if let Err(e) = provider.check_s4c_flag_conflicts(deps_dir) {
        return Err((e, FailureCert { message: String::new(), refutation: Vec::new() }));
    }
    let canonical_aliases_cert = provider.finalize();

    match solve_with_refutation(&provider, ROOT, root_version(), strategy) {
        Ok(solution) => {
            if let Some(e) = provider.take_error() {
                return Err((e, FailureCert { message: String::new(), refutation: Vec::new() }));
            }
            // Mirror `resolve`: enforce attestation policy after the solve.
            // On strict failure, produce a FAILURE certificate (empty refutation —
            // this is not a SOLVE-CONFLICT) and propagate the error. §2.5 requires
            // the cert to be written on both success and failure paths.
            if let Err(e) = enforce_attestation_policy(&provider, manifest, require_attested_metadata) {
                return Err((e, FailureCert { message: String::new(), refutation: Vec::new() }));
            }
            let cert = provider.build_success_cert(&solution);
            let graph = provider.build_graph(&solution, &canonical_aliases_cert);
            // B-nimcfg SSOT: rebuild _deps/ view (alias symlinks + stale-entry removal).
            // Mirrors resolve() — the cert path must also own the rebuild.
            rebuild_deps_view(&graph, deps_dir, store);
            Ok((graph, cert))
        }
        Err((solver_err, refutation)) => {
            let message = solver_err.to_string();
            Err((
                MilpaError::Solver(solver_err),
                FailureCert { message, refutation },
            ))
        }
    }
}

impl ResolveProvider<'_> {
    /// Build a §5.1 success certificate from the completed solve.
    ///
    /// `resolved`: all packages in the solution (including root) sorted by name.
    /// `witness`: one entry per dep-edge across all resolved packages, sorted
    ///   by (package, satisfied_by) per spec §2.5.1.
    fn build_success_cert(&self, solution: &BTreeMap<String, Version>) -> SuccessCert {
        // resolved — sorted by package name (BTreeMap iteration is already sorted).
        let resolved: Vec<(String, String)> = solution
            .iter()
            .map(|(pkg, ver)| (pkg.clone(), ver.to_string()))
            .collect();

        // witness — one entry per dep edge (depender → dep, with constraint).
        // A dep edge: package `depender` at `depender_version` requires `dep` in
        // `constraint_vs`. We iterate every resolved package's `Candidate.deps`.
        let cands = self.candidates.borrow();
        let mut entries: Vec<WitnessEntry> = Vec::new();
        let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();

        for (depender, depender_ver) in solution {
            if let Some(c) = cands
                .get(depender)
                .and_then(|m| m.get(depender_ver))
            {
                for dep in &c.deps {
                    // Only emit witness entries for packages that are in the solution.
                    let Some(dep_ver) = solution.get(&dep.package) else {
                        continue;
                    };
                    let cstr = vs_to_constraint_str(&dep.constraint);
                    let key = (dep.package.clone(), cstr.clone(), depender.clone());
                    if seen.insert(key) {
                        entries.push(WitnessEntry {
                            package: dep.package.clone(),
                            version: dep_ver.to_string(),
                            constraint: cstr,
                            satisfied_by: depender.clone(),
                        });
                    }
                }
            }
        }

        // Sort per §2.5.1: lexicographic by (package, satisfied_by).
        entries.sort_by(|a, b| a.package.cmp(&b.package).then(a.satisfied_by.cmp(&b.satisfied_by)));

        SuccessCert { resolved, witness: entries }
    }
}

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod resolver_tests;
