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

use milpa_manifest::{Dep, LocalDep, Manifest, Override, Predicate, Profile, TarballDep, UrlDep};
use milpa_solver::{
    parse_version, solve, solve_with_refutation, vs_to_constraint_str, Dep as SolverDep,
    PackageProvider, RefutationEntry, Strategy, VersionSet,
};
use milpa_types::{EdgeSet, Lockfile, Provenance, ProvenanceRecord, ResolvedDep, ResolvedGraph, Version};

use crate::edge_sources::{EdgeSourceCtx, NimbleEdgeSource};
use crate::error::{CoreError, MilpaError};
use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::identity::compute_content_hash;
use crate::lockfile::cond_require_sort_key;
use crate::registry::{Index, IndexVersion};
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
) -> Result<ResolvedGraph, MilpaError> {
    // §6: filter conditional deps by the active profile before anything else.
    // An absent profile disables filtering entirely (§6 absent-profile rule).
    let filtered;
    let manifest = match profile {
        Some(p) => {
            filtered = filter_manifest_by_profile(manifest, p);
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

    // Build the synthetic root candidate (requires every manifest dep) and the
    // BFS queue. dev_deps for the ROOT are enrolled here alongside deps (§9);
    // transitive deps never read dev_deps.
    let queue = provider.seed_root(manifest)?;
    provider.process_items(queue)?;

    // Content-hash dedup/alias for eagerly-materialized candidates (Phase B, #32).
    provider.finalize();

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

    Ok(provider.build_graph(&solution))
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
    )
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
) -> Result<ResolvedGraph, MilpaError> {
    let overrides: BTreeMap<String, Override> = workspace
        .overrides
        .iter()
        .map(|o| (o.name.clone(), o.clone()))
        .collect();
    let members_by_name: BTreeSet<String> =
        workspace.members.iter().map(|m| m.name.clone()).collect();

    // RES-WS-OVERRIDE-MEMBER-COLLISION: a name cannot be both an external
    // override and an in-tree member.
    let mut collisions: Vec<&str> = overrides
        .keys()
        .filter(|n| members_by_name.contains(n.as_str()))
        .map(String::as_str)
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
    for member in &workspace.members {
        for dep in &member.manifest.deps {
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
    let queue = provider.seed_workspace(workspace, profile)?;
    provider.process_items(queue)?;
    provider.finalize();
    let solution = solve(&provider, ROOT, root_version(), strategy)?;
    if let Some(e) = provider.take_error() {
        return Err(e);
    }

    // §13.1 workspace attestation policy enforcement — reuse the pre-computed
    // ws_is_strict (single computation, no duplicate any_member_strict loop).
    enforce_attestation_policy_strict(&provider, ws_is_strict)?;

    Ok(provider.build_graph(&solution))
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
            error: RefCell::new(None),
            dep_decl_store,
            strict_attestation,
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
                    seen_by_name.insert(name, (PKey::Tarball(t.url.clone()), true));
                    queue.push(Item::Tarball(t.clone()));
                }
                Dep::Local(l) => {
                    root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                    root_requires.push(name.clone());
                    seen_by_name.insert(name, (PKey::Local(l.path.clone()), true));
                    queue.push(Item::Local(l.clone()));
                }
                Dep::Url(u) => {
                    root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                    root_requires.push(name.clone());
                    let pkey = match self.overrides.get(&name) {
                        Some(ov) => PKey::Url(ov.git.clone(), ov.git_ref.clone()),
                        None => PKey::Url(u.git.clone(), u.git_ref.clone()),
                    };
                    seen_by_name.insert(name, (pkey, true));
                    queue.push(Item::Url(u.clone()));
                }
                Dep::Named(n) => {
                    // Manifest-parsed: use the pre-validated VersionSet
                    // (MAN-DEP-NAMED-CONSTRAINT raised at parse time).
                    let vs = n
                        .parsed_constraint
                        .clone()
                        .unwrap_or_else(VersionSet::full);
                    if self.overrides.contains_key(&name) {
                        // Override routes a named dep to a URL fetch → singleton.
                        let ov = &self.overrides[&name];
                        root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                        seen_by_name.insert(
                            name.clone(),
                            (PKey::Url(ov.git.clone(), ov.git_ref.clone()), true),
                        );
                    } else {
                        root_deps.push(SolverDep::new(name.clone(), vs.clone()));
                        seen_by_name.insert(name.clone(), (PKey::Named(name.clone()), true));
                    }
                    root_requires.push(name.clone());
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
                }
            }
        }

        for ov in &manifest.overrides {
            authority.insert(ov.name.clone());
            seen_by_name
                .entry(ov.name.clone())
                .or_insert_with(|| (PKey::Url(ov.git.clone(), ov.git_ref.clone()), true));
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
    fn seed_workspace(
        &mut self,
        workspace: &LoadedWorkspace,
        profile: Option<&Profile>,
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
            seen_by_name.insert(
                ov.name.clone(),
                (PKey::Url(ov.git.clone(), ov.git_ref.clone()), true),
            );
        }

        for member in &workspace.members {
            // Per-member profile filtering (§6) when a profile is active.
            let filtered;
            let manifest = match profile {
                Some(p) => {
                    filtered = filter_manifest_by_profile(&member.manifest, p);
                    &filtered
                }
                None => &member.manifest,
            };

            let mut terms: Vec<SolverDep> = Vec::new();
            let mut requires: Vec<String> = Vec::new();
            for dep in manifest.deps.iter().chain(manifest.dev_deps.iter()) {
                let name = dep.name().to_string();
                authority.insert(name.clone());

                // Member ref / member-named auto-coercion: satisfied by the
                // in-tree member candidate, no fetch, no queue.
                if matches!(dep, Dep::Member(_)) || members_by_name.contains(&name) {
                    terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                    requires.push(name);
                    continue;
                }

                if self.overrides.contains_key(&name) {
                    let ov = &self.overrides[&name];
                    terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                    requires.push(name.clone());
                    seen_by_name
                        .entry(name.clone())
                        .or_insert((PKey::Url(ov.git.clone(), ov.git_ref.clone()), true));
                    // Override converts Named→Url at dispatch; constraint is unused.
                    queue.push(Item::Named {
                        name,
                        constraint: VersionSet::full(),
                    });
                    continue;
                }

                match dep {
                    Dep::Url(u) => {
                        terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                        requires.push(name.clone());
                        seen_by_name
                            .entry(name.clone())
                            .or_insert((PKey::Url(u.git.clone(), u.git_ref.clone()), true));
                        queue.push(Item::Url(u.clone()));
                    }
                    Dep::Local(l) => {
                        terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                        requires.push(name.clone());
                        seen_by_name
                            .entry(name.clone())
                            .or_insert((PKey::Local(l.path.clone()), true));
                        queue.push(Item::Local(l.clone()));
                    }
                    Dep::Tarball(t) => {
                        terms.push(SolverDep::new(name.clone(), eq_sentinel()));
                        requires.push(name.clone());
                        seen_by_name
                            .entry(name.clone())
                            .or_insert((PKey::Tarball(t.url.clone()), true));
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
                }),
                dep_decl: None, // workspace members never resolved via DepDecl
                requires_predicates: std::collections::BTreeMap::new(),
            });
            root_deps.push(SolverDep::new(member.name.clone(), eq_sentinel()));
            root_requires.push(member.name.clone());
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
                Some(ov) => Item::Url(url_dep(&d.name, &ov.git, &ov.git_ref)),
                None => item,
            },
            Item::Named { name, .. } => match self.overrides.get(name) {
                Some(ov) => Item::Url(url_dep(name, &ov.git, &ov.git_ref)),
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
            return Ok(());
        }

        let (expected_identity, pinned_sha) = self.git_pin(&dep);

        // Ordered candidate list (§8a): primary, dep-block mirrors, prior
        // self-mirrors — all carrying the pinned commit (same commit ⇒ same
        // bytes ⇒ same identity).
        let mut provs = vec![git_prov(&dep.git, &dep.git_ref, pinned_sha.clone())];
        for m in &dep.mirrors {
            provs.push(git_prov(m, &dep.git_ref, pinned_sha.clone()));
        }
        for sm in self.prior_self_mirrors(&dep.name) {
            provs.push(git_prov(&sm, &dep.git_ref, pinned_sha.clone()));
        }

        let dest = self.deps_dir.join(&dep.name);
        let (identity, receipt) =
            self.fetch_any(&dep.name, &provs, &dest, expected_identity.as_deref())?;

        let ex =
            self.extract_requires(&dest, &dep.name, &url_dep_version(), false, None, None)?;

        // Record the declared primary provenance; carry the resolved commit
        // (preferring the freshly-resolved SHA over a pin) for emission.
        let commit = receipt.resolved_ref.or(pinned_sha);
        self.store_candidate(Candidate {
            name: dep.name.clone(),
            version: url_dep_version(),
            identity,
            src_dir: ex.src_dir,
            requires_names: ex.requires_names,
            deps: ex.deps,
            provenance: Some(ProvenanceRecord::Git {
                url: dep.git.clone(),
                ref_spec: opt(&dep.git_ref),
                commit_sha: commit,
            }),
            dep_decl: None, // URL deps not in the index; no DepDecl pin
            requires_predicates: ex.requires_predicates,
        });

        self.process_items(ex.sub_items)?;
        Ok(())
    }

    fn process_local(&self, dep: LocalDep) -> Result<(), MilpaError> {
        if !self.seen_local.borrow_mut().insert(dep.path.clone()) {
            return Ok(());
        }
        let abs = self.project_root.join(&dep.path);
        let dest = self.deps_dir.join(&dep.name);
        clear_dir(&dest)?;
        let prov = Provenance::Local {
            // The fetcher copies from the absolute path; the recorded
            // provenance keeps the *declared* relative path (portable).
            path: abs.to_string_lossy().into_owned(),
        };
        self.fetcher
            .fetch(&dep.name, &prov, &dest)
            .map_err(MilpaError::from)?;
        let identity = compute_content_hash(&dest)?;
        let ex =
            self.extract_requires(&dest, &dep.name, &url_dep_version(), false, None, None)?;
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
            }),
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
            self.extract_requires(&dest, &dep.name, &url_dep_version(), false, None, None)?;
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
            }),
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
        // Phase A enumerate: the index applies the full resolve-time policy
        // (TNG-NOT-FOUND / TNG-AMBIGUOUS-NAME / TNG-NO-SATISFYING-VERSION /
        // TNG-NO-PROVENANCE) and returns every satisfying version newest-first.
        let vs = &constraint;
        let raw_str: Option<&str> = None; // display hint only; constraint is pre-parsed
        let versions = self
            .index
            .resolve_named_all(name, vs, raw_str)
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
        let ex = self.extract_requires(&dest, name, version, false,
                entry.dep_decl.as_deref(),
                entry.dep_decl_schema_version)?;
        // S6: dep_decl pin records the artifact hash only when DepDeclEdgeSource was
        // actually used (edge_set.source == DepDecl). If we fell back to milpa.kdl or
        // nimble (e.g. non-strict FETCH-FAILED), the pin is None — matching Python:
        // `iv.dep_decl if es.source == EdgeSource.DEP_DECL else None`.
        let dep_decl_pin = if matches!(ex.edge_set.source, milpa_types::EdgeSource::DepDecl) {
            entry.dep_decl.clone()
        } else {
            None
        };
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
            dep_decl: dep_decl_pin,
            requires_predicates: ex.requires_predicates,
        };
        self.store_candidate(candidate);
        self.stubs
            .borrow_mut()
            .get_mut(name)
            .map(|m| m.remove(version));
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
        let mut last_err: Option<String> = None;
        for prov in candidates {
            clear_dir(dest)?;
            match self.fetcher.fetch(name, prov, dest) {
                Ok(receipt) => {
                    let identity = compute_content_hash(dest)?;
                    match expected_identity {
                        Some(exp) if exp != identity => {
                            last_err = Some(format!(
                                "identity mismatch (expected {exp}, got {identity})"
                            ));
                            continue;
                        }
                        _ => return Ok((identity, receipt)),
                    }
                }
                Err(e) => {
                    last_err = Some(format!("{}: {}", e.code(), fetch_msg(&e)));
                    continue;
                }
            }
        }
        clear_dir(dest)?;
        Err(MilpaError::Fetch(FetchError::AllFailed(format!(
            "all {} candidate(s) failed for {name:?}: {}",
            candidates.len(),
            last_err.unwrap_or_else(|| "no candidates".into())
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
    ) -> Result<Extracted, MilpaError> {
        let has_milpa_kdl = dest.join("milpa.kdl").is_file();

        // Clause (a): cache hit → reconstruct Extracted from cached EdgeSet
        let cache_key = (name.to_string(), version.clone());
        {
            let cache = self.edge_cache.borrow();
            if let Some(es) = cache.get(&cache_key) {
                return self.edgeset_to_extracted(es, name);
            }
        }

        // Cache miss: dispatch to appropriate source (clauses b/c/d).
        let es: EdgeSet = if is_overridden {
            // Clause (b): is_overridden suppresses DepDecl — use milpa.kdl or nimble.
            if has_milpa_kdl {
                let text =
                    std::fs::read_to_string(dest.join("milpa.kdl")).map_err(io_err)?;
                let manifest = milpa_manifest::parse_manifest(&text)?;
                self.build_edgeset_from_manifest(&manifest)
            } else {
                let ctx = EdgeSourceCtx {
                    dep_path: Some(dest),
                    dep_name: name,
                    dep_decl: None,
                    is_overridden,
                    has_milpa_kdl: false,
                    dep_decl_schema_version: None,
                    overrides_by_name: &self.overrides,
                };
                let src = NimbleEdgeSource;
                src.edges_for(name, version, &ctx)
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
                            self.build_edgeset_from_manifest(&manifest)
                        } else {
                            let fallback_ctx = EdgeSourceCtx {
                                dep_path: Some(dest),
                                dep_name: name,
                                dep_decl: None,
                                is_overridden: false,
                                has_milpa_kdl: false,
                                dep_decl_schema_version: None,
                                overrides_by_name: &self.overrides,
                            };
                            let src = NimbleEdgeSource;
                            src.edges_for(name, version, &fallback_ctx)
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
                    self.build_edgeset_from_manifest(&manifest)
                } else {
                    let ctx = EdgeSourceCtx {
                        dep_path: Some(dest),
                        dep_name: name,
                        dep_decl,
                        is_overridden: false,
                        has_milpa_kdl: false,
                        dep_decl_schema_version,
                        overrides_by_name: &self.overrides,
                    };
                    let src = NimbleEdgeSource;
                    src.edges_for(name, version, &ctx)
                }
            }
        } else if has_milpa_kdl {
            // Clause (d): milpa.kdl present — parse with flag-predicate filtering.
            // For milpa.kdl, parse the manifest here so we can apply flag-predicate
            // filtering (§6 transitive: each dep evaluates against its own default
            // flags). Flag filtering is resolver-local and not part of the EdgeSource
            // seam's normative projection; it happens before constructing the EdgeSet.
            let text = std::fs::read_to_string(dest.join("milpa.kdl")).map_err(io_err)?;
            let manifest = milpa_manifest::parse_manifest(&text)?;
            self.build_edgeset_from_manifest(&manifest)
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
            };
            let src = NimbleEdgeSource;
            src.edges_for(name, version, &ctx)
        };

        // Seal cache (clause a) then convert to Extracted
        let extracted = self.edgeset_to_extracted(&es, name)?;
        self.edge_cache.borrow_mut().insert(cache_key, es);
        Ok(extracted)
    }

    /// Build an `EdgeSet` from a parsed `milpa.kdl` manifest, applying flag-
    /// predicate filtering (§6 transitive: each dep evaluates against its own
    /// default flags). Only `manifest.deps` is included — **never** `dev_deps`
    /// (§9) — and `overrides` are dropped entirely (§10.2).
    ///
    /// Flag filtering is applied here (resolver-local) rather than in
    /// `edge_sources::manifest_to_edgeset` (which is the pure normative
    /// projection used by tests that don't need flag filtering).
    fn build_edgeset_from_manifest(&self, manifest: &Manifest) -> EdgeSet {
        use milpa_types::{NamedRequire, RequireEntry, UrlRequire};
        let active: BTreeSet<&str> = manifest
            .flags
            .iter()
            .filter(|f| f.default)
            .map(|f| f.name.as_str())
            .collect();
        let mut requires = Vec::new();
        for d in &manifest.deps {
            if !dep_passes_flag_predicates(d, &active) {
                continue;
            }
            match d {
                Dep::Url(u) => {
                    requires.push(RequireEntry::Url(UrlRequire {
                        url: u.git.clone(),
                        ref_: u.git_ref.clone(),
                        predicates: Vec::new(),
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
                        items.push(Item::Url(url_dep(&dep_name, &u.url, &u.ref_)));
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
        for p in &locked.provenances {
            if let ProvenanceRecord::Git {
                url,
                ref_spec,
                commit_sha,
            } = p
            {
                if url == &dep.git && ref_spec.as_deref() == Some(dep.git_ref.as_str()) {
                    return (Some(identity), commit_sha.clone());
                }
                break; // primary git record only
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
            if let ProvenanceRecord::Tarball { url, sha256 } = p {
                if url == &dep.url {
                    return (Some(identity), sha256.clone());
                }
            }
        }
        (None, None)
    }

    fn prior_self_mirrors(&self, name: &str) -> Vec<String> {
        self.prior
            .and_then(|p| p.deps.iter().find(|d| d.name == name))
            .map(|d| d.self_mirrors.clone())
            .unwrap_or_default()
    }

    // --- finalize / graph --------------------------------------------------

    /// Content-hash dedup/alias (Phase B, #32): eagerly-materialized candidates
    /// sharing an identity collapse to the lexicographically-smallest name; the
    /// duplicates' `_deps/<name>` dirs are removed and every candidate's deps +
    /// requires are rewritten to the canonical name. Named candidates are
    /// materialized after this point and bypass dedup (matching the reference).
    fn finalize(&self) {
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

        let mut aliases: BTreeMap<String, String> = BTreeMap::new();
        for (_hash, mut group) in by_hash {
            if group.len() < 2 {
                continue;
            }
            group.sort();
            let canonical = group[0].clone();
            for other in &group[1..] {
                aliases.insert(other.clone(), canonical.clone());
                cands.remove(other);
                let _ = std::fs::remove_dir_all(self.deps_dir.join(other));
            }
        }

        if aliases.is_empty() {
            return;
        }
        for versions in cands.values_mut() {
            for c in versions.values_mut() {
                for d in &mut c.deps {
                    if let Some(can) = aliases.get(&d.package) {
                        d.package = can.clone();
                    }
                }
                for r in &mut c.requires_names {
                    if let Some(can) = aliases.get(r) {
                        *r = can.clone();
                    }
                }
            }
        }
    }

    /// Map the solver solution → a topologically-ordered [`ResolvedGraph`]
    /// (deps before dependents), excluding the synthetic root. Canonical
    /// lexicographic *emission* order is applied later (S7c).
    fn build_graph(&self, solution: &BTreeMap<String, Version>) -> ResolvedGraph {
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
                    // Every non-root candidate carries a provenance; default
                    // defensively (unreachable — root is excluded above).
                    provenance: c.provenance.clone().unwrap_or(ProvenanceRecord::Local {
                        path: String::new(),
                    }),
                    dep_decl: c.dep_decl.clone(),
                    cond_requires,
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
        },
        Provenance::Tarball {
            url,
            expected_sha256,
            ..
        } => ProvenanceRecord::Tarball {
            url: url.clone(),
            sha256: expected_sha256.clone(),
        },
        Provenance::Local { path } => ProvenanceRecord::Local { path: path.clone() },
        Provenance::Oci {
            registry,
            repository,
            digest,
        } => ProvenanceRecord::Oci {
            registry: registry.clone(),
            repository: repository.clone(),
            digest: digest.clone(),
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

/// Filter conditional deps by the active profile (§6). Flag predicates evaluate
/// against `profile.flags`; `nim` predicates against `profile.nim_version`.
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
        | FetchError::Extract(_, m)
        | FetchError::Transport(_, m) => m.clone(),
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
) -> Result<(ResolvedGraph, SuccessCert), (MilpaError, FailureCert)> {
    // Delegates to `solve_with_refutation` instead of `solve`; all setup is
    // identical to `resolve` — factored through `build_single_provider` (D-F2).
    let filtered;
    let manifest = match profile {
        Some(p) => {
            filtered = filter_manifest_by_profile(manifest, p);
            &filtered
        }
        None => manifest,
    };

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
    provider.finalize();

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
            let graph = provider.build_graph(&solution);
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
