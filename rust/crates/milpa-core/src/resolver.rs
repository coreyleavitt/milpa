//! Resolver orchestration (RFC §6 S7b; spec `docs/spec/resolver-semantics.md`).
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

use milpa_manifest::nimble::{parse_nimble, NimbleRequirement};
use milpa_manifest::{Dep, LocalDep, Manifest, Override, Predicate, Profile, TarballDep, UrlDep};
use milpa_solver::{parse_version, solve, Dep as SolverDep, PackageProvider, Strategy, VersionSet};
use milpa_types::{Lockfile, Provenance, ProvenanceRecord, ResolvedDep, ResolvedGraph, Version};

use crate::error::{CoreError, MilpaError};
use crate::fetch::{FetchError, FetcherRegistry};
use crate::identity::compute_content_hash;
use crate::registry::{Index, IndexEntry};

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
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    manifest: &Manifest,
    index: Option<&Index>,
    fetcher: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&Lockfile>,
    strategy: Strategy,
    deps_dir: &Path,
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

    let overrides: BTreeMap<String, Override> = manifest
        .overrides
        .iter()
        .map(|ov| (ov.name.clone(), ov.clone()))
        .collect();

    // Index presence: a named dep with neither an index nor an override is
    // unresolvable (resolver-semantics — RES-NO-INDEX).
    let empty_index = Index::default();
    let index: &Index = match index {
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
            &empty_index
        }
    };

    std::fs::create_dir_all(deps_dir).map_err(io_err)?;

    let project_root = deps_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut provider = ResolveProvider::new(
        fetcher,
        index,
        deps_dir.to_path_buf(),
        project_root,
        overrides,
        prior,
    );

    // Build the synthetic root candidate (requires every manifest dep) and the
    // BFS queue. dev_deps for the ROOT are enrolled here alongside deps (§9);
    // transitive deps never read dev_deps.
    let queue = provider.seed_root(manifest)?;
    for item in queue {
        provider.process_item(item)?;
    }

    // Content-hash dedup/alias for eagerly-materialized candidates (Phase B, #32).
    provider.finalize();

    // Solve over the materialized + stubbed candidate universe.
    let solution = solve(&provider, ROOT, root_version(), strategy)?;

    // A lazy fetch failure during solve is captured (the provider's queries are
    // infallible); surface it in preference to any downstream solver outcome.
    if let Some(e) = provider.take_error() {
        return Err(e);
    }

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
    )
}

// ---------------------------------------------------------------------------
// Queue items + provenance keys
// ---------------------------------------------------------------------------

/// One unit of fetch work discovered during BFS.
#[derive(Debug, Clone)]
enum Item {
    Url(UrlDep),
    Named {
        name: String,
        constraint: Option<String>,
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

/// What `extract_requires` / `build_from_*` return: solver edges, the require
/// names (for the graph), the dep's `src_dir`, and the sub-items to enqueue.
type Extracted = (Vec<SolverDep>, Vec<String>, String, Vec<Item>);

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
    /// `None` for the synthetic root; `Some` for every fetched dep.
    provenance: Option<Provenance>,
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

    candidates: RefCell<BTreeMap<String, BTreeMap<Version, Candidate>>>,
    stubs: RefCell<BTreeMap<String, BTreeMap<Version, IndexEntry>>>,

    seen_url: RefCell<BTreeSet<(String, String)>>,
    seen_named: RefCell<BTreeSet<String>>,
    seen_local: RefCell<BTreeSet<String>>,
    seen_tarball: RefCell<BTreeSet<String>>,
    seen_by_name: RefCell<BTreeMap<String, (PKey, bool)>>,

    error: RefCell<Option<MilpaError>>,
}

/// The cross-name gate's verdict for an item (§10).
enum Gate {
    Proceed,
    Suppress,
    Conflict(PKey, PKey),
}

impl<'a> ResolveProvider<'a> {
    fn new(
        fetcher: &'a dyn FetcherRegistry,
        index: &'a Index,
        deps_dir: PathBuf,
        project_root: PathBuf,
        overrides: BTreeMap<String, Override>,
        prior: Option<&'a Lockfile>,
    ) -> Self {
        ResolveProvider {
            fetcher,
            index,
            deps_dir,
            project_root,
            overrides,
            prior,
            root_authority: BTreeSet::new(),
            candidates: RefCell::new(BTreeMap::new()),
            stubs: RefCell::new(BTreeMap::new()),
            seen_url: RefCell::new(BTreeSet::new()),
            seen_named: RefCell::new(BTreeSet::new()),
            seen_local: RefCell::new(BTreeSet::new()),
            seen_tarball: RefCell::new(BTreeSet::new()),
            seen_by_name: RefCell::new(BTreeMap::new()),
            error: RefCell::new(None),
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
                    if self.overrides.contains_key(&name) {
                        // Override routes a named dep to a URL fetch → singleton.
                        let ov = &self.overrides[&name];
                        root_deps.push(SolverDep::new(name.clone(), eq_sentinel()));
                        seen_by_name.insert(
                            name.clone(),
                            (PKey::Url(ov.git.clone(), ov.git_ref.clone()), true),
                        );
                    } else {
                        root_deps.push(SolverDep::new(
                            name.clone(),
                            from_constraint(n.constraint.as_deref())?,
                        ));
                        seen_by_name.insert(name.clone(), (PKey::Named(name.clone()), true));
                    }
                    root_requires.push(name.clone());
                    queue.push(Item::Named {
                        name,
                        constraint: n.constraint.clone(),
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
        };
        self.store_candidate(root);
        Ok(queue)
    }

    /// Apply overrides, run the precedence gate, and dispatch one item.
    fn process_item(&self, item: Item) -> Result<(), MilpaError> {
        let item = self.apply_override(item);

        match self.gate(&item) {
            Gate::Suppress => return Ok(()),
            Gate::Conflict(a, b) => {
                return Err(res_err(
                    "RES-PROVENANCE-CONFLICT",
                    format!(
                        "provenance conflict for package {:?}: one transitive dep claims {a:?} \
                         and another claims {b:?}; the root manifest does not override it. \
                         Add an override to resolve which source to use.",
                        item.name()
                    ),
                ));
            }
            Gate::Proceed => {}
        }

        match item {
            Item::Url(dep) => self.process_url(dep),
            Item::Local(dep) => self.process_local(dep),
            Item::Tarball(dep) => self.process_tarball(dep),
            Item::Named { name, constraint } => self.process_named(&name, constraint.as_deref()),
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
        let (identity, resolved_ref) =
            self.fetch_any(&dep.name, &provs, &dest, expected_identity.as_deref())?;

        let (deps, requires, src_dir, sub_items) = self.extract_requires(&dest, &dep.name)?;

        // Record the declared primary provenance; carry the resolved commit
        // (preferring the freshly-resolved SHA over a pin) for S7c emission.
        let commit = resolved_ref.or(pinned_sha);
        let prov = git_prov(&dep.git, &dep.git_ref, commit);
        self.store_candidate(Candidate {
            name: dep.name.clone(),
            version: url_dep_version(),
            identity,
            src_dir,
            requires_names: requires,
            deps,
            provenance: Some(prov),
        });

        for it in sub_items {
            self.process_item(it)?;
        }
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
        let (deps, requires, src_dir, sub_items) = self.extract_requires(&dest, &dep.name)?;
        self.store_candidate(Candidate {
            name: dep.name.clone(),
            version: url_dep_version(),
            identity,
            src_dir,
            requires_names: requires,
            deps,
            provenance: Some(Provenance::Local {
                path: dep.path.clone(),
            }),
        });
        for it in sub_items {
            self.process_item(it)?;
        }
        Ok(())
    }

    fn process_tarball(&self, dep: TarballDep) -> Result<(), MilpaError> {
        if !self.seen_tarball.borrow_mut().insert(dep.url.clone()) {
            return Ok(());
        }
        let expected_identity = self.tarball_pin(&dep);
        let prov = Provenance::Tarball {
            url: dep.url.clone(),
            expected_sha256: dep.sha256.clone(),
            strip_components: dep.strip_components,
        };
        let dest = self.deps_dir.join(&dep.name);
        let (identity, _ref) = self.fetch_any(
            &dep.name,
            std::slice::from_ref(&prov),
            &dest,
            expected_identity.as_deref(),
        )?;
        let (deps, requires, src_dir, sub_items) = self.extract_requires(&dest, &dep.name)?;
        self.store_candidate(Candidate {
            name: dep.name.clone(),
            version: url_dep_version(),
            identity,
            src_dir,
            requires_names: requires,
            deps,
            provenance: Some(prov),
        });
        for it in sub_items {
            self.process_item(it)?;
        }
        Ok(())
    }

    /// Phase A: enumerate index versions for a named dep as stubs (no fetch).
    fn process_named(&self, name: &str, constraint: Option<&str>) -> Result<(), MilpaError> {
        if name == "nim" {
            self.seen_named.borrow_mut().insert(name.to_string());
            return Ok(());
        }
        if !self.seen_named.borrow_mut().insert(name.to_string()) {
            return Ok(());
        }
        let entries = self.index_entries_for(name, constraint)?;
        let mut by_ver: BTreeMap<Version, IndexEntry> = BTreeMap::new();
        for e in entries {
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
        entry: &IndexEntry,
    ) -> Result<Vec<SolverDep>, MilpaError> {
        let dest = self.deps_dir.join(name);
        let expected = if entry.content_hash.is_empty() {
            None
        } else {
            Some(entry.content_hash.as_str())
        };
        let (identity, _ref) = self.fetch_any(
            name,
            std::slice::from_ref(&entry.provenance),
            &dest,
            expected,
        )?;
        let (deps, requires, src_dir, sub_items) = self.extract_requires(&dest, name)?;
        let candidate = Candidate {
            name: name.to_string(),
            version: version.clone(),
            identity,
            src_dir,
            requires_names: requires,
            deps: deps.clone(),
            provenance: Some(entry.provenance.clone()),
        };
        self.store_candidate(candidate);
        self.stubs
            .borrow_mut()
            .get_mut(name)
            .map(|m| m.remove(version));
        // Enroll transitives discovered in this named dep (URL fetched eagerly;
        // named enrolled as stubs) so the solver can continue without a restart.
        for it in sub_items {
            self.process_item(it)?;
        }
        Ok(deps)
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
    ) -> Result<(String, Option<String>), MilpaError> {
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
                        _ => return Ok((identity, receipt.resolved_ref)),
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

    /// Read a fetched dep's transitive requires. Prefers `milpa.kdl`; falls
    /// back to `.nimble` for legacy Nim packages. Returns
    /// `(solver deps, requires names, src_dir, sub-items)`.
    fn extract_requires(&self, dest: &Path, name: &str) -> Result<Extracted, MilpaError> {
        let milpa_kdl = dest.join("milpa.kdl");
        if milpa_kdl.is_file() {
            let text = std::fs::read_to_string(&milpa_kdl).map_err(io_err)?;
            let manifest = milpa_manifest::parse_manifest(&text)?;
            return self.build_from_manifest(&manifest);
        }
        if let Some(nimble) = find_nimble(dest, name) {
            let text = std::fs::read_to_string(&nimble).map_err(io_err)?;
            let nm = parse_nimble(&text);
            return self.build_from_nimble(&nm);
        }
        Ok((Vec::new(), Vec::new(), String::new(), Vec::new()))
    }

    /// Build solver deps from a transitive dep's `milpa.kdl`. Only `manifest.deps`
    /// is read — **never** `dev_deps` (the §9 transitive-exclusion guard) — and
    /// deps are filtered by `when flag=` predicates against this dep's own
    /// default flags.
    fn build_from_manifest(&self, manifest: &Manifest) -> Result<Extracted, MilpaError> {
        let active: BTreeSet<&str> = manifest
            .flags
            .iter()
            .filter(|f| f.default)
            .map(|f| f.name.as_str())
            .collect();

        let mut deps = Vec::new();
        let mut names = Vec::new();
        let mut items = Vec::new();
        for d in &manifest.deps {
            if !dep_passes_flag_predicates(d, &active) {
                continue;
            }
            match d {
                Dep::Url(u) => {
                    deps.push(SolverDep::new(u.name.clone(), eq_sentinel()));
                    names.push(u.name.clone());
                    items.push(Item::Url(u.clone()));
                }
                Dep::Named(n) => {
                    if n.name == "nim" {
                        continue;
                    }
                    let vs = if self.overrides.contains_key(&n.name) {
                        eq_sentinel()
                    } else {
                        from_constraint(n.constraint.as_deref())?
                    };
                    deps.push(SolverDep::new(n.name.clone(), vs));
                    names.push(n.name.clone());
                    items.push(Item::Named {
                        name: n.name.clone(),
                        constraint: n.constraint.clone(),
                    });
                }
                // Local/Tarball/Member from a transitive milpa.kdl are out of
                // scope (mirrors the Python reference's deferral).
                Dep::Local(_) | Dep::Tarball(_) | Dep::Member(_) => {}
            }
        }
        Ok((deps, names, manifest.src_dir.clone(), items))
    }

    /// Build solver deps from a transitive dep's `.nimble` requires.
    fn build_from_nimble(
        &self,
        nm: &milpa_manifest::nimble::NimbleManifest,
    ) -> Result<Extracted, MilpaError> {
        let mut deps = Vec::new();
        let mut names = Vec::new();
        let mut items = Vec::new();
        for req in &nm.requires {
            match req {
                NimbleRequirement::Url { url, ref_spec, .. } => {
                    let dep_name = name_from_url(url)?;
                    deps.push(SolverDep::new(dep_name.clone(), eq_sentinel()));
                    names.push(dep_name.clone());
                    let git_ref = ref_spec.clone().unwrap_or_else(|| "main".to_string());
                    items.push(Item::Url(url_dep(&dep_name, url, &git_ref)));
                }
                NimbleRequirement::Named {
                    name, constraint, ..
                } => {
                    if name == "nim" {
                        continue;
                    }
                    let vs = if self.overrides.contains_key(name) {
                        eq_sentinel()
                    } else {
                        from_constraint(constraint.as_deref())?
                    };
                    deps.push(SolverDep::new(name.clone(), vs));
                    names.push(name.clone());
                    items.push(Item::Named {
                        name: name.clone(),
                        constraint: constraint.clone(),
                    });
                }
            }
        }
        Ok((deps, names, nm.src_dir.clone().unwrap_or_default(), items))
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

    fn tarball_pin(&self, dep: &TarballDep) -> Option<String> {
        let prior = self.prior?;
        let locked = prior.deps.iter().find(|d| d.name == dep.name)?;
        let identity = locked.identity.clone().filter(|s| !s.is_empty())?;
        for p in &locked.provenances {
            if let ProvenanceRecord::Tarball { url, .. } = p {
                if url == &dep.url {
                    return Some(identity);
                }
            }
        }
        None
    }

    fn prior_self_mirrors(&self, name: &str) -> Vec<String> {
        self.prior
            .and_then(|p| p.deps.iter().find(|d| d.name == name))
            .map(|d| d.self_mirrors.clone())
            .unwrap_or_default()
    }

    // --- index -------------------------------------------------------------

    /// Index entries for `name` satisfying `constraint` (parseable versions only).
    fn index_entries_for(
        &self,
        name: &str,
        constraint: Option<&str>,
    ) -> Result<Vec<IndexEntry>, MilpaError> {
        let Some((_, entries)) = self.index.packages.iter().find(|(n, _)| n == name) else {
            return Ok(Vec::new());
        };
        let vs = from_constraint(constraint)?;
        let mut out = Vec::new();
        for e in entries {
            if let Some(v) = parse_version(&e.version) {
                if vs.contains(&v) {
                    out.push(e.clone());
                }
            }
        }
        Ok(out)
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
            .map(|c| ResolvedDep {
                name: c.name.clone(),
                identity: c.identity.clone(),
                version: c.version.clone(),
                src_dir: c.src_dir.clone(),
                requires: c.requires_names.clone(),
                // Every non-root candidate carries a provenance; default
                // defensively (unreachable — root is excluded above).
                provenance: c.provenance.clone().unwrap_or(Provenance::Local {
                    path: String::new(),
                }),
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

/// `VersionSet::from_constraint`, remapping the solver's uncoded
/// [`ConstraintError`](milpa_solver::ConstraintError) to `MAN-NIMBLE-CONSTRAINT`
/// (resolver-semantics — a malformed constraint discovered at resolve time).
fn from_constraint(constraint: Option<&str>) -> Result<VersionSet, MilpaError> {
    VersionSet::from_constraint(constraint).map_err(|e| {
        MilpaError::Manifest(milpa_manifest::ManifestError::new(
            "MAN-NIMBLE-CONSTRAINT",
            format!("malformed version constraint {constraint:?}: {e}"),
        ))
    })
}

fn git_prov(url: &str, git_ref: &str, commit_sha: Option<String>) -> Provenance {
    Provenance::Git {
        url: url.to_string(),
        ref_spec: git_ref.to_string(),
        commit_sha,
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

fn find_nimble(dir: &Path, hint: &str) -> Option<PathBuf> {
    let by_hint = dir.join(format!("{hint}.nimble"));
    if by_hint.is_file() {
        return Some(by_hint);
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut found: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "nimble"))
        .collect();
    found.sort();
    found.into_iter().next()
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
        "nim" => match &profile.nim_version {
            Some(actual) => pred.values.iter().any(|v| version_satisfies(actual, v)),
            None => false,
        },
        // `platform` / `arch` / `milpa` need profile fields the minimal S6
        // `Profile` does not yet carry; a present profile that lacks the field
        // matches nothing (mirrors Python's `getattr(profile, name, None)`).
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

/// Filesystem failures during resolution are uncoded in the spec (§5 leaves
/// them to the host), rendered as the non-catalog `MILPA-INTERNAL-IO` sentinel
/// (kept out of `all_codes()`, same as the identity/CAS I/O sentinel).
fn io_err(e: std::io::Error) -> MilpaError {
    MilpaError::Core(CoreError::Resolver("MILPA-INTERNAL-IO", e.to_string()))
}

fn fetch_msg(e: &FetchError) -> String {
    match e {
        FetchError::Failed(m) | FetchError::AllFailed(m) | FetchError::Extract(_, m) => m.clone(),
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

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod resolver_tests;
