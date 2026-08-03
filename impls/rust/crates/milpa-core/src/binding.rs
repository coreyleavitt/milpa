//! `BindingResolver` — the deterministic, in-memory binding phase (S2), per
//! `docs/rfc-origin-as-identity.md` §4.3. Mirrors Python's `milpa/binding.py`
//! function-for-function (§9 cross-impl discipline).
//!
//! This is the first-class **binding phase** that produces the solver's
//! source-id variables, replacing the fragile `provenance_gate`/`TIER_*`
//! side-table as the accept/reject authority for every `Item` kind. **Post
//! S3b:** the validate-against-registry functions
//! (`normalize_git_source_url`/`registry_git_urls`/
//! `registry_oci_source_urls`/`validate_transitive_url_against_registry`,
//! all `resolver.rs`) were fully dead (defined, never called) and are
//! deleted outright. **S5-rekey (Stage A):** `Item::Local`/`Item::Tarball`
//! admission is migrated onto `BindingResolver` too, exactly like
//! `Item::Named`/`Item::Url` — `gate()`/`Gate`/`TIER_*`/`PKey`/`seen_by_name`
//! (`resolver.rs`) are deleted entirely; `gate_only`'s four branches
//! (`Named`/`Url`/`Local`/`Tarball`) are the sole admission mechanism, each
//! calling `record_discovery` directly for the Phase B discovery-order side
//! effect.
//!
//! **Root-first is structural, not a convention.** Root/override `Claim`s
//! are reconciled by the CALLER (override pre-empts the root dep
//! declaration — mirroring today's git-override-to-url-dep transform)
//! before they ever reach `BindingResolver`. All root claims are bound in
//! `new()`; `submit()` accepts only non-root claims (it panics otherwise).
//! So "root submitted first" is enforced by the API shape, not caller
//! discipline.
//!
//! **Authority is a two-valued fact, not a lattice.** `Claim.is_root: bool`
//! is the entire authority model — arbitration only ever asks "is this
//! root?", never compares a priority integer.
//!
//! **Keyed by `DepKey` (`(name, namespace)`), never a bare name (§4.3
//! B1/G1).** A bare-name store is the LITERAL #193 root cause. `Claim.name`
//! carries the manifest/solver qualified-name form (`"foo"` or `"ns::foo"`,
//! `spec/resolver-semantics.md` §6b) — the grouping key is derived from
//! that field alone via `DepKey::from_solver_var`, never from the accepted
//! `SourceId`'s own fields. This is what makes the "override to a different
//! registry coordinate" case (RFC §5 row) work: the grouping key stays the
//! *overridden* coordinate even when the accepted `SourceId` is a
//! `Registry` origin in a completely different `(namespace, name)`.

use std::collections::{HashMap, HashSet};

use milpa_manifest::{Dep, Override, OverrideTarget};
use milpa_types::{DepKey, FetchableOrigin, Provenance, SolverKey, SourceId};

use crate::error::{CoreError, MilpaError};
use crate::registry::{BareLookup, Index, Package};
use crate::source_id::{canonical, format_source_id, normalize_git_url, normalize_source};

/// One declaration site's claim on a dep's origin.
///
/// `name` is the label THIS declaration used — the manifest/solver
/// qualified-name form (`"foo"` or `"ns::foo"`; see module docs), used both
/// for diagnostics/slot projection and to derive the grouping `DepKey`.
///
/// `claimant` is message text ONLY (`"root"` / `"override:<name>"` /
/// `"<parent>@<version>"`) — never parsed, never compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub name: String,
    pub source_id: SourceId,
    pub is_root: bool,
    pub claimant: String,
}

/// The 3-way outcome of a claim submission (RFC §4.3 G2 — NOT a bool).
///
/// Flattening `Duplicate`/`LostToRoot` into one `suppressed: bool` would
/// reproduce the exact opacity the RFC's §2.2 condemns in the old
/// side-table: a user asking "why didn't my transitive git fork get picked
/// up?" deserves a typed answer, not a log grep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// First claim for this key — caller enqueues/fetches.
    New,
    /// Matched the existing binding — harmless no-op.
    Duplicate,
    /// Disagreed with a root binding — discarded (Cargo `[patch]` semantics).
    LostToRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingDecision {
    pub accepted: SourceId,
    /// Caller enqueues iff `outcome == BindOutcome::New`.
    pub outcome: BindOutcome,
}

/// The grouping key — derived from `claim.name` alone (never from
/// `claim.source_id`'s own fields; see module docs).
fn key_for(claim: &Claim) -> DepKey {
    DepKey::from_solver_var(&claim.name)
}

fn conflict(msg: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::Resolver("RES-BINDING-CONFLICT", msg.into()))
}

/// One instance per `resolve()`. Deterministic, in-memory-only: it never
/// fetches a package tree.
///
/// Root/override claims are bound at construction; only transitive claims
/// arrive via `submit()`.
#[derive(Debug)]
pub struct BindingResolver {
    bindings: HashMap<DepKey, SourceId>,
    root_keys: HashSet<DepKey>,
    /// RFC origin-as-identity §4.4 (S5-rekey): a SECOND index over the SAME
    /// authoritative store — `canonical(source_id)` → the first `DepKey`
    /// ever bound to it (insertion order == BFS-first, mirroring Phase B's
    /// alias-selection convention). This is the "provider-internal
    /// canonical → DepKey map" §4.4 calls for, kept INSIDE `BindingResolver`
    /// (not a separately-maintained side-table) so it is always exactly in
    /// sync with `bindings` — updated atomically in `new`/`submit`, never
    /// rebuilt or threaded separately. A second, different `DepKey` later
    /// bound to the SAME source_id (the "two labels, one origin" case) does
    /// not overwrite the first entry — this is the pre-fetch collapse the
    /// solver re-key exists to realize. DE1: stores the interned `SolverKey`
    /// (origin string → the one SolverKey the solver uses, whose `.display()`
    /// is the BFS-first DepKey), replacing the old `canonical → DepKey` reverse
    /// map. Mirrors Python's `binding.BindingResolver._solverkey_index`.
    solverkey_index: HashMap<String, SolverKey>,
}

impl BindingResolver {
    /// # Panics
    /// Panics if any `root_claims` entry has `is_root == false` (only
    /// root/override claims may be passed here — transitive claims go
    /// through `submit()`), or if two root claims disagree on the source
    /// for one `DepKey` — unreachable by construction (RFC §4.3: the
    /// caller must reconcile override-vs-base-dep-declaration BEFORE
    /// building `root_claims`; two disagreeing root claims arriving here is
    /// an internal invariant violation, never `RES-BINDING-CONFLICT`).
    pub fn new(root_claims: &[Claim]) -> Self {
        let mut bindings: HashMap<DepKey, SourceId> = HashMap::new();
        let mut root_keys: HashSet<DepKey> = HashSet::new();
        let mut solverkey_index: HashMap<String, SolverKey> = HashMap::new();
        for claim in root_claims {
            assert!(
                claim.is_root,
                "BindingResolver::new received a non-root claim (name={:?}, claimant={:?}); \
                 only root/override claims may be passed to new() — transitive claims go \
                 through submit()",
                claim.name, claim.claimant
            );
            let key = key_for(claim);
            if let Some(existing) = bindings.get(&key) {
                assert!(
                    existing == &claim.source_id,
                    "BindingResolver received two disagreeing root claims for {key:?}: {} vs {} \
                     — root claims must be reconciled (override pre-empts the base dep \
                     declaration) before BindingResolver is constructed",
                    format_source_id(existing),
                    format_source_id(&claim.source_id),
                );
            }
            bindings.insert(key.clone(), claim.source_id.clone());
            root_keys.insert(key.clone());
            let ck = canonical(&claim.source_id);
            solverkey_index
                .entry(ck.clone())
                .or_insert_with(|| SolverKey::new(ck, key));
        }
        BindingResolver { bindings, root_keys, solverkey_index }
    }

    /// Submit a non-root (transitive) claim.
    ///
    /// # Errors
    /// Returns `RES-BINDING-CONFLICT` when a non-root claim disagrees with
    /// another non-root binding and no root claim exists for that `DepKey`
    /// to arbitrate.
    ///
    /// # Panics
    /// Panics if handed a root claim (`claim.is_root == true`) — root
    /// claims are bound at `new()` only, not `submit()`.
    pub fn submit(&mut self, claim: &Claim) -> Result<BindingDecision, MilpaError> {
        assert!(
            !claim.is_root,
            "BindingResolver::submit received a root claim (name={:?}, claimant={:?}); root \
             claims are bound at new(), not submit()",
            claim.name, claim.claimant
        );
        let key = key_for(claim);
        let existing = self.bindings.get(&key).cloned();
        match existing {
            None => {
                self.bindings.insert(key.clone(), claim.source_id.clone());
                let ck = canonical(&claim.source_id);
                self.solverkey_index
                    .entry(ck.clone())
                    .or_insert_with(|| SolverKey::new(ck, key));
                Ok(BindingDecision { accepted: claim.source_id.clone(), outcome: BindOutcome::New })
            }
            Some(existing) if existing == claim.source_id => {
                Ok(BindingDecision { accepted: existing, outcome: BindOutcome::Duplicate })
            }
            Some(existing) if self.root_keys.contains(&key) => {
                // Transitive disagrees with a ROOT binding: loses to root
                // silently — Cargo-`[patch]` semantics.
                Ok(BindingDecision { accepted: existing, outcome: BindOutcome::LostToRoot })
            }
            Some(existing) => {
                // Transitive disagrees with another TRANSITIVE binding, and
                // no root claim exists for this name: unresolvable without
                // human input.
                Err(conflict(format!(
                    "conflicting sources for {:?}: {} vs {}; declare it at the root via \
                     `overrides {{}}` to resolve",
                    claim.name,
                    format_source_id(&existing),
                    format_source_id(&claim.source_id),
                )))
            }
        }
    }

    pub fn source_id_for(&self, key: &DepKey) -> Option<&SourceId> {
        self.bindings.get(key)
    }

    /// Is `key` bound by a ROOT/override claim? The registry-shadow tripwire
    /// uses this to decide whether to second-guess a transitive claim: root
    /// owns a source only over the EXACT `DepKey` it declared, never over a
    /// bare name — a root `foo namespace="ns1"` gives NO authority over a bare
    /// `foo` a transitive tries to source elsewhere (that would let an
    /// unrelated namespaced root dep silently disable the dependency-confusion
    /// check for a different coordinate). Mirrors Python's
    /// `BindingResolver.is_root_authority`.
    pub fn is_root_authority(&self, key: &DepKey) -> bool {
        self.root_keys.contains(key)
    }

    /// `canonical(source_id_for(key))` — the string the solver sees for an
    /// ALREADY-BOUND `DepKey` (RFC §4.4 deliverable #1). Returns
    /// `MILPA-INTERNAL` if `key` has never been bound — every caller reaches
    /// this only after a root claim (bound at `new`) or an accepted
    /// `submit()` (`New`/`Duplicate`), so an unbound key here is an internal
    /// invariant violation, not a user-facing condition. Mirrors Python's
    /// `binding.BindingResolver.canonical_for`.
    pub fn canonical_for(&self, key: &DepKey) -> Result<SolverKey, MilpaError> {
        let sid = self.bindings.get(key).ok_or_else(|| {
            MilpaError::Core(CoreError::Resolver(
                "MILPA-INTERNAL",
                format!(
                    "canonical_for({key:?}) has no binding — this is an internal milpa bug; \
                     please report it"
                ),
            ))
        })?;
        // The origin was interned (with its BFS-first display) at bind time in
        // `new`/`submit`; read that interned SolverKey. The `unwrap_or_else`
        // fallback (this key as display) is defensive — unreached for a bound
        // key, since binding always populates `solverkey_index`.
        let ck = canonical(sid);
        Ok(self
            .solverkey_index
            .get(&ck)
            .cloned()
            .unwrap_or_else(|| SolverKey::new(ck, key.clone())))
    }

    /// The BFS-first display `DepKey` for an origin string, read off the
    /// interned `SolverKey`. `None` for a variable that was never minted as a
    /// prefixed canonical (a bare/`ns::name`/sentinel string — the caller
    /// falls back to `DepKey::from_solver_var`, exact for those). This is the
    /// single projection boundary for a solver variable held only as `&str`
    /// (DE1: a caller holding the `SolverKey` itself reads `.display()`
    /// directly and never needs this).
    pub fn display_for(&self, solver_var: &str) -> Option<&DepKey> {
        self.solverkey_index.get(solver_var).map(SolverKey::display)
    }
}

/// The `canonical(source_id)` string a `requires` occurrence WOULD claim if
/// submitted right now (RFC §4.4 deliverable #1) — a pure, side-effect-free
/// companion to `dep_declared_raw_origin`/`override_target_to_raw_origin`
/// (same primitives, no new dispatch logic), generalized to the raw
/// `(name, namespace, url)` fields root/sub-item term construction have on
/// hand (an `EdgeSet`'s url/named requires, not a `milpa_manifest::Dep`).
///
/// Used to feed the solver `Term`/provider-dict key BEFORE the corresponding
/// claim is actually `submit()`ted (submission happens later, at BFS
/// dispatch, batched so a sibling conflict is caught before any fetch — RFC
/// §3a). This is safe because admission is a DETERMINISTIC function of
/// (name, override state): every occurrence of the same name, wherever
/// declared, computes the exact string `BindingResolver` will later accept —
/// UNLESS it is a losing transitive claim in a genuine conflict, in which
/// case resolution aborts with `RES-BINDING-CONFLICT` before anything
/// downstream ever reads the string.
///
/// `url: None` selects the named/registry branch; `url: Some(_)` selects the
/// git branch — the only two kinds root/sub-item term construction ever
/// builds terms for (Local/Tarball transitive requires are dropped upstream,
/// M2 security gate). Mirrors Python's `binding.canonical_key_for_requirement`.
///
/// Phase 1 — name-resolution (`reference → source_id`), BINDING-AWARE:
///
/// 1. *name*'s `DepKey` already bound? → `binding_resolver.source_id_for
///    (dep_key)` wins, REGARDLESS of source-id kind. Root/override claims
///    bind at `BindingResolver::new`; earlier accepted transitive claims
///    bind during BFS (`gate_only`'s `submit()` calls — every kind). A
///    later disagreeing claim for an already-bound ref is
///    `RES-BINDING-CONFLICT` (root) or silently `LostToRoot` (transitive
///    vs. root) — unchanged, handled entirely by
///    `BindingResolver::submit`/`new`, not here.
/// 2. Else (genuinely unbound — first-ever encounter): a KIND DEFAULT —
///    `root_self_name` match (§14, checked first — a structural identity,
///    never redirected by `overrides{}`) → the root-self `SourceId::Member`
///    sentinel; `overrides_by_name` match → the override's target
///    `SourceId`; `url` present → that git declaration's own `GitSourceId`;
///    otherwise → an ordinary registry coordinate.
///
/// Phase 2 — canonicalization (`source_id → canonical`): uniform,
/// kind-free — `canonical()` (`source_id.rs`), always.
///
/// `root_self_name`: the resolving root's own manifest name (§14 "root
/// satisfies its own name"), or `None` for a context with no such concept
/// (e.g. `resolve_workspace`, or a manifest with no declared name).
///
/// `binding_resolver`: the resolver's `BindingResolver` instance, when
/// available — the PRIMARY source for the require-name key: if this name's
/// `DepKey` is already bound, the term key must agree with THAT binding's
/// actual candidate key, not a fresh guess. `None` only in a standalone/unit
/// test context with no live resolve() in progress — falls back to the
/// guess-only behavior.
pub fn canonical_key_for_requirement(
    name: &str,
    namespace: Option<&str>,
    url: Option<&str>,
    overrides_by_name: &std::collections::BTreeMap<String, Override>,
    index: &Index,
    root_self_name: Option<&str>,
    binding_resolver: Option<&BindingResolver>,
) -> Result<SolverKey, MilpaError> {
    let dk = DepKey { name: name.to_string(), namespace: namespace.map(str::to_string) };
    if let Some(br) = binding_resolver {
        if br.source_id_for(&dk).is_some() {
            // Bound: return the interned SolverKey (BFS-first display).
            return br.canonical_for(&dk);
        }
    }
    // Unbound (first encounter): the kind-default guess. This requirement's
    // own DepKey IS the first (BFS-first) label for the guessed origin, so it
    // is the display; when the claim is later submitted, `canonical_for` interns
    // the same origin with the same first-seen display.
    if namespace.is_none() && url.is_none() {
        if let Some(rsn) = root_self_name {
            if name == rsn {
                return Ok(SolverKey::new(
                    canonical(&SourceId::Member { member_name: name.to_string() }),
                    dk,
                ));
            }
        }
    }
    let raw = match overrides_by_name.get(name) {
        Some(ov) => override_target_to_raw_origin(ov, index),
        None => match url {
            Some(u) => SourceId::Fetchable(FetchableOrigin::Git { url: u.to_string(), subpath: None }),
            None => SourceId::Fetchable(FetchableOrigin::Registry {
                registry: DEFAULT_REGISTRY_ALIAS.to_string(),
                namespace: resolved_registry_namespace(name, namespace, index),
                name: name.to_string(),
            }),
        },
    };
    Ok(SolverKey::new(canonical(&normalize_source(&raw)?), dk))
}

// ---------------------------------------------------------------------------
// Root-claim reconciliation (S3a) — override-preempts-root-dep, RFC §4.3.
// Mirrors Python's `binding.reconcile_root_claims` function-for-function.
// ---------------------------------------------------------------------------

/// The registry alias every `Registry` source-id uses today (RFC §4.1 — the
/// registry component is a CONFIGURED ALIAS slug, never a base URL). milpa
/// does not yet support multiple configured registries/aliases; one
/// hardcoded alias is the minimal-viable choice until a second registry is a
/// proven need. Mirrors Python's `binding.DEFAULT_REGISTRY_ALIAS`.
pub const DEFAULT_REGISTRY_ALIAS: &str = "tianguis";

/// The REAL resolved index namespace for a registry coordinate (RFC §4.3
/// B1/G1 — `Registry.namespace` is always the real resolved index
/// namespace, never the manifest qualifier; the two CAN differ).
///
/// An explicit manifest qualifier is used as-is. A bare (unqualified) name is
/// looked up; an unambiguous match uses the index's own recorded namespace.
/// An absent or ambiguous bare name falls back to `None` — the ordinary
/// enumeration path raises the appropriate `TNG-NOT-FOUND`/`TNG-AMBIGUOUS-NAME`
/// immediately afterward regardless. Mirrors Python's
/// `binding.resolved_registry_namespace`.
pub fn resolved_registry_namespace(name: &str, namespace: Option<&str>, index: &Index) -> Option<String> {
    if let Some(ns) = namespace {
        return Some(ns.to_string());
    }
    match index.lookup_bare(name) {
        BareLookup::Found(pkg) => {
            if pkg.namespace.is_empty() { None } else { Some(pkg.namespace) }
        }
        _ => None,
    }
}

/// The `SourceId` an override's target denotes (pre-normalization). Mirrors
/// Python's `binding._override_target_to_raw_origin`.
///
/// `index` (S8b, rfc-origin-as-identity.md §7 B5) is consulted ONLY for a
/// `Registry` target whose `namespace` is unset — a bare-name index lookup,
/// mirroring `dep_declared_raw_origin`'s `Named` branch, so the root claim
/// built here (at `BindingResolver::new` time) agrees with whatever the
/// "named" BFS arm will independently compute for the SAME coordinate later.
fn override_target_to_raw_origin(ov: &Override, index: &Index) -> SourceId {
    match &ov.target {
        OverrideTarget::Git { url, subpath, .. } => {
            SourceId::Fetchable(FetchableOrigin::Git { url: url.clone(), subpath: subpath.clone() })
        }
        OverrideTarget::Local { path } => {
            SourceId::Fetchable(FetchableOrigin::Local { path: path.clone() })
        }
        OverrideTarget::Member { member_name } => SourceId::Member { member_name: member_name.clone() },
        OverrideTarget::Oci { registry, repository, subpath, .. } => SourceId::Fetchable(
            FetchableOrigin::Oci { registry: registry.clone(), repository: repository.clone(), subpath: subpath.clone() },
        ),
        OverrideTarget::Tarball { url, subpath, .. } => {
            SourceId::Fetchable(FetchableOrigin::Tarball { url: url.clone(), subpath: subpath.clone() })
        }
        OverrideTarget::Registry { name, namespace } => {
            let ns = resolved_registry_namespace(name, namespace.as_deref(), index);
            SourceId::Fetchable(FetchableOrigin::Registry {
                registry: DEFAULT_REGISTRY_ALIAS.to_string(),
                namespace: ns,
                name: name.clone(),
            })
        }
    }
}

/// The `SourceId` a dep's OWN declaration denotes (pre-normalization,
/// pre-override), or `None` for a dep kind that makes no claim of its own
/// (`Dep::Member` — a workspace-only concern; the caller registers a
/// `SourceId::Member` claim per workspace member independently, not via a
/// dep declaration). Mirrors Python's `binding._dep_declared_raw_origin`.
fn dep_declared_raw_origin(dep: &Dep, index: &Index) -> Option<SourceId> {
    match dep {
        Dep::Url(d) => Some(SourceId::Fetchable(FetchableOrigin::Git { url: d.git.clone(), subpath: d.subpath.clone() })),
        Dep::Named(d) => Some(SourceId::Fetchable(FetchableOrigin::Registry {
            registry: DEFAULT_REGISTRY_ALIAS.to_string(),
            namespace: resolved_registry_namespace(&d.name, d.namespace.as_deref(), index),
            name: d.name.clone(),
        })),
        Dep::Tarball(d) => Some(SourceId::Fetchable(FetchableOrigin::Tarball { url: d.url.clone(), subpath: d.subpath.clone() })),
        Dep::Local(d) => Some(SourceId::Fetchable(FetchableOrigin::Local { path: d.path.clone() })),
        Dep::Member(_) => None,
    }
}

/// Build the reconciled root `Claim` set for `BindingResolver::new` (RFC
/// §4.3: "the override pre-empts the root dep declaration before binding" —
/// mirroring the git-override-to-url-dep transform).
///
/// `deps` is every root-authoritative dep declaration — a single manifest's
/// `deps + dev_deps` for a standalone resolve; every workspace member's
/// `deps + dev_deps` for `resolve_workspace`; the caller assembles the right
/// list. Dep-source-agnostic so both entry points (and a later frozen-path
/// slice) reuse the identical override-reconciliation transform.
///
/// Reconciliation: for each dep, an override on the SAME name wins — its
/// target (not the dep's own declaration) determines the claim's `SourceId`
/// — so two disagreeing root claims for one name are unreachable by
/// construction (`BindingResolver::new` treats that as an internal invariant
/// violation, never `RES-BINDING-CONFLICT`). An override with NO
/// corresponding dep declaration (RFC §5 "Overrides" row — patching a
/// transitive-only name) still produces its own root `Claim`, bound
/// regardless of whether the name is ever declared as a root dep.
/// `Dep::Member` entries produce no claim. Mirrors Python's
/// `binding.reconcile_root_claims`.
pub fn reconcile_root_claims(
    deps: &[Dep],
    overrides: &[Override],
    index: &Index,
) -> Result<Vec<Claim>, MilpaError> {
    let overrides_by_name: HashMap<&str, &Override> =
        overrides.iter().map(|ov| (ov.name.as_str(), ov)).collect();
    let mut claims: Vec<Claim> = Vec::new();
    // Bare names — drives the override catch-up loop below (overrides have
    // no namespace axis, so they can only ever be looked up/deduped bare).
    let mut seen_names: HashSet<String> = HashSet::new();
    // Qualified (name, namespace) dedup — a bare root dep and a
    // NAMESPACE-QUALIFIED root dep sharing a bare name are DIFFERENT deps
    // (S5b B1/G1: qualified vs. bare never cross-bind) and each needs its
    // own claim.
    let mut seen_keys: HashSet<DepKey> = HashSet::new();
    // The source bound to each already-seen key. A SECOND root declaration of
    // the same (name, namespace) that disagrees on source is a hard
    // RES-BINDING-CONFLICT, not a silent drop: the old first-wins skip hid
    // `deps { foo local="./a" }` + `dev-deps { foo local="./b" }`, producing a
    // lockfile whose recorded `source` disagreed with the materialized bytes.
    // RFC §4.3: root claims bind cleanly or raise — never a silent condition.
    let mut seen_key_source: HashMap<DepKey, SourceId> = HashMap::new();
    for dep in deps {
        let name = dep.name().to_string();
        let namespace = match dep {
            Dep::Named(n) => n.namespace.clone(),
            _ => None,
        };
        let key = DepKey { name: name.clone(), namespace: namespace.clone() };
        let first_time = !seen_keys.contains(&key);
        seen_keys.insert(key.clone());
        seen_names.insert(name.clone());
        let (raw, claimant, claim_name): (SourceId, String, String) =
            match overrides_by_name.get(name.as_str()) {
                // An override's grouping key is always bare — Override has no
                // namespace concept, and overrides_by_name matches by bare
                // name regardless of the matched dep's own namespace.
                Some(ov) => (
                    override_target_to_raw_origin(ov, index),
                    format!("override:{name}"),
                    name.clone(),
                ),
                None => match dep_declared_raw_origin(dep, index) {
                    // A plain (non-overridden) declaration's grouping key
                    // carries the dep's own qualified identity — a
                    // namespace-qualified root NamedDep binds under
                    // DepKey(name, namespace), never the bare DepKey(name,
                    // None) — so it never cross-binds an unrelated bare dep
                    // sharing the same bare name.
                    Some(raw) => (raw, "root".to_string(), key.solver_var()),
                    None => continue,
                },
            };
        let source_id = normalize_source(&raw)?;
        if !first_time {
            if let Some(prior) = seen_key_source.get(&key) {
                if *prior != source_id {
                    return Err(conflict(format!(
                        "package {claim_name:?} is declared at the root more than \
                         once with disagreeing sources: {} vs {}; a package may be \
                         declared at the root (across deps and dev-deps) only once",
                        format_source_id(prior),
                        format_source_id(&source_id),
                    )));
                }
            }
            // Same source (or the first sighting produced no claim) — the
            // first-seen claim stands; this is an idempotent duplicate.
            continue;
        }
        seen_key_source.insert(key.clone(), source_id.clone());
        claims.push(Claim {
            name: claim_name,
            source_id,
            is_root: true,
            claimant,
        });
    }
    for ov in overrides {
        if seen_names.contains(&ov.name) {
            continue;
        }
        seen_names.insert(ov.name.clone());
        let raw = override_target_to_raw_origin(ov, index);
        claims.push(Claim {
            name: ov.name.clone(),
            source_id: normalize_source(&raw)?,
            is_root: true,
            claimant: format!("override:{}", ov.name),
        });
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Registry-shadow tripwire (S3c) — RFC §6.1/§11 D-Fork1. Mirrors Python's
// `binding.check_registry_shadow` function-for-function.
// ---------------------------------------------------------------------------

/// The pre-fetch dependency-confusion tripwire (RFC §6.1/§11 D-Fork1, S3c —
/// the security-critical companion that must land atomically with
/// `BindingResolver` becoming authoritative, S3a).
///
/// This is NOT a source-selection mechanism (coordinate-is-origin already
/// settled that — RFC §3.2) — it is an orthogonal, additive TRUST check
/// consulted before a NEW (previously-unbound) transitive `git=`/`tarball=`/
/// `oci=` claim is admitted:
///
/// - **Trigger**: the claim's bare name is ALSO a name the registry owns, in
///   ANY namespace (an ambiguous bare name checks every namespace it
///   resolves to).
/// - **Refine**: if the registry records a comparable upstream source (a git
///   provenance URL or an OCI provenance `source_url`, across every version
///   of every owning package) that matches the claim's own normalized
///   source — silent accept (a legitimate pin of the registry's own
///   repository).
/// - Otherwise (the URL disagrees, or NOTHING comparable is recorded) —
///   this is a silent name-shadow: warn by default, hard-fail under
///   `attestation-policy strict`.
///
/// Deliberately does NOT reconcile via post-fetch `content_hash` comparison
/// — this is a STATIC, pre-fetch, URL-only check.
///
/// Never mutates `BindingResolver` state and never touches its own
/// multi-claim arbitration (`RES-BINDING-CONFLICT` governs disagreements
/// between two EXPLICIT claims independently of this check).
pub fn check_registry_shadow(claim: &Claim, index: &Index, is_strict: bool) -> Result<(), MilpaError> {
    let sid = &claim.source_id;
    let is_fetchable_self_source = matches!(
        sid,
        SourceId::Fetchable(FetchableOrigin::Git { .. })
            | SourceId::Fetchable(FetchableOrigin::Tarball { .. })
            | SourceId::Fetchable(FetchableOrigin::Oci { .. })
    );
    if !is_fetchable_self_source {
        return Ok(()); // not a fetchable self-declared-source claim — nothing to shadow-check
    }

    let bare_name = DepKey::from_solver_var(&claim.name).name;
    let mut packages: Vec<Package> = Vec::new();
    match index.lookup_bare(&bare_name) {
        BareLookup::Found(pkg) => packages.push(pkg),
        BareLookup::Ambiguous(namespaces) => {
            for ns in &namespaces {
                if let Some(pkg) = index.lookup_qualified(ns, &bare_name) {
                    packages.push(pkg);
                }
            }
        }
        BareLookup::NotFound => {}
    }
    if packages.is_empty() {
        return Ok(()); // the name is not registry-owned at all — an ordinary self-source
    }

    let claim_url: Option<&str> = match sid {
        SourceId::Fetchable(FetchableOrigin::Git { url, .. }) => Some(url.as_str()),
        SourceId::Fetchable(FetchableOrigin::Tarball { url, .. }) => Some(url.as_str()),
        _ => None,
    };
    if let Some(url) = claim_url {
        let claim_norm = normalize_git_url(url);
        for pkg in &packages {
            for iv in &pkg.versions {
                for prov in &iv.provenances {
                    let upstream: Option<&str> = match prov {
                        Provenance::Git { url, .. } => Some(url.as_str()),
                        Provenance::Oci { source_url: Some(u), .. } if !u.is_empty() => Some(u.as_str()),
                        _ => None,
                    };
                    if let Some(u) = upstream {
                        if normalize_git_url(u) == claim_norm {
                            return Ok(()); // legitimate same-repository pin — silent accept
                        }
                    }
                }
            }
        }
    }

    let mut owning: Vec<String> = packages
        .iter()
        .map(|pkg| {
            if pkg.namespace.is_empty() {
                pkg.name.clone()
            } else {
                format!("{}/{}", pkg.namespace, pkg.name)
            }
        })
        .collect();
    owning.sort();

    let message = format!(
        "{} shares the name {bare_name:?} with a tianguis registry package ({owning:?}), but its \
         source does not match any upstream URL the registry records for it — this could be a \
         legitimate fork, or a dependency-confusion attempt. Pin it explicitly at the root \
         (deps/overrides) to silence this warning.",
        format_source_id(sid),
    );
    if is_strict {
        return Err(MilpaError::Core(CoreError::Resolver("RES-REGISTRY-SHADOW", message)));
    }
    eprintln!("[milpa] warning: {message}");
    Ok(())
}

#[cfg(test)]
#[path = "binding_tests.rs"]
mod binding_tests;
