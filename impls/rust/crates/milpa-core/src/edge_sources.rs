//! EdgeSource seam (RFC `spec/dep-decl.md §4.2.1`).
//!
//! Implements the priority-ordered edge-sourcing decision that the resolver
//! delegates to when extracting transitive requires from a fetched dep.
//! Three sources:
//!
//! - `NimbleEdgeSource` — parses a `.nimble` file (heuristic fallback).
//! - `MilpaKdlEdgeSource` — parses a `milpa.kdl` manifest with the normative
//!   transitive projection (§9 + §10.2): only `manifest.deps`, never
//!   `dev_deps`, drops `overrides` entirely.
//! - `DepDeclEdgeSource` — S3b; wired from the resolver via `DepDeclStore`
//!   (see `resolver.rs` L1200+ and `milpa-cli/src/main.rs` `maybe_dep_decl_store`).
//!
//! `resolve_edges` is the coordinator: it implements the §4.2.1 normative
//! priority structure with an `edge_cache` memo keyed on `(source_id, version)`
//! (RFC origin-as-identity §4.5, S4 — re-keyed from `(name, version)` so two
//! consumer labels for one origin coalesce to one sealed EdgeSet).
//! Clause (a): sealed once per key — parent-independent (diamond deps get
//! identical `EdgeSet`). Clause (b): `is_overridden` suppresses DepDecl.
//! Clause (c): `dep_decl + dep_decl_source` → DepDecl [S3b]. Clause (d):
//! `has_milpa_kdl` → MilpaKdl. Else → NimbleFallback.
//!
//! `edgeset_to_terms` converts an `EdgeSet` → the solver-facing
//! `(Vec<SolverDep>, Vec<String>, Vec<Item>)` triple (mirrors `Extracted`
//! without `src_dir`, which flows through `EdgeSet.src_dir` directly).
//!
//! Mirrors `milpa/edge_sources.py` in `impls/python`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use milpa_manifest::nimble::{parse_nimble, NimbleRequirement};
use milpa_manifest::{contains_unsafe_char, Dep, Manifest, ManifestError, Override};
use milpa_solver::{Dep as SolverDep, VersionSet, VersionSource};
use milpa_types::{EdgeSet, EdgeSource, NamedRequire, RequireEntry, SourceId, UrlRequire, Version};


// Re-export Item from resolver scope — we import locally within the functions
// that produce sub-items (private to this module; the caller also imports Item).

// ---------------------------------------------------------------------------
// Flag-predicate helpers (SSOT — also used by resolver.rs for root/fixpoint)
// ---------------------------------------------------------------------------

/// Returns `true` when `dep` passes all flag-axis predicates given `active`.
///
/// Only evaluates `"flag"` predicates; platform/arch predicates are ignored
/// here (they are evaluated at root-manifest parse time, not in the transitive
/// EdgeSet). A dep with no flag predicates always passes.
///
/// This is the single implementation of flag-predicate admission logic — it is
/// imported by `resolver.rs` rather than re-implemented there.
pub(crate) fn dep_passes_flag_predicates(dep: &Dep, active: &BTreeSet<&str>) -> bool {
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

/// Build an `EdgeSet` from a manifest with flag-predicate filtering (§6 transitive).
///
/// Merges the manifest's own default-active flags with `active_flags` from the
/// consumer's flag requests (S3 single-hop activation). Only `manifest.deps` is
/// included — `dev_deps` excluded (§9) and `overrides` dropped (§10.2).
/// Carries `flag_requests` from URL dep entries so callers can reconstruct
/// `Item::Url.flag_requests` for multi-consumer union (S4b).
///
/// Pass `&BTreeSet::new()` for `active_flags` on transitive hops (single-hop
/// scope): only the manifest's own defaults activate flags then.
///
/// This is the SSOT for "EdgeSet from milpa.kdl with flag filtering". Both
/// `MilpaKdlEdgeSource` and `Provider::extract_requires` use this function;
/// `manifest_to_edgeset` (pure normative projection, no flag filtering) is kept
/// separately for unit tests and callers that do not need flag filtering.
pub fn build_edgeset_with_flags(manifest: &Manifest, active_flags: &BTreeSet<String>) -> EdgeSet {
    // Merge manifest's own default-active flags with consumer requests.
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
    for dep in &manifest.deps {
        if !dep_passes_flag_predicates(dep, &active) {
            continue;
        }
        match dep {
            Dep::Url(u) => {
                // S4b: carry flag_requests so the caller can reconstruct Item::Url.flag_requests
                // for multi-consumer union (§3.1.3). FlagRequest is the SSOT (milpa-types).
                //
                // Carry the DECLARED KDL node name (`u.name`) so the parent's
                // solver term / BFS enqueue / provenance-gate key all agree with
                // this name even when it differs from the URL's tail (the
                // alias-name bug — spec §10.1 override-a-transitive workflow).
                requires.push(RequireEntry::Url(UrlRequire {
                    url: u.git.clone(),
                    ref_: u.git_ref.clone(),
                    predicates: Vec::new(),
                    flag_requests: u.flag_requests.clone(),
                    name: Some(u.name.clone()),
                }));
            }
            Dep::Named(n) => {
                if n.name == "nim" {
                    continue;
                }
                // H2: carry namespace from manifest NamedDep into NamedRequire so
                // transitive qualified deps preserve their namespace through the EdgeSet.
                requires.push(RequireEntry::Named(NamedRequire {
                    name: n.name.clone(),
                    constraint_str: n.constraint.clone().unwrap_or_default(),
                    predicates: Vec::new(),
                    namespace: n.namespace.clone(),
                }));
            }
            // Local/Tarball/Member from a transitive milpa.kdl are out of scope.
            Dep::Local(_) | Dep::Tarball(_) | Dep::Member(_) => {}
        }
    }
    // §10.2: manifest.overrides dropped entirely.
    EdgeSet {
        requires,
        src_dir: manifest.src_dir.clone(),
        source: EdgeSource::MilpaKdl,
    }
}

// ---------------------------------------------------------------------------
// Context carrier
// ---------------------------------------------------------------------------

/// Per-package context for the edge-sourcing decision (§4.2.1 coordinator).
///
/// Constructed once per `(name, version)` before calling `resolve_edges`.
pub struct EdgeSourceCtx<'a> {
    /// Fetched dep root on disk (the `_deps/<name>/` directory). `None` only for
    /// synthetic packages that have no on-disk presence.
    pub dep_path: Option<&'a Path>,
    /// Package name (used for `.nimble` filename heuristic).
    pub dep_name: &'a str,
    /// Raw `dep_decl` string from the index entry. `None` when absent or when
    /// the dep was not index-resolved.
    pub dep_decl: Option<&'a str>,
    /// True when this dep was redirected via an override in the root manifest.
    /// In that case, the original DepDecl (if any) describes a different source
    /// tree and MUST NOT be used (§4.2.1 clause b).
    pub is_overridden: bool,
    /// True when a `milpa.kdl` was found in `dep_path` at pre-flight time.
    /// Set before calling `resolve_edges` to avoid redundant filesystem probing.
    pub has_milpa_kdl: bool,
    /// The `dep_decl_schema_version` integer from the index entry. `None` when
    /// absent. Used by `DepDeclEdgeSource` for the schema-consistency check
    /// (spec §5 S3b): the index pointer's schema version MUST match the
    /// artifact's embedded version (`TNG-DEPDECL-SCHEMA-MISMATCH`).
    pub dep_decl_schema_version: Option<i64>,
    /// Overrides map from the root manifest (used to detect when a transitive
    /// named dep is itself overridden, so it enters as an eq_sentinel).
    pub overrides_by_name: &'a BTreeMap<String, Override>,
    /// S3 RFC #23: flags requested by the consumer's dep declaration (single-hop
    /// activation). Merged with the dep's own defaults by `build_edgeset_from_manifest`
    /// before filtering. Empty for transitive hops (S4a multi-hop is separate).
    pub active_flags: BTreeSet<String>,
    /// The dep declaration's git ref (branch/tag/SHA), or `None`. Only ever
    /// populated by `process_url` (§3 Axis A (b) step 3 — A3); local/tarball/
    /// named/member deps have no ref and always leave this `None`. Consumed
    /// solely by `declared_version_for`'s step-3 tag fallback.
    pub ref_: Option<&'a str>,
    /// The dep declaration's own `version=` annotation (§3 Axis A (b) step 4
    /// — A3b), or `None`. Populated by `process_url`/`process_local`/
    /// `process_tarball` from `UrlDep.version`/`LocalDep.version`/
    /// `TarballDep.version` — for an override-redirected dep this is the
    /// OVERRIDE RULE's `version=` (D-A3: the redirect discards the original
    /// declaration entirely and builds a fresh dep from the override target,
    /// so a stale annotation on the now-redirected original is never read).
    /// Named/member deps never populate this (out of A3b's grammar scope).
    /// Consumed solely by `declared_version_for`'s step-4 fallback.
    pub version: Option<Version>,
}

// ---------------------------------------------------------------------------
// Source implementations
// ---------------------------------------------------------------------------

/// Produces an `EdgeSet` by parsing a `.nimble` file in `ctx.dep_path`.
///
/// If no `.nimble` file is found or the dep_path is absent, returns an empty
/// `EdgeSet` (graceful fallback — nimble is the last-resort source).
pub struct NimbleEdgeSource;

impl NimbleEdgeSource {
    /// Parse the `.nimble` file at `ctx.dep_path` and return the `EdgeSet`.
    ///
    /// Returns `Ok(empty)` when no `.nimble` is found (graceful fallback).
    /// Returns `Err(ManifestError)` when the nimble-sourced `srcDir` contains
    /// an unsafe character (MAN-SRC-DIR-UNSAFE) -- the same check applied to
    /// milpa.kdl `src_dir` at parse time (SSOT: `milpa_manifest::contains_unsafe_char`).
    pub fn edges_for(
        &self,
        _name: &str,
        _version: &Version,
        ctx: &EdgeSourceCtx,
    ) -> Result<EdgeSet, ManifestError> {
        let Some(dep_path) = ctx.dep_path else {
            return Ok(empty_nimble());
        };
        let Some(nimble_path) = find_nimble(dep_path, ctx.dep_name) else {
            return Ok(empty_nimble());
        };
        let text = match std::fs::read_to_string(&nimble_path) {
            Ok(t) => t,
            Err(_) => return Ok(empty_nimble()),
        };
        let nm = parse_nimble(&text);

        // Security: validate src_dir at the earliest boundary where nimble-sourced
        // values are materialized -- mirrors the milpa.kdl parse path.
        // `contains_unsafe_char` is the SSOT predicate (milpa_manifest::lib.rs).
        let src_dir = nm.src_dir.unwrap_or_default();
        if !src_dir.is_empty() && contains_unsafe_char(&src_dir) {
            return Err(ManifestError::new(
                "MAN-SRC-DIR-UNSAFE",
                format!(
                    "dep {:?}: 'srcDir' value {:?} from .nimble contains a control character                      or Unicode line separator (U+2028/U+2029) -- possible nim.cfg injection attack",
                    ctx.dep_name, src_dir
                ),
            ));
        }

        let mut requires = Vec::new();
        for req in &nm.requires {
            match req {
                NimbleRequirement::Url { url, ref_spec, predicates, .. } => {
                    // §7.2 normative: bare URL with no `#ref` defaults to HEAD
                    // (the remote's default branch), matching nimble's behavior.
                    let ref_ = ref_spec.clone().unwrap_or_else(|| "HEAD".to_string());
                    requires.push(RequireEntry::Url(UrlRequire {
                        url: url.clone(),
                        ref_,
                        predicates: predicates.clone(),
                        flag_requests: Vec::new(),
                        // Nimble `requires` lines carry only a URL, no separate
                        // declared node name — always fall back to the URL-tail
                        // derivation downstream (matches Python: nimble-sourced
                        // UrlDep.name is itself URL-derived, so leaving this
                        // None and falling back yields an identical result).
                        name: None,
                    }));
                }
                NimbleRequirement::Named { name, constraint, predicates, .. } => {
                    if name == "nim" {
                        continue;
                    }
                    // Nimble sources have no namespace concept; keep None.
                    requires.push(RequireEntry::Named(NamedRequire {
                        name: name.clone(),
                        constraint_str: constraint.clone().unwrap_or_default(),
                        predicates: predicates.clone(),
                        namespace: None,
                    }));
                }
            }
        }
        Ok(EdgeSet {
            requires,
            src_dir,
            source: EdgeSource::NimbleFallback,
        })
    }
}

fn empty_nimble() -> EdgeSet {
    EdgeSet {
        requires: Vec::new(),
        src_dir: String::new(),
        source: EdgeSource::NimbleFallback,
    }
}

/// Produces an `EdgeSet` by parsing `dep_path/milpa.kdl` with the normative
/// transitive projection (§9 + §10.2):
///
/// - Reads ONLY `manifest.deps` — **never** `dev_deps` (§9 transitive guard).
/// - Drops `manifest.overrides` entirely (§10.2 normative).
/// - Maps `manifest.src_dir` → `EdgeSet.src_dir`.
///
/// On any I/O or parse error, returns an empty `EdgeSet` non-fatally and lets
/// the caller fall through to the nimble heuristic if desired.
pub struct MilpaKdlEdgeSource;

impl MilpaKdlEdgeSource {
    /// Parse `dep_path/milpa.kdl` and return an `EdgeSet` with flag-predicate
    /// filtering applied (§6 transitive, §9, §10.2).
    ///
    /// Uses `ctx.active_flags` (S3 single-hop consumer requests) merged with the
    /// manifest's own default-active flags via `build_edgeset_with_flags`.
    /// This is the SSOT milpa.kdl edge source — delegates to `build_edgeset_with_flags`
    /// which carries `flag_requests` and applies dep-level flag filtering.
    pub fn edges_for(&self, _name: &str, _version: &Version, ctx: &EdgeSourceCtx) -> EdgeSet {
        let Some(dep_path) = ctx.dep_path else {
            return empty_milpa_kdl();
        };
        let kdl_path = dep_path.join("milpa.kdl");
        let text = match std::fs::read_to_string(&kdl_path) {
            Ok(t) => t,
            Err(_) => return empty_milpa_kdl(),
        };
        let manifest = match milpa_manifest::parse_manifest(&text) {
            Ok(m) => m,
            Err(_) => return empty_milpa_kdl(),
        };
        // Apply flag filtering via ctx.active_flags (S3 single-hop) + manifest defaults.
        build_edgeset_with_flags(&manifest, &ctx.active_flags)
    }
}

fn empty_milpa_kdl() -> EdgeSet {
    EdgeSet {
        requires: Vec::new(),
        src_dir: String::new(),
        source: EdgeSource::MilpaKdl,
    }
}

/// Axis A (b) precedence steps 1-4 (resolution-semantics RFC §3 Axis A): the
/// fetched package's own declared version, source-agnostic.
///
/// Precedence (steps 1-4):
///
/// 1. the fetched package's `milpa.kdl` `version` field (A1's manifest parse) —
///    `VersionSource::Manifest`;
/// 2. else its `.nimble` `version` (A1's nimble scanner) — `VersionSource::Nimble`;
/// 3. else, **git deps only** (`ctx.ref_` populated), a version-shaped git ref
///    tag (`v?X.Y.Z`) — parsed via the same `parse_version` used everywhere
///    else (A3) — `VersionSource::Tag`;
/// 4. else, the dep declaration's own `version=` annotation (`ctx.version`,
///    A3b) — the user-supplied escape hatch for when the fetched artifact
///    (steps 1-2) and its ref (step 3) yield no version. Steps 1-3 WIN over
///    the annotation when present — `VersionSource::Annotation`.
///
/// Reads the SAME on-disk files `MilpaKdlEdgeSource`/`NimbleEdgeSource` already
/// parse for requires, but for a different question — hence a peer function,
/// not a shared field. Non-fatal on any read/parse failure or absence: falls
/// through to the next step, ultimately `None` (version-unknown; A2 keeps the
/// sentinel label for that case — the constrained/unconstrained partition +
/// hard error is A4, out of scope here).
///
/// Only meaningful for git/url/local/tarball deps. Named/index deps get their
/// real version from the index directly and never call this.
///
/// Returns `(version, source)` as one pair — never merged into a sum type at
/// the STORAGE boundary (A5, §3 Axis A: value and source stay two sibling
/// fields on the candidate/lockfile record); paired here only so a single
/// `declared_version_for` call yields both facts without a second,
/// potentially file-re-reading, lookup (mirrors `candidate_label`'s existing
/// `(label, version_unknown)` pairing).
///
/// Mirrors `milpa/edge_sources.py`'s `declared_version_for`.
pub fn declared_version_for(ctx: &EdgeSourceCtx) -> Option<(Version, VersionSource)> {
    if let Some(dep_path) = ctx.dep_path {
        if ctx.has_milpa_kdl {
            let kdl_path = dep_path.join("milpa.kdl");
            if let Ok(text) = std::fs::read_to_string(&kdl_path) {
                if let Ok(manifest) = milpa_manifest::parse_manifest(&text) {
                    if let Some(v) = manifest.version {
                        return Some((v, VersionSource::Manifest));
                    }
                }
            }
        }

        if let Some(nimble_path) = find_nimble(dep_path, ctx.dep_name) {
            if let Ok(text) = std::fs::read_to_string(&nimble_path) {
                let nm = parse_nimble(&text);
                if let Some(v) = nm.version {
                    return Some((v, VersionSource::Nimble));
                }
            }
        }
    }

    // Step 3 (A3): git tag-derived fallback. `ctx.ref_` is populated only by
    // `process_url` — local/tarball/named/member contexts leave it `None`, so
    // this step is a no-op for them. A branch name, bare SHA, or `main` simply
    // fails `parse_version`'s strict semver grammar and falls through to
    // version-unknown (A4, out of scope) — no separate "is this a tag" check
    // is needed beyond the version shape itself.
    if let Some(r) = ctx.ref_ {
        if let Some(v) = milpa_solver::parse_version(r) {
            return Some((v, VersionSource::Tag));
        }
    }

    // Step 4 (A3b): the dep declaration's `version=` annotation. Only reached
    // when steps 1-3 all missed — steps 1-3 WIN over the annotation when
    // present (this is a gap-filler, not an override).
    if let Some(v) = &ctx.version {
        return Some((v.clone(), VersionSource::Annotation));
    }

    None
}

/// Normative transitive projection (§9 + §10.2): reads ONLY `manifest.deps`,
/// drops `dev_deps` and `overrides` entirely, maps `src_dir`.
///
/// This is the SSOT for the "what a transitive dep contributes to the solver"
/// rule — it must never read `manifest.dev_deps` or `manifest.overrides`.
pub fn manifest_to_edgeset(manifest: &Manifest) -> EdgeSet {
    let mut requires = Vec::new();
    for dep in &manifest.deps {
        // NORMATIVE §9: only manifest.deps; dev_deps excluded
        match dep {
            Dep::Url(u) => {
                requires.push(RequireEntry::Url(UrlRequire {
                    url: u.git.clone(),
                    ref_: u.git_ref.clone(),
                    predicates: Vec::new(),
                    flag_requests: Vec::new(),
                    name: Some(u.name.clone()),
                }));
            }
            Dep::Named(n) => {
                if n.name == "nim" {
                    continue;
                }
                // H2: carry namespace from manifest NamedDep so transitive
                // qualified deps preserve their namespace through the EdgeSet.
                requires.push(RequireEntry::Named(NamedRequire {
                    name: n.name.clone(),
                    constraint_str: n.constraint.clone().unwrap_or_default(),
                    predicates: Vec::new(),
                    namespace: n.namespace.clone(),
                }));
            }
            // Local/Tarball/Member from a transitive milpa.kdl are out of
            // scope (§9 transitive projection — only URL + Named).
            Dep::Local(_) | Dep::Tarball(_) | Dep::Member(_) => {}
        }
    }
    // NORMATIVE §10.2: manifest.overrides dropped entirely.
    EdgeSet {
        requires,
        src_dir: manifest.src_dir.clone(),
        source: EdgeSource::MilpaKdl,
    }
}

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

/// Priority-ordered edge-sourcing coordinator (§4.2.1).
///
/// Implements the three clauses:
/// - Clause (a): `edge_cache` memo seal — parent-independent.
/// - Clause (b): `is_overridden` → skip DepDecl, fall through to milpa.kdl / nimble.
/// - Clause (c): `dep_decl + dep_decl_source` → DepDecl [S3b].
/// - Clause (d): `has_milpa_kdl` → MilpaKdl; else → NimbleFallback.
///
/// The `edge_cache` is a `HashMap<(SourceId, Version), EdgeSet>` owned by the
/// caller's `ResolveProvider`; this function receives a mutable reference so
/// the caller remains the sealing authority.
///
/// RFC origin-as-identity §4.5 (S4): keyed by `(source_id, version)`, not
/// `(name, version)` — two BFS parents reaching the SAME origin under TWO
/// different labels (e.g. `z3` vs `nimz3` for one repo) must coalesce to ONE
/// sealed EdgeSet, not two (the pre-S4 latent "missed unification" bug,
/// RFC §2.1). `name`/`version` still drive clauses (b)(c)(d) — filesystem
/// lookups, `EdgeSourceCtx.dep_name`, etc. — only the CACHE dimension moved
/// to `source_id`, which the caller obtains from `BindingResolver::source_id_for`.
pub fn resolve_edges<'cache>(
    name: &str,
    version: &Version,
    ctx: &EdgeSourceCtx,
    edge_cache: &'cache mut HashMap<(SourceId, Version), EdgeSet>,
    source_id: &SourceId,
    nimble_source: Option<&NimbleEdgeSource>,
    milpakdl_source: Option<&MilpaKdlEdgeSource>,
    // dep_decl_source: S3b injection point (wired from DepDeclStore in resolver.rs L1200+).
    dep_decl_source: Option<&dyn DepDeclSource>,
) -> Result<&'cache EdgeSet, crate::MilpaError> {
    let cache_key = (source_id.clone(), version.clone());
    // Clause (a): sealed once per (source_id, version) — parent-independent
    if edge_cache.contains_key(&cache_key) {
        return Ok(&edge_cache[&cache_key]);
    }

    let default_nimble = NimbleEdgeSource;
    let default_milpa = MilpaKdlEdgeSource;
    let nimble = nimble_source.unwrap_or(&default_nimble);
    let milpa = milpakdl_source.unwrap_or(&default_milpa);

    let es = if ctx.is_overridden {
        // Clause (b): is_overridden → original DepDecl invalid; use milpa.kdl or nimble
        if ctx.has_milpa_kdl {
            milpa.edges_for(name, version, ctx)
        } else {
            nimble.edges_for(name, version, ctx)?
        }
    } else if ctx.dep_decl.is_some() {
        if let Some(dds) = dep_decl_source {
            // Clause (c): dep_decl + dep_decl_source → DepDecl [S3b].
            // `DepDeclSource::edges_for` returns Result<EdgeSet, MilpaError>:
            // implementors handle the soft `TNG-DEPDECL-FETCH-FAILED` policy
            // internally; hard integrity failures propagate here.
            dds.edges_for(name, version, ctx)?
        } else {
            // dep_decl_source=None (compat path): fall through to milpa.kdl / nimble
            if ctx.has_milpa_kdl {
                milpa.edges_for(name, version, ctx)
            } else {
                nimble.edges_for(name, version, ctx)?
            }
        }
    } else if ctx.has_milpa_kdl {
        // Clause (d): milpa.kdl present
        milpa.edges_for(name, version, ctx)
    } else {
        nimble.edges_for(name, version, ctx)?
    };

    edge_cache.insert(cache_key.clone(), es);
    Ok(&edge_cache[&cache_key])
}

// ---------------------------------------------------------------------------
// S3b injection-point trait + DepDeclEdgeSource implementation
// ---------------------------------------------------------------------------

/// S3b injection-point trait. Implementors parse a pre-fetched DepDecl
/// artifact and return an `EdgeSet`. The trait is structurally present so
/// S3b can inject without changing the coordinator's signature.
///
/// Returns `Result<EdgeSet, MilpaError>` so that integrity failures
/// (`HASH-MISMATCH`, `PARSE-ERROR`, `SCHEMA-MISMATCH`, `SCHEMA-UNSUPPORTED`)
/// can be propagated as hard errors through `resolve_edges`.
/// `TNG-DEPDECL-FETCH-FAILED` (soft, policy-gated) should be handled by the
/// implementor before returning; see `PolicyDepDeclSource` in `resolver.rs`.
pub trait DepDeclSource {
    fn edges_for(
        &self,
        name: &str,
        version: &Version,
        ctx: &EdgeSourceCtx,
    ) -> Result<EdgeSet, crate::MilpaError>;
}

/// S3b: DepDecl-backed edge source. Wraps a `DepDeclStore` and implements
/// the hash-verify → parse → schema-check pipeline.
///
/// SECURITY: integrity failures (`HASH-MISMATCH`, `PARSE-ERROR`,
/// `SCHEMA-MISMATCH`, `SCHEMA-UNSUPPORTED`) are ALWAYS hard errors — no
/// silent fallback to MilpaKdl/Nimble. Only `FETCH-FAILED` (unreachable)
/// is subject to strict/non-strict policy (S5).
///
/// Note: `edges_for` returns `EdgeSet` (not `Result`). To surface errors,
/// the conformance adapter catches them before they disappear into the
/// `DepDeclSource` trait. Use `edges_for_result` for the error-propagating path.
pub struct DepDeclEdgeSource<'a> {
    store: &'a dyn crate::dep_decl_store::DepDeclStore,
}

impl<'a> DepDeclEdgeSource<'a> {
    /// Create a new `DepDeclEdgeSource` backed by `store`.
    pub fn new(store: &'a dyn crate::dep_decl_store::DepDeclStore) -> Self {
        DepDeclEdgeSource { store }
    }

    /// Fetch, verify, parse, and schema-check a DepDecl artifact.
    ///
    /// Returns `Err(MilpaError)` on any integrity failure (HASH-MISMATCH,
    /// PARSE-ERROR, SCHEMA-MISMATCH, SCHEMA-UNSUPPORTED).
    pub fn edges_for_result(
        &self,
        name: &str,
        ctx: &EdgeSourceCtx,
    ) -> Result<EdgeSet, crate::MilpaError> {
        use crate::dep_decl::{parse_dep_decl, MAX_DEP_DECL_SCHEMA_VERSION};
        use crate::error::CoreError;
        use crate::MilpaError;

        let dep_decl_hash_str = ctx.dep_decl.expect("DepDeclEdgeSource requires ctx.dep_decl");

        // Step 1: fetch + hash-verify (SECURITY: store.get() is the ONE verify site).
        let artifact_bytes = self.store.get(dep_decl_hash_str)?;

        // Step 2: parse → (EdgeSet, schema_version) from the KDL DOM.
        // parse_dep_decl returns the schema_version extracted from the DOM node —
        // NOT from a secondary text-scan.  This is the SSOT fix for R3.
        let (es, artifact_schema_version) = parse_dep_decl(&artifact_bytes)?;

        // Step 3: check (i) — artifact schema version MUST NOT exceed impl cap.
        // Overflow safety: parse_dep_decl uses i64::try_from(i128).unwrap_or(i64::MAX),
        // so an out-of-range value becomes i64::MAX > MAX_DEP_DECL_SCHEMA_VERSION=0.
        if artifact_schema_version > MAX_DEP_DECL_SCHEMA_VERSION {
            return Err(MilpaError::Core(CoreError::DepDecl(
                "TNG-DEPDECL-SCHEMA-UNSUPPORTED",
                format!(
                    "DepDecl artifact for {name:?} declares dep_decl_schema_version \
                     {artifact_schema_version}, but this milpa only understands up to \
                     {MAX_DEP_DECL_SCHEMA_VERSION} — upgrade milpa to read this artifact"
                ),
            )));
        }

        // Step 4: check (ii) — artifact schema version MUST match index pointer version.
        if let Some(index_ver) = ctx.dep_decl_schema_version {
            if artifact_schema_version != index_ver {
                return Err(MilpaError::Core(CoreError::DepDecl(
                    "TNG-DEPDECL-SCHEMA-MISMATCH",
                    format!(
                        "DepDecl artifact for {name:?} embeds dep_decl_schema_version \
                         {artifact_schema_version}, but the index pointer says \
                         {index_ver} — the artifact and index are out of sync"
                    ),
                )));
            }
        }

        Ok(es)
    }
}

// ---------------------------------------------------------------------------
// EdgeSet → solver terms converter
// ---------------------------------------------------------------------------

/// Convert an `EdgeSet` into the solver-facing triple:
/// `(Vec<SolverDep>, Vec<String>, Vec<SubItem>)`.
///
/// The caller supplies `overrides_by_name` so that a named transitive dep that
/// is itself overridden is detected (S8).
///
/// Axis A (a) (resolution-semantics RFC §3, D-A2): a URL require's own term —
/// and an overridden named require's term — is always `VersionSet::full()`,
/// never `eq(sentinel)`.  Such a dep has exactly one real candidate
/// (materialised elsewhere), so `full()` is harmless and fixes the causality
/// hole of a pre-fetch term racing the post-fetch candidate label (which now
/// carries the real declared version when one is parseable —
/// `declared_version_for`).  There is therefore no longer a "sentinel version"
/// parameter here; the self-term does not need one.
///
/// Returns `(deps, requires_names, sub_items)`. `sub_items` are the `Item`
/// variants that must be enqueued for BFS processing.
pub fn edgeset_to_terms(
    es: &EdgeSet,
    overrides_by_name: &BTreeMap<String, Override>,
) -> EdgeSetTerms {
    let mut deps: Vec<SolverDep> = Vec::new();
    let mut requires_names: Vec<String> = Vec::new();
    let mut url_requires: Vec<(String, String)> = Vec::new(); // (url, ref_)
    let mut named_requires: Vec<(String, VersionSet)> = Vec::new(); // (name, vs)
    // S4 (C1 fix): maps dep-name → ALL predicate-vecs collected across ALL occurrences.
    // A dep appearing in ≥2 `when` branches yields ≥2 entries in the inner Vec,
    // each carrying that branch's own predicate set.  One CondRequire is emitted
    // per inner entry (§3.5, lockfile-schema.md).  Using `.entry().or_default().push()`
    // instead of `.insert()` so same-name occurrences accumulate rather than overwrite.
    let mut requires_predicates: std::collections::BTreeMap<String, Vec<Vec<milpa_types::Predicate>>> =
        std::collections::BTreeMap::new();
    // Track names already added to deps/requires_names to avoid solver duplicates
    // (the solver needs each dep name exactly once as a Term).  Dedup is correct
    // HERE (resolved dep set); the raw scanner (nimble.py/nimble.rs) no longer dedupes.
    let mut seen_dep_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for entry in &es.requires {
        match entry {
            RequireEntry::Url(u) => {
                // Prefer the DECLARED node name (milpa.kdl/nimble source) over the
                // URL-tail derivation — mirrors Python's `edgeset_to_terms`. This is
                // the alias-name fix: a transitive milpa.kdl may declare a git
                // sub-dep under a node name that differs from its URL's tail, and
                // that declared name must be what the parent's solver term / BFS
                // enqueue / gate key all agree on. Only DepDecl-sourced entries
                // (name=None) fall back to the URL-tail derivation.
                let name = match &u.name {
                    Some(n) => n.clone(),
                    None => match url_tail_name(&u.url) {
                        Some(n) => n,
                        None => continue, // malformed URL; skip silently (resolver handles error paths)
                    },
                };
                // Dedup the SOLVER TERM only (one Term per name).
                // Axis A (a)/D-A2: full() self-term, never eq(sentinel).
                if !seen_dep_names.contains(&name) {
                    deps.push(SolverDep::new(name.clone(), VersionSet::full()));
                    requires_names.push(name.clone());
                    seen_dep_names.insert(name.clone());
                }
                // ALWAYS record the url_require so the caller reconstructs an
                // Item::Url per distinct provenance — two URLs stripping to the
                // same name must both reach the provenance gate downstream
                // (RES-PROVENANCE-CONFLICT). Mirrors edgeset_to_extracted; the
                // gate (not this dedup) decides suppress-vs-conflict.
                url_requires.push((u.url.clone(), u.ref_.clone()));
                // S4: record predicates if non-empty (accumulate, do not overwrite).
                if !u.predicates.is_empty() {
                    requires_predicates.entry(name).or_default().push(u.predicates.clone());
                }
            }
            RequireEntry::Named(n) => {
                if !seen_dep_names.contains(&n.name) {
                    let vs = if overrides_by_name.contains_key(&n.name) {
                        // Overridden named dep → URL-like full() self-term (D-A2).
                        VersionSet::full()
                    } else {
                        // Constraint already validated at parse boundary; re-parse here
                        // is safe (the string came from a correctly-parsed manifest).
                        // Map parse errors to full (any) to avoid silent drops — a
                        // malformed constraint is already caught at manifest parse time.
                        VersionSet::from_constraint(Some(&n.constraint_str))
                            .unwrap_or_else(|_| VersionSet::full())
                    };
                    deps.push(SolverDep::new(n.name.clone(), vs.clone()));
                    requires_names.push(n.name.clone());
                    named_requires.push((n.name.clone(), vs));
                    seen_dep_names.insert(n.name.clone());
                }
                // S4: record predicates if non-empty (accumulate, do not overwrite).
                if !n.predicates.is_empty() {
                    requires_predicates.entry(n.name.clone()).or_default().push(n.predicates.clone());
                }
            }
        }
    }

    EdgeSetTerms {
        deps,
        requires_names,
        url_requires,
        named_requires,
        requires_predicates,
    }
}

/// Output of `edgeset_to_terms`. The caller reconstructs `Vec<Item>` from
/// `url_requires` + `named_requires` using the local `Item` type (which is
/// private to `resolver.rs`). We surface the raw data to avoid a circular
/// dependency on the resolver's private types.
pub struct EdgeSetTerms {
    pub deps: Vec<SolverDep>,
    pub requires_names: Vec<String>,
    /// (url, ref_) pairs for URL requires — caller constructs `Item::Url`.
    pub url_requires: Vec<(String, String)>,
    /// (name, vs) pairs for Named requires — caller constructs `Item::Named`.
    pub named_requires: Vec<(String, VersionSet)>,
    /// S4: advisory predicate metadata (RFC cond-requires §3.4.3 option a).
    /// Maps dep-name → ALL predicate-vecs collected across ALL occurrences.
    /// A dep appearing in ≥2 `when` branches yields ≥2 inner `Vec<Predicate>`
    /// entries; each becomes one `CondRequire` in the lockfile (§3.5, C1 fix).
    /// Never consulted for selection/solving — purely for lockfile annotation.
    pub requires_predicates: std::collections::BTreeMap<String, Vec<Vec<milpa_types::Predicate>>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_nimble(dir: &Path, hint: &str) -> Option<std::path::PathBuf> {
    let by_hint = dir.join(format!("{hint}.nimble"));
    if by_hint.is_file() {
        return Some(by_hint);
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut found: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "nimble"))
        .collect();
    found.sort();
    found.into_iter().next()
}

/// Derive a package name from a URL tail (`…/foo.git` → `"foo"`).
/// Returns `None` for malformed URLs (path traversal, empty name).
fn url_tail_name(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');
    let tail = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let name = tail.strip_suffix(".git").unwrap_or(tail);
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return None;
    }
    Some(name.to_string())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::source_id::normalize_source;
    use milpa_types::FetchableOrigin;

    fn make_dep_tree(base: &Path, name: &str, kdl_content: &str) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("milpa.kdl"), kdl_content).unwrap();
        dir
    }

    fn make_nimble_tree(base: &Path, name: &str, nimble_content: &str) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.nimble")), nimble_content).unwrap();
        dir
    }

    fn no_overrides() -> BTreeMap<String, Override> {
        BTreeMap::new()
    }

    fn url_ver() -> Version {
        Version::release(0, 0, 1)
    }

    /// A well-formed, distinct `SourceId` for test package `label` — the
    /// `resolve_edges` cache key dimension since RFC origin-as-identity §4.5
    /// (S4) re-keyed `edge_cache` from `(name, version)` to
    /// `(source_id, version)`. Two DIFFERENT labels only coalesce in
    /// `edge_cache` when the CALLER passes the SAME `source_id` — this
    /// helper makes each test's intent (same origin vs different origin)
    /// explicit at the call site rather than accidental.
    fn sid(label: &str) -> SourceId {
        normalize_source(&SourceId::Fetchable(FetchableOrigin::Git {
            url: format!("https://example.com/{label}.git"),
            git_ref: None,
            subpath: None,
        }))
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // Clause (a): memo seal
    // -----------------------------------------------------------------------

    #[test]
    fn test_clause_a_memo_seal_returns_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(
            tmp.path(),
            "pkg",
            "name \"pkg\"\nsrc_dir \"src\"\nkind \"library\"",
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache: HashMap<(SourceId, Version), EdgeSet> = HashMap::new();
        let pkg_sid = sid("pkg");

        // First call populates cache
        let es1_src = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap().source.clone();
        // Second call returns cached value
        let es2_src = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap().source.clone();
        assert_eq!(es1_src, EdgeSource::MilpaKdl);
        assert_eq!(es2_src, EdgeSource::MilpaKdl);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_clause_a_sealed_value_not_overwritten() {
        // Pre-populate cache; subsequent call must return the cached value,
        // not re-invoke sources.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let version = url_ver();
        let pkg_sid = sid("pkg");
        let mut cache: HashMap<(SourceId, Version), EdgeSet> = HashMap::new();
        // Pre-populate with a NimbleFallback-tagged EdgeSet
        cache.insert(
            (pkg_sid.clone(), version.clone()),
            EdgeSet {
                requires: Vec::new(),
                src_dir: "pre-cached".to_string(),
                source: EdgeSource::NimbleFallback,
            },
        );
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        // Even though has_milpa_kdl=false → nimble path, cache returns pre-populated value.
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        assert_eq!(es.source, EdgeSource::NimbleFallback);
        assert_eq!(es.src_dir, "pre-cached");
    }

    #[test]
    fn test_two_parents_same_source_different_labels_coalesce_edge_cache() {
        // RFC origin-as-identity §4.5 (S4): edge_cache re-keyed to
        // (source_id, Version) — the "missed unification" / latent
        // double-seal bug fix (RFC §2.1).
        //
        // Two BFS parents can reach the SAME upstream repo under TWO
        // DIFFERENT consumer-facing labels (one writes `z3`, another writes
        // `nimz3` for one repo — the exact §2.1 example). Before S4,
        // edge_cache was keyed by (name, version), so this diamond sealed
        // TWO separate EdgeSet entries for one tree — a latent correctness
        // bug. Keyed by (source_id, version), the two labels must coalesce
        // into ONE sealed entry, and the SECOND call must not even
        // re-resolve.
        //
        // Parent B's ctx deliberately points at a NONEXISTENT dep_path: if
        // the cache still keyed by name (the bug), "nimz3" would miss the
        // cache and the pure dispatch would actually run against that
        // (bogus) path, silently falling back to an EMPTY EdgeSet
        // (MilpaKdlEdgeSource treats a missing milpa.kdl as non-fatal) — a
        // DIFFERENT, wrong object from parent A's real, non-empty EdgeSet.
        // So this test fails loudly (requires content) if the double-seal
        // bug regresses, not just a shallow "same key type" check.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(
            tmp.path(),
            "z3",
            "name \"z3\"\ndeps {\n  stew \">= 0.1.0\"\n}\n",
        );
        let overrides = no_overrides();
        let version = url_ver();
        // One real upstream repo, referenced under two different labels —
        // the ALREADY-NORMALIZED, identical source_id both labels resolve
        // to (BindingResolver, not resolve_edges, is what unifies them;
        // resolve_edges just trusts the source_id it's handed).
        let one_repo_sid = sid("nim-z3");

        let mut cache: HashMap<(SourceId, Version), EdgeSet> = HashMap::new();

        // Parent A: consumer wrote `z3` — real fetched tree.
        let ctx_a = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "z3",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let es_a = resolve_edges("z3", &version, &ctx_a, &mut cache, &one_repo_sid, None, None, None)
            .unwrap()
            .clone();

        // Parent B: consumer wrote `nimz3` for the SAME upstream repo (one
        // BFS diamond reaching one repo under two labels) — nonexistent
        // dep_path proves the second call never re-resolves.
        let missing_path = tmp.path().join("does-not-exist");
        let ctx_b = EdgeSourceCtx {
            dep_path: Some(&missing_path),
            dep_name: "nimz3",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let es_b = resolve_edges("nimz3", &version, &ctx_b, &mut cache, &one_repo_sid, None, None, None)
            .unwrap()
            .clone();

        assert_eq!(
            es_a, es_b,
            "two labels for the SAME source must coalesce to ONE sealed EdgeSet \
             (pre-S4 bug: this sealed two separate entries)"
        );
        assert_eq!(cache.len(), 1, "one source, one version → exactly one edge_cache entry");
        let names: Vec<&str> = es_b
            .requires
            .iter()
            .filter_map(|r| match r {
                RequireEntry::Named(n) => Some(n.name.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            names.contains(&"stew"),
            "the coalesced EdgeSet must be parent A's REAL result, not an empty \
             fallback from re-resolving parent B's nonexistent path"
        );

        // Contrast: a genuinely DIFFERENT source at the same version must
        // NOT coalesce — proves the key is actually source_id-driven, not a
        // silent collapse-everything bug.
        let other_dep_path = make_dep_tree(tmp.path(), "other", "name \"other\"\n");
        let other_sid = sid("other");
        let ctx_c = EdgeSourceCtx {
            dep_path: Some(&other_dep_path),
            dep_name: "other",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let es_c = resolve_edges("other", &version, &ctx_c, &mut cache, &other_sid, None, None, None)
            .unwrap()
            .clone();

        assert_ne!(es_c, es_a, "a genuinely different source must NOT coalesce");
        assert_eq!(cache.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Clause (b): is_overridden
    // -----------------------------------------------------------------------

    #[test]
    fn test_clause_b_overridden_with_milpa_kdl_uses_milpa_kdl() {
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(
            tmp.path(),
            "pkg",
            "name \"pkg\"\nsrc_dir \"src\"\nkind \"library\"",
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: Some("some-dep-decl"),
            is_overridden: true,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        assert_eq!(es.source, EdgeSource::MilpaKdl, "overridden+milpa.kdl → MilpaKdl");
    }

    #[test]
    fn test_clause_b_overridden_no_milpa_kdl_uses_nimble() {
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_nimble_tree(
            tmp.path(),
            "pkg",
            r#"requires "nim >= 1.6.0""#,
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: Some("some-dep-decl"),
            is_overridden: true,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        assert_eq!(es.source, EdgeSource::NimbleFallback, "overridden+no milpa.kdl → NimbleFallback");
    }

    // -----------------------------------------------------------------------
    // Clause (c): dep_decl_source=None falls through
    // -----------------------------------------------------------------------

    #[test]
    fn test_clause_c_dep_decl_source_none_falls_through_to_milpa_kdl() {
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(
            tmp.path(),
            "pkg",
            "name \"pkg\"\nsrc_dir \"src\"\nkind \"library\"",
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: Some("present-but-source-is-none"),
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        // dep_decl_source=None → should fall through to milpa.kdl
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        assert_eq!(es.source, EdgeSource::MilpaKdl);
    }

    // -----------------------------------------------------------------------
    // Transitive projection: dev_deps + overrides dropped
    // -----------------------------------------------------------------------

    #[test]
    fn test_milpa_kdl_drops_dev_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(
            tmp.path(),
            "pkg",
            r#"name "pkg"
               src_dir "src"
               kind "library"
               deps {
                   foo git=(url)"https://example.com/foo.git" ref="main"
               }
               dev-deps {
                   devtool git=(url)"https://example.com/devtool.git" ref="main"
               }"#,
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        assert_eq!(es.source, EdgeSource::MilpaKdl);
        // Only foo should appear — devtool must be excluded
        let names: Vec<&str> = es.requires.iter().filter_map(|r| {
            if let RequireEntry::Url(u) = r {
                url_tail_name(&u.url).map(|_| u.url.as_str())
            } else {
                None
            }
        }).collect();
        assert!(names.iter().any(|u| u.contains("foo")), "foo should be present");
        assert!(!names.iter().any(|u| u.contains("devtool")), "devtool must be absent");
    }

    #[test]
    fn test_milpa_kdl_drops_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(
            tmp.path(),
            "pkg",
            "name \"pkg\"\nsrc_dir \"src\"\nkind \"library\"\ndeps {\n    foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n}\noverrides {\n    pkg \"asyncdispatch\" git=(url)\"https://example.com/asyncdispatch.git\" ref=\"patched\"\n}",
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        // overrides must not appear in requires
        let url_names: Vec<String> = es.requires.iter().filter_map(|r| {
            if let RequireEntry::Url(u) = r { url_tail_name(&u.url) } else { None }
        }).collect();
        assert!(!url_names.iter().any(|n| n == "asyncdispatch"), "asyncdispatch override must be absent");
        assert!(url_names.iter().any(|n| n == "foo"), "foo dep must be present");
    }

    #[test]
    fn test_milpa_kdl_maps_src_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(
            tmp.path(),
            "pkg",
            "name \"pkg\"\nsrc_dir \"src\"\nkind \"library\"",
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        assert_eq!(es.src_dir, "src");
    }

    // -----------------------------------------------------------------------
    // manifest_to_edgeset: normative projection
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest_to_edgeset_normative_projection() {
        let kdl = r#"name "pkg"
src_dir "src"
kind "library"
deps {
    foo git=(url)"https://example.com/foo.git" ref="main"
    bar ">= 1.0.0"
}
dev-deps {
    unittest2 git=(url)"https://example.com/unittest2.git" ref="main"
}
overrides {
    pkg "asyncdispatch" git=(url)"https://example.com/asyncdispatch.git" ref="patched"
}"#;
        let manifest = milpa_manifest::parse_manifest(kdl).unwrap();
        let es = manifest_to_edgeset(&manifest);
        assert_eq!(es.source, EdgeSource::MilpaKdl);
        assert_eq!(es.src_dir, "src");
        // deps: foo (url) + bar (named)
        assert_eq!(es.requires.len(), 2);
        let has_foo = es.requires.iter().any(|r| matches!(r, RequireEntry::Url(u) if u.url.contains("foo")));
        let has_bar = es.requires.iter().any(|r| matches!(r, RequireEntry::Named(n) if n.name == "bar"));
        assert!(has_foo, "foo url dep must be present");
        assert!(has_bar, "bar named dep must be present");
        // dev-deps and overrides excluded
        let has_unittest2 = es.requires.iter().any(|r| matches!(r, RequireEntry::Url(u) if u.url.contains("unittest2")));
        assert!(!has_unittest2, "unittest2 dev-dep must be absent");
    }

    // -----------------------------------------------------------------------
    // edgeset_to_terms
    // -----------------------------------------------------------------------

    #[test]
    fn test_edgeset_to_terms_url_require() {
        let es = EdgeSet {
            requires: vec![RequireEntry::Url(UrlRequire {
                url: "https://example.com/foo.git".to_string(),
                ref_: "main".to_string(),
                predicates: Vec::new(),
                flag_requests: Vec::new(),
                name: None,
            })],
            src_dir: String::new(),
            source: EdgeSource::MilpaKdl,
        };
        let terms = edgeset_to_terms(&es, &no_overrides());
        assert_eq!(terms.requires_names, vec!["foo"]);
        assert_eq!(terms.url_requires.len(), 1);
        assert_eq!(terms.named_requires.len(), 0);
    }

    #[test]
    fn test_edgeset_to_terms_named_require() {
        let es = EdgeSet {
            requires: vec![RequireEntry::Named(NamedRequire {
                name: "bar".to_string(),
                constraint_str: ">= 1.0.0".to_string(),
                predicates: Vec::new(),
                namespace: None,
            })],
            src_dir: String::new(),
            source: EdgeSource::MilpaKdl,
        };
        let terms = edgeset_to_terms(&es, &no_overrides());
        assert_eq!(terms.requires_names, vec!["bar"]);
        assert_eq!(terms.named_requires.len(), 1);
        assert_eq!(terms.named_requires[0].0, "bar");
    }

    // C1: same dep name in two when branches — accumulates, does not overwrite.

    fn plat(name: &str) -> milpa_types::Predicate {
        milpa_types::Predicate {
            name: "platform".to_string(),
            values: vec![name.to_string()],
            negated: false,
        }
    }

    #[test]
    fn c1_same_named_dep_two_branches_accumulates_predicates() {
        // Same dep name "foo" in two when-branches (linux vs macosx).
        // requires_predicates["foo"] must have BOTH predicate-vecs, not just last.
        let p_linux = plat("linux");
        let p_mac = plat("macosx");
        let es = EdgeSet {
            requires: vec![
                RequireEntry::Named(NamedRequire {
                    name: "foo".to_string(),
                    constraint_str: String::new(),
                    predicates: vec![p_linux.clone()],
                    namespace: None,
                }),
                RequireEntry::Named(NamedRequire {
                    name: "foo".to_string(),
                    constraint_str: String::new(),
                    predicates: vec![p_mac.clone()],
                    namespace: None,
                }),
            ],
            src_dir: String::new(),
            source: EdgeSource::NimbleFallback,
        };
        let terms = edgeset_to_terms(&es, &no_overrides());
        // Dep appears exactly once in the solver (one requires_name)
        assert_eq!(terms.requires_names.iter().filter(|n| n.as_str() == "foo").count(), 1);
        // Both predicate-vecs must be recorded
        let preds = terms.requires_predicates.get("foo").expect("foo must be in requires_predicates");
        assert_eq!(preds.len(), 2, "both branches must accumulate");
        assert!(preds.contains(&vec![p_linux]), "linux branch must be present");
        assert!(preds.contains(&vec![p_mac]), "macosx branch must be present");
    }

    #[test]
    fn c1_same_url_dep_two_branches_accumulates_predicates() {
        // Same URL dep appearing in two when-branches.
        let p_linux = plat("linux");
        let p_mac = plat("macosx");
        let url = "https://example.com/foo.git";
        let es = EdgeSet {
            requires: vec![
                RequireEntry::Url(UrlRequire {
                    url: url.to_string(),
                    ref_: "main".to_string(),
                    predicates: vec![p_linux.clone()],
                    flag_requests: Vec::new(),
                    name: None,
                }),
                RequireEntry::Url(UrlRequire {
                    url: url.to_string(),
                    ref_: "main".to_string(),
                    predicates: vec![p_mac.clone()],
                    flag_requests: Vec::new(),
                    name: None,
                }),
            ],
            src_dir: String::new(),
            source: EdgeSource::NimbleFallback,
        };
        let terms = edgeset_to_terms(&es, &no_overrides());
        // Dep appears exactly once in requires_names
        assert_eq!(terms.requires_names.iter().filter(|n| n.as_str() == "foo").count(), 1);
        // Both predicate-vecs recorded
        let preds = terms.requires_predicates.get("foo").expect("foo must be in requires_predicates");
        assert_eq!(preds.len(), 2, "both branches must accumulate");
        assert!(preds.contains(&vec![p_linux]));
        assert!(preds.contains(&vec![p_mac]));
    }

    #[test]
    fn c1_single_occurrence_still_works() {
        // Single occurrence with predicate → list with one entry.
        let p = plat("linux");
        let es = EdgeSet {
            requires: vec![RequireEntry::Named(NamedRequire {
                name: "extra".to_string(),
                constraint_str: String::new(),
                predicates: vec![p.clone()],
                namespace: None,
            })],
            src_dir: String::new(),
            source: EdgeSource::NimbleFallback,
        };
        let terms = edgeset_to_terms(&es, &no_overrides());
        let preds = terms.requires_predicates.get("extra").unwrap();
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0], vec![p]);
    }

    // -----------------------------------------------------------------------
    // §7.2 normative: bare URL with no `#ref` defaults to HEAD
    // -----------------------------------------------------------------------

    #[test]
    fn nimble_bare_url_no_ref_defaults_to_head() {
        // A .nimble `requires "https://github.com/user/pkg.git"` with no `#ref`
        // fragment MUST resolve ref_ == "HEAD" (spec/dep-decl.md §7.2 normative).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_nimble_tree(
            tmp.path(),
            "pkg",
            r#"requires "https://github.com/user/pkg.git""#,
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        assert_eq!(es.source, EdgeSource::NimbleFallback);
        assert_eq!(es.requires.len(), 1);
        match &es.requires[0] {
            RequireEntry::Url(u) => {
                assert_eq!(u.url, "https://github.com/user/pkg.git");
                assert_eq!(u.ref_, "HEAD", "bare URL with no #ref must default to HEAD per §7.2");
            }
            other => panic!("expected UrlRequire, got {other:?}"),
        }
    }

    #[test]
    fn nimble_url_with_explicit_ref_uses_that_ref() {
        // A `#ref` fragment MUST be honored as-is, not overridden with HEAD.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_nimble_tree(
            tmp.path(),
            "pkg",
            r#"requires "https://github.com/user/pkg.git#v1.2.3""#,
        );
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        let version = url_ver();
        let mut cache = HashMap::new();
        let pkg_sid = sid("pkg");
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, &pkg_sid, None, None, None).unwrap();
        match &es.requires[0] {
            RequireEntry::Url(u) => {
                assert_eq!(u.ref_, "v1.2.3", "explicit #ref must be preserved");
            }
            other => panic!("expected UrlRequire, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // declared_version_for — Axis A (b) step 3 (A3): git tag-derived fallback
    // -----------------------------------------------------------------------

    #[test]
    fn declared_version_for_git_tag_with_v_prefix() {
        // A git dep pinned to tag `v1.2.3` with no milpa.kdl/.nimble version
        // resolves its declared version from the tag (step 3).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("v1.2.3"),
            version: None,
        };
        assert_eq!(declared_version_for(&ctx), Some((Version::release(1, 2, 3), VersionSource::Tag)));
    }

    #[test]
    fn declared_version_for_git_tag_without_v_prefix() {
        // A bare `1.2.3` tag (no leading `v`) also parses (step 3).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("1.2.3"),
            version: None,
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(1, 2, 3), VersionSource::Tag))
        );
    }

    #[test]
    fn declared_version_for_branch_ref_stays_version_unknown() {
        // A branch ref (`main`) is not version-shaped — no regression: stays
        // version-unknown (`None`), same as before A3.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("main"),
            version: None,
        };
        assert_eq!(declared_version_for(&ctx), None);
    }

    #[test]
    fn declared_version_for_sha_ref_stays_version_unknown() {
        // A commit-SHA ref is not version-shaped — stays version-unknown.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"),
            version: None,
        };
        assert_eq!(declared_version_for(&ctx), None);
    }

    #[test]
    fn declared_version_for_milpa_kdl_version_wins_over_tag() {
        // Steps 1-2 still take precedence over step 3: a fetched `milpa.kdl
        // version` wins over a differing tag (precedence preserved).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(tmp.path(), "pkg", "name \"pkg\"\nversion \"2.0.0\"\n");
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("v9.9.9"),
            version: None,
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(2, 0, 0), VersionSource::Manifest))
        );
    }

    #[test]
    fn declared_version_for_nimble_version_wins_over_tag() {
        // A fetched `.nimble version` (step 2) wins over a differing tag
        // (step 3 never reached).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_nimble_tree(tmp.path(), "pkg", "version = \"0.5.0\"\nauthor = \"x\"\n");
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("v9.9.9"),
            version: None,
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(0, 5, 0), VersionSource::Nimble))
        );
    }

    #[test]
    fn declared_version_for_milpa_kdl_version_wins_over_differing_nimble_version() {
        // L11: step 1 (`milpa.kdl version`) must win over step 2 (`.nimble
        // version`) when a fetched tree carries BOTH and they DIFFER — the
        // existing coverage only proved step 1/2 beat step 3 (git tag) and
        // step 4 (the `version=` annotation) individually; this proves the
        // step-1-over-step-2 edge of the SAME precedence chain directly,
        // with no tag/annotation in play to potentially mask a
        // short-circuit bug in `declared_version_for`'s own early-return.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(tmp.path(), "pkg", "name \"pkg\"\nversion \"3.0.0\"\n");
        std::fs::write(
            dep_path.join("pkg.nimble"),
            "version = \"1.0.0\"\nauthor = \"x\"\n",
        )
        .unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(3, 0, 0), VersionSource::Manifest)),
            "milpa.kdl version=3.0.0 must win over the differing .nimble version=1.0.0"
        );
    }

    #[test]
    fn declared_version_for_no_ref_stays_version_unknown() {
        // Local/tarball/member/named contexts leave `ref_: None` — step 3 is
        // a no-op, unaffected by A3 (no regression for non-git dep kinds).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: None,
        };
        assert_eq!(declared_version_for(&ctx), None);
    }

    // -----------------------------------------------------------------------
    // declared_version_for — Axis A (b) step 4 (A3b): version= annotation
    // -----------------------------------------------------------------------

    #[test]
    fn declared_version_for_annotation_used_when_no_other_source() {
        // A version= annotation (ctx.version) is used when steps 1-3
        // (milpa.kdl, .nimble, git tag) all miss.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("main"),
            version: Some(Version::release(1, 5, 0)),
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(1, 5, 0), VersionSource::Annotation))
        );
    }

    #[test]
    fn declared_version_for_annotation_used_with_no_ref_at_all() {
        // local/tarball deps have no `ref` concept at all — the annotation
        // still applies (A3b extends the reach to local/tarball, not just git).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: Some(Version::release(2, 2, 2)),
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(2, 2, 2), VersionSource::Annotation))
        );
    }

    #[test]
    fn declared_version_for_milpa_kdl_version_wins_over_annotation() {
        // Step 1 (milpa.kdl version) still wins over the annotation when
        // present — the annotation is a gap-filler, never an override.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_dep_tree(tmp.path(), "pkg", "name \"pkg\"\nversion \"2.0.0\"\n");
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: true,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: Some(Version::release(9, 9, 9)),
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(2, 0, 0), VersionSource::Manifest))
        );
    }

    #[test]
    fn declared_version_for_nimble_version_wins_over_annotation() {
        // Step 2 (.nimble version) still wins over the annotation when present.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = make_nimble_tree(tmp.path(), "pkg", "version = \"0.5.0\"\nauthor = \"x\"\n");
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: None,
            version: Some(Version::release(9, 9, 9)),
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(0, 5, 0), VersionSource::Nimble))
        );
    }

    #[test]
    fn declared_version_for_git_tag_wins_over_annotation() {
        // Step 3 (git tag) still wins over the annotation when present.
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("v1.2.3"),
            version: Some(Version::release(9, 9, 9)),
        };
        assert_eq!(
            declared_version_for(&ctx),
            Some((Version::release(1, 2, 3), VersionSource::Tag))
        );
    }

    #[test]
    fn declared_version_for_annotation_absent_stays_version_unknown() {
        // No annotation, no other source → still version-unknown (no regression).
        let tmp = tempfile::tempdir().unwrap();
        let dep_path = tmp.path().join("pkg");
        std::fs::create_dir_all(&dep_path).unwrap();
        let overrides = no_overrides();
        let ctx = EdgeSourceCtx {
            dep_path: Some(&dep_path),
            dep_name: "pkg",
            dep_decl: None,
            is_overridden: false,
            has_milpa_kdl: false,
            dep_decl_schema_version: None,
            overrides_by_name: &overrides,
            active_flags: BTreeSet::new(),
            ref_: Some("main"),
            version: None,
        };
        assert_eq!(declared_version_for(&ctx), None);
    }
}
