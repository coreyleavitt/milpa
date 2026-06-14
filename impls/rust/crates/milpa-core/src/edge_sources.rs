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
//! priority structure with an `edge_cache` memo keyed on `(name, version)`.
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

use std::collections::BTreeMap;
use std::path::Path;

use milpa_manifest::nimble::{parse_nimble, NimbleRequirement};
use milpa_manifest::{Dep, Manifest, Override};
use milpa_solver::{Dep as SolverDep, VersionSet};
use milpa_types::{EdgeSet, EdgeSource, NamedRequire, RequireEntry, UrlRequire, Version};


// Re-export Item from resolver scope — we import locally within the functions
// that produce sub-items (private to this module; the caller also imports Item).

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
    pub fn edges_for(&self, _name: &str, _version: &Version, ctx: &EdgeSourceCtx) -> EdgeSet {
        let Some(dep_path) = ctx.dep_path else {
            return empty_nimble();
        };
        let Some(nimble_path) = find_nimble(dep_path, ctx.dep_name) else {
            return empty_nimble();
        };
        let text = match std::fs::read_to_string(&nimble_path) {
            Ok(t) => t,
            Err(_) => return empty_nimble(),
        };
        let nm = parse_nimble(&text);
        let mut requires = Vec::new();
        for req in &nm.requires {
            match req {
                NimbleRequirement::Url { url, ref_spec, predicates, .. } => {
                    let ref_ = ref_spec.clone().unwrap_or_else(|| "main".to_string());
                    requires.push(RequireEntry::Url(UrlRequire {
                        url: url.clone(),
                        ref_,
                        predicates: predicates.clone(),
                    }));
                }
                NimbleRequirement::Named { name, constraint, predicates, .. } => {
                    if name == "nim" {
                        continue;
                    }
                    requires.push(RequireEntry::Named(NamedRequire {
                        name: name.clone(),
                        constraint_str: constraint.clone().unwrap_or_default(),
                        predicates: predicates.clone(),
                    }));
                }
            }
        }
        EdgeSet {
            requires,
            src_dir: nm.src_dir.unwrap_or_default(),
            source: EdgeSource::NimbleFallback,
        }
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
        manifest_to_edgeset(&manifest)
    }
}

fn empty_milpa_kdl() -> EdgeSet {
    EdgeSet {
        requires: Vec::new(),
        src_dir: String::new(),
        source: EdgeSource::MilpaKdl,
    }
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
/// The `edge_cache` is a `BTreeMap<(String, Version), EdgeSet>` owned by the
/// caller's `ResolveProvider`; this function receives a mutable reference so
/// the caller remains the sealing authority.
pub fn resolve_edges<'cache>(
    name: &str,
    version: &Version,
    ctx: &EdgeSourceCtx,
    edge_cache: &'cache mut BTreeMap<(String, Version), EdgeSet>,
    nimble_source: Option<&NimbleEdgeSource>,
    milpakdl_source: Option<&MilpaKdlEdgeSource>,
    // dep_decl_source: S3b injection point (wired from DepDeclStore in resolver.rs L1200+).
    dep_decl_source: Option<&dyn DepDeclSource>,
) -> &'cache EdgeSet {
    let cache_key = (name.to_string(), version.clone());
    // Clause (a): sealed once per (name, version) — parent-independent
    if edge_cache.contains_key(&cache_key) {
        return &edge_cache[&cache_key];
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
            nimble.edges_for(name, version, ctx)
        }
    } else if ctx.dep_decl.is_some() {
        if let Some(dds) = dep_decl_source {
            // Clause (c): dep_decl + dep_decl_source → DepDecl [S3b]
            dds.edges_for(name, version, ctx)
        } else {
            // dep_decl_source=None (compat path): fall through to milpa.kdl / nimble
            if ctx.has_milpa_kdl {
                milpa.edges_for(name, version, ctx)
            } else {
                nimble.edges_for(name, version, ctx)
            }
        }
    } else if ctx.has_milpa_kdl {
        // Clause (d): milpa.kdl present
        milpa.edges_for(name, version, ctx)
    } else {
        nimble.edges_for(name, version, ctx)
    };

    edge_cache.insert(cache_key.clone(), es);
    &edge_cache[&cache_key]
}

// ---------------------------------------------------------------------------
// S3b injection-point trait + DepDeclEdgeSource implementation
// ---------------------------------------------------------------------------

/// S3b injection-point trait. Implementors parse a pre-fetched DepDecl
/// artifact and return an `EdgeSet`. The trait is structurally present so
/// S3b can inject without changing the coordinator's signature.
pub trait DepDeclSource {
    fn edges_for(&self, name: &str, version: &Version, ctx: &EdgeSourceCtx) -> EdgeSet;
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
/// is itself overridden enters the solver with `eq_sentinel()` (§10).
/// `url_dep_version` is the singleton version for URL deps (§3).
///
/// Returns `(deps, requires_names, sub_items)`. `sub_items` are the `Item`
/// variants that must be enqueued for BFS processing.
pub fn edgeset_to_terms(
    es: &EdgeSet,
    overrides_by_name: &BTreeMap<String, Override>,
    url_dep_version: Version,
) -> EdgeSetTerms {
    let mut deps: Vec<SolverDep> = Vec::new();
    let mut requires_names: Vec<String> = Vec::new();
    let mut url_requires: Vec<(String, String)> = Vec::new(); // (url, ref_)
    let mut named_requires: Vec<(String, VersionSet)> = Vec::new(); // (name, vs)

    for entry in &es.requires {
        match entry {
            RequireEntry::Url(u) => {
                // URL dep name derived from the URL tail (mirrors name_from_url in resolver).
                let name = match url_tail_name(&u.url) {
                    Some(n) => n,
                    None => continue, // malformed URL; skip silently (resolver handles error paths)
                };
                deps.push(SolverDep::new(name.clone(), VersionSet::eq(url_dep_version.clone())));
                requires_names.push(name.clone());
                url_requires.push((u.url.clone(), u.ref_.clone()));
            }
            RequireEntry::Named(n) => {
                let vs = if overrides_by_name.contains_key(&n.name) {
                    // Overridden named dep → enters as eq_sentinel (§10)
                    VersionSet::eq(url_dep_version.clone())
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
            }
        }
    }

    EdgeSetTerms {
        deps,
        requires_names,
        url_requires,
        named_requires,
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
        };
        let version = url_ver();
        let mut cache: BTreeMap<(String, Version), EdgeSet> = BTreeMap::new();

        // First call populates cache
        let es1_src = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None).source.clone();
        // Second call returns cached value
        let es2_src = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None).source.clone();
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
        let mut cache: BTreeMap<(String, Version), EdgeSet> = BTreeMap::new();
        // Pre-populate with a NimbleFallback-tagged EdgeSet
        cache.insert(
            ("pkg".to_string(), version.clone()),
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
        };
        // Even though has_milpa_kdl=false → nimble path, cache returns pre-populated value.
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None);
        assert_eq!(es.source, EdgeSource::NimbleFallback);
        assert_eq!(es.src_dir, "pre-cached");
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
        };
        let version = url_ver();
        let mut cache = BTreeMap::new();
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None);
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
        };
        let version = url_ver();
        let mut cache = BTreeMap::new();
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None);
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
        };
        let version = url_ver();
        let mut cache = BTreeMap::new();
        // dep_decl_source=None → should fall through to milpa.kdl
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None);
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
        };
        let version = url_ver();
        let mut cache = BTreeMap::new();
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None);
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
        };
        let version = url_ver();
        let mut cache = BTreeMap::new();
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None);
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
        };
        let version = url_ver();
        let mut cache = BTreeMap::new();
        let es = resolve_edges("pkg", &version, &ctx, &mut cache, None, None, None);
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
            })],
            src_dir: String::new(),
            source: EdgeSource::MilpaKdl,
        };
        let terms = edgeset_to_terms(&es, &no_overrides(), url_ver());
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
            })],
            src_dir: String::new(),
            source: EdgeSource::MilpaKdl,
        };
        let terms = edgeset_to_terms(&es, &no_overrides(), url_ver());
        assert_eq!(terms.requires_names, vec!["bar"]);
        assert_eq!(terms.named_requires.len(), 1);
        assert_eq!(terms.named_requires[0].0, "bar");
    }
}
