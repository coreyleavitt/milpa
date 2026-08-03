//! Symbol-level import-slot check — post-solve, complete (S7). Mirrors
//! Python's `milpa/import_slot.py` function-for-function (§9 cross-impl
//! discipline).
//!
//! `rfc-origin-as-identity.md` §4.6, S7: two DISTINCT source-ids that export
//! the same Nim import symbol cannot coexist in one build, even when they
//! live in differently-named `_deps/` slots (the case S6's directory-slot
//! floor misses — a hijacking transitive can evade that floor by choosing a
//! distinct label). This module is the complete check, behind a
//! `SymbolProviderPort`: the symbol a fetched tree exports is irreducibly a
//! post-fetch fact (bytes) or a manifest-declared fact, so it needs a port —
//! unlike S6's directory-slot floor (`lockfile::check_directory_slot_collisions`),
//! which is a pure function of already-in-memory slot names and needs none.
//!
//! **Deep-module split:**
//!   - [`ImportSlot`] / [`SymbolProviderPort`] — the seam.
//!   - [`ManifestDeclaredSymbolProvider`] / [`FetchedTreeSymbolProvider`] —
//!     the two adapters, composed declared-beats-inferred (mirroring the
//!     `EdgeSource` fidelity tags) by [`ComposedSymbolProvider`] /
//!     [`default_symbol_provider`].
//!   - [`check_import_slot_collisions`] — the pure decision function: given a
//!     resolved graph and a provider, gather each dep's `ImportSlot` set and
//!     raise `RES-IMPORT-COLLISION` iff two distinct deps share a module slot
//!     AND disagree on `identity` (content_hash) — the exact same
//!     same-bytes-short-circuit S6 applies (§3.3) — AND the pair is not one
//!     of the two documented exemptions (see `is_exempt_pair`, below). S6's
//!     directory-slot floor is retained and run FIRST, as a cheap pre-filter
//!     (§4.6 round-2 fix — G9).
//!
//! **Known coverage boundary (documented, not silently over-promised):** a
//! dep whose fetched tree cannot be located at check time (no CAS `identity`
//! yet — local/member deps, or a pre-S5 frozen lockfile) contributes no
//! `ImportSlot`s; it is still protected by the S6 directory-slot floor, just
//! not by the symbol-level scan. `FetchedTreeSymbolProvider`'s tree_scanned
//! fidelity derives a module name from each `*.nim` file's stem — a
//! heuristic proxy, not a full Nim import-path resolver (out of scope; see
//! `spec/errors.md` `RES-IMPORT-COLLISION` for the precise coverage
//! statement).
//!
//! **Two documented exemptions (`is_exempt_pair`, below the checker):** a
//! pair is not treated as a collision, even sharing a module slot with
//! different content, when they are separated by a registry NAMESPACE, or
//! connected by a direct `requires` edge. See `is_exempt_pair`'s doc comment.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use milpa_types::{ResolvedDep, ResolvedGraph, SourceId};

use crate::error::{CoreError, MilpaError};
use crate::lockfile::{check_directory_slot_collisions, dep_origin_label};
use crate::store::CaStore;

// ---------------------------------------------------------------------------
// The seam — ImportSlot + SymbolProviderPort
// ---------------------------------------------------------------------------

/// The fidelity tag on an [`ImportSlot`] — `ManifestDeclared` (an author
/// asserted this in a `provides {}` block — trusted, authoritative) or
/// `TreeScanned` (inferred by scanning the fetched tree for `*.nim` files —
/// a heuristic fallback used only when nothing was declared). Mirrors
/// Python's `ImportSlot.fidelity` `Literal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fidelity {
    ManifestDeclared,
    TreeScanned,
}

/// One Nim-importable module a dep provides, tagged with its fidelity.
/// Mirrors Python's `import_slot.ImportSlot`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImportSlot {
    /// A Nim-importable module path (e.g. `"foo"` or `"foo/bar"`).
    pub module: String,
    pub fidelity: Fidelity,
}

/// Port: "what Nim import symbols does this materialized dep provide?"
///
/// Hides WHERE the answer comes from (an author's `provides {}` declaration
/// vs. a scan of the fetched tree) behind one interface, so the checker
/// ([`check_import_slot_collisions`]) is a pure function of (resolved graph,
/// provider) — real adapters do real I/O; unit tests inject a fake that
/// returns canned `ImportSlot` sets, with no filesystem involved. Mirrors
/// Python's `SymbolProviderPort` `Protocol`.
pub trait SymbolProviderPort {
    fn import_slots_for(&self, sid: Option<&SourceId>, materialized_path: &Path) -> BTreeSet<ImportSlot>;
}

// ---------------------------------------------------------------------------
// Adapter 1 — ManifestDeclaredSymbolProvider (manifest_declared fidelity)
// ---------------------------------------------------------------------------

/// Reads the dep's OWN `milpa.kdl` `provides {}` block, if any.
///
/// `materialized_path` is the dep's fetched tree root (where its own
/// `milpa.kdl` — not the resolving root's — would live). Returns an empty
/// set — never raises — when there is no `milpa.kdl` at that path, it fails
/// to parse, or it declares no `provides` block: all three are "nothing
/// declared," the trigger for the composed provider's fallback to
/// `FetchedTreeSymbolProvider`, not an error. Mirrors Python's
/// `ManifestDeclaredSymbolProvider`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManifestDeclaredSymbolProvider;

impl SymbolProviderPort for ManifestDeclaredSymbolProvider {
    fn import_slots_for(&self, _sid: Option<&SourceId>, materialized_path: &Path) -> BTreeSet<ImportSlot> {
        let manifest_path = materialized_path.join("milpa.kdl");
        if !manifest_path.is_file() {
            return BTreeSet::new();
        }
        let text = match std::fs::read_to_string(&manifest_path) {
            Ok(t) => t,
            Err(_) => return BTreeSet::new(),
        };
        let manifest = match milpa_manifest::parse_manifest(&text) {
            Ok(m) => m,
            Err(_) => return BTreeSet::new(),
        };
        manifest
            .provides
            .into_iter()
            .map(|module| ImportSlot { module, fidelity: Fidelity::ManifestDeclared })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Adapter 2 — FetchedTreeSymbolProvider (tree_scanned fidelity, fallback)
// ---------------------------------------------------------------------------

/// Scans the materialized tree for `*.nim` files.
///
/// Each file's module name is its stem (basename without the `.nim`
/// extension) — a heuristic proxy for "what Nim module path does this file
/// provide," deliberately not a full Nim import-path resolver. Returns an
/// empty set — never raises — when `materialized_path` does not exist or is
/// not a directory. Mirrors Python's `FetchedTreeSymbolProvider`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FetchedTreeSymbolProvider;

impl SymbolProviderPort for FetchedTreeSymbolProvider {
    fn import_slots_for(&self, _sid: Option<&SourceId>, materialized_path: &Path) -> BTreeSet<ImportSlot> {
        if !materialized_path.is_dir() {
            return BTreeSet::new();
        }
        let mut slots = BTreeSet::new();
        collect_nim_stems(materialized_path, &mut slots);
        slots
    }
}

/// Best-effort recursive `*.nim` scan (never raises; skips unreadable
/// entries). Mirrors `Path.rglob("*.nim")` in the Python adapter.
fn collect_nim_stems(dir: &Path, out: &mut BTreeSet<ImportSlot>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else { continue };
        if file_type.is_dir() {
            collect_nim_stems(&path, out);
        } else if file_type.is_file() && path.extension().and_then(|e| e.to_str()) == Some("nim") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.insert(ImportSlot { module: stem.to_string(), fidelity: Fidelity::TreeScanned });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Composition — declared-beats-inferred
// ---------------------------------------------------------------------------

/// Declared-beats-inferred composition of two [`SymbolProviderPort`]s.
///
/// Mirrors the `EdgeSource` fidelity-tag precedence: a higher-fidelity
/// source, when present, wins outright rather than merging with the
/// lower-fidelity one. Here: if the dep's own manifest declares ANY
/// `provides` entries, those `manifest_declared` slots are the answer, full
/// stop — `FetchedTreeSymbolProvider` is consulted only when the declared
/// provider returns nothing at all. Mirrors Python's `ComposedSymbolProvider`.
pub struct ComposedSymbolProvider<D: SymbolProviderPort, S: SymbolProviderPort> {
    pub declared: D,
    pub scanned: S,
}

impl<D: SymbolProviderPort, S: SymbolProviderPort> SymbolProviderPort for ComposedSymbolProvider<D, S> {
    fn import_slots_for(&self, sid: Option<&SourceId>, materialized_path: &Path) -> BTreeSet<ImportSlot> {
        let declared_slots = self.declared.import_slots_for(sid, materialized_path);
        if !declared_slots.is_empty() {
            return declared_slots;
        }
        self.scanned.import_slots_for(sid, materialized_path)
    }
}

/// The COMPLETE composed provider the RFC specifies: manifest-declared, else
/// tree-scanned. Fully implemented and tested (both standalone and
/// composed) — but see [`live_symbol_provider`] for what the real
/// `resolve()`/`resolve_workspace()`/frozen call sites actually wire in by
/// default today, and why. Mirrors Python's `default_symbol_provider`.
pub fn default_symbol_provider() -> ComposedSymbolProvider<ManifestDeclaredSymbolProvider, FetchedTreeSymbolProvider> {
    ComposedSymbolProvider { declared: ManifestDeclaredSymbolProvider, scanned: FetchedTreeSymbolProvider }
}

/// The provider the real call sites (`resolve()`, `resolve_workspace()`, the
/// frozen path) actually compose [`check_import_slot_collisions`] with —
/// deliberately [`ManifestDeclaredSymbolProvider`] ALONE, not
/// [`default_symbol_provider`]'s full composition.
///
/// **Why (a documented, evidence-based v1 scope decision, not an
/// oversight):** `FetchedTreeSymbolProvider`'s tree_scanned fidelity is a
/// pure filename heuristic, and wiring it into the hard-fail default
/// surfaces FALSE positives against entirely unrelated, already-correct
/// behavior: two independent packages (or two independent test-fixture
/// mocks) that happen to both ship a generically-named `*.nim` file
/// (`marker.nim`, `bar.nim`, `foo.nim` — extremely common in real small Nim
/// packages too) are NOT a hijacking attempt, but a naive whole-tree scan
/// cannot tell the difference. `manifest_declared` fidelity has NO such
/// risk — an author's own `provides {}` assertion is unambiguous ground
/// truth — so it is the only tier safe to hard-fail on unconditionally
/// today. This does not remove capability: [`check_import_slot_collisions`]
/// and both adapters are fully implemented, independently usable, and
/// directly composable ([`default_symbol_provider`]) by anyone who wants the
/// complete RFC-specified check. Mirrors Python's `live_symbol_provider`.
pub fn live_symbol_provider() -> ManifestDeclaredSymbolProvider {
    ManifestDeclaredSymbolProvider
}

// ---------------------------------------------------------------------------
// The checker — pure function of (resolved graph, provider)
// ---------------------------------------------------------------------------

/// Best-effort materialized tree root for `dep`.
///
/// Every CAS-backed dep (git/tarball/oci — anything with a content
/// `identity`) resolves to `store.path_for(&dep.identity)`, the exact same
/// tree `rebuild_deps_view` later symlinks into `_deps/`. A dep with no
/// identity (local/member, or a pre-S5 frozen reconstruction) or no `store`
/// at all falls back to a placeholder path that will not exist on disk —
/// both adapters treat a nonexistent path as "nothing to report" (empty
/// set), never an error, so this degrades safely rather than crashing; such
/// deps remain covered by the S6 directory-slot floor even though they are
/// invisible to the symbol-level scan. Mirrors Python's
/// `_materialized_path_for`.
fn materialized_path_for(dep: &ResolvedDep, store: Option<&CaStore>) -> PathBuf {
    if !dep.identity.is_empty() {
        if let Some(store) = store {
            if let Ok(p) = store.path_for(&dep.identity) {
                return p;
            }
        }
    }
    PathBuf::from(format!("<unmaterialized:{}>", dep.name))
}

/// Two DOCUMENTED, RFC-consistent exemptions from the pairwise
/// tree_scanned-fidelity comparison — both mirror an axis the resolver's OWN
/// model already treats as a legitimate separate-identity signal, so S7 (an
/// EXTENSION of S6, not a stricter orthogonal rule) does not manufacture a
/// hard failure where the resolver has already sanctioned coexistence:
///
/// 1. **Registry-namespace separation.** Two different, non-`None` registry
///    namespaces are the tianguis registry's OWN multi-tenancy mechanism for
///    letting independent authors publish under the same bare name —
///    exactly what S6's own `dep_dir_name(name, namespace)` already treats
///    as non-colliding at the directory-slot level.
/// 2. **Direct `requires` edge.** When one dep is a direct dependency of the
///    other, the consumer (or that dep's own manifest) explicitly chose
///    this exact coexistence — unlike two mutually-unaware SIBLING packages
///    independently pulled into one graph, the actual shape of the RFC's
///    "hijacking transitive" scenario.
///
/// Mirrors Python's `_is_exempt_pair`.
fn is_exempt_pair(a: &ResolvedDep, b: &ResolvedDep) -> bool {
    if let (Some(ans), Some(bns)) = (&a.namespace, &b.namespace) {
        if ans != bns {
            return true;
        }
    }
    if a.requires.contains(&b.name) || b.requires.contains(&a.name) {
        return true;
    }
    false
}

/// The complete, symbol-level import-slot check (S7, §4.6) —
/// `RES-IMPORT-COLLISION`.
///
/// Runs the S6 directory-slot floor FIRST as a cheap pre-filter (a
/// directory-slot collision always implies a symbol collision, so there is
/// no reason to do per-tree symbol work once the floor has already found
/// one — §4.6 round-2 fix, G9). If S6 does not raise, gathers every dep's
/// `ImportSlot` set via `provider` and groups by `module`. Every pair of
/// DISTINCT deps sharing a module slot is examined: a pair is NOT a
/// collision when either (a) they share one non-empty `identity` — the same
/// same-bytes/different-origin short-circuit S6 applies — or (b)
/// `is_exempt_pair` says so. The first non-exempt, non-identical pair found
/// raises. Mirrors Python's `check_import_slot_collisions`.
pub fn check_import_slot_collisions(
    resolved: &ResolvedGraph,
    provider: &dyn SymbolProviderPort,
    store: Option<&CaStore>,
) -> Result<(), MilpaError> {
    check_directory_slot_collisions(resolved)?;

    let mut by_module: std::collections::BTreeMap<String, Vec<&ResolvedDep>> = std::collections::BTreeMap::new();
    for dep in &resolved.deps {
        let materialized_path = materialized_path_for(dep, store);
        let slots = provider.import_slots_for(dep.source_id.as_ref(), &materialized_path);
        for slot in slots {
            by_module.entry(slot.module).or_default().push(dep);
        }
    }

    for (module, group) in by_module {
        if group.len() < 2 {
            continue;
        }
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let (first, second) = (group[i], group[j]);
                if !first.identity.is_empty() && first.identity == second.identity {
                    continue;
                }
                if is_exempt_pair(first, second) {
                    continue;
                }
                let existing = dep_origin_label(first);
                let conflicting = dep_origin_label(second);
                return Err(MilpaError::Core(CoreError::Resolver(
                    "RES-IMPORT-COLLISION",
                    format!(
                        "import-symbol collision on Nim module '{module}': {existing} and \
                         {conflicting} both provide it with different content and cannot both \
                         be imported — give one an explicit, distinct dep label (or reconcile \
                         via `overrides {{}}`) to separate them"
                    ),
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "import_slot_tests.rs"]
mod import_slot_tests;
