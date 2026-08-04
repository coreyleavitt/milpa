//! S7 (rfc-origin-as-identity.md §4.6/§10 item 13) — the complete,
//! symbol-level import-slot check. Mirrors Python's
//! `test_s7_import_slot_symbol_collision.py` function-for-function.

use std::collections::BTreeSet;
use std::path::Path;

use milpa_types::{FetchableOrigin, ProvenanceRecord, ResolvedDep, ResolvedGraph, SourceId, Version};

use super::*;

const HASH_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn git_source(url: &str) -> SourceId {
    SourceId::Fetchable(FetchableOrigin::Git { git_ref: None, url: url.to_string(), subpath: None })
}

fn oci_source(registry: &str, repository: &str) -> SourceId {
    SourceId::Fetchable(FetchableOrigin::Oci {
        digest: None,
        registry: registry.to_string(),
        repository: repository.to_string(),
        subpath: None,
    })
}

/// Mirrors Python's `_dep` test helper — a `ResolvedDep` with sensible
/// defaults for every field this module doesn't care about.
fn dep(
    name: &str,
    identity: &str,
    source_id: Option<SourceId>,
    url: &str,
    namespace: Option<&str>,
    requires: &[&str],
) -> ResolvedDep {
    ResolvedDep {
        name: name.to_string(),
        namespace: namespace.map(str::to_string),
        identity: identity.to_string(),
        version: Version::release(0, 0, 1),
        src_dir: String::new(),
        requires: requires.iter().map(|s| s.to_string()).collect(),
        provenances: vec![ProvenanceRecord::Git {
            url: url.to_string(),
            ref_spec: None,
            commit_sha: None,
            origin: "observed".to_string(),
            submodule_shas: vec![],
        }],
        dep_decl: None,
        cond_requires: vec![],
        aliases: vec![],
        active_flags: vec![],
        attestation: None,
        declared_version_source: None,
        source_id,
    }
}

/// A `SymbolProviderPort` fake keyed by dep name (via the materialized
/// placeholder path's basename — see `materialized_path_for`, which uses
/// `"<unmaterialized:{name}>"` when no CAS store is supplied). Lets tests
/// assign canned `ImportSlot` sets per dep without touching a filesystem at
/// all. Mirrors Python's `_FakeProvider`.
struct FakeProvider {
    slots_by_dep_name: std::collections::BTreeMap<String, BTreeSet<ImportSlot>>,
}

impl SymbolProviderPort for FakeProvider {
    fn import_slots_for(&self, _sid: Option<&SourceId>, materialized_path: &Path) -> BTreeSet<ImportSlot> {
        let basename = materialized_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let name = basename
            .strip_prefix("<unmaterialized:")
            .and_then(|s| s.strip_suffix('>'))
            .unwrap_or(basename);
        self.slots_by_dep_name.get(name).cloned().unwrap_or_default()
    }
}

fn slot(module: &str, fidelity: Fidelity) -> ImportSlot {
    ImportSlot { module: module.to_string(), fidelity }
}

fn fake(pairs: &[(&str, &[ImportSlot])]) -> FakeProvider {
    FakeProvider {
        slots_by_dep_name: pairs
            .iter()
            .map(|(name, slots)| (name.to_string(), slots.iter().cloned().collect()))
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// 1. The checker's decision logic — fake providers, no filesystem
// ---------------------------------------------------------------------------

#[test]
fn raises_when_different_slots_export_same_module() {
    let a = dep("pkg-a", HASH_A, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("pkg-b", HASH_B, Some(oci_source("reg.example.com", "pkg-b")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[
        ("pkg-a", &[slot("shared", Fidelity::TreeScanned)]),
        ("pkg-b", &[slot("shared", Fidelity::TreeScanned)]),
    ]);

    let err = check_import_slot_collisions(&graph, &provider, None).unwrap_err();
    assert_eq!(err.code(), "RES-IMPORT-COLLISION");
    assert!(err.message().contains("shared"));
}

#[test]
fn no_raise_when_modules_distinct() {
    let a = dep("pkg-a", HASH_A, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("pkg-b", HASH_B, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[
        ("pkg-a", &[slot("foo", Fidelity::TreeScanned)]),
        ("pkg-b", &[slot("bar", Fidelity::TreeScanned)]),
    ]);

    assert!(check_import_slot_collisions(&graph, &provider, None).is_ok());
}

#[test]
fn content_hash_short_circuit_no_raise_when_identity_matches() {
    let a = dep("pkg-a", HASH_A, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("pkg-b", HASH_A, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[
        ("pkg-a", &[slot("shared", Fidelity::TreeScanned)]),
        ("pkg-b", &[slot("shared", Fidelity::TreeScanned)]),
    ]);

    assert!(check_import_slot_collisions(&graph, &provider, None).is_ok());
}

#[test]
fn raises_when_one_identity_is_empty() {
    // A missing identity can never be PROVEN equal — no short-circuit.
    let a = dep("pkg-a", "", Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("pkg-b", HASH_A, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[
        ("pkg-a", &[slot("shared", Fidelity::TreeScanned)]),
        ("pkg-b", &[slot("shared", Fidelity::TreeScanned)]),
    ]);

    let err = check_import_slot_collisions(&graph, &provider, None).unwrap_err();
    assert_eq!(err.code(), "RES-IMPORT-COLLISION");
}

#[test]
fn directory_slot_collision_still_raises_as_pre_filter() {
    let a = dep("foo", HASH_A, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("foo", HASH_B, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    // A provider that reports NO overlapping modules at all — if S7's
    // symbol-level scan were the only thing running, this would NOT raise.
    // The S6 pre-filter must catch it before the provider's answer matters.
    let provider = fake(&[]);

    let err = check_import_slot_collisions(&graph, &provider, None).unwrap_err();
    assert_eq!(err.code(), "RES-IMPORT-COLLISION");
}

#[test]
fn directory_slot_short_circuit_still_holds() {
    let same_id = HASH_A;
    let a = dep("chronos", same_id, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("chronos", same_id, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[]);

    assert!(check_import_slot_collisions(&graph, &provider, None).is_ok());
}

// ---------------------------------------------------------------------------
// TestExemptPairs
// ---------------------------------------------------------------------------

#[test]
fn different_registry_namespaces_exempt() {
    let a = dep("bar", HASH_A, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", Some("ns1"), &[]);
    let b = dep("bar", HASH_B, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", Some("ns2"), &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[("bar", &[slot("bar", Fidelity::TreeScanned)])]);

    assert!(check_import_slot_collisions(&graph, &provider, None).is_ok());
}

#[test]
fn same_registry_namespace_not_exempt() {
    let a = dep("bar", HASH_A, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", Some("ns1"), &[]);
    let b = dep("baz", HASH_B, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", Some("ns1"), &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[
        ("bar", &[slot("shared", Fidelity::TreeScanned)]),
        ("baz", &[slot("shared", Fidelity::TreeScanned)]),
    ]);

    let err = check_import_slot_collisions(&graph, &provider, None).unwrap_err();
    assert_eq!(err.code(), "RES-IMPORT-COLLISION");
}

#[test]
fn direct_requires_edge_exempt() {
    // t1 requires foo (direct edge) — a coexistence the consumer's own
    // dependency graph explicitly chose.
    let foo = dep("foo", HASH_A, Some(git_source("https://example.com/foo.git")), "https://example.com/foo.git", None, &[]);
    let t1 = dep("t1", HASH_B, Some(git_source("https://example.com/t1.git")), "https://example.com/t1.git", None, &["foo"]);
    let graph = ResolvedGraph { deps: vec![foo, t1] };
    let provider = fake(&[
        ("foo", &[slot("marker", Fidelity::TreeScanned)]),
        ("t1", &[slot("marker", Fidelity::TreeScanned)]),
    ]);

    assert!(check_import_slot_collisions(&graph, &provider, None).is_ok());
}

#[test]
fn unconnected_siblings_not_exempt() {
    // Two root-level siblings with NO requires edge and NO namespace — the
    // actual headline-shape threat — are NOT exempt.
    let a = dep("pkg-a", HASH_A, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("pkg-b", HASH_B, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };
    let provider = fake(&[
        ("pkg-a", &[slot("marker", Fidelity::TreeScanned)]),
        ("pkg-b", &[slot("marker", Fidelity::TreeScanned)]),
    ]);

    let err = check_import_slot_collisions(&graph, &provider, None).unwrap_err();
    assert_eq!(err.code(), "RES-IMPORT-COLLISION");
}

// ---------------------------------------------------------------------------
// live_symbol_provider / default_symbol_provider
// ---------------------------------------------------------------------------

#[test]
fn live_symbol_provider_is_manifest_declared_only() {
    // Type-level assertion: live_symbol_provider() returns exactly
    // ManifestDeclaredSymbolProvider (mirrors Python's isinstance check) —
    // proven here by using it directly as that concrete type.
    let provider: ManifestDeclaredSymbolProvider = live_symbol_provider();
    let tmp = tempfile::tempdir().unwrap();
    // No milpa.kdl at all -> empty, confirming this is the declared-only
    // adapter (a tree-scanning provider would still be empty here too, but
    // the point is the TYPE, asserted by the function's return type itself).
    assert!(provider.import_slots_for(None, tmp.path()).is_empty());
}

#[test]
fn default_symbol_provider_is_the_full_composition() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("foo.nim"), "# foo\n").unwrap();
    let provider = default_symbol_provider();
    // The composed provider falls back to tree-scanning when nothing is
    // declared — proving it is the FULL composition, not declared-only.
    let slots = provider.import_slots_for(None, tmp.path());
    assert_eq!(slots, BTreeSet::from([slot("foo", Fidelity::TreeScanned)]));
}

// ---------------------------------------------------------------------------
// 2. ManifestDeclaredSymbolProvider — real temp milpa.kdl reads
// ---------------------------------------------------------------------------

#[test]
fn manifest_declared_reads_provides_block() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("milpa.kdl"),
        "name \"foo\"\nkind \"library\"\nprovides {\n    module \"foo\"\n    module \"foo/bar\"\n}\n",
    )
    .unwrap();
    let provider = ManifestDeclaredSymbolProvider;
    let slots = provider.import_slots_for(None, tmp.path());
    assert_eq!(
        slots,
        BTreeSet::from([
            slot("foo", Fidelity::ManifestDeclared),
            slot("foo/bar", Fidelity::ManifestDeclared),
        ])
    );
}

#[test]
fn manifest_declared_no_milpa_kdl_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = ManifestDeclaredSymbolProvider;
    assert!(provider.import_slots_for(None, tmp.path()).is_empty());
}

#[test]
fn manifest_declared_no_provides_block_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("milpa.kdl"), "name \"foo\"\nkind \"library\"\n").unwrap();
    let provider = ManifestDeclaredSymbolProvider;
    assert!(provider.import_slots_for(None, tmp.path()).is_empty());
}

#[test]
fn manifest_declared_malformed_milpa_kdl_returns_empty_not_panic() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("milpa.kdl"), "this is not { valid kdl").unwrap();
    let provider = ManifestDeclaredSymbolProvider;
    assert!(provider.import_slots_for(None, tmp.path()).is_empty());
}

// ---------------------------------------------------------------------------
// 3. FetchedTreeSymbolProvider — real temp tree scan
// ---------------------------------------------------------------------------

#[test]
fn fetched_tree_scans_nim_files_at_root() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("foo.nim"), "# foo\n").unwrap();
    std::fs::write(tmp.path().join("bar.nim"), "# bar\n").unwrap();
    std::fs::write(tmp.path().join("README.md"), "not nim\n").unwrap();
    let provider = FetchedTreeSymbolProvider;
    let slots = provider.import_slots_for(None, tmp.path());
    assert_eq!(
        slots,
        BTreeSet::from([slot("foo", Fidelity::TreeScanned), slot("bar", Fidelity::TreeScanned)])
    );
}

#[test]
fn fetched_tree_scans_nested_nim_files() {
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("src").join("sub");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("deep.nim"), "# deep\n").unwrap();
    let provider = FetchedTreeSymbolProvider;
    let slots = provider.import_slots_for(None, tmp.path());
    assert_eq!(slots, BTreeSet::from([slot("deep", Fidelity::TreeScanned)]));
}

#[test]
fn fetched_tree_nonexistent_path_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = FetchedTreeSymbolProvider;
    assert!(provider.import_slots_for(None, &tmp.path().join("does-not-exist")).is_empty());
}

#[test]
fn fetched_tree_no_nim_files_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("README.md"), "nothing nim here\n").unwrap();
    let provider = FetchedTreeSymbolProvider;
    assert!(provider.import_slots_for(None, tmp.path()).is_empty());
}

// ---------------------------------------------------------------------------
// 4. ComposedSymbolProvider — declared-beats-inferred
// ---------------------------------------------------------------------------

#[test]
fn composed_declared_wins_over_scanned_even_when_scan_disagrees() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("milpa.kdl"), "name \"foo\"\nprovides {\n    module \"x\"\n}\n").unwrap();
    std::fs::write(tmp.path().join("decoy.nim"), "# decoy\n").unwrap();

    let composed = ComposedSymbolProvider { declared: ManifestDeclaredSymbolProvider, scanned: FetchedTreeSymbolProvider };
    let slots = composed.import_slots_for(None, tmp.path());
    assert_eq!(slots, BTreeSet::from([slot("x", Fidelity::ManifestDeclared)]));
}

#[test]
fn composed_falls_back_to_scanned_when_nothing_declared() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("foo.nim"), "# foo\n").unwrap();
    let composed = ComposedSymbolProvider { declared: ManifestDeclaredSymbolProvider, scanned: FetchedTreeSymbolProvider };
    let slots = composed.import_slots_for(None, tmp.path());
    assert_eq!(slots, BTreeSet::from([slot("foo", Fidelity::TreeScanned)]));
}

// ---------------------------------------------------------------------------
// End-to-end: the composed provider + checker together, over real temp
// trees, with an injected CaStore (exercises `materialized_path_for`'s real
// branch).
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_cross_slot_collision_detected_via_real_store_and_composed_provider() {
    let tmp = tempfile::tempdir().unwrap();
    let store = crate::store::CaStore::new(tmp.path().join(".cas"));
    std::fs::create_dir_all(&store.root).unwrap();

    let tree_a = tmp.path().join("tree-a");
    std::fs::create_dir_all(&tree_a).unwrap();
    std::fs::write(tree_a.join("shared.nim"), "# a\n").unwrap();
    let id_a = crate::identity::compute_content_hash(&tree_a).unwrap();
    store.admit(&tree_a, &id_a).unwrap();

    let tree_b = tmp.path().join("tree-b");
    std::fs::create_dir_all(&tree_b).unwrap();
    std::fs::write(tree_b.join("shared.nim"), "# b (different bytes)\n").unwrap();
    let id_b = crate::identity::compute_content_hash(&tree_b).unwrap();
    store.admit(&tree_b, &id_b).unwrap();

    let a = dep("pkg-a", &id_a, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("pkg-b", &id_b, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };

    let err = check_import_slot_collisions(&graph, &default_symbol_provider(), Some(&store)).unwrap_err();
    assert_eq!(err.code(), "RES-IMPORT-COLLISION");
}

#[test]
fn end_to_end_identical_bytes_via_real_store_does_not_raise() {
    let tmp = tempfile::tempdir().unwrap();
    let store = crate::store::CaStore::new(tmp.path().join(".cas"));
    std::fs::create_dir_all(&store.root).unwrap();

    let tree_a = tmp.path().join("tree-a");
    std::fs::create_dir_all(&tree_a).unwrap();
    std::fs::write(tree_a.join("shared.nim"), "# identical\n").unwrap();
    let identity = crate::identity::compute_content_hash(&tree_a).unwrap();
    store.admit(&tree_a, &identity).unwrap();

    let tree_b = tmp.path().join("tree-b");
    std::fs::create_dir_all(&tree_b).unwrap();
    std::fs::write(tree_b.join("shared.nim"), "# identical\n").unwrap();
    assert_eq!(crate::identity::compute_content_hash(&tree_b).unwrap(), identity);

    let a = dep("pkg-a", &identity, Some(git_source("https://example.com/a.git")), "https://example.com/a.git", None, &[]);
    let b = dep("pkg-b", &identity, Some(git_source("https://example.com/b.git")), "https://example.com/b.git", None, &[]);
    let graph = ResolvedGraph { deps: vec![a, b] };

    assert!(check_import_slot_collisions(&graph, &default_symbol_provider(), Some(&store)).is_ok());
}
