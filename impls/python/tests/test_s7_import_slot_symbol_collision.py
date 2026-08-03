"""S7 (rfc-origin-as-identity.md §4.6/§10 item 13) — the complete,
symbol-level import-slot check: ``SymbolProviderPort``/``ImportSlot``,
``ManifestDeclaredSymbolProvider``/``FetchedTreeSymbolProvider``,
``ComposedSymbolProvider``, and ``check_import_slot_collisions``.

Coverage:
1. The checker's decision logic (fake providers, no filesystem): the
   headline S7 win over S6 (two distinct source-ids in DIFFERENTLY-named
   slots both exporting one module, differing content_hash → raise), the
   content_hash short-circuit (§3.3, same module + same identity → no
   raise), and the S6 directory-slot floor still firing FIRST as the
   retained pre-filter.
2. ``ManifestDeclaredSymbolProvider`` — real temp ``milpa.kdl`` reads,
   including the "nothing declared" fallback trigger.
3. ``FetchedTreeSymbolProvider`` — real temp tree scan (this is the one
   adapter this module's design bar calls for testing against a real tree,
   not a fake).
4. ``ComposedSymbolProvider`` — declared-beats-inferred fidelity precedence.
5. ``_is_exempt_pair``'s two documented exemptions (registry-namespace
   separation, direct ``requires`` edge) — the fix for the false positives
   a naive whole-tree filename scan produced against this repo's OWN
   generic-filler mocked-fetch conventions (`marker.nim`/`bar.nim` reused
   verbatim across many unrelated fixtures).
6. ``live_symbol_provider()`` — the conservative, manifest_declared-only
   provider the 4 real ``resolve()``/``resolve_workspace()``/frozen call
   sites actually compose with (see its own docstring for the evidence-
   based reason ``FetchedTreeSymbolProvider`` is not, yet, part of the
   zero-config hard-fail default); ``default_symbol_provider()`` remains
   the COMPLETE RFC-specified composition, fully available for direct use.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from milpa.errors import RES_IMPORT_COLLISION, MilpaError
from milpa.import_slot import (
    ComposedSymbolProvider,
    FetchedTreeSymbolProvider,
    ImportSlot,
    ManifestDeclaredSymbolProvider,
    check_import_slot_collisions,
    default_symbol_provider,
    live_symbol_provider,
)
from milpa.lockfile import GitProvenanceRecord, ResolvedDep, ResolvedGraph
from milpa.source_id import GitSourceId, OciSourceId, normalize_source

_HASH_A = "sha256:" + "a" * 64
_HASH_B = "sha256:" + "b" * 64


def _dep(
    name: str,
    identity: str | None,
    *,
    source_id: object | None = None,
    url: str = "https://example.com/x.git",
    namespace: str | None = None,
    requires: tuple[str, ...] = (),
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        identity=identity,
        version="0.0.1",
        src_dir="",
        requires=requires,
        provenances=(GitProvenanceRecord(url=url),),
        namespace=namespace,
        source_id=source_id,
    )


@dataclass(frozen=True)
class _FakeProvider:
    """A ``SymbolProviderPort`` fake keyed by dep name (via the materialized
    placeholder path's basename — see ``import_slot._materialized_path_for``,
    which uses ``Path(f"<unmaterialized:{dep.name}>")`` when no CAS store is
    supplied). Lets tests assign canned ``ImportSlot`` sets per dep without
    touching a filesystem at all.
    """

    slots_by_dep_name: dict[str, frozenset[ImportSlot]]

    def import_slots_for(self, sid: object, materialized_path: Path) -> frozenset[ImportSlot]:
        # materialized_path is "<unmaterialized:NAME>" when store=None (the
        # default for these pure-decision tests) — recover NAME from it.
        name = materialized_path.name.removeprefix("<unmaterialized:").removesuffix(">")
        return self.slots_by_dep_name.get(name, frozenset())


# ---------------------------------------------------------------------------
# 1. The checker's decision logic — fake providers, no filesystem
# ---------------------------------------------------------------------------


class TestCrossSlotSymbolCollision:
    """The headline S7 win: two distinct source-ids in DIFFERENTLY-named
    slots, both exporting the same module, with DIFFERENT content_hash —
    S6's directory-slot floor cannot see this (dep_dir_name differs); S7's
    symbol-level scan must."""

    def test_raises_when_different_slots_export_same_module(self) -> None:
        a = _dep(
            "pkg-a", _HASH_A,
            source_id=normalize_source(GitSourceId(url="https://example.com/a.git")),
        )
        b = _dep(
            "pkg-b", _HASH_B,
            source_id=normalize_source(OciSourceId(registry="reg.example.com", repository="pkg-b")),
        )
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(
            slots_by_dep_name={
                "pkg-a": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
                "pkg-b": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
            }
        )

        with pytest.raises(MilpaError) as exc_info:
            check_import_slot_collisions(graph, provider)
        assert exc_info.value.slug == RES_IMPORT_COLLISION
        msg = str(exc_info.value)
        assert "shared" in msg

    def test_no_raise_when_modules_distinct(self) -> None:
        a = _dep("pkg-a", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("pkg-b", _HASH_B, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(
            slots_by_dep_name={
                "pkg-a": frozenset({ImportSlot(module="foo", fidelity="tree_scanned")}),
                "pkg-b": frozenset({ImportSlot(module="bar", fidelity="tree_scanned")}),
            }
        )

        check_import_slot_collisions(graph, provider)  # must not raise


class TestContentHashShortCircuit:
    """§3.3: same module slot, SAME content_hash → milpa's own
    same-bytes/different-origin differentiator, never a conflict."""

    def test_no_raise_when_identity_matches(self) -> None:
        a = _dep("pkg-a", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("pkg-b", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(
            slots_by_dep_name={
                "pkg-a": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
                "pkg-b": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
            }
        )

        check_import_slot_collisions(graph, provider)  # must not raise

    def test_raises_when_one_identity_is_none(self) -> None:
        """A missing identity can never be PROVEN equal — no short-circuit."""
        a = _dep("pkg-a", None, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("pkg-b", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(
            slots_by_dep_name={
                "pkg-a": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
                "pkg-b": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
            }
        )

        with pytest.raises(MilpaError) as exc_info:
            check_import_slot_collisions(graph, provider)
        assert exc_info.value.slug == RES_IMPORT_COLLISION


class TestDirectorySlotFloorRetainedAsPreFilter:
    """S6's floor (`check_directory_slot_collisions`) must still fire, FIRST,
    through the new S7 entry point — retained, not deleted (§4.6/G9)."""

    def test_directory_slot_collision_still_raises(self) -> None:
        a = _dep("foo", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("foo", _HASH_B, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))
        # A provider that reports NO overlapping modules at all — if S7's
        # symbol-level scan were the only thing running, this would NOT
        # raise. The S6 pre-filter must catch it before the provider's
        # answer is even relevant.
        provider = _FakeProvider(slots_by_dep_name={})

        with pytest.raises(MilpaError) as exc_info:
            check_import_slot_collisions(graph, provider)
        assert exc_info.value.slug == RES_IMPORT_COLLISION

    def test_directory_slot_short_circuit_still_holds(self) -> None:
        """Same slot, same identity — S6's own short-circuit still applies
        via the S7 entry point (never regressed)."""
        a = _dep("chronos", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("chronos", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(slots_by_dep_name={})

        check_import_slot_collisions(graph, provider)  # must not raise


class TestExemptPairs:
    """``_is_exempt_pair``'s two documented exemptions — the fix for the
    false positives a naive whole-tree scan produced against unrelated,
    already-correct behavior (registry-namespaced sibling packages;
    a dep and its own direct dependency) sharing a coincidental module
    name."""

    def test_different_registry_namespaces_exempt(self) -> None:
        a = _dep(
            "bar", _HASH_A, namespace="ns1",
            source_id=normalize_source(GitSourceId(url="https://example.com/a.git")),
        )
        b = _dep(
            "bar", _HASH_B, namespace="ns2",
            source_id=normalize_source(GitSourceId(url="https://example.com/b.git")),
        )
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(
            slots_by_dep_name={
                "bar": frozenset({ImportSlot(module="bar", fidelity="tree_scanned")}),
            }
        )
        check_import_slot_collisions(graph, provider)  # must not raise

    def test_same_registry_namespace_not_exempt(self) -> None:
        """Only DIFFERENT non-None namespaces are exempt — two deps sharing
        the SAME namespace get no special treatment (dep_dir_name would
        already collide for them anyway, but the exemption predicate itself
        must not over-broadly match same-namespace pairs)."""
        a = _dep(
            "bar", _HASH_A, namespace="ns1",
            source_id=normalize_source(GitSourceId(url="https://example.com/a.git")),
        )
        b = _dep(
            "baz", _HASH_B, namespace="ns1",
            source_id=normalize_source(GitSourceId(url="https://example.com/b.git")),
        )
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(
            slots_by_dep_name={
                "bar": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
                "baz": frozenset({ImportSlot(module="shared", fidelity="tree_scanned")}),
            }
        )
        with pytest.raises(MilpaError) as exc_info:
            check_import_slot_collisions(graph, provider)
        assert exc_info.value.slug == RES_IMPORT_COLLISION

    def test_direct_requires_edge_exempt(self) -> None:
        """t1 requires foo (direct edge) — a coexistence the consumer's own
        dependency graph explicitly chose; a coincidental shared module name
        between them is exempt."""
        foo = _dep(
            "foo", _HASH_A,
            source_id=normalize_source(GitSourceId(url="https://example.com/foo.git")),
        )
        t1 = _dep(
            "t1", _HASH_B, requires=("foo",),
            source_id=normalize_source(GitSourceId(url="https://example.com/t1.git")),
        )
        graph = ResolvedGraph(deps=(foo, t1))
        provider = _FakeProvider(
            slots_by_dep_name={
                "foo": frozenset({ImportSlot(module="marker", fidelity="tree_scanned")}),
                "t1": frozenset({ImportSlot(module="marker", fidelity="tree_scanned")}),
            }
        )
        check_import_slot_collisions(graph, provider)  # must not raise

    def test_unconnected_siblings_not_exempt(self) -> None:
        """Two root-level siblings with NO requires edge and NO namespace —
        the actual headline-shape threat — are NOT exempt."""
        a = _dep("pkg-a", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("pkg-b", _HASH_B, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))
        provider = _FakeProvider(
            slots_by_dep_name={
                "pkg-a": frozenset({ImportSlot(module="marker", fidelity="tree_scanned")}),
                "pkg-b": frozenset({ImportSlot(module="marker", fidelity="tree_scanned")}),
            }
        )
        with pytest.raises(MilpaError) as exc_info:
            check_import_slot_collisions(graph, provider)
        assert exc_info.value.slug == RES_IMPORT_COLLISION


class TestLiveSymbolProvider:
    """``live_symbol_provider()`` — the conservative default the 4 real
    call sites actually wire in (manifest_declared fidelity only)."""

    def test_live_symbol_provider_is_manifest_declared_only(self) -> None:
        assert isinstance(live_symbol_provider(), ManifestDeclaredSymbolProvider)

    def test_default_symbol_provider_is_the_full_composition(self) -> None:
        """``default_symbol_provider()`` stays the COMPLETE RFC-specified
        composition — distinct from what the live call sites use."""
        assert isinstance(default_symbol_provider(), ComposedSymbolProvider)


# ---------------------------------------------------------------------------
# 2. ManifestDeclaredSymbolProvider — real temp milpa.kdl reads
# ---------------------------------------------------------------------------


class TestManifestDeclaredSymbolProvider:
    def test_reads_provides_block(self, tmp_path: Path) -> None:
        (tmp_path / "milpa.kdl").write_text(
            'name "foo"\nkind "library"\nprovides {\n    module "foo"\n    module "foo/bar"\n}\n',
            encoding="utf-8",
        )
        provider = ManifestDeclaredSymbolProvider()
        slots = provider.import_slots_for(None, tmp_path)
        assert slots == frozenset(
            {
                ImportSlot(module="foo", fidelity="manifest_declared"),
                ImportSlot(module="foo/bar", fidelity="manifest_declared"),
            }
        )

    def test_no_milpa_kdl_returns_empty(self, tmp_path: Path) -> None:
        provider = ManifestDeclaredSymbolProvider()
        assert provider.import_slots_for(None, tmp_path) == frozenset()

    def test_milpa_kdl_with_no_provides_block_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "milpa.kdl").write_text('name "foo"\nkind "library"\n', encoding="utf-8")
        provider = ManifestDeclaredSymbolProvider()
        assert provider.import_slots_for(None, tmp_path) == frozenset()

    def test_malformed_milpa_kdl_returns_empty_not_raise(self, tmp_path: Path) -> None:
        (tmp_path / "milpa.kdl").write_text("this is not { valid kdl", encoding="utf-8")
        provider = ManifestDeclaredSymbolProvider()
        assert provider.import_slots_for(None, tmp_path) == frozenset()


# ---------------------------------------------------------------------------
# 3. FetchedTreeSymbolProvider — real temp tree scan
# ---------------------------------------------------------------------------


class TestFetchedTreeSymbolProvider:
    def test_scans_nim_files_at_root(self, tmp_path: Path) -> None:
        (tmp_path / "foo.nim").write_text("# foo\n", encoding="utf-8")
        (tmp_path / "bar.nim").write_text("# bar\n", encoding="utf-8")
        (tmp_path / "README.md").write_text("not nim\n", encoding="utf-8")
        provider = FetchedTreeSymbolProvider()
        slots = provider.import_slots_for(None, tmp_path)
        assert slots == frozenset(
            {
                ImportSlot(module="foo", fidelity="tree_scanned"),
                ImportSlot(module="bar", fidelity="tree_scanned"),
            }
        )

    def test_scans_nested_nim_files(self, tmp_path: Path) -> None:
        nested = tmp_path / "src" / "sub"
        nested.mkdir(parents=True)
        (nested / "deep.nim").write_text("# deep\n", encoding="utf-8")
        provider = FetchedTreeSymbolProvider()
        slots = provider.import_slots_for(None, tmp_path)
        assert slots == frozenset({ImportSlot(module="deep", fidelity="tree_scanned")})

    def test_nonexistent_path_returns_empty(self, tmp_path: Path) -> None:
        provider = FetchedTreeSymbolProvider()
        assert provider.import_slots_for(None, tmp_path / "does-not-exist") == frozenset()

    def test_no_nim_files_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("nothing nim here\n", encoding="utf-8")
        provider = FetchedTreeSymbolProvider()
        assert provider.import_slots_for(None, tmp_path) == frozenset()


# ---------------------------------------------------------------------------
# 4. ComposedSymbolProvider — declared-beats-inferred
# ---------------------------------------------------------------------------


class TestComposedSymbolProvider:
    """Manifest-declared beats tree-scanned: fidelity precedence."""

    def test_declared_wins_over_scanned_even_when_scan_disagrees(self, tmp_path: Path) -> None:
        # The tree scan WOULD find "decoy" — but the manifest declares "x",
        # and declared must win outright (not merge).
        (tmp_path / "milpa.kdl").write_text(
            'name "foo"\nprovides {\n    module "x"\n}\n', encoding="utf-8"
        )
        (tmp_path / "decoy.nim").write_text("# decoy\n", encoding="utf-8")

        composed = ComposedSymbolProvider(
            declared=ManifestDeclaredSymbolProvider(),
            scanned=FetchedTreeSymbolProvider(),
        )
        slots = composed.import_slots_for(None, tmp_path)
        assert slots == frozenset({ImportSlot(module="x", fidelity="manifest_declared")})
        assert all(s.fidelity == "manifest_declared" for s in slots)

    def test_falls_back_to_scanned_when_nothing_declared(self, tmp_path: Path) -> None:
        (tmp_path / "foo.nim").write_text("# foo\n", encoding="utf-8")
        composed = ComposedSymbolProvider(
            declared=ManifestDeclaredSymbolProvider(),
            scanned=FetchedTreeSymbolProvider(),
        )
        slots = composed.import_slots_for(None, tmp_path)
        assert slots == frozenset({ImportSlot(module="foo", fidelity="tree_scanned")})

    def test_default_symbol_provider_is_composed(self) -> None:
        provider = default_symbol_provider()
        assert isinstance(provider, ComposedSymbolProvider)


# ---------------------------------------------------------------------------
# End-to-end: the composed provider + checker together, over real temp trees,
# with an injected CAStore (exercises _materialized_path_for's real branch).
# ---------------------------------------------------------------------------


class TestEndToEndWithRealStore:
    def test_cross_slot_collision_detected_via_real_store_and_composed_provider(
        self, tmp_path: Path
    ) -> None:
        from milpa.cas import CAStore
        from milpa.identity import compute_content_hash

        store = CAStore(tmp_path / ".cas")
        store.root.mkdir(parents=True, exist_ok=True)

        tree_a = tmp_path / "tree-a"
        tree_a.mkdir()
        (tree_a / "shared.nim").write_text("# a\n", encoding="utf-8")
        id_a = compute_content_hash(tree_a)
        store.admit(tree_a, id_a)

        tree_b = tmp_path / "tree-b"
        tree_b.mkdir()
        (tree_b / "shared.nim").write_text("# b (different bytes)\n", encoding="utf-8")
        id_b = compute_content_hash(tree_b)
        store.admit(tree_b, id_b)

        a = _dep("pkg-a", id_a, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("pkg-b", id_b, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))

        with pytest.raises(MilpaError) as exc_info:
            check_import_slot_collisions(graph, default_symbol_provider(), store=store)
        assert exc_info.value.slug == RES_IMPORT_COLLISION

    def test_identical_bytes_via_real_store_does_not_raise(self, tmp_path: Path) -> None:
        from milpa.cas import CAStore
        from milpa.identity import compute_content_hash

        store = CAStore(tmp_path / ".cas")
        store.root.mkdir(parents=True, exist_ok=True)

        tree_a = tmp_path / "tree-a"
        tree_a.mkdir()
        (tree_a / "shared.nim").write_text("# identical\n", encoding="utf-8")
        identity = compute_content_hash(tree_a)
        store.admit(tree_a, identity)

        tree_b = tmp_path / "tree-b"
        tree_b.mkdir()
        (tree_b / "shared.nim").write_text("# identical\n", encoding="utf-8")
        # Re-admitting byte-identical content under the SAME computed
        # identity is the CAS-hit no-op path — both deps legitimately share
        # one identity, milpa's §3.3 differentiator.
        assert compute_content_hash(tree_b) == identity

        a = _dep("pkg-a", identity, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("pkg-b", identity, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))

        check_import_slot_collisions(graph, default_symbol_provider(), store=store)  # must not raise
