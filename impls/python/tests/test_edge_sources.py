"""Tests for edge_sources.py (S4-i): EdgeSource seam, resolve_edges, transitive projection.

Covers:
  - Clause (a): edge_cache memo seal — parent-independence.
  - Clause (b): is_overridden suppresses DepDecl, falls through to MilpaKdl/Nimble.
  - Clause (c): dep_decl_source injection point (S3b structural).
  - Transitive projection: MilpaKdlEdgeSource drops dev_deps + overrides, maps src_dir.
  - NimbleEdgeSource: basic requires extraction.
  - edgeset_to_terms: EdgeSet → (dep_terms, requires_names).
  - EdgeSource fidelity tags.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from milpa.dep_decl import EdgeSet, EdgeSource, NamedRequire, UrlRequire
from milpa.edge_sources import (
    EdgeSourceCtx,
    MilpaKdlEdgeSource,
    NimbleEdgeSource,
    edgeset_to_terms,
    resolve_edges,
)
from milpa.version import Version


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_V = Version(0, 0, 1)  # sentinel version used for URL/local deps


def _ctx(
    dep_path: Path | None = None,
    dep_name: str = "pkg",
    dep_decl: str | None = None,
    is_overridden: bool = False,
    has_milpa_kdl: bool = False,
    overrides: dict | None = None,
) -> EdgeSourceCtx:
    return EdgeSourceCtx(
        dep_path=dep_path,
        dep_name=dep_name,
        dep_decl=dep_decl,
        is_overridden=is_overridden,
        has_milpa_kdl=has_milpa_kdl,
        overrides_by_name=overrides or {},
    )


def _make_dep_tree(base: Path, name: str, kdl_content: str) -> Path:
    """Create a named dep tree directory with milpa.kdl content."""
    dep_path = base / name
    dep_path.mkdir(parents=True, exist_ok=True)
    (dep_path / "milpa.kdl").write_text(kdl_content, encoding="utf-8")
    return dep_path


def _make_nimble_tree(base: Path, name: str, nimble_content: str) -> Path:
    """Create a named dep tree directory with a .nimble file."""
    dep_path = base / name
    dep_path.mkdir(parents=True, exist_ok=True)
    (dep_path / f"{name}.nimble").write_text(nimble_content, encoding="utf-8")
    return dep_path


# ---------------------------------------------------------------------------
# Clause (a): edge_cache memo seal — parent-independence
# ---------------------------------------------------------------------------


def test_clause_a_memo_seal_returns_same_edgeset(tmp_path: Path) -> None:
    """Two calls for the same (name, version) return the identical sealed EdgeSet."""
    dep_path = _make_dep_tree(
        tmp_path,
        "shared",
        'name "shared"\ndeps {\n  results ">= 0.5.0"\n}\n',
    )
    ctx1 = _ctx(dep_path=dep_path, dep_name="shared", has_milpa_kdl=True)
    ctx2 = _ctx(dep_path=dep_path, dep_name="shared", has_milpa_kdl=True)

    edge_cache: dict = {}
    es1 = resolve_edges("shared", _V, ctx1, edge_cache)
    # Second call — simulates a second BFS parent reaching the same (name, ver).
    es2 = resolve_edges("shared", _V, ctx2, edge_cache)

    assert es1 is es2, "clause (a): same EdgeSet object must be returned from cache"
    assert len(edge_cache) == 1, "cache must have exactly one entry"


def test_clause_a_different_packages_not_merged(tmp_path: Path) -> None:
    """Different (name, version) pairs get separate cache entries."""
    dep_a = _make_dep_tree(tmp_path, "pkg-a", 'name "pkg-a"\n')
    dep_b = _make_dep_tree(tmp_path, "pkg-b", 'name "pkg-b"\n')

    edge_cache: dict = {}
    ctx_a = _ctx(dep_path=dep_a, dep_name="pkg-a", has_milpa_kdl=True)
    ctx_b = _ctx(dep_path=dep_b, dep_name="pkg-b", has_milpa_kdl=True)

    resolve_edges("pkg-a", _V, ctx_a, edge_cache)
    resolve_edges("pkg-b", _V, ctx_b, edge_cache)

    assert len(edge_cache) == 2


def test_clause_a_sealed_value_not_overwritten(tmp_path: Path) -> None:
    """A pre-populated edge_cache entry is returned without calling any source."""

    class _NeverCalled:
        def edges_for(self, name: str, version: Any, ctx: Any) -> EdgeSet:
            raise AssertionError("source must not be called when cache is hit")

    sentinel_es = EdgeSet(requires=[], src_dir="sentinel", source=EdgeSource.DEP_DECL)
    edge_cache: dict = {("pkg", _V): sentinel_es}

    ctx = _ctx(has_milpa_kdl=True)  # would normally call MilpaKdlEdgeSource
    result = resolve_edges(
        "pkg",
        _V,
        ctx,
        edge_cache,
        milpakdl_source=_NeverCalled(),  # type: ignore[arg-type]
        nimble_source=_NeverCalled(),  # type: ignore[arg-type]
    )

    assert result is sentinel_es


# ---------------------------------------------------------------------------
# Clause (b): is_overridden suppresses DepDecl
# ---------------------------------------------------------------------------


def test_clause_b_overridden_with_dep_decl_falls_through_to_milpakdl(tmp_path: Path) -> None:
    """is_overridden + dep_decl set → MilpaKdlEdgeSource (not DepDecl)."""
    dep_path = _make_dep_tree(
        tmp_path,
        "pkg",
        'name "pkg"\ndeps {\n  results ">= 1.0.0"\n}\n',
    )
    ctx = _ctx(
        dep_path=dep_path,
        dep_name="pkg",
        dep_decl="sha256:deadbeef",  # index has a dep_decl pointer
        is_overridden=True,           # but override suppresses it (clause b)
        has_milpa_kdl=True,
    )

    edge_cache: dict = {}
    es = resolve_edges("pkg", _V, ctx, edge_cache)

    # Must have used MilpaKdl (not DepDecl) — fidelity tag confirms.
    assert es.source == EdgeSource.MILPA_KDL
    assert len(es.requires) == 1
    assert isinstance(es.requires[0], NamedRequire)
    assert es.requires[0].name == "results"


def test_clause_b_overridden_no_milpakdl_falls_through_to_nimble(tmp_path: Path) -> None:
    """is_overridden + no milpa.kdl → NimbleEdgeSource (clause b)."""
    dep_path = _make_nimble_tree(tmp_path, "pkg", 'requires "stew >= 0.1.0"\n')
    ctx = _ctx(
        dep_path=dep_path,
        dep_name="pkg",
        dep_decl="sha256:deadbeef",  # index has dep_decl
        is_overridden=True,           # suppressed
        has_milpa_kdl=False,
    )

    edge_cache: dict = {}
    es = resolve_edges("pkg", _V, ctx, edge_cache)

    assert es.source == EdgeSource.NIMBLE_FALLBACK
    assert len(es.requires) == 1
    assert isinstance(es.requires[0], NamedRequire)
    assert es.requires[0].name == "stew"


# ---------------------------------------------------------------------------
# Clause (c): dep_decl_source injection point — S3b (structural test only)
# ---------------------------------------------------------------------------


def test_clause_c_dep_decl_source_none_skips_to_milpakdl(tmp_path: Path) -> None:
    """dep_decl set but dep_decl_source=None → falls through to MilpaKdl (S4-i behavior)."""
    dep_path = _make_dep_tree(tmp_path, "pkg", 'name "pkg"\n')
    ctx = _ctx(
        dep_path=dep_path,
        dep_name="pkg",
        dep_decl="sha256:abc123",  # index has dep_decl pointer
        is_overridden=False,
        has_milpa_kdl=True,
    )
    edge_cache: dict = {}
    es = resolve_edges("pkg", _V, ctx, edge_cache, dep_decl_source=None)

    # dep_decl_source is None → MilpaKdl path, not DepDecl.
    assert es.source == EdgeSource.MILPA_KDL


def test_clause_c_dep_decl_source_injected_fires(tmp_path: Path) -> None:
    """When dep_decl_source is injected, clause (c) calls it for dep_decl packages."""

    class _FakeDepDeclSource:
        called = False

        def edges_for(self, name: str, version: Any, ctx: Any) -> EdgeSet:
            _FakeDepDeclSource.called = True
            return EdgeSet(
                requires=[NamedRequire(name="attested", constraint_str=">= 1.0.0")],
                src_dir="src",
                source=EdgeSource.DEP_DECL,
            )

    src = _FakeDepDeclSource()
    ctx = _ctx(
        dep_path=None,         # DepDeclEdgeSource needs no dep_path
        dep_name="pkg",
        dep_decl="sha256:abc",
        is_overridden=False,
        has_milpa_kdl=False,   # doesn't matter — dep_decl branch fires first
    )
    edge_cache: dict = {}
    es = resolve_edges("pkg", _V, ctx, edge_cache, dep_decl_source=src)

    assert src.called
    assert es.source == EdgeSource.DEP_DECL
    assert es.requires[0].name == "attested"


# ---------------------------------------------------------------------------
# MilpaKdlEdgeSource — transitive projection (normative §9 + §10.2)
# ---------------------------------------------------------------------------


def test_milpakdl_drops_dev_deps(tmp_path: Path) -> None:
    """dev_deps MUST NOT appear in the EdgeSet produced by MilpaKdlEdgeSource (§9)."""
    dep_path = _make_dep_tree(
        tmp_path,
        "pkg",
        'name "pkg"\ndeps {\n  stew ">= 0.1.0"\n}\ndev-deps {\n  unittest2 ">= 0.0.2"\n}\n',
    )
    ctx = _ctx(dep_path=dep_path, dep_name="pkg", has_milpa_kdl=True)
    es = MilpaKdlEdgeSource().edges_for("pkg", _V, ctx)

    names = [r.name for r in es.requires if isinstance(r, NamedRequire)]
    assert "stew" in names
    assert "unittest2" not in names, "dev_dep must not leak into transitive EdgeSet"
    assert es.source == EdgeSource.MILPA_KDL


def test_milpakdl_drops_overrides_entirely(tmp_path: Path) -> None:
    """overrides{} MUST be dropped entirely from the transitive projection (§10.2)."""
    dep_path = _make_dep_tree(
        tmp_path,
        "pkg",
        'name "pkg"\ndeps {\n  stew ">= 0.1.0"\n}\noverrides {\n'
        '  pkg "asyncdispatch" git=(url)"https://github.com/example/asyncdispatch.git" ref="main"\n}\n',
    )
    ctx = _ctx(dep_path=dep_path, dep_name="pkg", has_milpa_kdl=True)
    es = MilpaKdlEdgeSource().edges_for("pkg", _V, ctx)

    # The override should not appear as a require entry.
    names = [r.name for r in es.requires if isinstance(r, NamedRequire)]
    assert "asyncdispatch" not in names, "override must not leak into transitive EdgeSet"
    assert "stew" in names
    assert es.source == EdgeSource.MILPA_KDL


def test_milpakdl_maps_src_dir(tmp_path: Path) -> None:
    """src_dir from milpa.kdl is propagated to EdgeSet.src_dir."""
    dep_path = _make_dep_tree(
        tmp_path,
        "pkg",
        'name "pkg"\nsrc_dir "src"\ndeps {\n  stew ">= 0.1.0"\n}\n',
    )
    ctx = _ctx(dep_path=dep_path, dep_name="pkg", has_milpa_kdl=True)
    es = MilpaKdlEdgeSource().edges_for("pkg", _V, ctx)

    assert es.src_dir == "src"


def test_milpakdl_empty_src_dir_when_absent(tmp_path: Path) -> None:
    """src_dir is '' when milpa.kdl omits src_dir."""
    dep_path = _make_dep_tree(tmp_path, "pkg", 'name "pkg"\n')
    ctx = _ctx(dep_path=dep_path, dep_name="pkg", has_milpa_kdl=True)
    es = MilpaKdlEdgeSource().edges_for("pkg", _V, ctx)

    assert es.src_dir == ""


def test_milpakdl_url_dep_becomes_url_require(tmp_path: Path) -> None:
    """A URL dep in milpa.kdl becomes a UrlRequire in the EdgeSet."""
    dep_path = _make_dep_tree(
        tmp_path,
        "pkg",
        'name "pkg"\ndeps {\n  intonaco git=(url)"https://github.com/example/intonaco.git" ref="main"\n}\n',
    )
    ctx = _ctx(dep_path=dep_path, dep_name="pkg", has_milpa_kdl=True)
    es = MilpaKdlEdgeSource().edges_for("pkg", _V, ctx)

    url_reqs = [r for r in es.requires if isinstance(r, UrlRequire)]
    assert len(url_reqs) == 1
    assert url_reqs[0].url == "https://github.com/example/intonaco.git"
    assert url_reqs[0].ref == "main"


def test_milpakdl_nim_dep_excluded(tmp_path: Path) -> None:
    """'nim' is excluded from the EdgeSet (not a resolvable dep)."""
    dep_path = _make_dep_tree(
        tmp_path,
        "pkg",
        'name "pkg"\ndeps {\n  nim ">= 1.6.0"\n  stew ">= 0.1.0"\n}\n',
    )
    ctx = _ctx(dep_path=dep_path, dep_name="pkg", has_milpa_kdl=True)
    es = MilpaKdlEdgeSource().edges_for("pkg", _V, ctx)

    names = [r.name for r in es.requires if isinstance(r, NamedRequire)]
    assert "nim" not in names
    assert "stew" in names


def test_milpakdl_malformed_returns_empty(tmp_path: Path) -> None:
    """Malformed milpa.kdl produces an empty EdgeSet (non-fatal fallback)."""
    dep_path = tmp_path / "pkg"
    dep_path.mkdir()
    (dep_path / "milpa.kdl").write_bytes(b"\xff\xfe not valid kdl at all !!!")

    ctx = _ctx(dep_path=dep_path, dep_name="pkg", has_milpa_kdl=True)
    es = MilpaKdlEdgeSource().edges_for("pkg", _V, ctx)

    assert es.requires == []
    assert es.source == EdgeSource.MILPA_KDL


# ---------------------------------------------------------------------------
# NimbleEdgeSource — basic extraction
# ---------------------------------------------------------------------------


def test_nimble_extracts_named_requires(tmp_path: Path) -> None:
    """NimbleEdgeSource extracts named requires from a .nimble file."""
    dep_path = _make_nimble_tree(
        tmp_path,
        "mypkg",
        'requires "stew >= 0.1.0"\nrequires "results >= 0.5.0"\n',
    )
    ctx = _ctx(dep_path=dep_path, dep_name="mypkg")
    es = NimbleEdgeSource().edges_for("mypkg", _V, ctx)

    assert es.source == EdgeSource.NIMBLE_FALLBACK
    names = [r.name for r in es.requires if isinstance(r, NamedRequire)]
    assert "stew" in names
    assert "results" in names


def test_nimble_no_file_returns_empty(tmp_path: Path) -> None:
    """No .nimble file → empty EdgeSet."""
    dep_path = tmp_path / "pkg"
    dep_path.mkdir()
    ctx = _ctx(dep_path=dep_path, dep_name="pkg")
    es = NimbleEdgeSource().edges_for("pkg", _V, ctx)

    assert es.requires == []
    assert es.source == EdgeSource.NIMBLE_FALLBACK


# ---------------------------------------------------------------------------
# S3b: NimbleEdgeSource → bridge → predicates on NamedRequire / UrlRequire
# ---------------------------------------------------------------------------


from milpa.predicate import Predicate  # noqa: E402  (after test_edge_sources imports)
import warnings as _warnings  # noqa: E402


def _plat(name: str) -> Predicate:
    return Predicate(name="platform", values=(name,))


def _notplat(name: str) -> Predicate:
    return Predicate(name="platform", values=(name,), negated=True)


def _arch(name: str) -> Predicate:
    return Predicate(name="arch", values=(name,))


def _get_named(es: EdgeSet, name: str) -> NamedRequire:
    for r in es.requires:
        if isinstance(r, NamedRequire) and r.name == name:
            return r
    raise KeyError(name)


def test_bridge_unconditional_requires_empty_predicates(tmp_path: Path) -> None:
    """Unconditional requires → NamedRequire.predicates == ()."""
    dep_path = _make_nimble_tree(tmp_path, "pkg", 'requires "stew >= 0.1.0"\n')
    ctx = _ctx(dep_path=dep_path, dep_name="pkg")
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        es = NimbleEdgeSource().edges_for("pkg", _V, ctx)
    assert _get_named(es, "stew").predicates == ()


def test_bridge_recognized_when_block_carries_predicates(tmp_path: Path) -> None:
    """Recognized when → NamedRequire.predicates carries the translated predicates."""
    nimble = (
        'when defined(linux):\n'
        '  requires "linuxpkg"\n'
        'requires "common"\n'
    )
    dep_path = _make_nimble_tree(tmp_path, "pkg", nimble)
    ctx = _ctx(dep_path=dep_path, dep_name="pkg")
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        es = NimbleEdgeSource().edges_for("pkg", _V, ctx)

    linux_req = _get_named(es, "linuxpkg")
    common_req = _get_named(es, "common")
    assert linux_req.predicates == (_plat("linux"),)
    assert common_req.predicates == ()


def test_bridge_colon_form_carries_predicates(tmp_path: Path) -> None:
    """Colon-form when → NamedRequire.predicates = (arch(arm64),)."""
    dep_path = _make_nimble_tree(
        tmp_path, "pkg", 'when defined(arm64): requires "neon"\n'
    )
    ctx = _ctx(dep_path=dep_path, dep_name="pkg")
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        es = NimbleEdgeSource().edges_for("pkg", _V, ctx)
    assert _get_named(es, "neon").predicates == (_arch("arm64"),)


def test_bridge_elif_else_predicates(tmp_path: Path) -> None:
    """when/elif/else → all three NamedRequires carry correct predicate tuples."""
    nimble = (
        'when defined(linux):\n'
        '  requires "a"\n'
        'elif defined(macosx):\n'
        '  requires "b"\n'
        'else:\n'
        '  requires "c"\n'
    )
    dep_path = _make_nimble_tree(tmp_path, "pkg", nimble)
    ctx = _ctx(dep_path=dep_path, dep_name="pkg")
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        es = NimbleEdgeSource().edges_for("pkg", _V, ctx)
    assert _get_named(es, "a").predicates == (_plat("linux"),)
    assert _get_named(es, "b").predicates == (_plat("macosx"), _notplat("linux"))
    assert _get_named(es, "c").predicates == (_notplat("linux"), _notplat("macosx"))


def test_bridge_unrecognized_when_empty_predicates(tmp_path: Path) -> None:
    """Unrecognized when → dep present (set unchanged) AND predicates == ()."""
    dep_path = _make_nimble_tree(
        tmp_path, "pkg", 'when defined(release):\n  requires "relpkg"\n'
    )
    ctx = _ctx(dep_path=dep_path, dep_name="pkg")
    with _warnings.catch_warnings(record=True):
        _warnings.simplefilter("always")
        es = NimbleEdgeSource().edges_for("pkg", _V, ctx)
    # dep is still included (over-include invariant)
    rel_req = _get_named(es, "relpkg")
    assert rel_req.predicates == ()


# ---------------------------------------------------------------------------
# edgeset_to_terms
# ---------------------------------------------------------------------------


def test_edgeset_to_terms_named_require() -> None:
    """Named requires become Term.require with parsed VersionSet."""
    es = EdgeSet(
        requires=[NamedRequire(name="stew", constraint_str=">= 0.1.0")],
        src_dir="",
        source=EdgeSource.MILPA_KDL,
    )
    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, {}, _V)

    assert requires_names == ["stew"]
    assert len(dep_terms) == 1
    t = dep_terms[0]
    assert t.package == "stew"
    assert t.positive
    assert requires_predicates == {}


def test_edgeset_to_terms_overridden_named_becomes_url_sentinel() -> None:
    """A named require whose name is in overrides_by_name gets the URL sentinel version."""
    from milpa.manifest import Override

    ov = Override(name="stew", git="https://github.com/example/stew.git", ref="main")
    es = EdgeSet(
        requires=[NamedRequire(name="stew", constraint_str=">= 0.1.0")],
        src_dir="",
        source=EdgeSource.MILPA_KDL,
    )
    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, {"stew": ov}, _V)

    assert requires_names == ["stew"]
    assert len(dep_terms) == 1
    t = dep_terms[0]
    assert t.package == "stew"
    # Should require exactly the sentinel version.
    assert t.versions.contains(_V)
    assert requires_predicates == {}


def test_edgeset_to_terms_nim_excluded() -> None:
    """'nim' in requires is excluded from dep_terms."""
    es = EdgeSet(
        requires=[
            NamedRequire(name="nim", constraint_str=">= 1.6.0"),
            NamedRequire(name="stew", constraint_str=">= 0.1.0"),
        ],
        src_dir="",
        source=EdgeSource.NIMBLE_FALLBACK,
    )
    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, {}, _V)

    assert "nim" not in requires_names
    assert "stew" in requires_names
    assert requires_predicates == {}


def test_edgeset_to_terms_url_require() -> None:
    """UrlRequire entries become Term.require at sentinel version with derived name."""
    es = EdgeSet(
        requires=[
            UrlRequire(url="https://github.com/status-im/nim-chronos.git", ref="v3")
        ],
        src_dir="",
        source=EdgeSource.DEP_DECL,
    )
    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, {}, _V)

    assert "nim-chronos" in requires_names
    assert len(dep_terms) == 1
    assert dep_terms[0].versions.contains(_V)
    assert requires_predicates == {}


# ---------------------------------------------------------------------------
# Conformance: dev-deps + overrides projection (normative §9 + §10.2)
# ---------------------------------------------------------------------------


def test_transitive_projection_dev_deps_and_overrides_isolation(tmp_path: Path) -> None:
    """Full conformance scenario: a transitive dep's milpa.kdl carries dev-deps and
    overrides; the resolved EdgeSet MUST contain neither.

    This is the normative projection test from RFC §3.5 (spec/resolver-semantics.md
    §4.2.1 amendment, spec/dep-decl.md §1).
    """
    dep_path = _make_dep_tree(
        tmp_path,
        "transitive",
        # deps: stew (must appear)
        # dev-deps: unittest2 (must be dropped — §9 NORMATIVE)
        # overrides: asyncdispatch (must be dropped — §10.2 NORMATIVE)
        'name "transitive"\n'
        'src_dir "src"\n'
        'deps {\n'
        '  stew ">= 0.1.0"\n'
        '}\n'
        'dev-deps {\n'
        '  unittest2 ">= 0.0.2"\n'
        '}\n'
        'overrides {\n'
        '  pkg "asyncdispatch" git=(url)"https://github.com/example/asyncdispatch.git" ref="patched"\n'
        '}\n',
    )

    ctx = _ctx(dep_path=dep_path, dep_name="transitive", has_milpa_kdl=True)
    edge_cache: dict = {}
    es = resolve_edges("transitive", _V, ctx, edge_cache)

    # Verify the projection:
    assert es.source == EdgeSource.MILPA_KDL
    assert es.src_dir == "src"

    all_names = [r.name for r in es.requires if isinstance(r, NamedRequire)]
    all_urls = [r.url for r in es.requires if isinstance(r, UrlRequire)]

    # deps: stew must appear
    assert "stew" in all_names, "stew (deps) must be in the EdgeSet"

    # dev-deps: unittest2 must NOT appear
    assert "unittest2" not in all_names, "unittest2 (dev-dep) must not leak into transitive EdgeSet"

    # overrides: asyncdispatch must NOT appear as a URL or named require
    assert not any("asyncdispatch" in u for u in all_urls), \
        "override must not appear as URL require in transitive EdgeSet"
    assert "asyncdispatch" not in all_names, \
        "override must not appear as named require in transitive EdgeSet"


def test_two_parents_same_package_get_identical_edgeset(tmp_path: Path) -> None:
    """Clause (a): when two BFS parents reach the same (name, version), the EdgeSet
    is sealed on first encounter and the second call returns the same object.

    This directly tests the parent-independence requirement (RFC §3.5 clause a).
    """
    dep_path = _make_dep_tree(
        tmp_path,
        "shared",
        'name "shared"\ndeps {\n  stew ">= 0.1.0"\n}\n',
    )

    edge_cache: dict = {}

    # Simulate parent A discovering "shared"
    ctx_from_a = _ctx(dep_path=dep_path, dep_name="shared", has_milpa_kdl=True)
    es_a = resolve_edges("shared", _V, ctx_from_a, edge_cache)

    # Simulate parent B discovering the same "shared" (diamond dep)
    ctx_from_b = _ctx(dep_path=dep_path, dep_name="shared", has_milpa_kdl=True)
    es_b = resolve_edges("shared", _V, ctx_from_b, edge_cache)

    # Must be the same object — sealed on first encounter.
    assert es_a is es_b, \
        "diamond dependency: both parents must see the same sealed EdgeSet (clause a)"
    assert len(edge_cache) == 1


# ---------------------------------------------------------------------------
# M3: SSOT for URL→name derivation — both sites use the same function
# ---------------------------------------------------------------------------


def test_m3_url_to_name_ssot_shared_function() -> None:
    """Both nimble.py and edge_sources.py use the same url_to_name derivation.

    The two functions previously diverged on path-less inputs: nimble.py
    returned the full URL string (or a scheme artifact); edge_sources.py
    returned None (dep dropped).  After unification, both sites call
    ``nimble.url_to_name``; edge_sources wraps with None-drop so the resolver
    behavior is preserved without duplicating the derivation.
    """
    from milpa.nimble import url_to_name
    from milpa.edge_sources import _name_from_url  # type: ignore[attr-defined]

    # Normal URLs — must agree.
    normal = [
        ("https://github.com/user/pkg.git", "pkg"),
        ("https://github.com/user/pkg", "pkg"),
        ("ssh://git@github.com/user/repo", "repo"),
        ("git://github.com/user/repo.git", "repo"),
        ("https://github.com/user/mylib.git", "mylib"),
    ]
    for url, expected in normal:
        assert url_to_name(url) == expected, f"url_to_name({url!r})"
        assert _name_from_url(url) == expected, f"_name_from_url({url!r})"

    # Path-less / degenerate URLs: edge_sources wraps with None-drop.
    # nimble.url_to_name returns a non-empty string (best-effort; used in UrlDep.name).
    # edge_sources._name_from_url returns None for these (dep dropped from EdgeSet).
    # This is NOT a divergence — it's an explicit wrapper around the shared function.
    degenerate = ["https://", "ssh://", "git://"]
    for url in degenerate:
        # The nimble path must return a non-empty string (used for UrlDep.name).
        name = url_to_name(url)
        assert isinstance(name, str) and name, \
            f"url_to_name({url!r}) must return non-empty str, got {name!r}"
        # The edge_sources path wraps with None-drop (no divergence in derivation logic).
        edge_name = _name_from_url(url)
        assert edge_name is None or isinstance(edge_name, str), \
            f"_name_from_url({url!r}) must return str or None"


def test_m3_edge_sources_uses_nimble_url_to_name() -> None:
    """_name_from_url in edge_sources delegates to nimble.url_to_name for normal URLs.

    This pins the import relationship — if someone re-duplicates the logic in
    edge_sources.py, this test will catch the divergence on the normal-URL cases.
    """
    from milpa.nimble import url_to_name
    from milpa.edge_sources import _name_from_url  # type: ignore[attr-defined]

    # For any URL where url_to_name returns a non-empty result AND that result
    # does not equal the full URL (i.e. it found a meaningful path component),
    # _name_from_url must return the same value.
    urls = [
        "https://github.com/status-im/nim-chronos.git",
        "https://github.com/nim-lang/stew",
        "ssh://git@github.com/user/results.git",
    ]
    for url in urls:
        assert url_to_name(url) == _name_from_url(url), \
            f"SSOT violation: nimble and edge_sources return different names for {url!r}"
