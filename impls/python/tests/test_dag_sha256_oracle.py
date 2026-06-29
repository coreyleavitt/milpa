"""Self-test for the frozen epoch-2 ``dag-sha256:`` Merkle-DAG oracle.

RFC ``rfc-identity-conformance-authority`` slice B1; ``spec/identity.md`` §1.8.

This test proves the **standalone reference oracle**
(``conformance/spec-v1/_oracle/dag_sha256_reference.py``) is internally
consistent and frozen: it reproduces the two pinned digests that the epoch-2
conformance fixtures carry. It deliberately does **NOT** touch milpa's identity
implementation (``milpa.identity`` / the Rust core) — an oracle that shares code
with the impl cannot catch a bug shared by both impls (the differential blind
spot, [[testing_differential_blind_spot]]). The oracle is the cross-impl anchor
that B2 implements against; this test pins the anchor.

The fixtures are SKIPPED by the conformance runners until B2 (the impls still
emit the interim epoch-1 flat digest), so this is the only place the epoch-2
pins are actively asserted in the suite — and it asserts them against the
hand-frozen reference, not against milpa.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

# Repo root: impls/python/tests → parents[3].
_REPO_ROOT = Path(__file__).resolve().parents[3]
_CORPUS = _REPO_ROOT / "conformance" / "spec-v1"
_ORACLE_PY = _CORPUS / "_oracle" / "dag_sha256_reference.py"

# The two frozen pins (also stored in each fixture's expected/content_hash).
_EMPTY_ROOT_PIN = "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_NESTED_PIN = "dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f"

_EMPTY_FIXTURE = _CORPUS / "fixture-329-dag-oracle-empty-root"
_NESTED_FIXTURE = _CORPUS / "fixture-330-dag-oracle-nested-leafsort"


def _load_oracle():
    """Import the standalone reference by path WITHOUT importing milpa.

    The reference lives under conformance/ and is not part of the milpa package;
    we load it as an isolated module so this test cannot accidentally exercise
    milpa's identity code path.
    """
    spec = importlib.util.spec_from_file_location("_dag_sha256_reference", _ORACLE_PY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _expected_content_hash(fixture_dir: Path) -> str:
    return (fixture_dir / "expected" / "content_hash").read_text(encoding="utf-8").strip()


def test_oracle_does_not_import_milpa() -> None:
    """The reference must stay independent of the impl (SSOT discipline).

    Parsed with ``ast`` (not substring matching) so a docstring that *mentions*
    milpa does not trip the guard — only a real ``import``/``from`` statement
    naming milpa fails.
    """
    import ast

    tree = ast.parse(_ORACLE_PY.read_text(encoding="utf-8"))
    offending: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offending += [a.name for a in node.names if a.name.split(".")[0] == "milpa"]
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] == "milpa":
                offending.append(node.module)
    assert not offending, f"oracle must not import milpa, found: {offending}"


def test_oracle_reproduces_empty_root_pin() -> None:
    """The empty source tree hashes to dag-sha256:e3b0c442…b855 (= sha256(b''))."""
    oracle = _load_oracle()
    got = oracle.compute_for_fixture(_EMPTY_FIXTURE)
    assert got == _EMPTY_ROOT_PIN
    assert got == _expected_content_hash(_EMPTY_FIXTURE)
    # Independent cross-check: the empty-root digest is exactly sha256 of "".
    assert got == "dag-sha256:" + hashlib.sha256(b"").hexdigest()


def test_oracle_reproduces_nested_leafsort_pin() -> None:
    """The 2-level leaf-name-sort fixture hashes to the frozen nested pin."""
    oracle = _load_oracle()
    got = oracle.compute_for_fixture(_NESTED_FIXTURE)
    assert got == _NESTED_PIN
    assert got == _expected_content_hash(_NESTED_FIXTURE)


def test_nested_fixture_actually_exercises_leafsort_divergence() -> None:
    """Guard: the nested fixture's leaf-name order must differ from full-path order.

    This is the property that makes the fixture catch the top cross-impl bug
    (§1.8.3). If a future edit makes the two orders coincide, the fixture stops
    being a divergence anchor — fail loudly so it is re-designed, not silently
    weakened.
    """
    import json

    entries = json.loads((_NESTED_FIXTURE / "dag-oracle.json").read_text())["entries"]
    relpaths = [e["relpath"] for e in entries if ".git" not in e["relpath"].split("/")]

    # Root-level immediate children (the level where the divergence lives).
    def root_child(rp: str) -> tuple[str, bool]:
        head = rp.split("/", 1)[0]
        is_dir = "/" in rp
        return head, is_dir

    children = {root_child(rp) for rp in relpaths}
    # Full-relpath order of the root children, as a materializer would stream them.
    full_path_order = [
        root_child(rp) for rp in sorted(relpaths, key=lambda s: s.encode("utf-8"))
    ]
    # De-dup preserving first appearance (full-path stream order of distinct children).
    seen: list[tuple[str, bool]] = []
    for c in full_path_order:
        if c not in seen:
            seen.append(c)
    # Correct per-level leaf-name order.
    leaf_order = sorted(children, key=lambda c: c[0].encode("utf-8"))

    assert seen != leaf_order, (
        "nested fixture no longer exercises the leaf-name-vs-full-path sort "
        f"divergence: stream order {seen} == leaf order {leaf_order}"
    )
    # And concretely: a subdirectory must sort before a sibling file whose name
    # extends the directory name (the `a` vs `a.txt` case).
    assert ("a", True) in children and ("a.txt", False) in children


def test_oracle_self_test_module_loads_independently() -> None:
    """Smoke: the reference computes a 64-hex dag-sha256 for an ad-hoc tree."""
    oracle = _load_oracle()
    out = oracle.compute_dag_sha256(
        [{"relpath": "x", "mode": "regular", "content": "hi"}]
    )
    assert out.startswith("dag-sha256:")
    assert len(out) == len("dag-sha256:") + 64


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
