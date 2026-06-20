"""S5b/S6 — Phase-A error-slug regression (workspace-completion RFC §3.B).

S5b spike confirmed: both Python and Rust previously emitted
``TNG-NO-SATISFYING-VERSION`` on the §3.B error-path case (dep requires
``foo >= 2.0.0``, index has only 1.x).

S6 fix: both impls now enumerate-all at Phase A (resolver-semantics §2.1) and
emit the canonical ``SOLVE-CONFLICT``.  The solver, not the enumerator, owns
satisfiability.  See corpus fixture-261 for the canonical cross-impl assertion.

This test serves as an in-process regression guard for the Python path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import SOLVE_CONFLICT
from milpa.fetchers.mocked import mocked_registry
from milpa.manifest import Manifest, NamedDep
from milpa.registry import GitIndexProvenance, Index, IndexVersion, Package
from milpa.resolver import resolve
from milpa.version import Strategy


def _make_env(tmp_path: Path, index: Index) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    # No fetcher mocks needed: Phase A errors before any fetch.
    # The mocked_registry needs an existing dir (it scans it); create an empty one.
    mocked_dir = tmp_path / "no-mocked-fetches"
    mocked_dir.mkdir(parents=True, exist_ok=True)
    fetcher = mocked_registry(mocked_dir)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _manifest(deps: list) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=deps,
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _index_with_foo_1x() -> Index:
    """An index with foo at 1.0.0 only — cannot satisfy foo >= 2.0.0."""
    return Index(
        packages=[
            Package(
                name="foo",
                namespace="",
                versions=(
                    IndexVersion(
                        version="1.0.0",
                        content_hash="sha256:0000000000000000000000000000000000000000000000000000000000000001",
                        provenances=(
                            GitIndexProvenance(
                                url="https://example.com/foo.git",
                                ref="v1.0.0",
                                commit_sha=None,
                            ),
                        ),
                    ),
                ),
            )
        ]
    )


def test_s6_enumerate_all_yields_solve_conflict(tmp_path: Path) -> None:
    """S6: enumerate-all normative — SOLVE-CONFLICT for unsatisfiable constraint.

    dep requires foo >= 2.0.0 but the index has only foo 1.0.0.  After the
    S6 fix (pre-check at resolver.py:1378 removed, enumerate-all normative per
    resolver-semantics §2.1), the solver sees all 1.x stubs and accumulates the
    foo >= 2.0.0 incompatibility, yielding SOLVE-CONFLICT.

    S5b spike confirmed TNG-NO-SATISFYING-VERSION as the pre-S6 baseline for both
    Python (BFS pre-check) and Rust (process_named constraint filter).
    """
    dep = NamedDep(name="foo", constraint=">= 2.0.0")
    m = _manifest([dep])
    env = _make_env(tmp_path, _index_with_foo_1x())
    params = ResolveParams(strategy=Strategy.MAXVER)

    with pytest.raises(Exception) as exc_info:
        resolve(m, tmp_path / "_deps", env, params)

    err = exc_info.value
    assert err.slug == SOLVE_CONFLICT, (
        f"S6 enumerate-all normative: expected SOLVE-CONFLICT, got {err.slug!r}"
    )
