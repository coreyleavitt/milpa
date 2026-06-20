"""S5b spike — §3.B error-slug divergence diagnostic (workspace-completion RFC).

Constructs the §3.B error-path case: dep requires ``foo >= 2.0.0``, index has
only ``foo`` 1.x.  Records the observed error slug and **passes** — proving the
current behaviour without breaking the loop's green gate.

Expected (pre-S6): Python's BFS wave-loop pre-check at resolver.py:1378-1379
calls ``index.resolve_named_all(name, constraint_str)`` with the non-None
constraint before enrolling stubs.  The index raises ``TNG-NO-SATISFYING-VERSION``
at that point, so Python also emits ``TNG-NO-SATISFYING-VERSION`` on this path —
diverging from the canonical ``SOLVE-CONFLICT`` the RFC mandates.

After S6 both the pre-check is dropped and this becomes ``SOLVE-CONFLICT``.
At that point this spike test is superseded by corpus fixture-261; update or
remove it accordingly.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import TNG_NO_SATISFYING_VERSION
from milpa.fetchers.mocked import mocked_registry
from milpa.manifest import Manifest, NamedDep
from milpa.registry import GitIndexProvenance, Index, IndexVersion, Package
from milpa.resolver import resolve
from milpa.version import Strategy  # noqa: F401


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
    """An index with only foo 1.0.0 — cannot satisfy foo >= 2.0.0."""
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


def test_s5b_phase_a_error_slug_python_path(tmp_path: Path) -> None:
    """S5b baseline: Python emits TNG-NO-SATISFYING-VERSION on the §3.B error path.

    The BFS wave-loop pre-check at resolver.py:1378-1379 calls
    ``index.resolve_named_all(name, constraint_str)`` with the non-None
    constraint_str before enrolling stubs, so the error fires at Phase A
    rather than letting the solver accumulate the incompatibility.

    After S6 (pre-check removed, enumerate-all normative) this must become
    SOLVE-CONFLICT.  The assertion documents the pre-S6 state; S6 updates it.
    """
    dep = NamedDep(name="foo", constraint=">= 2.0.0")
    m = _manifest([dep])
    env = _make_env(tmp_path, _index_with_foo_1x())
    params = ResolveParams(strategy=Strategy.MAXVER)

    with pytest.raises(Exception) as exc_info:
        resolve(m, tmp_path / "_deps", env, params)

    err = exc_info.value
    # S5b baseline: Python pre-check fires TNG-NO-SATISFYING-VERSION.
    # After S6 this must become SOLVE-CONFLICT (enumerate-all normative).
    assert err.slug == TNG_NO_SATISFYING_VERSION, (
        f"S5b spike: Python Phase-A pre-check emits {err.slug!r} "
        f"(expected TNG-NO-SATISFYING-VERSION pre-S6; after S6 it becomes SOLVE-CONFLICT)"
    )
