"""Slice C parts c1/c2 (rfc-conformance-parity §4): black-box runner
normalization gaps that made tarball-identity and local-dep fixtures fail
identically in both impls (Finding 4, docs/rfc-conformance-parity.baseline.md).

c1 — `<TARBALL-SHA256>` placeholder: a built tarball's archive bytes are not
     reproducible across impls/runs (gzip headers), so `expected/milpa.lock`
     pins the provenance `sha256` as a placeholder. The harness must substitute
     it before diffing AND before storing the cross-impl value.
c2 — local-dep symlink: `_deps/<name>` for a local dep points outside the CAS
     (at a working tree), so `_deps_structure.txt` expects `<name> -> (symlink)`,
     not a CAS path.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from harness.assertions import (
    _apply_lock_placeholders,
    _normalize_deps_structure,
    assert_conformance,
)
from harness.descriptors import build_descriptors
from harness.runner import run_fixture

_REPO = Path(__file__).resolve().parents[1]

_SHA = "e47338bef4b540c8ed1c0295ac19b2779e1d0838a2456c4f374f570ddb2232d0"


# --- c1: lock placeholder substitution (pure) ---


def test_tarball_sha_placeholder_applied_when_expected_uses_it() -> None:
    expected = '    provenance {\n        sha256 "<TARBALL-SHA256>"\n    }\n'
    actual = f'    provenance {{\n        sha256 "{_SHA}"\n    }}\n'
    assert _apply_lock_placeholders(expected, actual) == expected


def test_placeholder_not_applied_when_expected_pins_real_sha() -> None:
    expected = f'        sha256 "{_SHA}"\n'
    actual = f'        sha256 "{_SHA}"\n'
    # No placeholder token in expected → actual returned unchanged.
    assert _apply_lock_placeholders(expected, actual) == actual


def test_identity_line_is_not_substituted() -> None:
    # The identity field (`identity "sha256:<hex>"`) must never be normalized.
    expected = 'sha256 "<TARBALL-SHA256>"'
    actual = f'identity "sha256:{_SHA}"\nsha256 "{_SHA}"'
    out = _apply_lock_placeholders(expected, actual)
    assert f'identity "sha256:{_SHA}"' in out
    assert 'sha256 "<TARBALL-SHA256>"' in out


# --- c2: local-dep symlink normalization (pure, with real symlinks) ---


def test_deps_structure_local_symlink_renders_as_symlink_token() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cas = root / "cas"
        cas.mkdir()
        worktree = root / "mylib-src"
        worktree.mkdir()
        deps = root / "scratch" / "_deps"
        deps.mkdir(parents=True)
        os.symlink(worktree, deps / "mylib")
        out = _normalize_deps_structure(str(root / "scratch"), str(cas))
        assert out == "mylib -> (symlink)\n"


def test_deps_structure_cas_symlink_still_renders_cas_root() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cas = root / "cas"
        target = cas / "sha256" / "abc"
        target.mkdir(parents=True)
        deps = root / "scratch" / "_deps"
        deps.mkdir(parents=True)
        os.symlink(target, deps / "foo")
        out = _normalize_deps_structure(str(root / "scratch"), str(cas))
        assert out == "foo -> <CAS_ROOT>/sha256/abc/\n"


# --- integration: the fixtures now pass black-box for python ---


def _run_python_black_box(name: str):
    fx = _REPO / "conformance" / "spec-v1" / name
    py = next(d for d in build_descriptors(_REPO) if d.name == "python")
    run = run_fixture(fx, py)
    res = assert_conformance(run, fx)
    run.cleanup()
    return res


def test_fixture_181_local_dep_passes_black_box() -> None:
    res = _run_python_black_box("fixture-181-fetch-local-dep")
    assert res.passed, [f.detail for f in res.failures]


def test_fixture_182_tarball_gz_passes_black_box() -> None:
    res = _run_python_black_box("fixture-182-tarball-gz-identity")
    assert res.passed, [f.detail for f in res.failures]


def test_fixture_183_tarball_xz_passes_black_box() -> None:
    res = _run_python_black_box("fixture-183-tarball-xz-identity")
    assert res.passed, [f.detail for f in res.failures]
