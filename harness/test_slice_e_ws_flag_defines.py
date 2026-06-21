"""Slice E (rfc-conformance-parity §4): the Python CLI's workspace nim.cfg
emission must include the workspace-wide flag-union `-d:` defines.

213/214/282 were python-fail / rust-pass divergences: Python emitted member
nim.cfg files WITHOUT any `-d:` defines because the two workspace call sites
called format_workspace_nimcfgs() without flag_defines (the single-package sites
pass build_flag_defines()). In-process pytest never caught it — it bypasses CLI
routing — so this is driven black-box (Finding 2, baseline doc).
"""

from __future__ import annotations

from pathlib import Path

from harness.assertions import assert_conformance
from harness.descriptors import build_descriptors
from harness.runner import run_fixture

_REPO = Path(__file__).resolve().parents[1]


def _run_python_black_box(name: str):
    fx = _REPO / "conformance" / "spec-v1" / name
    py = next(d for d in build_descriptors(_REPO) if d.name == "python")
    run = run_fixture(fx, py)
    res = assert_conformance(run, fx)
    run.cleanup()
    return res


def test_fixture_213_workspace_wide_union_passes_black_box() -> None:
    res = _run_python_black_box("fixture-213-s11-workspace-wide-union")
    assert res.passed, [f.detail for f in res.failures]


def test_fixture_214_workspace_root_flags_passes_black_box() -> None:
    res = _run_python_black_box("fixture-214-s11-workspace-root-flags")
    assert res.passed, [f.detail for f in res.failures]


def test_fixture_282_ws_cross_pkg_enable_fixpoint_passes_black_box() -> None:
    res = _run_python_black_box("fixture-282-ws-cross-pkg-enable-fixpoint")
    assert res.passed, [f.detail for f in res.failures]
