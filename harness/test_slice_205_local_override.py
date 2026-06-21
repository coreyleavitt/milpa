"""fixture-205 (rfc-conformance-parity §4 Slice C "205"): local-override transitive.

The mocked registry used by the CLI in conformance mode (mocked_registry, via
MILPA_MOCKED_FETCHES) registered MockedLocalFetcher, which requires a
mocked-fetches/<url_key>/ entry. But local deps/overrides are filesystem-native:
the fixture ships the override target as a real dir (mylib-fork/), copied to
scratch. The in-process adapter already uses the REAL LocalFetcher for exactly
this reason; the CLI mock path did not — so 205 passed in-process but failed
black-box (FETCH-MOCK-MISSING) in both impls (Finding 4, baseline doc).
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


def test_fixture_205_local_override_passes_black_box() -> None:
    res = _run_python_black_box("fixture-205-s8a-local-override-transitive")
    assert res.passed, [f.detail for f in res.failures]
