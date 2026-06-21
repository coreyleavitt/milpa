"""Slice B (rfc-conformance-parity §4): the black-box runner must translate the
MILPA_CLI_FEATURES family from a fixture's env into the verb-level feature flags
the CLI actually reads (--features / --no-default-features / --all-features),
mirroring the in-process adapter (test_conformance.py::_fixture_cli_features).

Without this the env keys are set on the subprocess but never read, so ~10
feature/profile fixtures pass in-process and fail black-box (Finding 3,
docs/rfc-conformance-parity.baseline.md).
"""

from __future__ import annotations

from pathlib import Path

from harness.assertions import assert_conformance
from harness.descriptors import build_descriptors
from harness.runner import _feature_argv, run_fixture

_REPO = Path(__file__).resolve().parents[1]


def test_features_list_to_flag() -> None:
    assert _feature_argv({"MILPA_CLI_FEATURES": "tls"}) == ["--features", "tls"]
    assert _feature_argv({"MILPA_CLI_FEATURES": "tls, http"}) == [
        "--features",
        "tls, http",
    ]


def test_empty_features_is_no_flag() -> None:
    assert _feature_argv({}) == []
    assert _feature_argv({"MILPA_CLI_FEATURES": ""}) == []
    assert _feature_argv({"MILPA_CLI_FEATURES": "   "}) == []


def test_no_default_features_bool() -> None:
    assert _feature_argv({"MILPA_NO_DEFAULT_FEATURES": "1"}) == ["--no-default-features"]
    assert _feature_argv({"MILPA_NO_DEFAULT_FEATURES": "0"}) == []
    assert _feature_argv({"MILPA_NO_DEFAULT_FEATURES": "false"}) == []


def test_all_features_bool() -> None:
    assert _feature_argv({"MILPA_ALL_FEATURES": "1"}) == ["--all-features"]
    assert _feature_argv({"MILPA_ALL_FEATURES": "0"}) == []


def test_combined_order() -> None:
    assert _feature_argv(
        {"MILPA_CLI_FEATURES": "tls", "MILPA_ALL_FEATURES": "1"}
    ) == ["--features", "tls", "--all-features"]


# --- integration: the previously-black-box-red feature fixtures now pass ---


def _run_python_black_box(name: str):
    fx = _REPO / "conformance" / "spec-v1" / name
    py = next(d for d in build_descriptors(_REPO) if d.name == "python")
    run = run_fixture(fx, py)
    res = assert_conformance(run, fx)
    run.cleanup()
    return res


def test_fixture_209_features_flag_passes_black_box() -> None:
    res = _run_python_black_box("fixture-209-s9-features-flag")
    assert res.passed, [f.detail for f in res.failures]


def test_fixture_210_no_default_features_passes_black_box() -> None:
    res = _run_python_black_box("fixture-210-s9-no-default-features")
    assert res.passed, [f.detail for f in res.failures]


def test_fixture_211_all_features_passes_black_box() -> None:
    res = _run_python_black_box("fixture-211-s9-all-features")
    assert res.passed, [f.detail for f in res.failures]
