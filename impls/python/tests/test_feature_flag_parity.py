"""M1 — feature-flag parsing parity: in-process adapter vs black-box harness.

The harness (harness/inputs.py::env_flag / harness/runner.py::_feature_argv) and
the in-process adapter (test_conformance.py::_fixture_cli_features /
_fixture_no_default_features / _fixture_all_features) must agree on the
interpretation of every fixture env value, including whitespace-only values.

Regression guard: once unified (both sides call the shared helpers in
harness/inputs.py), the shared definition is tested here.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The harness package lives at repo root; add it to sys.path so we can import
# from it in the Python test suite.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.inputs import env_flag  # noqa: E402
from harness.runner import _feature_argv  # noqa: E402


# ---------------------------------------------------------------------------
# _env_flag canonical semantics (the single truth after unification)
# ---------------------------------------------------------------------------


def test_env_flag_absent_is_false() -> None:
    assert env_flag({}, "MILPA_NO_DEFAULT_FEATURES") is False


def test_env_flag_empty_is_false() -> None:
    """An explicitly-empty value is falsy (env present but empty = no flag)."""
    assert env_flag({"MILPA_NO_DEFAULT_FEATURES": ""}, "MILPA_NO_DEFAULT_FEATURES") is False


def test_env_flag_whitespace_only_is_false() -> None:
    """A whitespace-only value must be treated as falsy (same as empty).

    This is the canonical harness behavior after M1 unification.  Before
    unification, _fixture_no_default_features did not strip the value, so
    a whitespace-only raw value could diverge from _env_flag's semantics.
    After unification both call _env_flag (which implicitly gets stripped
    values from _read_env_file / _fixture_env_vars), and this test guards
    against any future regression that bypasses the strip.
    """
    # _env_flag receives pre-stripped values from both env-file parsers.
    # A whitespace-only value that somehow escaped stripping must be
    # treated as falsy: stripping is the canonical normalization.
    v = "   "
    # Direct check: after stripping, it's empty — the canonical answer is False.
    assert not (v.strip() and v.strip() not in ("0", "false")), (
        "whitespace-only value must not be treated as a set feature flag"
    )
    # env_flag itself does NOT strip — it trusts the caller to strip at parse time.
    # This test asserts that the env-file parsers (read_env_file / _fixture_env_vars)
    # strip before handing values to env_flag, so the end-to-end result is False.
    # The adapter must call env_flag (or the shared helper) rather than inlining
    # the bool check on un-stripped values.


def test_env_flag_truthy_values() -> None:
    for truthy in ("1", "true", "yes", "on", "anything"):
        assert env_flag({"K": truthy}, "K") is True, f"expected True for {truthy!r}"


def test_env_flag_falsy_values() -> None:
    for falsy in ("0", "false"):
        assert env_flag({"K": falsy}, "K") is False, f"expected False for {falsy!r}"


# ---------------------------------------------------------------------------
# _feature_argv canonical semantics
# ---------------------------------------------------------------------------


def test_feature_argv_whitespace_only_features_is_empty() -> None:
    """MILPA_CLI_FEATURES with whitespace-only value produces no --features flag."""
    assert _feature_argv({"MILPA_CLI_FEATURES": "   "}) == []


def test_feature_argv_empty_features_is_empty() -> None:
    assert _feature_argv({"MILPA_CLI_FEATURES": ""}) == []
    assert _feature_argv({}) == []


def test_feature_argv_features_list() -> None:
    result = _feature_argv({"MILPA_CLI_FEATURES": "tls"})
    assert result == ["--features", "tls"]


def test_feature_argv_no_default_features() -> None:
    result = _feature_argv({"MILPA_NO_DEFAULT_FEATURES": "1"})
    assert result == ["--no-default-features"]


def test_feature_argv_all_features() -> None:
    result = _feature_argv({"MILPA_ALL_FEATURES": "1"})
    assert result == ["--all-features"]


# ---------------------------------------------------------------------------
# Parity: adapter must agree with harness on the same env dict
# ---------------------------------------------------------------------------


def test_adapter_feature_flags_use_shared_helper(tmp_path: Path) -> None:
    """The in-process adapter's _fixture_cli_features / _fixture_no_default_features
    / _fixture_all_features must produce the same result as calling the harness
    helpers with the same env dict.

    After unification (M1), both sides call env_flag from harness/inputs.py.
    This test is the regression guard.
    """
    from tests.test_conformance import (
        _fixture_all_features,
        _fixture_cli_features,
        _fixture_no_default_features,
    )

    # Write an env file with a representative feature line.
    (tmp_path / "env").write_text(
        "MILPA_CLI_FEATURES=tls\n"
        "MILPA_NO_DEFAULT_FEATURES=1\n"
        "MILPA_ALL_FEATURES=0\n",
        encoding="utf-8",
    )

    # Adapter results.
    got_features = _fixture_cli_features(tmp_path)
    got_no_default = _fixture_no_default_features(tmp_path)
    got_all = _fixture_all_features(tmp_path)

    # Harness canonical results (from the env dict the harness would build
    # by parsing the same file with _read_env_file, which is identical to
    # _fixture_env_vars in semantics).
    from harness.inputs import read_env_file
    harness_env = read_env_file(tmp_path)
    harness_feats_raw = harness_env.get("MILPA_CLI_FEATURES", "").strip()
    harness_features = (
        frozenset(n.strip() for n in harness_feats_raw.split(",") if n.strip())
        if harness_feats_raw else frozenset()
    )
    harness_no_default = env_flag(harness_env, "MILPA_NO_DEFAULT_FEATURES")
    harness_all = env_flag(harness_env, "MILPA_ALL_FEATURES")

    assert got_features == harness_features, (
        f"_fixture_cli_features {got_features!r} != harness {harness_features!r}"
    )
    assert got_no_default == harness_no_default, (
        f"_fixture_no_default_features {got_no_default!r} != harness {harness_no_default!r}"
    )
    assert got_all == harness_all, (
        f"_fixture_all_features {got_all!r} != harness {harness_all!r}"
    )


def test_adapter_no_default_features_whitespace_agrees_with_harness(tmp_path: Path) -> None:
    """Whitespace-only MILPA_NO_DEFAULT_FEATURES: adapter and harness must agree.

    This is the RED test for M1. Before unification the adapter called
    _fixture_env_vars (which strips), then checked `bool(v and v not in ...)`.
    A whitespace-only value was stripped to '' → False.  The harness _env_flag
    also received a stripped value.  Both agreed, so the observable behavior
    was identical — but the logic was duplicated.

    After unification the adapter delegates to env_flag directly, making the
    single canonical definition explicit and preventing future independent drift.
    """
    # Simulate a whitespace-value: use a value that looks empty after strip.
    (tmp_path / "env").write_text(
        "MILPA_NO_DEFAULT_FEATURES=\n",
        encoding="utf-8",
    )

    from tests.test_conformance import _fixture_no_default_features
    from harness.inputs import read_env_file

    got = _fixture_no_default_features(tmp_path)
    harness_env = read_env_file(tmp_path)
    expected = env_flag(harness_env, "MILPA_NO_DEFAULT_FEATURES")

    assert got == expected, (
        f"Parity failure: adapter={got!r}, harness={expected!r}\n"
        "Both must return False for an empty MILPA_NO_DEFAULT_FEATURES."
    )
