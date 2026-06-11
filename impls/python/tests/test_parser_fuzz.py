"""Parser fuzz tests — RFC differential-conformance-harness §2d.

Invariant enforced: the impl never panics/crashes on bad input.
Every failure must be clean:
  - The parser's own typed exception (ManifestError / LockfileError /
    TianguisError) with a non-None .code that is present in ERROR_CATALOG.
  - No other exception type may escape the parser boundary.
  - Any escaping non-typed exception is a real bug: a Gap-1 hole where a
    failure path carries no slug.

4a — parser-direct fuzz (one test per parser, 3 tests).
4b — CLI-level bytes fuzz via `main(["-C", tmp, "show"])`.
"""

import io
import re
import contextlib
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st

from milpa.error_catalog import ERROR_CATALOG
from milpa.lockfile import LockfileError, parse_lockfile
from milpa.manifest import ManifestError, parse_manifest
from milpa.tianguis_client import TianguisError, parse_index
from milpa.cli import main


# ---------------------------------------------------------------------------
# Shared: slug-line regex (matches test_error_channel.py)
# ---------------------------------------------------------------------------

_SLUG_LINE = re.compile(r"^milpa-error: ([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)$", re.M)


def _slug_lines(stderr: str) -> list[str]:
    """Return every full-line `milpa-error: <SLUG>` match's slug."""
    return _SLUG_LINE.findall(stderr)


# ---------------------------------------------------------------------------
# Shared: the clean-failure assertion
# ---------------------------------------------------------------------------

def _assert_clean_parse(parse_fn, allowed_exc, text: str) -> None:
    """Assert parse_fn either succeeds or raises exactly allowed_exc
    with a non-None .code present in ERROR_CATALOG.

    Any other exception propagates and fails the Hypothesis test — that is
    the point. Broadening to `except Exception` here would defeat the test.
    """
    try:
        parse_fn(text)
    except allowed_exc as e:
        assert e.code is not None, (
            f"{allowed_exc.__name__} raised with no slug for input {text!r}"
        )
        assert e.code in ERROR_CATALOG, (
            f"slug {e.code!r} not in catalog for input {text!r}"
        )
    # Any other exception propagates — a genuine finding.


# ---------------------------------------------------------------------------
# Input strategies
# ---------------------------------------------------------------------------

# Unicode garbage (default alphabet — surrogates excluded by Hypothesis)
_text_st = st.text()

# Bytes-shaped garbage decoded to str (hit NUL bytes, high bytes, etc.)
_bytes_as_text_st = st.binary().map(lambda b: b.decode("utf-8", "replace"))

# Structural: KDL-ish but broken — random tokens from the KDL grammar
# character set, interleaved with structure characters that trigger
# unbalanced-delimiter and depth bugs.
_KDL_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
_STRUCTURAL_TOKENS = ["{", "}", '"', "=", "\n", " ", "/", "\\", "(", ")", ";"]

_structural_st = st.builds(
    lambda tokens, name: "".join(tokens + [name]),
    st.lists(st.sampled_from(_STRUCTURAL_TOKENS), min_size=0, max_size=40),
    st.text(alphabet=_KDL_CHARS, max_size=20),
)

# Deep-nesting: classic RecursionError trigger.
_deep_nest_st = st.integers(min_value=1, max_value=5000).map(lambda n: "{" * n)

# Union of all four strategies.
_adversarial_st = st.one_of(
    _text_st,
    _bytes_as_text_st,
    _structural_st,
    _deep_nest_st,
)


# ---------------------------------------------------------------------------
# 4a — parser-direct fuzz: manifest
# ---------------------------------------------------------------------------

@given(_adversarial_st)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_parse_manifest(text: str) -> None:
    """parse_manifest never lets a non-ManifestError escape for any input."""
    _assert_clean_parse(parse_manifest, ManifestError, text)


# ---------------------------------------------------------------------------
# 4a — parser-direct fuzz: lockfile
# ---------------------------------------------------------------------------

@given(_adversarial_st)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_parse_lockfile(text: str) -> None:
    """parse_lockfile never lets a non-LockfileError escape for any input."""
    _assert_clean_parse(parse_lockfile, LockfileError, text)


# ---------------------------------------------------------------------------
# 4a — parser-direct fuzz: index (tianguis)
# ---------------------------------------------------------------------------

@given(_adversarial_st)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_parse_index(text: str) -> None:
    """parse_index never lets a non-TianguisError escape for any input."""
    _assert_clean_parse(parse_index, TianguisError, text)


# ---------------------------------------------------------------------------
# 4b — CLI-level bytes fuzz: write arbitrary bytes to milpa.lock,
#      run `main(["-C", tmp, "show"])`, confirm clean exit + channel.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Regression tests — counterexamples found by Hypothesis above (shrink→fix→pin)
# ---------------------------------------------------------------------------

def test_regression_parse_index_junk_after_node() -> None:
    """Minimal counterexample: '?\x08' — kdl.ParseError leaked as a raw library
    exception before TNG-KDL-SYNTAX wrapping was added to parse_index.
    Fix: tianguis_client.py wraps kdl.parse() in TianguisError(code='TNG-KDL-SYNTAX').
    """
    _assert_clean_parse(parse_index, TianguisError, "?\x08")


def test_regression_parse_index_expected_a_node() -> None:
    """Minimal counterexample: '0' — kdl.ParseError 'Expected a node' leaked.
    Same root cause as test_regression_parse_index_junk_after_node.
    """
    _assert_clean_parse(parse_index, TianguisError, "0")


# ---------------------------------------------------------------------------
# 4b — CLI-level bytes fuzz: write arbitrary bytes to milpa.lock,
#      run `main(["-C", tmp, "show"])`, confirm clean exit + channel.
# ---------------------------------------------------------------------------

@given(st.binary())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_cli_show_arbitrary_lockfile(data: bytes) -> None:
    """Arbitrary bytes in milpa.lock → show exits 0 or 1 with clean channel.

    Uses a tempfile context manager (not tmp_path) to avoid the
    function-scoped fixture + @given health-check failure; a fresh
    directory is created for each Hypothesis example.

    Invariant:
      - rc must be 0 or 1 (never 2, never uncaught traceback)
      - rc == 1 → exactly one milpa-error: <SLUG> line on stderr
      - rc == 0 → no milpa-error: line on stderr
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        (tmp / "milpa.lock").write_bytes(data)

        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            rc = main(["-C", str(tmp), "show"])

        err = err_buf.getvalue()
        slugs = _slug_lines(err)

        assert rc in (0, 1), (
            f"show exited {rc!r} (expected 0 or 1); stderr: {err!r}"
        )
        if rc == 1:
            assert len(slugs) == 1, (
                f"rc=1 but slug count={len(slugs)!r}; stderr: {err!r}"
            )
        else:
            assert slugs == [], (
                f"rc=0 but slug lines present: {slugs!r}; stderr: {err!r}"
            )
