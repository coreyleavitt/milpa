"""errors.py bijection + MilpaError shape tests.

Bijection invariant (post-swap S11c):
    errors.py slug-constant set == spec/errors.md slugs (exactly)

spec/errors.md is the spec-owned SSOT.  errors.py bijection-checks against it.
PENDING_SPEC_INCLUSION is empty post-swap.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import milpa.errors as errors_mod

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]  # impls/python/tests → repo root
ERRORS_MD = REPO_ROOT / "spec" / "errors.md"

# Import the single authoritative slug parser from the harness.
# harness/ lives at the repo root; add it to sys.path if needed.
_REPO_ROOT_STR = str(REPO_ROOT)
if _REPO_ROOT_STR not in sys.path:
    sys.path.insert(0, _REPO_ROOT_STR)

from harness.errors_md import parse_spec_slugs as _parse_spec_slugs_from_md  # noqa: E402


def _parse_spec_slugs() -> frozenset[str]:
    """Return slugs from spec/errors.md via the SSOT parser in harness/errors_md.py."""
    return _parse_spec_slugs_from_md(ERRORS_MD)


def _module_slug_constants() -> frozenset[str]:
    """Collect all SCREAMING_SNAKE_CASE constants in errors_mod whose value is a str
    matching the SLUG pattern (non-empty, uppercase-kebab)."""
    result: set[str] = set()
    slug_re = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z][A-Z0-9]*)+$")
    for name, val in vars(errors_mod).items():
        if name.startswith("_"):
            continue
        if isinstance(val, str) and slug_re.match(val):
            result.add(val)
    return frozenset(result)


# ---------------------------------------------------------------------------
# Bijection test
# ---------------------------------------------------------------------------


def test_bijection_with_spec_errors_md() -> None:
    """errors.py slug set == spec/errors.md slugs exactly (PENDING_SPEC_INCLUSION is empty)."""
    spec_slugs = _parse_spec_slugs()
    module_slugs = _module_slug_constants()

    missing_from_module = spec_slugs - module_slugs
    extra_in_module = module_slugs - spec_slugs

    assert not missing_from_module, (
        "Slugs in spec/errors.md but ABSENT from errors.py:\n"
        + "\n".join(sorted(missing_from_module))
    )
    assert not extra_in_module, (
        "Slugs in errors.py but NOT in spec/errors.md:\n"
        + "\n".join(sorted(extra_in_module))
    )


def test_all_slugs_frozenset_matches_module_constants() -> None:
    """errors.ALL_SLUGS equals the set discovered by introspection."""
    assert _module_slug_constants() == errors_mod.ALL_SLUGS


def test_pending_spec_inclusion_is_empty() -> None:
    """PENDING_SPEC_INCLUSION is empty post-swap: all codes are in spec/errors.md."""
    assert errors_mod.PENDING_SPEC_INCLUSION == frozenset()


# ---------------------------------------------------------------------------
# MilpaError shape tests
# ---------------------------------------------------------------------------


def test_milpa_error_carries_slug_and_message() -> None:
    """MilpaError stores slug and message as attributes."""
    from milpa.errors import MAN_KDL_SYNTAX, MilpaError

    err = MilpaError(MAN_KDL_SYNTAX, "unexpected token at line 3")
    assert err.slug == MAN_KDL_SYNTAX
    assert err.message == "unexpected token at line 3"


def test_milpa_error_carries_context_kwargs() -> None:
    """MilpaError stores arbitrary structured context."""
    from milpa.errors import LOCK_FILE_NOT_FOUND, MilpaError

    err = MilpaError(LOCK_FILE_NOT_FOUND, "no lockfile", path="/proj/milpa.lock", retries=3)
    assert err.context == {"path": "/proj/milpa.lock", "retries": 3}


def test_milpa_error_is_exception() -> None:
    """MilpaError is a subclass of Exception and is raise-able."""
    from milpa.errors import SOLVE_CONFLICT, MilpaError

    with _raises_milpa_error(SOLVE_CONFLICT):
        raise MilpaError(SOLVE_CONFLICT, "no solution")


def test_milpa_error_str_includes_slug() -> None:
    """str(MilpaError) includes the slug for readable tracebacks."""
    from milpa.errors import MAN_NAME_MISSING, MilpaError

    err = MilpaError(MAN_NAME_MISSING, "manifest has no name")
    assert MAN_NAME_MISSING in str(err)


def test_named_constant_value_matches_slug() -> None:
    """A spot-check: the constant name maps to the slug string via the obvious mapping."""
    from milpa import errors

    # MAN_DEP_REF_MISSING → "MAN-DEP-REF-MISSING"
    assert errors.MAN_DEP_REF_MISSING == "MAN-DEP-REF-MISSING"
    # FETCH_REF_DISCOVERY_FAILED → "FETCH-REF-DISCOVERY-FAILED"
    assert errors.FETCH_REF_DISCOVERY_FAILED == "FETCH-REF-DISCOVERY-FAILED"
    # MILPA_INDEX_UNREACHABLE → "MILPA-INDEX-UNREACHABLE"
    assert errors.MILPA_INDEX_UNREACHABLE == "MILPA-INDEX-UNREACHABLE"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _raises_milpa_error:
    """Context-manager: assert MilpaError is raised with the given slug."""

    def __init__(self, expected_slug: str) -> None:
        self.expected_slug = expected_slug

    def __enter__(self) -> _raises_milpa_error:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        from milpa.errors import MilpaError

        if exc_type is None:
            raise AssertionError(f"Expected MilpaError({self.expected_slug!r}) not raised")
        if not isinstance(exc_val, MilpaError):
            return False  # let the exception propagate
        assert exc_val.slug == self.expected_slug, (
            f"Expected slug {self.expected_slug!r}, got {exc_val.slug!r}"
        )
        return True  # suppress the exception
