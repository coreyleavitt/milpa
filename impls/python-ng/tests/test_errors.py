"""Stage 1a: errors.py bijection + MilpaError shape tests.

Bijection invariant:
    errors.py slug-constant set == (spec/errors.md slugs) ∪ {FETCH-REF-DISCOVERY-FAILED,
                                                              MILPA-INDEX-UNREACHABLE}

At swap (S11c): errors.md is regenerated FROM errors.py (gaining the two pending codes),
the Rust DEFERRED→implemented companion lands alongside raise sites, and the ∪ {pending}
term is deleted so this reduces to: errors.py == errors.md exactly.
"""

from __future__ import annotations

import re
from pathlib import Path

import milpa.errors as errors_mod

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]  # impls/python-ng/tests → repo root
ERRORS_MD = REPO_ROOT / "spec" / "errors.md"

# Two codes pending spec inclusion (added to errors.py now; enter errors.md at swap S11c).
PENDING_SPEC_INCLUSION = {"FETCH-REF-DISCOVERY-FAILED", "MILPA-INDEX-UNREACHABLE"}


def _parse_spec_slugs() -> frozenset[str]:
    """Parse spec/errors.md using the same logic as the Rust corpus test.

    The Rust test (corpus.rs::spec_error_codes) strips the prefix ``### \\`````
    and takes up to the next backtick.  We mirror that exactly.
    """
    text = ERRORS_MD.read_text(encoding="utf-8")
    slugs: set[str] = set()
    for line in text.splitlines():
        if line.startswith("### `"):
            # strip "### `", take up to next "`"
            rest = line[5:]
            end = rest.find("`")
            if end != -1:
                slugs.add(rest[:end])
    return frozenset(slugs)


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
    """errors.py slug set == spec/errors.md slugs ∪ PENDING_SPEC_INCLUSION."""
    spec_slugs = _parse_spec_slugs()
    module_slugs = _module_slug_constants()
    expected = spec_slugs | PENDING_SPEC_INCLUSION

    missing_from_module = expected - module_slugs
    extra_in_module = module_slugs - expected

    assert not missing_from_module, (
        "Slugs in spec/errors.md (or pending) but ABSENT from errors.py:\n"
        + "\n".join(sorted(missing_from_module))
    )
    assert not extra_in_module, (
        "Slugs in errors.py but NOT in spec/errors.md and NOT pending:\n"
        + "\n".join(sorted(extra_in_module))
    )


def test_all_slugs_frozenset_matches_module_constants() -> None:
    """errors.ALL_SLUGS equals the set discovered by introspection."""
    assert _module_slug_constants() == errors_mod.ALL_SLUGS


def test_pending_spec_inclusion_is_subset_of_all_slugs() -> None:
    """PENDING_SPEC_INCLUSION slugs are present in errors.py."""
    assert PENDING_SPEC_INCLUSION <= errors_mod.ALL_SLUGS


def test_pending_spec_inclusion_constant_matches() -> None:
    """The PENDING_SPEC_INCLUSION constant in errors.py matches the test's expectation."""
    assert frozenset(PENDING_SPEC_INCLUSION) == errors_mod.PENDING_SPEC_INCLUSION


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
    # FETCH_REF_DISCOVERY_FAILED → "FETCH-REF-DISCOVERY-FAILED" (pending)
    assert errors.FETCH_REF_DISCOVERY_FAILED == "FETCH-REF-DISCOVERY-FAILED"
    # MILPA_INDEX_UNREACHABLE → "MILPA-INDEX-UNREACHABLE" (pending)
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
