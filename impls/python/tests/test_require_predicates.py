"""S2 — RequireEntry.predicates field (RFC rfc-conditional-requires.md §3.3).

Tests for the optional ``predicates`` field on ``NamedRequire`` and
``UrlRequire``.  Nothing populates it yet (that is S3b); these tests verify
the data model alone.

TDD discipline: tests were written RED before the field was added.
"""

from __future__ import annotations

import pytest

from milpa.predicate import Predicate
from milpa.dep_decl import EdgeSet, EdgeSource, NamedRequire, UrlRequire


# ---------------------------------------------------------------------------
# TestNamedRequirePredicates
# ---------------------------------------------------------------------------


class TestNamedRequirePredicates:
    def test_different_predicates_are_not_equal(self) -> None:
        """Two NamedRequires with distinct predicates must not compare equal."""
        p1 = Predicate(name="platform", values=("linux",))
        p2 = Predicate(name="platform", values=("windows",))
        a = NamedRequire("foo", "", predicates=(p1,))
        b = NamedRequire("foo", "", predicates=(p2,))
        assert a != b

    def test_identical_predicates_are_equal(self) -> None:
        """Two NamedRequires with the same predicates must compare equal."""
        p = Predicate(name="platform", values=("linux",))
        a = NamedRequire("foo", "", predicates=(p,))
        b = NamedRequire("foo", "", predicates=(p,))
        assert a == b

    def test_default_predicates_is_empty_tuple(self) -> None:
        """Omitting predicates gives an empty tuple (back-compat)."""
        r = NamedRequire("foo", ">= 1.0")
        assert r.predicates == ()

    def test_positional_construction_still_works(self) -> None:
        """Back-compat: positional ``NamedRequire(name, constraint)`` is unchanged."""
        r = NamedRequire("foo", ">= 1.0")
        assert r.name == "foo"
        assert r.constraint_str == ">= 1.0"
        assert r.predicates == ()

    def test_non_empty_predicates_not_equal_to_empty(self) -> None:
        """A require with predicates != one without (empty default)."""
        p = Predicate(name="platform", values=("linux",))
        with_pred = NamedRequire("foo", "", predicates=(p,))
        without_pred = NamedRequire("foo", "")
        assert with_pred != without_pred


# ---------------------------------------------------------------------------
# TestUrlRequirePredicates
# ---------------------------------------------------------------------------


class TestUrlRequirePredicates:
    def test_different_predicates_are_not_equal(self) -> None:
        """Two UrlRequires with distinct predicates must not compare equal."""
        p1 = Predicate(name="arch", values=("amd64",))
        p2 = Predicate(name="arch", values=("arm64",))
        a = UrlRequire("https://example.com/foo.git", "main", predicates=(p1,))
        b = UrlRequire("https://example.com/foo.git", "main", predicates=(p2,))
        assert a != b

    def test_identical_predicates_are_equal(self) -> None:
        p = Predicate(name="arch", values=("amd64",))
        a = UrlRequire("https://example.com/foo.git", "v1", predicates=(p,))
        b = UrlRequire("https://example.com/foo.git", "v1", predicates=(p,))
        assert a == b

    def test_default_predicates_is_empty_tuple(self) -> None:
        r = UrlRequire("https://example.com/foo.git", "main")
        assert r.predicates == ()

    def test_positional_construction_still_works(self) -> None:
        r = UrlRequire("https://example.com/foo.git", "main")
        assert r.url == "https://example.com/foo.git"
        assert r.ref == "main"
        assert r.predicates == ()

    def test_non_empty_predicates_not_equal_to_empty(self) -> None:
        p = Predicate(name="arch", values=("amd64",))
        with_pred = UrlRequire("https://example.com/foo.git", "main", predicates=(p,))
        without_pred = UrlRequire("https://example.com/foo.git", "main")
        assert with_pred != without_pred


# ---------------------------------------------------------------------------
# TestEdgeSetPredicateRoundTrip
# ---------------------------------------------------------------------------


class TestEdgeSetPredicateRoundTrip:
    def test_edgeset_with_predicated_entry_not_equal_to_plain(self) -> None:
        """An EdgeSet whose entry has a predicate != one whose entry has none."""
        p = Predicate(name="platform", values=("linux",))
        with_pred = EdgeSet(
            requires=[NamedRequire("extra", "", predicates=(p,))],
            source=EdgeSource.NIMBLE_FALLBACK,
        )
        without_pred = EdgeSet(
            requires=[NamedRequire("extra", "")],
            source=EdgeSource.NIMBLE_FALLBACK,
        )
        assert with_pred != without_pred

    def test_repr_surfaces_predicates(self) -> None:
        """repr of an EdgeSet propagates its entry's predicates string."""
        p = Predicate(name="platform", values=("linux",))
        es = EdgeSet(
            requires=[NamedRequire("extra", "", predicates=(p,))],
            source=EdgeSource.NIMBLE_FALLBACK,
        )
        r = repr(es)
        assert "linux" in r
        assert "platform" in r


# ---------------------------------------------------------------------------
# TestSSOTImportCycleFree
# ---------------------------------------------------------------------------


class TestSSOTImportCycleFree:
    def test_predicate_is_same_object_from_both_paths(self) -> None:
        """milpa.manifest.Predicate IS milpa.predicate.Predicate (re-export identity)."""
        from milpa.predicate import Predicate as PP
        from milpa.manifest import Predicate as MP

        assert MP is PP

    def test_no_import_cycle_constructing_named_require_with_predicate(self) -> None:
        """Constructing NamedRequire with a Predicate imported from predicate.py
        must not raise ImportError or any cycle-related error."""
        from milpa.predicate import Predicate as P
        from milpa.dep_decl import NamedRequire as NR

        r = NR("bar", ">= 1.0", predicates=(P(name="platform", values=("linux",)),))
        assert r.predicates[0].name == "platform"
        assert r.predicates[0].values == ("linux",)
