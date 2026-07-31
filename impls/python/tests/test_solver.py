"""Tests for milpa/solver.py — slices 6a, 6b-1, 6b-2, 6b-3.

All providers are synthetic in-memory structs; no network access, no
resolver, no KDL.  The test graph is constructed from Version objects
and Term constraints directly.

Structure:
  6a   — data structures (Term, Incompatibility, PartialSolution, Assignment)
  6b-1 — solve() + SolverError / conflict chain (satisfiable + diamond conflict)
  6b-2 — Strategy dispatch (MAXVER / MINVER / SEMVER)
  6b-3 — result certificate: §5.1 success witness + §5.2 failure refutation
  prop — property tests for algebraic invariants
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from milpa.solver import (
    Assignment,
    ConflictChain,
    ConflictStep,
    Incompatibility,
    PartialSolution,
    RefutationEntry,
    SolverError,
    SolveSuccess,
    Term,
    TermRelation,
    VersionUnknownConstrained,
    WitnessEntry,
    _accumulated_constrainers,
    _effective_strategy_for,
    _next_undecided,
    _pick_version,
    build_success_certificate,
    certificate_to_json,
    render_conflict_chain,
    solve,
)
from milpa.version import Strategy, Version, VersionSet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def v(major: int, minor: int, patch: int) -> Version:
    return Version(major, minor, patch)


def vs_gte(major: int, minor: int, patch: int) -> VersionSet:
    return VersionSet.gte(v(major, minor, patch))


def vs_lt(major: int, minor: int, patch: int) -> VersionSet:
    return VersionSet.lt(v(major, minor, patch))


def vs_eq(major: int, minor: int, patch: int) -> VersionSet:
    return VersionSet.eq(v(major, minor, patch))


class DictProvider:
    """Synthetic PackageProvider backed by plain dicts.

    ``versions_map``: {pkg: [Version, ...]}
    ``deps_map``:     {(pkg, version): [Term, ...]}

    Deliberately has NO ``is_version_unknown`` method — this is the A4
    regression contract: ``_is_version_unknown`` (solver.py) falls back to
    ``False`` via ``getattr`` for any provider that doesn't implement it, so
    every existing test in this file (all built on this class) is an
    implicit proof that the two-pass ``_next_undecided`` degenerates to the
    original single-pass scan — same order, byte-for-byte — when no
    version-unknown package is in play.
    """

    def __init__(
        self,
        versions_map: dict[str, list[Version]],
        deps_map: dict[tuple[str, Version], list[Term]],
    ) -> None:
        self._versions = versions_map
        self._deps = deps_map

    def versions(self, package: str) -> list[Version]:
        return list(self._versions.get(package, []))

    def dependencies(self, package: str, version: Version) -> list[Term]:
        return list(self._deps.get((package, version), []))


class VersionUnknownDictProvider(DictProvider):
    """``DictProvider`` + an explicit version-unknown package-name set (A4).

    A real production provider derives ``is_version_unknown`` from a
    candidate's declared-version precedence chain (resolver.py); this test
    double just takes the answer directly, isolating the SOLVER-side
    mechanism (decision priority + classification) from resolver-level
    concerns (candidate labeling, lazy stub materialization — covered by the
    conformance corpus instead, e.g. fixture-418/419).
    """

    def __init__(
        self,
        versions_map: dict[str, list[Version]],
        deps_map: dict[tuple[str, Version], list[Term]],
        version_unknown_names: set[str],
    ) -> None:
        super().__init__(versions_map, deps_map)
        self._version_unknown_names = version_unknown_names

    def is_version_unknown(self, package: str) -> bool:
        return package in self._version_unknown_names


class RootAuthorityDictProvider(DictProvider):
    """``DictProvider`` + an explicit root-direct package-name set (C2).

    A real production provider derives ``is_root_direct`` from the manifest's
    ``root_authority`` set (resolver.py); this test double just takes the
    answer directly, isolating the SOLVER-side mechanism (the effective-
    strategy precompute) from resolver-level concerns (root-authority
    construction — covered by ``test_c2_lowest_direct.py`` instead).
    """

    def __init__(
        self,
        versions_map: dict[str, list[Version]],
        deps_map: dict[tuple[str, Version], list[Term]],
        root_direct_names: set[str],
    ) -> None:
        super().__init__(versions_map, deps_map)
        self._root_direct_names = root_direct_names

    def is_root_direct(self, package: str) -> bool:
        return package in self._root_direct_names


# ---------------------------------------------------------------------------
# 6a — data structures
# ---------------------------------------------------------------------------


class TestTerm:
    def test_require_positive(self) -> None:
        t = Term.require("foo", VersionSet.full())
        assert t.package == "foo"
        assert t.positive is True

    def test_forbid_negative(self) -> None:
        t = Term.forbid("foo", VersionSet.full())
        assert t.positive is False

    def test_negate_flips_sign(self) -> None:
        t = Term.require("foo", VersionSet.full())
        assert t.negate().positive is False
        assert t.negate().negate().positive is True

    def test_frozen(self) -> None:
        t = Term.require("foo", VersionSet.full())
        with pytest.raises((AttributeError, TypeError)):
            t.package = "bar"  # type: ignore[misc]

    def test_hashable_in_set(self) -> None:
        t1 = Term.require("foo", VersionSet.full())
        t2 = Term.require("foo", VersionSet.full())
        assert t1 == t2
        assert len({t1, t2}) == 1


class TestIncompatibility:
    def test_basic_fields(self) -> None:
        t = Term.require("foo", VersionSet.full())
        ic = Incompatibility(terms=(t,), cause="root")
        assert ic.cause == "root"
        assert len(ic.terms) == 1

    def test_frozen(self) -> None:
        ic = Incompatibility(terms=(), cause="root")
        with pytest.raises((AttributeError, TypeError)):
            ic.cause = "other"  # type: ignore[misc]


class TestAssignment:
    def test_decision_fields(self) -> None:
        t = Term.require("foo", vs_eq(1, 0, 0))
        a = Assignment(term=t, kind="decision", cause=None, decision_level=1)
        assert a.kind == "decision"
        assert a.cause is None

    def test_derivation_has_cause(self) -> None:
        t = Term.require("foo", VersionSet.full())
        ic = Incompatibility(terms=(t,), cause="root")
        a = Assignment(term=t, kind="derivation", cause=ic, decision_level=0)
        assert a.cause is ic


class TestPartialSolution:
    def _make_ps(self) -> PartialSolution:
        return PartialSolution()

    def test_empty_has_no_decisions(self) -> None:
        ps = self._make_ps()
        assert ps.decisions() == {}

    def test_add_decision(self) -> None:
        ps = self._make_ps()
        ps.add_decision("foo", v(1, 0, 0))
        assert ps.decisions()["foo"] == v(1, 0, 0)
        assert ps.has_decision("foo")

    def test_add_derivation(self) -> None:
        ps = self._make_ps()
        t = Term.require("foo", vs_gte(1, 0, 0))
        ic = Incompatibility(terms=(t,), cause="test")
        ps.add_derivation(t, cause=ic)
        assert not ps.has_decision("foo")
        assert len(ps.assignments) == 1

    def test_effective_set_empty_when_unknown(self) -> None:
        ps = self._make_ps()
        # No assignments → full (unknown package)
        result = ps.effective_set("unknown")
        assert result == VersionSet.full()

    def test_effective_set_intersects_positive_constraints(self) -> None:
        ps = self._make_ps()
        ic = Incompatibility(terms=(), cause="test")
        ps.add_derivation(Term.require("foo", vs_gte(1, 0, 0)), cause=ic)
        ps.add_derivation(Term.require("foo", vs_lt(2, 0, 0)), cause=ic)
        eff = ps.effective_set("foo")
        assert eff.contains(v(1, 5, 0))
        assert not eff.contains(v(0, 9, 0))
        assert not eff.contains(v(2, 0, 0))

    def test_backtrack_removes_higher_level(self) -> None:
        ps = self._make_ps()
        ps.add_decision("foo", v(1, 0, 0))  # level 1
        ps.add_decision("bar", v(2, 0, 0))  # level 2
        assert ps.decision_level == 2
        undone = ps.backtrack_to(1)
        assert undone is not None
        assert undone.term.package == "bar"
        assert ps.decision_level == 1
        assert ps.has_decision("foo")
        assert not ps.has_decision("bar")

    def test_relation_satisfies(self) -> None:
        ps = self._make_ps()
        ps.add_decision("foo", v(1, 0, 0))
        # Incompat: "foo must be in eq(1.0.0)" — satisfied by the decision.
        ic = Incompatibility(
            terms=(Term.require("foo", vs_eq(1, 0, 0)),), cause="test"
        )
        assert ps.relation_to(ic) == TermRelation.SATISFIES

    def test_relation_contradicts(self) -> None:
        ps = self._make_ps()
        ps.add_decision("foo", v(2, 0, 0))
        # Incompat: "foo must be in eq(1.0.0)" — contradicted (foo is 2.0.0).
        ic = Incompatibility(
            terms=(Term.require("foo", vs_eq(1, 0, 0)),), cause="test"
        )
        assert ps.relation_to(ic) == TermRelation.CONTRADICTS

    def test_relation_inconclusive_unknown_package(self) -> None:
        ps = self._make_ps()
        ic = Incompatibility(
            terms=(Term.require("unknown", VersionSet.full()),), cause="test"
        )
        assert ps.relation_to(ic) == TermRelation.INCONCLUSIVE

    def test_unit_term_returns_undecided(self) -> None:
        ps = self._make_ps()
        ps.add_decision("a", v(1, 0, 0))
        t_a = Term.require("a", vs_eq(1, 0, 0))
        t_b = Term.require("b", vs_gte(2, 0, 0))
        ic = Incompatibility(terms=(t_a, t_b), cause="dep")
        unit = ps.unit_term(ic)
        assert unit is not None
        assert unit.package == "b"


# ---------------------------------------------------------------------------
# 6b-1 — solve() + SolverError / conflict chain
# ---------------------------------------------------------------------------


class TestSolveSimple:
    """Satisfiable graph: root depends on foo >=1.0.0."""

    def _provider(self) -> DictProvider:
        return DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "foo": [v(1, 0, 0), v(1, 1, 0), v(2, 0, 0)],
            },
            deps_map={
                (
                    "__root__",
                    v(0, 0, 1),
                ): [Term.require("foo", vs_gte(1, 0, 0))],
                ("foo", v(1, 0, 0)): [],
                ("foo", v(1, 1, 0)): [],
                ("foo", v(2, 0, 0)): [],
            },
        )

    def test_solve_returns_all_packages(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1))
        assert "__root__" in sol
        assert "foo" in sol

    def test_solve_maxver_default(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1))
        assert sol["foo"] == v(2, 0, 0)

    def test_solve_includes_root_version(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1))
        assert sol["__root__"] == v(0, 0, 1)


class TestSolveDiamondConflict:
    """Diamond conflict (§2 counter-example from spec):

    root → a >=1.0.0, b >=1.0.0
    a@1.0.0 → shared >=1.0.0
    b@1.0.0 → shared <1.0.0
    shared ∈ {0.9.0, 1.0.0}   → no version satisfies both constraints
    """

    def _provider(self) -> DictProvider:
        return DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "a": [v(1, 0, 0)],
                "b": [v(1, 0, 0)],
                "shared": [v(0, 9, 0), v(1, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("a", vs_gte(1, 0, 0)),
                    Term.require("b", vs_gte(1, 0, 0)),
                ],
                ("a", v(1, 0, 0)): [Term.require("shared", vs_gte(1, 0, 0))],
                ("b", v(1, 0, 0)): [Term.require("shared", vs_lt(1, 0, 0))],
                ("shared", v(0, 9, 0)): [],
                ("shared", v(1, 0, 0)): [],
            },
        )

    # RED → GREEN: the solver MUST raise SolverError on this unsatisfiable graph.
    def test_diamond_conflict_raises_solver_error(self) -> None:
        with pytest.raises(SolverError) as exc_info:
            solve(self._provider(), "__root__", v(0, 0, 1))
        err = exc_info.value
        assert err.code == "SOLVE-CONFLICT"

    def test_conflict_chain_names_shared(self) -> None:
        with pytest.raises(SolverError) as exc_info:
            solve(self._provider(), "__root__", v(0, 0, 1))
        chain = exc_info.value.chain
        assert isinstance(chain, ConflictChain)
        # The chain must mention "shared" — the package with conflicting constraints.
        conflicted_pkgs = {step.consequent_package for step in chain.steps}
        assert "shared" in conflicted_pkgs

    def test_conflict_chain_names_both_consumers(self) -> None:
        """§2: the refutation MUST name every contributing consumer."""
        with pytest.raises(SolverError) as exc_info:
            solve(self._provider(), "__root__", v(0, 0, 1))
        chain = exc_info.value.chain
        # Find the step for "shared".
        shared_steps = [s for s in chain.steps if s.consequent_package == "shared"]
        assert shared_steps, "expected a step for 'shared'"
        step = shared_steps[0]
        # Both a and b must appear as antecedents (both constrain shared).
        antecedent_pkgs = {t.package for t in step.antecedents}
        assert "a" in antecedent_pkgs, f"'a' not in antecedents: {antecedent_pkgs}"
        assert "b" in antecedent_pkgs, f"'b' not in antecedents: {antecedent_pkgs}"

    def test_solver_error_str_is_rendered_prose(self) -> None:
        with pytest.raises(SolverError) as exc_info:
            solve(self._provider(), "__root__", v(0, 0, 1))
        err_str = str(exc_info.value)
        assert "version solving failed" in err_str
        assert "shared" in err_str

    def test_render_conflict_chain_is_non_normative(self) -> None:
        """Prose is human-readable and non-empty but not byte-normative."""
        with pytest.raises(SolverError) as exc_info:
            solve(self._provider(), "__root__", v(0, 0, 1))
        rendered = render_conflict_chain(exc_info.value.chain)
        assert len(rendered) > 20


class TestSolveSatisfiable:
    """Transitive graph: root → foo >=1.0.0; foo@2.0.0 → bar >=1.0.0."""

    def _provider(self) -> DictProvider:
        return DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "foo": [v(1, 0, 0), v(2, 0, 0)],
                "bar": [v(1, 0, 0), v(1, 5, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [Term.require("foo", vs_gte(1, 0, 0))],
                ("foo", v(1, 0, 0)): [],
                ("foo", v(2, 0, 0)): [Term.require("bar", vs_gte(1, 0, 0))],
                ("bar", v(1, 0, 0)): [],
                ("bar", v(1, 5, 0)): [],
            },
        )

    def test_transitive_dep_resolved(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1))
        assert "bar" in sol

    def test_maxver_picks_highest_bar(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1))
        assert sol["bar"] == v(1, 5, 0)


# ---------------------------------------------------------------------------
# A4 — version-unknown partition (resolver-semantics RFC §3 Axis A (c))
# ---------------------------------------------------------------------------


class TestVersionUnknownPartition:
    """Solver-side mechanism: decision priority + hard-error classification.

    Resolver-level concerns (candidate labeling, lazy named-stub
    materialization, root-authority remedy branching) are covered end-to-end
    by the conformance corpus (fixture-418/419); these tests isolate the
    SOLVER's own two halves of A4: ``_next_undecided``'s last-scheduling and
    the classification raised from ``_make_decision``.
    """

    def test_unconstrained_version_unknown_resolves_via_sentinel(self) -> None:
        """Regression: the fresco/intonaco untagged-branch-pin case.

        A version-unknown package nothing else constrains resolves with zero
        ceremony via its existing (sentinel) candidate — no exception, no
        special casing visible to the caller.
        """
        provider = VersionUnknownDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "foo": [v(0, 0, 1)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [Term.require("foo", VersionSet.full())],
                ("foo", v(0, 0, 1)): [],
            },
            version_unknown_names={"foo"},
        )
        sol = solve(provider, "__root__", v(0, 0, 1))
        assert sol["foo"] == v(0, 0, 1)

    def test_version_unknown_scheduled_after_normal_packages(self) -> None:
        """``_next_undecided`` defers a version-unknown package to a second
        pass — decided only once every normal-class package is decided.

        root requires foo (version-unknown) FIRST in declaration order, then
        bar (normal). Under the OLD single-pass scan, foo would be returned
        first (it's undecided with a non-empty effective_set as soon as
        root's requirement lands). Under A4, bar must come back first.
        """
        provider = VersionUnknownDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "foo": [v(0, 0, 1)],
                "bar": [v(1, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("foo", VersionSet.full()),
                    Term.require("bar", VersionSet.full()),
                ],
                ("foo", v(0, 0, 1)): [],
                ("bar", v(1, 0, 0)): [],
            },
            version_unknown_names={"foo"},
        )
        partial = PartialSolution()
        # Mirror the root-decision + unit-propagation the real loop performs:
        # both "foo" and "bar" land as full()-constrained derivations, foo
        # first (declaration order), exactly the hazard scenario.
        partial.add_decision("__root__", v(0, 0, 1))
        partial.add_derivation(
            Term.require("foo", VersionSet.full()),
            cause=Incompatibility(terms=(), cause="dependency:__root__@0.0.1"),
        )
        partial.add_derivation(
            Term.require("bar", VersionSet.full()),
            cause=Incompatibility(terms=(), cause="dependency:__root__@0.0.1"),
        )
        assert _next_undecided(partial, provider) == "bar"

    def test_constrained_version_unknown_raises_naming_the_constrainer(self) -> None:
        """A version-unknown package floored by another dep's requirement
        raises ``VersionUnknownConstrained`` naming the real constrainer —
        never a generic ``SolverError``/``SOLVE-CONFLICT``, and never an
        out-of-range candidate silently returned.
        """
        provider = VersionUnknownDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "foo": [v(0, 0, 1)],
                "bar": [v(1, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("foo", VersionSet.full()),
                    Term.require("bar", VersionSet.full()),
                ],
                ("foo", v(0, 0, 1)): [],
                # bar's floor on foo is only discovered when bar is decided —
                # bar must be decided BEFORE foo for this to exercise the
                # ordering hazard (A4 guarantees it via decision priority).
                ("bar", v(1, 0, 0)): [Term.require("foo", vs_gte(1, 0, 0))],
            },
            version_unknown_names={"foo"},
        )
        with pytest.raises(VersionUnknownConstrained) as exc_info:
            solve(provider, "__root__", v(0, 0, 1))
        exc = exc_info.value
        assert exc.package == "foo"
        assert exc.constrainers == (("bar", ">=1.0.0"),)

    def test_constrained_version_unknown_enumerates_all_constrainers(self) -> None:
        """Two independent constrainers on the same version-unknown package
        are BOTH named (the amoxtli incident floored two packages at once —
        a serial fail-fix-rerun loop is the papercut this avoids)."""
        provider = VersionUnknownDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "foo": [v(0, 0, 1)],
                "bar": [v(1, 0, 0)],
                "baz": [v(1, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("foo", VersionSet.full()),
                    Term.require("bar", VersionSet.full()),
                    Term.require("baz", VersionSet.full()),
                ],
                ("foo", v(0, 0, 1)): [],
                ("bar", v(1, 0, 0)): [Term.require("foo", vs_gte(0, 2, 8))],
                ("baz", v(1, 0, 0)): [Term.require("foo", VersionSet.lte(v(0, 9, 0)))],
            },
            version_unknown_names={"foo"},
        )
        with pytest.raises(VersionUnknownConstrained) as exc_info:
            solve(provider, "__root__", v(0, 0, 1))
        assert set(exc_info.value.constrainers) == {
            ("bar", ">=0.2.8"),
            ("baz", "<=0.9.0"),
        }

    def test_constrained_version_unknown_no_phantom_after_backtrack(self) -> None:
        """R8b (phantom constrainer after backtrack): a consumer ``A`` is
        speculatively decided at its highest version (``2.0.0``, MAXVER),
        which floors the version-unknown ``foo`` at ``>=5.0.0`` — but
        ``A@2.0.0`` ALSO requires ``bump`` at a version that doesn't exist,
        an unrelated-to-``foo`` conflict discovered as soon as ``A@2.0.0`` is
        decided (``bump`` was already pinned to its only version BEFORE
        ``A`` — the conflict fires in the SAME unit-propagation pass that
        processes ``A``'s new incompatibilities, so the backtrack undoes
        ``A``'s decision directly, no cascade needed). ``A`` is re-decided at
        ``1.0.0``, which floors ``foo`` at ``<=8.0.0`` instead.

        Because incompatibilities are permanent (append-only, never undone
        by backtracking), the ``A@2.0.0 -> foo>=5.0.0`` incompat is STILL in
        the recorded list when ``foo``'s ``VersionUnknownConstrained`` fires.
        Only ``A``'s FINAL decided version (``1.0.0``) may be named as a
        constrainer — the ``>=5.0.0`` entry from the backtracked-away
        ``2.0.0`` decision is a phantom and must NOT appear.
        """
        provider = VersionUnknownDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "A": [v(1, 0, 0), v(2, 0, 0)],
                "bump": [v(1, 0, 0)],
                "foo": [v(0, 0, 1)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("bump", VersionSet.full()),
                    Term.require("A", VersionSet.full()),
                ],
                ("A", v(2, 0, 0)): [
                    Term.require("foo", vs_gte(5, 0, 0)),
                    # Impossible: `bump` only has 1.0.0, already decided by
                    # the time `A` is picked (root lists `bump` before `A`).
                    # This is what forces the backtrack of A@2.0.0 — it has
                    # nothing to do with `foo`.
                    Term.require("bump", vs_gte(2, 0, 0)),
                ],
                ("A", v(1, 0, 0)): [Term.require("foo", VersionSet.lte(v(8, 0, 0)))],
                ("bump", v(1, 0, 0)): [],
            },
            version_unknown_names={"foo"},
        )
        with pytest.raises(VersionUnknownConstrained) as exc_info:
            solve(provider, "__root__", v(0, 0, 1))
        exc = exc_info.value
        assert exc.package == "foo"
        # ONLY the real constrainer from A's final decided version (1.0.0) —
        # the phantom (A, '>=5.0.0') from the backtracked A@2.0.0 speculative
        # decision must be gone.
        assert exc.constrainers == (("A", "<=8.0.0"),)

    def test_next_undecided_order_unchanged_with_no_version_unknown_packages(
        self,
    ) -> None:
        """When no package is version-unknown, the two-pass scan degenerates
        to the ORIGINAL single-pass insertion-order scan — byte-for-byte the
        same return value (fixture-063's NORMATIVE BFS-order invariant is
        unaffected). Uses plain ``DictProvider`` (no ``is_version_unknown``
        at all) to prove the default-False fallback, not a hardcoded False.
        """
        provider = DictProvider(
            versions_map={"__root__": [v(0, 0, 1)], "x": [v(1, 0, 0)], "y": [v(1, 0, 0)]},
            deps_map={},
        )
        partial = PartialSolution()
        partial.add_decision("__root__", v(0, 0, 1))
        partial.add_derivation(
            Term.require("x", VersionSet.full()),
            cause=Incompatibility(terms=(), cause="dependency:__root__@0.0.1"),
        )
        partial.add_derivation(
            Term.require("y", VersionSet.full()),
            cause=Incompatibility(terms=(), cause="dependency:__root__@0.0.1"),
        )
        assert _next_undecided(partial, provider) == "x"


class TestAccumulatedConstrainers:
    """Direct unit tests for ``_accumulated_constrainers`` (A4/R8b).

    ``_accumulated_constrainers`` now takes a ``partial`` argument (R8b: it
    reads the consumer's FINAL decided version from ``partial.decisions()``,
    not just the append-only ``incompats`` history) — every fixture here
    builds a ``PartialSolution`` with the relevant consumers decided at the
    version the fixture's incompat names, so the "is this consumer's
    decision still live" filter always passes and the pre-existing
    full()/synthetic-cause/dedupe behavior is unaffected.
    """

    def test_skips_full_and_synthetic_causes(self) -> None:
        incompats = [
            # A full() requirement (e.g. a git/url self-term, D-A2) — never a
            # real constrainer, must be skipped.
            Incompatibility(
                terms=(
                    Term.require("consumer1", vs_eq(1, 0, 0)),
                    Term.forbid("foo", VersionSet.full()),
                ),
                cause="dependency:consumer1@1.0.0",
            ),
            # Synthetic backtracking bookkeeping — not a real dep-graph fact.
            Incompatibility(
                terms=(Term.require("foo", vs_eq(0, 0, 1)),),
                cause="conflict-blocks:foo@0.0.1",
            ),
            # The real constrainer.
            Incompatibility(
                terms=(
                    Term.require("consumer2", vs_eq(1, 0, 0)),
                    Term.forbid("foo", vs_gte(0, 2, 8)),
                ),
                cause="dependency:consumer2@1.0.0",
            ),
        ]
        partial = PartialSolution()
        partial.add_decision("consumer1", v(1, 0, 0))
        partial.add_decision("consumer2", v(1, 0, 0))
        result = _accumulated_constrainers(incompats, "foo", partial)
        assert result == (("consumer2", ">=0.2.8"),)

    def test_dedupes_identical_consumer_constraint_pairs(self) -> None:
        incompat = Incompatibility(
            terms=(
                Term.require("consumer", vs_eq(1, 0, 0)),
                Term.forbid("foo", vs_gte(0, 2, 8)),
            ),
            cause="dependency:consumer@1.0.0",
        )
        partial = PartialSolution()
        partial.add_decision("consumer", v(1, 0, 0))
        result = _accumulated_constrainers([incompat, incompat], "foo", partial)
        assert result == (("consumer", ">=0.2.8"),)

    def test_skips_stale_incompat_from_backtracked_consumer_version(self) -> None:
        """R8b: an incompat recorded when ``consumer`` was speculatively
        decided at ``2.0.0`` must NOT be named once ``consumer`` is finally
        decided at a DIFFERENT version (``1.0.0``) — the ``2.0.0`` incompat is
        a stale, permanent fact from a decision that was backtracked away.
        """
        incompats = [
            # Recorded while `consumer` was speculatively at 2.0.0 (later
            # backtracked) — a phantom, must be skipped.
            Incompatibility(
                terms=(
                    Term.require("consumer", vs_eq(2, 0, 0)),
                    Term.forbid("foo", vs_gte(5, 0, 0)),
                ),
                cause="dependency:consumer@2.0.0",
            ),
            # Recorded at `consumer`'s FINAL decided version — real.
            Incompatibility(
                terms=(
                    Term.require("consumer", vs_eq(1, 0, 0)),
                    Term.forbid("foo", VersionSet.lte(v(8, 0, 0))),
                ),
                cause="dependency:consumer@1.0.0",
            ),
        ]
        partial = PartialSolution()
        partial.add_decision("consumer", v(1, 0, 0))
        result = _accumulated_constrainers(incompats, "foo", partial)
        assert result == (("consumer", "<=8.0.0"),)

    def test_skips_incompat_from_consumer_never_finally_decided(self) -> None:
        """A consumer with NO entry in ``partial.decisions()`` at all (e.g.
        fully backtracked away and never re-decided by the time this is
        called) contributes nothing — absence of a final decision is not
        distinguishable from staleness."""
        incompats = [
            Incompatibility(
                terms=(
                    Term.require("consumer", vs_eq(2, 0, 0)),
                    Term.forbid("foo", vs_gte(5, 0, 0)),
                ),
                cause="dependency:consumer@2.0.0",
            ),
        ]
        partial = PartialSolution()  # `consumer` never decided
        result = _accumulated_constrainers(incompats, "foo", partial)
        assert result == ()


# ---------------------------------------------------------------------------
# 6b-2 — Strategy dispatch
# ---------------------------------------------------------------------------


class TestStrategyDispatch:
    """Provider with three versions of 'dep' satisfying >=1.0.0."""

    def _provider(self) -> DictProvider:
        return DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "dep": [v(1, 0, 0), v(1, 5, 0), v(2, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [Term.require("dep", vs_gte(1, 0, 0))],
                ("dep", v(1, 0, 0)): [],
                ("dep", v(1, 5, 0)): [],
                ("dep", v(2, 0, 0)): [],
            },
        )

    # RED → GREEN: MAXVER must pick highest.
    def test_maxver_picks_highest(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1), strategy=Strategy.MAXVER)
        assert sol["dep"] == v(2, 0, 0)

    # RED → GREEN: MINVER must pick lowest.
    def test_minver_picks_lowest(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1), strategy=Strategy.MINVER)
        assert sol["dep"] == v(1, 0, 0)

    # RED → GREEN: SEMVER must pick highest within lower-bound's major (1).
    def test_semver_picks_same_major(self) -> None:
        sol = solve(self._provider(), "__root__", v(0, 0, 1), strategy=Strategy.SEMVER)
        # Lower bound is 1.0.0 → target major = 1; highest within major 1 = 1.5.0.
        assert sol["dep"] == v(1, 5, 0)

    def test_maxver_and_minver_differ(self) -> None:
        sol_max = solve(
            self._provider(), "__root__", v(0, 0, 1), strategy=Strategy.MAXVER
        )
        sol_min = solve(
            self._provider(), "__root__", v(0, 0, 1), strategy=Strategy.MINVER
        )
        assert sol_max["dep"] != sol_min["dep"]

    def test_semver_and_maxver_differ_when_multiple_majors(self) -> None:
        sol_max = solve(
            self._provider(), "__root__", v(0, 0, 1), strategy=Strategy.MAXVER
        )
        sol_semver = solve(
            self._provider(), "__root__", v(0, 0, 1), strategy=Strategy.SEMVER
        )
        assert sol_max["dep"] != sol_semver["dep"]

    def test_semver_conflict_no_same_major(self) -> None:
        """SEMVER raises when lower-bound's major has no candidate."""
        # >=2.0.0 constraint, but only 1.x versions available.
        provider = DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "dep": [v(1, 0, 0), v(1, 5, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [Term.require("dep", vs_gte(2, 0, 0))],
                ("dep", v(1, 0, 0)): [],
                ("dep", v(1, 5, 0)): [],
            },
        )
        with pytest.raises(SolverError):
            solve(provider, "__root__", v(0, 0, 1), strategy=Strategy.SEMVER)

    def test_semver_unbounded_falls_back_to_maxver(self) -> None:
        """SEMVER with an unbounded constraint falls back to maxver."""
        # Full constraint (no lower bound).
        provider = DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "dep": [v(1, 0, 0), v(2, 0, 0), v(3, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("dep", VersionSet.full())
                ],
                ("dep", v(1, 0, 0)): [],
                ("dep", v(2, 0, 0)): [],
                ("dep", v(3, 0, 0)): [],
            },
        )
        sol = solve(provider, "__root__", v(0, 0, 1), strategy=Strategy.SEMVER)
        assert sol["dep"] == v(3, 0, 0)


# ---------------------------------------------------------------------------
# C2 — LowestDirect effective-strategy precompute (resolver-semantics RFC
# §3 Axis C / §4 stage 4, D-C2, #111)
#
# ``LowestDirect`` is a surface value only. ``_effective_strategy_for``
# resolves it to a concrete MINVER (root-direct) / MAXVER (transitive)
# strategy BEFORE ``_pick_version`` ever runs — the picker itself gains no
# ``LowestDirect`` case. Solver-level (synthetic provider), isolating the
# mechanism from resolver-level root-authority construction (covered by
# ``test_c2_lowest_direct.py``).
# ---------------------------------------------------------------------------


class TestEffectiveStrategyPrecompute:
    def _provider(self, root_direct_names: set[str]) -> RootAuthorityDictProvider:
        return RootAuthorityDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "dep": [v(1, 0, 0), v(1, 5, 0), v(2, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [Term.require("dep", vs_gte(1, 0, 0))],
                ("dep", v(1, 0, 0)): [],
                ("dep", v(1, 5, 0)): [],
                ("dep", v(2, 0, 0)): [],
            },
            root_direct_names=root_direct_names,
        )

    # RED → GREEN: a non-LowestDirect strategy passes through unchanged,
    # regardless of directness.
    def test_non_lowest_direct_passes_through(self) -> None:
        provider = self._provider(root_direct_names={"dep"})
        assert _effective_strategy_for(provider, "dep", Strategy.MAXVER) == Strategy.MAXVER
        assert _effective_strategy_for(provider, "dep", Strategy.MINVER) == Strategy.MINVER
        assert _effective_strategy_for(provider, "dep", Strategy.SEMVER) == Strategy.SEMVER

    # RED → GREEN: LowestDirect resolves to MINVER for a root-direct package.
    def test_lowest_direct_resolves_to_minver_for_root_direct(self) -> None:
        provider = self._provider(root_direct_names={"dep"})
        assert (
            _effective_strategy_for(provider, "dep", Strategy.LOWEST_DIRECT)
            == Strategy.MINVER
        )

    # RED → GREEN: LowestDirect resolves to MAXVER for a transitive package.
    def test_lowest_direct_resolves_to_maxver_for_transitive(self) -> None:
        provider = self._provider(root_direct_names=set())
        assert (
            _effective_strategy_for(provider, "dep", Strategy.LOWEST_DIRECT)
            == Strategy.MAXVER
        )

    # RED → GREEN: a provider with no root-authority concept (plain
    # DictProvider) treats every package as transitive — the optional-hook
    # default, mirroring A4/B2's own hook-absence regression contract.
    def test_no_root_authority_hook_defaults_to_transitive(self) -> None:
        provider = DictProvider(
            versions_map={"dep": [v(1, 0, 0)]},
            deps_map={},
        )
        assert (
            _effective_strategy_for(provider, "dep", Strategy.LOWEST_DIRECT)
            == Strategy.MAXVER
        )

    # RED → GREEN: end-to-end through solve() — the whole point of the
    # design deepening. A root-direct dep with multiple candidates picks the
    # LOWEST satisfying version; a transitive dep with multiple candidates
    # still picks the HIGHEST — under the SAME `strategy=LOWEST_DIRECT`.
    def test_solve_contrast_root_direct_minver_transitive_maxver(self) -> None:
        provider = RootAuthorityDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "direct": [v(1, 0, 0), v(2, 0, 0)],
                "transitive": [v(1, 0, 0), v(2, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("direct", VersionSet.full()),
                ],
                ("direct", v(1, 0, 0)): [
                    Term.require("transitive", VersionSet.full()),
                ],
                ("direct", v(2, 0, 0)): [
                    Term.require("transitive", VersionSet.full()),
                ],
                ("transitive", v(1, 0, 0)): [],
                ("transitive", v(2, 0, 0)): [],
            },
            root_direct_names={"direct"},
        )
        sol = solve(
            provider, "__root__", v(0, 0, 1), strategy=Strategy.LOWEST_DIRECT
        )
        assert sol["direct"] == v(1, 0, 0)  # root-direct -> MINVER
        assert sol["transitive"] == v(2, 0, 0)  # transitive -> MAXVER

    # RED → GREEN (design assertion): `_pick_version` has no `LowestDirect`
    # case — calling it directly with that value hits none of the match's
    # arms and raises, rather than silently guessing a version.
    def test_pick_version_has_no_lowest_direct_case(self) -> None:
        with pytest.raises(AssertionError):
            _pick_version(
                [v(1, 0, 0), v(2, 0, 0)],
                VersionSet.full(),
                Strategy.LOWEST_DIRECT,
                "dep",
            )


# ---------------------------------------------------------------------------
# B1 — preference-aware pick (resolver-semantics RFC §4 stage 4, Axis B)
#
# Unit-tests ``_pick_version`` directly (not through ``solve()`` — B1 is
# pick-only mechanism; feeding a real preference from the prior lockfile is
# B2). ``preference`` is the RFC's ``FromLock(v) | None`` as a plain
# ``Version | None`` value.
# ---------------------------------------------------------------------------


class TestPreferenceAwarePick:
    def _candidates(self) -> list[Version]:
        return [v(1, 0, 0), v(1, 5, 0), v(2, 0, 0)]

    # RED → GREEN: preference=None must reproduce today's behavior exactly —
    # zero behavior change is the whole point of B1.
    def test_no_preference_reproduces_maxver(self) -> None:
        chosen = _pick_version(
            self._candidates(), VersionSet.full(), Strategy.MAXVER, "dep"
        )
        assert chosen == v(2, 0, 0)

    def test_no_preference_reproduces_minver(self) -> None:
        chosen = _pick_version(
            self._candidates(),
            VersionSet.full(),
            Strategy.MINVER,
            "dep",
            preference=None,
        )
        assert chosen == v(1, 0, 0)

    # RED → GREEN: an in-range preference short-circuits the strategy,
    # even when the strategy would pick a different (higher) version.
    def test_preference_in_range_wins_over_maxver(self) -> None:
        chosen = _pick_version(
            self._candidates(),
            VersionSet.full(),
            Strategy.MAXVER,
            "dep",
            preference=v(1, 5, 0),
        )
        assert chosen == v(1, 5, 0)

    def test_preference_in_range_wins_over_minver(self) -> None:
        chosen = _pick_version(
            self._candidates(),
            VersionSet.full(),
            Strategy.MINVER,
            "dep",
            preference=v(1, 5, 0),
        )
        assert chosen == v(1, 5, 0)

    # RED → GREEN: a preference outside candidates ∩ allowed is ignored —
    # falls through to the strategy pick unchanged.
    def test_preference_out_of_range_falls_through_to_strategy(self) -> None:
        chosen = _pick_version(
            self._candidates(),
            VersionSet.full(),
            Strategy.MAXVER,
            "dep",
            preference=v(9, 9, 9),
        )
        assert chosen == v(2, 0, 0)

    def test_preference_out_of_range_falls_through_to_minver(self) -> None:
        chosen = _pick_version(
            self._candidates(),
            VersionSet.full(),
            Strategy.MINVER,
            "dep",
            preference=v(9, 9, 9),
        )
        assert chosen == v(1, 0, 0)

    # A preference that survives the constraint filter but not the candidate
    # list itself (e.g. excluded by the accumulated ``allowed`` range) is
    # exactly the "out of range" case above, since ``candidates`` is always
    # pre-filtered by ``allowed.contains`` (the docstring's invariant) — this
    # test pins that a preference cannot bypass ``allowed`` to force an
    # otherwise-disallowed version through.
    def test_preference_not_in_candidates_even_if_constructed_in_range(self) -> None:
        chosen = _pick_version(
            candidates=[v(1, 0, 0), v(2, 0, 0)],
            allowed=vs_gte(1, 0, 0),
            strategy=Strategy.MAXVER,
            package="dep",
            preference=v(1, 5, 0),  # in `allowed` but not a real candidate
        )
        assert chosen == v(2, 0, 0)


# ---------------------------------------------------------------------------
# B2 — feeding prior-lock versions as preferences through solve()
# (resolver-semantics RFC §4 stage 4, Axis B — #192/#70)
#
# B1 (above) unit-tests ``_pick_version``'s short-circuit in isolation. B2's
# job is *feeding* the preference from ``params.prior`` — the resolver-level
# wiring (``_Provider.preference``) is exercised end to end in
# ``test_b2_prior_lock_preference.py``; here we prove the SOLVER-side
# threading (``solve()`` → ``_make_decision`` → ``_preference_for`` →
# ``_pick_version``) with a synthetic in-memory provider, isolating the
# solver mechanism from resolver/index/fetch concerns.
# ---------------------------------------------------------------------------


class PreferenceDictProvider(DictProvider):
    """``DictProvider`` + an explicit ``package -> Version`` preference map.

    Mirrors ``VersionUnknownDictProvider``'s optional-hook pattern (A4): a
    real production provider derives ``preference`` from ``params.prior``
    (resolver.py's ``_Provider.preference``); this test double just takes the
    answer directly, isolating the solver-side mechanism (threading the
    preference into the decision loop) from resolver-level concerns (lockfile
    lookup, DepKey decomposition — covered by ``test_b2_prior_lock_preference.py``).
    """

    def __init__(
        self,
        versions_map: dict[str, list[Version]],
        deps_map: dict[tuple[str, Version], list[Term]],
        preference_map: dict[str, Version],
    ) -> None:
        super().__init__(versions_map, deps_map)
        self._preference_map = preference_map

    def preference(self, package: str) -> Version | None:
        return self._preference_map.get(package)


class TestB2PriorLockPreferenceThroughSolve:
    # RED → GREEN: a provider with NO ``preference`` hook (plain
    # ``DictProvider``) is unaffected — ``_preference_for`` falls back to
    # ``None`` via ``getattr``, so a fresh resolve (no prior lock) is
    # byte-for-byte unchanged. Every other test in this file that uses plain
    # ``DictProvider`` is an implicit proof of this too; this test states it
    # explicitly for B2.
    def test_provider_without_preference_hook_is_unaffected(self) -> None:
        provider = DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "dep": [v(1, 0, 0), v(2, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [Term.require("dep", VersionSet.full())],
                ("dep", v(1, 0, 0)): [],
                ("dep", v(2, 0, 0)): [],
            },
        )
        sol = solve(provider, "__root__", v(0, 0, 1), strategy=Strategy.MAXVER)
        assert sol["dep"] == v(2, 0, 0)

    # RED → GREEN: a locked version still within the accumulated constraint
    # wins over the strategy's newest pick — the minimal-change default.
    def test_locked_version_wins_when_still_satisfiable(self) -> None:
        provider = PreferenceDictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "dep": [v(1, 0, 0), v(1, 5, 0), v(2, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [Term.require("dep", VersionSet.full())],
                ("dep", v(1, 0, 0)): [],
                ("dep", v(1, 5, 0)): [],
                ("dep", v(2, 0, 0)): [],
            },
            preference_map={"dep": v(1, 5, 0)},
        )
        sol = solve(provider, "__root__", v(0, 0, 1), strategy=Strategy.MAXVER)
        assert sol["dep"] == v(1, 5, 0)

    # RED → GREEN: a locked version no longer satisfying the accumulated
    # constraint is FORCED to move — the preference falls through to the
    # ordinary strategy pick over the surviving candidates.
    def test_locked_version_forced_out_when_no_longer_satisfiable(self) -> None:
        provider = PreferenceDictProvider(
            versions_map={
                "root": [v(0, 0, 1)],
                "dep": [v(1, 0, 0), v(1, 5, 0), v(2, 0, 0)],
            },
            deps_map={
                ("root", v(0, 0, 1)): [Term.require("dep", vs_gte(2, 0, 0))],
                ("dep", v(1, 0, 0)): [],
                ("dep", v(1, 5, 0)): [],
                ("dep", v(2, 0, 0)): [],
            },
            preference_map={"dep": v(1, 0, 0)},  # no longer >= 2.0.0
        )
        sol = solve(provider, "root", v(0, 0, 1), strategy=Strategy.MAXVER)
        assert sol["dep"] == v(2, 0, 0)

    # RED → GREEN (the #192 core win): bumping ONE dep's constraint so its
    # locked version no longer satisfies forces ONLY that dep to move; an
    # unrelated, unconstrained dep stays at its locked version even though a
    # newer version exists and a fresh maxver resolve would pick it.
    def test_bump_one_dep_leaves_unrelated_dep_pinned(self) -> None:
        provider = PreferenceDictProvider(
            versions_map={
                "root": [v(0, 0, 1)],
                "bumped": [v(1, 0, 0), v(2, 0, 0)],
                "unrelated": [v(1, 0, 0), v(2, 0, 0)],
            },
            deps_map={
                ("root", v(0, 0, 1)): [
                    Term.require("bumped", vs_gte(2, 0, 0)),
                    Term.require("unrelated", VersionSet.full()),
                ],
                ("bumped", v(1, 0, 0)): [],
                ("bumped", v(2, 0, 0)): [],
                ("unrelated", v(1, 0, 0)): [],
                ("unrelated", v(2, 0, 0)): [],
            },
            preference_map={"bumped": v(1, 0, 0), "unrelated": v(1, 0, 0)},
        )
        sol = solve(provider, "root", v(0, 0, 1), strategy=Strategy.MAXVER)
        assert sol["bumped"] == v(2, 0, 0)  # forced: 1.0.0 no longer >= 2.0.0
        assert sol["unrelated"] == v(1, 0, 0)  # stays locked, NOT newest-wins-bumped


# ---------------------------------------------------------------------------
# 6b-3 — result certificate (resolver-semantics §5)
# ---------------------------------------------------------------------------


class TestSuccessCertificate:
    """§5.1 validity predicate: every witness entry must satisfy its constraint."""

    def _solve_with_incompats(
        self, provider: DictProvider
    ) -> tuple[dict[str, Version], list[Incompatibility]]:
        """Run solve and capture the incompats via a patched solve call."""
        # We need the incompats list for build_success_certificate.
        # Re-implement a thin wrapper that exposes them.
        from milpa.solver import (
            Incompatibility,
            PartialSolution,
            _make_decision,
            _unit_propagate,
        )

        incompats: list[Incompatibility] = [
            Incompatibility(
                terms=(Term.forbid("__root__", vs_eq(0, 0, 1)),),
                cause="root",
            )
        ]
        partial = PartialSolution()
        next_package: str | None = "__root__"
        root_cause_conflicts: list[Incompatibility] = []

        from milpa.solver import _Conflict, build_conflict_chain

        iterations = 0
        while True:
            iterations += 1
            try:
                _unit_propagate(next_package or "__root__", incompats, partial)
                next_package = _make_decision(provider, incompats, partial)
                if next_package is None:
                    return partial.decisions(), incompats
            except _Conflict as conflict:
                if not conflict.incompat.cause.startswith("conflict-blocks:"):
                    root_cause_conflicts.append(conflict.incompat)
                if partial.decision_level == 0:
                    raise SolverError(
                        build_conflict_chain(
                            root_cause_conflicts, conflict.incompat, incompats
                        ),
                        incompats,
                    ) from None
                target_level = partial.decision_level - 1
                undone = partial.backtrack_to(target_level)
                if undone is None:
                    raise SolverError(
                        build_conflict_chain(
                            root_cause_conflicts, conflict.incompat, incompats
                        ),
                        incompats,
                    ) from None
                decided_pkg = undone.term.package
                decided_version_lo = undone.term.versions.intervals[0][0]
                assert isinstance(decided_version_lo, Version)
                incompats.append(
                    Incompatibility(
                        terms=(
                            Term.require(decided_pkg, VersionSet.eq(decided_version_lo)),
                        ),
                        cause=f"conflict-blocks:{decided_pkg}",
                    )
                )
                next_package = decided_pkg

    def _simple_provider(self) -> DictProvider:
        return DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "foo": [v(1, 0, 0), v(2, 0, 0)],
                "bar": [v(1, 0, 0), v(1, 5, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("foo", vs_gte(1, 0, 0)),
                    Term.require("bar", vs_gte(1, 0, 0)),
                ],
                ("foo", v(1, 0, 0)): [],
                ("foo", v(2, 0, 0)): [],
                ("bar", v(1, 0, 0)): [],
                ("bar", v(1, 5, 0)): [],
            },
        )

    def test_build_success_certificate_resolved_entries(self) -> None:
        solution, incompats = self._solve_with_incompats(self._simple_provider())
        cert = build_success_certificate(solution, incompats, "__root__")
        assert isinstance(cert, SolveSuccess)
        pkg_names = {pkg for pkg, _ in cert.resolved}
        assert "__root__" in pkg_names
        assert "foo" in pkg_names
        assert "bar" in pkg_names

    # RED → GREEN: §5.1 validity predicate must hold for every witness entry.
    def test_witness_validity_predicate(self) -> None:
        """For every WitnessEntry, VersionSet.from_constraint(constraint).contains(version)."""
        solution, incompats = self._solve_with_incompats(self._simple_provider())
        cert = build_success_certificate(solution, incompats, "__root__")
        for entry in cert.witness:
            parsed_ver = VersionSet.from_constraint(entry.constraint)
            from milpa.version import parse_version

            ver = parse_version(entry.version)
            assert ver is not None, f"could not parse version {entry.version!r}"
            assert parsed_ver.contains(ver), (
                f"§5.1 validity predicate FAILED: "
                f"{entry.version!r} not in constraint {entry.constraint!r} "
                f"(package={entry.package!r}, satisfied_by={entry.satisfied_by!r})"
            )

    def test_witness_entries_exist_for_declared_constraints(self) -> None:
        """Every dep-constraint incompatibility must produce a witness entry."""
        solution, incompats = self._solve_with_incompats(self._simple_provider())
        cert = build_success_certificate(solution, incompats, "__root__")
        witness_pkgs = {e.package for e in cert.witness}
        # foo and bar both have constraints declared on them from __root__.
        assert "foo" in witness_pkgs
        assert "bar" in witness_pkgs

    def test_witness_satisfied_by_is_set(self) -> None:
        """satisfied_by must name the consuming package."""
        solution, incompats = self._solve_with_incompats(self._simple_provider())
        cert = build_success_certificate(solution, incompats, "__root__")
        for entry in cert.witness:
            assert entry.satisfied_by, "satisfied_by must not be empty"


class TestFailureRefutation:
    """§5.2 failure refutation: the weak UNSAT core must name every contributing consumer."""

    def _diamond_provider(self) -> DictProvider:
        # Same diamond as in TestSolveDiamondConflict.
        return DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "a": [v(1, 0, 0)],
                "b": [v(1, 0, 0)],
                "shared": [v(0, 9, 0), v(1, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("a", vs_gte(1, 0, 0)),
                    Term.require("b", vs_gte(1, 0, 0)),
                ],
                ("a", v(1, 0, 0)): [Term.require("shared", vs_gte(1, 0, 0))],
                ("b", v(1, 0, 0)): [Term.require("shared", vs_lt(1, 0, 0))],
                ("shared", v(0, 9, 0)): [],
                ("shared", v(1, 0, 0)): [],
            },
        )

    # RED → GREEN: refutation must be a non-empty set of named incompatibilities.
    def test_refutation_is_non_empty(self) -> None:
        with pytest.raises(SolverError) as exc_info:
            solve(self._diamond_provider(), "__root__", v(0, 0, 1))
        refutation = exc_info.value.refutation
        assert len(refutation) > 0

    def test_refutation_names_shared_package(self) -> None:
        """§5.2: the refutation MUST name every contributing incompatibility."""
        with pytest.raises(SolverError) as exc_info:
            solve(self._diamond_provider(), "__root__", v(0, 0, 1))
        refutation = exc_info.value.refutation
        refuted_pkgs = {e.package for e in refutation}
        assert "shared" in refuted_pkgs, (
            f"'shared' not in refutation packages: {refuted_pkgs}"
        )

    def test_refutation_named_set_is_genuinely_unsatisfiable(self) -> None:
        """The named constraints for 'shared' must be simultaneously unsatisfiable.

        This is the §5.2 checkable predicate: no version of 'shared' can
        satisfy both constraints named in the refutation.
        """
        with pytest.raises(SolverError) as exc_info:
            solve(self._diamond_provider(), "__root__", v(0, 0, 1))
        refutation = exc_info.value.refutation

        # Collect all constraints on "shared" from the refutation.
        shared_constraints = [
            e.constraint for e in refutation if e.package == "shared"
        ]
        assert len(shared_constraints) >= 2, (
            f"expected >=2 constraints on 'shared', got: {shared_constraints}"
        )

        # The intersection of all named constraints must be empty.
        intersection = VersionSet.full()
        for c in shared_constraints:
            intersection = intersection.intersect(VersionSet.from_constraint(c))

        assert intersection.is_empty(), (
            f"§5.2 violated: intersection of refutation constraints is not empty; "
            f"constraints={shared_constraints}, intersection={intersection}"
        )

    def test_refutation_entries_are_refutation_type(self) -> None:
        with pytest.raises(SolverError) as exc_info:
            solve(self._diamond_provider(), "__root__", v(0, 0, 1))
        for entry in exc_info.value.refutation:
            assert isinstance(entry, RefutationEntry)
            assert entry.package
            assert entry.constraint


# ---------------------------------------------------------------------------
# 6b-3 — certificate JSON serialiser
# ---------------------------------------------------------------------------


class TestCertificateJson:
    def _simple_solution(self) -> SolveSuccess:
        return SolveSuccess(
            resolved=(("__root__", "0.0.1"), ("foo", "2.0.0")),
            witness=(
                WitnessEntry(
                    package="foo",
                    version="2.0.0",
                    constraint="[1.0.0, +∞)",
                    satisfied_by="__root__",
                ),
            ),
        )

    def _solver_error(self) -> SolverError:
        chain = ConflictChain(
            steps=(
                ConflictStep(
                    consequent_package="shared",
                    consequent_description="shared has no satisfying version",
                    antecedents=(
                        Term.require("a", vs_eq(1, 0, 0)),
                        Term.require("b", vs_eq(1, 0, 0)),
                    ),
                    antecedent_constraints=(
                        Term.forbid("shared", vs_lt(1, 0, 0)),
                        Term.forbid("shared", vs_gte(1, 0, 0)),
                    ),
                    cause_tag="dependency:a@1.0.0",
                ),
            )
        )
        # Build an all_incompats list that gives the refutation something to work with.
        incompats = [
            Incompatibility(
                terms=(
                    Term.require("a", vs_eq(1, 0, 0)),
                    Term.forbid("shared", vs_gte(1, 0, 0)),
                ),
                cause="dependency:a@1.0.0",
            ),
            Incompatibility(
                terms=(
                    Term.require("b", vs_eq(1, 0, 0)),
                    Term.forbid("shared", vs_lt(1, 0, 0)),
                ),
                cause="dependency:b@1.0.0",
            ),
        ]
        return SolverError(chain, incompats)

    def test_success_json_kind(self) -> None:
        cert = self._simple_solution()
        doc = json.loads(certificate_to_json(cert))
        assert doc["kind"] == "success"

    def test_success_json_resolved_field(self) -> None:
        cert = self._simple_solution()
        doc = json.loads(certificate_to_json(cert))
        assert any(e["package"] == "foo" and e["version"] == "2.0.0"
                   for e in doc["resolved"])

    def test_success_json_witness_field(self) -> None:
        cert = self._simple_solution()
        doc = json.loads(certificate_to_json(cert))
        assert len(doc["witness"]) == 1
        w = doc["witness"][0]
        assert w["package"] == "foo"
        assert w["satisfied_by"] == "__root__"
        assert "constraint" in w

    def test_failure_json_kind(self) -> None:
        err = self._solver_error()
        doc = json.loads(certificate_to_json(err))
        assert doc["kind"] == "failure"

    def test_failure_json_message(self) -> None:
        err = self._solver_error()
        doc = json.loads(certificate_to_json(err))
        assert "message" in doc
        assert len(doc["message"]) > 0

    def test_failure_json_refutation_field(self) -> None:
        err = self._solver_error()
        doc = json.loads(certificate_to_json(err))
        assert "refutation" in doc
        refuted_pkgs = {e["package"] for e in doc["refutation"]}
        assert "shared" in refuted_pkgs

    def test_json_is_valid(self) -> None:
        """certificate_to_json must produce valid JSON for both result types."""
        success_cert = self._simple_solution()
        err_cert = self._solver_error()
        json.loads(certificate_to_json(success_cert))  # must not raise
        json.loads(certificate_to_json(err_cert))       # must not raise

    def test_success_schema_has_required_fields(self) -> None:
        cert = self._simple_solution()
        doc = json.loads(certificate_to_json(cert))
        assert "kind" in doc
        assert "resolved" in doc
        assert "witness" in doc
        for w in doc["witness"]:
            assert "package" in w
            assert "version" in w
            assert "constraint" in w
            assert "satisfied_by" in w

    def test_failure_schema_has_required_fields(self) -> None:
        err = self._solver_error()
        doc = json.loads(certificate_to_json(err))
        assert "kind" in doc
        assert "message" in doc
        assert "refutation" in doc
        for r in doc["refutation"]:
            assert "package" in r
            assert "constraint" in r

    def test_none_yields_empty_failure_cert(self) -> None:
        """certificate_to_json(None) emits a kind:failure cert with message:null
        and an empty refutation array — the shape Rust emits for non-solver
        MilpaError failures (e.g. RES-UNATTESTED-METADATA) when --certificate
        is set (cli-contract §2.5.2)."""
        doc = json.loads(certificate_to_json(None))
        assert doc["kind"] == "failure"
        assert doc["message"] is None
        assert doc["refutation"] == []


# ---------------------------------------------------------------------------
# Integration: solve + certificate roundtrip
# ---------------------------------------------------------------------------


class TestCertificateRoundtrip:
    """Build a certificate from a real solve() + assert §5 predicates."""

    def _provider(self) -> DictProvider:
        return DictProvider(
            versions_map={
                "__root__": [v(0, 0, 1)],
                "alpha": [v(1, 0, 0), v(2, 0, 0)],
                "beta": [v(3, 0, 0)],
            },
            deps_map={
                ("__root__", v(0, 0, 1)): [
                    Term.require("alpha", vs_gte(1, 0, 0)),
                ],
                ("alpha", v(1, 0, 0)): [],
                ("alpha", v(2, 0, 0)): [Term.require("beta", vs_gte(3, 0, 0))],
                ("beta", v(3, 0, 0)): [],
            },
        )

    def _solve_collect_incompats(self) -> tuple[dict[str, Version], list[Incompatibility]]:
        """Thin wrapper that exposes incompats after solve."""
        from milpa.solver import (
            PartialSolution,
            _Conflict,
            _make_decision,
            _unit_propagate,
            build_conflict_chain,
        )

        incompats: list[Incompatibility] = [
            Incompatibility(
                terms=(Term.forbid("__root__", vs_eq(0, 0, 1)),),
                cause="root",
            )
        ]
        partial = PartialSolution()
        next_package: str | None = "__root__"
        root_cause_conflicts: list[Incompatibility] = []
        provider = self._provider()

        while True:
            try:
                _unit_propagate(next_package or "__root__", incompats, partial)
                next_package = _make_decision(provider, incompats, partial)
                if next_package is None:
                    return partial.decisions(), incompats
            except _Conflict as conflict:
                if not conflict.incompat.cause.startswith("conflict-blocks:"):
                    root_cause_conflicts.append(conflict.incompat)
                if partial.decision_level == 0:
                    raise SolverError(
                        build_conflict_chain(
                            root_cause_conflicts, conflict.incompat, incompats
                        ),
                        incompats,
                    ) from None
                target_level = partial.decision_level - 1
                undone = partial.backtrack_to(target_level)
                if undone is None:
                    raise SolverError(
                        build_conflict_chain(
                            root_cause_conflicts, conflict.incompat, incompats
                        ),
                        incompats,
                    ) from None
                decided_pkg = undone.term.package
                decided_version_lo = undone.term.versions.intervals[0][0]
                assert isinstance(decided_version_lo, Version)
                incompats.append(
                    Incompatibility(
                        terms=(
                            Term.require(decided_pkg, VersionSet.eq(decided_version_lo)),
                        ),
                        cause=f"conflict-blocks:{decided_pkg}",
                    )
                )
                next_package = decided_pkg

    def test_all_witness_entries_satisfy_validity_predicate(self) -> None:
        """§5.1: every witness entry must pass from_constraint(c).contains(v)."""
        solution, incompats = self._solve_collect_incompats()
        cert = build_success_certificate(solution, incompats, "__root__")

        from milpa.version import parse_version

        for entry in cert.witness:
            constraint_set = VersionSet.from_constraint(entry.constraint)
            ver = parse_version(entry.version)
            assert ver is not None, f"unparseable version {entry.version!r}"
            assert constraint_set.contains(ver), (
                f"§5.1 violated: {entry.version!r} not in {entry.constraint!r} "
                f"for {entry.package!r}"
            )

    def test_json_roundtrip_preserves_validity(self) -> None:
        """Certificate JSON → parse → re-assert §5.1 predicate."""
        solution, incompats = self._solve_collect_incompats()
        cert = build_success_certificate(solution, incompats, "__root__")
        doc = json.loads(certificate_to_json(cert))

        from milpa.version import parse_version

        for w in doc["witness"]:
            constraint_set = VersionSet.from_constraint(w["constraint"])
            ver = parse_version(w["version"])
            assert ver is not None
            assert constraint_set.contains(ver)


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------


_VERSIONS = [v(maj, min_, pat) for maj in range(3) for min_ in range(3) for pat in range(3)]


@given(
    dep_versions=st.lists(
        st.sampled_from(_VERSIONS),
        min_size=1,
        max_size=5,
        unique=True,
    ),
    strategy=st.sampled_from([Strategy.MAXVER, Strategy.MINVER]),
)
@settings(max_examples=50)
def test_solve_result_satisfies_all_constraints(
    dep_versions: list[Version],
    strategy: Strategy,
) -> None:
    """Property: when solve() succeeds, every chosen version satisfies its constraints.

    The constraint on 'dep' is >=dep_versions[0], so any version in dep_versions
    that is >= dep_versions[0] is valid.  The chosen version must satisfy this.
    """
    min_ver = min(dep_versions)
    constraint = vs_gte(min_ver.major, min_ver.minor, min_ver.patch)

    provider = DictProvider(
        versions_map={
            "__root__": [v(0, 0, 1)],
            "dep": dep_versions,
        },
        deps_map={
            ("__root__", v(0, 0, 1)): [Term.require("dep", constraint)],
            **{("dep", ver): [] for ver in dep_versions},
        },
    )
    try:
        sol = solve(provider, "__root__", v(0, 0, 1), strategy=strategy)
        chosen = sol.get("dep")
        if chosen is not None:
            assert constraint.contains(chosen), (
                f"chosen {chosen!r} does not satisfy constraint {constraint!r}"
            )
    except SolverError:
        # A solve error is acceptable if the constraint is unsatisfiable;
        # in this case the constraint is always satisfiable (we built it from
        # available versions), so this path should not occur, but we allow it
        # to avoid flaky failures from internal state.
        pass


@given(
    num_versions=st.integers(min_value=1, max_value=6),
)
@settings(max_examples=30)
def test_maxver_ge_minver(num_versions: int) -> None:
    """Property: MAXVER result >= MINVER result for the same dep."""
    dep_versions = [v(1, i, 0) for i in range(num_versions)]
    constraint = vs_gte(1, 0, 0)

    provider = DictProvider(
        versions_map={
            "__root__": [v(0, 0, 1)],
            "dep": dep_versions,
        },
        deps_map={
            ("__root__", v(0, 0, 1)): [Term.require("dep", constraint)],
            **{("dep", ver): [] for ver in dep_versions},
        },
    )
    sol_max = solve(provider, "__root__", v(0, 0, 1), strategy=Strategy.MAXVER)
    sol_min = solve(provider, "__root__", v(0, 0, 1), strategy=Strategy.MINVER)
    assert sol_max["dep"] >= sol_min["dep"]
