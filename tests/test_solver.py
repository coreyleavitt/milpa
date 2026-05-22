"""PubGrub solver tests.

The pure algorithm is exercised against synthetic PackageProviders —
small in-memory dicts of (package, version) → list of dependency Terms.
No network, no git, no .nimble files.
"""

from dataclasses import dataclass

import pytest

from milpa.solver import Term, VersionSet, solve


@dataclass
class DictProvider:
    """In-test PackageProvider backed by a static dict.

    Maps package_name -> { version: list[Term] }. The Terms list is the
    package's dependencies at that version (positive Term per dep with
    its allowed VersionSet).
    """
    data: dict[str, dict[tuple[int, int, int], list[Term]]]

    def versions(self, package: str) -> list[tuple[int, int, int]]:
        return sorted(self.data.get(package, {}).keys())

    def dependencies(self, package: str, version: tuple[int, int, int]) -> list[Term]:
        return self.data.get(package, {}).get(version, [])


def test_versionset_contains_single_interval():
    # >= 0.5.0 (no upper bound)
    s = VersionSet.gte((0, 5, 0))
    assert s.contains((0, 5, 0))
    assert s.contains((0, 5, 1))
    assert s.contains((1, 0, 0))
    assert not s.contains((0, 4, 9))


def test_versionset_from_constraint_string_examples():
    # The constraint shapes our nimble parser produces. parsed via the
    # solver's from_constraint to match what the resolver actually does.
    full = VersionSet.from_constraint(None)
    assert full.contains((0, 0, 0)) and full.contains((99, 99, 99))

    any_kw = VersionSet.from_constraint("any version")
    assert any_kw.contains((0, 0, 0)) and any_kw.contains((99, 99, 99))

    gte = VersionSet.from_constraint(">= 0.5.0")
    assert gte.contains((0, 5, 0)) and gte.contains((1, 0, 0))
    assert not gte.contains((0, 4, 0))

    eq = VersionSet.from_constraint("== 0.5.0")
    assert eq.contains((0, 5, 0))
    assert not eq.contains((0, 5, 1))
    assert not eq.contains((0, 4, 9))

    rng = VersionSet.from_constraint(">= 0.5.0 & < 1.0.0")
    assert rng.contains((0, 5, 0)) and rng.contains((0, 9, 9))
    assert not rng.contains((1, 0, 0)) and not rng.contains((0, 4, 9))

    lt = VersionSet.from_constraint("< 1.0.0")
    assert lt.contains((0, 9, 9))
    assert not lt.contains((1, 0, 0))


def test_versionset_complement():
    # Complement of [0.5.0, ∞) is (-∞, 0.5.0)
    s = VersionSet.gte((0, 5, 0))
    c = s.complement()
    assert c.contains((0, 4, 9))
    assert not c.contains((0, 5, 0))
    assert not c.contains((1, 0, 0))

    # Complement of [0.5.0, 1.0.0) is (-∞, 0.5.0) ∪ [1.0.0, ∞)
    rng = VersionSet.from_constraint(">= 0.5.0 & < 1.0.0")
    c = rng.complement()
    assert c.contains((0, 4, 9))
    assert c.contains((1, 0, 0))
    assert c.contains((2, 0, 0))
    assert not c.contains((0, 5, 0))
    assert not c.contains((0, 9, 9))

    # Complement of empty is full
    assert VersionSet.empty().complement().contains((0, 0, 0))
    # Complement of full is empty
    assert not VersionSet.full().complement().contains((0, 0, 0))


def test_solve_single_root_no_deps():
    provider = DictProvider({
        "root": {(1, 0, 0): []},
    })
    solution = solve(provider, "root", (1, 0, 0))
    assert solution == {"root": (1, 0, 0)}


def test_solve_single_named_dep_one_version():
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("foo", VersionSet.full()),
        ]},
        "foo": {(1, 0, 0): []},
    })
    solution = solve(provider, "root", (1, 0, 0))
    assert solution == {"root": (1, 0, 0), "foo": (1, 0, 0)}


def test_solve_picks_highest_matching_version():
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("foo", VersionSet.from_constraint(">= 0.5.0")),
        ]},
        "foo": {
            (0, 4, 0): [],
            (0, 5, 0): [],
            (0, 6, 0): [],
            (1, 0, 0): [],
        },
    })
    solution = solve(provider, "root", (1, 0, 0))
    assert solution["foo"] == (1, 0, 0)  # highest matching


def test_solve_unifies_compatible_constraints_across_packages():
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("a", VersionSet.full()),
            Term.require("b", VersionSet.full()),
        ]},
        "a": {(1, 0, 0): [
            Term.require("shared", VersionSet.from_constraint(">= 0.5.0")),
        ]},
        "b": {(1, 0, 0): [
            Term.require("shared", VersionSet.from_constraint("< 1.0.0")),
        ]},
        "shared": {
            (0, 5, 0): [],
            (0, 9, 0): [],
            (1, 0, 0): [],
        },
    })
    solution = solve(provider, "root", (1, 0, 0))
    # Intersection [0.5.0, 1.0.0) — highest matching is 0.9.0
    assert solution["shared"] == (0, 9, 0)


def test_solve_incompatible_constraints_raises_with_chain():
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("a", VersionSet.full()),
            Term.require("b", VersionSet.full()),
        ]},
        "a": {(1, 0, 0): [
            Term.require("shared", VersionSet.from_constraint(">= 1.0.0")),
        ]},
        "b": {(1, 0, 0): [
            Term.require("shared", VersionSet.from_constraint("< 1.0.0")),
        ]},
        "shared": {
            (0, 9, 0): [],
            (1, 0, 0): [],
        },
    })
    from milpa.solver import SolverError
    with pytest.raises(SolverError) as exc:
        solve(provider, "root", (1, 0, 0))
    msg = str(exc.value)
    assert "shared" in msg


def test_solve_cycle_is_handled_without_infinite_loop():
    # A→B→A. Both have one version. The cycle should resolve without
    # hanging or raising spuriously — A and B can coexist at their
    # single versions, just with circular constraints.
    provider = DictProvider({
        "a": {(1, 0, 0): [
            Term.require("b", VersionSet.full()),
        ]},
        "b": {(1, 0, 0): [
            Term.require("a", VersionSet.full()),
        ]},
    })
    solution = solve(provider, "a", (1, 0, 0))
    assert solution == {"a": (1, 0, 0), "b": (1, 0, 0)}


def test_solve_missing_dep_raises_naming_the_dep():
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("missing_pkg", VersionSet.full()),
        ]},
        # `missing_pkg` is not in provider data
    })
    from milpa.solver import SolverError
    with pytest.raises(SolverError) as exc:
        solve(provider, "root", (1, 0, 0))
    assert "missing_pkg" in str(exc.value)


def test_solve_semver_strategy_locks_to_lower_bound_major():
    """SemVer: highest candidate within the same major as the
    constraint's lower bound. Constraint `>= 1.2.0` with candidates
    [1.2, 1.5, 2.0, 2.3]: pick 1.5 (highest within major=1)."""
    from milpa.solver import Strategy
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("foo", VersionSet.from_constraint(">= 1.2.0")),
        ]},
        "foo": {
            (1, 2, 0): [],
            (1, 5, 0): [],
            (2, 0, 0): [],
            (2, 3, 0): [],
        },
    })
    solution = solve(provider, "root", (1, 0, 0), strategy=Strategy.SEMVER)
    assert solution["foo"] == (1, 5, 0)


def test_solve_semver_with_unbounded_constraint_falls_back_to_maxver():
    """If the constraint has no lower bound, SemVer can't pick a
    'compatible major' — falls back to MaxVer behavior."""
    from milpa.solver import Strategy
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("foo", VersionSet.from_constraint("< 5.0.0")),
        ]},
        "foo": {
            (1, 0, 0): [],
            (2, 0, 0): [],
            (3, 0, 0): [],
            (4, 0, 0): [],
        },
    })
    solution = solve(provider, "root", (1, 0, 0), strategy=Strategy.SEMVER)
    # No lower bound → max(candidates)
    assert solution["foo"] == (4, 0, 0)


def test_solve_semver_rejects_when_only_cross_major_candidates_exist():
    """If only candidates with a different major can satisfy the
    constraint, SemVer refuses rather than silently accepting a
    cross-major version."""
    from milpa.solver import SolverError, Strategy
    provider = DictProvider({
        "root": {(1, 0, 0): [
            # Wide constraint allows both 1.x and 2.x candidates
            Term.require("foo", VersionSet.from_constraint(">= 1.0.0")),
        ]},
        "foo": {
            # No 1.x — only 2.x candidates exist
            (2, 0, 0): [],
            (2, 5, 0): [],
        },
    })
    with pytest.raises(SolverError):
        solve(provider, "root", (1, 0, 0), strategy=Strategy.SEMVER)


def test_solve_minver_strategy_picks_lowest_satisfying():
    """MinVer locks libraries against the floor of their supported
    versions — `requires "X >= 0.5"` resolves X=0.5.0, not the latest."""
    from milpa.solver import Strategy
    provider = DictProvider({
        "root": {(1, 0, 0): [
            Term.require("foo", VersionSet.from_constraint(">= 0.5.0")),
        ]},
        "foo": {
            (0, 4, 0): [],
            (0, 5, 0): [],
            (0, 6, 0): [],
            (1, 0, 0): [],
        },
    })
    solution = solve(provider, "root", (1, 0, 0), strategy=Strategy.MINVER)
    # Floor of the satisfying range is 0.5.0, not 1.0.0 like MaxVer would pick
    assert solution["foo"] == (0, 5, 0)


def test_solve_backtracks_to_compatible_version():
    """The PubGrub-forcing test.

    A naïve greedy resolver picks A@2 (highest), then can't find any B
    satisfying B@>=2 (only B@1 exists), and fails. A proper PubGrub
    solver backtracks to A@1, finds B@1, succeeds.
    """
    provider = DictProvider({
        "root": {(1, 0, 0): [Term.require("a", VersionSet.full())]},
        "a": {
            (1, 0, 0): [Term.require("b", VersionSet.from_constraint(">= 1.0.0"))],
            (2, 0, 0): [Term.require("b", VersionSet.from_constraint(">= 2.0.0"))],
        },
        "b": {
            (1, 0, 0): [],
            # No b@2 exists — so a@2 is unsatisfiable; solver must pick a@1
        },
    })
    solution = solve(provider, "root", (1, 0, 0))
    assert solution["a"] == (1, 0, 0)
    assert solution["b"] == (1, 0, 0)
