"""S2 (RFC #23 §7): same-package `enables` closure — unit tests.

Conformance note (stated explicitly, not a gap):
  S2's pure closure function is NOT observable through the conformance
  runner's `resolve` command because active_flags in the lockfile are only
  populated when S3/S4a wire cross-package flag activation through the
  resolver.  The conformance corpus fixtures for S2 arrive when S5 lands
  (lockfile active_flags) and S3/S4a (resolver wiring).  S2 is covered
  here via unit tests in both impls asserting identical closure results
  on identical inputs (cycles + multi-hop + idempotence + order-independence).
"""

from __future__ import annotations

import pytest

from milpa.manifest import FlagDecl, flag_enables_closure


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flags(*specs: tuple[str, tuple[str, ...]]) -> tuple[FlagDecl, ...]:
    """Build a flags tuple from (name, enables_same_pkg) pairs."""
    return tuple(
        FlagDecl(name=name, enables_same_pkg=enables) for name, enables in specs
    )


# ---------------------------------------------------------------------------
# Property 1: Seed inclusion — result ⊇ seed
# ---------------------------------------------------------------------------


class TestSeedInclusion:
    def test_empty_seed_returns_empty(self) -> None:
        flags = _flags(("tls", ()), ("http", ()))
        assert flag_enables_closure(flags, frozenset()) == frozenset()

    def test_seed_with_no_enables(self) -> None:
        flags = _flags(("tls", ()), ("http", ()))
        result = flag_enables_closure(flags, frozenset({"tls"}))
        assert "tls" in result

    def test_full_seed_preserved(self) -> None:
        flags = _flags(("tls", ()), ("http", ()))
        seed = frozenset({"tls", "http"})
        result = flag_enables_closure(flags, seed)
        assert seed <= result


# ---------------------------------------------------------------------------
# Property 2: One-hop enable
# ---------------------------------------------------------------------------


class TestOneHopEnable:
    def test_one_hop(self) -> None:
        """seed {full} where full enables 'tls' → result ⊇ {full, tls}."""
        flags = _flags(("tls", ()), ("http", ()), ("full", ("tls", "http")))
        result = flag_enables_closure(flags, frozenset({"full"}))
        assert result == frozenset({"full", "tls", "http"})

    def test_inactive_flag_does_not_propagate(self) -> None:
        """A flag not in the seed does not pull in its enables targets."""
        flags = _flags(("tls", ()), ("full", ("tls",)))
        # seed does NOT include "full"
        result = flag_enables_closure(flags, frozenset({"tls"}))
        assert result == frozenset({"tls"})

    def test_enables_multiple_targets(self) -> None:
        flags = _flags(("a", ()), ("b", ()), ("c", ()), ("meta", ("a", "b", "c")))
        result = flag_enables_closure(flags, frozenset({"meta"}))
        assert result == frozenset({"meta", "a", "b", "c"})


# ---------------------------------------------------------------------------
# Property 3: Transitive (multi-hop)
# ---------------------------------------------------------------------------


class TestTransitive:
    def test_two_hop(self) -> None:
        """a enables b, b enables c, seed {a} → {a, b, c}."""
        flags = _flags(("c", ()), ("b", ("c",)), ("a", ("b",)))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert result == frozenset({"a", "b", "c"})

    def test_three_hop(self) -> None:
        """a→b→c→d chain from seed {a}."""
        flags = _flags(("d", ()), ("c", ("d",)), ("b", ("c",)), ("a", ("b",)))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert result == frozenset({"a", "b", "c", "d"})

    def test_diamond(self) -> None:
        """Diamond: a→{b,c}, b→d, c→d. result is {a,b,c,d} (no dup)."""
        flags = _flags(("d", ()), ("b", ("d",)), ("c", ("d",)), ("a", ("b", "c")))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert result == frozenset({"a", "b", "c", "d"})


# ---------------------------------------------------------------------------
# Property 4: Idempotence — closure(closure(S)) == closure(S)
# ---------------------------------------------------------------------------


class TestIdempotence:
    def test_closure_is_idempotent(self) -> None:
        flags = _flags(("c", ()), ("b", ("c",)), ("a", ("b",)))
        seed = frozenset({"a"})
        first = flag_enables_closure(flags, seed)
        second = flag_enables_closure(flags, first)
        assert first == second

    def test_idempotent_no_enables(self) -> None:
        flags = _flags(("x", ()), ("y", ()))
        seed = frozenset({"x", "y"})
        first = flag_enables_closure(flags, seed)
        second = flag_enables_closure(flags, first)
        assert first == second


# ---------------------------------------------------------------------------
# Property 5: Cycle termination — must terminate and return the cycle nodes
# ---------------------------------------------------------------------------


class TestCycleTermination:
    def test_two_cycle(self) -> None:
        """a enables b, b enables a, seed {a} → {a, b}; function terminates."""
        flags = _flags(("b", ("a",)), ("a", ("b",)))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert result == frozenset({"a", "b"})

    def test_self_enable(self) -> None:
        """A flag that enables itself is a trivial cycle; still terminates."""
        flags = _flags(("a", ("a",)))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert result == frozenset({"a"})

    def test_three_cycle(self) -> None:
        """a→b→c→a cycle; seed {a} → {a, b, c}."""
        flags = _flags(("c", ("a",)), ("b", ("c",)), ("a", ("b",)))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert result == frozenset({"a", "b", "c"})

    def test_cycle_plus_tail(self) -> None:
        """a→b→a cycle, a also enables d; seed {a} → {a, b, d}."""
        flags = _flags(("d", ()), ("b", ("a",)), ("a", ("b", "d")))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert result == frozenset({"a", "b", "d"})


# ---------------------------------------------------------------------------
# Property 6: Order-independence / monotonicity
# ---------------------------------------------------------------------------


class TestOrderIndependence:
    def test_flag_table_order_does_not_affect_result(self) -> None:
        """The closure result is the same regardless of flag declaration order."""
        seed = frozenset({"meta"})
        # Order A: meta last
        flags_a = _flags(("a", ()), ("b", ()), ("meta", ("a", "b")))
        # Order B: meta first
        flags_b = _flags(("meta", ("a", "b")), ("b", ()), ("a", ()))
        assert flag_enables_closure(flags_a, seed) == flag_enables_closure(flags_b, seed)

    def test_union_of_enables_is_commutative(self) -> None:
        """Two flags in seed, each enabling a target; order of seeding doesn't matter."""
        flags = _flags(("x", ()), ("y", ()), ("fa", ("x",)), ("fb", ("y",)))
        r1 = flag_enables_closure(flags, frozenset({"fa", "fb"}))
        r2 = flag_enables_closure(flags, frozenset({"fb", "fa"}))
        assert r1 == r2 == frozenset({"fa", "fb", "x", "y"})


# ---------------------------------------------------------------------------
# Property 7: Cross-package enables_cross_pkg entries are IGNORED (S2 scope)
# ---------------------------------------------------------------------------


class TestCrossPkgIgnored:
    def test_cross_pkg_entries_not_followed(self) -> None:
        """cross-package enables children are ignored by S2 closure (resolve-time, S3/S4a)."""
        from milpa.manifest import CrossPkgEnable, FlagRequest

        cross = CrossPkgEnable(dep="chronos", flag_requests=(FlagRequest(name="tls", enabled=True),))
        flags = (
            FlagDecl(name="tls"),
            FlagDecl(name="full", enables_same_pkg=("tls",), enables_cross_pkg=(cross,)),
        )
        result = flag_enables_closure(flags, frozenset({"full"}))
        # "tls" (same-pkg) is reached; "chronos" is NOT a flag name here
        assert "tls" in result
        assert "chronos" not in result

    def test_flag_with_only_cross_pkg_enables_still_in_seed(self) -> None:
        """A flag with no same-pkg enables but cross-pkg only still returns itself."""
        from milpa.manifest import CrossPkgEnable, FlagRequest

        cross = CrossPkgEnable(dep="somelib", flag_requests=(FlagRequest(name="feature", enabled=True),))
        flags = (
            FlagDecl(name="net", enables_cross_pkg=(cross,)),
        )
        result = flag_enables_closure(flags, frozenset({"net"}))
        assert result == frozenset({"net"})


# ---------------------------------------------------------------------------
# Regression: unknown flag names in enables_same_pkg (post-parse validated,
# but the closure must handle them gracefully — skip unknown targets)
# ---------------------------------------------------------------------------


class TestUnknownTargetGraceful:
    def test_closure_skips_unknown_enables_targets(self) -> None:
        """Closure skips enables targets not in the flag table (should not exist
        after post-parse validation, but the fn must not crash)."""
        flags = _flags(("a", ("nonexistent",)))
        result = flag_enables_closure(flags, frozenset({"a"}))
        assert "a" in result
        assert "nonexistent" not in result


# ---------------------------------------------------------------------------
# Integration-style: full example matching RFC §3.1.1 sample
# ---------------------------------------------------------------------------


class TestRFCExample:
    def test_rfc_full_flag_example(self) -> None:
        """RFC §3.1.1 example: tls, http, full enables {tls, http}.

        Seed {full} → {full, tls, http}. cross-pkg (chronos) ignored in S2.
        """
        from milpa.manifest import CrossPkgEnable, FlagRequest

        chronos_tls = CrossPkgEnable(dep="chronos", flag_requests=(FlagRequest(name="tls", enabled=True),))
        flags = (
            FlagDecl(name="tls", default=False),
            FlagDecl(name="http", default=False),
            FlagDecl(name="full", default=False, enables_same_pkg=("tls", "http"), enables_cross_pkg=(chronos_tls,)),
        )
        result = flag_enables_closure(flags, frozenset({"full"}))
        assert result == frozenset({"full", "tls", "http"})

    def test_default_seeding_is_callers_responsibility(self) -> None:
        """The closure fn takes an explicit seed; callers seed from default-true flags.

        This confirms the design choice: flag_enables_closure is a pure fn
        over (flags, seed). Default-based seeding happens in the caller
        (resolver, frozen path) — not baked into the closure fn.
        The test seeds from default-true flags manually and asserts the result.
        """
        flags = (
            FlagDecl(name="ssl", default=True),   # default-true
            FlagDecl(name="debug", default=False),
            FlagDecl(name="net", default=True, enables_same_pkg=("ssl",)),
        )
        # Caller seeds from default-true flags
        defaults_seed = frozenset(f.name for f in flags if f.default)
        assert defaults_seed == frozenset({"ssl", "net"})
        result = flag_enables_closure(flags, defaults_seed)
        # net enables ssl (already in seed); debug not activated
        assert result == frozenset({"ssl", "net"})
        assert "debug" not in result
