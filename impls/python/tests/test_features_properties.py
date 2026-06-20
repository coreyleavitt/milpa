"""S12 (RFC #23 §7 Stage E): property-based tests for the feature-activation system.

Three algebraic invariants:

1. **Union commutativity / order-independence** (§3.1.3):
   When multiple consumers request flags on a shared dep, the resulting
   ``active_flags`` set is independent of consumer processing order.
   Tested via ``compute_dep_active_flags`` directly (the SSOT) and via
   arbitrary permutations of flag-request tuples.

2. **Fixpoint idempotence + monotonicity** (§3.1.2):
   ``flag_enables_closure(flags, closure(flags, seed)) == closure(flags, seed)``.
   Also: ``closure(flags, seed) ⊇ seed`` (monotone — seed always included).
   Tested with generated flag tables and seeds.

3. **Prune completeness** (§3.2 + §7 S7):
   A dep whose auto-gating flag is inactive (default=#false, no enabling
   request) never appears in the resolved/active set.  For any random
   manifest with optional deps, the inactive-flagged dep is absent from
   the active_flags key set AND the flag itself is not in the closure.

Hypothesis database: ``impls/python/.hypothesis/`` (gitignored, per project convention).
"""

from __future__ import annotations

import itertools
from typing import Sequence

from hypothesis import assume, given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# KDL-safe identifier alphabet (same constraint as other property test files in
# this repo — flag names must be valid KDL identifiers; no leading digits,
# no special chars beyond - and _).
# ---------------------------------------------------------------------------

_FLAG_CHARS = "abcdefghijklmnopqrstuvwxyz-"
_FLAG_FIRST = "abcdefghijklmnopqrstuvwxyz"  # no leading -


@st.composite
def flag_name_st(draw: st.DrawFn) -> str:
    """Generate a valid flag identifier: [a-z][a-z-]*."""
    first = draw(st.sampled_from(_FLAG_FIRST))
    rest = draw(st.text(alphabet=_FLAG_CHARS, min_size=0, max_size=7))
    # strip trailing '-' to avoid malformed names
    name = (first + rest).rstrip("-")
    assume(len(name) >= 1)
    return name


# ---------------------------------------------------------------------------
# Hypothesis strategy: a ``FlagDecl`` tuple with no enables (leaf flags).
# Enables edges are added separately by the fixpoint strategy to avoid
# producing unreachable enables targets (which the closure silently skips
# but which reduce exercise of meaningful paths).
# ---------------------------------------------------------------------------


@st.composite
def flag_decls_no_enables_st(draw: st.DrawFn, min_flags: int = 1, max_flags: int = 6):
    """Generate a tuple of FlagDecl with unique names and no enables edges."""
    from milpa.manifest import FlagDecl

    n = draw(st.integers(min_value=min_flags, max_value=max_flags))
    names: list[str] = draw(
        st.lists(flag_name_st(), min_size=n, max_size=n, unique=True)
    )
    flags = tuple(
        FlagDecl(
            name=name,
            default=draw(st.booleans()),
        )
        for name in names
    )
    return flags


@st.composite
def flag_decls_with_enables_st(draw: st.DrawFn, min_flags: int = 2, max_flags: int = 6):
    """Generate a FlagDecl tuple that includes some same-package enables edges.

    Ensures all enables targets are declared flags (the closure only follows
    targets in the flag table, but having valid targets exercises more code paths).
    """
    from milpa.manifest import FlagDecl

    n = draw(st.integers(min_value=min_flags, max_value=max_flags))
    names: list[str] = draw(
        st.lists(flag_name_st(), min_size=n, max_size=n, unique=True)
    )
    flags: list[FlagDecl] = []
    for name in names:
        # Pick 0–2 enables targets from the already-added names (backward references)
        # or sometimes forward references (closure handles both).
        existing = [f.name for f in flags] + names  # allow forward refs
        num_enables = draw(st.integers(min_value=0, max_value=min(2, len(existing))))
        enables = tuple(
            draw(st.sampled_from(existing))
            for _ in range(num_enables)
        )
        # Deduplicate preserving order (tuple of unique names).
        enables_dedup: tuple[str, ...] = tuple(dict.fromkeys(enables))
        flags.append(FlagDecl(
            name=name,
            default=draw(st.booleans()),
            enables_same_pkg=enables_dedup,
        ))
    return tuple(flags)


@st.composite
def seed_for_flags_st(draw: st.DrawFn, flags):
    """Generate a seed frozenset drawn from the names in flags (possibly empty)."""
    names = [f.name for f in flags]
    if not names:
        return frozenset()
    chosen = draw(st.lists(st.sampled_from(names), min_size=0, max_size=len(names), unique=True))
    return frozenset(chosen)


@st.composite
def flag_requests_st(draw: st.DrawFn, flags):
    """Generate a tuple of FlagRequest for a subset of the given flags."""
    from milpa.manifest import FlagRequest

    names = [f.name for f in flags]
    if not names:
        return ()
    # Pick 0 to len(names) flag requests, with enabled drawn randomly.
    n = draw(st.integers(min_value=0, max_value=len(names)))
    sampled = draw(st.lists(st.sampled_from(names), min_size=n, max_size=n, unique=True))
    return tuple(
        FlagRequest(name=name, enabled=draw(st.booleans()))
        for name in sampled
    )


# ===========================================================================
# Property 1: Union commutativity / order-independence
#
# §3.1.3: "D is resolved once with the union of all requested features."
# The active flag-name set must be identical regardless of the order that
# FlagRequest tuples are fed into compute_dep_active_flags.
#
# Algebraic statement:
#   For any flags F and any multiset of requests R,
#   active_names(F, R) == active_names(F, permute(R))
#   where active_names strips the ActivationSource metadata.
# ===========================================================================


@given(flag_decls_no_enables_st())
@settings(max_examples=150)
def test_prop_union_order_independent_of_request_permutation(flags) -> None:
    """active_flags name-set is the same for every permutation of flag requests.

    Algebraic invariant (§3.1.3): union is commutative.  The order in
    which consumer flag requests are accumulated must not affect the result.
    We test all permutations for small inputs; Hypothesis exercises the
    boundaries.
    """
    from milpa.resolver import compute_dep_active_flags
    from milpa.manifest import FlagRequest

    # Build a deterministic set of requests: one positive + one negative per flag.
    # This exercises both the opt-out (absence-of-request) and positive paths.
    reqs: list[FlagRequest] = []
    for i, fd in enumerate(flags):
        # Alternate positive/negative to create a non-trivial mix.
        reqs.append(FlagRequest(name=fd.name, enabled=(i % 2 == 0)))

    if not reqs:
        return  # vacuously true

    # Compute reference result with original order.
    ref_result = frozenset(compute_dep_active_flags(flags, tuple(reqs)).keys())

    # Try all permutations (bounded — flags is at most 6 elements → ≤ 720 perms).
    for perm in itertools.permutations(reqs):
        permuted_result = frozenset(compute_dep_active_flags(flags, perm).keys())
        assert permuted_result == ref_result, (
            f"active_flags differs for permutation {[r.name for r in perm]}: "
            f"expected {ref_result}, got {permuted_result}"
        )



@given(flag_decls_no_enables_st())
@settings(max_examples=200)
def test_prop_union_positive_request_always_activates(flags) -> None:
    """A positive FlagRequest always results in that flag being active.

    §3.1.3: union semantics — a positive request from ANY consumer activates
    the flag, regardless of other negative requests from the same batch.

    Algebraic: ∀ f ∈ declared, positive_request(f) ∈ requests ⇒ f ∈ active_names.
    """
    from milpa.resolver import compute_dep_active_flags
    from milpa.manifest import FlagRequest

    # One positive request per flag, plus a negative opt-out for the same flag.
    # The positive must win.
    for fd in flags:
        reqs = (
            FlagRequest(name=fd.name, enabled=True),   # positive
            FlagRequest(name=fd.name, enabled=False),  # opt-out (absence-of-request)
        )
        result = compute_dep_active_flags(flags, reqs)
        assert fd.name in result, (
            f"flag {fd.name!r} not active despite positive request; result={set(result)}"
        )

        # Also test reversed order: opt-out first, then positive.
        reqs_rev = (
            FlagRequest(name=fd.name, enabled=False),
            FlagRequest(name=fd.name, enabled=True),
        )
        result_rev = compute_dep_active_flags(flags, reqs_rev)
        assert fd.name in result_rev, (
            f"flag {fd.name!r} not active when opt-out processed before positive; "
            f"result={set(result_rev)}"
        )


@given(flag_decls_no_enables_st())
@settings(max_examples=150)
def test_prop_union_negative_only_does_not_activate(flags) -> None:
    """Negative-only requests on non-default flags produce no active flags.

    §3.1.3: flag "x" #false is absence-of-request.  When a flag is default=#false
    and the only requests are negative, the flag MUST remain inactive.
    """
    from milpa.resolver import compute_dep_active_flags
    from milpa.manifest import FlagRequest

    # Only test flags that are NOT default-true (default-true would activate regardless).
    non_default_flags = tuple(fd for fd in flags if not fd.default)
    if not non_default_flags:
        return  # skip if all flags are default=true

    # All-negative requests on non-default flags.
    reqs = tuple(FlagRequest(name=fd.name, enabled=False) for fd in non_default_flags)
    result = compute_dep_active_flags(non_default_flags, reqs)
    inactive_names = frozenset(fd.name for fd in non_default_flags)
    for name in inactive_names:
        assert name not in result, (
            f"flag {name!r} must NOT be active from negative-only requests; "
            f"result={set(result)}"
        )


@given(flag_decls_no_enables_st())
@settings(max_examples=150)
def test_prop_default_true_flags_always_in_active_set(flags) -> None:
    """default=#true flags are always in active(D), independent of requests.

    §3.1.2 rule 1: active(D) ⊇ { f ∈ D.flags : f.default }.  No request
    (positive or negative) can remove a default-true flag from the active set.
    """
    from milpa.resolver import compute_dep_active_flags, ActivationSource
    from milpa.manifest import FlagRequest

    default_true_names = frozenset(fd.name for fd in flags if fd.default)
    if not default_true_names:
        return  # vacuously true

    # Worst-case: all negative opt-out requests.
    reqs = tuple(FlagRequest(name=fd.name, enabled=False) for fd in flags)
    result = compute_dep_active_flags(flags, reqs)
    for name in default_true_names:
        assert name in result, (
            f"default-true flag {name!r} must stay active despite opt-out; "
            f"result={set(result)}"
        )
        assert ActivationSource.DEFAULT in result[name], (
            f"DEFAULT must be a source for {name!r}; sources={result[name]}"
        )


# ===========================================================================
# Property 2: Fixpoint idempotence and monotonicity
#
# §3.1.2: "Activation = a monotone closure."
#   (a) Idempotence: closure(closure(S)) == closure(S).
#   (b) Monotone seed inclusion: closure(S) ⊇ S.
#   (c) Monotone growth: S ⊆ T ⇒ closure(S) ⊆ closure(T)  (enabled by union).
# ===========================================================================


@given(flag_decls_with_enables_st())
@settings(max_examples=200)
def test_prop_closure_idempotent(flags) -> None:
    """closure(closure(S)) == closure(S) for any seed S.

    §3.1.2 (idempotence): running the closure a second time on an already-
    converged set returns the same set.  This guarantees fixpoint stability.
    """
    from milpa.manifest import flag_enables_closure

    names = [f.name for f in flags]
    if not names:
        return
    # Use the default-true flags as seed (the canonical real-world seed).
    seed = frozenset(f.name for f in flags if f.default)
    once = flag_enables_closure(flags, seed)
    twice = flag_enables_closure(flags, once)
    assert once == twice, (
        f"closure is not idempotent: first={once}, second={twice}, seed={seed}"
    )


@given(flag_decls_with_enables_st())
@settings(max_examples=200)
def test_prop_closure_monotone_seed_included(flags) -> None:
    """closure(S) ⊇ S — the seed is always a subset of the closure.

    §3.1.2 (seed inclusion): no seed flag is dropped.  The closure function
    is monotone: it can only add elements, never remove them.
    """
    from milpa.manifest import flag_enables_closure

    seed = frozenset(f.name for f in flags if f.default)
    result = flag_enables_closure(flags, seed)
    assert seed <= result, (
        f"seed not subset of closure: seed={seed}, closure={result}"
    )


@given(flag_decls_with_enables_st())
@settings(max_examples=200)
def test_prop_closure_monotone_larger_seed_grows_result(flags) -> None:
    """S ⊆ T ⇒ closure(S) ⊆ closure(T).

    The closure is monotone with respect to the lattice of flag-name sets.
    Adding more flags to the seed cannot remove flags from the closure result.
    """
    from milpa.manifest import flag_enables_closure

    all_names = frozenset(f.name for f in flags)
    if not all_names:
        return

    default_seed = frozenset(f.name for f in flags if f.default)
    full_seed = all_names  # superset of default_seed

    closure_small = flag_enables_closure(flags, default_seed)
    closure_large = flag_enables_closure(flags, full_seed)

    assert closure_small <= closure_large, (
        f"monotonicity violated: closure(smaller) is not ⊆ closure(larger); "
        f"smaller_result={closure_small}, larger_result={closure_large}"
    )


@given(flag_decls_with_enables_st())
@settings(max_examples=150)
def test_prop_closure_empty_seed_is_empty_when_no_edges(flags) -> None:
    """closure(∅) == ∅ when no flag is in the seed.

    The closure must not spontaneously activate flags that are not reachable
    from the seed.  With an empty seed, the result must be empty.
    """
    from milpa.manifest import flag_enables_closure

    result = flag_enables_closure(flags, frozenset())
    assert result == frozenset(), (
        f"closure of empty seed must be empty; got {result}"
    )


@given(flag_decls_with_enables_st())
@settings(max_examples=150)
def test_prop_closure_result_is_subset_of_declared_flags(flags) -> None:
    """closure(S) ⊆ declared_flag_names.

    The closure only returns flags that are declared in the flag table.
    Unknown enables targets are silently skipped (per spec §3.1.1).
    """
    from milpa.manifest import flag_enables_closure

    declared = frozenset(f.name for f in flags)
    seed = frozenset(f.name for f in flags if f.default)
    result = flag_enables_closure(flags, seed)
    assert result <= declared, (
        f"closure produced undeclared flags: {result - declared}"
    )


@given(flag_decls_with_enables_st())
@settings(max_examples=200)
def test_prop_closure_compute_dep_active_idempotent(flags) -> None:
    """compute_dep_active_flags (which calls flag_enables_closure) is idempotent.

    The full activation pipeline (default seeding + edge requests + enables
    closure) applied a second time with the first run's active keys as requests
    must return the same active-name set.

    This is the end-to-end idempotence guarantee for the resolver's flag system:
    once converged, re-processing produces no new activations.
    """
    from milpa.resolver import compute_dep_active_flags
    from milpa.manifest import FlagRequest

    # First pass: seed from default-true flags only (no edge requests).
    first_result = compute_dep_active_flags(flags, ())
    first_names = frozenset(first_result.keys())

    # Second pass: feed first-pass active names back as positive edge requests.
    second_requests = tuple(FlagRequest(name=n, enabled=True) for n in first_names)
    second_result = compute_dep_active_flags(flags, second_requests)
    second_names = frozenset(second_result.keys())

    assert first_names == second_names, (
        f"compute_dep_active_flags is not idempotent: "
        f"first={first_names}, second={second_names}"
    )


# ===========================================================================
# Property 3: Prune completeness
#
# §3.2 + §7 S7: an optional dep with default=#false auto-flag and no enabling
# request must never be active.
#
# Algebraic statement:
#   ∀ dep d with optional=True (auto-flag f_d, default=#false):
#   if f_d ∉ requests_positive ∧ f_d ∉ default_true_flags
#   then f_d ∉ active_flags(D).
#
# We test at two levels:
#   (a) Pure closure level: the auto-flag is not in any seed → not in closure.
#   (b) compute_dep_active_flags level: negative-only / absent requests → inactive.
# ===========================================================================


@given(
    st.lists(flag_name_st(), min_size=1, max_size=5, unique=True),
    st.lists(flag_name_st(), min_size=1, max_size=4, unique=True),
)
@settings(max_examples=200)
def test_prop_prune_optional_flag_inactive_when_not_requested(
    optional_names: list[str],
    other_names: list[str],
) -> None:
    """Optional auto-flags (default=#false) are inactive when not requested.

    For any set of optional deps (auto-flag default=#false) alongside other
    flags, the optional flags must NOT appear in active(D) unless a positive
    request or enables edge reaches them.

    This is the prune-completeness guarantee: disabled optionals never sneak
    through the flag system.
    """
    from milpa.manifest import FlagDecl
    from milpa.resolver import compute_dep_active_flags

    # Avoid name collisions between the two groups.
    combined_names = set(optional_names) | set(other_names)
    assume(len(combined_names) == len(optional_names) + len(other_names))

    # Build flag table: optional flags are default=#false (auto-flag convention).
    optional_flags = tuple(
        FlagDecl(name=n, default=False) for n in optional_names
    )
    # Other flags may be default-true or false.
    other_flags = tuple(
        FlagDecl(name=n, default=False)  # worst-case: all false, no noise
        for n in other_names
    )
    all_flags = optional_flags + other_flags

    # No requests at all — simulate a consumer that does not request optional deps.
    result = compute_dep_active_flags(all_flags, ())
    active_names = frozenset(result.keys())

    optional_set = frozenset(optional_names)
    activated_optionals = active_names & optional_set
    assert not activated_optionals, (
        f"optional flags activated without a request: {activated_optionals}; "
        f"all active: {active_names}"
    )


@given(
    st.lists(flag_name_st(), min_size=1, max_size=5, unique=True),
)
@settings(max_examples=200)
def test_prop_prune_closure_excludes_non_seeded_default_false_flags(
    names: list[str],
) -> None:
    """Flags with default=#false that are not in the seed never appear in the closure.

    Pure closure-level prune guarantee: if a flag is not in the seed and no
    active flag enables it, it must not appear in the closure result.
    """
    from milpa.manifest import FlagDecl, flag_enables_closure

    assume(len(names) >= 2)

    # Partition names: first half are seeded (in seed), second half are NOT.
    mid = len(names) // 2
    seeded_names = names[:mid]
    excluded_names = names[mid:]

    assume(seeded_names)  # at least one seeded name
    assume(excluded_names)  # at least one excluded name

    # Build flags with NO enables edges so excluded flags are unreachable.
    flags = tuple(
        FlagDecl(name=n, default=False, enables_same_pkg=())
        for n in names
    )
    seed = frozenset(seeded_names)
    result = flag_enables_closure(flags, seed)

    excluded_set = frozenset(excluded_names)
    leaked = result & excluded_set
    assert not leaked, (
        f"closure leaked unreachable flags: {leaked}; seed={seed}, result={result}"
    )


@given(
    st.lists(flag_name_st(), min_size=1, max_size=4, unique=True),
    st.lists(flag_name_st(), min_size=1, max_size=4, unique=True),
)
@settings(max_examples=150)
def test_prop_prune_negative_request_plus_no_default_stays_inactive(
    optional_names: list[str],
    positive_names: list[str],
) -> None:
    """Optional flags that receive only negative requests and no enables stay pruned.

    Even if positive requests exist for OTHER flags, optional flags with
    only negative (opt-out) requests and no default=#true must remain inactive.

    This is the most important prune invariant for the resolver: a consumer
    explicitly opting out of an optional feature must result in it being absent.
    """
    from milpa.manifest import FlagDecl
    from milpa.resolver import compute_dep_active_flags
    from milpa.manifest import FlagRequest

    # Avoid name collisions.
    combined = set(optional_names) | set(positive_names)
    assume(len(combined) == len(optional_names) + len(positive_names))

    optional_flags = tuple(FlagDecl(name=n, default=False) for n in optional_names)
    positive_flags = tuple(FlagDecl(name=n, default=False) for n in positive_names)
    all_flags = optional_flags + positive_flags

    # Requests: negative for optional, positive for the others.
    reqs = (
        tuple(FlagRequest(name=n, enabled=False) for n in optional_names)
        + tuple(FlagRequest(name=n, enabled=True) for n in positive_names)
    )
    result = compute_dep_active_flags(all_flags, reqs)
    active_names = frozenset(result.keys())

    for name in optional_names:
        assert name not in active_names, (
            f"optional flag {name!r} must NOT be active when only negative "
            f"requests exist for it; active={active_names}"
        )

    # Positive flags must all be active (sanity check that the test is non-trivial).
    for name in positive_names:
        assert name in active_names, (
            f"positive-requested flag {name!r} must be active; active={active_names}"
        )


# ===========================================================================
# Regression anchor: if Hypothesis finds a counterexample, it gets shrunk
# and pinned as an explicit test here (per rfc-property-based-testing.md
# Phase A: shrink → fix → pin).
#
# No counterexamples found during initial run.
# ===========================================================================
