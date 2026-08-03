"""Property-based tests for ``milpa.binding.BindingResolver`` (S2,
rfc-origin-as-identity.md §4.3).

Two laws with a genuine algebraic character:

  (a) **Idempotence** — resubmitting a claim that matches the current binding
      always yields ``DUPLICATE``, no matter how many times it is resubmitted.
  (b) **Order-independence of DUPLICATE detection** — whichever of two
      matching transitive claims arrives first becomes ``NEW``; every
      subsequent matching claim (regardless of how many, or in what order
      relative to OTHER distinct names interleaved) is ``DUPLICATE``.

Generators draw from URL-shaped alphabets (matching
``test_source_id_properties.py``'s convention) so source-ids are realistic,
not bare identifiers.
"""

from __future__ import annotations

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from milpa.binding import BindingResolver, BindOutcome, Claim
from milpa.source_id import GitSourceId

_URL_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:"
_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"


@st.composite
def git_source_id_st(draw: st.DrawFn) -> GitSourceId:
    url = draw(st.text(alphabet=_URL_CHARS, min_size=1, max_size=30))
    return GitSourceId(url=f"https://example.com/{url}")


@st.composite
def dep_name_st(draw: st.DrawFn) -> str:
    return draw(st.text(alphabet=_NAME_CHARS, min_size=1, max_size=12))


class TestIdempotence:
    @given(dep_name_st(), git_source_id_st(), st.integers(min_value=1, max_value=6))
    @settings(max_examples=200)
    def test_resubmitting_a_matching_claim_is_always_duplicate(
        self, name: str, sid: GitSourceId, n_extra: int
    ) -> None:
        resolver = BindingResolver([])
        first = resolver.submit(Claim(name=name, source_id=sid, is_root=False, claimant="a@1.0.0"))
        assert first.outcome is BindOutcome.NEW

        for _ in range(n_extra):
            decision = resolver.submit(
                Claim(name=name, source_id=sid, is_root=False, claimant="b@1.0.0")
            )
            assert decision.outcome is BindOutcome.DUPLICATE
            assert decision.accepted == sid

    @given(dep_name_st(), git_source_id_st())
    @settings(max_examples=100)
    def test_matching_root_claim_then_repeated_submit_is_always_duplicate(
        self, name: str, sid: GitSourceId
    ) -> None:
        root_claim = Claim(name=name, source_id=sid, is_root=True, claimant="root")
        resolver = BindingResolver([root_claim])
        for _ in range(3):
            decision = resolver.submit(
                Claim(name=name, source_id=sid, is_root=False, claimant="a@1.0.0")
            )
            assert decision.outcome is BindOutcome.DUPLICATE
            assert decision.accepted == sid


class TestOrderIndependenceOfDuplicateDetection:
    @given(dep_name_st(), git_source_id_st(), git_source_id_st())
    @settings(max_examples=200)
    def test_whichever_matching_claim_arrives_first_is_new_rest_are_duplicate(
        self, name: str, sid_a: GitSourceId, sid_b: GitSourceId
    ) -> None:
        """Two independently-generated source-ids might coincide (equal
        dataclasses) — the law holds either way: exactly the FIRST submitted
        claim for a key is NEW; every subsequent claim that matches whatever
        got bound is DUPLICATE, regardless of which of sid_a/sid_b was first."""
        resolver = BindingResolver([])
        first_decision = resolver.submit(
            Claim(name=name, source_id=sid_a, is_root=False, claimant="a@1.0.0")
        )
        assert first_decision.outcome is BindOutcome.NEW
        assert first_decision.accepted == sid_a

        second_decision = resolver.submit(
            Claim(name=name, source_id=sid_a, is_root=False, claimant="b@1.0.0")
        )
        assert second_decision.outcome is BindOutcome.DUPLICATE
        assert second_decision.accepted == sid_a

    @given(dep_name_st(), dep_name_st(), git_source_id_st(), git_source_id_st())
    @settings(max_examples=200)
    def test_interleaving_two_distinct_names_does_not_disturb_duplicate_detection(
        self, name_x: str, name_y: str, sid_x: GitSourceId, sid_y: GitSourceId
    ) -> None:
        """Submitting claims for two DIFFERENT DepKeys, interleaved, does not
        perturb each key's own idempotent DUPLICATE detection — the keys
        never interact (this is the DepKey-scoping guarantee generalized
        beyond the specific namespace RED test)."""
        assume(name_x != name_y)
        resolver = BindingResolver([])

        d1 = resolver.submit(Claim(name=name_x, source_id=sid_x, is_root=False, claimant="a@1.0.0"))
        d2 = resolver.submit(Claim(name=name_y, source_id=sid_y, is_root=False, claimant="a@1.0.0"))
        assert d1.outcome is BindOutcome.NEW
        assert d2.outcome is BindOutcome.NEW

        d3 = resolver.submit(Claim(name=name_x, source_id=sid_x, is_root=False, claimant="b@1.0.0"))
        d4 = resolver.submit(Claim(name=name_y, source_id=sid_y, is_root=False, claimant="b@1.0.0"))
        assert d3.outcome is BindOutcome.DUPLICATE
        assert d3.accepted == sid_x
        assert d4.outcome is BindOutcome.DUPLICATE
        assert d4.accepted == sid_y
