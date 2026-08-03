"""Example-based tests for ``milpa.binding.BindingResolver`` (S2,
rfc-origin-as-identity.md §4.3).

Standalone, in-memory unit tests only — S2 does NOT wire ``BindingResolver``
into ``resolve()``/``resolve_workspace()`` (that's S3a) and does NOT delete
``provenance_gate``/``TIER_*`` (that's S3b). Property tests (idempotence,
order-independence of DUPLICATE detection) live in
``test_binding_properties.py``.
"""

from __future__ import annotations

import pytest

from milpa.binding import BindingResolver, BindOutcome, Claim, reconcile_root_claims
from milpa.errors import RES_BINDING_CONFLICT, MilpaError
from milpa.source_id import GitSourceId, RegistrySourceId
from milpa.version import DepKey

# ---------------------------------------------------------------------------
# Fixtures — a few representative source-ids
# ---------------------------------------------------------------------------

_NIMZ3 = GitSourceId(url="https://github.com/coreyleavitt/nim-z3")
_ZEVV_Z3 = GitSourceId(url="https://github.com/zevv/nimz3")
_REG_CHRONOS = RegistrySourceId(registry="tianguis", namespace=None, name="chronos")
_REG_CHRONOS_FORK = RegistrySourceId(registry="tianguis", namespace="acme", name="chronos-fork")


# ---------------------------------------------------------------------------
# __init__ — root/override binding
# ---------------------------------------------------------------------------


class TestInitRootBinding:
    def test_root_claim_is_bound_at_construction(self) -> None:
        claim = Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")
        resolver = BindingResolver([claim])
        assert resolver.source_id_for(DepKey(name="foo")) == _NIMZ3

    def test_empty_root_claims_binds_nothing(self) -> None:
        resolver = BindingResolver([])
        assert resolver.source_id_for(DepKey(name="foo")) is None

    def test_source_id_for_unknown_key_returns_none(self) -> None:
        resolver = BindingResolver([Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")])
        assert resolver.source_id_for(DepKey(name="bar")) is None

    def test_non_root_claim_in_init_raises(self) -> None:
        claim = Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="root@1.0.0")
        with pytest.raises(ValueError):
            BindingResolver([claim])

    def test_matching_duplicate_root_claims_are_fine(self) -> None:
        """Two root claims that AGREE (e.g. an override reasserting the same
        target as a placeholder dep decl) are not a conflict."""
        c1 = Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")
        c2 = Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="override:foo")
        resolver = BindingResolver([c1, c2])
        assert resolver.source_id_for(DepKey(name="foo")) == _NIMZ3

    def test_disagreeing_root_claims_is_internal_invariant_violation(self) -> None:
        """Two root claims for one name with DIFFERENT sources is
        unreachable by construction (the caller must pre-empt the base dep
        decl with its override before building root_claims) — an
        AssertionError, never RES-BINDING-CONFLICT."""
        c1 = Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")
        c2 = Claim(name="foo", source_id=_ZEVV_Z3, is_root=True, claimant="override:foo")
        with pytest.raises(AssertionError):
            BindingResolver([c1, c2])


# ---------------------------------------------------------------------------
# submit() — arbitration
# ---------------------------------------------------------------------------


class TestSubmitArbitration:
    def test_root_claim_in_submit_raises(self) -> None:
        resolver = BindingResolver([])
        claim = Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")
        with pytest.raises(ValueError):
            resolver.submit(claim)

    def test_first_transitive_claim_is_new(self) -> None:
        resolver = BindingResolver([])
        claim = Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="parent@1.0.0")
        decision = resolver.submit(claim)
        assert decision.outcome is BindOutcome.NEW
        assert decision.accepted == _NIMZ3
        assert resolver.source_id_for(DepKey(name="foo")) == _NIMZ3

    def test_matching_transitive_claim_is_duplicate(self) -> None:
        resolver = BindingResolver([])
        resolver.submit(Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="a@1.0.0"))
        decision = resolver.submit(Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="b@2.0.0"))
        assert decision.outcome is BindOutcome.DUPLICATE
        assert decision.accepted == _NIMZ3

    def test_transitive_disagrees_with_root_loses_silently(self) -> None:
        root_claim = Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")
        resolver = BindingResolver([root_claim])
        decision = resolver.submit(
            Claim(name="foo", source_id=_ZEVV_Z3, is_root=False, claimant="a@1.0.0")
        )
        assert decision.outcome is BindOutcome.LOST_TO_ROOT
        assert decision.accepted == _NIMZ3
        # The binding is untouched — root still wins.
        assert resolver.source_id_for(DepKey(name="foo")) == _NIMZ3

    def test_two_disagreeing_transitives_with_no_root_conflict(self) -> None:
        resolver = BindingResolver([])
        resolver.submit(Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="a@1.0.0"))
        with pytest.raises(MilpaError) as exc:
            resolver.submit(Claim(name="foo", source_id=_ZEVV_Z3, is_root=False, claimant="b@1.0.0"))
        assert exc.value.slug == RES_BINDING_CONFLICT

    def test_conflict_message_names_both_sources_and_remedy(self) -> None:
        resolver = BindingResolver([])
        resolver.submit(Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="a@1.0.0"))
        with pytest.raises(MilpaError) as exc:
            resolver.submit(Claim(name="foo", source_id=_ZEVV_Z3, is_root=False, claimant="b@1.0.0"))
        message = exc.value.message
        assert "nim-z3" in message
        assert "zevv/nimz3" in message
        assert "overrides {}" in message

    def test_conflict_does_not_mutate_existing_binding(self) -> None:
        resolver = BindingResolver([])
        resolver.submit(Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="a@1.0.0"))
        with pytest.raises(MilpaError):
            resolver.submit(Claim(name="foo", source_id=_ZEVV_Z3, is_root=False, claimant="b@1.0.0"))
        assert resolver.source_id_for(DepKey(name="foo")) == _NIMZ3


# ---------------------------------------------------------------------------
# Namespace non-crossing — first-class RED test (RFC §4.3 B1/G1, the literal
# #193 root cause: a bare-name store lets ns1::foo and ns2::foo cross-bind).
# ---------------------------------------------------------------------------


class TestNamespaceNonCrossing:
    def test_ns1_foo_and_ns2_foo_never_cross_bind_via_submit(self) -> None:
        resolver = BindingResolver([])
        d1 = resolver.submit(Claim(name="ns1::foo", source_id=_NIMZ3, is_root=False, claimant="a@1.0.0"))
        d2 = resolver.submit(Claim(name="ns2::foo", source_id=_ZEVV_Z3, is_root=False, claimant="b@1.0.0"))
        # Both are NEW — they must NOT be treated as the same binding.
        assert d1.outcome is BindOutcome.NEW
        assert d2.outcome is BindOutcome.NEW
        assert resolver.source_id_for(DepKey(name="foo", namespace="ns1")) == _NIMZ3
        assert resolver.source_id_for(DepKey(name="foo", namespace="ns2")) == _ZEVV_Z3
        # And the bare (unqualified) "foo" key was never touched.
        assert resolver.source_id_for(DepKey(name="foo")) is None

    def test_ns1_foo_and_ns2_foo_never_cross_bind_via_root(self) -> None:
        c1 = Claim(name="ns1::foo", source_id=_NIMZ3, is_root=True, claimant="root")
        c2 = Claim(name="ns2::foo", source_id=_ZEVV_Z3, is_root=True, claimant="root")
        # Different DepKeys — this must NOT raise, even though both claims
        # are is_root=True and would collide if keyed by bare name.
        resolver = BindingResolver([c1, c2])
        assert resolver.source_id_for(DepKey(name="foo", namespace="ns1")) == _NIMZ3
        assert resolver.source_id_for(DepKey(name="foo", namespace="ns2")) == _ZEVV_Z3

    def test_ns_qualified_transitive_vs_unqualified_root_do_not_interact(self) -> None:
        root_claim = Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")
        resolver = BindingResolver([root_claim])
        # A namespaced transitive claim for "ns1::foo" is a DIFFERENT DepKey
        # from the unqualified root's "foo" — it must be NEW, not LOST_TO_ROOT.
        decision = resolver.submit(
            Claim(name="ns1::foo", source_id=_ZEVV_Z3, is_root=False, claimant="a@1.0.0")
        )
        assert decision.outcome is BindOutcome.NEW
        assert resolver.source_id_for(DepKey(name="foo")) == _NIMZ3
        assert resolver.source_id_for(DepKey(name="foo", namespace="ns1")) == _ZEVV_Z3


# ---------------------------------------------------------------------------
# Override to a different coordinate (RFC §5 row) — grouping key stays the
# OVERRIDDEN name, not the accepted SourceId's own namespace/name.
# ---------------------------------------------------------------------------


class TestOverrideToDifferentCoordinate:
    def test_grouping_key_is_overridden_name_not_target_coordinate(self) -> None:
        # override "chronos" -> a DIFFERENTLY-NAMED/namespaced registry coordinate.
        override_claim = Claim(
            name="chronos", source_id=_REG_CHRONOS_FORK, is_root=True, claimant="override:chronos"
        )
        resolver = BindingResolver([override_claim])
        # Bound under the OVERRIDDEN key...
        assert resolver.source_id_for(DepKey(name="chronos")) == _REG_CHRONOS_FORK
        # ...never under the target coordinate's own (namespace, name).
        assert resolver.source_id_for(DepKey(name="chronos-fork", namespace="acme")) is None

    def test_transitive_matching_override_target_is_duplicate(self) -> None:
        override_claim = Claim(
            name="chronos", source_id=_REG_CHRONOS_FORK, is_root=True, claimant="override:chronos"
        )
        resolver = BindingResolver([override_claim])
        decision = resolver.submit(
            Claim(name="chronos", source_id=_REG_CHRONOS_FORK, is_root=False, claimant="a@1.0.0")
        )
        assert decision.outcome is BindOutcome.DUPLICATE

    def test_transitive_disagreeing_with_override_loses_to_root(self) -> None:
        override_claim = Claim(
            name="chronos", source_id=_REG_CHRONOS_FORK, is_root=True, claimant="override:chronos"
        )
        resolver = BindingResolver([override_claim])
        decision = resolver.submit(
            Claim(name="chronos", source_id=_REG_CHRONOS, is_root=False, claimant="a@1.0.0")
        )
        assert decision.outcome is BindOutcome.LOST_TO_ROOT
        assert decision.accepted == _REG_CHRONOS_FORK


# ---------------------------------------------------------------------------
# S5-rekey (RFC §4.4 deliverable #1) — canonical_for / depkey_for_canonical /
# canonical_key_for_requirement.  These are landed, tested building blocks
# for the solver re-key; NOT YET wired into resolve()/resolve_workspace()
# (Term.package / provider dicts still name-keyed) — see
# docs/rfc-origin-as-identity.md §4.4 and the S5-rekey handoff.
# ---------------------------------------------------------------------------


class TestCanonicalFor:
    def test_bound_key_returns_canonical_string(self) -> None:
        resolver = BindingResolver([Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")])
        from milpa.source_id import canonical

        assert resolver.canonical_for(DepKey(name="foo")) == canonical(_NIMZ3)

    def test_unbound_key_raises_milpa_internal(self) -> None:
        resolver = BindingResolver([])
        with pytest.raises(MilpaError) as exc_info:
            resolver.canonical_for(DepKey(name="never-bound"))
        assert exc_info.value.slug == "MILPA-INTERNAL"


class TestDepkeyForCanonical:
    def test_returns_none_when_nothing_bound(self) -> None:
        resolver = BindingResolver([])
        assert resolver.depkey_for_canonical("git+https://example.com/x") is None

    def test_returns_the_bound_depkey(self) -> None:
        resolver = BindingResolver([Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root")])
        from milpa.source_id import canonical

        assert resolver.depkey_for_canonical(canonical(_NIMZ3)) == DepKey(name="foo")

    def test_two_labels_one_source_collapse_to_the_first_bound_depkey(self) -> None:
        """The headline S5-rekey regression: two DIFFERENT root claims
        ("foo", "bar") that both target the SAME source-id are, from the
        reverse map's perspective, ONE canonical key — resolved to whichever
        DepKey was bound FIRST (BFS-first, mirroring Phase B's alias-
        selection convention), never the second."""
        resolver = BindingResolver(
            [
                Claim(name="foo", source_id=_NIMZ3, is_root=True, claimant="root"),
                Claim(name="bar", source_id=_NIMZ3, is_root=True, claimant="root"),
            ]
        )
        from milpa.source_id import canonical

        assert resolver.depkey_for_canonical(canonical(_NIMZ3)) == DepKey(name="foo")

    def test_transitive_claim_extends_the_index(self) -> None:
        resolver = BindingResolver([])
        from milpa.source_id import canonical

        resolver.submit(Claim(name="foo", source_id=_NIMZ3, is_root=False, claimant="a@1.0.0"))
        assert resolver.depkey_for_canonical(canonical(_NIMZ3)) == DepKey(name="foo")


class TestCanonicalKeyForRequirement:
    def test_url_requirement_matches_git_source_id_canonical(self) -> None:
        from milpa.registry import Index
        from milpa.binding import canonical_key_for_requirement
        from milpa.source_id import canonical

        key = canonical_key_for_requirement(
            name="foo",
            url="https://github.com/coreyleavitt/nim-z3",
            overrides_by_name={},
            index=Index(packages=[]),
        )
        assert key == canonical(_NIMZ3)

    def test_named_requirement_matches_registry_source_id_canonical(self) -> None:
        from milpa.registry import Index
        from milpa.binding import canonical_key_for_requirement
        from milpa.source_id import canonical

        key = canonical_key_for_requirement(
            name="chronos",
            namespace=None,
            overrides_by_name={},
            index=Index(packages=[]),
        )
        assert key == canonical(_REG_CHRONOS)

    def test_override_wins_over_the_requirement_s_own_declared_source(self) -> None:
        from milpa.manifest import GitTarget, Override
        from milpa.registry import Index
        from milpa.binding import canonical_key_for_requirement
        from milpa.source_id import canonical

        ov = Override(name="chronos", target=GitTarget(git=_ZEVV_Z3.url, ref="main"), version=None)
        key = canonical_key_for_requirement(
            name="chronos",
            namespace=None,
            overrides_by_name={"chronos": ov},
            index=Index(packages=[]),
        )
        assert key == canonical(_ZEVV_Z3)

    def test_two_labels_same_url_produce_the_same_canonical_key(self) -> None:
        """The pre-fetch collapse precondition: independent of WHICH label a
        requirement is declared under, the SAME (url, no-override) always
        yields the SAME canonical key — this is what lets `_candidates`/
        `Term.package` naturally collapse two labels for one origin."""
        from milpa.registry import Index
        from milpa.binding import canonical_key_for_requirement

        idx = Index(packages=[])
        key_foo = canonical_key_for_requirement(
            name="foo", url=_NIMZ3.url, overrides_by_name={}, index=idx
        )
        key_bar = canonical_key_for_requirement(
            name="bar", url=_NIMZ3.url, overrides_by_name={}, index=idx
        )
        assert key_foo == key_bar


class TestRootClaimDuplicateSourceConflict:
    """P1 (code-review): two root declarations of one package with disagreeing
    sources must raise RES-BINDING-CONFLICT, not silently keep the first.

    Reachable because `deps {}` and `dev-deps {}` carry independent per-block
    duplicate-name guards, so the same name in both blocks parses cleanly and
    only collides at root-claim reconciliation.
    """

    def test_same_name_different_local_paths_conflict(self) -> None:
        from milpa.manifest import LocalDep
        from milpa.registry import Index

        deps = [LocalDep(name="foo", path="./a"), LocalDep(name="foo", path="./b")]
        with pytest.raises(MilpaError) as exc:
            reconcile_root_claims(deps, [], index=Index(packages=[]))
        assert exc.value.slug == RES_BINDING_CONFLICT

    def test_same_name_same_source_is_idempotent(self) -> None:
        from milpa.manifest import LocalDep
        from milpa.registry import Index

        deps = [LocalDep(name="foo", path="./a"), LocalDep(name="foo", path="./a")]
        claims = reconcile_root_claims(deps, [], index=Index(packages=[]))
        assert len([c for c in claims if c.name.endswith("foo")]) == 1

    def test_distinct_namespaces_same_bare_name_do_not_conflict(self) -> None:
        from milpa.manifest import NamedDep
        from milpa.registry import Index, Package
        from milpa.source_id import GitSourceId

        idx = Index(
            packages=[
                Package(name="foo", namespace="ns1", versions=()),
                Package(name="foo", namespace="ns2", versions=()),
            ]
        )
        deps = [
            NamedDep(name="foo", constraint=None, namespace="ns1"),
            NamedDep(name="foo", constraint=None, namespace="ns2"),
        ]
        claims = reconcile_root_claims(deps, [], index=idx)
        # Two DIFFERENT packages (distinct DepKeys) — both claims survive.
        assert len(claims) == 2


class TestIsRootAuthority:
    """S1 (code-review): the registry-shadow tripwire gate must key on the
    EXACT DepKey, never a bare name — a root `foo namespace="ns1"` grants NO
    authority over a bare `foo` (else an unrelated namespaced root dep silently
    disables the dependency-confusion check for a different coordinate)."""

    def _reg(self, ns: str) -> RegistrySourceId:
        return RegistrySourceId(registry="tianguis", namespace=ns, name="foo")

    def test_bare_root_grants_authority_over_bare_key(self) -> None:
        br = BindingResolver(
            [Claim(name="foo", source_id=self._reg("ns1"), is_root=True, claimant="root")]
        )
        # claim.name "foo" -> DepKey(foo, None) (bare). Root owns the bare key.
        assert br.is_root_authority(DepKey(name="foo", namespace=None)) is True

    def test_namespaced_root_does_not_grant_authority_over_bare_key(self) -> None:
        br = BindingResolver(
            [Claim(name=DepKey(name="foo", namespace="ns1").solver_var(),
                   source_id=self._reg("ns1"), is_root=True, claimant="root")]
        )
        # Root declared foo@ns1; a bare `foo` a transitive sources elsewhere is
        # NOT covered — the shadow check must still fire.
        assert br.is_root_authority(DepKey(name="foo", namespace=None)) is False
        assert br.is_root_authority(DepKey(name="foo", namespace="ns1")) is True

    def test_unbound_key_is_not_root_authority(self) -> None:
        br = BindingResolver([])
        assert br.is_root_authority(DepKey(name="foo", namespace=None)) is False
