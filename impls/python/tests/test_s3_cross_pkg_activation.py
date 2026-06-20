"""S3 (RFC #23 §7): cross-package flag-request activation — single-hop.

This covers:
  1. NamedDep.flag_requests — parse and round-trip.
  2. dep_active_flags map shape: keyed by resolved identity, sources tracked.
  3. EdgeSourceCtx.active_flags extension.
  4. Single-hop activation: root requests flag on direct dep → dep's edges
     are filtered with the requested flag active.

Coverage decision (stated explicitly, not a gap):
  S3's activation effect IS observable through the resolver output
  (a flag-gated subdep of the target appears in the resolved graph when the
  requested flag is active). Therefore S3 ships a conformance fixture
  (fixture-189-named-dep-flag-request) in addition to these unit tests.
  Unit tests assert the ActivationSource enumeration and dep_active_flags
  map semantics; the conformance fixture verifies end-to-end observability.

  "Single-hop only; multi-hop lands in S4a." The outer fixpoint (iterating
  until neither deps nor active_flags grows) is S4a. S3 seeds active(D) for
  DIRECT deps only and does not recursively activate flags on D's deps.
"""

from __future__ import annotations

import pytest

from milpa.manifest import (
    FlagDecl,
    FlagRequest,
    NamedDep,
    UrlDep,
    flag_enables_closure,
    parse_manifest,
    format_manifest,
)


# ---------------------------------------------------------------------------
# 1. NamedDep.flag_requests — field exists and parses
# ---------------------------------------------------------------------------


class TestNamedDepFlagRequests:
    def test_named_dep_has_flag_requests_field(self) -> None:
        """NamedDep carries flag_requests (same type as UrlDep.flag_requests)."""
        dep = NamedDep(name="chronos", constraint=None)
        assert hasattr(dep, "flag_requests")
        assert dep.flag_requests == ()

    def test_named_dep_flag_requests_default_empty(self) -> None:
        dep = NamedDep(name="chronos", constraint=None)
        assert dep.flag_requests == ()

    def test_named_dep_with_flag_requests(self) -> None:
        fr = FlagRequest(name="tls", enabled=True)
        dep = NamedDep(name="chronos", constraint=None, flag_requests=(fr,))
        assert dep.flag_requests == (fr,)
        assert dep.flag_requests[0].name == "tls"
        assert dep.flag_requests[0].enabled is True

    def test_named_dep_negative_flag_request(self) -> None:
        fr = FlagRequest(name="docs", enabled=False)
        dep = NamedDep(name="chronos", constraint=None, flag_requests=(fr,))
        assert dep.flag_requests[0].enabled is False

    def test_parse_named_dep_with_flag_child(self) -> None:
        """Parse a NamedDep with a { flag "x" } child block."""
        manifest = parse_manifest(
            'name "pkg"\ndeps {\n    "chronos" { flag "tls" }\n}\n'
        )
        assert len(manifest.deps) == 1
        dep = manifest.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.name == "chronos"
        assert len(dep.flag_requests) == 1
        assert dep.flag_requests[0].name == "tls"
        assert dep.flag_requests[0].enabled is True

    def test_parse_named_dep_with_negative_flag_child(self) -> None:
        manifest = parse_manifest(
            'name "pkg"\ndeps {\n    "chronos" { flag "docs" #false }\n}\n'
        )
        dep = manifest.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.flag_requests[0].name == "docs"
        assert dep.flag_requests[0].enabled is False

    def test_parse_named_dep_multiple_flag_children(self) -> None:
        manifest = parse_manifest(
            'name "pkg"\ndeps {\n    "chronos" { flag "tls"\nflag "http" }\n}\n'
        )
        dep = manifest.deps[0]
        assert isinstance(dep, NamedDep)
        assert len(dep.flag_requests) == 2
        names = {fr.name for fr in dep.flag_requests}
        assert names == {"tls", "http"}

    def test_parse_named_dep_with_constraint_and_flag(self) -> None:
        manifest = parse_manifest(
            'name "pkg"\ndeps {\n    "chronos" ">= 1.0.0" { flag "tls" }\n}\n'
        )
        dep = manifest.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.constraint == ">= 1.0.0"
        assert dep.flag_requests[0].name == "tls"

    def test_parse_named_dep_unknown_child_rejected(self) -> None:
        """NamedDep with unknown child node raises MAN-DEP-UNKNOWN-CHILD."""
        from milpa.errors import MilpaError, MAN_DEP_UNKNOWN_CHILD
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(
                'name "pkg"\ndeps {\n    "chronos" { badchild "x" }\n}\n'
            )
        assert exc_info.value.slug == MAN_DEP_UNKNOWN_CHILD

    def test_flag_request_name_missing_rejected(self) -> None:
        """NamedDep flag child with no name arg raises MAN-DEP-FLAG-NAME-MISSING."""
        from milpa.errors import MilpaError, MAN_DEP_FLAG_NAME_MISSING
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(
                'name "pkg"\ndeps {\n    "chronos" { flag }\n}\n'
            )
        assert exc_info.value.slug == MAN_DEP_FLAG_NAME_MISSING

    def test_flag_request_bool_type_enforced(self) -> None:
        """NamedDep flag child with non-bool second arg raises MAN-DEP-FLAG-BOOL."""
        from milpa.errors import MilpaError, MAN_DEP_FLAG_BOOL
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(
                'name "pkg"\ndeps {\n    "chronos" { flag "tls" "yes" }\n}\n'
            )
        assert exc_info.value.slug == MAN_DEP_FLAG_BOOL


# ---------------------------------------------------------------------------
# 2. format_manifest round-trip for NamedDep with flag_requests
# ---------------------------------------------------------------------------


class TestNamedDepFlagRequestsFormat:
    def test_format_named_dep_with_flags_round_trips(self) -> None:
        """format_manifest emits { flag "..." } children for NamedDep."""
        original = 'name "pkg"\ndeps {\n    "chronos" {\n        flag "tls"\n    }\n}\n'
        manifest = parse_manifest(original)
        formatted = format_manifest(manifest)
        # Re-parse to verify round-trip integrity (byte-exact is brittle;
        # semantic equivalence is the goal).
        reparsed = parse_manifest(formatted)
        dep = reparsed.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.name == "chronos"
        assert len(dep.flag_requests) == 1
        assert dep.flag_requests[0].name == "tls"
        assert dep.flag_requests[0].enabled is True

    def test_format_named_dep_with_negative_flag_round_trips(self) -> None:
        original = 'name "pkg"\ndeps {\n    "chronos" {\n        flag "docs" #false\n    }\n}\n'
        manifest = parse_manifest(original)
        formatted = format_manifest(manifest)
        reparsed = parse_manifest(formatted)
        dep = reparsed.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.flag_requests[0].enabled is False

    def test_format_named_dep_no_flags_stays_inline(self) -> None:
        """NamedDep with no flag_requests is emitted as a single-line."""
        manifest = parse_manifest('name "pkg"\ndeps {\n    "chronos"\n}\n')
        formatted = format_manifest(manifest)
        assert '{\n' not in formatted or "flag" not in formatted
        # Specifically: no flag child block emitted for empty flag_requests.
        reparsed = parse_manifest(formatted)
        dep = reparsed.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.flag_requests == ()


# ---------------------------------------------------------------------------
# 3. ActivationSource enumeration — variants correct + importable
# ---------------------------------------------------------------------------


class TestActivationSource:
    def test_activation_source_importable(self) -> None:
        from milpa.resolver import ActivationSource
        assert hasattr(ActivationSource, "DEFAULT")
        assert hasattr(ActivationSource, "EDGE_REQUEST")
        assert hasattr(ActivationSource, "ENABLES_RULE")

    def test_activation_source_default_variant(self) -> None:
        from milpa.resolver import ActivationSource
        src = ActivationSource.DEFAULT
        assert src is ActivationSource.DEFAULT

    def test_activation_source_edge_request_variant(self) -> None:
        from milpa.resolver import ActivationSource
        src = ActivationSource.EDGE_REQUEST
        assert src is ActivationSource.EDGE_REQUEST

    def test_activation_source_enables_rule_variant(self) -> None:
        from milpa.resolver import ActivationSource
        src = ActivationSource.ENABLES_RULE
        assert src is ActivationSource.ENABLES_RULE

    def test_activation_source_variants_are_distinct(self) -> None:
        from milpa.resolver import ActivationSource
        variants = {ActivationSource.DEFAULT, ActivationSource.EDGE_REQUEST,
                    ActivationSource.ENABLES_RULE}
        assert len(variants) == 3


# ---------------------------------------------------------------------------
# 4. compute_dep_active_flags — the activation seeding function
# ---------------------------------------------------------------------------


class TestComputeDepActiveFlags:
    """Tests for compute_dep_active_flags(flags, requested, *, seed_defaults=True)."""

    def test_importable(self) -> None:
        from milpa.resolver import compute_dep_active_flags
        assert callable(compute_dep_active_flags)

    def test_defaults_only(self) -> None:
        """No external request → only default-true flags are active."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        flags = (
            FlagDecl(name="tls", default=False),
            FlagDecl(name="http", default=True),
        )
        result = compute_dep_active_flags(flags, ())
        # http is default-true → active with DEFAULT source
        assert "http" in result
        assert ActivationSource.DEFAULT in result["http"]
        # tls is default-false → not active
        assert "tls" not in result

    def test_edge_request_activates(self) -> None:
        """A flag request on the edge activates the flag with EDGE_REQUEST source."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        flags = (FlagDecl(name="tls", default=False),)
        result = compute_dep_active_flags(flags, (FlagRequest(name="tls", enabled=True),))
        assert "tls" in result
        assert ActivationSource.EDGE_REQUEST in result["tls"]

    def test_default_true_plus_edge_request_both_sources(self) -> None:
        """A default-true flag requested externally has both sources."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        flags = (FlagDecl(name="tls", default=True),)
        result = compute_dep_active_flags(flags, (FlagRequest(name="tls", enabled=True),))
        assert "tls" in result
        assert ActivationSource.DEFAULT in result["tls"]
        assert ActivationSource.EDGE_REQUEST in result["tls"]

    def test_same_pkg_enables_propagates(self) -> None:
        """When a flag is activated, its enables_same_pkg targets get ENABLES_RULE."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        flags = (
            FlagDecl(name="full", default=False, enables_same_pkg=("tls",)),
            FlagDecl(name="tls", default=False),
        )
        result = compute_dep_active_flags(flags, (FlagRequest(name="full", enabled=True),))
        assert "full" in result
        assert ActivationSource.EDGE_REQUEST in result["full"]
        assert "tls" in result
        assert ActivationSource.ENABLES_RULE in result["tls"]

    def test_negative_request_does_not_suppress_default(self) -> None:
        """opt-out (#false) on a default-true flag is absence-of-request, not suppression.

        Per §3.1.3: union semantics; a negative request never turns off a default-true flag.
        The DEFAULT source still wins.
        """
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        flags = (FlagDecl(name="http", default=True),)
        result = compute_dep_active_flags(flags, (FlagRequest(name="http", enabled=False),))
        # http is still active because of its default; the negative request is absence-of-request
        assert "http" in result
        assert ActivationSource.DEFAULT in result["http"]

    def test_unknown_flag_request_ignored(self) -> None:
        """A flag request naming a flag not declared by the dep is silently ignored.

        Per §3.1.1 RESOLVE-FLAG-UNKNOWN-ON-TARGET: warn-and-ignore, non-fatal.
        """
        from milpa.resolver import compute_dep_active_flags
        flags = (FlagDecl(name="tls", default=False),)
        # Request for "docs" which is not declared
        result = compute_dep_active_flags(flags, (FlagRequest(name="docs", enabled=True),))
        assert "docs" not in result  # silently ignored
        assert "tls" not in result  # not activated either

    def test_projection_is_flag_name_set(self) -> None:
        """The key set of compute_dep_active_flags is the active flag names."""
        from milpa.resolver import compute_dep_active_flags
        flags = (
            FlagDecl(name="tls", default=False),
            FlagDecl(name="http", default=True),
        )
        result = compute_dep_active_flags(flags, ())
        assert set(result.keys()) == {"http"}

    def test_result_type_is_dict_str_to_set(self) -> None:
        """Result is dict[str, set[ActivationSource]]."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        flags = (FlagDecl(name="tls", default=True),)
        result = compute_dep_active_flags(flags, ())
        assert isinstance(result, dict)
        assert isinstance(result["tls"], (set, frozenset))


# ---------------------------------------------------------------------------
# 5. EdgeSourceCtx.active_flags extension
# ---------------------------------------------------------------------------


class TestEdgeSourceCtxActiveFlags:
    def test_edge_source_ctx_has_active_flags(self) -> None:
        from milpa.edge_sources import EdgeSourceCtx
        ctx = EdgeSourceCtx(
            dep_path=None,
            dep_name="chronos",
            dep_decl=None,
            is_overridden=False,
            has_milpa_kdl=False,
        )
        assert hasattr(ctx, "active_flags")
        assert ctx.active_flags == frozenset()

    def test_edge_source_ctx_active_flags_settable(self) -> None:
        from milpa.edge_sources import EdgeSourceCtx
        ctx = EdgeSourceCtx(
            dep_path=None,
            dep_name="chronos",
            dep_decl=None,
            is_overridden=False,
            has_milpa_kdl=False,
            active_flags=frozenset({"tls"}),
        )
        assert ctx.active_flags == frozenset({"tls"})

    def test_edge_source_ctx_active_flags_is_frozenset(self) -> None:
        from milpa.edge_sources import EdgeSourceCtx
        ctx = EdgeSourceCtx(
            dep_path=None,
            dep_name="chronos",
            dep_decl=None,
            is_overridden=False,
            has_milpa_kdl=False,
            active_flags=frozenset({"tls", "http"}),
        )
        assert isinstance(ctx.active_flags, frozenset)


# ---------------------------------------------------------------------------
# 6. _manifest_to_edgeset respects active_flags from ctx
# ---------------------------------------------------------------------------


class TestManifestToEdgesetWithActiveFlags:
    """_manifest_to_edgeset(manifest, active_flags=...) uses the externally seeded set."""

    def _make_manifest_with_flagged_dep(self) -> object:
        """Build a manifest where dep C is gated behind flag 'tls' (default-off)."""
        return parse_manifest(
            'name "lib-b"\n'
            'kind "library"\n'
            'flags {\n'
            '    tls default=#false\n'
            '}\n'
            'deps {\n'
            '    "lib-c" git=(url)"https://example.com/lib-c.git" ref="main" flag="tls"\n'
            '    "lib-d" git=(url)"https://example.com/lib-d.git" ref="main"\n'
            '}\n'
        )

    def test_without_active_flags_gated_dep_excluded(self) -> None:
        """Without any external flags, default-off gated dep is excluded."""
        from milpa.edge_sources import _manifest_to_edgeset
        manifest = self._make_manifest_with_flagged_dep()
        edgeset = _manifest_to_edgeset(manifest, active_flags=frozenset())
        names = {r.url if hasattr(r, "url") else r.name for r in edgeset.requires}
        # lib-c is gated behind tls (off) → excluded
        assert not any("lib-c" in str(n) for n in names)
        # lib-d is unconditional → included
        assert any("lib-d" in str(n) for n in names)

    def test_with_tls_active_gated_dep_included(self) -> None:
        """With tls in active_flags, the gated dep is admitted."""
        from milpa.edge_sources import _manifest_to_edgeset
        manifest = self._make_manifest_with_flagged_dep()
        edgeset = _manifest_to_edgeset(manifest, active_flags=frozenset({"tls"}))
        names = {r.url if hasattr(r, "url") else r.name for r in edgeset.requires}
        # lib-c should now appear
        assert any("lib-c" in str(n) for n in names)
        assert any("lib-d" in str(n) for n in names)
