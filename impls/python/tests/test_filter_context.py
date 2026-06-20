"""S1 (RFC: workspace-completion §3.A): FilterContext + filter_manifest.

TDD vertical slices for the shared filter helper that unifies single-package
and workspace filter dispatch.

Coverage:
  C1 — FilterContext.build passthrough arm (profile=None, no flags)
  C2 — FilterContext.build flag-only arm (profile=None, cli_seed nonempty)
  C3 — FilterContext.build profile arm (profile present, no cli_seed)
  C4 — FilterContext.build profile+flags arm (profile present, cli_seed)
  C5 — filter_manifest passthrough arm: no profile, empty active_flags
  C6 — filter_manifest flag-only arm: no profile, active flags prune flag-gated deps
  C7 — filter_manifest profile arm: profile present, platform-gated dep pruned
  C8 — filter_manifest no double-eval: flag-only arm retains non-flag-predicate deps
  C9 — FilterContext.build uses *passed manifest's* flags, not root (Design-F1 footgun)
  C10 — filter_manifest profile arm skips flag predicates (Depth-F7: no double-eval)
  C11 — filter_manifest dev_deps filtered the same as deps
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manifest(
    *,
    name: str = "mypkg",
    flag_names: list[tuple[str, bool]] | None = None,
    url_deps: list[str] | None = None,
    url_deps_with_flag_pred: list[tuple[str, str]] | None = None,
    url_deps_with_platform_pred: list[tuple[str, str]] | None = None,
    dev_url_deps_with_flag_pred: list[tuple[str, str]] | None = None,
):
    """Build a minimal manifest with optional flags, deps, and predicates.

    flag_names: list of (name, default) tuples.
    url_deps: list of unconditional dep names.
    url_deps_with_flag_pred: list of (dep_name, flag_name) — dep gated on flag.
    url_deps_with_platform_pred: list of (dep_name, platform_value) — dep gated on platform.
    dev_url_deps_with_flag_pred: same as url_deps_with_flag_pred but for dev_deps.
    """
    from milpa.manifest import parse_manifest

    lines: list[str] = [f'name "{name}"\nkind "library"']

    if flag_names:
        flag_lines = "\n".join(
            f'    {fn} default=#{str(default).lower()}'
            for fn, default in flag_names
        )
        lines.append(f"flags {{\n{flag_lines}\n}}")

    dep_lines: list[str] = []
    for dname in (url_deps or []):
        dep_lines.append(
            f'    {dname} git=(url)"https://example.com/{dname}.git" ref="main"'
        )
    for dname, fname in (url_deps_with_flag_pred or []):
        dep_lines.append(
            f'    when flag="{fname}" {{\n'
            f'        {dname} git=(url)"https://example.com/{dname}.git" ref="main"\n'
            f'    }}'
        )
    for dname, plat in (url_deps_with_platform_pred or []):
        dep_lines.append(
            f'    when platform="{plat}" {{\n'
            f'        {dname} git=(url)"https://example.com/{dname}.git" ref="main"\n'
            f'    }}'
        )
    if dep_lines:
        lines.append("deps {\n" + "\n".join(dep_lines) + "\n}")

    dev_dep_lines: list[str] = []
    for dname, fname in (dev_url_deps_with_flag_pred or []):
        dev_dep_lines.append(
            f'    when flag="{fname}" {{\n'
            f'        {dname} git=(url)"https://example.com/{dname}.git" ref="main"\n'
            f'    }}'
        )
    if dev_dep_lines:
        lines.append("dev-deps {\n" + "\n".join(dev_dep_lines) + "\n}")

    return parse_manifest("\n".join(lines) + "\n")


def _profile(*, platform: str = "linux", arch: str = "amd64") -> object:
    from milpa.profile import Profile
    return Profile.from_environment(nim_version="2.0.0")


# ---------------------------------------------------------------------------
# C1: FilterContext.build passthrough arm
# ---------------------------------------------------------------------------


class TestFilterContextBuildPassthrough:
    """profile=None, cli_seed=None → active_flags empty, profile None."""

    def test_passthrough_profile_is_none(self):
        from milpa.resolver import FilterContext
        m = _make_manifest()
        ctx = FilterContext.build(m, None, cli_seed=None)
        assert ctx.profile is None

    def test_passthrough_active_flags_empty(self):
        from milpa.resolver import FilterContext
        m = _make_manifest()
        ctx = FilterContext.build(m, None, cli_seed=None)
        assert ctx.active_flags == frozenset()


# ---------------------------------------------------------------------------
# C2: FilterContext.build flag-only arm
# ---------------------------------------------------------------------------


class TestFilterContextBuildFlagOnly:
    """profile=None, cli_seed provided → active_flags = closure of seed."""

    def test_flag_only_profile_is_none(self):
        from milpa.resolver import FilterContext
        m = _make_manifest(flag_names=[("tls", False)])
        ctx = FilterContext.build(m, None, cli_seed=frozenset({"tls"}))
        assert ctx.profile is None

    def test_flag_only_active_flags_contains_seed(self):
        from milpa.resolver import FilterContext
        m = _make_manifest(flag_names=[("tls", False)])
        ctx = FilterContext.build(m, None, cli_seed=frozenset({"tls"}))
        assert "tls" in ctx.active_flags

    def test_flag_only_empty_seed_produces_empty_flags(self):
        from milpa.resolver import FilterContext
        m = _make_manifest(flag_names=[("tls", False)])
        ctx = FilterContext.build(m, None, cli_seed=frozenset())
        assert ctx.active_flags == frozenset()

    def test_flag_only_closure_expands_enables(self):
        """If flag B enables flag A, both appear in active_flags."""
        from milpa.manifest import parse_manifest
        from milpa.resolver import FilterContext
        m = parse_manifest(
            'name "mypkg"\nkind "library"\n'
            'flags {\n'
            '    a default=#false\n'
            '    b default=#false {\n'
            '        enables "a"\n'
            '    }\n'
            '}\n'
        )
        ctx = FilterContext.build(m, None, cli_seed=frozenset({"b"}))
        assert "b" in ctx.active_flags
        assert "a" in ctx.active_flags


# ---------------------------------------------------------------------------
# C3: FilterContext.build profile arm
# ---------------------------------------------------------------------------


class TestFilterContextBuildProfile:
    """profile present, cli_seed=None → active_flags from manifest defaults."""

    def test_profile_set(self):
        from milpa.resolver import FilterContext
        from milpa.profile import Profile
        p = Profile.from_environment(nim_version="2.0.0")
        m = _make_manifest(flag_names=[("debug", True)])
        ctx = FilterContext.build(m, p, cli_seed=None)
        assert ctx.profile is p

    def test_default_flags_in_active_flags(self):
        """Default-true flags appear in active_flags even with no cli_seed."""
        from milpa.resolver import FilterContext
        from milpa.profile import Profile
        p = Profile.from_environment(nim_version="2.0.0")
        m = _make_manifest(flag_names=[("debug", True), ("release", False)])
        ctx = FilterContext.build(m, p, cli_seed=None)
        assert "debug" in ctx.active_flags
        assert "release" not in ctx.active_flags


# ---------------------------------------------------------------------------
# C4: FilterContext.build profile+flags arm
# ---------------------------------------------------------------------------


class TestFilterContextBuildProfileFlags:
    """profile present, cli_seed provided → active_flags from cli_seed closure."""

    def test_cli_seed_overrides_defaults(self):
        from milpa.resolver import FilterContext
        from milpa.profile import Profile
        p = Profile.from_environment(nim_version="2.0.0")
        # debug is default=#true; tls is default=#false
        m = _make_manifest(flag_names=[("debug", True), ("tls", False)])
        # cli_seed=frozenset({"tls"}) with no_default_features equivalent: just tls
        ctx = FilterContext.build(m, p, cli_seed=frozenset({"tls"}))
        # cli_seed passed → closure is over cli_seed only
        assert "tls" in ctx.active_flags


# ---------------------------------------------------------------------------
# C5: filter_manifest passthrough arm
# ---------------------------------------------------------------------------


class TestFilterManifestPassthrough:
    """profile=None, active_flags empty → manifest returned as-is."""

    def test_passthrough_returns_same_manifest(self):
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(url_deps=["mylib"])
        ctx = FilterContext(profile=None, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        # All deps preserved
        assert len(result.deps) == 1
        assert result.deps[0].name == "mylib"

    def test_passthrough_flag_gated_dep_retained(self):
        """Flag-gated dep is retained when active_flags is empty (passthrough)."""
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(
            flag_names=[("tls", False)],
            url_deps_with_flag_pred=[("tlslib", "tls")],
        )
        ctx = FilterContext(profile=None, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "tlslib" in names


# ---------------------------------------------------------------------------
# C6: filter_manifest flag-only arm
# ---------------------------------------------------------------------------


class TestFilterManifestFlagOnly:
    """profile=None, active_flags nonempty → flag predicates filter, not platform."""

    def test_flag_gated_dep_pruned_when_flag_inactive(self):
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(
            flag_names=[("tls", False)],
            url_deps_with_flag_pred=[("tlslib", "tls")],
        )
        ctx = FilterContext(profile=None, active_flags=frozenset())
        # tls not active — dep should be pruned (flag-only: empty active = passthrough
        # but we use FilterContext with active_flags=frozenset({"someotherflag"}) to
        # trigger the arm and verify tls-gated dep is pruned)
        ctx_with_other = FilterContext(profile=None, active_flags=frozenset({"otherf"}))
        result = filter_manifest(m, ctx_with_other)
        names = {d.name for d in result.deps}
        assert "tlslib" not in names

    def test_flag_gated_dep_retained_when_flag_active(self):
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(
            flag_names=[("tls", False)],
            url_deps_with_flag_pred=[("tlslib", "tls")],
        )
        ctx = FilterContext(profile=None, active_flags=frozenset({"tls"}))
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "tlslib" in names

    def test_unconditional_dep_retained_in_flag_only_arm(self):
        """An unconditional dep is always retained even in flag-only mode."""
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(
            flag_names=[("tls", False)],
            url_deps=["base"],
            url_deps_with_flag_pred=[("tlslib", "tls")],
        )
        ctx = FilterContext(profile=None, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "base" in names


# ---------------------------------------------------------------------------
# C7: filter_manifest profile arm
# ---------------------------------------------------------------------------


class TestFilterManifestProfile:
    """profile present → platform-gated dep filtered by profile."""

    def test_platform_gated_dep_pruned_wrong_platform(self):
        from milpa.resolver import FilterContext, filter_manifest
        from milpa.profile import Profile
        p = Profile.partial(platform="windows", arch="amd64", nim="2.0.0", milpa="0.0.0")
        m = _make_manifest(
            url_deps_with_platform_pred=[("linuxonly", "linux")],
        )
        ctx = FilterContext(profile=p, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "linuxonly" not in names

    def test_platform_gated_dep_retained_right_platform(self):
        from milpa.resolver import FilterContext, filter_manifest
        from milpa.profile import Profile
        p = Profile.partial(platform="linux", arch="amd64", nim="2.0.0", milpa="0.0.0")
        m = _make_manifest(
            url_deps_with_platform_pred=[("linuxonly", "linux")],
        )
        ctx = FilterContext(profile=p, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "linuxonly" in names


# ---------------------------------------------------------------------------
# C8: filter_manifest flag-only arm does NOT prune non-flag-predicate deps
# ---------------------------------------------------------------------------


class TestFilterManifestFlagOnlyNoDoublePrune:
    """profile=None: non-flag predicates are NOT evaluated (§6 NORMATIVE)."""

    def test_platform_dep_retained_in_flag_only_arm(self):
        """A platform-gated dep survives flag-only filtering (no profile → pass)."""
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(
            url_deps_with_platform_pred=[("linuxonly", "linux")],
        )
        # active_flags nonempty but no platform profile
        ctx = FilterContext(profile=None, active_flags=frozenset({"someflag"}))
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        # no profile → platform predicate not evaluated → dep retained
        assert "linuxonly" in names


# ---------------------------------------------------------------------------
# C9: Design-F1 — smart constructor uses passed manifest's flags
# ---------------------------------------------------------------------------


class TestFilterContextBuildUsesPassedManifestFlags:
    """FilterContext.build closure runs against the *passed* manifest's flags.

    This is the footgun Design-F1 is designed to close: if a caller passes
    the wrong manifest (e.g. workspace root instead of member), the closure
    would use the wrong flags block.  Test that build() correctly closes over
    the flags of the manifest it receives.
    """

    def test_enables_closure_uses_passed_manifest_flags(self):
        """The enables-closure fires from the PASSED manifest's flags block.

        root_manifest has "seed" that enables "expanded_by_root".
        member_manifest has "seed" but NOT "expanded_by_root".

        FilterContext.build(root_manifest, ...) → "expanded_by_root" in active_flags.
        FilterContext.build(member_manifest, ...) → "expanded_by_root" NOT in active_flags.

        Verifies closure uses the passed manifest's flags, not inherited flags.
        """
        from milpa.manifest import parse_manifest
        from milpa.resolver import FilterContext

        # root declares "seed" enables "expanded_by_root"
        root_manifest = parse_manifest(
            'name "root"\nkind "application"\n'
            'flags {\n'
            '    expanded_by_root default=#false\n'
            '    seed default=#false {\n'
            '        enables "expanded_by_root"\n'
            '    }\n'
            '}\n'
        )
        # member has "seed" but NOT "expanded_by_root"
        member_manifest = parse_manifest(
            'name "member_a"\nkind "library"\n'
            'flags {\n'
            '    seed default=#false\n'
            '}\n'
        )

        # root: seed enables expanded_by_root → expanded_by_root in active_flags
        ctx_root = FilterContext.build(root_manifest, None, cli_seed=frozenset({"seed"}))
        assert "seed" in ctx_root.active_flags
        assert "expanded_by_root" in ctx_root.active_flags

        # member: seed has no enables → expanded_by_root NOT in active_flags
        ctx_member = FilterContext.build(member_manifest, None, cli_seed=frozenset({"seed"}))
        assert "seed" in ctx_member.active_flags
        assert "expanded_by_root" not in ctx_member.active_flags

    def test_member_specific_flag_activated_by_member_closure(self):
        """A flag that exists only in the member manifest is activated for the member."""
        from milpa.manifest import parse_manifest
        from milpa.resolver import FilterContext

        member_manifest = parse_manifest(
            'name "member_a"\nkind "library"\n'
            'flags {\n'
            '    member_flag default=#true\n'
            '}\n'
        )

        # cli_seed=None → uses default flags from member manifest
        ctx = FilterContext.build(member_manifest, None, cli_seed=None)
        assert "member_flag" in ctx.active_flags


# ---------------------------------------------------------------------------
# C10: profile arm skips flag predicates (Depth-F7 no double-eval)
# ---------------------------------------------------------------------------


class TestFilterManifestProfileSkipsFlagPredicates:
    """When profile is present, flag predicates are owned by the flag gate, not profile gate.

    A dep gated only on a flag predicate: when profile is active but
    active_flags is empty, the dep should be RETAINED by the profile gate
    (flag pred is not a platform pred — profile gate skips it).
    The flag gate then evaluates it: active_flags empty → passthrough → retained.

    Without the Depth-F7 fix (profile gate skipping flag preds), the profile
    gate would call _predicate_satisfied on the flag pred which would call
    dep_passes_flag_predicates with whatever the profile's flags are — potentially
    pruning when it shouldn't, or double-pruning.
    """

    def test_flag_only_predicate_dep_pruned_with_profile_active_flags_empty(self):
        """Profile gate + empty active_flags: flag-gated dep is PRUNED.

        The flag gate owns flag predicates (Depth-F7: profile gate skips them).
        With profile present and active_flags=frozenset(), the flag gate runs
        and evaluates flag=tls as False (tls not active) → dep pruned.

        This is Row-1 parity: the profile path always evaluated flag predicates,
        and an empty active set means no flags active → flag-gated dep excluded.
        """
        from milpa.resolver import FilterContext, filter_manifest
        from milpa.profile import Profile
        p = Profile.partial(platform="linux", arch="amd64", nim="2.0.0", milpa="0.0.0")
        m = _make_manifest(
            flag_names=[("tls", False)],
            url_deps_with_flag_pred=[("tlslib", "tls")],
        )
        ctx = FilterContext(profile=p, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        # tls not active → flag=tls predicate fails → dep pruned
        names = {d.name for d in result.deps}
        assert "tlslib" not in names

    def test_flag_only_predicate_dep_pruned_with_profile_and_flag_inactive(self):
        """Profile gate + active_flags has OTHER flag: flag-gated dep is pruned by flag gate."""
        from milpa.resolver import FilterContext, filter_manifest
        from milpa.profile import Profile
        p = Profile.partial(platform="linux", arch="amd64", nim="2.0.0", milpa="0.0.0")
        m = _make_manifest(
            flag_names=[("tls", False), ("other", False)],
            url_deps_with_flag_pred=[("tlslib", "tls")],
        )
        # active_flags has "other" but not "tls" → flag gate prunes tlslib
        ctx = FilterContext(profile=p, active_flags=frozenset({"other"}))
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "tlslib" not in names


# ---------------------------------------------------------------------------
# C11: dev_deps filtered identically to deps
# ---------------------------------------------------------------------------


class TestFilterManifestDevDeps:
    """dev_deps are filtered by the same predicates as deps."""

    def test_flag_gated_dev_dep_pruned(self):
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(
            flag_names=[("tls", False)],
            dev_url_deps_with_flag_pred=[("tlsdev", "tls")],
        )
        ctx = FilterContext(profile=None, active_flags=frozenset({"other"}))
        result = filter_manifest(m, ctx)
        dev_names = {d.name for d in result.dev_deps}
        assert "tlsdev" not in dev_names

    def test_flag_gated_dev_dep_retained(self):
        from milpa.resolver import FilterContext, filter_manifest
        m = _make_manifest(
            flag_names=[("tls", False)],
            dev_url_deps_with_flag_pred=[("tlsdev", "tls")],
        )
        ctx = FilterContext(profile=None, active_flags=frozenset({"tls"}))
        result = filter_manifest(m, ctx)
        dev_names = {d.name for d in result.dev_deps}
        assert "tlsdev" in dev_names


# ---------------------------------------------------------------------------
# C12 — S4 (#159): Profile.partial + absent-axis predicate semantics (§3.C)
# ---------------------------------------------------------------------------


class TestProfilePartialConstructor:
    """Profile.partial() builds a partial profile with None axes."""

    def test_partial_all_none_by_default(self):
        from milpa.profile import Profile
        p = Profile.partial()
        assert p.platform is None
        assert p.arch is None
        assert p.nim is None
        assert p.milpa is None
        assert p.flags == frozenset()

    def test_partial_one_axis_set(self):
        from milpa.profile import Profile
        p = Profile.partial(platform="linux")
        assert p.platform == "linux"
        assert p.arch is None
        assert p.nim is None
        assert p.milpa is None

    def test_partial_all_axes_set(self):
        from milpa.profile import Profile
        p = Profile.partial(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0")
        assert p.platform == "linux"
        assert p.arch == "amd64"
        assert p.nim == "2.0.0"
        assert p.milpa == "0.1.0"

    def test_partial_flags_propagated(self):
        from milpa.profile import Profile
        p = Profile.partial(platform="linux", flags=frozenset({"tls"}))
        assert p.flags == frozenset({"tls"})

    def test_from_environment_no_env_coupling(self):
        """Profile.partial has no env-var coupling; Profile.from_environment does."""
        from milpa.profile import Profile
        import os
        # from_environment defaults every axis from the host
        p_env = Profile.from_environment()
        assert p_env.platform is not None  # host-defaulted
        assert p_env.arch is not None

        # partial() leaves unset axes as None regardless of env
        p_partial = Profile.partial(platform="linux")
        assert p_partial.platform == "linux"
        assert p_partial.arch is None


class TestAbsentAxisPredicateSemantics:
    """§3.C: absent axis ⇒ predicate evaluates to false for BOTH positive and negated forms."""

    def test_positive_predicate_over_absent_axis_excludes(self):
        """when arch == "amd64" with arch=None → dep excluded (§3.C)."""
        from milpa.resolver import FilterContext, filter_manifest
        from milpa.profile import Profile
        # Partial profile: platform known, arch absent
        p = Profile.partial(platform="linux")
        m = _make_manifest(
            url_deps_with_platform_pred=[],  # we need arch pred; use _make_manifest directly
        )
        # Build a manifest with an arch predicate via KDL
        from milpa.manifest import parse_manifest
        kdl = (
            'name "mypkg"\nkind "library"\n'
            'deps {\n'
            '    when arch="amd64" {\n'
            '        archlib git=(url)"https://example.com/archlib.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        m = parse_manifest(kdl)
        ctx = FilterContext(profile=p, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "archlib" not in names, (
            "positive predicate over absent arch axis must exclude the dep"
        )

    def test_negated_predicate_over_absent_axis_excludes(self):
        """when arch != "arm64" with arch=None → dep ALSO excluded (§3.C).

        This is the load-bearing cross-impl divergence guard.  Python already
        returned False for absent axes (the early return before negation check
        in _predicate_satisfied_profile_only).  This test pins that it stays
        correct after making the axes str | None.
        """
        from milpa.resolver import FilterContext, filter_manifest
        from milpa.profile import Profile
        from milpa.manifest import parse_manifest
        # Partial profile: platform known, arch absent
        p = Profile.partial(platform="linux")
        # Dep gated on `when arch != "arm64"` — would be true on amd64,
        # but arch is absent → indeterminate → excluded.
        kdl = (
            'name "mypkg"\nkind "library"\n'
            'deps {\n'
            '    when arch=(not)"arm64" {\n'
            '        archlib git=(url)"https://example.com/archlib.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        m = parse_manifest(kdl)
        ctx = FilterContext(profile=p, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "archlib" not in names, (
            "negated predicate over absent arch axis must also exclude the dep "
            "(indeterminate ⇒ false, not true)"
        )

    def test_absent_whole_profile_is_passthrough(self):
        """Absent *whole* profile (profile=None) → passthrough, not exclusion (§470)."""
        from milpa.resolver import FilterContext, filter_manifest
        from milpa.manifest import parse_manifest
        kdl = (
            'name "mypkg"\nkind "library"\n'
            'deps {\n'
            '    when arch=(not)"arm64" {\n'
            '        archlib git=(url)"https://example.com/archlib.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        m = parse_manifest(kdl)
        # profile=None → platform-filtering disabled entirely
        ctx = FilterContext(profile=None, active_flags=frozenset())
        result = filter_manifest(m, ctx)
        names = {d.name for d in result.deps}
        assert "archlib" in names, (
            "absent *whole* profile must include all deps regardless of predicates (§470)"
        )
