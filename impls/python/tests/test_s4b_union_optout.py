"""S4b (RFC #23 §7): multi-consumer union + opt-out semantics.

Coverage:
  1. compute_dep_active_flags union: two separate flag-request sets produce the union
     (sources are merged per flag, not overwritten).
  2. Multi-consumer union via direct dep-entry flag_requests: two parents each request
     a DIFFERENT flag on the same shared dep (via UrlDep.flag_requests) → the shared
     dep's active_flags is the union of both sets, observable via admitted subdeps.
  3. Multi-consumer union via cross-pkg enables (S4a fixpoint path): two parents each
     use enables_cross_pkg targeting the same shared dep with different flags → union.
  4. Opt-out as absence-of-request: flag "x" #false from one consumer does NOT veto
     flag "x" #true from another consumer — x stays active.
  5. Opt-out first-consumer scenario: when the negative-request consumer is processed
     FIRST (before the positive one), x must still be active (union beats absence).

§3.1.3 normative: union is forced by monotonicity; opt-out is absence-of-request,
never a veto; exclusion is `conflicts` (S4c, NOT implemented here).
"""

from __future__ import annotations

from pathlib import Path
import pytest


# ---------------------------------------------------------------------------
# Helpers: mocked env builders
# ---------------------------------------------------------------------------

def _make_mock_env(tmp_path: Path, mocked_contents: dict):
    """Build a MilpaEnv with mocked git fetchers.

    mocked_contents: dict mapping (url, ref) → (milpa_kdl_text, commit_sha)
    """
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.cas import CAStore
    from milpa.context import MilpaEnv

    mocked_dir = tmp_path / "mocked-fetches"
    for (url, ref), (kdl, sha) in mocked_contents.items():
        key = url_key(url, ref)
        d = mocked_dir / key
        (d / "content").mkdir(parents=True)
        (d / "content" / "milpa.kdl").write_text(kdl, encoding="utf-8")
        (d / "sha").write_text(sha, encoding="utf-8")

    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


# ---------------------------------------------------------------------------
# 1. compute_dep_active_flags union semantics (unit, no resolver)
# ---------------------------------------------------------------------------

class TestComputeDepActiveFlagsUnion:
    """compute_dep_active_flags: union semantics verified at the SSOT level.

    §3.1.3: active(D) accumulates the union of every requester's flags plus
    D's own defaults + enables-closure.  This is a property of compute_dep_active_flags
    alone (no fixpoint needed).
    """

    def test_two_positive_requests_both_active(self) -> None:
        """Both flag "x" and flag "y" positive requests result in both active."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        from milpa.manifest import FlagDecl, FlagRequest

        flags = (
            FlagDecl(name="feat-x", default=False),
            FlagDecl(name="feat-y", default=False),
        )
        # Two separate positive requests (as if from two consumers merged into one tuple)
        reqs = (
            FlagRequest(name="feat-x", enabled=True),
            FlagRequest(name="feat-y", enabled=True),
        )
        result = compute_dep_active_flags(flags, reqs)
        assert "feat-x" in result
        assert "feat-y" in result
        assert ActivationSource.EDGE_REQUEST in result["feat-x"]
        assert ActivationSource.EDGE_REQUEST in result["feat-y"]

    def test_positive_plus_negative_same_flag_positive_wins(self) -> None:
        """Positive + negative requests on same flag: positive wins (union semantics).

        §3.1.3: flag "x" #false is absence-of-request from that edge, not a veto.
        If another request is positive, x is active.
        """
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        from milpa.manifest import FlagDecl, FlagRequest

        flags = (FlagDecl(name="feat-x", default=False),)
        reqs = (
            FlagRequest(name="feat-x", enabled=True),   # consumer A: positive
            FlagRequest(name="feat-x", enabled=False),  # consumer B: opt-out (absence)
        )
        result = compute_dep_active_flags(flags, reqs)
        # The positive request wins; the negative is absence-of-request (never a veto).
        assert "feat-x" in result
        assert ActivationSource.EDGE_REQUEST in result["feat-x"]

    def test_negative_only_does_not_activate(self) -> None:
        """A negative request alone does not activate the flag (it's absence-of-request)."""
        from milpa.resolver import compute_dep_active_flags
        from milpa.manifest import FlagDecl, FlagRequest

        flags = (FlagDecl(name="feat-x", default=False),)
        reqs = (FlagRequest(name="feat-x", enabled=False),)
        result = compute_dep_active_flags(flags, reqs)
        assert "feat-x" not in result

    def test_default_survives_negative_opt_out(self) -> None:
        """A default-true flag stays active even when a consumer opts out with #false.

        §3.1.3: opt-out is absence-of-request; DEFAULT source still activates.
        """
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        from milpa.manifest import FlagDecl, FlagRequest

        flags = (FlagDecl(name="feat-x", default=True),)
        reqs = (FlagRequest(name="feat-x", enabled=False),)  # opt-out
        result = compute_dep_active_flags(flags, reqs)
        assert "feat-x" in result
        assert ActivationSource.DEFAULT in result["feat-x"]

    def test_sources_are_unioned_not_overwritten(self) -> None:
        """When both DEFAULT and EDGE_REQUEST activate a flag, both sources are present."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        from milpa.manifest import FlagDecl, FlagRequest

        flags = (FlagDecl(name="feat-x", default=True),)
        reqs = (FlagRequest(name="feat-x", enabled=True),)
        result = compute_dep_active_flags(flags, reqs)
        assert "feat-x" in result
        # Both DEFAULT (manifest declares default=True) and EDGE_REQUEST are present.
        assert ActivationSource.DEFAULT in result["feat-x"]
        assert ActivationSource.EDGE_REQUEST in result["feat-x"]


# ---------------------------------------------------------------------------
# 2. Multi-consumer union via direct dep-entry flag_requests (integration)
# ---------------------------------------------------------------------------

class TestMultiConsumerUnionDirectFlagRequests:
    """S4b: two parents each request a different flag on the same shared dep.

    Scenario:
      Root → lib-a (unconditional) → lib-shared { flag "feat-x" }
      Root → lib-b (unconditional) → lib-shared { flag "feat-y" }

      lib-shared declares:
        feat-x (default=false) gates lib-e
        feat-y (default=false) gates lib-f

      With union semantics:
        active(lib-shared) = {feat-x, feat-y}
        → lib-e AND lib-f both admitted.

      Without union (first-consumer-wins bug):
        only one of feat-x or feat-y active → only lib-e OR lib-f admitted.

    This test pins the multi-consumer union behavior (§3.1.3) observable via
    admitted-deps difference (not lockfile active_flags, which is S5).
    """

    def _build_env(self, tmp_path: Path):
        lib_a_kdl = (
            'name "lib-a"\nkind "library"\n'
            'deps {\n'
            '    lib-shared git=(url)"https://example.com/lib-shared.git" ref="main" {\n'
            '        flag "feat-x"\n'
            '    }\n'
            '}\n'
        )
        lib_b_kdl = (
            'name "lib-b"\nkind "library"\n'
            'deps {\n'
            '    lib-shared git=(url)"https://example.com/lib-shared.git" ref="main" {\n'
            '        flag "feat-y"\n'
            '    }\n'
            '}\n'
        )
        lib_shared_kdl = (
            'name "lib-shared"\nkind "library"\n'
            'flags {\n'
            '    feat-x default=#false\n'
            '    feat-y default=#false\n'
            '}\n'
            'deps {\n'
            '    when flag="feat-x" {\n'
            '        lib-e git=(url)"https://example.com/lib-e.git" ref="main"\n'
            '    }\n'
            '    when flag="feat-y" {\n'
            '        lib-f git=(url)"https://example.com/lib-f.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        lib_e_kdl = 'name "lib-e"\nkind "library"\n'
        lib_f_kdl = 'name "lib-f"\nkind "library"\n'

        return _make_mock_env(tmp_path, {
            ("https://example.com/lib-a.git", "main"): (lib_a_kdl, "aaaa" * 10),
            ("https://example.com/lib-b.git", "main"): (lib_b_kdl, "bbbb" * 10),
            ("https://example.com/lib-shared.git", "main"): (lib_shared_kdl, "cccc" * 10),
            ("https://example.com/lib-e.git", "main"): (lib_e_kdl, "dddd" * 10),
            ("https://example.com/lib-f.git", "main"): (lib_f_kdl, "eeee" * 10),
        })

    def test_both_flags_admitted_union(self, tmp_path: Path) -> None:
        """S4b: union of feat-x and feat-y → lib-e AND lib-f both in resolved graph.

        §3.1.3: D is resolved once with the union of all requested features.
        lib-a requests feat-x on lib-shared; lib-b requests feat-y on lib-shared.
        active(lib-shared) must be {feat-x, feat-y} → both lib-e and lib-f admitted.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = self._build_env(tmp_path)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        assert "lib-shared" in dep_names, "lib-shared must be resolved"
        # lib-a requests feat-x → lib-e must be admitted
        assert "lib-e" in dep_names, (
            f"lib-e must be admitted (lib-a requests feat-x on lib-shared); "
            f"got: {dep_names}"
        )
        # lib-b requests feat-y → lib-f must be admitted (requires union fix)
        assert "lib-f" in dep_names, (
            f"lib-f must be admitted (lib-b requests feat-y on lib-shared); "
            f"got: {dep_names}"
        )

    def test_union_order_independent_b_before_a(self, tmp_path: Path) -> None:
        """S4b: same result when lib-b is declared before lib-a in root (order independence).

        Union commutativity (§3.1.2): active(D) is invariant to BFS visitation order.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        # lib-b declared FIRST (processes its deps first → lib-shared first encounter
        # records feat-y; lib-a's feat-x must still be merged)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = self._build_env(tmp_path)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        assert "lib-e" in dep_names, (
            f"lib-e must be admitted regardless of BFS order; got: {dep_names}"
        )
        assert "lib-f" in dep_names, (
            f"lib-f must be admitted regardless of BFS order; got: {dep_names}"
        )


# ---------------------------------------------------------------------------
# 3. Multi-consumer union via cross-pkg enables (S4a fixpoint path)
# ---------------------------------------------------------------------------

class TestMultiConsumerUnionViaEnables:
    """S4b: two parents use enables_cross_pkg to target the same shared dep.

    This path flows through the S4a fixpoint's additional_requests accumulator
    (which already unions via .extend()). Verified here as part of S4b coverage.

    Both consumers target lib-shared with different flags via enables.
    The root explicitly requests the enables-carrying flag on each parent
    (so dep_active_flags is populated for lib-a and lib-b at BFS time).

    Expected: union active(lib-shared) = {feat-x, feat-y} → lib-e AND lib-f admitted.

    Note: enables from a dep's *default-true* flags (without explicit root request)
    is a separate gap (#TBD default-flags-in-fixpoint) tracked as S4a follow-up.
    This test uses explicit root-level flag requests to stay on the S4b path.
    """

    def _build_env(self, tmp_path: Path):
        # lib-a: flag "use-x" (default=false, activated by root request)
        # enables lib-shared.feat-x via cross-pkg
        lib_a_kdl = (
            'name "lib-a"\nkind "library"\n'
            'flags {\n'
            '    use-x default=#false {\n'
            '        enables {\n'
            '            lib-shared { flag "feat-x" }\n'
            '        }\n'
            '    }\n'
            '}\n'
            'deps {\n'
            '    lib-shared git=(url)"https://example.com/lib-shared.git" ref="main"\n'
            '}\n'
        )
        # lib-b: flag "use-y" (default=false, activated by root request)
        # enables lib-shared.feat-y via cross-pkg
        lib_b_kdl = (
            'name "lib-b"\nkind "library"\n'
            'flags {\n'
            '    use-y default=#false {\n'
            '        enables {\n'
            '            lib-shared { flag "feat-y" }\n'
            '        }\n'
            '    }\n'
            '}\n'
            'deps {\n'
            '    lib-shared git=(url)"https://example.com/lib-shared.git" ref="main"\n'
            '}\n'
        )
        lib_shared_kdl = (
            'name "lib-shared"\nkind "library"\n'
            'flags {\n'
            '    feat-x default=#false\n'
            '    feat-y default=#false\n'
            '}\n'
            'deps {\n'
            '    when flag="feat-x" {\n'
            '        lib-e git=(url)"https://example.com/lib-e.git" ref="main"\n'
            '    }\n'
            '    when flag="feat-y" {\n'
            '        lib-f git=(url)"https://example.com/lib-f.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        lib_e_kdl = 'name "lib-e"\nkind "library"\n'
        lib_f_kdl = 'name "lib-f"\nkind "library"\n'

        return _make_mock_env(tmp_path, {
            ("https://example.com/lib-a.git", "main"): (lib_a_kdl, "aaaa" * 10),
            ("https://example.com/lib-b.git", "main"): (lib_b_kdl, "bbbb" * 10),
            ("https://example.com/lib-shared.git", "main"): (lib_shared_kdl, "cccc" * 10),
            ("https://example.com/lib-e.git", "main"): (lib_e_kdl, "dddd" * 10),
            ("https://example.com/lib-f.git", "main"): (lib_f_kdl, "eeee" * 10),
        })

    def test_both_subdeps_admitted_via_enables(self, tmp_path: Path) -> None:
        """Two parents with enables_cross_pkg → union on lib-shared → lib-e + lib-f.

        Root explicitly requests use-x on lib-a and use-y on lib-b (both default=false).
        The fixpoint fires from lib-a.use-x and lib-b.use-y, generating additional_requests
        for lib-shared.feat-x and lib-shared.feat-y respectively.
        additional_requests["lib-shared"] accumulates both (via .extend()) → union.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main" {\n'
            '        flag "use-x"\n'
            '    }\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main" {\n'
            '        flag "use-y"\n'
            '    }\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = self._build_env(tmp_path)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        assert "lib-e" in dep_names, (
            f"lib-e must be admitted (lib-a enables feat-x on lib-shared via enables); "
            f"got: {dep_names}"
        )
        assert "lib-f" in dep_names, (
            f"lib-f must be admitted (lib-b enables feat-y on lib-shared via enables); "
            f"got: {dep_names}"
        )


# ---------------------------------------------------------------------------
# 4. Opt-out: flag "x" #false is absence-of-request, not a veto
# ---------------------------------------------------------------------------

class TestOptOutAsAbsenceOfRequest:
    """S4b: opt-out semantics — §3.1.3 normative.

    A consumer's flag "x" #false means 'this edge does not request x'.
    Union still applies: x is active iff some other active edge or a
    non-suppressed default requests it.

    Tested here:
    - One consumer opts out (#false) on lib-shared; another requests positively.
    - Expected: x is active (positive wins), lib-e admitted. No error.
    """

    def _build_env(self, tmp_path: Path, a_flag_requests: str, b_flag_requests: str):
        """Build env with customisable flag requests on lib-shared from lib-a and lib-b."""
        lib_a_kdl = (
            'name "lib-a"\nkind "library"\n'
            'deps {\n'
            f'    lib-shared git=(url)"https://example.com/lib-shared.git" ref="main" {{\n'
            f'        {a_flag_requests}\n'
            '    }\n'
            '}\n'
        )
        lib_b_kdl = (
            'name "lib-b"\nkind "library"\n'
            'deps {\n'
            f'    lib-shared git=(url)"https://example.com/lib-shared.git" ref="main" {{\n'
            f'        {b_flag_requests}\n'
            '    }\n'
            '}\n'
        )
        lib_shared_kdl = (
            'name "lib-shared"\nkind "library"\n'
            'flags {\n'
            '    feat-x default=#false\n'
            '}\n'
            'deps {\n'
            '    when flag="feat-x" {\n'
            '        lib-e git=(url)"https://example.com/lib-e.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        lib_e_kdl = 'name "lib-e"\nkind "library"\n'

        return _make_mock_env(tmp_path, {
            ("https://example.com/lib-a.git", "main"): (lib_a_kdl, "aaaa" * 10),
            ("https://example.com/lib-b.git", "main"): (lib_b_kdl, "bbbb" * 10),
            ("https://example.com/lib-shared.git", "main"): (lib_shared_kdl, "cccc" * 10),
            ("https://example.com/lib-e.git", "main"): (lib_e_kdl, "dddd" * 10),
        })

    def test_positive_a_optout_b_x_active(self, tmp_path: Path) -> None:
        """lib-a requests feat-x; lib-b opts out with #false → feat-x stays ON.

        lib-a is declared first (processes lib-shared first with feat-x=true).
        lib-b's opt-out is the second consumer. feat-x must remain active.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = self._build_env(tmp_path,
            a_flag_requests='flag "feat-x"',          # positive
            b_flag_requests='flag "feat-x" #false',   # opt-out
        )
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        assert "lib-e" in dep_names, (
            f"lib-e must be admitted (feat-x active because lib-a requests it); "
            f"got: {dep_names}"
        )

    def test_optout_a_positive_b_x_active(self, tmp_path: Path) -> None:
        """lib-a opts out; lib-b requests feat-x positively → feat-x stays ON.

        lib-a is declared first (first consumer) and opts out.
        lib-b (second consumer) requests positively.
        The second consumer's positive request must win via union.

        This is the ordering-sensitive case: if the opt-out consumer is processed
        first and the positive consumer second, the positive must still win.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = self._build_env(tmp_path,
            a_flag_requests='flag "feat-x" #false',   # opt-out (first consumer)
            b_flag_requests='flag "feat-x"',           # positive (second consumer)
        )
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        assert "lib-e" in dep_names, (
            f"lib-e must be admitted (feat-x active because lib-b requests it, "
            f"even though lib-a opted out and was processed first); "
            f"got: {dep_names}"
        )

    def test_both_optout_x_not_active(self, tmp_path: Path) -> None:
        """Both consumers opt out: feat-x stays OFF (no positive request). Control."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = self._build_env(tmp_path,
            a_flag_requests='flag "feat-x" #false',
            b_flag_requests='flag "feat-x" #false',
        )
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        # Both opt out and feat-x has no default-true — lib-e must NOT be admitted.
        assert "lib-e" not in dep_names, (
            f"lib-e must NOT be admitted when both consumers opt out; got: {dep_names}"
        )
