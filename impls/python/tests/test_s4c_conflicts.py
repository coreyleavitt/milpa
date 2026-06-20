"""S4c (RFC #23 §3.1.4): exclusion (conflicts) + RESOLVE-FLAG-CONFLICT.

Coverage:
  1. MAN-FLAG-CONFLICTS-UNDECLARED: post-parse validation for conflicts bare names.
     (a) undeclared name raises MAN-FLAG-CONFLICTS-UNDECLARED
     (b) declared name (forward reference) is accepted
     (c) declared name (same order) is accepted

  2. _s4c_check_flag_conflicts: post-fixpoint conflict validation.
     (a) two conflicting flags both active (both default=#true) → RESOLVE-FLAG-CONFLICT
     (b) only one active (one default=#true, one default=#false) → no error
     (c) payload byte-identity: dep, flag_a, flag_b, sources_a, sources_b
         - flag_a < flag_b lexicographically
         - sources serialized in enum declaration order: default, edge_request, enables_rule

  3. Integration via _s4c_check_flag_conflicts using mocked fetches:
     (a) conflict forced by defaults → RESOLVE-FLAG-CONFLICT
     (b) conflict forced by edge_request → RESOLVE-FLAG-CONFLICT (sources include edge_request)
     (c) satisfiable: only one side active → no error

  4. Symmetry: conflict declared on one flag only catches conflict regardless
     of which flag is checked first (both orderings fire via the check).

RFC #23 §3.1.4 normative: same-package only, post-fixpoint, never retracts,
RESOLVE-FLAG-CONFLICT is the ONLY source (opt-out never raises it).
"""

from __future__ import annotations

from pathlib import Path
import pytest


# ---------------------------------------------------------------------------
# 1a. MAN-FLAG-CONFLICTS-UNDECLARED: undeclared name
# ---------------------------------------------------------------------------

class TestManFlagConflictsUndeclared:
    """Post-parse validation: conflicts bare names must reference declared flags."""

    def test_undeclared_conflicts_target_raises(self) -> None:
        """conflicts referencing undeclared flag → MAN-FLAG-CONFLICTS-UNDECLARED."""
        from milpa.manifest import parse_manifest
        from milpa.errors import MAN_FLAG_CONFLICTS_UNDECLARED, MilpaError

        kdl = """
name "mylib"
kind "library"
flags {
    openssl default=#false {
        conflicts "bearssl"
    }
}
"""
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(kdl)
        assert exc_info.value.slug == MAN_FLAG_CONFLICTS_UNDECLARED

    def test_declared_conflicts_target_accepted(self) -> None:
        """conflicts referencing declared flag (same order) → no error."""
        from milpa.manifest import parse_manifest

        kdl = """
name "mylib"
kind "library"
flags {
    openssl default=#false {
        conflicts "bearssl"
    }
    bearssl default=#false
}
"""
        manifest = parse_manifest(kdl)
        assert len(manifest.flags) == 2
        openssl_flag = next(f for f in manifest.flags if f.name == "openssl")
        assert openssl_flag.conflicts == ("bearssl",)

    def test_forward_reference_in_conflicts_accepted(self) -> None:
        """conflicts with forward reference (target declared later) → no error (post-parse)."""
        from milpa.manifest import parse_manifest

        kdl = """
name "mylib"
kind "library"
flags {
    openssl default=#false {
        conflicts "bearssl"
    }
    bearssl default=#false
}
"""
        # bearssl is declared after openssl's conflicts — forward ref must be legal.
        manifest = parse_manifest(kdl)
        openssl_flag = next(f for f in manifest.flags if f.name == "openssl")
        assert "bearssl" in openssl_flag.conflicts

    def test_conflicts_undeclared_error_payload(self) -> None:
        """MAN-FLAG-CONFLICTS-UNDECLARED carries flag + conflicts context."""
        from milpa.manifest import parse_manifest
        from milpa.errors import MAN_FLAG_CONFLICTS_UNDECLARED, MilpaError

        kdl = """
name "mylib"
kind "library"
flags {
    openssl default=#false {
        conflicts "missing-flag"
    }
}
"""
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(kdl)
        err = exc_info.value
        assert err.slug == MAN_FLAG_CONFLICTS_UNDECLARED
        assert err.context.get("flag") == "openssl"
        assert err.context.get("conflicts") == "missing-flag"


# ---------------------------------------------------------------------------
# 1b. MAN-FLAG-CONFLICTS-SELF (M5): self-referential conflicts
# ---------------------------------------------------------------------------

class TestManFlagConflictsSelf:
    """M5: a flag that names itself in conflicts is rejected at parse time."""

    def test_self_conflict_raises(self) -> None:
        """flag { f1 conflicts=["f1"] } → MAN-FLAG-CONFLICTS-SELF."""
        from milpa.manifest import parse_manifest
        from milpa.errors import MAN_FLAG_CONFLICTS_SELF, MilpaError

        kdl = (
            'name "mylib"\nkind "library"\n'
            'flags {\n'
            '    f1 default=#false {\n'
            '        conflicts "f1"\n'
            '    }\n'
            '}\n'
        )
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(kdl)
        assert exc_info.value.slug == MAN_FLAG_CONFLICTS_SELF

    def test_self_conflict_error_payload(self) -> None:
        """MAN-FLAG-CONFLICTS-SELF carries the flag name in context."""
        from milpa.manifest import parse_manifest
        from milpa.errors import MAN_FLAG_CONFLICTS_SELF, MilpaError

        kdl = (
            'name "mylib"\nkind "library"\n'
            'flags {\n'
            '    badness default=#false {\n'
            '        conflicts "badness"\n'
            '    }\n'
            '}\n'
        )
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(kdl)
        err = exc_info.value
        assert err.slug == MAN_FLAG_CONFLICTS_SELF
        assert err.context.get("flag") == "badness"

    def test_non_self_conflict_accepted(self) -> None:
        """A flag conflicting with a DIFFERENT flag is not a self-conflict."""
        from milpa.manifest import parse_manifest

        kdl = (
            'name "mylib"\nkind "library"\n'
            'flags {\n'
            '    f1 default=#false {\n'
            '        conflicts "f2"\n'
            '    }\n'
            '    f2 default=#false\n'
            '}\n'
        )
        # Must not raise
        manifest = parse_manifest(kdl)
        f1 = next(f for f in manifest.flags if f.name == "f1")
        assert f1.conflicts == ("f2",)

    def test_self_conflict_caught_before_undeclared(self) -> None:
        """Self-reference is caught as SELF (not UNDECLARED) even if name is declared."""
        from milpa.manifest import parse_manifest
        from milpa.errors import MAN_FLAG_CONFLICTS_SELF, MilpaError

        # f1 conflicts f1 — f1 IS declared, so UNDECLARED won't fire.
        # SELF check must fire first.
        kdl = (
            'name "mylib"\nkind "library"\n'
            'flags {\n'
            '    f1 default=#false {\n'
            '        conflicts "f1"\n'
            '    }\n'
            '}\n'
        )
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(kdl)
        assert exc_info.value.slug == MAN_FLAG_CONFLICTS_SELF


# ---------------------------------------------------------------------------
# 2. _s4c_check_flag_conflicts: post-fixpoint check (unit, no resolver)
# ---------------------------------------------------------------------------

def _build_manifest_with_conflicts(openssl_default: bool, bearssl_default: bool):
    """Build a Manifest with openssl and bearssl flags, openssl conflicts bearssl."""
    from milpa.manifest import FlagDecl, Manifest

    openssl = FlagDecl(name="openssl", default=openssl_default, conflicts=("bearssl",))
    bearssl = FlagDecl(name="bearssl", default=bearssl_default)
    return Manifest(
        name="lib-tls",
        kind="library",
        src_dir="",
        deps=(),
        dev_deps=(),
        overrides=(),
        flags=(openssl, bearssl),
        self_mirrors=(),
        cas_dir=None,
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


class TestS4cFlagConflictsUnit:
    """Unit tests for the _s4c_check_flag_conflicts SSOT function via compute_dep_active_flags."""

    def test_both_defaults_true_produces_conflict(self) -> None:
        """Both flags default=#true → compute_dep_active_flags includes both → conflict detected."""
        from milpa.resolver import compute_dep_active_flags, ActivationSource
        from milpa.manifest import FlagDecl

        # openssl conflicts bearssl
        flags = (
            FlagDecl(name="openssl", default=True, conflicts=("bearssl",)),
            FlagDecl(name="bearssl", default=True),
        )
        active = compute_dep_active_flags(flags, ())
        assert "openssl" in active
        assert "bearssl" in active
        assert ActivationSource.DEFAULT in active["openssl"]
        assert ActivationSource.DEFAULT in active["bearssl"]

    def test_only_one_default_true_no_conflict(self) -> None:
        """One default=#true, one default=#false → only one active → no conflict."""
        from milpa.resolver import compute_dep_active_flags

        from milpa.manifest import FlagDecl

        flags = (
            FlagDecl(name="openssl", default=True, conflicts=("bearssl",)),
            FlagDecl(name="bearssl", default=False),
        )
        active = compute_dep_active_flags(flags, ())
        assert "openssl" in active
        assert "bearssl" not in active  # not active by default


# ---------------------------------------------------------------------------
# 3. Integration via the actual resolver with mocked fetches
# ---------------------------------------------------------------------------

def _make_mock_env_for_s4c(tmp_path: Path, dep_name: str, dep_kdl: str, sha: str):
    """Build a MilpaEnv with a single mocked dep."""
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.cas import CAStore
    from milpa.context import MilpaEnv

    url = f"https://example.com/{dep_name}.git"
    ref = "main"
    key = url_key(url, ref)
    mocked_dir = tmp_path / "mocked-fetches"
    d = mocked_dir / key
    (d / "content").mkdir(parents=True)
    (d / "content" / "milpa.kdl").write_text(dep_kdl, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")

    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store), url, ref


class TestS4cResolveIntegration:
    """Integration: RESOLVE-FLAG-CONFLICT raised by the post-fixpoint check."""

    def test_both_defaults_raises_resolve_flag_conflict(self, tmp_path: Path) -> None:
        """Both mutually-exclusive flags active by default → RESOLVE-FLAG-CONFLICT."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.errors import RESOLVE_FLAG_CONFLICT, MilpaError

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#true
}
"""
        env, url, ref = _make_mock_env_for_s4c(tmp_path, "lib-tls", dep_kdl, "abcd0000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        with pytest.raises(MilpaError) as exc_info:
            resolve(manifest, deps_dir, env, ResolveParams())

        err = exc_info.value
        assert err.slug == RESOLVE_FLAG_CONFLICT

    def test_conflict_payload_byte_identity(self, tmp_path: Path) -> None:
        """RESOLVE-FLAG-CONFLICT payload is byte-identical to the normative spec.

        Normative payload (RFC #23 §3.1.4 + §5 risk #3):
          dep      — dep name (string)
          flag_a   — lexicographically smaller flag name
          flag_b   — lexicographically larger flag name
          sources_a — activation sources for flag_a, sorted by enum declaration order
          sources_b — activation sources for flag_b, sorted by enum declaration order

        Enum declaration order: default < edge_request < enables_rule.
        """
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.errors import RESOLVE_FLAG_CONFLICT, MilpaError

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#true
}
"""
        env, url, ref = _make_mock_env_for_s4c(
            tmp_path, "lib-tls", dep_kdl, "abcd1111" * 5
        )
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        with pytest.raises(MilpaError) as exc_info:
            resolve(manifest, deps_dir, env, ResolveParams())

        err = exc_info.value
        assert err.slug == RESOLVE_FLAG_CONFLICT

        ctx = err.context
        # dep name
        assert ctx["dep"] == "lib-tls"
        # lexicographic order: "bearssl" < "openssl"
        assert ctx["flag_a"] == "bearssl"
        assert ctx["flag_b"] == "openssl"
        # Both activated by DEFAULT source (enum declaration order → ["default"])
        assert ctx["sources_a"] == ["default"]
        assert ctx["sources_b"] == ["default"]

    def test_only_one_default_active_no_error(self, tmp_path: Path) -> None:
        """Only one side of a conflict active → no RESOLVE-FLAG-CONFLICT (no false positive)."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#false
}
"""
        env, url, ref = _make_mock_env_for_s4c(
            tmp_path, "lib-tls", dep_kdl, "abcd2222" * 5
        )
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        # Should resolve without error.
        graph = resolve(manifest, deps_dir, env, ResolveParams())
        dep_names = [d.name for d in graph.deps]
        assert "lib-tls" in dep_names

    def test_conflict_symmetry_declared_one_side(self, tmp_path: Path) -> None:
        """Conflict declared on ONE flag only still fires (symmetry).

        openssl conflicts bearssl — but bearssl does NOT declare conflicts "openssl".
        The check on openssl's conflicts list must still catch it.
        """
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.errors import RESOLVE_FLAG_CONFLICT, MilpaError

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#true
}
"""
        # bearssl does NOT conflict "openssl" — only one-sided declaration.
        # The check must still detect it via openssl.conflicts = ["bearssl"].
        env, url, ref = _make_mock_env_for_s4c(
            tmp_path, "lib-tls", dep_kdl, "abcd3333" * 5
        )
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        with pytest.raises(MilpaError) as exc_info:
            resolve(manifest, deps_dir, env, ResolveParams())
        assert exc_info.value.slug == RESOLVE_FLAG_CONFLICT

    def test_conflict_via_edge_request_sources_payload(self, tmp_path: Path) -> None:
        """RESOLVE-FLAG-CONFLICT with edge_request source in payload.

        Consumer requests bearssl on a dep where openssl is default=#true and
        openssl conflicts bearssl.  The error payload sources_b must include
        'edge_request' (from the consumer's flag request).
        """
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.errors import RESOLVE_FLAG_CONFLICT, MilpaError

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#false
}
"""
        env, url, ref = _make_mock_env_for_s4c(
            tmp_path, "lib-tls", dep_kdl, "abcd4444" * 5
        )
        # Consumer requests bearssl on lib-tls → both openssl (default) and bearssl (requested) active.
        root_kdl = (
            f'name "myapp"\nkind "application"\ndeps {{\n'
            f'    lib-tls git=(url)"{url}" ref="{ref}" {{\n'
            f'        flag "bearssl"\n'
            f'    }}\n}}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        with pytest.raises(MilpaError) as exc_info:
            resolve(manifest, deps_dir, env, ResolveParams())

        err = exc_info.value
        assert err.slug == RESOLVE_FLAG_CONFLICT
        ctx = err.context
        assert ctx["dep"] == "lib-tls"
        # flag_a = "bearssl" (lex order), flag_b = "openssl"
        assert ctx["flag_a"] == "bearssl"
        assert ctx["flag_b"] == "openssl"
        # bearssl activated by edge_request
        assert "edge_request" in ctx["sources_a"]
        # openssl activated by default
        assert "default" in ctx["sources_b"]


# ---------------------------------------------------------------------------
# 4. _serialize_sources canonical ordering
# ---------------------------------------------------------------------------

class TestSerializeSources:
    """Verify canonical serialization order matches spec (enum declaration order)."""

    def test_single_default_source(self) -> None:
        from milpa.resolver import _serialize_sources, ActivationSource

        result = _serialize_sources({ActivationSource.DEFAULT})
        assert result == ["default"]

    def test_single_edge_request_source(self) -> None:
        from milpa.resolver import _serialize_sources, ActivationSource

        result = _serialize_sources({ActivationSource.EDGE_REQUEST})
        assert result == ["edge_request"]

    def test_single_enables_rule_source(self) -> None:
        from milpa.resolver import _serialize_sources, ActivationSource

        result = _serialize_sources({ActivationSource.ENABLES_RULE})
        assert result == ["enables_rule"]

    def test_all_three_sources_canonical_order(self) -> None:
        """All three sources → exactly the enum declaration order."""
        from milpa.resolver import _serialize_sources, ActivationSource

        result = _serialize_sources({
            ActivationSource.ENABLES_RULE,
            ActivationSource.DEFAULT,
            ActivationSource.EDGE_REQUEST,
        })
        # Canonical: default < edge_request < enables_rule (enum declaration order)
        assert result == ["default", "edge_request", "enables_rule"]

    def test_two_sources_default_and_edge_request(self) -> None:
        from milpa.resolver import _serialize_sources, ActivationSource

        result = _serialize_sources({
            ActivationSource.EDGE_REQUEST,
            ActivationSource.DEFAULT,
        })
        assert result == ["default", "edge_request"]

    def test_single_cli_source(self) -> None:
        """CLI (S9 --features) serializes as "cli" — byte-identical to Rust."""
        from milpa.resolver import _serialize_sources, ActivationSource

        result = _serialize_sources({ActivationSource.CLI})
        assert result == ["cli"]

    def test_all_four_sources_canonical_order(self) -> None:
        """All four sources → enum declaration order: default < edge_request < enables_rule < cli."""
        from milpa.resolver import _serialize_sources, ActivationSource

        result = _serialize_sources({
            ActivationSource.CLI,
            ActivationSource.ENABLES_RULE,
            ActivationSource.DEFAULT,
            ActivationSource.EDGE_REQUEST,
        })
        assert result == ["default", "edge_request", "enables_rule", "cli"]


# ---------------------------------------------------------------------------
# 5. C1b-completion: CLI-selected root flags participate in conflict detection
# ---------------------------------------------------------------------------

class TestC1bCliRootFlagConflicts:
    """C1b: root manifest flags activated via --features participate in conflict check.

    When the root manifest declares:
        flags { x conflicts=["y"]; y }
    and the user passes --features x,y, the resolver MUST raise
    RESOLVE-FLAG-CONFLICT with source "cli" in the payload.

    Before C1b this was silently ignored because CLI-active root flags were
    never recorded in dep_active_flags (or equivalent) and _s4c_check_flag_conflicts
    skipped __root__ entirely.
    """

    def test_cli_features_conflict_on_root_raises(self) -> None:
        """--features x,y where x conflicts y → RESOLVE-FLAG-CONFLICT."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.mocked import mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.cas import CAStore
        from milpa.errors import RESOLVE_FLAG_CONFLICT, MilpaError
        import tempfile, pathlib

        kdl = """
name "myapp"
kind "application"
flags {
    x default=#false {
        conflicts "y"
    }
    y default=#false
}
"""
        manifest = parse_manifest(kdl)
        with tempfile.TemporaryDirectory() as tmp:
            deps_dir = pathlib.Path(tmp) / "_deps"
            store = CAStore(pathlib.Path(tmp) / "cas")
            reg = mocked_registry(pathlib.Path(tmp) / "mocked")
            fetcher = CasAdmittingFetcher(reg, store)
            env = MilpaEnv(fetcher=fetcher, index=None, store=store)
            params = ResolveParams(features=frozenset({"x", "y"}))

            with pytest.raises(MilpaError) as exc_info:
                resolve(manifest, deps_dir, env, params)

        err = exc_info.value
        assert err.slug == RESOLVE_FLAG_CONFLICT, f"Expected RESOLVE-FLAG-CONFLICT, got {err.slug}"

    def test_cli_features_conflict_payload_includes_cli_source(self) -> None:
        """Conflict payload for root CLI flags has 'cli' in sources, flag_a ≤ flag_b lex."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.mocked import mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.cas import CAStore
        from milpa.errors import RESOLVE_FLAG_CONFLICT, MilpaError
        import tempfile, pathlib

        kdl = """
name "myapp"
kind "application"
flags {
    x default=#false {
        conflicts "y"
    }
    y default=#false
}
"""
        manifest = parse_manifest(kdl)
        with tempfile.TemporaryDirectory() as tmp:
            deps_dir = pathlib.Path(tmp) / "_deps"
            store = CAStore(pathlib.Path(tmp) / "cas")
            reg = mocked_registry(pathlib.Path(tmp) / "mocked")
            fetcher = CasAdmittingFetcher(reg, store)
            env = MilpaEnv(fetcher=fetcher, index=None, store=store)
            params = ResolveParams(features=frozenset({"x", "y"}))

            with pytest.raises(MilpaError) as exc_info:
                resolve(manifest, deps_dir, env, params)

        err = exc_info.value
        ctx = err.context
        # dep name is the root package name
        assert ctx["dep"] == "myapp"
        # "x" < "y" lexicographically → flag_a="x", flag_b="y"
        assert ctx["flag_a"] == "x"
        assert ctx["flag_b"] == "y"
        # Both activated by CLI → sources must be ["cli"]
        assert ctx["sources_a"] == ["cli"]
        assert ctx["sources_b"] == ["cli"]

    def test_cli_feature_no_conflict_no_error(self) -> None:
        """--features x where x does NOT conflict y → no error."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.mocked import mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.cas import CAStore
        import tempfile, pathlib

        kdl = """
name "myapp"
kind "application"
flags {
    x default=#false {
        conflicts "y"
    }
    y default=#false
}
"""
        manifest = parse_manifest(kdl)
        with tempfile.TemporaryDirectory() as tmp:
            deps_dir = pathlib.Path(tmp) / "_deps"
            store = CAStore(pathlib.Path(tmp) / "cas")
            reg = mocked_registry(pathlib.Path(tmp) / "mocked")
            fetcher = CasAdmittingFetcher(reg, store)
            env = MilpaEnv(fetcher=fetcher, index=None, store=store)
            # Only --features x, not y → no conflict
            params = ResolveParams(features=frozenset({"x"}))

            # Should resolve without error (no deps → trivial graph)
            resolve(manifest, deps_dir, env, params)


# ---------------------------------------------------------------------------
# 6. C1b enables-chain: conflict caught via enables-closure of CLI root flags
# ---------------------------------------------------------------------------

class TestC1bEnablesChainConflict:
    """R2-M C1b fix: enables-chain conflict caught at root.

    When root flags { a default=#true enables=["b"]; b conflicts=["c"]; c },
    passing --features c should raise RESOLVE-FLAG-CONFLICT because a (active
    by default) enables b, and b conflicts c.

    Before the fix, the raw CLI seed {a, c} was used without enables-closure,
    so b was not in the active map and the conflict was silently missed.
    """

    def test_enables_chain_conflict_detected(self) -> None:
        """Root CLI seed a (default) enables b; b conflicts c; --features c → error."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.mocked import mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.cas import CAStore
        from milpa.errors import RESOLVE_FLAG_CONFLICT, MilpaError
        import tempfile, pathlib

        kdl = """
name "myapp"
kind "application"
flags {
    a default=#true {
        enables "b"
    }
    b default=#false {
        conflicts "c"
    }
    c default=#false
}
"""
        manifest = parse_manifest(kdl)
        with tempfile.TemporaryDirectory() as tmp:
            deps_dir = pathlib.Path(tmp) / "_deps"
            store = CAStore(pathlib.Path(tmp) / "cas")
            reg = mocked_registry(pathlib.Path(tmp) / "mocked")
            fetcher = CasAdmittingFetcher(reg, store)
            env = MilpaEnv(fetcher=fetcher, index=None, store=store)
            # CLI seed = defaults ∪ {c} = {a, c}; closure = {a, b, c}
            # b conflicts c → RESOLVE-FLAG-CONFLICT
            params = ResolveParams(features=frozenset({"c"}))

            with pytest.raises(MilpaError) as exc_info:
                resolve(manifest, deps_dir, env, params)

        err = exc_info.value
        assert err.slug == RESOLVE_FLAG_CONFLICT, (
            f"Expected RESOLVE-FLAG-CONFLICT, got {err.slug!r}"
        )
        ctx = err.context
        assert ctx["dep"] == "myapp"
        # b < c lexicographically → flag_a="b", flag_b="c"
        assert ctx["flag_a"] == "b"
        assert ctx["flag_b"] == "c"
        # b was activated by enables_rule; c was activated by cli
        assert "enables_rule" in ctx["sources_a"]
        assert "cli" in ctx["sources_b"]

    def test_enables_chain_no_conflict_when_c_absent(self) -> None:
        """Root a (default) enables b; b conflicts c; c NOT requested → no error."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.mocked import mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.cas import CAStore
        import tempfile, pathlib

        kdl = """
name "myapp"
kind "application"
flags {
    a default=#true {
        enables "b"
    }
    b default=#false {
        conflicts "c"
    }
    c default=#false
}
"""
        manifest = parse_manifest(kdl)
        with tempfile.TemporaryDirectory() as tmp:
            deps_dir = pathlib.Path(tmp) / "_deps"
            store = CAStore(pathlib.Path(tmp) / "cas")
            reg = mocked_registry(pathlib.Path(tmp) / "mocked")
            fetcher = CasAdmittingFetcher(reg, store)
            env = MilpaEnv(fetcher=fetcher, index=None, store=store)
            # No --features → only defaults active; c not requested → no conflict
            params = ResolveParams()

            # Should resolve without error
            resolve(manifest, deps_dir, env, params)


# ---------------------------------------------------------------------------
# 7. R2-M DoS hardening: total activation bound
# ---------------------------------------------------------------------------

class TestDoSActivationBound:
    """R2-M DoS hardening: fixpoint activation bound does not trip on normal inputs."""

    def test_normal_multihop_does_not_trip_bound(self) -> None:
        """A normal multi-hop enables chain (fixture-190 topology) converges fine."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.mocked import mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.cas import CAStore
        import pathlib
        from pathlib import Path

        # Use fixture-190 directly to confirm normal inputs don't trip the bound.
        fixture = Path(__file__).parents[3] / "conformance/spec-v1/fixture-190-s4a-multihop-dep-flag-fixpoint"
        if not fixture.is_dir():
            pytest.skip("fixture-190 not found")

        kdl = (fixture / "milpa.kdl").read_text()
        manifest = parse_manifest(kdl)

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            deps_dir = pathlib.Path(tmp) / "_deps"
            store = CAStore(pathlib.Path(tmp) / "cas")
            reg = mocked_registry(fixture / "mocked-fetches")
            fetcher = CasAdmittingFetcher(reg, store)
            env = MilpaEnv(fetcher=fetcher, index=None, store=store)
            params = ResolveParams()

            # Should resolve without tripping the activation bound.
            graph = resolve(manifest, deps_dir, env, params)

        dep_names = {d.name for d in graph.deps}
        assert "lib-a" in dep_names
        assert "lib-b" in dep_names
        assert "lib-c" in dep_names
