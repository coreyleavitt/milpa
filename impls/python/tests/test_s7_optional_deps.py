"""S7 (RFC #23 §3.2 + §7 Stage B): parse-time optional dep desugaring.

Coverage:
  1. optional=#true on UrlDep: parse succeeds, auto-flag injected, gate predicate injected.
  2. optional=#true on NamedDep: same desugar.
  3. optional=#false is a no-op (no flag injected, no predicate injected).
  4. MAN-DEP-OPTIONAL-INVALID-NAME: dep name violates flag charset.
  5. MAN-DEP-OPTIONAL-FLAG-CLASH: optional dep name collides with already-declared flag.
  6. MAN-DEP-OPTIONAL-FLAG-CLASH: non-optional dep name collides with declared flag (hygiene).
  7. Duplicate explicit gate predicate is collapsed (idempotent, NOT an error).
  8. Round-trip: format_manifest preserves optional=#true and does not serialize the
     auto-injected gate predicate (desugaring is internal).
  9. Pruning: resolver with disabled optional dep resolves empty graph (not fetched).
  10. Activation: resolver with enabled optional dep resolves the dep (present).
  11. dev-deps: optional=#true on a dev-dep behaves identically.
"""

from __future__ import annotations

import pytest
from pathlib import Path


# ---------------------------------------------------------------------------
# Unit-level parse tests
# ---------------------------------------------------------------------------


class TestOptionalUrlDepBasic:
    """Parse-time desugaring for UrlDep with optional=#true."""

    def _parse(self, text: str):
        from milpa.manifest import parse_manifest
        return parse_manifest(text)

    def test_optional_url_dep_injects_flag(self):
        """Auto-flag is injected into manifest.flags after desugar."""
        m = self._parse(
            'name "mylib"\n'
            'deps {\n'
            '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        flag_names = {f.name for f in m.flags}
        assert "myopt" in flag_names, "auto-flag 'myopt' should be in manifest.flags"

    def test_optional_url_dep_auto_flag_default_false(self):
        """Auto-flag has default=#false (dep absent by default)."""
        m = self._parse(
            'name "mylib"\n'
            'deps {\n'
            '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        auto_flag = next(f for f in m.flags if f.name == "myopt")
        assert auto_flag.default is False

    def test_optional_url_dep_injects_gate_predicate(self):
        """Gate predicate flag="myopt" is injected into the dep's predicates."""
        from milpa.predicate import Predicate
        m = self._parse(
            'name "mylib"\n'
            'deps {\n'
            '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        dep = m.deps[0]
        assert dep.name == "myopt"
        gate = Predicate(name="flag", values=("myopt",), negated=False)
        assert gate in dep.predicates, f"gate predicate missing; got {dep.predicates}"

    def test_optional_url_dep_optional_field_preserved(self):
        """dep.optional=True is preserved on the dataclass for round-trip."""
        m = self._parse(
            'name "mylib"\n'
            'deps {\n'
            '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        assert m.deps[0].optional is True

    def test_optional_false_is_noop(self):
        """optional=#false (default) injects nothing."""
        m = self._parse(
            'name "mylib"\n'
            'deps {\n'
            '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#false\n'
            '}\n'
            'kind "library"\n'
        )
        assert m.flags == ()
        assert m.deps[0].predicates == ()
        assert m.deps[0].optional is False


class TestOptionalNamedDepBasic:
    """Parse-time desugaring for NamedDep with optional=#true."""

    def _parse(self, text: str):
        from milpa.manifest import parse_manifest
        return parse_manifest(text)

    def test_optional_named_dep_injects_flag(self):
        """Auto-flag is injected into manifest.flags for optional NamedDep."""
        m = self._parse(
            'name "mylib"\n'
            'deps {\n'
            '    mynamed optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        flag_names = {f.name for f in m.flags}
        assert "mynamed" in flag_names

    def test_optional_named_dep_gate_predicate(self):
        """Gate predicate is injected into NamedDep.predicates."""
        from milpa.predicate import Predicate
        m = self._parse(
            'name "mylib"\n'
            'deps {\n'
            '    mynamed optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        dep = m.deps[0]
        gate = Predicate(name="flag", values=("mynamed",), negated=False)
        assert gate in dep.predicates


class TestOptionalErrors:
    """Error cases for invalid optional dep configurations."""

    def _parse(self, text: str):
        from milpa.manifest import parse_manifest
        return parse_manifest(text)

    def test_invalid_name_charset_raises(self):
        """MAN-DEP-NAME-INVALID for dep name with illegal chars (R2-C1 fix).

        Previously MAN-DEP-OPTIONAL-INVALID-NAME from the desugar pass;
        now MAN-DEP-NAME-INVALID at the parse boundary — validation runs
        for all dep names (optional or not) before optional desugaring.
        """
        from milpa.errors import MAN_DEP_NAME_INVALID
        from milpa.errors import MilpaError
        # Dep names with spaces or special chars violate [A-Za-z0-9_-]+
        # However, KDL identifiers are validated by the parser so we test
        # a name that KDL permits but the dep-name charset rejects.
        # KDL allows any bare identifier; the dep-name charset is stricter.
        # Use a quoted node name with a dot (valid KDL, invalid dep name).
        with pytest.raises(MilpaError) as exc_info:
            self._parse(
                'name "mylib"\n'
                'deps {\n'
                '    "my.opt" git=(url)"https://example.com/x.git" ref="main" optional=#true\n'
                '}\n'
                'kind "library"\n'
            )
        assert exc_info.value.slug == MAN_DEP_NAME_INVALID

    def test_flag_clash_optional_dep_raises(self):
        """MAN-DEP-OPTIONAL-FLAG-CLASH when optional dep name = declared flag."""
        from milpa.errors import MAN_DEP_OPTIONAL_FLAG_CLASH
        from milpa.errors import MilpaError
        with pytest.raises(MilpaError) as exc_info:
            self._parse(
                'name "mylib"\n'
                'flags {\n'
                '    myopt default=#false\n'
                '}\n'
                'deps {\n'
                '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#true\n'
                '}\n'
                'kind "library"\n'
            )
        assert exc_info.value.slug == MAN_DEP_OPTIONAL_FLAG_CLASH

    def test_flag_clash_non_optional_dep_raises(self):
        """MAN-DEP-OPTIONAL-FLAG-CLASH for non-optional dep sharing a flag name (hygiene)."""
        from milpa.errors import MAN_DEP_OPTIONAL_FLAG_CLASH
        from milpa.errors import MilpaError
        with pytest.raises(MilpaError) as exc_info:
            self._parse(
                'name "mylib"\n'
                'flags {\n'
                '    myopt default=#false\n'
                '}\n'
                'deps {\n'
                '    myopt git=(url)"https://example.com/myopt.git" ref="main"\n'
                '}\n'
                'kind "library"\n'
            )
        assert exc_info.value.slug == MAN_DEP_OPTIONAL_FLAG_CLASH


class TestOptionalDuplicateGateIdempotent:
    """Explicit flag=<depname> gate is collapsed (not an error)."""

    def test_explicit_gate_not_duplicated(self):
        """If the dep explicitly carries flag="myopt", it's not added twice."""
        from milpa.predicate import Predicate
        from milpa.manifest import parse_manifest
        m = parse_manifest(
            'name "mylib"\n'
            'deps {\n'
            '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#true {\n'
            '        flag "myopt"\n'
            '    }\n'
            '}\n'
            'kind "library"\n'
        )
        dep = m.deps[0]
        gate = Predicate(name="flag", values=("myopt",), negated=False)
        gate_count = sum(1 for p in dep.predicates if p == gate)
        assert gate_count == 1, f"gate predicate should appear exactly once; got predicates={dep.predicates}"


class TestOptionalRoundTrip:
    """format_manifest preserves optional=#true and does NOT serialize the auto-gate."""

    def test_url_dep_round_trip(self):
        """optional=#true round-trips; auto-gate predicate is not double-emitted."""
        from milpa.manifest import parse_manifest, format_manifest
        src = (
            '// generated by milpa; edit by hand or via `milpa add` / `milpa remove`\n\n'
            'name "mylib"\n\n'
            'deps {\n'
            '    "myopt" git=(url)"https://example.com/myopt.git" ref="main" optional=#true\n'
            '}\n\n'
            'kind "library"\n'
        )
        m = parse_manifest(src)
        out = format_manifest(m)
        # optional=#true must appear in the output
        assert "optional=#true" in out
        # The auto-gate predicate flag="myopt" must NOT appear as an explicit child
        # (it's implied by optional=#true)
        # The format should NOT have 'flag "myopt"' inside the dep block
        # since that would double-declare the gate.
        lines = out.splitlines()
        dep_block_lines = []
        in_dep = False
        for line in lines:
            if '"myopt"' in line and 'git=' in line:
                in_dep = True
            if in_dep:
                dep_block_lines.append(line)
                if line.strip() == "}":
                    break
        assert not any('flag "myopt"' in l for l in dep_block_lines), (
            f"auto-gate 'flag \"myopt\"' should not appear explicitly in formatted output;\n"
            f"dep block: {dep_block_lines}"
        )

    def test_format_then_reparse_is_stable(self):
        """format_manifest + parse_manifest produces the same Manifest."""
        from milpa.manifest import parse_manifest, format_manifest
        from milpa.predicate import Predicate
        src = (
            'name "mylib"\n'
            'deps {\n'
            '    myopt git=(url)"https://example.com/myopt.git" ref="main" optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        m1 = parse_manifest(src)
        out = format_manifest(m1)
        m2 = parse_manifest(out)

        # Both have optional dep with auto-flag
        assert {f.name for f in m1.flags} == {f.name for f in m2.flags}
        assert m1.deps[0].optional == m2.deps[0].optional
        # Both have the gate predicate
        gate = Predicate(name="flag", values=("myopt",), negated=False)
        assert gate in m1.deps[0].predicates
        assert gate in m2.deps[0].predicates


class TestOptionalDevDeps:
    """optional=#true on dev-deps behaves identically (RFC #23 §3.2)."""

    def test_dev_dep_optional_desugar(self):
        """optional=#true on a dev-dep injects auto-flag and gate predicate."""
        from milpa.manifest import parse_manifest
        from milpa.predicate import Predicate
        m = parse_manifest(
            'name "mylib"\n'
            'dev-deps {\n'
            '    devopt git=(url)"https://example.com/devopt.git" ref="main" optional=#true\n'
            '}\n'
            'kind "library"\n'
        )
        assert any(f.name == "devopt" for f in m.flags)
        dep = m.dev_deps[0]
        gate = Predicate(name="flag", values=("devopt",), negated=False)
        assert gate in dep.predicates


class TestOptionalResolverPruning:
    """Resolver-level: disabled optional dep is not fetched (pruned)."""

    def _build_mock_env(self, tmp_path: Path, extra_deps: dict[str, str] = None):
        """Build a MilpaEnv with optlib mocked."""
        from milpa.fetchers.mocked import url_key, mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.cas import CAStore
        from milpa.context import MilpaEnv

        optlib_kdl = 'name "optlib"\nkind "library"\n'

        mocked_dir = tmp_path / "mocked-fetches"
        key = url_key("https://example.com/optlib.git", "main")
        d = mocked_dir / key
        (d / "content").mkdir(parents=True)
        (d / "content" / "milpa.kdl").write_text(optlib_kdl, encoding="utf-8")
        (d / "sha").write_text("a" * 40, encoding="utf-8")

        store = CAStore(tmp_path / "cas")
        reg = mocked_registry(mocked_dir)
        fetcher = CasAdmittingFetcher(reg, store)
        return MilpaEnv(fetcher=fetcher, index=None, store=store)

    def test_optional_dep_absent_by_default(self, tmp_path: Path):
        """With the auto-flag default=#false, the optional dep is pruned."""
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.resolver import resolve

        root_manifest = parse_manifest(
            'name "myapp"\n'
            'kind "application"\n'
            'deps {\n'
            '    optlib git=(url)"https://example.com/optlib.git" ref="main" optional=#true\n'
            '}\n'
        )

        env = self._build_mock_env(tmp_path)
        deps_dir = tmp_path / "_deps"
        # Profile.from_environment() with empty flags — the auto-flag 'optlib'
        # has default=#false so it won't be in the active set.
        from milpa.profile import Profile
        params = ResolveParams(profile=Profile.from_environment())

        graph = resolve(root_manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}
        assert "optlib" not in dep_names, (
            f"optional dep with default=#false should be pruned; got {dep_names}"
        )

    def test_optional_dep_present_when_flag_enabled_by_default(self, tmp_path: Path):
        """An optional dep is present when a default=#true flag enables it.

        Uses `enables` from a default-true flag to activate the auto-flag
        through the S4a fixpoint loop.  The `optlib` auto-flag is default=#false
        but `use-network default=#true` enables it via `enables "optlib"`.
        """
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.resolver import resolve

        # 'use-network' default=#true enables 'optlib' (the auto-flag from desugar).
        # The S4a fixpoint computes active_flags for root = {use-network, optlib}.
        # Then the root dep 'optlib' with flag="optlib" predicate is admitted.
        root_manifest = parse_manifest(
            'name "myapp"\n'
            'kind "application"\n'
            'flags {\n'
            '    use-network default=#true {\n'
            '        enables "optlib"\n'
            '    }\n'
            '}\n'
            'deps {\n'
            '    optlib git=(url)"https://example.com/optlib.git" ref="main" optional=#true\n'
            '}\n'
        )

        env = self._build_mock_env(tmp_path)
        deps_dir = tmp_path / "_deps"
        from milpa.profile import Profile
        from milpa.context import ResolveParams
        params = ResolveParams(profile=Profile.from_environment())

        graph = resolve(root_manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}
        assert "optlib" in dep_names, (
            f"optional dep enabled by default-true flag should be present; got {dep_names}"
        )
