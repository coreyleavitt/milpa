"""S9 (RFC #23 §3.4): CLI feature-selection flags.

Anti-hollow: every test that exercises resolution MUST flow through the real
argparse layer (``main(argv)``) or the real ``cmd_fetch``/``cmd_lock``
signature — NOT through the conformance harness shortcut.

Coverage:
  1. ``--features x``: flag-gated dep admitted when real CLI arg is parsed.
  2. ``--no-default-features``: default-true flag suppressed; gated dep pruned.
  3. ``--all-features``: all root flags active; all gated deps admitted.
  4. ``_parse_features``: comma-separated parsing edge cases.
  5. Unknown feature name → FROZEN-ACTIVE-FLAGS-MISMATCH (validation in
     ``_compute_root_active_seed``).
  6. FROZEN-ACTIVE-FLAGS-MISMATCH: frozen + CLI features clash with lockfile.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Repo-root → shared conformance corpus
_REPO_ROOT = Path(__file__).parents[3]
_FX209 = _REPO_ROOT / "conformance/spec-v1/fixture-209-s9-features-flag"
_FX210 = _REPO_ROOT / "conformance/spec-v1/fixture-210-s9-no-default-features"
_FX211 = _REPO_ROOT / "conformance/spec-v1/fixture-211-s9-all-features"
_FX212 = _REPO_ROOT / "conformance/spec-v1/fixture-212-s9-frozen-active-flags-mismatch"


# ---------------------------------------------------------------------------
# _parse_features unit tests (pure)
# ---------------------------------------------------------------------------


class TestParseFeatures:
    """Unit tests for the ``_parse_features`` helper (no I/O)."""

    def _parse(self, raw: str) -> frozenset[str]:
        from milpa.cli import _parse_features
        return _parse_features(raw)

    def test_single_feature(self):
        assert self._parse("tls") == frozenset({"tls"})

    def test_comma_separated(self):
        assert self._parse("tls,debug") == frozenset({"tls", "debug"})

    def test_whitespace_trimmed(self):
        assert self._parse(" tls , debug ") == frozenset({"tls", "debug"})

    def test_empty_string(self):
        assert self._parse("") == frozenset()

    def test_trailing_comma(self):
        # trailing comma produces no phantom empty entry
        result = self._parse("tls,")
        assert result == frozenset({"tls"})

    def test_deduplicated(self):
        assert self._parse("tls,tls") == frozenset({"tls"})


# ---------------------------------------------------------------------------
# _compute_root_active_seed unit tests (pure)
# ---------------------------------------------------------------------------


class TestComputeRootActiveSeed:
    """Unit tests for ``_compute_root_active_seed`` in resolver.py."""

    def _manifest_with_flags(self, *flag_specs: tuple[str, bool]) -> object:
        """Build a minimal manifest with the given (name, default) flag pairs."""
        from milpa.manifest import parse_manifest

        flags_block = "\n".join(
            f'    {name} default=#{str(default).lower()}'
            for name, default in flag_specs
        )
        return parse_manifest(
            f'name "myapp"\nkind "application"\nflags {{\n{flags_block}\n}}\n'
        )

    def test_default_seed_includes_default_true_flags(self):
        from milpa.resolver import _compute_root_active_seed

        m = self._manifest_with_flags(("tls", False), ("debug", True))
        seed = _compute_root_active_seed(m, frozenset(), False, False)
        assert "debug" in seed
        assert "tls" not in seed

    def test_features_adds_to_defaults(self):
        from milpa.resolver import _compute_root_active_seed

        m = self._manifest_with_flags(("tls", False), ("debug", True))
        seed = _compute_root_active_seed(m, frozenset({"tls"}), False, False)
        assert "tls" in seed
        assert "debug" in seed

    def test_no_default_features_suppresses_defaults(self):
        from milpa.resolver import _compute_root_active_seed

        m = self._manifest_with_flags(("tls", False), ("debug", True))
        seed = _compute_root_active_seed(m, frozenset(), True, False)
        assert "debug" not in seed
        assert "tls" not in seed

    def test_no_default_features_with_explicit_features(self):
        from milpa.resolver import _compute_root_active_seed

        m = self._manifest_with_flags(("tls", False), ("debug", True))
        seed = _compute_root_active_seed(m, frozenset({"tls"}), True, False)
        assert "tls" in seed
        assert "debug" not in seed

    def test_all_features_activates_everything(self):
        from milpa.resolver import _compute_root_active_seed

        m = self._manifest_with_flags(("tls", False), ("debug", False))
        seed = _compute_root_active_seed(m, frozenset(), False, True)
        assert "tls" in seed
        assert "debug" in seed

    def test_unknown_feature_raises_mismatch(self):
        from milpa.resolver import _compute_root_active_seed
        from milpa.errors import MilpaError, FROZEN_ACTIVE_FLAGS_MISMATCH

        m = self._manifest_with_flags(("tls", False),)
        with pytest.raises(MilpaError) as exc_info:
            _compute_root_active_seed(m, frozenset({"nonexistent"}), False, False)
        assert exc_info.value.slug == FROZEN_ACTIVE_FLAGS_MISMATCH


# ---------------------------------------------------------------------------
# Anti-hollow: real CLI arg → ResolveParams → resolution
# ---------------------------------------------------------------------------
# These tests call ``main(argv)`` directly with MILPA_MOCKED_FETCHES set,
# exercising the full argparse → _parse_features → ResolveParams → resolve
# path without any harness shortcuts.
# ---------------------------------------------------------------------------


def _run_main(argv: list[str], mocked_fetches_dir: Path, project_dir: Path) -> int:
    """Call ``main(argv)`` with MILPA_MOCKED_FETCHES set to mocked_fetches_dir.

    Returns the exit code. The CAS is placed inside project_dir to avoid
    polluting the real store.
    """
    from milpa.cli import main

    old_env = os.environ.copy()
    try:
        os.environ["MILPA_MOCKED_FETCHES"] = str(mocked_fetches_dir)
        os.environ["MILPA_CACHE_DIR"] = str(project_dir / ".milpa-cache")
        # Suppress index to avoid network calls.
        return main(argv)
    finally:
        os.environ.clear()
        os.environ.update(old_env)


class TestCliFeaturesFlagEndToEnd:
    """Anti-hollow: verify real argparse → ResolveParams → resolution path."""

    def test_features_flag_admits_gated_dep(self, tmp_path: Path):
        """``--features tls`` admits featurelib (gated by when flag="tls")."""
        import shutil
        from milpa.lockfile import load_lockfile

        # Set up a temp project dir from fixture-209.
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        shutil.copy(_FX209 / "milpa.kdl", project_dir / "milpa.kdl")

        rc = _run_main(
            ["-C", str(project_dir), "fetch", "--features", "tls"],
            _FX209 / "mocked-fetches",
            project_dir,
        )
        assert rc == 0, f"milpa fetch --features tls exited {rc}"

        lock = load_lockfile(project_dir / "milpa.lock")
        dep_names = {d.name for d in lock.deps}
        assert "featurelib" in dep_names, (
            f"--features tls should admit featurelib; got {dep_names}"
        )

    def test_features_absent_prunes_gated_dep(self, tmp_path: Path):
        """Without ``--features tls``, featurelib (tls default=#false) is pruned."""
        import shutil
        from milpa.lockfile import load_lockfile

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        shutil.copy(_FX209 / "milpa.kdl", project_dir / "milpa.kdl")

        rc = _run_main(
            ["-C", str(project_dir), "fetch"],
            _FX209 / "mocked-fetches",
            project_dir,
        )
        assert rc == 0, f"milpa fetch exited {rc}"

        lock = load_lockfile(project_dir / "milpa.lock")
        dep_names = {d.name for d in lock.deps}
        assert "featurelib" not in dep_names, (
            f"featurelib should be pruned without --features tls; got {dep_names}"
        )

    def test_no_default_features_prunes_default_true_gated_dep(self, tmp_path: Path):
        """``--no-default-features`` suppresses default-true flag; gated dep pruned."""
        import shutil
        from milpa.lockfile import load_lockfile

        # fixture-210: tls default=#true; tlslib gated by tls.
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        shutil.copy(_FX210 / "milpa.kdl", project_dir / "milpa.kdl")

        # No mocked-fetches needed (no deps fetched when pruned).
        rc = _run_main(
            ["-C", str(project_dir), "fetch", "--no-default-features"],
            tmp_path / "empty-mocked",  # empty — no fetches should occur
            project_dir,
        )
        assert rc == 0, f"milpa fetch --no-default-features exited {rc}"

        lock = load_lockfile(project_dir / "milpa.lock")
        dep_names = {d.name for d in lock.deps}
        assert "tlslib" not in dep_names, (
            f"--no-default-features should prune tlslib; got {dep_names}"
        )

    def test_all_features_admits_all_gated_deps(self, tmp_path: Path):
        """``--all-features`` activates all root flags; all gated deps admitted."""
        import shutil
        from milpa.lockfile import load_lockfile

        # fixture-211: tls + debug both default=#false; tlslib + debuglib gated.
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        shutil.copy(_FX211 / "milpa.kdl", project_dir / "milpa.kdl")

        rc = _run_main(
            ["-C", str(project_dir), "fetch", "--all-features"],
            _FX211 / "mocked-fetches",
            project_dir,
        )
        assert rc == 0, f"milpa fetch --all-features exited {rc}"

        lock = load_lockfile(project_dir / "milpa.lock")
        dep_names = {d.name for d in lock.deps}
        assert "tlslib" in dep_names, (
            f"--all-features should admit tlslib; got {dep_names}"
        )
        assert "debuglib" in dep_names, (
            f"--all-features should admit debuglib; got {dep_names}"
        )


# ---------------------------------------------------------------------------
# FROZEN-ACTIVE-FLAGS-MISMATCH via cmd_fetch frozen path
# ---------------------------------------------------------------------------


class TestFrozenActiveFlagesMismatch:
    """``--frozen`` with mismatched feature selection exits with the right slug."""

    def test_frozen_features_mismatch_via_main(self, tmp_path: Path):
        """``milpa --frozen --features tls`` when lock lacks featurelib → exit 1."""
        import shutil

        # fixture-212: manifest has tls flag + featurelib, lock is empty (tls off)
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        shutil.copy(_FX212 / "milpa.kdl", project_dir / "milpa.kdl")
        shutil.copy(_FX212 / "milpa.lock", project_dir / "milpa.lock")

        # Call main() with --frozen --features tls. The CLI catches the
        # MilpaError and emits the slug on stderr, returning exit code 1.
        rc = _run_main(
            ["-C", str(project_dir), "--frozen", "fetch", "--features", "tls"],
            tmp_path / "empty-mocked",
            project_dir,
        )
        assert rc == 1, f"expected exit 1 for frozen mismatch, got {rc}"

    def test_frozen_features_mismatch_check_function(self, tmp_path: Path):
        """``_check_frozen_active_flags_mismatch`` raises FROZEN-ACTIVE-FLAGS-MISMATCH directly."""
        import shutil
        from milpa.errors import MilpaError, FROZEN_ACTIVE_FLAGS_MISMATCH
        from milpa.manifest import parse_manifest
        from milpa.lockfile import parse_lockfile
        from milpa.cli import _check_frozen_active_flags_mismatch

        # Manifest with tls flag + gated dep; empty lock (dep absent).
        manifest = parse_manifest(
            'name "myapp"\nkind "application"\n'
            'flags {\n    tls default=#false\n}\n'
            'deps {\n'
            '    when flag="tls" {\n'
            '        featurelib git=(url)"https://example.com/featurelib.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        lockfile = parse_lockfile(
            "// generated by milpa; reproducible build snapshot\n"
            "version 1\n"
            'strategy "maxver"\n'
        )

        with pytest.raises(MilpaError) as exc_info:
            _check_frozen_active_flags_mismatch(
                manifest, lockfile,
                features=frozenset({"tls"}),
                no_default_features=False,
                all_features=False,
            )
        assert exc_info.value.slug == FROZEN_ACTIVE_FLAGS_MISMATCH


# ---------------------------------------------------------------------------
# M4: --all-features + --no-default-features conflict (spec/errors.md §CLI)
# ---------------------------------------------------------------------------


class TestFeatureFlagsConflict:
    """M4: ``--all-features`` + ``--no-default-features`` together → CLI-FEATURE-FLAGS-CONFLICT.

    The two flags are mutually exclusive: --all-features activates every declared
    root flag; --no-default-features suppresses all defaults and starts from an
    empty baseline.  Passing both is a usage error (analogous to Cargo's policy).

    Each test goes through ``main(argv)`` (anti-hollow: real argparse layer) so
    the check at the dispatch site in main() is exercised, not just the helper.
    """

    def _minimal_project(self, tmp_path: Path) -> Path:
        """Create a minimal project dir with a trivial milpa.kdl."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text(
            'name "myapp"\nkind "application"\n', encoding="utf-8"
        )
        return project_dir

    def test_fetch_all_features_and_no_default_features_rejected(self, tmp_path: Path):
        """``fetch --all-features --no-default-features`` → exit 1 + CLI-FEATURE-FLAGS-CONFLICT."""
        import io
        from unittest.mock import patch

        project_dir = self._minimal_project(tmp_path)

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            rc = _run_main(
                ["-C", str(project_dir), "fetch",
                 "--all-features", "--no-default-features"],
                tmp_path / "empty-mocked",
                project_dir,
            )

        assert rc == 1, (
            f"expected exit 1 for --all-features + --no-default-features, got {rc}"
        )
        stderr_output = stderr_buf.getvalue()
        assert "CLI-FEATURE-FLAGS-CONFLICT" in stderr_output, (
            f"expected CLI-FEATURE-FLAGS-CONFLICT in stderr; got: {stderr_output!r}"
        )

    def test_lock_all_features_and_no_default_features_rejected(self, tmp_path: Path):
        """``lock --all-features --no-default-features`` → exit 1 + CLI-FEATURE-FLAGS-CONFLICT."""
        import io
        from unittest.mock import patch

        project_dir = self._minimal_project(tmp_path)

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            rc = _run_main(
                ["-C", str(project_dir), "lock",
                 "--all-features", "--no-default-features"],
                tmp_path / "empty-mocked",
                project_dir,
            )

        assert rc == 1, (
            f"expected exit 1 for lock --all-features + --no-default-features, got {rc}"
        )
        stderr_output = stderr_buf.getvalue()
        assert "CLI-FEATURE-FLAGS-CONFLICT" in stderr_output, (
            f"expected CLI-FEATURE-FLAGS-CONFLICT in stderr; got: {stderr_output!r}"
        )

    def test_update_all_features_and_no_default_features_rejected(self, tmp_path: Path):
        """``update --all-features --no-default-features`` → exit 1 + CLI-FEATURE-FLAGS-CONFLICT."""
        import io
        from unittest.mock import patch

        project_dir = self._minimal_project(tmp_path)
        # update needs a lockfile to proceed; write a minimal one.
        (project_dir / "milpa.lock").write_text(
            '// generated by milpa; reproducible build snapshot\nversion 1\nstrategy "maxver"\n',
            encoding="utf-8",
        )

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            rc = _run_main(
                ["-C", str(project_dir), "update",
                 "--all-features", "--no-default-features"],
                tmp_path / "empty-mocked",
                project_dir,
            )

        assert rc == 1, (
            f"expected exit 1 for update --all-features + --no-default-features, got {rc}"
        )
        stderr_output = stderr_buf.getvalue()
        assert "CLI-FEATURE-FLAGS-CONFLICT" in stderr_output, (
            f"expected CLI-FEATURE-FLAGS-CONFLICT in stderr; got: {stderr_output!r}"
        )

    def test_all_features_alone_still_accepted(self, tmp_path: Path):
        """``fetch --all-features`` alone (without --no-default-features) is NOT rejected.

        This is a negative test: the flag is valid on its own.  With no deps in
        milpa.kdl, resolve exits 0 immediately.
        """
        project_dir = self._minimal_project(tmp_path)

        rc = _run_main(
            ["-C", str(project_dir), "fetch", "--all-features"],
            tmp_path / "empty-mocked",
            project_dir,
        )
        assert rc == 0, f"expected exit 0 for --all-features alone, got {rc}"

    def test_no_default_features_alone_still_accepted(self, tmp_path: Path):
        """``fetch --no-default-features`` alone (without --all-features) is NOT rejected."""
        project_dir = self._minimal_project(tmp_path)

        rc = _run_main(
            ["-C", str(project_dir), "fetch", "--no-default-features"],
            tmp_path / "empty-mocked",
            project_dir,
        )
        assert rc == 0, f"expected exit 0 for --no-default-features alone, got {rc}"
