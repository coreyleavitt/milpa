"""D2 (resolution-semantics RFC §3 Axis D) — ``--exclude-newer <ts>`` CLI
sentinel + fetch/lock-only scoping + manifest ``resolution { exclude-newer }``
precedence, exercised through the REAL argparse layer (``main(argv)``), not
the conformance harness shortcut.

Mirrors ``test_c3_strategy_cli.py``'s infra (mocked git fetch, no index, no
network). D2 itself does not build any index-filter/git-validation behavior
(D3/D4) — these tests only prove:

1. ``--exclude-newer`` is scoped to fetch/lock ONLY (narrower than
   ``--strategy``'s per-verb scoping) — ``add``/``update``/``remove`` reject
   it as a parse error (exit 2).
2. A malformed ``--exclude-newer`` value raises ``CLI-EXCLUDE-NEWER-INVALID``
   (exit 1 + slug), distinct from the manifest's own
   ``MAN-RESOLUTION-EXCLUDE-NEWER-INVALID``.
3. The precedence-resolution helper (``_resolve_effective_exclude_newer``)
   is correct in isolation: CLI > manifest > None.
4. Threaded end-to-end: a real ``fetch`` invocation with an effective
   exclude-newer set (CLI or manifest) still resolves successfully (the
   value is inert today — D3/D4 will make it load-bearing).
"""

from __future__ import annotations

import contextlib
import io
import os
from datetime import datetime, timezone
from pathlib import Path

from milpa.fetchers.mocked import url_key
from milpa.lockfile import load_lockfile
from milpa.resolver import _resolve_effective_exclude_newer

_UNSAFE_NO_INDEX_ENV = {"MILPA_INDEX_URL": ""}


def _make_git_mock(mocked_dir: Path, url: str, ref: str, *, sha: str, marker: str) -> None:
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / "foo.nim").write_text(f"# foo {marker}\n", encoding="utf-8")
    (d / "foo.nimble").write_text(
        '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n', encoding="utf-8"
    )
    (d / "sha").write_text(sha, encoding="utf-8")


def _run_main(argv: list[str], mocked_fetches_dir: Path, project_dir: Path) -> tuple[int, str, str]:
    from milpa.cli import main

    old_env = os.environ.copy()
    try:
        os.environ["MILPA_MOCKED_FETCHES"] = str(mocked_fetches_dir)
        os.environ["MILPA_CACHE_DIR"] = str(project_dir / ".milpa-cache")
        os.environ.update(_UNSAFE_NO_INDEX_ENV)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _manifest_kdl(*, resolution_block: str = "") -> str:
    return (
        'name "myapp"\nkind "application"\n'
        f"{resolution_block}"
        "deps {\n"
        '    foo git=(url)"https://example.com/foo.git" ref="v1.0.0"\n'
        "}\n"
    )


def _setup_project(tmp_path: Path, *, resolution_block: str = "") -> tuple[Path, Path]:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "milpa.kdl").write_text(
        _manifest_kdl(resolution_block=resolution_block), encoding="utf-8"
    )
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    _make_git_mock(
        mocked_dir, "https://example.com/foo.git", "v1.0.0", sha="a" * 40, marker="v1"
    )
    return project_dir, mocked_dir


class TestExcludeNewerScopedToFetchLockOnly:
    """§3 Axis D "Verb reach": the CLI override flag is narrower than
    --strategy — registered on fetch/lock ONLY, not add/update/remove."""

    def test_fetch_accepts_exclude_newer_flag(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch", "--exclude-newer", "2026-01-01T00:00:00Z"],
            mocked_dir,
            project_dir,
        )
        assert rc == 0

    def test_lock_accepts_exclude_newer_flag(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "lock", "--exclude-newer", "2026-01-01T00:00:00Z"],
            mocked_dir,
            project_dir,
        )
        assert rc == 0

    def test_update_rejects_exclude_newer_flag(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        # Fetch first so update has a lockfile to work from.
        _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "update", "--exclude-newer", "2026-01-01T00:00:00Z"],
            mocked_dir,
            project_dir,
        )
        assert rc == 2

    def test_add_rejects_exclude_newer_flag(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(
            [
                "-C", str(project_dir), "add", "bar",
                "--git", "https://example.com/bar.git",
                "--exclude-newer", "2026-01-01T00:00:00Z",
            ],
            mocked_dir,
            project_dir,
        )
        assert rc == 2

    def test_remove_rejects_exclude_newer_flag(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "remove", "foo", "--exclude-newer", "2026-01-01T00:00:00Z"],
            mocked_dir,
            project_dir,
        )
        assert rc == 2


class TestExcludeNewerMalformed:
    def test_malformed_exclude_newer_raises_cli_slug(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--exclude-newer", "not-a-timestamp"],
            mocked_dir,
            project_dir,
        )
        assert rc == 1
        assert "CLI-EXCLUDE-NEWER-INVALID" in err


class TestExcludeNewerPrecedence:
    """D2 precedence: CLI > manifest resolution{exclude-newer} > None. No
    lockfile-recorded tier (distinct from --strategy's 4-tier chain — see
    _resolve_effective_exclude_newer's docstring)."""

    def test_pure_function_cli_overrides_manifest(self) -> None:
        from milpa.manifest import Resolution

        cli_value = datetime(2026, 1, 1, tzinfo=timezone.utc)
        manifest_value = datetime(2020, 1, 1, tzinfo=timezone.utc)

        class _FakeManifest:
            resolution = Resolution(exclude_newer=manifest_value)

        effective = _resolve_effective_exclude_newer(cli_value, _FakeManifest())
        assert effective == cli_value

    def test_pure_function_falls_back_to_manifest(self) -> None:
        from milpa.manifest import Resolution

        manifest_value = datetime(2020, 1, 1, tzinfo=timezone.utc)

        class _FakeManifest:
            resolution = Resolution(exclude_newer=manifest_value)

        effective = _resolve_effective_exclude_newer(None, _FakeManifest())
        assert effective == manifest_value

    def test_pure_function_none_when_both_absent(self) -> None:
        class _FakeManifest:
            resolution = None

        assert _resolve_effective_exclude_newer(None, _FakeManifest()) is None

    def test_explicit_cli_overrides_manifest_resolution_exclude_newer_e2e(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(
            tmp_path,
            resolution_block='resolution {\n    exclude-newer "2020-01-01T00:00:00Z"\n}\n',
        )
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch", "--exclude-newer", "2026-01-01T00:00:00Z"],
            mocked_dir,
            project_dir,
        )
        # D2 only threads the effective value (inert — D3/D4 consume it);
        # the resolve must still succeed either way.
        assert rc == 0
        # The WRITTEN lockfile must record the CLI tier's value (it wins over
        # the manifest's "resolution { exclude-newer }" tier).
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.exclude_newer == datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_unspecified_cli_uses_manifest_resolution_exclude_newer_e2e(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(
            tmp_path,
            resolution_block='resolution {\n    exclude-newer "2020-01-01T00:00:00Z"\n}\n',
        )
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch"], mocked_dir, project_dir
        )
        assert rc == 0
        # The WRITTEN lockfile must record the MANIFEST tier's value (no CLI
        # override was given, so the manifest fallback threads through).
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.exclude_newer == datetime(2020, 1, 1, tzinfo=timezone.utc)
