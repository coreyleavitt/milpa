"""C3 (resolution-semantics RFC §3 Axis C / D-C2) — ``--strategy`` CLI
sentinel + scoped registration + manifest ``resolution { strategy }``
precedence, exercised through the REAL argparse layer (``main(argv)``), not
the conformance harness shortcut.

Mirrors ``test_b3_locked_cli.py``'s infra (mocked git fetch, no index, no
network) — this is the "anti-hollow" proof that the CLI plumbing is real:

1. ``--strategy`` is scoped to the resolve-triggering verbs, NOT global —
   ``milpa show --strategy maxver`` is now a parse error (exit 2), whereas
   before C3 it was silently accepted and ignored.
2. Unspecified ``--strategy`` defers to the manifest's
   ``resolution { strategy }`` when declared.
3. Explicit CLI ``--strategy`` overrides the manifest's declared strategy.
4. Absent CLI AND absent manifest strategy defaults to maxver (unchanged
   behavior).
"""

from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path

from milpa.fetchers.mocked import url_key
from milpa.lockfile import load_lockfile

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


class TestStrategyScopedNotGlobal:
    """C3 CLI scoping: --strategy is registered per-verb now, not globally —
    a verb that doesn't declare it (e.g. show) must reject it as a parse
    error, mirroring --locked/--upgrade/--exclude-newer's existing scoping."""

    def test_show_rejects_strategy_flag(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "show", "--strategy", "maxver"],
            mocked_dir,
            project_dir,
        )
        assert rc == 2

    def test_fetch_accepts_strategy_flag(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch", "--strategy", "minver"],
            mocked_dir,
            project_dir,
        )
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "minver"


class TestStrategyPrecedence:
    """C3 precedence: CLI > manifest resolution{strategy} > default."""

    def test_unspecified_cli_uses_manifest_resolution_strategy(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(
            tmp_path,
            resolution_block='resolution {\n    strategy "minver"\n}\n',
        )
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch"], mocked_dir, project_dir
        )
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "minver"

    def test_explicit_cli_overrides_manifest_resolution_strategy(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(
            tmp_path,
            resolution_block='resolution {\n    strategy "minver"\n}\n',
        )
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch", "--strategy", "semver"],
            mocked_dir,
            project_dir,
        )
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "semver"

    def test_absent_cli_and_manifest_defaults_to_maxver(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch"], mocked_dir, project_dir
        )
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "maxver"
