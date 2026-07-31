"""R1 (code-review finding, High) — the implicit frozen fast-path in
``cmd_fetch``/``_cmd_fetch_workspace`` must compute the EFFECTIVE strategy
(C3) and EFFECTIVE exclude-newer bound (D2) BEFORE deciding whether to
attempt the no-solve reconstruction, and must skip the fast-path whenever
either value diverges from what the prior committed lock actually recorded.

Before the fix, the fast-path gate was the ad-hoc
``elif not locked and upgrade is None:`` — it never looked at ``--strategy``/
``--exclude-newer`` at all, so ``milpa fetch --strategy lowest-direct`` (or
``--exclude-newer <ts>``) on an already-locked, manifest-unchanged project
would silently reconstruct from the stale lock and exit 0, never running a
real solve and never honoring the flag.

These are in-process ``cmd_fetch``-level tests (real argparse via
``main(argv)``), NOT conformance fixtures — the harness's ``cmd:resolve``
path bypasses ``cmd_fetch`` entirely, which is exactly why this slipped
through. Mirrors ``test_b3_locked_cli.py``'s infra (mocked git fetch, no
index, no network) and its "(frozen)" vs "resolved N deps" stderr
convention for distinguishing the fast-path from a real resolve.
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
    """Call ``main(argv)`` with MILPA_MOCKED_FETCHES set; no network (empty index)."""
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


def _manifest_kdl() -> str:
    return (
        'name "myapp"\nkind "application"\n'
        "deps {\n"
        '    foo git=(url)"https://example.com/foo.git" ref="v1.0.0"\n'
        "}\n"
    )


def _setup_project(tmp_path: Path) -> tuple[Path, Path]:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "milpa.kdl").write_text(_manifest_kdl(), encoding="utf-8")
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    _make_git_mock(
        mocked_dir, "https://example.com/foo.git", "v1.0.0", sha="a" * 40, marker="v1"
    )
    return project_dir, mocked_dir


class TestFastPathPreservedWhenNothingDiverges:
    """The perf optimization itself must survive the fix: a bare ``fetch``
    on an up-to-date, unchanged project still takes the frozen fast-path."""

    def test_bare_fetch_still_takes_frozen_path(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0

        rc, _out, err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0
        assert "(frozen)" in err, f"expected the fast-path preserved; stderr={err!r}"


class TestStrategyDivergenceForcesResolve:
    """R1: --strategy diverging from the lock's recorded strategy must
    force a real resolve, never the frozen fast-path."""

    def test_strategy_flag_on_locked_project_reresolves_and_honors_flag(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "maxver"

        # Manifest unchanged, lockfile in sync -> before the fix this would
        # silently take the frozen fast-path and never touch --strategy.
        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--strategy", "minver"],
            mocked_dir,
            project_dir,
        )
        assert rc == 0
        assert "(frozen)" not in err, (
            f"--strategy diverging from the lock must force a real resolve; "
            f"stderr={err!r}"
        )
        assert "resolved" in err

        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "minver", "the effective --strategy must be honored"

    def test_strategy_flag_matching_the_lock_still_takes_fast_path(
        self, tmp_path: Path
    ) -> None:
        """Sanity check on the other side of the gate: an EXPLICIT
        --strategy that happens to equal what's already locked must not
        force a needless resolve (no value divergence -> fast-path stands)."""
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--strategy", "maxver"],
            mocked_dir,
            project_dir,
        )
        assert rc == 0
        assert "(frozen)" in err, f"same effective strategy -> fast-path should stand; stderr={err!r}"


class TestExcludeNewerDivergenceForcesResolve:
    """R1: --exclude-newer diverging from the lock's recorded bound must
    force a real resolve, never the frozen fast-path."""

    def test_exclude_newer_flag_on_locked_project_reresolves_and_honors_flag(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.exclude_newer is None

        # Manifest unchanged, lockfile in sync -> before the fix this would
        # silently take the frozen fast-path and never touch --exclude-newer.
        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--exclude-newer", "2026-01-01T00:00:00Z"],
            mocked_dir,
            project_dir,
        )
        assert rc == 0
        assert "(frozen)" not in err, (
            f"--exclude-newer diverging from the lock must force a real "
            f"resolve; stderr={err!r}"
        )
        assert "resolved" in err

        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.exclude_newer is not None, "the effective --exclude-newer must be honored"
        assert lock.exclude_newer.year == 2026
