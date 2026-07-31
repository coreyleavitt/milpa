"""B3 (resolution-semantics RFC §3 Axis B / §6 D-B2) — ``--locked`` CLI slice.

Anti-hollow: exercises the real argparse layer (``main(argv)``), not the
conformance harness shortcut — proving the flag is actually wired, scoped
to fetch/lock, and that it forces a real resolve rather than being silently
short-circuited by the implicit frozen fast-path (cli-contract.md §2.4's
documented "attempt unconditionally" behavior).

Scenarios:
  1. ``--locked`` on an up-to-date lock passes (resolve == lock).
  2. ``--locked`` is DISTINCT from frozen: a plain ``fetch`` on an in-sync
     project silently takes the frozen fast-path (stderr says "(frozen)"),
     but ``--locked`` never does — it always performs a real solve.
  3. ``--locked`` with no committed lockfile at all -> RES-LOCKED-DRIFT.
  4. A manifest edit that moves a dep's provenance -> RES-LOCKED-DRIFT,
     naming the drifted package.
  5. ``--locked`` is scoped to fetch/lock only (accepted there; a parse
     error elsewhere would be a `-2` exit, not exercised here since other
     verbs simply don't declare the flag).
"""

from __future__ import annotations

import os
from pathlib import Path

from milpa.fetchers.mocked import url_key

_UNSAFE_NO_INDEX_ENV = {"MILPA_INDEX_URL": ""}


def _make_git_mock(mocked_dir: Path, url: str, ref: str, *, sha: str, marker: str) -> None:
    """Stage one ``mocked-fetches/<url_key>/`` dir for a single git dep."""
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
        import io
        import contextlib

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _manifest_kdl(ref: str) -> str:
    return (
        'name "myapp"\nkind "application"\n'
        "deps {\n"
        f'    foo git=(url)"https://example.com/foo.git" ref="{ref}"\n'
        "}\n"
    )


def _setup_project(tmp_path: Path, *, ref: str = "v1.0.0") -> tuple[Path, Path]:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "milpa.kdl").write_text(_manifest_kdl(ref), encoding="utf-8")
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    _make_git_mock(
        mocked_dir,
        "https://example.com/foo.git",
        ref,
        sha="a" * 40,
        marker=ref,
    )
    return project_dir, mocked_dir


class TestLockedPassesWhenUpToDate:
    def test_locked_passes_after_a_fresh_fetch(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--locked"], mocked_dir, project_dir
        )
        assert rc == 0, f"--locked on an up-to-date lock should pass; stderr={err!r}"

    def test_locked_passes_on_lock_verb_too(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "lock"], mocked_dir, project_dir)
        assert rc == 0

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "lock", "--locked"], mocked_dir, project_dir
        )
        assert rc == 0, f"--locked on `lock` should also pass; stderr={err!r}"


class TestLockedDistinctFromFrozen:
    """--locked always performs a real solve; it must never be silently
    short-circuited by the implicit frozen fast-path (§2.4/§6)."""

    def test_plain_fetch_takes_the_implicit_frozen_path_when_in_sync(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0

        # Second bare `fetch`, lockfile already in sync: takes the implicit
        # frozen fast-path (this is pre-existing behavior, not introduced by
        # B3 — asserted here as the baseline the next test's contrast relies on).
        rc, _out, err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0
        assert "(frozen)" in err, f"expected the implicit frozen fast-path; stderr={err!r}"

    def test_locked_fetch_never_takes_the_frozen_path(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--locked"], mocked_dir, project_dir
        )
        assert rc == 0
        assert "(frozen)" not in err, (
            f"--locked must force a real resolve, never the frozen fast-path; stderr={err!r}"
        )
        assert "resolved" in err


class TestLockedNoPriorLock:
    def test_locked_with_no_committed_lock_fails(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        assert not (project_dir / "milpa.lock").exists()

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--locked"], mocked_dir, project_dir
        )
        assert rc == 1
        assert "milpa-error: RES-LOCKED-DRIFT" in err

    def test_locked_lock_verb_with_no_committed_lock_fails(self, tmp_path: Path) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, err = _run_main(
            ["-C", str(project_dir), "lock", "--locked"], mocked_dir, project_dir
        )
        assert rc == 1
        assert "milpa-error: RES-LOCKED-DRIFT" in err


class TestLockedDetectsDrift:
    def test_provenance_change_after_manifest_edit_fails_naming_the_dep(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(tmp_path, ref="v1.0.0")
        rc, _out, _err = _run_main(["-C", str(project_dir), "fetch"], mocked_dir, project_dir)
        assert rc == 0

        # Move the dep to a different tag -> different commit_sha/provenance
        # (and, since the mocked content differs too, a different identity).
        _make_git_mock(
            mocked_dir,
            "https://example.com/foo.git",
            "v2.0.0",
            sha="b" * 40,
            marker="v2.0.0",
        )
        (project_dir / "milpa.kdl").write_text(
            _manifest_kdl("v2.0.0"), encoding="utf-8"
        )

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "fetch", "--locked"], mocked_dir, project_dir
        )
        assert rc == 1
        assert "milpa-error: RES-LOCKED-DRIFT" in err
        assert "foo" in err

        # And the committed lockfile/nim.cfg must NOT have been clobbered by
        # the drifted resolve.
        from milpa.lockfile import load_lockfile

        lock = load_lockfile(project_dir / "milpa.lock")
        (dep,) = lock.deps
        assert dep.provenances[0].ref == "v1.0.0"
