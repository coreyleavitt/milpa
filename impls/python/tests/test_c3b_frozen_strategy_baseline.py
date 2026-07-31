"""C3b (resolution-semantics RFC §3 Axis C / §6 D-C2, §7 C3b) — the
``FROZEN-STRATEGY-MISMATCH`` baseline must be the manifest's EFFECTIVE
``resolution { strategy }`` (default ``maxver``), not the hardcoded
``"maxver"`` literal.

Bug: before this fix, ``resolve_frozen``/``resolve_workspace_frozen``
compared ``lockfile.strategy`` against a hardcoded ``_DEFAULT_STRATEGY =
"maxver"`` literal (``frozen.py``). A project that declares ``resolution {
strategy "minver" }`` and has a genuinely-consistent ``minver`` lock would
spuriously fail ``--frozen`` on every run, since ``"minver" != "maxver"``
even though nothing has actually diverged.

Fix: the baseline is now ``resolver._resolve_effective_strategy(None,
manifest, None)`` — tiers 2 (manifest ``resolution { strategy }``) + 4
(global default ``maxver``) only; no CLI tier (frozen has no ``--strategy``)
and no lockfile-prior tier (the frozen path's "prior" IS the very lockfile
being checked — threading it through would make the check compare the
lock against itself and never fire).

Behaviors under test (CLI-level, real ``main(argv)``, mocked git fetch,
mirrors ``test_c3_strategy_cli.py``'s infra):

1. ``resolution { strategy "minver" }`` + a genuinely-consistent ``minver``
   lock → ``--frozen fetch`` PASSES (the regression this slice fixes).
2. A genuine divergence (manifest declares one strategy, the committed lock
   was produced under another) → ``--frozen fetch`` still correctly FAILS
   with ``FROZEN-STRATEGY-MISMATCH``.
3. No ``resolution { }`` block at all → baseline stays ``maxver``
   (unchanged behavior, regression guard).

A second class of tests exercises ``resolve_workspace_frozen`` directly
(no CLI) — the workspace root's ``resolution { strategy }`` is the SAME
root-authority field the workspace-completion RFC already uses for
index-trust/entry-trust, so the fix applies there too.
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


class TestFrozenBaselineFollowsManifestStrategy:
    """The core C3b regression guard: a non-default manifest strategy with a
    genuinely-consistent lock must PASS ``--frozen``, not spuriously fail
    against a hardcoded ``maxver`` baseline."""

    def test_frozen_passes_with_minver_manifest_and_minver_lock(
        self, tmp_path: Path
    ) -> None:
        project_dir, mocked_dir = _setup_project(
            tmp_path,
            resolution_block='resolution {\n    strategy "minver"\n}\n',
        )
        # Real (non-frozen) fetch establishes the lock + CAS + _deps/.
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch"], mocked_dir, project_dir
        )
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "minver"

        # Now the frozen fast-path: baseline must be "minver" (the
        # manifest's declared strategy), matching the lock exactly.
        rc, _out, err = _run_main(
            ["-C", str(project_dir), "--frozen", "fetch"], mocked_dir, project_dir
        )
        assert rc == 0, f"frozen fetch must succeed on a genuinely-consistent minver lock; stderr={err!r}"
        assert "milpa-error:" not in err

    def test_frozen_default_baseline_unchanged_with_no_resolution_block(
        self, tmp_path: Path
    ) -> None:
        """Regression guard: absent ``resolution { }`` still means the
        baseline is ``maxver`` (unchanged behavior)."""
        project_dir, mocked_dir = _setup_project(tmp_path)
        rc, _out, _err = _run_main(
            ["-C", str(project_dir), "fetch"], mocked_dir, project_dir
        )
        assert rc == 0
        lock = load_lockfile(project_dir / "milpa.lock")
        assert lock.strategy == "maxver"

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "--frozen", "fetch"], mocked_dir, project_dir
        )
        assert rc == 0, f"frozen fetch must succeed on the default maxver lock; stderr={err!r}"


class TestFrozenStillCatchesGenuineDivergence:
    """A REAL divergence between the manifest's declared strategy and the
    committed lock's recorded strategy must still raise
    FROZEN-STRATEGY-MISMATCH — the fix narrows the baseline, it does not
    disable the check."""

    def test_frozen_fails_when_manifest_strategy_changes_after_lock(
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

        # Mutate the manifest's declared strategy WITHOUT re-resolving —
        # simulates a project whose milpa.kdl and milpa.lock have drifted
        # out of sync (e.g. a hand-edit, or a merge).
        (project_dir / "milpa.kdl").write_text(
            _manifest_kdl(resolution_block='resolution {\n    strategy "semver"\n}\n'),
            encoding="utf-8",
        )

        rc, _out, err = _run_main(
            ["-C", str(project_dir), "--frozen", "fetch"], mocked_dir, project_dir
        )
        assert rc == 1
        assert "FROZEN-STRATEGY-MISMATCH" in err


# ---------------------------------------------------------------------------
# resolve_workspace_frozen — same fix, the workspace-root code path
# ---------------------------------------------------------------------------


def _make_workspace_with_resolution(
    tmp_path: Path, *, resolution_block: str = ""
) -> "object":
    from milpa.workspace import load_workspace

    root_dir = tmp_path / "project"
    root_dir.mkdir()
    (root_dir / "milpa.kdl").write_text(
        'workspace {\n    member "mylib"\n}\n' f"{resolution_block}",
        encoding="utf-8",
    )
    lib_dir = root_dir / "mylib"
    lib_dir.mkdir()
    (lib_dir / "milpa.kdl").write_text(
        'name "mylib"\nkind "library"\n', encoding="utf-8"
    )
    return load_workspace(root_dir), lib_dir


class TestWorkspaceFrozenBaselineFollowsRootManifestStrategy:
    """``resolve_workspace_frozen``'s ``FROZEN-STRATEGY-MISMATCH`` baseline
    must be the workspace ROOT manifest's effective ``resolution {
    strategy }`` — the same root-authority model as index-trust/entry-trust
    (only the root may declare it; the RFC's C3b fix applies identically
    here)."""

    def test_workspace_frozen_passes_with_minver_root_and_minver_lock(
        self, tmp_path: Path
    ) -> None:
        from milpa.cas import CAStore
        from milpa.context import MilpaEnv
        from milpa.frozen import resolve_workspace_frozen
        from milpa.identity import compute_content_hash
        from milpa.lockfile import Lockfile, LockedDep, MemberProvenanceRecord

        workspace, lib_dir = _make_workspace_with_resolution(
            tmp_path, resolution_block='resolution {\n    strategy "minver"\n}\n'
        )
        member_identity = compute_content_hash(lib_dir)
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
            aliases=(),
        )
        lockfile = Lockfile(deps=(member_locked,), strategy="minver")

        cas_root = tmp_path / ".cas"
        cas_root.mkdir()
        env = MilpaEnv(fetcher=None, index=None, store=CAStore(cas_root))  # type: ignore[arg-type]
        deps_dir = tmp_path / "_deps"

        # Must NOT raise FROZEN-STRATEGY-MISMATCH — "minver" == "minver".
        graph = resolve_workspace_frozen(workspace, lockfile, env, deps_dir)
        assert graph is not None

    def test_workspace_frozen_fails_on_genuine_root_strategy_divergence(
        self, tmp_path: Path
    ) -> None:
        from milpa.cas import CAStore
        from milpa.context import MilpaEnv
        from milpa.errors import FROZEN_STRATEGY_MISMATCH, MilpaError
        from milpa.frozen import resolve_workspace_frozen
        from milpa.identity import compute_content_hash
        from milpa.lockfile import Lockfile, LockedDep, MemberProvenanceRecord

        workspace, lib_dir = _make_workspace_with_resolution(
            tmp_path, resolution_block='resolution {\n    strategy "minver"\n}\n'
        )
        member_identity = compute_content_hash(lib_dir)
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
            aliases=(),
        )
        # Lock genuinely recorded "maxver" while the root manifest now
        # declares "minver" — a real divergence, must still fail.
        lockfile = Lockfile(deps=(member_locked,), strategy="maxver")

        cas_root = tmp_path / ".cas"
        cas_root.mkdir()
        env = MilpaEnv(fetcher=None, index=None, store=CAStore(cas_root))  # type: ignore[arg-type]
        deps_dir = tmp_path / "_deps"

        try:
            resolve_workspace_frozen(workspace, lockfile, env, deps_dir)
            assert False, "expected FROZEN-STRATEGY-MISMATCH"
        except MilpaError as e:
            assert e.slug == FROZEN_STRATEGY_MISMATCH

    def test_workspace_frozen_default_baseline_unchanged_with_no_resolution_block(
        self, tmp_path: Path
    ) -> None:
        from milpa.cas import CAStore
        from milpa.context import MilpaEnv
        from milpa.frozen import resolve_workspace_frozen
        from milpa.identity import compute_content_hash
        from milpa.lockfile import Lockfile, LockedDep, MemberProvenanceRecord

        workspace, lib_dir = _make_workspace_with_resolution(tmp_path)
        member_identity = compute_content_hash(lib_dir)
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
            aliases=(),
        )
        lockfile = Lockfile(deps=(member_locked,), strategy="maxver")

        cas_root = tmp_path / ".cas"
        cas_root.mkdir()
        env = MilpaEnv(fetcher=None, index=None, store=CAStore(cas_root))  # type: ignore[arg-type]
        deps_dir = tmp_path / "_deps"

        graph = resolve_workspace_frozen(workspace, lockfile, env, deps_dir)
        assert graph is not None
