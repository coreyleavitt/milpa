"""F6 regression: resolve_workspace_frozen must skip MemberDep in the
external-dep alignment loop (conditions 2-4).

BUG (pre-fix): the alignment loop iterated over ALL deps from filter_manifest,
including MemberDep entries.  When a MemberDep referenced a member whose name
was absent from the lockfile, the loop fired FROZEN-MANIFEST-DEP-NOT-IN-LOCK
with a misleading message ("dep 'a' has no entry in lockfile" looks like an
external dep is missing when it is actually a member-to-member edge).

FIX: ``if isinstance(dep, MemberDep): continue`` in the alignment loop so
only external deps are checked there.  Member-to-member validation is the
responsibility of conditions 9 (FROZEN-MEMBER-NOT-IN-WORKSPACE) and 10
(FROZEN-MEMBER-IDENTITY-DRIFT), which operate on the lockfile side.

Scenario
--------
Workspace root
  member "a"   (lib_a — a minimal library, no deps)
  member "b"   (lib_b — declares ``member "a"``)

Happy path: lockfile has both "a" and "b" as member deps → success.
Bug path (pre-fix): lockfile has "b" but NOT "a" (name mismatch / missing
member record) → pre-fix fires FROZEN-MANIFEST-DEP-NOT-IN-LOCK; post-fix
skips the MemberDep and falls through to condition 9 checks or succeeds.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv
from milpa.errors import (
    FROZEN_MANIFEST_DEP_NOT_IN_LOCK,
    MilpaError,
)
from milpa.frozen import resolve_workspace_frozen
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    LockedDep,
    Lockfile,
    MemberProvenanceRecord,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env(tmp_path: Path) -> MilpaEnv:
    """MilpaEnv with an empty CAS (no external deps need to be in the store)."""
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    return MilpaEnv(fetcher=None, index=None, store=store)  # type: ignore[arg-type]


def _member_locked(name: str, abs_dir: Path) -> LockedDep:
    return LockedDep(
        name=name,
        identity=compute_content_hash(abs_dir),
        version="0.0.1",
        src_dir="",
        requires=(),
        provenances=(MemberProvenanceRecord(name=name),),
        aliases=(),
    )


def _build_workspace(tmp_path: Path) -> tuple:
    """Build a workspace on disk with two members, where member B references member A.

    Layout:
      project/milpa.kdl           — workspace declaring member "a" + member "b"
      project/a/milpa.kdl         — library "a" (no deps)
      project/b/milpa.kdl         — library "b" with ``deps { member "a" }``

    Returns (root_dir, workspace, a_dir, b_dir).
    """
    from milpa.workspace import load_workspace

    root_dir = tmp_path / "project"
    root_dir.mkdir()

    # Workspace manifest
    (root_dir / "milpa.kdl").write_text(
        'workspace {\n    member "a"\n    member "b"\n}\n',
        encoding="utf-8",
    )

    # Member A — simple library, no deps
    a_dir = root_dir / "a"
    a_dir.mkdir()
    (a_dir / "milpa.kdl").write_text(
        'name "a"\nkind "library"\n',
        encoding="utf-8",
    )

    # Member B — library that references member A via ``member "a"``
    b_dir = root_dir / "b"
    b_dir.mkdir()
    (b_dir / "milpa.kdl").write_text(
        'name "b"\nkind "library"\ndeps {\n    member "a"\n}\n',
        encoding="utf-8",
    )

    workspace = load_workspace(root_dir)
    return root_dir, workspace, a_dir, b_dir


# ---------------------------------------------------------------------------
# F6 — RED test (pre-fix behavior)
# ---------------------------------------------------------------------------


class TestF6MemberDepSkippedInAlignmentLoop:
    """resolve_workspace_frozen must NOT fire FROZEN-MANIFEST-DEP-NOT-IN-LOCK
    for a MemberDep entry.  Member deps are validated by conditions 9/10, not
    by the external-dep alignment loop (conditions 2-4).
    """

    def test_memberdep_missing_from_lock_does_not_fire_external_dep_slug(
        self, tmp_path: Path
    ) -> None:
        """Pre-fix: FROZEN-MANIFEST-DEP-NOT-IN-LOCK fires for a missing member dep.
        Post-fix: the MemberDep is skipped → no FROZEN-MANIFEST-DEP-NOT-IN-LOCK.

        This is the RED test — it will FAIL before the ``isinstance(dep, MemberDep):
        continue`` guard is added to ``frozen.py``.
        """
        env = _make_env(tmp_path)
        deps_dir = tmp_path / "_deps"

        _, workspace, a_dir, b_dir = _build_workspace(tmp_path)

        # Lockfile: member "b" is present but member "a" is ABSENT.
        # This represents a lockfile that is stale/mismatched for member "a".
        # Pre-fix: iterating member B's deps finds MemberDep("a") and checks
        #   "a" not in locked_by_name → fires FROZEN-MANIFEST-DEP-NOT-IN-LOCK.
        # Post-fix: MemberDep("a") is skipped → the loop does NOT fire that slug.
        b_locked = _member_locked("b", b_dir)
        lockfile = Lockfile(deps=(b_locked,), strategy="maxver")

        # Post-fix expectation: FROZEN-MANIFEST-DEP-NOT-IN-LOCK must NOT fire.
        # (Another error may fire — e.g. FROZEN-MEMBER-NOT-IN-WORKSPACE for "a" not
        # in workspace members, or success if the checks have no further objection.)
        # The invariant is only: the WRONG slug must not fire for a MemberDep.
        try:
            resolve_workspace_frozen(workspace, lockfile, env, deps_dir)
            # Success is also acceptable — means MemberDep was skipped cleanly.
        except MilpaError as exc:
            assert exc.slug != FROZEN_MANIFEST_DEP_NOT_IN_LOCK, (
                f"FROZEN-MANIFEST-DEP-NOT-IN-LOCK must NOT fire for a MemberDep "
                f"in the external-dep alignment check; got slug={exc.slug!r}\n"
                f"msg={exc}"
            )

    def test_happy_path_both_members_in_lock_succeeds(
        self, tmp_path: Path
    ) -> None:
        """When both members are in the lockfile the workspace frozen path succeeds.

        This is the smoke test confirming the fix did not break the normal case.
        """
        env = _make_env(tmp_path)
        deps_dir = tmp_path / "_deps"

        _, workspace, a_dir, b_dir = _build_workspace(tmp_path)

        a_locked = _member_locked("a", a_dir)
        b_locked = _member_locked("b", b_dir)
        lockfile = Lockfile(deps=(a_locked, b_locked), strategy="maxver")

        # No exception: both members are in the lockfile, identity matches.
        graph = resolve_workspace_frozen(workspace, lockfile, env, deps_dir)
        assert len(graph.deps) == 2
        names = {d.name for d in graph.deps}
        assert names == {"a", "b"}
