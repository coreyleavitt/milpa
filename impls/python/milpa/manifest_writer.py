"""milpa manifest writer — atomic mutation of milpa.kdl.

Slice 10d per docs/rfc-python-clean-room-rewrite.md.
S9b per docs/rfc-workspace-completion.md.

Provides:
  ``mutate_manifest_file(path, mutator)`` — read milpa.kdl, apply a pure
      ``Manifest → Manifest`` transform, then write the canonical re-render
      atomically.  ``format_manifest`` is the SSOT serializer; this module
      does ZERO KDL-AST construction — it handles file I/O only.

  ``mutate_workspace_manifest_file(path, mutator)`` — typed analog of
      ``mutate_manifest_file`` for workspace manifests.

  ``apply_workspace_manifest_change(root, env, params, mutate)`` — workspace
      orchestration analog of the single-package add/remove orchestration
      (``_cmd_add_git`` / ``cmd_remove`` in cli.py).  Implements the
      validate→resolve-in-memory→write-manifest→write-lock atomicity ordering
      (RFC: workspace-completion §3.F): resolves the proposed workspace in
      memory BEFORE any on-disk write, so a network or resolution failure
      leaves the manifest untouched.

  ``WriteResult`` — what a mutation did to disk.

Atomic write contract (cli-contract.md §5.6):
  Writes are performed via a sibling tmp file + ``os.replace()``.  A
  mid-write kill leaves the file unmodified.  The only residual window is an
  fs-write failure between the manifest write and the lock write — identical
  to what single-package add/remove already accept.

Comment-dropped warning:
  Detected by ``format_manifest`` via ``Manifest.had_comments`` — the warning
  is emitted to stderr by ``format_manifest`` itself (§3), not by this module.

Refuses:
  - Missing file → ``MAN-MUTATE-FILE-NOT-FOUND``
  - ``.nimble`` file → ``MAN-MUTATE-NIMBLE-REFUSED``
  - Workspace manifest → ``MAN-MUTATE-WORKSPACE-REFUSED`` (package path only;
    workspace-typed path is explicitly allowed via ``mutate_workspace_manifest_file``
    and ``apply_workspace_manifest_change``).
  - Malformed manifest → the ``MAN-*`` parse code surfaces unchanged.

Spec authority: spec/cli-contract.md §5.6, §5.9, spec/manifest-grammar.md §8.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from milpa.errors import (
    MAN_MUTATE_FILE_NOT_FOUND,
    MAN_MUTATE_NIMBLE_REFUSED,
    MAN_MUTATE_WORKSPACE_REFUSED,
    MilpaError,
)
from milpa.manifest import (
    Manifest,
    WorkspaceManifest,
    format_manifest,
    format_workspace_manifest,
    parse_workspace_or_manifest,
)

# ---------------------------------------------------------------------------
# WriteResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WriteResult:
    """Outcome of a manifest mutation + write.

    ``path``           — absolute path of the (re)written milpa.kdl.
    ``comments_lost``  — number of ``//``-comment lines dropped by the
                         declarative re-render (heuristic count; matches the
                         Rust ``WriteResult.comments_lost`` semantics).
    """

    path: Path
    comments_lost: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _count_comments(text: str) -> int:
    """Count ``//``-prefixed lines (after stripping leading whitespace).

    Conservative heuristic — matches the Rust ``count_comments``.
    """
    return sum(1 for line in text.splitlines() if line.lstrip().startswith("//"))


def _atomic_write_text(path: Path, text: str) -> None:
    """Write *text* to *path* atomically (sibling tmp + os.replace).

    The tmp file is a sibling of *path* so the rename is always on the same
    filesystem (required for POSIX atomic rename).
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def mutate_manifest_file(
    path: Path,
    mutator: Callable[[Manifest], Manifest],
) -> WriteResult:
    """Read ``milpa.kdl`` at *path*, apply *mutator*, and write the canonical
    re-render atomically.

    Parameters
    ----------
    path:
        Absolute path to the ``milpa.kdl`` to mutate.  Must be a plain
        package manifest (not a ``.nimble`` or a workspace manifest).
    mutator:
        A pure ``Manifest → Manifest`` function.  Called with the parsed
        manifest; its return value is serialized via ``format_manifest`` and
        written atomically.  Mutator MUST NOT perform I/O.

    Returns
    -------
    WriteResult
        Contains the path written and the heuristic comment-loss count.

    Raises
    ------
    MilpaError(MAN-MUTATE-FILE-NOT-FOUND)
        If *path* does not exist or cannot be read.
    MilpaError(MAN-MUTATE-NIMBLE-REFUSED)
        If *path* has a ``.nimble`` extension.
    MilpaError(MAN-MUTATE-WORKSPACE-REFUSED)
        If *path* is a workspace manifest.
    MilpaError(MAN-*)
        If the manifest is malformed (parse error surfaces unchanged).
    """
    # Guard 1: .nimble refused (cannot safely round-trip NimScript).
    if path.suffix == ".nimble":
        raise MilpaError(
            MAN_MUTATE_NIMBLE_REFUSED,
            f"refusing to mutate a .nimble file ({path}); "
            "promote to milpa.kdl first",
            path=str(path),
        )

    # Guard 2: file must exist and be readable.
    if not path.exists():
        raise MilpaError(
            MAN_MUTATE_FILE_NOT_FOUND,
            f"manifest file not found: {path} — create a milpa.kdl first",
            path=str(path),
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MilpaError(
            MAN_MUTATE_FILE_NOT_FOUND,
            f"cannot read {path}: {exc}",
            path=str(path),
        ) from exc

    # Guard 3: parse; refuse workspace manifests.
    doc = parse_workspace_or_manifest(text)
    if isinstance(doc, WorkspaceManifest):
        raise MilpaError(
            MAN_MUTATE_WORKSPACE_REFUSED,
            f"{path}: workspace manifests are pure containers and cannot be mutated",
            path=str(path),
        )

    assert isinstance(doc, Manifest)

    # Apply the mutation (pure transform).
    new_manifest = mutator(doc)

    # Render and write atomically.
    rendered = format_manifest(new_manifest)
    before = _count_comments(text)
    after = _count_comments(rendered)
    _atomic_write_text(path, rendered)

    return WriteResult(
        path=path,
        comments_lost=max(0, before - after),
    )


def mutate_workspace_manifest_file(
    path: Path,
    mutator: Callable[[WorkspaceManifest], WorkspaceManifest],
) -> WriteResult:
    """Read a workspace ``milpa.kdl`` at *path*, apply *mutator*, and write the
    canonical re-render atomically.

    Typed analog of ``mutate_manifest_file`` for the workspace role.
    The serializer is ``format_workspace_manifest``; the write primitive
    is the existing ``_atomic_write_text``.

    Parameters
    ----------
    path:
        Absolute path to the workspace ``milpa.kdl`` to mutate.  Must be a
        workspace manifest (not a package manifest or ``.nimble``).
    mutator:
        A pure ``WorkspaceManifest → WorkspaceManifest`` function.  Mutator
        MUST NOT perform I/O.

    Returns
    -------
    WriteResult
        Contains the path written and the heuristic comment-loss count.

    Raises
    ------
    MilpaError(MAN-MUTATE-FILE-NOT-FOUND)
        If *path* does not exist or cannot be read.
    MilpaError(MAN-MUTATE-NIMBLE-REFUSED)
        If *path* has a ``.nimble`` extension.
    MilpaError(MAN-MUTATE-WORKSPACE-REFUSED)
        If the file is a package manifest (not a workspace).
    MilpaError(MAN-*)
        If the manifest is malformed (parse error surfaces unchanged).
    """
    from milpa.errors import MAN_MUTATE_WORKSPACE_REFUSED as _WS_REFUSED

    # Guard 1: .nimble refused.
    if path.suffix == ".nimble":
        raise MilpaError(
            MAN_MUTATE_NIMBLE_REFUSED,
            f"refusing to mutate a .nimble file ({path}); "
            "promote to milpa.kdl first",
            path=str(path),
        )

    # Guard 2: file must exist and be readable.
    if not path.exists():
        raise MilpaError(
            MAN_MUTATE_FILE_NOT_FOUND,
            f"manifest file not found: {path} — create a milpa.kdl first",
            path=str(path),
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MilpaError(
            MAN_MUTATE_FILE_NOT_FOUND,
            f"cannot read {path}: {exc}",
            path=str(path),
        ) from exc

    # Guard 3: parse; require a workspace manifest.
    doc = parse_workspace_or_manifest(text)
    if isinstance(doc, Manifest):
        raise MilpaError(
            _WS_REFUSED,
            f"{path}: not a workspace manifest — use mutate_manifest_file for package manifests",
            path=str(path),
        )

    assert isinstance(doc, WorkspaceManifest)

    # Apply the mutation (pure transform).
    new_ws = mutator(doc)

    # Render and write atomically.
    rendered = format_workspace_manifest(new_ws)
    before = _count_comments(text)
    after = _count_comments(rendered)
    _atomic_write_text(path, rendered)

    return WriteResult(
        path=path,
        comments_lost=max(0, before - after),
    )


# ---------------------------------------------------------------------------
# S9b: apply_workspace_manifest_change — workspace orchestration primitive
# ---------------------------------------------------------------------------


def apply_workspace_manifest_change(
    root: Path,
    env: "MilpaEnv",
    params: "ResolveParams",
    mutate: Callable[[WorkspaceManifest], WorkspaceManifest],
) -> "tuple[ResolvedGraph, WriteResult]":
    """Orchestration analog of the single-package add/remove ordering.

    Atomicity ordering (RFC: workspace-completion §3.F):
      *validate → workspace-resolve with the proposed manifest in memory →
      write manifest → write lock.*

    Resolution happens **before** any on-disk mutation, so a network or
    resolution failure leaves the manifest (and lock) untouched.  The only
    residual window is an fs-write failure between the manifest write and the
    lock write — identical to what single-package add/remove already accept;
    it is not eliminated, only minimized.

    Signature symmetry (Design-F4): same shape as the inlined single-package
    add/remove orchestration — no separate ``validate`` callable on either
    path; validation is implicit in "the mutated doc resolves."

    Parameters
    ----------
    root:
        Absolute path to the workspace root directory (contains
        ``milpa.kdl``).
    env:
        Injectable seams (fetcher, index, store).
    params:
        Per-call resolution parameters (strategy, max_parallel, profile, …).
    mutate:
        A pure ``WorkspaceManifest → WorkspaceManifest`` transform.  Called
        with the parsed workspace manifest; its return value drives the
        in-memory resolve and then is serialized + written atomically.
        Mutator MUST NOT perform I/O.

    Returns
    -------
    tuple[ResolvedGraph, WriteResult]
        The resolved graph and the write result (path + comment-loss count).
        Both are returned so the caller (e.g. ``workspace add-member``) can
        emit progress output.

    Raises
    ------
    MilpaError
        Any error from workspace loading, the mutate call, member-loading, or
        resolution.  On any raise, NO on-disk file is modified.
    """
    # Lazy imports to avoid circular deps (manifest_writer is imported early).
    from milpa.lockfile import from_graph, write_lockfile
    from milpa.resolver import resolve_workspace
    from milpa.workspace import load_workspace, load_workspace_from_manifest

    # Step 1: Load the current workspace from root (reads milpa.kdl + members).
    current_ws = load_workspace(root)

    # Step 2: Apply the mutation (pure transform on the workspace manifest).
    proposed_ws_manifest = mutate(current_ws.workspace_manifest)

    # Step 3: Build the proposed LoadedWorkspace by reading member manifests
    # from disk for the proposed member list.  This validates member dirs exist
    # and have milpa.kdl before we attempt resolution — load_workspace_from_manifest
    # raises WS-MEMBER-* on any member-topology error, leaving disk untouched.
    proposed_ws = load_workspace_from_manifest(root, proposed_ws_manifest)

    # Step 4: Resolve the proposed workspace IN MEMORY.  Any resolution or
    # network failure raises here — manifest and lock are still unmodified.
    deps_dir = root / "_deps"
    graph = resolve_workspace(proposed_ws, deps_dir, env, params)

    # Step 5: Resolution succeeded — commit both outputs atomically.
    # Write manifest first, then lock.  (The only residual window is an
    # fs-write failure between the two writes — same as single-package.)
    lockfile_val = from_graph(graph, strategy=str(params.strategy))
    manifest_path = root / "milpa.kdl"
    lock_path = root / "milpa.lock"

    # Read the current manifest text for comment-loss counting.
    try:
        original_text = manifest_path.read_text(encoding="utf-8")
    except OSError:
        original_text = ""
    rendered = format_workspace_manifest(proposed_ws_manifest)
    before = _count_comments(original_text)
    after = _count_comments(rendered)
    _atomic_write_text(manifest_path, rendered)

    write_lockfile(lockfile_val, lock_path)

    wr = WriteResult(
        path=manifest_path,
        comments_lost=max(0, before - after),
    )
    return graph, wr


# ---------------------------------------------------------------------------
# S11e: apply_member_manifest_change — member-dir orchestration primitive (F11)
# ---------------------------------------------------------------------------


def apply_member_manifest_change(
    workspace_root: Path,
    env: "MilpaEnv",
    params: "ResolveParams",
    member_dir: Path,
    mutate_member_manifest: "Callable[[Manifest], Manifest]",
) -> "tuple[ResolvedGraph, WriteResult]":
    """Orchestration primitive for ``add``/``remove`` invoked from a member dir.

    Mirrors the validate→resolve-in-memory→write-manifest→write-lock ordering
    of ``apply_workspace_manifest_change``, but targets ONE member's manifest
    rather than the workspace manifest.

    Atomicity ordering (spec/cli-contract.md §5.6–5.7):
      *reload-workspace → apply mutator to member manifest → resolve-in-memory
      → write member manifest → write shared lock.*

    Resolution happens **before** any on-disk write, so a network or resolution
    failure leaves both the member manifest and the shared lock untouched.

    The workspace is re-loaded from root (step 1) so that a member dir deleted
    since the command started is caught by ``load_workspace`` before we attempt
    resolution — identical validation rigor to ``apply_workspace_manifest_change``.

    Parameters
    ----------
    workspace_root:
        Absolute path to the workspace root directory.
    env:
        Injectable seams (fetcher, index, store).
    params:
        Per-call resolution parameters (strategy, max_parallel, profile, prior,
        manifest_dir, …).  Caller must set ``params.manifest_dir = workspace_root``.
    member_dir:
        Absolute path to the member directory whose manifest is being mutated.
        Must resolve to a declared member of the workspace.
    mutate_member_manifest:
        A pure ``Manifest → Manifest`` transform applied to the member's
        current on-disk manifest.  Mutator MUST NOT perform I/O.

    Returns
    -------
    tuple[ResolvedGraph, WriteResult]
        The resolved graph and the write result (path to the member manifest
        + comment-loss count).

    Raises
    ------
    MilpaError
        Any error from workspace loading, the mutate call, or resolution.
        On any raise, NO on-disk file is modified.
    """
    from milpa.lockfile import from_graph, write_lockfile
    from milpa.manifest import parse_manifest
    from milpa.resolver import resolve_workspace
    from milpa.workspace import load_workspace, load_workspace_with_member_override

    # Step 1: Re-load the workspace from root.  This re-validates that all
    # declared member dirs still exist and have milpa.kdl — catching the
    # "member dir deleted since last load" case before any resolution attempt.
    current_ws = load_workspace(workspace_root)

    # Step 2: Read and parse the target member's current manifest.
    member_dir_resolved = member_dir.resolve()
    member_manifest_path = member_dir_resolved / "milpa.kdl"
    try:
        member_text = member_manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MilpaError(
            MAN_MUTATE_FILE_NOT_FOUND,
            f"cannot read member manifest at {member_manifest_path}: {exc}",
            path=str(member_manifest_path),
        ) from exc
    member_manifest = parse_manifest(member_text)

    # Step 3: Apply the mutator (pure transform on the member manifest).
    proposed_member_manifest = mutate_member_manifest(member_manifest)

    # Step 4: Build the proposed LoadedWorkspace with the mutated member manifest.
    proposed_ws = load_workspace_with_member_override(
        current_ws, member_dir_resolved, proposed_member_manifest
    )

    # Step 5: Resolve the proposed workspace IN MEMORY.  Any resolution or
    # network failure raises here — member manifest and shared lock are still
    # unmodified.
    deps_dir = workspace_root / "_deps"
    graph = resolve_workspace(proposed_ws, deps_dir, env, params)

    # Step 6: Resolution succeeded — commit both outputs atomically.
    # Write member manifest first, then shared lock.
    lockfile_val = from_graph(graph, strategy=str(params.strategy))
    lock_path = workspace_root / "milpa.lock"

    before = _count_comments(member_text)
    rendered = format_manifest(proposed_member_manifest)
    after = _count_comments(rendered)
    _atomic_write_text(member_manifest_path, rendered)

    write_lockfile(lockfile_val, lock_path)

    wr = WriteResult(
        path=member_manifest_path,
        comments_lost=max(0, before - after),
    )
    return graph, wr


# ---------------------------------------------------------------------------
# Type stubs for forward references used in apply_workspace_manifest_change
# and apply_member_manifest_change
# ---------------------------------------------------------------------------
# The TYPE_CHECKING guard keeps these imports from being executed at module
# load time (avoiding circular imports), while still satisfying type checkers.

from typing import TYPE_CHECKING  # noqa: E402
if TYPE_CHECKING:
    from milpa.context import MilpaEnv, ResolveParams  # noqa: F401
    from milpa.resolver import ResolvedGraph  # noqa: F401
