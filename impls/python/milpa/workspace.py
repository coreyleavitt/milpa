"""Workspace loading and manifest discovery — all filesystem I/O lives here.

This module owns every file-system operation that the rest of milpa needs for
manifest discovery and workspace topology.  ``manifest.py`` is pure text↔value
(RFC §4.2); this module is the I/O layer on top.

Public surface
--------------
``load_or_discover_manifest(project_dir) -> Manifest``
    Read ``milpa.kdl`` from ``project_dir`` (or fall back to ``.nimble``),
    return a parsed ``Manifest``.

``load_workspace(workspace_root) -> LoadedWorkspace``
    Read the workspace manifest and all member manifests.  Emits the
    orphan-member warning (cli-contract.md §7.1).  Raises ``WS-*`` on errors.

``find_workspace_root(start_dir) -> LoadedWorkspace | None``
    Walk up the filesystem from ``start_dir`` looking for a workspace
    manifest that legitimately contains ``start_dir``.
    Returns ``None`` if no workspace is found (single-package mode).

Internal helpers (not exported)
--------------------------------
``_load_nimble_file(path) -> str``
    Read a ``.nimble`` file, raising ``MilpaError`` on I/O failure (this is
    the canonical error path that replaced the old ``NimbleParseError``).

RFC §4.2: workspace.py owns ALL filesystem I/O — including the manifest
loader/discovery helper (``load_or_discover_manifest`` with the ``.nimble``
fallback).  ``manifest.py`` has none.

Error codes raised here (WS-* and file-level MAN-*/NIMBLE-*):
    WS-MEMBER-DIR-MISSING     — declared member dir does not exist
    WS-MEMBER-DOT             — "." used as member path
    WS-MEMBER-DUPLICATE-NAME  — two members share a package name
    WS-MEMBER-HAS-OVERRIDES   — member declares its own overrides block
    WS-MEMBER-IS-WORKSPACE    — member is itself a workspace
    WS-MEMBER-NO-MANIFEST     — member dir has no milpa.kdl
    WS-NO-MANIFEST            — workspace root has no milpa.kdl
    WS-NOT-A-WORKSPACE        — root milpa.kdl is a package, not workspace
    MAN-FILE-NOT-FOUND        — milpa.kdl not found
    MAN-FILE-UNREADABLE       — milpa.kdl cannot be read
    NIMBLE-FILE-NOT-FOUND     — .nimble not found (fallback path)
    NIMBLE-FILE-UNREADABLE    — .nimble cannot be read (fallback path)
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from milpa.errors import (
    MAN_FILE_NOT_FOUND,
    MAN_FILE_UNREADABLE,
    MAN_NIMBLE_AMBIGUOUS,
    MAN_NO_MANIFEST,
    NIMBLE_FILE_NOT_FOUND,
    NIMBLE_FILE_UNREADABLE,
    WS_MEMBER_DIR_MISSING,
    WS_MEMBER_DOT,
    WS_MEMBER_DUPLICATE_NAME,
    WS_MEMBER_HAS_OVERRIDES,
    WS_MEMBER_IS_WORKSPACE,
    WS_MEMBER_NO_MANIFEST,
    WS_MEMBER_PATH_ESCAPE,
    WS_NO_MANIFEST,
    WS_NOT_A_WORKSPACE,
    MilpaError,
)
from milpa.manifest import (
    Manifest,
    WorkspaceManifest,
    parse_manifest,
    parse_workspace_or_manifest,
)
from milpa.nimble import NimbleManifest, parse_nimble

# ---------------------------------------------------------------------------
# LoadedMember / LoadedWorkspace — the outputs of workspace loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoadedMember:
    """A loaded workspace member: its parsed manifest and its directory.

    ``rel_path`` is the workspace-relative path as declared in the workspace
    manifest (e.g. ``"member-a"``).  ``abs_dir`` is the resolved absolute
    filesystem path.
    """

    rel_path: str
    abs_dir: Path
    manifest: Manifest


@dataclass(frozen=True)
class LoadedWorkspace:
    """A fully loaded workspace: root manifest, members, and root directory.

    ``root_dir`` is the absolute path of the workspace root (the directory
    that contains the workspace ``milpa.kdl``).
    ``workspace_manifest`` is the parsed workspace container.
    ``members`` is an ordered tuple of loaded members (declaration order).
    """

    root_dir: Path
    workspace_manifest: WorkspaceManifest
    members: tuple[LoadedMember, ...]


# ---------------------------------------------------------------------------
# Public: load_or_discover_manifest
# ---------------------------------------------------------------------------


def load_or_discover_manifest(project_dir: Path) -> Manifest:
    """Read and parse the manifest for ``project_dir``.

    Discovery precedence (spec §3.1):
      1. ``milpa.kdl`` in ``project_dir`` — parsed as a package manifest.
         (A workspace manifest at this path is not an error here; callers
         that need workspace detection use ``find_workspace_root`` instead.)
      2. A single ``*.nimble`` file — scanned as a NimbleManifest-shaped stub.
      3. Neither → ``MAN-NO-MANIFEST``.
      4. Both milpa.kdl AND multiple .nimble → milpa.kdl wins silently.
      5. Multiple .nimble files → ``MAN-NIMBLE-AMBIGUOUS``.

    Raises
    ------
    MilpaError
        ``MAN-FILE-NOT-FOUND``, ``MAN-FILE-UNREADABLE``, ``MAN-NO-MANIFEST``,
        ``MAN-KDL-SYNTAX``, ``MAN-NAME-MISSING``, etc.
    """
    kdl_path = project_dir / "milpa.kdl"
    if kdl_path.exists():
        text = _read_text(kdl_path, MAN_FILE_NOT_FOUND, MAN_FILE_UNREADABLE)
        return parse_manifest(text)

    # .nimble fallback
    nimble_files = list(project_dir.glob("*.nimble"))
    if len(nimble_files) == 0:
        raise MilpaError(
            MAN_NO_MANIFEST,
            f"no milpa.kdl or .nimble file found in {project_dir}",
            path=str(project_dir),
        )
    if len(nimble_files) > 1:
        names = sorted(f.name for f in nimble_files)
        raise MilpaError(
            MAN_NIMBLE_AMBIGUOUS,
            f"multiple .nimble files found in {project_dir}: {names}; "
            f"milpa cannot determine which to use",
            path=str(project_dir),
            files=names,
        )

    nimble_path = nimble_files[0]
    nimble_text = _load_nimble_file(nimble_path)
    nimble_manifest = parse_nimble(nimble_text, src_path=nimble_path)
    return _manifest_from_nimble(nimble_manifest, project_dir, nimble_path)


# ---------------------------------------------------------------------------
# Internal helper: best-effort path resolution (spec §11.0 — S4, #168)
# ---------------------------------------------------------------------------


def _best_effort_resolve(path: Path) -> Path:
    """Resolve a path, stopping at the longest *stat-existing* prefix.

    Unlike ``Path.resolve(strict=False)``, this function treats **dangling and
    cyclic symlinks as non-existent** by using ``os.stat()`` (which follows
    symlinks) rather than ``os.lstat()`` to determine which prefix exists:

    - An existing symlink whose target resolves to a real path is fully
      canonicalized (``Path.resolve(strict=True)`` on the full path).
    - A dangling symlink (target absent) or cyclic symlink (ELOOP) causes
      ``os.stat()`` to fail, so the symlink itself is excluded from the
      "longest existing prefix."  The result is ``canonical_parent / symlink_name``
      — i.e. the path stays inside its parent directory, not following the link.

    Algorithm (mirrors Rust ``best_effort_resolve`` with stat-not-lstat, spec §11.0):
    1. Try ``path.stat()`` (follows symlinks).  If it succeeds, the path fully
       exists; return ``path.resolve(strict=True)`` for full canonicalization.
    2. Walk up the path hierarchy from longest to shortest prefix, finding the
       longest prefix for which ``stat()`` succeeds.  Canonicalize that prefix
       (resolves all symlinks in it), then append the non-existent suffix and
       normalize ``..`` / ``.`` lexically via ``os.path.normpath``.
    3. If no stat-existing prefix is found (degenerate case), fall back to
       ``os.path.normpath``.
    """
    try:
        path.stat()  # follows symlinks; raises for dangling or cyclic
        return path.resolve(strict=True)
    except OSError:
        pass

    # Find the longest ancestor prefix that stat()-exists.
    parts = path.parts
    for i in range(len(parts) - 1, 0, -1):
        prefix = Path(*parts[:i])
        try:
            prefix.stat()  # follows symlinks at every component of the prefix
            real_prefix = prefix.resolve(strict=True)
            suffix = Path(*parts[i:])
            # Normalize ".." / "." in the suffix relative to real_prefix.
            return Path(os.path.normpath(real_prefix / suffix))
        except OSError:
            continue

    # No stat-existing prefix found — pure lexical normalization.
    return Path(os.path.normpath(path))


# ---------------------------------------------------------------------------
# Internal helper: member-path containment check (spec §11.0 — S4, #168)
# ---------------------------------------------------------------------------


def _member_path_is_under_root(real_root: Path, resolved_cand: Path) -> bool:
    """Return True if the pre-resolved candidate path is within the workspace root.

    Implements the containment check from spec §11.0 (S4, #168).  Both
    arguments must already be resolved (caller owns the resolution step so
    the single ``_best_effort_resolve`` call is not duplicated):

      - ``real_root`` — ``workspace_root.resolve(strict=True)`` (always exists).
      - ``resolved_cand`` — result of ``_best_effort_resolve(workspace_root / rel_path)``.

    Returns ``real_cand.is_relative_to(real_root)`` — **inclusive**: a path
    that resolves TO the root returns True (not an escape), which lets it
    fall through to the ``WS-MEMBER-IS-WORKSPACE`` manifest-parse check.

    Consequences (spec §11.0):
    - An existing symlink pointing outside the root is caught (stat follows
      the live link → real outside path → escape → ``WS-MEMBER-PATH-ESCAPE``).
    - A cyclic symlink (ELOOP) → stat fails → treated as non-existent →
      result = canonical_root/symlink_name → no escape → ``WS-MEMBER-DIR-MISSING``.
    - A dangling symlink (target absent) → stat fails → same as cyclic →
      ``WS-MEMBER-DIR-MISSING``.
    """
    return resolved_cand.is_relative_to(real_root)


# ---------------------------------------------------------------------------
# Public: load_workspace
# ---------------------------------------------------------------------------


def load_workspace(workspace_root: Path) -> LoadedWorkspace:
    """Load the workspace rooted at ``workspace_root``.

    Validates the workspace topology per spec §3.2 and cli-contract.md §7.1.
    Emits an orphan-member warning for each depth-1 subdir that contains a
    ``milpa.kdl`` but is NOT declared as a workspace member.

    Raises
    ------
    MilpaError
        ``WS-NO-MANIFEST``, ``WS-NOT-A-WORKSPACE``, ``WS-MEMBER-*``, etc.
    """
    kdl_path = workspace_root / "milpa.kdl"
    if not kdl_path.exists():
        raise MilpaError(
            WS_NO_MANIFEST,
            f"no milpa.kdl at workspace root {workspace_root}",
            path=str(workspace_root),
        )

    root_text = _read_text(kdl_path, WS_NO_MANIFEST, WS_NO_MANIFEST)
    root_doc = parse_workspace_or_manifest(root_text)
    if isinstance(root_doc, Manifest):
        raise MilpaError(
            WS_NOT_A_WORKSPACE,
            f"{kdl_path} is a package manifest, not a workspace",
            path=str(kdl_path),
        )

    assert isinstance(root_doc, WorkspaceManifest)
    workspace_manifest = root_doc

    # Load each declared member
    members: list[LoadedMember] = []
    seen_names: dict[str, str] = {}  # name → rel_path (for duplicate detection)
    declared_abs: set[Path] = set()

    for rel_path in workspace_manifest.members:
        # §WS-MEMBER-DOT: "." is not supported
        if rel_path == "." or rel_path == "./":
            raise MilpaError(
                WS_MEMBER_DOT,
                'workspace member path "." is not supported; '
                "the workspace root cannot also be a package",
                path=str(workspace_root),
                member=rel_path,
            )

        # §WS-MEMBER-PATH-ESCAPE: member path must not resolve outside the workspace root.
        # Uses _best_effort_resolve (stat-based, spec §11.0) so that dangling and
        # cyclic symlinks are treated as non-existent (no escape) and fall through
        # to WS-MEMBER-DIR-MISSING rather than WS-MEMBER-PATH-ESCAPE.
        # Checked before dir-existence so a live escaping path always yields this slug
        # regardless of whether the target dir exists.
        resolved_root = workspace_root.resolve(strict=True)
        best_effort_abs = _best_effort_resolve(workspace_root / rel_path)
        if not _member_path_is_under_root(resolved_root, best_effort_abs):
            raise MilpaError(
                WS_MEMBER_PATH_ESCAPE,
                f"workspace member {rel_path!r} resolves outside the workspace root "
                f"({best_effort_abs} is not under {resolved_root})",
                member=rel_path,
                path=str(best_effort_abs),
                workspace_root=str(resolved_root),
            )

        abs_dir = best_effort_abs
        declared_abs.add(abs_dir)

        # §WS-MEMBER-DIR-MISSING: member directory must exist
        if not abs_dir.is_dir():
            raise MilpaError(
                WS_MEMBER_DIR_MISSING,
                f"workspace member {rel_path!r} not found at {abs_dir}",
                member=rel_path,
                path=str(abs_dir),
            )

        # §WS-MEMBER-NO-MANIFEST: member must have milpa.kdl
        member_kdl = abs_dir / "milpa.kdl"
        if not member_kdl.exists():
            raise MilpaError(
                WS_MEMBER_NO_MANIFEST,
                f"workspace member {rel_path!r} has no milpa.kdl at {abs_dir}",
                member=rel_path,
                path=str(abs_dir),
            )

        # Parse member manifest (milpa.kdl only — .nimble fallback not used
        # for declared workspace members; they must have milpa.kdl per spec)
        member_text = _read_text(
            member_kdl, WS_MEMBER_NO_MANIFEST, WS_MEMBER_NO_MANIFEST
        )
        member_doc = parse_workspace_or_manifest(member_text)

        # §WS-MEMBER-IS-WORKSPACE: nested workspaces not supported
        if isinstance(member_doc, WorkspaceManifest):
            raise MilpaError(
                WS_MEMBER_IS_WORKSPACE,
                f"workspace member {rel_path!r} is itself a workspace; "
                f"nested workspaces are not supported",
                member=rel_path,
                path=str(member_kdl),
            )

        assert isinstance(member_doc, Manifest)
        member_manifest = member_doc

        # §WS-MEMBER-HAS-OVERRIDES: per-member overrides not supported
        if member_manifest.overrides:
            raise MilpaError(
                WS_MEMBER_HAS_OVERRIDES,
                f"workspace member {rel_path!r} declares its own overrides block; "
                f"per-member overrides are not supported",
                member=rel_path,
                path=str(member_kdl),
            )

        # §WS-MEMBER-DUPLICATE-NAME: two members with the same package name
        name = member_manifest.name
        if name in seen_names:
            raise MilpaError(
                WS_MEMBER_DUPLICATE_NAME,
                f"workspace members {seen_names[name]!r} and {rel_path!r} "
                f"both declare package name {name!r}",
                member=rel_path,
                name=name,
                existing_member=seen_names[name],
            )
        seen_names[name] = rel_path

        members.append(LoadedMember(
            rel_path=rel_path,
            abs_dir=abs_dir,
            manifest=member_manifest,
        ))

    # Orphan-member warning (cli-contract.md §7.1): emit a warning for each
    # depth-1 subdir that contains a milpa.kdl but is NOT declared as a member.
    _warn_orphan_members(workspace_root, declared_abs)

    return LoadedWorkspace(
        root_dir=workspace_root,
        workspace_manifest=workspace_manifest,
        members=tuple(members),
    )


# ---------------------------------------------------------------------------
# Public: load_workspace_from_manifest
# ---------------------------------------------------------------------------


def load_workspace_from_manifest(
    workspace_root: Path,
    ws_manifest: WorkspaceManifest,
) -> LoadedWorkspace:
    """Build a ``LoadedWorkspace`` from an *in-memory* ``WorkspaceManifest``.

    Identical to ``load_workspace`` except that the workspace manifest itself
    is provided as an already-parsed value (not read from disk).  Member
    manifests are still read from disk.

    Used by ``apply_workspace_manifest_change`` to construct a proposed
    ``LoadedWorkspace`` from a mutated manifest *before* any on-disk write,
    so that resolution can fail cleanly without touching the manifest file.

    Raises
    ------
    MilpaError
        The same ``WS-MEMBER-*`` codes that ``load_workspace`` raises for
        member-loading failures.
    """
    members: list[LoadedMember] = []
    seen_names: dict[str, str] = {}
    declared_abs: set[Path] = set()

    for rel_path in ws_manifest.members:
        if rel_path == "." or rel_path == "./":
            raise MilpaError(
                WS_MEMBER_DOT,
                'workspace member path "." is not supported; '
                "the workspace root cannot also be a package",
                path=str(workspace_root),
                member=rel_path,
            )

        # §WS-MEMBER-PATH-ESCAPE: containment check before dir-existence check.
        # Uses _best_effort_resolve (stat-based, spec §11.0) so that dangling and
        # cyclic symlinks are treated as non-existent (no escape) and fall through
        # to WS-MEMBER-DIR-MISSING rather than WS-MEMBER-PATH-ESCAPE.
        # Mirrors the identical pattern in load_workspace().
        resolved_root = workspace_root.resolve(strict=True)
        best_effort_abs = _best_effort_resolve(workspace_root / rel_path)
        if not _member_path_is_under_root(resolved_root, best_effort_abs):
            raise MilpaError(
                WS_MEMBER_PATH_ESCAPE,
                f"workspace member {rel_path!r} resolves outside the workspace root "
                f"({best_effort_abs} is not under {resolved_root})",
                member=rel_path,
                path=str(best_effort_abs),
                workspace_root=str(resolved_root),
            )

        abs_dir = best_effort_abs
        declared_abs.add(abs_dir)

        if not abs_dir.is_dir():
            raise MilpaError(
                WS_MEMBER_DIR_MISSING,
                f"workspace member {rel_path!r} not found at {abs_dir}",
                member=rel_path,
                path=str(abs_dir),
            )

        member_kdl = abs_dir / "milpa.kdl"
        if not member_kdl.exists():
            raise MilpaError(
                WS_MEMBER_NO_MANIFEST,
                f"workspace member {rel_path!r} has no milpa.kdl at {abs_dir}",
                member=rel_path,
                path=str(abs_dir),
            )

        member_text = _read_text(
            member_kdl, WS_MEMBER_NO_MANIFEST, WS_MEMBER_NO_MANIFEST
        )
        member_doc = parse_workspace_or_manifest(member_text)

        if isinstance(member_doc, WorkspaceManifest):
            raise MilpaError(
                WS_MEMBER_IS_WORKSPACE,
                f"workspace member {rel_path!r} is itself a workspace; "
                f"nested workspaces are not supported",
                member=rel_path,
                path=str(member_kdl),
            )

        assert isinstance(member_doc, Manifest)
        member_manifest = member_doc

        if member_manifest.overrides:
            raise MilpaError(
                WS_MEMBER_HAS_OVERRIDES,
                f"workspace member {rel_path!r} declares its own overrides block; "
                f"per-member overrides are not supported",
                member=rel_path,
                path=str(member_kdl),
            )

        name = member_manifest.name
        if name in seen_names:
            raise MilpaError(
                WS_MEMBER_DUPLICATE_NAME,
                f"workspace members {seen_names[name]!r} and {rel_path!r} "
                f"both declare package name {name!r}",
                member=rel_path,
                name=name,
                existing_member=seen_names[name],
            )
        seen_names[name] = rel_path

        members.append(LoadedMember(
            rel_path=rel_path,
            abs_dir=abs_dir,
            manifest=member_manifest,
        ))

    _warn_orphan_members(workspace_root, declared_abs)

    return LoadedWorkspace(
        root_dir=workspace_root,
        workspace_manifest=ws_manifest,
        members=tuple(members),
    )


# ---------------------------------------------------------------------------
# Public: load_workspace_with_member_override
# ---------------------------------------------------------------------------


def load_workspace_with_member_override(
    workspace: LoadedWorkspace,
    member_dir: Path,
    proposed_manifest: Manifest,
) -> LoadedWorkspace:
    """Return a new ``LoadedWorkspace`` with one member's manifest replaced.

    S11e (RFC: workspace-completion §3.G / D5): used by ``add``/``remove``
    invoked from a member dir to build the proposed workspace for resolution
    *before* any on-disk write.  The resolver sees the updated member manifest
    while the workspace topology (root, other members) remains unchanged.

    Parameters
    ----------
    workspace:
        The current loaded workspace (from disk).
    member_dir:
        The absolute path of the member whose manifest is being replaced.
        Must match one of ``workspace.members[i].abs_dir``.
    proposed_manifest:
        The in-memory manifest to substitute for that member.

    Returns
    -------
    LoadedWorkspace
        Structurally identical to ``workspace`` except the matching member's
        ``manifest`` field is replaced with ``proposed_manifest``.

    Raises
    ------
    AssertionError
        If ``member_dir`` (resolved) does not match any declared member.
    """
    member_dir_resolved = member_dir.resolve()
    new_members: list[LoadedMember] = []
    found = False
    for m in workspace.members:
        if m.abs_dir == member_dir_resolved:
            new_members.append(LoadedMember(
                rel_path=m.rel_path,
                abs_dir=m.abs_dir,
                manifest=proposed_manifest,
            ))
            found = True
        else:
            new_members.append(m)
    if not found:
        raise MilpaError(
            WS_MEMBER_DIR_MISSING,
            f"load_workspace_with_member_override: member dir {member_dir_resolved} "
            f"not found in workspace members",
            path=str(member_dir_resolved),
        )
    return LoadedWorkspace(
        root_dir=workspace.root_dir,
        workspace_manifest=workspace.workspace_manifest,
        members=tuple(new_members),
    )


# ---------------------------------------------------------------------------
# Public: find_workspace_root
# ---------------------------------------------------------------------------


def find_workspace_root(start_dir: Path) -> LoadedWorkspace | None:
    """Walk up the filesystem from ``start_dir`` looking for a workspace root.

    Implements the parent-traversal algorithm from cli-contract.md §7.1:

    1. Start from ``start_dir`` (should be absolute).
    2. Walk up one level at a time.
    3. At each level, look for ``milpa.kdl``:
       - Parse failure → treat as absent; continue upward.
       - Package manifest → transparent; continue upward.
       - Workspace manifest → this is the workspace root; stop.
    4. Filesystem root reached → return ``None``.

    After finding a workspace root:
    5. Load the workspace via ``load_workspace``.
    6. Verify that ``start_dir`` is either the workspace root itself OR the
       resolved directory of one of the declared members.  If neither →
       return ``None`` (the workspace does not legitimately contain ``start_dir``).

    Returns ``None`` if no workspace is found (single-package mode is active).
    Any ``MilpaError`` from loading the workspace propagates to the caller.
    """
    current = start_dir.resolve()
    start_resolved = current

    while True:
        kdl_path = current / "milpa.kdl"
        if kdl_path.exists():
            try:
                text = kdl_path.read_text(encoding="utf-8", errors="replace")
                doc = parse_workspace_or_manifest(text)
            except OSError:
                # I/O error → treat as absent; continue upward.
                doc = None
            except MilpaError as exc:
                # Workspace-semantic errors (MAN-WORKSPACE-*) mean the document
                # IS a workspace manifest but is semantically invalid. These MUST
                # propagate — treating them as "absent" would silently skip the
                # error and produce a confusing failure downstream.
                # All other MilpaErrors (MAN-KDL-SYNTAX, MAN-UNKNOWN-TOP-LEVEL,
                # etc.) are treated as "absent" during the ancestor walk — those
                # files are not workspace manifests (they fail at the KDL or
                # generic manifest level, not the workspace-grammar level).
                if exc.slug.startswith("MAN-WORKSPACE-"):
                    raise
                doc = None

            if isinstance(doc, WorkspaceManifest):
                # Found the workspace root.
                ws = load_workspace(current)

                # Check membership: start_dir must be the root or a declared member.
                if start_resolved == current:
                    return ws

                for member in ws.members:
                    if start_resolved == member.abs_dir:
                        return ws

                # The workspace doesn't declare start_dir as a member.
                return None

            # Package manifest or None → transparent; continue upward.

        parent = current.parent
        if parent == current:
            # Filesystem root reached.
            return None
        current = parent


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _read_text(path: Path, not_found_slug: str, unreadable_slug: str) -> str:
    """Read a text file, raising ``MilpaError`` on I/O failure.

    ``not_found_slug`` is used for ``FileNotFoundError``; ``unreadable_slug``
    for other ``OSError`` (permissions, encoding issues, etc.).
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise MilpaError(
            not_found_slug,
            f"file not found: {path}",
            path=str(path),
        ) from exc
    except OSError as exc:
        raise MilpaError(
            unreadable_slug,
            f"cannot read {path}: {exc}",
            path=str(path),
        ) from exc


def _load_nimble_file(path: Path) -> str:
    """Read a ``.nimble`` file from disk, raising ``MilpaError`` on I/O failure.

    This is the canonical file-I/O boundary for ``.nimble`` files.  All I/O
    failures are raised as ``MilpaError`` (``NIMBLE-FILE-NOT-FOUND`` /
    ``NIMBLE-FILE-UNREADABLE``) — no ``NimbleParseError``, no bare ``OSError``.

    The read content is returned as a string; parsing is the caller's job
    (call ``nimble.parse_nimble(text)`` on the result).
    """
    return _read_text(path, NIMBLE_FILE_NOT_FOUND, NIMBLE_FILE_UNREADABLE)


def _manifest_from_nimble(
    nimble: NimbleManifest,
    project_dir: Path,
    nimble_path: Path,
) -> Manifest:
    """Convert a ``NimbleManifest`` into a ``Manifest`` (best-effort).

    The package name is derived from the ``.nimble`` filename (stem).
    The ``src_dir`` is taken from the scanner output.  All other fields
    default to empty/package-library defaults.
    """
    name = nimble_path.stem  # e.g. "chronos" from "chronos.nimble"
    return Manifest(
        name=name,
        deps=nimble.deps,
        kind="library",
        src_dir=nimble.src_dir or "",
    )


def _warn_orphan_members(workspace_root: Path, declared_abs: set[Path]) -> None:
    """Emit a warning for each depth-1 subdir with a ``milpa.kdl`` not declared.

    cli-contract.md §7.1: the warning MUST be emitted to stderr but MUST NOT
    cause the workspace load to fail.

    Walk depth-1 subdirectories of ``workspace_root``.  For each one that
    contains a ``milpa.kdl`` but whose resolved absolute path is NOT in
    ``declared_abs``, emit the warning.
    """
    try:
        children = list(workspace_root.iterdir())
    except OSError:
        return

    for child in sorted(children):
        if not child.is_dir():
            continue
        candidate_kdl = child / "milpa.kdl"
        if not candidate_kdl.exists():
            continue
        abs_child = child.resolve()
        if abs_child not in declared_abs:
            rel = child.relative_to(workspace_root)
            print(
                f"warning: {rel}/milpa.kdl exists but is not declared as a workspace member\n"
                f"         (add `member \"{rel}\"` to the workspace block to include it)",
                file=sys.stderr,
            )
