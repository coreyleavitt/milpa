"""Workspace discovery + structural validation.

Two layers:

  Discovery (mechanical):
    find_workspace_root(start_dir) -> Path | None
        Walk up from start_dir looking for a milpa.kdl that is a
        workspace manifest. Returns the directory containing it, or
        None if no workspace ancestor exists. Package milpa.kdls
        encountered along the way do NOT terminate discovery —
        members carry their own package manifest, so terminating on
        them would prevent finding the workspace above.

  Validation (structural):
    load_workspace(root) -> Workspace
        Loads the workspace manifest at `root`, plus each declared
        member's manifest. Returns a fully-validated Workspace value
        with LoadedMember entries. Raises WorkspaceError on topology
        problems (missing member dir, no name, nested workspace,
        duplicate names, member ".", etc.). Member-manifest parse
        errors propagate as ManifestError with the member path in
        the message.

  Composition (CLI use case):
    workspace_containing(start_dir) -> Workspace | None
        find_workspace_root + load_workspace, AND verify start_dir
        is either the workspace root or one of its declared members.
        Returns the loaded Workspace if so; None otherwise. The
        membership check guards against the "random milpa.kdl up
        the tree claims my dir" edge case.

See #25 (umbrella) and W2 (#74).
"""

import sys
from dataclasses import dataclass
from pathlib import Path

from .manifest import (
    Manifest,
    ManifestError,
    Override,
    WorkspaceManifest,
    kdl_has_workspace_block,
    parse_workspace_or_manifest,
)


class WorkspaceError(Exception):
    """Raised for workspace-level structural problems: missing member
    directory, no name on a member, nested workspace, duplicate member
    names, etc.

    Distinct from ManifestError (which signals grammar problems with
    a single file) — workspace topology is its own concern.
    """

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LoadedMember:
    """A workspace member as it actually exists on disk.

    - `name`: from the member's milpa.kdl (intrinsic identity)
    - `path`: as-declared workspace-relative string (preserved for
      lockfile portability per W3)
    - `directory`: absolute resolved path (for filesystem ops)
    - `manifest`: the loaded package Manifest

    Both `path` and `directory` are kept; `directory` is derivable
    (`root / path` then .resolve()) but `path` is the workspace-level
    truth and isn't recoverable from `directory` alone.
    """
    name: str
    path: str
    directory: Path
    manifest: Manifest


@dataclass(frozen=True)
class Workspace:
    """A loaded, fully-validated workspace."""
    root: Path
    members: tuple[LoadedMember, ...]
    overrides: tuple[Override, ...] = ()


def find_workspace_root(start_dir: Path) -> Path | None:
    """Walk up from start_dir looking for a workspace milpa.kdl.

    Package milpa.kdls along the way are transparent — discovery
    continues past them. This lets `find_workspace_root` called from
    a member directory walk up past the member's own manifest to find
    the workspace root above.

    Returns the directory containing the workspace milpa.kdl, or None
    if no workspace ancestor exists (search terminates at the
    filesystem root).
    """
    current = start_dir.resolve()
    while True:
        candidate = current / "milpa.kdl"
        if candidate.exists():
            text = candidate.read_text()
            if kdl_has_workspace_block(text):
                # The file is workspace-shaped. Parse it fully — any
                # ManifestError here is a real schema violation in a
                # workspace manifest and MUST propagate (not be swallowed).
                parsed = parse_workspace_or_manifest(text)
                if isinstance(parsed, WorkspaceManifest):
                    return current
            # Not workspace-shaped (no workspace block, or KDL syntax error)
            # — treat as absent for discovery purposes and keep walking.
        parent = current.parent
        if parent == current:
            return None
        current = parent


def load_workspace(root: Path) -> Workspace:
    """Load and structurally validate the workspace at `root`.

    Reads `<root>/milpa.kdl` as a workspace manifest, then for each
    declared member loads its package manifest from
    `<root>/<member-path>/milpa.kdl`. Returns a Workspace with
    LoadedMember entries in declaration order.

    Raises WorkspaceError on structural problems; ManifestError
    propagates from underlying parse failures with member-path context.
    """
    root = root.resolve()
    workspace_kdl = root / "milpa.kdl"
    if not workspace_kdl.exists():
        raise WorkspaceError(
            f"no milpa.kdl at workspace root {root}",
            code="WS-NO-MANIFEST",
        )
    parsed = parse_workspace_or_manifest(workspace_kdl.read_text())
    if not isinstance(parsed, WorkspaceManifest):
        raise WorkspaceError(
            f"{workspace_kdl} is a package manifest, not a workspace",
            code="WS-NOT-A-WORKSPACE",
        )

    loaded: list[LoadedMember] = []
    name_to_path: dict[str, str] = {}
    for member_path in parsed.members:
        if member_path == ".":
            raise WorkspaceError(
                'member "." is not supported under virtual-workspace-only '
                '— the workspace root is a pure container and cannot also '
                'be a package. To make a package the workspace root, '
                'place it in a subdirectory and list that subdirectory '
                'as the member.',
                code="WS-MEMBER-DOT",
            )
        member_dir = (root / member_path).resolve()
        if not member_dir.is_dir():
            raise WorkspaceError(
                f"workspace member {member_path!r} has no directory at "
                f"{member_dir}",
                code="WS-MEMBER-DIR-MISSING",
            )
        member_kdl = member_dir / "milpa.kdl"
        if not member_kdl.exists():
            raise WorkspaceError(
                f"workspace member {member_path!r} has no milpa.kdl at "
                f"{member_kdl}",
                code="WS-MEMBER-NO-MANIFEST",
            )
        member_text = member_kdl.read_text()
        member_parsed = parse_workspace_or_manifest(member_text)
        if isinstance(member_parsed, WorkspaceManifest):
            raise WorkspaceError(
                f"workspace member {member_path!r} is itself a workspace "
                f"— nested workspaces are not supported",
                code="WS-MEMBER-IS-WORKSPACE",
            )
        if member_parsed.overrides:
            raise WorkspaceError(
                f"workspace member {member_parsed.name!r} declares its own "
                f"`overrides` block — per-member overrides are not supported "
                f"in v1; overrides may only appear at the workspace root",
                code="WS-MEMBER-HAS-OVERRIDES",
            )
        if member_parsed.name in name_to_path:
            other = name_to_path[member_parsed.name]
            raise WorkspaceError(
                f"workspace has two members claiming name "
                f"{member_parsed.name!r}: {other!r} and {member_path!r}",
                code="WS-MEMBER-DUPLICATE-NAME",
            )
        name_to_path[member_parsed.name] = member_path
        loaded.append(LoadedMember(
            name=member_parsed.name,
            path=member_path,
            directory=member_dir,
            manifest=member_parsed,
        ))

    _warn_orphan_members(root, loaded)

    return Workspace(
        root=root,
        members=tuple(loaded),
        overrides=parsed.overrides,
    )


def workspace_containing(start_dir: Path) -> Workspace | None:
    """Return the Workspace that legitimately contains start_dir, or
    None.

    Composes `find_workspace_root` and `load_workspace`, then verifies
    that start_dir is EITHER the workspace root itself OR exactly the
    directory of one of its declared members. This membership check
    is what guards against the "random workspace ancestor accidentally
    owns me" scenario — discovery is mechanical (walks past package
    manifests), so the load-time membership check is where
    correctness lives.
    """
    root = find_workspace_root(start_dir)
    if root is None:
        return None
    ws = load_workspace(root)
    target = start_dir.resolve()
    if target == ws.root:
        return ws
    if any(m.directory == target for m in ws.members):
        return ws
    return None


def _warn_orphan_members(root: Path, loaded: list[LoadedMember]) -> None:
    """Scan depth-1 children of root for directories containing
    milpa.kdl that are NOT in the loaded member list. Print a warning
    line to stderr per orphan. Non-fatal — workspace still loads."""
    declared_dirs = {m.directory for m in loaded}
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if not (child / "milpa.kdl").exists():
            continue
        if child.resolve() in declared_dirs:
            continue
        rel = child.relative_to(root)
        print(
            f"warning: {rel}/milpa.kdl exists but is not declared as a "
            f"workspace member (add `member \"{rel}\"` to the workspace "
            f"block to include it)",
            file=sys.stderr,
        )
