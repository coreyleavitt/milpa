"""Manifest writer + mutation orchestration (#15, #16).

format_manifest already handles Manifest → text. This module adds:

  - write_manifest(m, path)              — atomic file write (temp + rename)
  - mutate_manifest_file(path, fn)       — read-modify-write with comment reporting
  - apply_manifest_change_with_resolve(...) — resolve-first orchestration:
      run a full resolve on the proposed manifest; only if resolution
      succeeds, atomically commit manifest + lockfile. cargo/uv-shape
      transaction. Single canonical entry point for every command that
      edits milpa.kdl (cmd_add, cmd_add_mirror, future cmd_remove, etc.).

Trivia preservation is out of scope here — see #80 for the Python-
specific limitation. Mutations DROP comments; callers warn the user
via WriteResult.comments_lost.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .manifest import Manifest, ManifestError, format_manifest, parse_manifest


@dataclass(frozen=True)
class WriteResult:
    """Outcome of a manifest mutation. `comments_lost` is the count of
    // comments present in the source but absent from the output —
    callers should warn the user when nonzero (#80 tracks the
    Python-specific gap)."""
    path: Path
    comments_lost: int


def write_manifest(m: Manifest, path: Path) -> Path:
    """Write `m` to `path` atomically.

    Parent directory is auto-created. The write is staged via a temp
    file in the same directory and committed via os.replace (POSIX
    rename semantics — also atomic on Windows). Returns the path.
    """
    text = format_manifest(m)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    try:
        os.replace(tmp, path)
    except BaseException:
        if tmp.exists():
            tmp.unlink()
        raise
    return path


def mutate_manifest_file(
    path: Path,
    mutator: Callable[[Manifest], Manifest],
) -> WriteResult:
    """Read milpa.kdl at `path`, apply `mutator`, write the result
    atomically. Returns a WriteResult describing what changed on disk.

    Comments in the source file are LOST on rewrite (#80 tracks the
    upstream limitation in kdl-py). WriteResult.comments_lost lets
    callers surface this to the user.
    """
    if not path.exists():
        raise ManifestError(
            f"manifest file not found: {path} — "
            f"create a milpa.kdl before mutating"
        )
    if path.suffix == ".nimble":
        raise ManifestError(
            f"refusing to mutate a .nimble file ({path}); "
            f"promote to milpa.kdl first (`milpa init` — TBD)"
        )
    text = path.read_text()
    if "workspace" in text and _has_workspace_block(text):
        raise ManifestError(
            f"{path}: workspace manifests are pure containers and "
            f"cannot be mutated by this helper"
        )
    m = parse_manifest(text)
    new_m = mutator(m)
    before_comments = _count_line_comments(text)
    write_manifest(new_m, path)
    after_comments = _count_line_comments(path.read_text())
    lost = max(0, before_comments - after_comments)
    return WriteResult(path=path, comments_lost=lost)


def apply_manifest_change_with_resolve(
    project_dir: Path,
    *,
    proposed_manifest: Manifest,
    fetcher,                              # FetcherRegistry
    list_tags,                            # Callable[[str], list[str]]
    registry_loader,                      # cache_path → registry dict
    strategy,                             # Strategy enum
    pre_resolve_validate: "Callable[[], None] | None" = None,
) -> WriteResult:
    """Resolve proposed_manifest in full; on success atomically commit
    milpa.kdl and milpa.lock.

    Sequence:
      1. pre_resolve_validate() (optional) — transport-specific checks
         that the resolver won't do (e.g., probe a mirror URL).
      2. resolve(proposed_manifest) — full graph including any new dep.
         If resolution raises, NEITHER file is written.
      3. Atomic commit: write milpa.lock first, then milpa.kdl.
         Lockfile-first ordering means a mid-sequence crash leaves a
         self-healing state — next `milpa fetch` sees a lockfile
         "ahead" of the manifest and runs slow path to reconcile.

    Single point of orchestration for every manifest mutation that
    changes resolution: cmd_add, cmd_add_mirror, future cmd_remove,
    cmd_update, etc.
    """
    from .lockfile import from_graph, load_lockfile, write_lockfile
    from .resolver import resolve

    if pre_resolve_validate is not None:
        pre_resolve_validate()

    # Pick up the prior lockfile (if any) so existing deps inherit
    # identity-pin protection during the proposed-manifest resolve.
    # New deps in the proposed manifest have no entry yet — no pin
    # is enforced for them (consistent with _pin_for_*_dep returning
    # None when the name isn't in the lockfile).
    prior_lockfile_path = project_dir / "milpa.lock"
    prior_lockfile = None
    if prior_lockfile_path.exists():
        try:
            prior_lockfile = load_lockfile(prior_lockfile_path)
        except Exception:
            prior_lockfile = None

    deps_dir = project_dir / "_deps"
    deps_dir.mkdir(parents=True, exist_ok=True)
    cache_path = deps_dir / ".packages_official.json"
    registry = registry_loader(cache_path=cache_path)

    graph = resolve(
        proposed_manifest,
        deps_dir=deps_dir,
        registry=registry,
        fetcher=fetcher,
        list_tags=list_tags,
        strategy=strategy,
        prior_lockfile=prior_lockfile,
    )
    new_lockfile = from_graph(graph, strategy=str(strategy))

    write_lockfile(new_lockfile, project_dir / "milpa.lock")
    return _commit_manifest(project_dir / "milpa.kdl", proposed_manifest)


def _commit_manifest(path: Path, m: Manifest) -> WriteResult:
    """Write a manifest atomically; report comment loss vs prior text
    if file existed."""
    before_comments = 0
    if path.exists():
        before_comments = _count_line_comments(path.read_text())
    write_manifest(m, path)
    after_comments = _count_line_comments(path.read_text())
    return WriteResult(path=path, comments_lost=max(0, before_comments - after_comments))


def _count_line_comments(text: str) -> int:
    """Count line-comment lines (// or #) — naive line scan. Block
    comments (/* */) are ignored; they're rare in milpa manifests
    and out of scope for the warning surface (#80)."""
    n = 0
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("#"):
            n += 1
    return n


def _has_workspace_block(text: str) -> bool:
    """Cheap pre-parse detector — true if the source declares a
    `workspace { ... }` block at the top level."""
    import kdl
    try:
        doc = kdl.parse(text)
    except Exception:
        return False
    return any(node.name == "workspace" for node in doc.nodes)
