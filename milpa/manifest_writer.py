"""Manifest writer + mutation orchestration (#15).

format_manifest already handles Manifest → text. This module adds:

  - write_manifest(m, path)         — atomic file write (temp + rename)
  - mutate_manifest_file(path, fn)  — read-modify-write with comment reporting
  - apply_manifest_change(...)      — canonical validate → mutate → relock

The orchestration helper (apply_manifest_change) is the layer the CLI
commands use; lower layers exist for niche use + tests.

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


def apply_manifest_change(
    project_dir: Path,
    *,
    validate: Callable[[], None],
    mutate: Callable[[Manifest], Manifest],
    relock: Callable[[Path], None] | None,
) -> WriteResult:
    """Canonical orchestration for any command that edits milpa.kdl.

    Sequence:
      1. validate()  — raises if the change isn't safe to apply
      2. mutate      — atomic read-modify-write of milpa.kdl
      3. relock      — refresh milpa.lock to match the new manifest
                       (pass None to skip; default callers always relock)

    The relock callback is parameterized so workspace- or test-specific
    flows can substitute their own re-resolution. Production CLI
    commands pass cmd_lock.
    """
    validate()
    result = mutate_manifest_file(project_dir / "milpa.kdl", mutate)
    if relock is not None:
        relock(project_dir)
    return result


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
