"""milpa manifest writer — atomic mutation of milpa.kdl.

Slice 10d per docs/rfc-python-clean-room-rewrite.md.

Provides:
  ``mutate_manifest_file(path, mutator)`` — read milpa.kdl, apply a pure
      ``Manifest → Manifest`` transform, then write the canonical re-render
      atomically.  ``format_manifest`` is the SSOT serializer; this module
      does ZERO KDL-AST construction — it handles file I/O only.

  ``WriteResult`` — what a mutation did to disk.

Atomic write contract (cli-contract.md §5.6):
  Writes are performed via a sibling tmp file + ``os.replace()``.  A
  mid-write kill leaves the file unmodified.

Comment-dropped warning:
  Detected by ``format_manifest`` via ``Manifest.had_comments`` — the warning
  is emitted to stderr by ``format_manifest`` itself (§3), not by this module.

Refuses:
  - Missing file → ``MAN-MUTATE-FILE-NOT-FOUND``
  - ``.nimble`` file → ``MAN-MUTATE-NIMBLE-REFUSED``
  - Workspace manifest → ``MAN-MUTATE-WORKSPACE-REFUSED``
  - Malformed manifest → the ``MAN-*`` parse code surfaces unchanged.

Spec authority: spec/cli-contract.md §5.6, spec/manifest-grammar.md §8.
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
