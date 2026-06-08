"""Filesystem helpers shared across modules that materialize trees.

Single source of truth for the "clear a stale destination" operation
([[feedback_audit_for_duplication]]). Several call sites need to make a
path ready to be (re)written — the CAS linker, the local fetcher's
copytree, the multi-provenance fall-through cleanup. Each must handle
three distinct on-disk shapes, and a symlink-to-directory is the case
that catches naive code: `Path.exists()` follows the link (so the path
looks present) but `shutil.rmtree` refuses a symlink, so a guard of
`if dest.exists(): shutil.rmtree(dest)` raises `OSError("Cannot call
rmtree on a symbolic link")` (CPython 3.14). See milpa #112.
"""

import shutil
from pathlib import Path


def clear_dest(dest: Path) -> None:
    """Remove `dest` if it exists, leaving its parent intact.

    Handles all three shapes a stale entry can take:
      - symlink (including symlink-to-directory): unlinked, never
        followed — we must not rmtree through a symlink into whatever
        it points at (e.g. a CAS entry).
      - regular file: unlinked.
      - directory: removed recursively.

    The symlink check comes first because for a symlink-to-directory
    both `is_symlink()` and `is_dir()` are True, and rmtree on it would
    raise (and, if forced, would delete the link target's contents).

    No-op if `dest` does not exist. Not idempotent against concurrent
    mutation — callers hold the relevant per-dest invariant.
    """
    if dest.is_symlink() or dest.is_file():
        dest.unlink()
    elif dest.is_dir():
        shutil.rmtree(dest)
