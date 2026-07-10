"""Shared atomic-write primitives for content-addressed / cache stores.

Single source of truth for the per-write-unique-temp-name write pattern used
by every fetch-or-cache store in milpa: ``index_cache.py`` (index + bundle +
baseline sidecars), ``dep_decl_store.py`` (``HttpDepDeclStore``), and
``entry_bundle_store.py`` (``HttpEntryBundleStore``).

spec/registry-protocol.md §3.5.2 NORMATIVE (concurrency): a FIXED temp
sibling name lets two concurrent writers interleave partial writes before
either renames — if one writer crashes mid-write, the OTHER writer's
``os.replace`` can rename a truncated/interleaved file into place. For a
content-addressed cache keyed by a hash pin, that produces a poisoned entry:
the next read fails hash verification with a hard, non-self-healing error
even though both writers were fetching genuine content. Every write in the
stores named above MUST go through this module (directly, or via
``atomic_write_bytes``) so no call site can regress to a fixed name.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path


def unique_temp_path(path: Path) -> Path:
    """A per-write-unique sibling temp path for *path* (PID + random suffix).

    Never repeats across calls (within a process, across processes) with
    overwhelming probability — see module docstring for why fixed names are
    unsafe.
    """
    return Path(f"{path}.tmp.{os.getpid()}.{secrets.token_hex(8)}")


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically (unique sibling tmp + os.replace).

    On failure the temp file is best-effort cleaned up and the original
    ``OSError`` is re-raised. Callers that want a write failure to be
    non-fatal (e.g. "the bytes were already hash-verified; a cache-write
    error shouldn't fail the whole operation") should catch ``OSError`` at
    the call site — this function always surfaces the error rather than
    silently swallowing it, so that decision stays visible at each caller.
    """
    tmp = unique_temp_path(path)
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise
