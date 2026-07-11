"""Shared atomic-write/read primitives for content-addressed / cache stores.

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

This module also holds the read-side counterpart, ``read_verified_or_self_heal``:
the CACHED-read self-heal pattern (CR16) — "on a cache hit, verify; if the
cached bytes are locally corrupt, discard the file and report a cache miss
so the caller re-fetches" — shared by both ``HttpDepDeclStore`` and
``HttpEntryBundleStore``. This is the read-side twin of the write-side unify
above: same duplication discipline, same two call sites.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path
from typing import Callable

from milpa.errors import MilpaError


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


def read_verified_or_self_heal(
    cache_path: Path, verify_fn: "Callable[[bytes], None]"
) -> "bytes | None":
    """Read+verify a cached file, self-healing a locally-corrupt entry.

    This is the SHARED cached-read half of the fetch-or-cache pattern (the
    write half is ``atomic_write_bytes`` above). Both ``HttpDepDeclStore``
    and ``HttpEntryBundleStore`` fetch-or-cache an immutable, hash-pinned
    artifact; both need the identical cached-read behavior, so it lives here
    once (CR16).

    Behavior:
        - Cache miss (file absent, or unreadable with ``OSError``) → ``None``
          (caller falls through to fetch).
        - Cache hit, ``verify_fn(bytes)`` raises → the file is a locally
          corrupt entry (e.g. a truncated write left behind by the
          pre-unique-temp-name concurrency race, or plain disk corruption).
          Self-heal: unlink it and return ``None`` so the caller re-fetches,
          rather than a permanent hard failure.
        - Cache hit, ``verify_fn(bytes)`` succeeds → the verified bytes.

    CRITICAL INVARIANT: self-heal applies ONLY to this cached-read path. A
    verify failure on bytes the caller just fetched fresh from the network
    (the server genuinely served the wrong content) MUST NOT go through this
    function — that call site invokes ``verify_fn`` directly and lets the
    exception propagate as a hard error. Routing freshly-fetched bytes
    through this function would silently discard evidence of a real
    delivery-path/server compromise.
    """
    try:
        cached_bytes = cache_path.read_bytes()
    except OSError:
        return None  # cache miss: absent, or unreadable — fall through to fetch
    try:
        verify_fn(cached_bytes)
    except MilpaError:
        # Locally-corrupt cache entry: self-heal by discarding it.
        with contextlib.suppress(OSError):
            cache_path.unlink(missing_ok=True)
        return None
    return cached_bytes
