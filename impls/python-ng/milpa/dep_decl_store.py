"""DepDeclStore protocol + FileDepDeclStore + HttpDepDeclStore (S3b).

spec/dep-decl.md §3.5 — fetch-or-cache + hash-verify as one sealed unit.

Design
------
``DepDeclStore`` is the single sealed responsibility for:
    1. Fetching artifact bytes (from disk or HTTP).
    2. Verifying ``sha256(bytes) == dep_decl_hash`` (the ONE hash-verify site).
    3. Caching immutably, forever, no TTL (§3.3.1 NORMATIVE).

This file defines:

``FileDepDeclStore(dir: Path)``
    Selected when ``MILPA_DEP_DECL_DIR`` is set.  Reads
    ``<dir>/<sha256_hex>.kdl`` — no network; still hash-verifies the bytes.

``HttpDepDeclStore(base_url: str, cache_dir: Path)``
    Production.  Artifact URL = ``<base_url>/dep-decl/<sha256_hex>.kdl``.
    Caches immutably by hash (no TTL).  Uses the existing ``urllib`` transport
    (same as ``index_cache.py``) — no new network machinery.

``index_base_url(milpa_index_url: str) -> str``
    §3.3 normative URL-derivation: remove last segment if it matches
    ``*.kdl`` or ``index*``; else append ``/``.

SECURITY INVARIANT (NORMATIVE):
    ``TNG-DEPDECL-HASH-MISMATCH`` and ``TNG-DEPDECL-FETCH-FAILED`` are
    raised HERE and ONLY HERE.  No caller is permitted to silently fall
    back when ``get`` raises — integrity failures are always hard errors.

Cache notes:
    - ``HttpDepDeclStore`` cache lives in a **separate** directory from the
      source-tree CAS (e.g. ``~/.cache/milpa/dep-decl/``).
    - ``milpa clean`` MUST NOT remove it (enforced by the CLI, not here).
    - No GC; entries are content-addressed, immutable, and small.

Spec authority: spec/dep-decl.md §3.5; docs/rfc-content-addressed-metadata.md
§3.3 + §3.3.1.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Protocol

from milpa.dep_decl import dep_decl_hash
from milpa.errors import (
    TNG_DEPDECL_FETCH_FAILED,
    TNG_DEPDECL_HASH_MISMATCH,
    MilpaError,
)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class DepDeclStore(Protocol):
    """Sealed fetch-or-cache + hash-verify seam for DepDecl artifacts.

    ``get`` is the ONE site where ``sha256(bytes) == dep_decl_hash`` is
    verified.  Two hard-error codes can be raised here:

    ``TNG-DEPDECL-FETCH-FAILED``
        Artifact not found / not reachable (file missing, HTTP error).
        S5 refines the policy for this code (strict vs. non-strict fallback);
        in S3b the code is always raised as a hard error from ``get``.

    ``TNG-DEPDECL-HASH-MISMATCH``
        ``sha256(bytes) != dep_decl_hash`` — bytes don't match the hash
        pointer.  Always a hard error (SECURITY INVARIANT — no fallback).

    ``is_cached(dep_decl_hash) -> bool`` is a local-only probe (no network);
    used by §3.7.2 offline-verify (S6).
    """

    def get(self, dep_decl_hash_str: str) -> bytes: ...
    def is_cached(self, dep_decl_hash_str: str) -> bool: ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hex_from_hash(dep_decl_hash_str: str) -> str:
    """Extract the lowercase-hex digest from a ``sha256:<hex>`` string.

    Raises ``ValueError`` if the string is not in the expected form.
    """
    if not dep_decl_hash_str.startswith("sha256:"):
        raise ValueError(
            f"dep_decl_hash {dep_decl_hash_str!r} does not start with 'sha256:'"
        )
    return dep_decl_hash_str[len("sha256:"):]


def _verify(artifact_bytes: bytes, dep_decl_hash_str: str) -> None:
    """Verify ``sha256(artifact_bytes) == dep_decl_hash_str``.

    This is the ONE hash-verify site (SECURITY INVARIANT).  Raises
    ``MilpaError(TNG-DEPDECL-HASH-MISMATCH)`` on mismatch.
    """
    computed = dep_decl_hash(artifact_bytes)
    if computed != dep_decl_hash_str:
        raise MilpaError(
            TNG_DEPDECL_HASH_MISMATCH,
            f"DepDecl artifact hash mismatch: expected {dep_decl_hash_str!r} "
            f"but computed {computed!r} — artifact may be corrupted or tampered",
            expected=dep_decl_hash_str,
            computed=computed,
        )


# ---------------------------------------------------------------------------
# FileDepDeclStore
# ---------------------------------------------------------------------------


class FileDepDeclStore:
    """Reads ``<dir>/<sha256_hex>.kdl`` — no network, still hash-verifies.

    Selected when ``MILPA_DEP_DECL_DIR`` is set.  Used by the conformance
    harness (S3a) and any air-gapped / local-mirror deployment.

    File naming: the stored file is named ``<sha256_hex>.kdl`` where
    ``sha256_hex`` is the 64-character lowercase hex digest extracted from
    the ``sha256:<hex>`` hash pointer.

    The file's bytes are hash-verified on every read (not just on first
    cache-miss) so that a corrupted local file raises ``HASH-MISMATCH``
    rather than being silently passed to the parser.
    """

    def __init__(self, dir: Path) -> None:
        self._dir = dir

    def get(self, dep_decl_hash_str: str) -> bytes:
        """Read artifact bytes, verify hash, return bytes.

        Raises:
            MilpaError(TNG-DEPDECL-FETCH-FAILED): File not found.
            MilpaError(TNG-DEPDECL-HASH-MISMATCH): Hash mismatch (one
                verify site — SECURITY INVARIANT).
        """
        hex_digest = _hex_from_hash(dep_decl_hash_str)
        artifact_path = self._dir / f"{hex_digest}.kdl"
        try:
            artifact_bytes = artifact_path.read_bytes()
        except FileNotFoundError:
            raise MilpaError(
                TNG_DEPDECL_FETCH_FAILED,
                f"DepDecl artifact not found at {artifact_path} "
                f"(hash {dep_decl_hash_str!r}) — check MILPA_DEP_DECL_DIR",
                hash=dep_decl_hash_str,
                path=str(artifact_path),
            )
        except OSError as exc:
            raise MilpaError(
                TNG_DEPDECL_FETCH_FAILED,
                f"DepDecl artifact unreadable at {artifact_path}: {exc}",
                hash=dep_decl_hash_str,
                path=str(artifact_path),
            ) from exc

        _verify(artifact_bytes, dep_decl_hash_str)
        return artifact_bytes

    def is_cached(self, dep_decl_hash_str: str) -> bool:
        """Return True iff the artifact file exists locally (no network)."""
        try:
            hex_digest = _hex_from_hash(dep_decl_hash_str)
        except ValueError:
            return False
        return (self._dir / f"{hex_digest}.kdl").is_file()


# ---------------------------------------------------------------------------
# HttpDepDeclStore
# ---------------------------------------------------------------------------

#: DepDecl cache sub-directory under ``~/.cache/milpa/``.
_DEP_DECL_CACHE_SUBDIR = "dep-decl"

#: Maximum size of a DepDecl artifact fetched over HTTP (§3.3.1 NORMATIVE).
#:
#: A legitimate DepDecl is KDL text with one dep_decl_schema_version, one
#: src_dir, and O(dozens) of require lines — comfortably under 10 KiB in
#: practice.  1 MiB is a generous-but-safe ceiling that admits any plausible
#: future growth while bounding the resource-exhaustion surface: a compromised
#: or misconfigured index can point dep_decl at an arbitrary URL, so we must
#: never buffer an unbounded response body.
#:
#: Enforcement:
#:   1. Content-Length header > cap → early-reject without reading the body.
#:   2. Actual read capped at (cap + 1) bytes; if we get cap+1 we know the
#:      body is oversized even when Content-Length was absent or lying.
#:
#: On exceed: raises ``TNG-DEPDECL-FETCH-FAILED`` (non-strict fallback is
#: possible; strict mode is a hard fail — same policy as other fetch failures).
_DEP_DECL_MAX_ARTIFACT_BYTES: int = 1024 * 1024  # 1 MiB


def _default_dep_decl_cache_dir() -> Path:
    """Return the platform-appropriate DepDecl cache directory.

    ``$XDG_CACHE_HOME/milpa/dep-decl/`` (default ``~/.cache/milpa/dep-decl/``).
    Mirrors ``index_cache._default_cache_dir`` with a different sub-dir so
    the two caches don't collide (spec §3.3.1 NORMATIVE: separate cache
    roots for source-tree CAS vs. DepDecl artifacts).
    """
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "milpa" / _DEP_DECL_CACHE_SUBDIR


class HttpDepDeclStore:
    """Production DepDecl store: fetch from HTTP + immutable cache.

    Artifact URL = ``<base_url>/dep-decl/<sha256_hex>.kdl``.
    Cache is ``<cache_dir>/<sha256_hex>.kdl`` — immutable forever, no TTL
    (spec §3.3.1 NORMATIVE: content-addressed artifact can never change).

    Cache writes are atomic (tmp-sibling + ``os.replace``), mirroring the
    index cache.  Concurrent readers never observe a partial write.

    OCI base URLs (``oci://…``): not supported.  If the base URL starts
    with ``oci://``, ``get`` raises ``TNG-DEPDECL-FETCH-FAILED`` with a
    clear message instructing the caller to set ``MILPA_DEP_DECL_DIR``
    (spec §3.3 NOTE on OCI).

    Transport: ``urllib.request.urlopen`` (same as ``index_cache.py``).
    No new network machinery.  Supports ``http://``, ``https://``, and
    ``file://`` (air-gapped / local-mirror) schemes.
    """

    def __init__(self, base_url: str, cache_dir: Path | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._cache_dir = cache_dir if cache_dir is not None else _default_dep_decl_cache_dir()

    def _artifact_url(self, hex_digest: str) -> str:
        return f"{self._base_url}/dep-decl/{hex_digest}.kdl"

    def _cache_path(self, hex_digest: str) -> Path:
        return self._cache_dir / f"{hex_digest}.kdl"

    def get(self, dep_decl_hash_str: str) -> bytes:
        """Fetch artifact bytes (cache-first), verify hash, return bytes.

        Cache-first: if the artifact is already cached (by hash), return it
        without any network access.  On a cache miss, fetch from the network,
        verify, write to cache, return.

        Raises:
            MilpaError(TNG-DEPDECL-FETCH-FAILED): Network / file error.
            MilpaError(TNG-DEPDECL-HASH-MISMATCH): Hash mismatch.
        """
        hex_digest = _hex_from_hash(dep_decl_hash_str)

        # OCI: not supported — direct caller to MILPA_DEP_DECL_DIR.
        if self._base_url.startswith("oci://"):
            raise MilpaError(
                TNG_DEPDECL_FETCH_FAILED,
                f"OCI index base URLs ({self._base_url!r}) do not support the "
                f"DepDecl URL template — set MILPA_DEP_DECL_DIR to a local "
                f"directory containing {hex_digest}.kdl",
                hash=dep_decl_hash_str,
                base_url=self._base_url,
            )

        # Cache-first (immutable: a hit is always valid; no staleness check).
        cache_path = self._cache_path(hex_digest)
        artifact_bytes: bytes | None = None
        if cache_path.is_file():
            try:
                artifact_bytes = cache_path.read_bytes()
            except OSError:
                artifact_bytes = None  # corrupted cache: fall through to re-fetch
            if artifact_bytes is not None:
                _verify(artifact_bytes, dep_decl_hash_str)
                return artifact_bytes

        # Cache miss: fetch from network.
        artifact_url = self._artifact_url(hex_digest)
        fetched_bytes: bytes
        try:
            import urllib.request
            with urllib.request.urlopen(artifact_url) as resp:  # noqa: S310
                # R8: Early-reject on Content-Length header (fast path; header
                # may lie, so we also cap the actual read below).
                # file:// responses return a BufferedReader with no getheader;
                # skip the header check for those (the read cap still applies).
                raw_cl = resp.getheader("Content-Length") if hasattr(resp, "getheader") else None
                if raw_cl is not None:
                    try:
                        cl = int(raw_cl)
                    except ValueError:
                        cl = 0
                    if cl > _DEP_DECL_MAX_ARTIFACT_BYTES:
                        raise MilpaError(
                            TNG_DEPDECL_FETCH_FAILED,
                            f"DepDecl artifact at {artifact_url!r} advertises "
                            f"Content-Length {cl} which exceeds the "
                            f"{_DEP_DECL_MAX_ARTIFACT_BYTES}-byte cap — "
                            f"rejecting to prevent resource exhaustion",
                            hash=dep_decl_hash_str,
                            url=artifact_url,
                        )
                # Read at most (cap + 1) bytes; if we fill the buffer the body
                # is oversized even when Content-Length was absent or lying.
                buf = resp.read(_DEP_DECL_MAX_ARTIFACT_BYTES + 1)
                if len(buf) > _DEP_DECL_MAX_ARTIFACT_BYTES:
                    raise MilpaError(
                        TNG_DEPDECL_FETCH_FAILED,
                        f"DepDecl artifact at {artifact_url!r} exceeds the "
                        f"{_DEP_DECL_MAX_ARTIFACT_BYTES}-byte cap "
                        f"(read {len(buf)} bytes) — rejecting to prevent "
                        f"resource exhaustion",
                        hash=dep_decl_hash_str,
                        url=artifact_url,
                    )
                fetched_bytes = buf
        except MilpaError:
            raise
        except Exception as exc:
            raise MilpaError(
                TNG_DEPDECL_FETCH_FAILED,
                f"Failed to fetch DepDecl artifact from {artifact_url!r}: {exc}",
                hash=dep_decl_hash_str,
                url=artifact_url,
            ) from exc

        # Verify before caching — don't persist a corrupt artifact.
        _verify(fetched_bytes, dep_decl_hash_str)

        # Atomic write to cache.
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = cache_path.with_suffix(".kdl.tmp")
        try:
            tmp_path.write_bytes(fetched_bytes)
            os.replace(tmp_path, cache_path)
        except OSError:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            # Cache write failure is non-fatal; the bytes were already verified.

        return fetched_bytes

    def is_cached(self, dep_decl_hash_str: str) -> bool:
        """Return True iff the artifact is in the local cache (no network)."""
        try:
            hex_digest = _hex_from_hash(dep_decl_hash_str)
        except ValueError:
            return False
        return self._cache_path(hex_digest).is_file()


# ---------------------------------------------------------------------------
# §3.3 URL derivation — index_base_url
# ---------------------------------------------------------------------------

#: Regex matching a KDL-file-like last segment: ``*.kdl`` or ``index*``.
_KDL_OR_INDEX_SEGMENT = re.compile(r"^(?:.*\.kdl|index.*)$", re.IGNORECASE)


def index_base_url(milpa_index_url: str) -> str:
    """Derive ``<index_base_url>`` from ``MILPA_INDEX_URL`` (§3.3 NORMATIVE).

    Rule: remove the last path segment of the URL iff that segment matches
    ``*.kdl`` or ``index*`` (case-insensitive); otherwise append ``/``.

    Examples (from the RFC):
        ``…/tianguis/main/index.kdl``  →  ``…/tianguis/main/``
        ``https://example.com/registry/v2``  →  ``https://example.com/registry/v2/``
        ``file:///home/user/conformance/index.kdl``  →  ``file:///home/user/conformance/``

    ``file://`` URIs are handled correctly: the path is extracted from the
    URI, the last segment is examined, and the result is re-composed.

    Note: The ``oci://`` scheme is NOT supported — see ``HttpDepDeclStore``
    docstring for policy.
    """
    # Split on the last ``/`` to get (prefix, last_segment).
    # Handle the edge case where the URL ends with ``/`` (no last segment).
    stripped = milpa_index_url.rstrip("/")
    slash_pos = stripped.rfind("/")
    if slash_pos == -1:
        # No slash at all — can't identify a segment; just append /.
        return milpa_index_url.rstrip("/") + "/"

    prefix = stripped[:slash_pos + 1]  # includes the trailing /
    last_segment = stripped[slash_pos + 1:]

    if _KDL_OR_INDEX_SEGMENT.match(last_segment):
        # Remove the last segment (keep prefix which includes the /).
        return prefix
    else:
        # The URL doesn't end in a KDL-filename-like segment; append /.
        return stripped + "/"


def make_dep_decl_store(milpa_index_url: str | None = None) -> "HttpDepDeclStore":
    """Build an ``HttpDepDeclStore`` from the runtime index URL.

    Reads ``MILPA_INDEX_URL`` from the environment when ``milpa_index_url``
    is not provided.  Derives ``<index_base_url>`` per §3.3.

    This is the production factory called by the CLI when
    ``MILPA_DEP_DECL_DIR`` is NOT set.
    """
    index_url = milpa_index_url or os.environ.get("MILPA_INDEX_URL", "").strip()
    if not index_url:
        from milpa.index_cache import DEFAULT_INDEX_URL
        index_url = DEFAULT_INDEX_URL
    base = index_base_url(index_url)
    return HttpDepDeclStore(base_url=base)
