"""EntryBundleStore protocol + FileEntryBundleStore + HttpEntryBundleStore (P3a).

RFC: docs/rfc-per-entry-attestation.md §7 — per-entry Sigstore bundles are
content-addressed leaves pinned from the signed index (the second instance of
the registry's two-tier pattern: mutable signed map → immutable hash-pinned
artifacts; DepDecl was the first).

Design
------
``EntryBundleStore`` is the sealed responsibility for:
    1. Fetching bundle bytes (from disk or HTTP), keyed by the §2 ``bundle
       sha256=`` pin.
    2. Verifying ``sha256(bytes) == bundle_pin`` (the ONE hash-verify site —
       the ``TNG-DEPDECL-HASH-MISMATCH`` precedent, extended to bundles).
    3. Caching immutably, forever, no TTL (content-addressed ⇒ never changes).

This file defines:

``FileEntryBundleStore(dir: Path)``
    Selected when ``MILPA_ENTRY_BUNDLE_DIR`` is set — the mirror of
    ``MILPA_DEP_DECL_DIR`` (RFC §7).  Reads ``<dir>/<sha256_hex>.bundle`` — no
    network; still hash-verifies the bytes.  This is P3a's mockable
    bundle-acquisition surface — the file-backed variant the conformance
    fixtures and any air-gapped / local-mirror deployment use.

``HttpEntryBundleStore(base_url: str, cache_dir: Path)``
    Production.  Artifact URL = ``<base_url>/attestation/<sha256_hex>.bundle``
    (same §3.3 URL-derivation convention as ``dep-decl/``).  Caches immutably
    by hash (no TTL).  Uses the existing ``urllib`` transport (same as
    ``index_cache.py`` / ``dep_decl_store.py``) — no new network machinery.

Extract-or-decline (RFC §7 "an extraction owed under the §6 extract-or-decline
discipline"): this module intentionally DUPLICATES ``dep_decl_store.py``'s
shape (fetch-or-cache + hash-verify Protocol pair) rather than generalizing it
into one parametrized artifact store.  Decision recorded here because the RFC
names the generalization as owed: refactoring the already-battle-tested
``dep_decl_store.py`` now would risk that module for no test-coverage gain in
P3a (bundle HTTP-production correctness is untestable before P4 ships real
bundles — see RFC §5, prerequisite 1's "honest tail"). The mock-gated
``FileEntryBundleStore`` variant is P3a's actual deliverable per RFC §7
("P3a's mockable acquisition surface IS this store's file-backed variant").
Revisit the generalized extraction once both HTTP stores have real-world
mileage (P4).

Bundle bytes' size cap (4 MiB): a placeholder, not a measured-corpus figure —
no real per-entry Sigstore bundle exists yet (P4-gated).  A Sigstore bundle
(cert chain + inclusion proof + SET) is meaningfully larger than a DepDecl KDL
text (~10s of KiB), so the DepDecl cap (1 MiB) is not reused verbatim; 4 MiB
is a conservative ceiling pending real measurement at P4.

SECURITY INVARIANT (NORMATIVE):
    ``TNG-ENTRY-BUNDLE-PIN-MISMATCH`` is raised HERE and ONLY HERE, and is
    ALWAYS a hard error — never policy-gated, not even under ``entry-trust
    "warn"`` (RFC §5 NORMATIVE, mirroring the ``TNG-DEPDECL-HASH-MISMATCH``
    severity model).  ``TNG-ENTRY-BUNDLE-MISSING`` (cause ``unfetchable``) is
    raised here for fetch failures; the caller (the ``entry-trust`` gate in
    ``entry_trust.py``) applies policy to that one.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from milpa.errors import (
    TNG_ENTRY_BUNDLE_MISSING,
    TNG_ENTRY_BUNDLE_PIN_MISMATCH,
    MilpaError,
)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class EntryBundleStore(Protocol):
    """Sealed fetch-or-cache + hash-verify seam for per-entry attestation bundles.

    ``get`` is the ONE site where ``sha256(bytes) == bundle_pin`` is verified.
    Two hard-error codes can be raised here:

    ``TNG-ENTRY-BUNDLE-MISSING`` (cause ``unfetchable``)
        Bundle not found / not reachable (file missing, HTTP error).  The
        ``entry-trust`` gate applies warn/strict policy to this one.

    ``TNG-ENTRY-BUNDLE-PIN-MISMATCH``
        ``sha256(bytes) != bundle_pin`` — delivery-path tampering or serious
        infra corruption.  Always a hard error (SECURITY INVARIANT — no
        policy fallback, not even under ``warn``).

    ``is_cached(bundle_pin) -> bool`` is a local-only probe (no network); used
    by ``milpa verify``'s offline re-verification (RFC §7).
    """

    def get(self, bundle_pin: str) -> bytes: ...
    def is_cached(self, bundle_pin: str) -> bool: ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verify(bundle_bytes: bytes, bundle_pin: str) -> None:
    """Verify ``sha256(bundle_bytes) == bundle_pin``.

    This is the ONE hash-verify site (SECURITY INVARIANT).  Raises
    ``MilpaError(TNG-ENTRY-BUNDLE-PIN-MISMATCH)`` on mismatch.  ``bundle_pin``
    is bare lowercase hex (no ``sha256:`` prefix — registry.py's
    ``_parse_bundle_pin`` already validates and stores it in that form).
    """
    import hashlib

    computed = hashlib.sha256(bundle_bytes).hexdigest()
    if computed != bundle_pin:
        raise MilpaError(
            TNG_ENTRY_BUNDLE_PIN_MISMATCH,
            f"attestation bundle hash mismatch: expected {bundle_pin!r} but "
            f"computed {computed!r} — the delivery path served different "
            f"bytes than the Layer-1-verified index committed to",
            expected=bundle_pin,
            computed=computed,
        )


# ---------------------------------------------------------------------------
# FileEntryBundleStore
# ---------------------------------------------------------------------------


class FileEntryBundleStore:
    """Reads ``<dir>/<sha256_hex>.bundle`` — no network, still hash-verifies.

    Selected when ``MILPA_ENTRY_BUNDLE_DIR`` is set (the mirror of
    ``MILPA_DEP_DECL_DIR``, RFC §7).  Used by the conformance harness (P3a)
    and any air-gapped / local-mirror deployment.

    The file's bytes are hash-verified on every read (not just on first
    cache-miss) so that a corrupted local file raises
    ``TNG-ENTRY-BUNDLE-PIN-MISMATCH`` rather than being silently passed to
    the verifier.
    """

    def __init__(self, dir: Path) -> None:
        self._dir = dir

    def get(self, bundle_pin: str) -> bytes:
        """Read bundle bytes, verify hash, return bytes.

        Raises:
            MilpaError(TNG-ENTRY-BUNDLE-MISSING): File not found (cause=unfetchable).
            MilpaError(TNG-ENTRY-BUNDLE-PIN-MISMATCH): Hash mismatch (one
                verify site — SECURITY INVARIANT).
        """
        bundle_path = self._dir / f"{bundle_pin}.bundle"
        try:
            bundle_bytes = bundle_path.read_bytes()
        except FileNotFoundError:
            raise MilpaError(
                TNG_ENTRY_BUNDLE_MISSING,
                f"attestation bundle not found at {bundle_path} "
                f"(pin {bundle_pin!r}) — check MILPA_ENTRY_BUNDLE_DIR",
                pin=bundle_pin,
                path=str(bundle_path),
                cause="unfetchable",
            )
        except OSError as exc:
            raise MilpaError(
                TNG_ENTRY_BUNDLE_MISSING,
                f"attestation bundle unreadable at {bundle_path}: {exc}",
                pin=bundle_pin,
                path=str(bundle_path),
                cause="unfetchable",
            ) from exc

        _verify(bundle_bytes, bundle_pin)
        return bundle_bytes

    def is_cached(self, bundle_pin: str) -> bool:
        """Return True iff the bundle file exists locally (no network)."""
        return (self._dir / f"{bundle_pin}.bundle").is_file()


# ---------------------------------------------------------------------------
# HttpEntryBundleStore
# ---------------------------------------------------------------------------

#: Attestation-bundle cache sub-directory under ``~/.cache/milpa/``.
_ENTRY_BUNDLE_CACHE_SUBDIR = "attestation"

#: Maximum size of a per-entry attestation bundle fetched over HTTP.
#: Placeholder pending P4 real-corpus measurement — see module docstring.
_ENTRY_BUNDLE_MAX_ARTIFACT_BYTES: int = 4 * 1024 * 1024  # 4 MiB


def _default_entry_bundle_cache_dir() -> Path:
    """Return the platform-appropriate attestation-bundle cache directory.

    ``$XDG_CACHE_HOME/milpa/attestation/`` (default
    ``~/.cache/milpa/attestation/``).  Mirrors
    ``dep_decl_store._default_dep_decl_cache_dir`` with a different sub-dir
    (RFC §7: bundles are cached "alongside the index cache" but keyed by the
    bundle pin, in their own sub-directory — the store's native key).
    """
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "milpa" / _ENTRY_BUNDLE_CACHE_SUBDIR


class HttpEntryBundleStore:
    """Production entry-bundle store: fetch from HTTP + immutable cache.

    Artifact URL = ``<base_url>/attestation/<sha256_hex>.bundle`` (RFC §7).
    Cache is ``<cache_dir>/<sha256_hex>.bundle`` — immutable forever, no TTL.

    Cache writes are atomic (tmp-sibling + ``os.replace``), mirroring
    ``HttpDepDeclStore``.  Concurrent readers never observe a partial write.

    Transport: ``urllib.request.urlopen`` (same as ``index_cache.py`` /
    ``dep_decl_store.py``).  Supports ``http://``, ``https://``, and
    ``file://`` schemes.
    """

    def __init__(self, base_url: str, cache_dir: Path | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._cache_dir = (
            cache_dir if cache_dir is not None else _default_entry_bundle_cache_dir()
        )

    def _artifact_url(self, bundle_pin: str) -> str:
        return f"{self._base_url}/attestation/{bundle_pin}.bundle"

    def _cache_path(self, bundle_pin: str) -> Path:
        return self._cache_dir / f"{bundle_pin}.bundle"

    def get(self, bundle_pin: str) -> bytes:
        """Fetch bundle bytes (cache-first), verify hash, return bytes.

        Raises:
            MilpaError(TNG-ENTRY-BUNDLE-MISSING): Network / file error (cause=unfetchable).
            MilpaError(TNG-ENTRY-BUNDLE-PIN-MISMATCH): Hash mismatch.
        """
        # Cache-first (immutable: a hit is always valid; no staleness check).
        cache_path = self._cache_path(bundle_pin)
        if cache_path.is_file():
            try:
                cached_bytes = cache_path.read_bytes()
            except OSError:
                cached_bytes = None  # corrupted cache: fall through to re-fetch
            if cached_bytes is not None:
                _verify(cached_bytes, bundle_pin)
                return cached_bytes

        # Cache miss: fetch from network.
        artifact_url = self._artifact_url(bundle_pin)
        fetched_bytes: bytes
        try:
            import urllib.request

            with urllib.request.urlopen(artifact_url) as resp:  # noqa: S310
                raw_cl = resp.getheader("Content-Length") if hasattr(resp, "getheader") else None
                if raw_cl is not None:
                    try:
                        cl = int(raw_cl)
                    except ValueError:
                        cl = 0
                    if cl > _ENTRY_BUNDLE_MAX_ARTIFACT_BYTES:
                        raise MilpaError(
                            TNG_ENTRY_BUNDLE_MISSING,
                            f"attestation bundle at {artifact_url!r} advertises "
                            f"Content-Length {cl} which exceeds the "
                            f"{_ENTRY_BUNDLE_MAX_ARTIFACT_BYTES}-byte cap — "
                            f"rejecting to prevent resource exhaustion",
                            pin=bundle_pin,
                            url=artifact_url,
                            cause="unfetchable",
                        )
                buf = resp.read(_ENTRY_BUNDLE_MAX_ARTIFACT_BYTES + 1)
                if len(buf) > _ENTRY_BUNDLE_MAX_ARTIFACT_BYTES:
                    raise MilpaError(
                        TNG_ENTRY_BUNDLE_MISSING,
                        f"attestation bundle at {artifact_url!r} exceeds the "
                        f"{_ENTRY_BUNDLE_MAX_ARTIFACT_BYTES}-byte cap "
                        f"(read {len(buf)} bytes) — rejecting to prevent "
                        f"resource exhaustion",
                        pin=bundle_pin,
                        url=artifact_url,
                        cause="unfetchable",
                    )
                fetched_bytes = buf
        except MilpaError:
            raise
        except Exception as exc:
            raise MilpaError(
                TNG_ENTRY_BUNDLE_MISSING,
                f"failed to fetch attestation bundle from {artifact_url!r}: {exc}",
                pin=bundle_pin,
                url=artifact_url,
                cause="unfetchable",
            ) from exc

        # Verify before caching — don't persist a corrupt/tampered bundle.
        _verify(fetched_bytes, bundle_pin)

        # Atomic write to cache.
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = cache_path.with_suffix(".bundle.tmp")
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

    def is_cached(self, bundle_pin: str) -> bool:
        """Return True iff the bundle is in the local cache (no network)."""
        return self._cache_path(bundle_pin).is_file()


# ---------------------------------------------------------------------------
# Store selection — mirrors dep_decl_store.dep_decl_store_from_paths
# ---------------------------------------------------------------------------


def entry_bundle_store_from_paths(
    entry_bundle_dir: "Path | None",
    index_url: "str | None",
    no_index: bool = False,
) -> "FileEntryBundleStore | HttpEntryBundleStore | None":
    """Select the EntryBundleStore given resolved paths/URLs.

    Priority (mirrors ``dep_decl_store.dep_decl_store_from_paths``):

    0. ``no_index`` → ``None`` (no index ⇒ no registry-resolved deps ⇒ the
       entry-trust gate never runs).
    1. ``entry_bundle_dir`` not None and is_dir → ``FileEntryBundleStore``.
    2. ``index_url`` non-empty → ``HttpEntryBundleStore`` derived via
       ``dep_decl_store.index_base_url`` (same §3.3 URL-derivation rule).
    3. ``index_url`` is ``None`` or empty → ``None``.
    """
    if no_index:
        return None
    if entry_bundle_dir is not None and entry_bundle_dir.is_dir():
        return FileEntryBundleStore(entry_bundle_dir)
    if index_url:
        from milpa.dep_decl_store import index_base_url

        base = index_base_url(index_url)
        return HttpEntryBundleStore(base_url=base)
    return None
