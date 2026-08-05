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
    by hash (no TTL).  Uses ``bounded_http.request`` (same native transport
    as ``index_cache.py`` / ``dep_decl_store.py``) — no bespoke network
    machinery.

Extraction (RFC §7 "an extraction owed under the §6 extract-or-decline
discipline", issue #201): ``HttpEntryBundleStore`` is a thin instantiation
of ``dep_decl_store.ContentAddressedHttpArtifactStore`` — the fetch-or-cache
+ hash-verify shape it shares with ``HttpDepDeclStore`` lives there once now
(CLAUDE.md: "Duplicate code paths are bugs ... unify them"). The mock-gated
``FileEntryBundleStore`` variant is P3a's actual deliverable per RFC §7
("P3a's mockable acquisition surface IS this store's file-backed variant")
and is untouched by the extraction — it never duplicated HTTP-store logic.

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

from milpa.dep_decl_store import ContentAddressedHttpArtifactStore
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
#:
#: Enforcement: the transport (``bounded_http.request``, RFC docs/rfc-native-
#: oci-fetch.md §3.3) streams the body and rejects as soon as the cumulative
#: byte count exceeds the cap.  A pre-flight Content-Length-header early
#: reject was possible under the old direct ``urllib.request.urlopen`` call;
#: ``bounded_http.request`` is a single atomic ``(cap, sink)`` call with no
#: header-peek hook, so that optimization is gone (NAMED behavior change,
#: mirrors dep_decl_store.py's identical change — see
#: test_http_store_lying_content_length_no_longer_pre_rejected).  The
#: actual-bytes-cap enforcement, and therefore the security property, is
#: unchanged.
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


def _entry_bundle_fetch_failed_error(bundle_pin: str, artifact_url: str, detail: str) -> MilpaError:
    """Build the ``TNG-ENTRY-BUNDLE-MISSING`` error for a fetch failure.

    Passed to ``ContentAddressedHttpArtifactStore`` as
    ``make_fetch_failed_error`` (mirrors ``dep_decl_store._dep_decl_fetch_
    failed_error``) — this is the ONE place that builds this error,
    regardless of whether the failure was a transport exception, a cap
    breach, or an HTTP error status (``detail`` carries the specifics).
    """
    return MilpaError(
        TNG_ENTRY_BUNDLE_MISSING,
        f"failed to fetch attestation bundle from {artifact_url!r}: {detail}",
        pin=bundle_pin,
        url=artifact_url,
        cause="unfetchable",
    )


class HttpEntryBundleStore:
    """Production entry-bundle store: fetch from HTTP + immutable cache.

    Artifact URL = ``<base_url>/attestation/<sha256_hex>.bundle`` (RFC §7).
    Cache is ``<cache_dir>/<sha256_hex>.bundle`` — immutable forever, no TTL.

    Cache writes are atomic (tmp-sibling + ``os.replace``), mirroring
    ``HttpDepDeclStore``.  Concurrent readers never observe a partial write.

    Transport: ``bounded_http.request`` (RFC docs/rfc-native-oci-fetch.md
    §3.3 — the single native in-process transport every consumer HTTP call
    site converges on; same primitive as ``index_cache.py`` /
    ``dep_decl_store.py``).  Supports ``http://``, ``https://``, and
    ``file://`` schemes.
    """

    def __init__(self, base_url: str, cache_dir: Path | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._cache_dir = (
            cache_dir if cache_dir is not None else _default_entry_bundle_cache_dir()
        )
        self._core = ContentAddressedHttpArtifactStore(
            self._base_url,
            self._cache_dir,
            subpath="attestation",
            extension=".bundle",
            max_bytes=_ENTRY_BUNDLE_MAX_ARTIFACT_BYTES,
            verify=_verify,
            make_fetch_failed_error=_entry_bundle_fetch_failed_error,
        )

    def get(self, bundle_pin: str) -> bytes:
        """Fetch bundle bytes (cache-first), verify hash, return bytes.

        Raises:
            MilpaError(TNG-ENTRY-BUNDLE-MISSING): Network / file error (cause=unfetchable).
            MilpaError(TNG-ENTRY-BUNDLE-PIN-MISMATCH): Hash mismatch.
        """
        return self._core.get(bundle_pin)

    def is_cached(self, bundle_pin: str) -> bool:
        """Return True iff the bundle is in the local cache (no network)."""
        return self._core.is_cached(bundle_pin)


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
