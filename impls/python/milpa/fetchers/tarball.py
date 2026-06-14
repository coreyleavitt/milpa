"""TarballFetcher — download + safe_extract transport (slice 7d-3).

Downloads an archive over HTTP (injected transport seam), verifies SHA-256
if expected, extracts it via ``safe_extract``, and returns a receipt carrying
``archive_sha256`` — the TOFU first-use mechanism described in RFC S9c.

Public surface:
  - ``TarballProvenance``  — ``Provenance`` subclass for tarball deps.
  - ``TarballReceipt``     — ``ProvenanceReceipt`` carrying ``archive_sha256``.
  - ``TarballFetcher``     — ``Fetcher`` ABC implementation.
  - ``make_http_get``      — production seam: ``curl -fsSL`` backed transport.

TOFU precedence (mirrors Rust + RFC S9c):
    The receipt always carries the SHA-256 of the raw (compressed) archive
    bytes.  The resolver's ``_process_tarball`` reads ``receipt.archive_sha256``
    and records it to the lock.  On refetch with a prior lock the caller
    passes the locked hash as ``expected_sha256`` on the ``TarballProvenance``;
    a mismatch raises ``FETCH-SHA256-MISMATCH`` **before extraction**.
"""

from __future__ import annotations

import hashlib
import io
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from milpa.errors import (
    FETCH_DOWNLOAD_FAILED,
    FETCH_EXTRACT_FAILED,
    FETCH_SHA256_MISMATCH,
    MilpaError,
)
from milpa.fetchers.safe_extract import _DEFAULT_LIMITS, Limits, extract_tar
from milpa.fetchers.types import (
    Fetcher,
    Provenance,
    ProvenanceReceipt,
)

# ---------------------------------------------------------------------------
# TarballProvenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TarballProvenance(Provenance):
    """Provenance descriptor for a tarball dep.

    Fields
    ------
    url:
        HTTPS URL of the archive (``*.tar.gz``, ``*.tgz``, or plain ``.tar``).
    expected_sha256:
        When set (refetch with a prior lock), MUST match the actual archive
        sha256; raises ``FETCH-SHA256-MISMATCH`` on mismatch.  ``None`` on
        first-fetch (TOFU: the sha is *recorded* from ``receipt.archive_sha256``
        but not asserted on first use).  Accepts bare hex OR ``sha256:``-prefixed.
    strip_components:
        Equivalent to ``tar --strip-components=N``.  Silently skips entries with
        fewer than N path components.
    """

    cas_admissible: ClassVar[bool] = True

    url: str
    expected_sha256: str | None = None
    strip_components: int = 0


# ---------------------------------------------------------------------------
# TarballReceipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TarballReceipt(ProvenanceReceipt):
    """Receipt produced by a successful tarball fetch.

    ``archive_sha256`` is the hex-only SHA-256 of the **raw (compressed)
    archive bytes** — the same value gated by ``expected_sha256``.

    This field is the TOFU evidence (RFC S9c):
        - First fetch (``dep.sha256 is None``): resolver reads
          ``receipt.archive_sha256`` and persists it to the lockfile.
        - Refetch: resolver threads the locked sha back as
          ``TarballProvenance.expected_sha256``; a mismatch is caught here
          before extraction.
    """

    archive_sha256: str  # bare hex, 64 chars

    def transport_fields(self) -> dict[str, str]:
        return {"archive_sha256": self.archive_sha256}


# ---------------------------------------------------------------------------
# HttpGet seam type
# ---------------------------------------------------------------------------

#: Injected HTTP transport: maps a URL to its raw bytes or raises.
#: The callable raises ``MilpaError(FETCH_DOWNLOAD_FAILED, …)`` on failure
#: (or any exception that the fetcher re-wraps with that slug).
HttpGet = Callable[[str], bytes]


def make_http_get() -> HttpGet:
    """Return a production ``HttpGet`` backed by ``curl -fsSL``."""

    def _curl(url: str) -> bytes:
        result = subprocess.run(
            ["curl", "-fsSL", url],
            capture_output=True,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise MilpaError(
                FETCH_DOWNLOAD_FAILED,
                f"curl failed for {url!r}: {detail}",
                url=url,
            )
        return result.stdout

    return _curl


# ---------------------------------------------------------------------------
# TarballFetcher
# ---------------------------------------------------------------------------


class TarballFetcher(Fetcher):
    """Download + safe-extract fetcher for tarball deps (slice 7d-3).

    The network transport is injected via ``http_get`` so tests need no
    network.  The production transport is ``make_http_get()``.

    Protocol (plugin-contract.md §1):
        1. ``can_handle`` → True for ``TarballProvenance``.
        2. ``fetch``      → download archive, verify optional SHA-256,
                            extract to ``dest/``, return ``TarballReceipt``.
        3. Receipt carries ``archive_sha256`` (transport-pinning field).

    Failure codes:
        ``FETCH-DOWNLOAD-FAILED``   — HTTP transport error.
        ``FETCH-SHA256-MISMATCH``   — archive sha mismatch (refetch + prior lock).
        ``FETCH-EXTRACT-FAILED``    — safe_extract raised (zip-slip, size cap, …).
    """

    def __init__(
        self,
        http_get: HttpGet | None = None,
        limits: Limits = _DEFAULT_LIMITS,
    ) -> None:
        self._http_get: HttpGet = http_get if http_get is not None else make_http_get()
        self._limits = limits

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, TarballProvenance)

    def fetch(
        self,
        name: str,
        p: Provenance,
        *,
        dest: Path,
    ) -> ProvenanceReceipt:
        if not isinstance(p, TarballProvenance):
            # Programmer-invariant: only called after can_handle → True.
            raise TypeError(f"TarballFetcher.fetch called with {type(p).__name__!r}")

        # 1. Download.
        try:
            raw_bytes = self._http_get(p.url)
        except MilpaError:
            raise
        except Exception as exc:
            raise MilpaError(
                FETCH_DOWNLOAD_FAILED,
                f"fetching {name!r} from {p.url!r}: {exc}",
                dep=name,
                url=p.url,
            ) from exc

        # 2. Compute archive SHA-256 (always — needed for TOFU recording even on
        #    first-use when expected_sha256 is None).
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()

        # 3. Verify against expected (refetch + prior lock path).
        if p.expected_sha256 is not None:
            want = p.expected_sha256.removeprefix("sha256:")
            if actual_sha != want:
                raise MilpaError(
                    FETCH_SHA256_MISMATCH,
                    f"fetching {name!r}: archive sha256 mismatch — "
                    f"expected {p.expected_sha256!r}, got {actual_sha!r} "
                    f"(URL {p.url!r}); rejected before extraction",
                    dep=name,
                    url=p.url,
                    expected=p.expected_sha256,
                    actual=actual_sha,
                )

        # 4. Extract.
        dest.mkdir(parents=True, exist_ok=True)
        try:
            extract_tar(
                io.BytesIO(raw_bytes),
                dest,
                strip_components=p.strip_components,
                limits=self._limits,
            )
        except MilpaError as exc:
            raise MilpaError(
                FETCH_EXTRACT_FAILED,
                f"fetching {name!r}: safe extraction failed ({exc.slug}): {exc.message}",
                dep=name,
                url=p.url,
                inner_slug=exc.slug,
            ) from exc
        except Exception as exc:
            raise MilpaError(
                FETCH_EXTRACT_FAILED,
                f"fetching {name!r}: extraction error: {exc}",
                dep=name,
                url=p.url,
            ) from exc

        return TarballReceipt(archive_sha256=actual_sha)
