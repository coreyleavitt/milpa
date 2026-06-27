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

#: Chunk size for streaming reads in `make_http_get`.  64 KiB balances
#: syscall overhead against bounded-memory granularity: the process never
#: buffers more than compressed_cap + _CHUNK_SIZE bytes from a response that
#: exceeds the cap.
_CHUNK_SIZE: int = 65_536  # 64 KiB

#: ZIP local-file-header magic bytes (PK\x03\x04).  Used to detect and reject
#: ZIP archives early with a clear error (H0 §zip-guard).  Promoted to module
#: level alongside _CHUNK_SIZE for consistency with other format-magic constants.
_MAGIC_ZIP: bytes = b"\x50\x4b\x03\x04"

from milpa.errors import (
    FETCH_DOWNLOAD_FAILED,
    FETCH_DOWNLOAD_SIZE_EXCEEDED,
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
# R4 — compressed-download cap
# ---------------------------------------------------------------------------

#: Maximum compressed bytes accepted from a single HTTP download before the
#: request is rejected.  Set to 4 × Limits.max_total_size (4 GiB) — a
#: conservative upper bound given typical archive compression ratios.
#:
#: Both impls (Python and Rust) use the SAME numeric value so the transport
#: hardening is cross-impl byte-identical (finding R4).
#:
#: The cap is enforced by streaming at most ``MAX_COMPRESSED_BYTES`` bytes from
#: the transport; if the response exceeds the cap, ``FETCH-DOWNLOAD-SIZE-EXCEEDED``
#: is raised before any bytes are buffered beyond the cap.
MAX_COMPRESSED_BYTES: int = _DEFAULT_LIMITS.max_total_size * 4  # 4 GiB

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


def make_http_get(compressed_cap: int = MAX_COMPRESSED_BYTES) -> HttpGet:
    """Return a production ``HttpGet`` backed by ``curl -fsSL``.

    H1 — streaming bounded read: uses ``subprocess.Popen`` to read curl's
    stdout in ``_CHUNK_SIZE`` chunks and aborts (kills curl) as soon as the
    cumulative byte count exceeds ``compressed_cap``.  This bounds the process
    memory to at most ``compressed_cap + _CHUNK_SIZE`` bytes regardless of how
    large the server's response is — the full response is never buffered before
    the cap check fires.

    Raises:
        MilpaError(FETCH_DOWNLOAD_SIZE_EXCEEDED): compressed body exceeded cap.
        MilpaError(FETCH_DOWNLOAD_FAILED): curl exited non-zero (network error).
    """

    def _curl(url: str) -> bytes:
        # R1-13: wrap Popen in `with proc:` so stdout and stderr are always
        # closed and the process is always reaped across every exit path
        # (cap-exceeded, read exception, curl failure, success).
        # R2-05: single coherent cleanup discipline — use communicate() once on
        # the non-streaming paths; on kill paths, kill then raise and let
        # __exit__ do the final reap via communicate().  No manual close/wait
        # before or after communicate(); double-drain confuses Popen.__exit__.
        with subprocess.Popen(
            ["curl", "-fsSL", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            assert proc.stdout is not None
            chunks: list[bytes] = []
            total = 0
            try:
                while True:
                    chunk = proc.stdout.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > compressed_cap:
                        # Abort: kill curl and raise.  Popen.__exit__ handles
                        # the final reap via communicate() — do NOT manually
                        # close stdout or call wait() here (that would cause a
                        # double-drain in __exit__).
                        proc.kill()
                        raise MilpaError(
                            FETCH_DOWNLOAD_SIZE_EXCEEDED,
                            f"curl response for {url!r} exceeded download cap "
                            f"({compressed_cap} bytes); request aborted",
                            url=url,
                            cap=compressed_cap,
                        )
                    chunks.append(chunk)
            except MilpaError:
                raise
            except Exception as exc:
                proc.kill()
                raise MilpaError(
                    FETCH_DOWNLOAD_FAILED,
                    f"curl read error for {url!r}: {exc}",
                    url=url,
                ) from exc

            # Stdout is now fully drained (the read loop exited cleanly).
            # Use communicate() to drain stderr and reap the process in one call.
            # communicate() will also close both pipes.
            _, stderr_bytes = proc.communicate()
            returncode = proc.returncode
            if returncode != 0:
                stderr = stderr_bytes.decode(errors="replace").strip() if stderr_bytes else ""
                raise MilpaError(
                    FETCH_DOWNLOAD_FAILED,
                    f"curl failed for {url!r}: {stderr}",
                    url=url,
                )
            return b"".join(chunks)

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
        ``FETCH-DOWNLOAD-FAILED``        — HTTP transport error (network failure).
        ``FETCH-DOWNLOAD-SIZE-EXCEEDED`` — compressed body exceeded the download cap.
        ``FETCH-SHA256-MISMATCH``        — archive sha mismatch (refetch + prior lock).
        ``FETCH-EXTRACT-FAILED``         — safe_extract raised (zip-slip, size cap, …).
    """

    def __init__(
        self,
        http_get: HttpGet | None = None,
        limits: Limits = _DEFAULT_LIMITS,
        compressed_cap: int = MAX_COMPRESSED_BYTES,
    ) -> None:
        self._http_get: HttpGet = http_get if http_get is not None else make_http_get()
        self._limits = limits
        self._compressed_cap = compressed_cap

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

        # 1. Download (R4: compressed-download cap).
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

        # H1: enforce the compressed-body cap.  The production transport streams
        # and aborts early, raising FETCH_DOWNLOAD_SIZE_EXCEEDED itself.
        # This safety-net check catches injected transports (tests, mocks) that
        # return bytes directly without streaming — they return a full blob and
        # the fetcher must still raise the security slug (not FETCH-DOWNLOAD-FAILED)
        # so the distinction between "network error" and "size cap exceeded" is
        # preserved regardless of which transport path is in use.
        if len(raw_bytes) > self._compressed_cap:
            raise MilpaError(
                FETCH_DOWNLOAD_SIZE_EXCEEDED,
                f"fetching {name!r} from {p.url!r}: compressed body "
                f"({len(raw_bytes)} bytes) exceeds download cap "
                f"({self._compressed_cap} bytes); possible oversized mirror",
                dep=name,
                url=p.url,
                cap=self._compressed_cap,
            )

        # 1b. Unsupported-format guard: ZIP archives are not supported by
        #     TarballFetcher.  A .zip URL with Python's tarfile produces an
        #     obscure multi-method ReadError; detect the ZIP magic bytes early
        #     and raise FETCH-EXTRACT-FAILED with an actionable message (H0
        #     §zip-guard).  Uses the module-level _MAGIC_ZIP constant.
        if raw_bytes[:4] == _MAGIC_ZIP:
            raise MilpaError(
                FETCH_EXTRACT_FAILED,
                f"fetching {name!r}: unsupported archive format: .zip "
                f"(TarballFetcher accepts .tar.gz / .tar.bz2 / .tar.xz / .tar only; "
                f"use a tarball URL or a git= dep)",
                dep=name,
                url=p.url,
            )

        # 2. Compute archive SHA-256 (always — needed for TOFU recording even on
        #    first-use when expected_sha256 is None).
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()

        # 3. Verify against expected (refetch + prior lock path).
        if p.expected_sha256 is not None:
            want = p.expected_sha256.removeprefix("sha256:").lower()
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
