"""TarballFetcher — download + safe_extract transport (slice 7d-3).

Downloads an archive over HTTP (injected transport seam), verifies SHA-256
if expected, extracts it via ``safe_extract``, and returns a receipt carrying
``archive_sha256`` — the TOFU first-use mechanism described in RFC S9c.

Public surface:
  - ``TarballProvenance``  — ``Provenance`` subclass for tarball deps.
  - ``TarballReceipt``     — ``ProvenanceReceipt`` carrying ``archive_sha256``.
  - ``TarballFetcher``     — ``Fetcher`` ABC implementation.
  - ``make_http_get``      — production seam: ``bounded_http.request`` backed
                             transport (RFC docs/rfc-native-oci-fetch.md §3.3;
                             the ``curl`` shell-out this replaced is deleted).

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
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

#: ZIP local-file-header magic bytes (PK\x03\x04).  Used to detect and reject
#: ZIP archives early with a clear error (H0 §zip-guard).
_MAGIC_ZIP: bytes = b"\x50\x4b\x03\x04"

from milpa import bounded_http
from milpa.dag_identity import (
    MODE_EXECUTABLE,
    MODE_REGULAR,
    MODE_SYMLINK,
    MaterializedEntry,
)
from milpa.errors import (
    FETCH_DOWNLOAD_FAILED,
    FETCH_DOWNLOAD_SIZE_EXCEEDED,
    FETCH_EXTRACT_FAILED,
    FETCH_SHA256_MISMATCH,
    ID_NON_UTF8_RELPATH,
    ID_NON_UTF8_SYMLINK_TARGET,
    MilpaError,
)
from milpa.fetchers.safe_extract import (
    _DEFAULT_LIMITS,
    _decompress_capped,
    Limits,
    extract_tar,
)
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

#: Injected HTTP transport: streams the response body for ``url`` into the
#: file at ``dest``, or raises.  The callable raises
#: ``MilpaError(FETCH_DOWNLOAD_FAILED, …)`` on failure (or any exception that
#: the fetcher re-wraps with that slug).
#:
#: H3 (finding — memory-safety per RFC docs/rfc-native-oci-fetch.md §3.3):
#: the seam is Path-based, not bytes-returning.  A caller that returned the
#: whole compressed archive as ``bytes`` would force every concurrent
#: tarball worker to hold up to ``MAX_COMPRESSED_BYTES`` (4 GiB) in process
#: memory at once — the RFC's own stated rationale for routing the tarball
#: body (like the OCI blob) through a file ``Path`` sink instead.
HttpGet = Callable[[str, Path], None]


def make_http_get(compressed_cap: int = MAX_COMPRESSED_BYTES) -> HttpGet:
    """Return a production ``HttpGet`` backed by ``bounded_http.request``
    (RFC docs/rfc-native-oci-fetch.md §3.3) — the in-process transport that
    replaced the ``curl -fsSL`` shell-out.

    H1 — streaming bounded read: ``bounded_http.request`` streams the body
    under ``compressed_cap``, raising ``FETCH_DOWNLOAD_SIZE_EXCEEDED``
    mid-stream as soon as the cumulative byte count exceeds the cap.  This
    bounds process memory to at most ``compressed_cap + chunk_size`` bytes
    regardless of how large the server's response is — the full response is
    never buffered before the cap check fires (see
    ``bounded_http._stream_capped``, the single streaming-cap implementation
    every native HTTP caller now shares).

    H3 — the body streams directly to ``dest`` (a file ``Path``), never
    through an in-memory ``BytesIO`` sink: ``bounded_http.request`` opens
    ``dest`` and writes each chunk straight to disk, so the compressed
    archive is never held as a Python ``bytes`` object in this process —
    mirroring the OCI blob path (``OciRegistryClient.blob``), which streams
    to a ``Path`` for the identical reason (an N-worker concurrent resolve
    would otherwise hold N x ``MAX_COMPRESSED_BYTES`` at once).

    Raises:
        MilpaError(FETCH_DOWNLOAD_SIZE_EXCEEDED): compressed body exceeded cap.
        MilpaError(FETCH_DOWNLOAD_FAILED): transport failure (DNS, connection
            refused, timeout) or a non-2xx HTTP status.  ``curl -f`` failed
            the request on any HTTP error status; ``bounded_http`` treats
            status as data (RFC §3.4), so this adapter reproduces curl's
            behavior with an explicit status check.
    """

    def _get(url: str, dest: Path) -> None:
        resp = bounded_http.request("GET", url, cap=compressed_cap, sink=dest)
        # file:// responses carry no HTTP status (bounded_http leaves it
        # None) — only a genuine HTTP error status is a failure here.
        if resp.status is not None and resp.status >= 400:
            raise MilpaError(
                FETCH_DOWNLOAD_FAILED,
                f"fetching {url!r} failed: HTTP {resp.status}",
                url=url,
            )

    return _get


def sha256_of_file(path: Path, *, chunk_size: int = 65_536) -> str:
    """Streaming sha256 of a file's contents — never loads the whole archive
    into memory (H3).

    N1 (finding — duplicated streaming-hash-of-file helper): this is the
    single source of truth for both the tarball archive-digest (this
    module) and the OCI blob-digest (``fetchers/oci_client.py::blob``)
    verification paths. ``oci_client.py`` already imports
    ``MAX_COMPRESSED_BYTES`` from this module, so this hoists the hash loop
    to match that established cross-boundary precedent instead of leaving
    a byte-for-byte duplicate in each module.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# enumerate_tarball_entries — the tarball materialize seam (RFC slice B2-tarball)
# ---------------------------------------------------------------------------


def enumerate_tarball_entries(
    archive: bytes | io.IOBase,
    *,
    strip_components: int = 0,
    limits: Limits = _DEFAULT_LIMITS,
) -> list[MaterializedEntry]:
    """The tarball **materialize seam** (RFC slice B2-tarball): read an archive's
    members into a buffered ``list[MaterializedEntry]`` (spec §1.8.4), feeding the
    epoch-2 DAG builder (``milpa.dag_identity.compute_dag_identity``).

    This is the tarball sibling of ``enumerate_git_entries``: it produces the same
    abstract ``(relpath, mode_byte, content)`` sequence from a ``.tar(.gz/.bz2/.xz)``
    archive, applying the same content rules as git so that identity is
    **transport-independent** (spec §1.1): a git tree and a faithful tarball of the
    same source bytes hash to the same ``dag-sha256:``. The decompression cap is
    reused from ``safe_extract`` (the SSOT); ``compute_dag_identity`` is the single
    DAG builder.

    Mode mapping (spec §1.8.2.1):
      * tar entry with any POSIX execute bit set (``mode & 0o111``) → ``0x01``.
      * tar entry with no execute bit → ``0x00``.
      * tar symlink entry (``issym``) → ``0x80``; content is the link-target
        string bytes (``linkname``), not followed.
      * tar hardlink entry (``islnk``) → resolved to the target's content bytes
        (copy-bytes, same as ``extract_tar`` pass 2); exec bit from the link's mode.
      * directories, device nodes, and FIFOs contribute no leaf (subtrees are
        synthesised by the builder; the others are never legitimate source).

    LOSSY-ARCHIVE RULE (spec/identity.md §1.8.10, RFC §3.4): the exec bit is part
    of epoch-2 identity. A ``.tar`` records POSIX modes faithfully, so a tarball of
    a tree with an executable script reproduces the same digest as the git tree. An
    archive format that **drops** POSIX exec bits (e.g. a ``.zip``) materializes a
    *genuinely different* tree — every file is ``0x00`` — and therefore hashes
    differently. That is correct behaviour, not a bug: the bytes-plus-modes that
    were actually delivered are what get hashed. ``.zip`` is rejected upstream by
    ``TarballFetcher`` (it is not an exec-bit-faithful tar format).

    Args:
        archive:          Raw archive bytes, or a binary file object.
        strip_components: Drop this many leading path components per entry
                          (like ``tar --strip-components=N``); entries with fewer
                          components are skipped. Matches ``extract_tar``.
        limits:           Extraction caps; only ``decomp_cap`` is consulted here
                          (the stream-level decompression-bomb guard).

    Returns:
        Buffered ``list[MaterializedEntry]`` (blobs + symlinks), POSIX relpaths.

    Raises:
        MilpaError(EXTRACT_SIZE_LIMIT)         — decompressed stream exceeds the cap.
        MilpaError(ID_NON_UTF8_RELPATH)        — a member path is not valid UTF-8.
        MilpaError(ID_NON_UTF8_SYMLINK_TARGET) — a symlink target is not valid UTF-8.
    """
    raw = archive if isinstance(archive, bytes) else archive.read()
    # Reuse the safe_extract decompression SSOT (stream-level bomb cap).
    raw_tar_bytes, archive_fmt = _decompress_capped(raw, limits.decomp_cap)
    tar_mode = "r:" if archive_fmt != "tar" else "r:*"

    entries: list[MaterializedEntry] = []
    with tarfile.open(fileobj=io.BytesIO(raw_tar_bytes), mode=tar_mode) as tf:
        for member in tf.getmembers():
            relpath = _tar_member_relpath(member.name, strip_components)
            if relpath is None:
                continue
            if member.isdir():
                # Subtrees are synthesised by the builder from the relpath set.
                continue
            if member.issym():
                target = _check_utf8(
                    member.linkname,
                    ID_NON_UTF8_SYMLINK_TARGET,
                    f"tarball symlink {member.name!r} target is not valid UTF-8",
                )
                entries.append(
                    MaterializedEntry(relpath, MODE_SYMLINK, target.encode("utf-8"))
                )
            elif member.isfile() or member.islnk():
                # extractfile follows hardlinks to the target's content bytes.
                fobj = tf.extractfile(member)
                content = fobj.read() if fobj is not None else b""
                mode_byte = MODE_EXECUTABLE if (member.mode & 0o111) else MODE_REGULAR
                entries.append(MaterializedEntry(relpath, mode_byte, content))
            # device nodes / FIFOs: silently skipped (never legitimate source).
    return entries


def _tar_member_relpath(name: str, strip_components: int) -> str | None:
    """Normalise a tar member name to a POSIX relpath, or ``None`` to skip.

    Drops empty + ``.`` components and applies ``strip_components``; an entry with
    no components left is skipped (mirrors ``extract_tar._check_and_strip``). Path
    containment (zip-slip) is the disk-writer's concern, not the identity seam's —
    the builder hashes whatever relpaths the archive declares.
    """
    raw_parts = [p for p in name.split("/") if p and p != "."]
    if len(raw_parts) <= strip_components:
        return None
    relpath = "/".join(raw_parts[strip_components:])
    _check_utf8(relpath, ID_NON_UTF8_RELPATH, f"tarball entry path {name!r} is not valid UTF-8")
    return relpath


def _check_utf8(s: str, slug: str, message: str) -> str:
    """Return ``s`` if it round-trips through UTF-8, else raise ``MilpaError(slug)``.

    ``tarfile`` decodes member names/linknames with ``surrogateescape``, so a
    non-UTF-8 byte sequence survives as lone surrogates that fail to re-encode.
    """
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MilpaError(slug, message, value=s.encode("utf-8", "backslashreplace").decode()) from exc
    return s


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

        # H3: stream the compressed archive to a scratch temp file rather
        # than buffering it in a Python ``bytes`` object for the duration of
        # the (network-bound, adversary-timed) download — mirrors the OCI
        # blob path (``OciRegistryClient.blob``, RFC
        # docs/rfc-native-oci-fetch.md §3.3), which already streams to a
        # ``Path`` and hashes it via a streaming sha256-of-file helper.  A
        # resolver running N tarball workers concurrently no longer holds N
        # full compressed archives (up to ``MAX_COMPRESSED_BYTES`` each) in
        # process memory at once.
        with tempfile.TemporaryDirectory(prefix="milpa-tarball-") as tmp_dir:
            archive_path = Path(tmp_dir) / "archive"

            # 1. Download (R4: compressed-download cap).
            try:
                self._http_get(p.url, archive_path)
            except MilpaError:
                raise
            except Exception as exc:
                raise MilpaError(
                    FETCH_DOWNLOAD_FAILED,
                    f"fetching {name!r} from {p.url!r}: {exc}",
                    dep=name,
                    url=p.url,
                ) from exc

            if not archive_path.is_file():
                # Transport contract violation: a well-behaved HttpGet always
                # creates ``dest`` (even for an empty body) on success.
                raise MilpaError(
                    FETCH_DOWNLOAD_FAILED,
                    f"fetching {name!r} from {p.url!r}: transport did not "
                    f"produce a downloaded archive",
                    dep=name,
                    url=p.url,
                )

            # H1: enforce the compressed-body cap.  The production transport
            # streams and aborts early, raising FETCH_DOWNLOAD_SIZE_EXCEEDED
            # itself.  This stat-based safety-net check catches injected
            # transports (tests, mocks) that write the full archive directly
            # without streaming/capping themselves — the fetcher must still
            # raise the security slug (not FETCH-DOWNLOAD-FAILED) so the
            # distinction between "network error" and "size cap exceeded" is
            # preserved regardless of which transport path is in use.
            archive_size = archive_path.stat().st_size
            if archive_size > self._compressed_cap:
                raise MilpaError(
                    FETCH_DOWNLOAD_SIZE_EXCEEDED,
                    f"fetching {name!r} from {p.url!r}: compressed body "
                    f"({archive_size} bytes) exceeds download cap "
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
            with open(archive_path, "rb") as f:
                magic = f.read(4)
            if magic == _MAGIC_ZIP:
                raise MilpaError(
                    FETCH_EXTRACT_FAILED,
                    f"fetching {name!r}: unsupported archive format: .zip "
                    f"(TarballFetcher accepts .tar.gz / .tar.bz2 / .tar.xz / .tar only; "
                    f"use a tarball URL or a git= dep)",
                    dep=name,
                    url=p.url,
                )

            # 2. Compute archive SHA-256 (always — needed for TOFU recording
            #    even on first-use when expected_sha256 is None).  Streamed
            #    off disk — never materializes the archive as a Python bytes
            #    object (H3).
            actual_sha = sha256_of_file(archive_path)

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

            # 4. Extract.  ``extract_tar`` accepts a Path directly (it reads
            #    the file itself), so the archive is handed to it without an
            #    extra in-memory ``BytesIO`` wrap — the second buffering copy
            #    the finding called out is eliminated.
            dest.mkdir(parents=True, exist_ok=True)
            try:
                extract_tar(
                    archive_path,
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
