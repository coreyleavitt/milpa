"""Safe tar extraction — standalone utility (spec §plugin-contract.md §2.1).

Guards against:
  - EXTRACT-ZIP-SLIP: entry path escapes dest via ``..`` or absolute paths.
  - EXTRACT-SYMLINK-ESCAPE: symlink target resolves outside dest.
  - EXTRACT-SIZE-LIMIT: per-file / total-bytes / file-count caps (decompression-bomb defence).

No dependency on the fetcher protocol.  This module is a pure filesystem utility;
callers are responsible for cleaning up a partially-extracted ``dest`` on error.

All size limits are applied **during** extraction (streaming); path-escape checks
run **per-entry before any write**.  Device nodes, FIFOs, and other non-regular,
non-symlink, non-directory entry types are silently skipped.

SA-1 decompression-bomb guard (Python path — two layers):

Layer 1 — stream-level cap (H1b, defense-in-depth):
  When the archive is compressed (gz/bz2/xz, detected by magic bytes), the entire
  compressed stream is pre-decompressed with a hard byte cap (``Limits.decomp_cap``)
  before ``tarfile`` sees any bytes.  If the decompressor produces more than
  ``decomp_cap`` bytes, ``EXTRACT-SIZE-LIMIT`` is raised immediately.  This catches
  decompression bombs that embed large payloads in compressed-stream padding —
  bytes that never appear in any tar entry's ``member.size`` field and therefore
  escape Layer 2.  Mirrors the Rust ``.take(decomp_cap)`` mechanism so both impls
  guard the same threat.

Layer 2 — per-entry header cap:
  Python's ``tarfile`` reads ``member.size`` (uncompressed size) from each tar
  header *before* extracting the entry's data.  The per-file and total-size checks
  below operate on ``member.size`` and fire before any bytes are written to disk.
  This layer catches honest archives that simply contain large files.  Together
  with Layer 1, the two caps cover both the honest-header large-file case and the
  lying-header compressed-stream-padding case.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from milpa.errors import (
    EXTRACT_IO_ERROR,
    EXTRACT_SIZE_LIMIT,
    EXTRACT_SYMLINK_ESCAPE,
    EXTRACT_ZIP_SLIP,
    MilpaError,
)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


#: Overhead added to ``Limits.max_total_size`` to compute the default
#: ``Limits.decomp_cap`` — one tar header block (512 B) to allow tar framing
#: around file data.  Matches the Rust ``DECOMP_CAP_OVERHEAD`` constant so the
#: two impls apply the same cap formula (single source of truth per impl).
_DECOMP_CAP_OVERHEAD: int = 512


@dataclass(frozen=True)
class Limits:
    """Extraction caps.  Defaults are normative per plugin-contract.md §2.1.

    Args:
        max_total_size:  Maximum total uncompressed bytes across all entries.  Default 1 GiB.
        max_file_size:   Maximum uncompressed bytes for a single entry.  Default 256 MiB.
        max_file_count:  Maximum number of regular files + symlinks.  Default 100 000.
        decomp_cap:      Hard cap on total decompressed stream bytes (H1b — Layer 1
                         stream-level guard).  Applied BEFORE tarfile sees any bytes:
                         if the decompressor produces more than ``decomp_cap`` bytes the
                         archive is rejected with ``EXTRACT-SIZE-LIMIT``.
                         Default is ``(1 << 30) + _DECOMP_CAP_OVERHEAD`` (1 GiB + 512 B) —
                         the production value matching Rust's ``DECOMP_CAP_OVERHEAD``.
                         Pass an explicit value in tests to exercise the cap without
                         building a 1 GiB bomb.  This field is independent of
                         ``max_total_size`` so that tests using a tiny ``max_total_size``
                         (to exercise Layer 2 per-entry limits) do not accidentally
                         tighten the decompressor cap as well.
    """

    max_total_size: int = field(default=1 << 30)   # 1 GiB
    max_file_size: int = field(default=1 << 28)    # 256 MiB
    max_file_count: int = field(default=100_000)
    decomp_cap: int = field(default=(1 << 30) + _DECOMP_CAP_OVERHEAD)  # 1 GiB + 512


# ---------------------------------------------------------------------------
# ExtractionResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractionResult:
    """Counts produced by a successful extraction."""

    file_count: int
    total_bytes: int


# ---------------------------------------------------------------------------
# Lexical path normalisation (no filesystem access)
# ---------------------------------------------------------------------------


def _normalize_lexical(path: Path) -> Path:
    """Resolve ``.`` and ``..`` components without touching the filesystem.

    ``..`` pops the last *normal* component; if the stack is empty the ``..``
    is kept (mirrors Rust ``normalize_lexical``).
    """
    parts: list[str] = []
    for part in path.parts:
        if part == "..":
            if parts and parts[-1] not in ("", ".."):
                parts.pop()
            else:
                parts.append(part)
        elif part == ".":
            pass
        else:
            parts.append(part)
    if not parts:
        return Path(".")
    return Path(*parts)


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Magic-byte signatures for compressed formats (mirrors fetchers.rs MAGIC_*)
# ---------------------------------------------------------------------------

_MAGIC_GZIP: bytes = b"\x1f\x8b"
_MAGIC_BZ2: bytes = b"BZh"
_MAGIC_XZ: bytes = b"\xfd\x37\x7a\x58\x5a\x00"


# ---------------------------------------------------------------------------
# Stream-level decompression helper (H1b — Layer 1 cap)
# ---------------------------------------------------------------------------


def _is_lzma_alone_header(data: bytes) -> bool:
    """Return True iff ``data`` starts with a structurally valid LZMA-alone header.

    LZMA-alone header (13 bytes):
      - Byte 0 (props):     encodes lc ∈ [0,8], lp ∈ [0,4], pb ∈ [0,4]
                            as ``(pb*5 + lp)*9 + lc``.  Max valid value =
                            (4*5+4)*9+0 = 216 = 0xD8 (lc=0, lp=4, pb=4);
                            the absolute formula maximum 0xE0 (lc=8, lp=4, pb=4)
                            is inadmissible because lc+lp=12 > 4.  The lc+lp ≤ 4
                            constraint is enforced explicitly below.
      - Bytes 1-4 (dict_size LE): must be ≥ 2^12 (LZMA minimum) and ≤ 2^30.
                            liblzma normalises to ``2^n`` or ``2^n + 2^(n-1)``;
                            we accept any value in the valid range since
                            the props-byte check already prunes most false positives.

    This two-check filter rejects plain .tar files whose first byte happens to
    be a valid props byte (e.g. ASCII 'l' = 0x6c from a symlink entry name)
    because their bytes 1-4 (the tar filename chars) encode a dict_size that
    is either zero, out of the valid range, or not a power-of-two shape.
    """
    import struct

    if len(data) < 13:
        return False
    props = data[0]
    if props > 0xD8:  # max valid LZMA1 props byte (lc=0, lp=4, pb=4 → 216 = 0xD8)
        return False
    # Validate lp + lc ≤ 4 (liblzma constraint in addition to max-props check).
    lc = props % 9
    remainder = props // 9
    lp = remainder % 5
    pb = remainder // 5
    if lc + lp > 4:
        return False
    # dict_size: bytes 1-4, little-endian uint32.
    # liblzma requires dict_size to be exactly 2^k or 2^k + 2^(k-1) for k ∈ [12..30].
    # This is a much tighter constraint than "any value in [4096, 2^30]" and rejects
    # arbitrary tar header bytes that happen to form numbers in the valid range.
    dict_size = struct.unpack_from("<I", data, 1)[0]
    _valid_dict = False
    for _k in range(12, 31):
        if dict_size == (1 << _k) or (_k >= 1 and dict_size == (1 << _k) + (1 << (_k - 1))):
            _valid_dict = True
            break
    if not _valid_dict:
        return False
    return True


def _decompress_capped(
    data: bytes,
    decomp_cap: int,
) -> tuple[bytes, str] | None:
    """Detect and decompress a compressed archive, enforcing a stream-level cap.

    If ``data`` starts with a recognised magic sequence (gzip / bz2 / xz),
    decompress the entire stream, reading at most ``decomp_cap + 1`` bytes.
    If the decompressor produces more than ``decomp_cap`` bytes, return
    ``None`` to signal a cap breach (the caller raises ``EXTRACT-SIZE-LIMIT``).
    If decompression succeeds within the cap, return ``(raw_tar_bytes, format)``
    where ``format`` is one of ``"gz"``, ``"bz2"``, ``"xz"``, ``"lzma"``.

    For streams that do not match the reliable gzip/bz2/xz magics, a structural
    lzma-alone header check (``_is_lzma_alone_header``) is applied, followed by
    a guarded attempt-decode.  On success the capped bytes are returned with
    format ``"lzma"``; on ``lzma.LZMAError`` the bytes fall through as plain tar.
    This mirrors Rust's attempt-decode-then-fallthrough semantics exactly.

    If ``data`` does not match any format, return ``(data, "tar")`` — unmodified,
    no cap applied (the per-entry checks in the caller handle the size limit for
    plain tars).

    Raises ``MilpaError(EXTRACT_SIZE_LIMIT)`` on cap breach.
    """
    if data[:2] == _MAGIC_GZIP:
        fmt = "gz"
        decompressor: IO[bytes] = gzip.GzipFile(fileobj=io.BytesIO(data))  # type: ignore[assignment]
    elif data[:3] == _MAGIC_BZ2:
        fmt = "bz2"
        decompressor = bz2.BZ2File(io.BytesIO(data))  # type: ignore[assignment]
    elif data[:6] == _MAGIC_XZ:
        fmt = "xz"
        decompressor = lzma.LZMAFile(io.BytesIO(data), format=lzma.FORMAT_XZ)  # type: ignore[assignment]
    else:
        # R2-02 + R3-01 NORMATIVE: unified lzma-alone detection via structural header
        # check + guarded attempt-decode.  Mirrors Rust's attempt-decode-then-fallthrough
        # semantics: no 2-byte magic fast-path, no unguarded LZMAFile construction.
        #
        # LZMA-alone header (13 bytes): [props(1)] [dict_size(4LE)] [uncomp_size(8LE)]
        # Structural validity constraints (liblzma compatible):
        #   1. props byte ≤ 0xD8 (max: lc=0, lp=4, pb=4 → 0xD8; lc+lp ≤ 4 enforced below)
        #   2. dict_size must be 2^n or 2^n + 2^(n-1) for n ∈ [12..30]
        #      (liblzma normalizes any dict size but round-trips through these values)
        # These two checks together reject plain .tar files whose first bytes happen
        # to have a valid props byte (e.g. 0x6c from 'l', the ASCII of 'link').
        if _is_lzma_alone_header(data):
            try:
                probe = lzma.LZMAFile(io.BytesIO(data), format=lzma.FORMAT_ALONE)
                probe_raw = probe.read(decomp_cap + 1)
                if len(probe_raw) > decomp_cap:
                    raise MilpaError(
                        EXTRACT_SIZE_LIMIT,
                        f"decompressed archive stream exceeds cap ({decomp_cap} bytes); "
                        f"possible decompression bomb (format: lzma)",
                        cap=decomp_cap,
                        format="lzma",
                    )
                return (probe_raw, "lzma")
            except (lzma.LZMAError, EOFError, ValueError):
                # Not a valid lzma FORMAT_ALONE stream — treat as plain tar.
                pass
        return (data, "tar")

    # Read one byte beyond the cap to detect overflow without buffering the full stream.
    raw = decompressor.read(decomp_cap + 1)
    if len(raw) > decomp_cap:
        raise MilpaError(
            EXTRACT_SIZE_LIMIT,
            f"decompressed archive stream exceeds cap ({decomp_cap} bytes); "
            f"possible decompression bomb (format: {fmt})",
            cap=decomp_cap,
            format=fmt,
        )
    return (raw, fmt)


#: Singleton used as the ``extract_tar`` default so ruff B008 (no call in
#: default position) is satisfied while preserving the normative defaults.
_DEFAULT_LIMITS = Limits()


def _regular_file_mode(member: tarfile.TarInfo) -> int:
    """On-disk mode for a regular/hardlink tar member (spec/identity.md §1.7.4).

    Any POSIX execute bit in the tar header's mode → 0o755, else 0o644. Single
    source of truth shared by both ``extract_tar`` write branches (pass 1
    regular files, pass 2 hardlink copies) so the two stay in lockstep with
    ``enumerate_tarball_entries``' identical ``member.mode & 0o111`` check.
    """
    return 0o755 if (member.mode & 0o111) else 0o644


def extract_tar(
    archive: str | Path | IO[bytes],
    dest: str | Path,
    *,
    strip_components: int = 0,
    limits: Limits = _DEFAULT_LIMITS,
) -> ExtractionResult:
    """Extract a tar archive (any compression tarfile supports) into *dest*.

    Args:
        archive:          Path or file-object for the archive.
        dest:             Directory into which entries are extracted (created if absent).
        strip_components: Drop this many leading path components per entry
                          (like ``tar --strip-components=N``).  Entries with
                          fewer components are silently skipped.
        limits:           Extraction caps.  Defaults are normative.

    Returns:
        :class:`ExtractionResult` with ``file_count`` and ``total_bytes``.

    Raises:
        MilpaError: with slug ``EXTRACT-ZIP-SLIP``, ``EXTRACT-SYMLINK-ESCAPE``,
                    or ``EXTRACT-SIZE-LIMIT`` on the matching attack class.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    # Canonicalise dest so prefix comparisons are reliable even when the
    # caller passed a symlink-containing path.
    dest_root = dest.resolve()

    total_bytes = 0
    file_count = 0

    # SA-1 decompression-bomb guard — Layer 1: stream-level cap (H1b).
    # Read the archive bytes upfront so we can (a) detect the compression format
    # by magic bytes and (b) pre-decompress with a hard byte cap before tarfile
    # sees any bytes.  This catches decompression bombs embedded in compressed-
    # stream padding that never appears in any tar entry's member.size field and
    # would therefore escape Layer 2's per-entry checks.
    # Mirrors the Rust `.take(decomp_cap)` mechanism (single source of truth
    # per impl: `_decompress_capped` in this module).
    #
    # Memory note (R1-23b): this path buffers the whole compressed archive then
    # the whole decompressed stream in memory.  Both are bounded by
    # limits.decomp_cap (≤ ~1 GiB by default).  A streaming rewrite would reduce
    # peak RSS but is a large refactor; it is deliberately deferred.
    if isinstance(archive, (str, Path)):
        raw_archive_bytes = Path(archive).read_bytes()
    else:
        raw_archive_bytes = archive.read()

    # Layer 1: apply the stream-level decompressor cap (H1b).
    # _decompress_capped raises EXTRACT-SIZE-LIMIT if the decompressed stream
    # exceeds limits.decomp_cap.  For plain tar (no magic match) it returns
    # the original bytes unchanged without any cap check.
    raw_tar_bytes, _archive_fmt = _decompress_capped(raw_archive_bytes, limits.decomp_cap)

    # Open with mode "r:" (plain tar — already decompressed above) or "r:*"
    # if format detection returned "tar" (no magic match → may be plain or
    # an unrecognised compressed format; let tarfile decide).
    tar_mode = "r:" if _archive_fmt != "tar" else "r:*"

    # H2 — two-pass extraction (spec/plugin-contract.md §2.2).
    # Hardlink entries (typeflag '1') carry an archive-absolute linkname that
    # may forward-reference a target not yet written.  All regular files,
    # directories, and symlinks are written in pass 1; hardlinks are resolved
    # in pass 2 when every target is guaranteed to exist.
    # Each list element is (member, candidate) — already stripped and checked.
    hardlinks: list[tuple[tarfile.TarInfo, Path]] = []

    def _check_and_strip(
        member: tarfile.TarInfo,
    ) -> Path | None:
        """Return the stripped, zip-slip-checked candidate Path, or None to skip."""
        if member.name.startswith("/"):
            raise MilpaError(
                EXTRACT_ZIP_SLIP,
                f"archive entry {member.name!r} has an absolute path",
                entry=member.name,
                dest=str(dest_root),
            )
        raw_parts = [p for p in member.name.split("/") if p and p != "."]
        if len(raw_parts) <= strip_components:
            return None
        stripped_name = "/".join(raw_parts[strip_components:])
        candidate = _normalize_lexical(dest_root / stripped_name)
        if not str(candidate).startswith(str(dest_root) + os.sep) and candidate != dest_root:
            raise MilpaError(
                EXTRACT_ZIP_SLIP,
                f"archive entry {member.name!r} resolves outside destination: "
                f"{candidate} not under {dest_root}",
                entry=member.name,
                dest=str(dest_root),
            )
        return candidate

    with tarfile.open(fileobj=io.BytesIO(raw_tar_bytes), mode=tar_mode) as tf:
        # ------------------------------------------------------------------
        # Pass 1: dirs, regular files, symlinks (everything except hardlinks)
        # ------------------------------------------------------------------
        for member in tf.getmembers():
            candidate = _check_and_strip(member)
            if candidate is None:
                continue

            if member.isdir():
                candidate.mkdir(parents=True, exist_ok=True)

            elif member.islnk():
                # Hardlink — defer to pass 2 (forward-reference safety).
                hardlinks.append((member, candidate))

            elif member.issym():
                # symlink-escape: resolve target relative to its parent
                link_target_raw = member.linkname
                parent = candidate.parent
                resolved_target = _normalize_lexical(parent / link_target_raw)
                under_dest = (
                    str(resolved_target).startswith(str(dest_root) + os.sep)
                    or resolved_target == dest_root
                )
                if not under_dest:
                    raise MilpaError(
                        EXTRACT_SYMLINK_ESCAPE,
                        f"symlink {member.name!r} → {link_target_raw!r} resolves outside "
                        f"destination: {resolved_target} not under {dest_root}",
                        entry=member.name,
                        link_target=link_target_raw,
                        dest=str(dest_root),
                    )
                file_count += 1
                if file_count > limits.max_file_count:
                    raise MilpaError(
                        EXTRACT_SIZE_LIMIT,
                        f"archive file count exceeds cap "
                        f"({file_count} > {limits.max_file_count})",
                        file_count=file_count,
                        cap=limits.max_file_count,
                    )
                candidate.parent.mkdir(parents=True, exist_ok=True)
                if candidate.exists() or candidate.is_symlink():
                    candidate.unlink()
                candidate.symlink_to(link_target_raw)

            elif member.isfile():
                # per-file size cap (checked before writing)
                if member.size > limits.max_file_size:
                    raise MilpaError(
                        EXTRACT_SIZE_LIMIT,
                        f"entry {member.name!r} exceeds per-file cap "
                        f"({member.size} > {limits.max_file_size})",
                        entry=member.name,
                        size=member.size,
                        cap=limits.max_file_size,
                    )
                total_bytes += member.size
                if total_bytes > limits.max_total_size:
                    raise MilpaError(
                        EXTRACT_SIZE_LIMIT,
                        f"archive total size exceeds cap "
                        f"({total_bytes} > {limits.max_total_size})",
                        total_bytes=total_bytes,
                        cap=limits.max_total_size,
                    )
                file_count += 1
                if file_count > limits.max_file_count:
                    raise MilpaError(
                        EXTRACT_SIZE_LIMIT,
                        f"archive file count exceeds cap "
                        f"({file_count} > {limits.max_file_count})",
                        file_count=file_count,
                        cap=limits.max_file_count,
                    )
                candidate.parent.mkdir(parents=True, exist_ok=True)
                fobj = tf.extractfile(member)
                if fobj is not None:
                    try:
                        candidate.write_bytes(fobj.read())
                    except OSError as exc:
                        raise MilpaError(
                            EXTRACT_IO_ERROR,
                            f"I/O error writing entry {member.name!r}: {exc}",
                            entry=member.name,
                            dest=str(dest_root),
                        ) from exc
                    # Preserve the executable bit (spec/identity.md §1.7.4 disk
                    # contract). Mirrors enumerate_tarball_entries' mode mapping
                    # and materialize_git_tree's on-disk chmod (fetchers/git.py)
                    # so identity is transport-independent end-to-end, not just
                    # at the object-store-enumeration layer.
                    candidate.chmod(_regular_file_mode(member))

            # device nodes, FIFOs, etc. — silently skip (never legitimate in source)

        # ------------------------------------------------------------------
        # Pass 2: hardlinks — copy bytes from the (now-existing) target
        # (spec/plugin-contract.md §2.2: copy-bytes materialisation;
        #  strip_components applied to linkname via POSIX '/' split;
        #  linkname is archive-absolute, resolved against dest_root.)
        # ------------------------------------------------------------------
        for member, candidate in hardlinks:
            link_target_raw = member.linkname
            # Apply strip_components to linkname via POSIX '/' split
            # (not the host Path separator — see plugin-contract.md §2.2).
            raw_link_parts = [p for p in link_target_raw.split("/") if p and p != "."]
            if len(raw_link_parts) <= strip_components:
                # Linkname stripped away entirely → dangling; treat as escape.
                raise MilpaError(
                    EXTRACT_ZIP_SLIP,
                    f"hardlink {member.name!r} → {link_target_raw!r}: linkname has "
                    f"fewer than {strip_components + 1} component(s); cannot strip",
                    entry=member.name,
                    link_target=link_target_raw,
                    dest=str(dest_root),
                )
            stripped_link = "/".join(raw_link_parts[strip_components:])
            # Resolve against dest_root (hardlink geometry, not symlink geometry).
            resolved_link = _normalize_lexical(dest_root / stripped_link)
            if not str(resolved_link).startswith(str(dest_root) + os.sep) and resolved_link != dest_root:
                raise MilpaError(
                    EXTRACT_ZIP_SLIP,
                    f"hardlink {member.name!r} → {link_target_raw!r} resolves outside "
                    f"destination: {resolved_link} not under {dest_root}",
                    entry=member.name,
                    link_target=link_target_raw,
                    dest=str(dest_root),
                )
            # Copy bytes from the target (which pass 1 guarantees exists).
            if not resolved_link.is_file():
                raise MilpaError(
                    EXTRACT_ZIP_SLIP,
                    f"hardlink {member.name!r} → {link_target_raw!r}: target "
                    f"{resolved_link} does not exist or is not a file",
                    entry=member.name,
                    link_target=link_target_raw,
                    dest=str(dest_root),
                )
            try:
                source_bytes = resolved_link.read_bytes()
            except OSError as exc:
                raise MilpaError(
                    EXTRACT_IO_ERROR,
                    f"I/O error reading hardlink target {resolved_link!r} "
                    f"for entry {member.name!r}: {exc}",
                    entry=member.name,
                    link_target=link_target_raw,
                    dest=str(dest_root),
                ) from exc
            # Size caps: treat the copy as if it were a regular file.
            copy_size = len(source_bytes)
            if copy_size > limits.max_file_size:
                raise MilpaError(
                    EXTRACT_SIZE_LIMIT,
                    f"hardlink {member.name!r} target exceeds per-file cap "
                    f"({copy_size} > {limits.max_file_size})",
                    entry=member.name,
                    size=copy_size,
                    cap=limits.max_file_size,
                )
            total_bytes += copy_size
            if total_bytes > limits.max_total_size:
                raise MilpaError(
                    EXTRACT_SIZE_LIMIT,
                    f"archive total size exceeds cap "
                    f"({total_bytes} > {limits.max_total_size})",
                    total_bytes=total_bytes,
                    cap=limits.max_total_size,
                )
            file_count += 1
            if file_count > limits.max_file_count:
                raise MilpaError(
                    EXTRACT_SIZE_LIMIT,
                    f"archive file count exceeds cap "
                    f"({file_count} > {limits.max_file_count})",
                    file_count=file_count,
                    cap=limits.max_file_count,
                )
            candidate.parent.mkdir(parents=True, exist_ok=True)
            try:
                candidate.write_bytes(source_bytes)
            except OSError as exc:
                raise MilpaError(
                    EXTRACT_IO_ERROR,
                    f"I/O error writing hardlink copy {candidate!r} "
                    f"for entry {member.name!r}: {exc}",
                    entry=member.name,
                    link_target=link_target_raw,
                    dest=str(dest_root),
                ) from exc
            # Preserve the executable bit on the hardlink's OWN mode (not the
            # target's) — enumerate_tarball_entries computes mode_byte from the
            # islnk() member's own `member.mode`, so a hardlink entry with the
            # exec bit set must chmod its copy the same way pass 1 does for
            # regular files (see _regular_file_mode).
            candidate.chmod(_regular_file_mode(member))

    return ExtractionResult(file_count=file_count, total_bytes=total_bytes)
