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

SA-1 decompression-bomb guard (Python path):
Python's ``tarfile`` reads ``member.size`` (uncompressed size) from each tar
header *before* extracting the entry's data.  The per-file and total-size checks
below operate on ``member.size`` and are therefore effective decompression-bomb
defenses: the cap fires before any compressed bytes are decompressed and written
to disk.  The Rust path uses a ``.take(decomp_cap)`` wrapper on the GzDecoder
because Rust decompresses the whole stream up-front before calling
``extract_tar``; that early abort is not needed here because Python's tarfile
decompresses lazily per-entry.
"""

from __future__ import annotations

import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from milpa.errors import (
    EXTRACT_SIZE_LIMIT,
    EXTRACT_SYMLINK_ESCAPE,
    EXTRACT_ZIP_SLIP,
    MilpaError,
)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Limits:
    """Extraction caps.  Defaults are normative per plugin-contract.md §2.1.

    Args:
        max_total_size:  Maximum total uncompressed bytes across all entries.  Default 1 GiB.
        max_file_size:   Maximum uncompressed bytes for a single entry.  Default 256 MiB.
        max_file_count:  Maximum number of regular files + symlinks.  Default 100 000.
    """

    max_total_size: int = field(default=1 << 30)   # 1 GiB
    max_file_size: int = field(default=1 << 28)    # 256 MiB
    max_file_count: int = field(default=100_000)


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


#: Singleton used as the ``extract_tar`` default so ruff B008 (no call in
#: default position) is satisfied while preserving the normative defaults.
_DEFAULT_LIMITS = Limits()


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

    # SA-1 decompression-bomb guard (Python path):
    # Python's tarfile decompresses lazily: it reads member headers (which
    # record the *uncompressed* size in member.size) and decompresses each
    # entry's data only when it is extracted.  The per-file and total-size
    # checks below operate on member.size (uncompressed) and are therefore
    # effective decompression-bomb defenses — no additional wrapping needed.
    # The Rust path uses a `.take(decomp_cap)` on the GzDecoder to catch
    # bombs before any bytes are written to disk; in Python the equivalent
    # is the per-entry size check that fires before the fobj.read() call.

    # Open with mode "r:*" so tarfile handles gz/bz2/xz automatically.
    with tarfile.open(fileobj=archive if not isinstance(archive, (str, Path)) else None,
                      name=archive if isinstance(archive, (str, Path)) else None,
                      mode="r:*") as tf:
        for member in tf.getmembers():
            # --- absolute-path check (zip-slip variant) ----------------------
            # An entry whose name starts with "/" is an absolute path traversal.
            # We reject it before stripping, because stripping the empty leading
            # component would silently "fix" it and let /etc/passwd land at
            # dest/etc/passwd rather than escaping — but the spec requires
            # EXTRACT-ZIP-SLIP for any absolute-path entry.
            if member.name.startswith("/"):
                raise MilpaError(
                    EXTRACT_ZIP_SLIP,
                    f"archive entry {member.name!r} has an absolute path",
                    entry=member.name,
                    dest=str(dest_root),
                )

            # --- strip_components -------------------------------------------
            raw_parts = [p for p in member.name.split("/") if p and p != "."]
            if len(raw_parts) <= strip_components:
                continue
            stripped_name = "/".join(raw_parts[strip_components:])

            # --- zip-slip check (lexical, target doesn't exist yet) ----------
            candidate = _normalize_lexical(dest_root / stripped_name)
            if not str(candidate).startswith(str(dest_root) + os.sep) and candidate != dest_root:
                raise MilpaError(
                    EXTRACT_ZIP_SLIP,
                    f"archive entry {member.name!r} resolves outside destination: "
                    f"{candidate} not under {dest_root}",
                    entry=member.name,
                    dest=str(dest_root),
                )

            # --- dispatch by type -------------------------------------------
            if member.isdir():
                candidate.mkdir(parents=True, exist_ok=True)

            elif member.issym() or member.islnk():
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
                    candidate.write_bytes(fobj.read())

            # device nodes, FIFOs, etc. — silently skip (never legitimate in source)

    return ExtractionResult(file_count=file_count, total_bytes=total_bytes)
