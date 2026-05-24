"""Sandboxed archive extraction.

Defends against the standard archive-extraction attack classes:

  - Zip-slip: entries whose resolved path escapes the destination
    directory (`../../etc/passwd`, absolute paths)
  - Symlink-escape: symlink entries whose target resolves outside
    the destination tree
  - Decompression bombs: archives whose decompressed size vastly
    exceeds compressed size (billion laughs-style)
  - Excessive file count: archives creating millions of tiny files

Used by TarballFetcher (F2) and any future fetcher that handles
extractable archives (F6 OCI, F7 IPFS). See
docs/rfc-pluggable-fetchers.md §Sandboxing fetcher execution.

The module exports `extract_tar` as the primary entry point. Caps
are passed as kwargs so callers can tune per use case (e.g., the
toolchain RFC's compiler-binary extraction might allow larger
total size).
"""

import os
import tarfile
from dataclasses import dataclass
from pathlib import Path


class ExtractionError(Exception):
    """Base class for archive-extraction failures."""


class ZipSlipError(ExtractionError):
    """An entry's path resolves outside the destination directory."""


class SymlinkEscapeError(ExtractionError):
    """A symlink entry's target resolves outside the destination tree."""


class SizeLimitError(ExtractionError):
    """The archive exceeds a configured size or file-count limit."""


@dataclass(frozen=True)
class ExtractionResult:
    """What extract_tar reports back.

    Counts files actually written (post-strip_components filtering)
    and the total uncompressed bytes those files contained.
    """
    file_count: int
    total_bytes: int


def extract_tar(
    archive_path: Path,
    dest: Path,
    *,
    strip_components: int = 0,
    max_total_size: int = 1 << 30,      # 1 GiB
    max_file_size: int = 1 << 28,       # 256 MiB
    max_file_count: int = 100_000,
) -> ExtractionResult:
    """Extract a tar archive (any compression tarfile supports) to dest.

    `strip_components` removes the first N path components from each
    entry (like `tar --strip-components=N`). Entries with fewer than
    N path components are skipped (they're parents we're stripping).

    Defends against the attack classes documented at module level.
    Raises ExtractionError subclasses on violations; the partial
    extraction state at dest is the caller's problem to clean up
    (typically: rmtree dest on any failure).
    """
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()

    total_bytes = 0
    file_count = 0

    with tarfile.open(archive_path, "r:*") as tf:
        for member in tf:
            # Apply strip_components: split the entry's path and skip
            # the first N components. Entries with too few components
            # are dropped silently (they're the parents we're stripping).
            parts = member.name.split("/")
            parts = [p for p in parts if p not in ("", ".")]
            if len(parts) <= strip_components:
                continue
            stripped_name = "/".join(parts[strip_components:])

            # Resolve the target path under dest. Catch zip-slip:
            # any entry whose resolved path escapes dest is malicious.
            target = (dest / stripped_name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                raise ZipSlipError(
                    f"archive entry {member.name!r} resolves outside "
                    f"destination: {target} not under {dest_resolved}"
                )

            if member.issym() or member.islnk():
                # Symlink targets are evaluated relative to the symlink's
                # parent directory; resolve to check the eventual target.
                link_target = (target.parent / member.linkname).resolve()
                try:
                    link_target.relative_to(dest_resolved)
                except ValueError:
                    raise SymlinkEscapeError(
                        f"symlink {member.name!r} → {member.linkname!r} "
                        f"resolves outside destination: {link_target} "
                        f"not under {dest_resolved}"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, target)
                file_count += 1
                continue

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            if not member.isfile():
                # Skip char/block devices, fifos, etc. — never legitimate
                # in a source archive.
                continue

            if member.size > max_file_size:
                raise SizeLimitError(
                    f"archive entry {member.name!r} exceeds per-file "
                    f"size cap ({member.size} > {max_file_size})"
                )
            total_bytes += member.size
            if total_bytes > max_total_size:
                raise SizeLimitError(
                    f"archive total decompressed size exceeds cap "
                    f"({total_bytes} > {max_total_size})"
                )
            file_count += 1
            if file_count > max_file_count:
                raise SizeLimitError(
                    f"archive file count exceeds cap "
                    f"({file_count} > {max_file_count})"
                )

            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tf.extractfile(member)
            if extracted is None:
                # Should not happen for regular files; guard defensively.
                continue
            target.write_bytes(extracted.read())

    return ExtractionResult(file_count=file_count, total_bytes=total_bytes)
