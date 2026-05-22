"""Identity computation — sha256 of a source tree per milpa's spec.

milpa's *identity* of a dep is the sha256 hash of its source tree,
computed by walking every entry under the tree root and feeding a
canonical stream of bytes into sha256. The output is the same
regardless of which transport delivered the bytes (git, tarball,
mercurial, OCI, IPFS, local copy) — identity is provenance-
independent.

See docs/identity-and-provenance.md for the conceptual model.
See docs/rfc-content-addressed-identity.md §"What exactly is 'content'"
for the bytes-level spec this module implements.

Algorithm (canonical):

  For each entry under `path` (excluding `.git/`):
      relpath_bytes + 0x00 + mode_marker + 0x00 + entry_content + 0x00

  Entries sorted by POSIX relpath. mode_marker is a single byte:
      0x00 — regular file, non-executable
      0x01 — regular file, executable (owner-execute bit set)
      0x80 — symlink (entry_content is the link target string as UTF-8)

  Empty directories are not hashed (no entry contributes for them).

  Final output: hex digest of the accumulator.
"""

from hashlib import sha256
from pathlib import Path
import os
import stat


MODE_REGULAR = b"\x00"
MODE_EXECUTABLE = b"\x01"
MODE_SYMLINK = b"\x80"


def compute_content_hash(path: Path) -> str:
    """Compute the sha256 content hash of the source tree at `path`.

    Returns a 64-character lowercase hex digest. Same input bytes
    always produce the same hash, regardless of host filesystem,
    clone location, or transport.
    """
    h = sha256()
    for entry in _enumerate_entries(path):
        relpath_bytes = entry.relpath.encode("utf-8")
        h.update(relpath_bytes)
        h.update(b"\x00")
        h.update(entry.mode_marker)
        h.update(b"\x00")
        h.update(entry.content)
        h.update(b"\x00")
    return h.hexdigest()


class _Entry:
    """Internal: one tree entry to be hashed."""
    __slots__ = ("relpath", "mode_marker", "content")

    def __init__(self, relpath: str, mode_marker: bytes, content: bytes):
        self.relpath = relpath
        self.mode_marker = mode_marker
        self.content = content


def _enumerate_entries(root: Path) -> list[_Entry]:
    """Walk `root`, yielding canonical _Entry records.

    Skips:
      - .git/ directories at any depth (provenance, not content)
      - directories themselves (only their file/symlink entries count)
      - empty directories (silently)

    Symlinks are NOT followed; their target string is hashed as content
    with the symlink mode marker.
    """
    entries: list[_Entry] = []
    for p in root.rglob("*"):
        # Exclude anything under .git/
        if ".git" in p.parts:
            continue

        if p.is_symlink():
            # Hash the link target string as content; don't follow.
            target = os.readlink(p).encode("utf-8")
            entries.append(_Entry(
                relpath=p.relative_to(root).as_posix(),
                mode_marker=MODE_SYMLINK,
                content=target,
            ))
        elif p.is_file():
            mode = p.stat().st_mode
            marker = (
                MODE_EXECUTABLE if mode & stat.S_IXUSR else MODE_REGULAR
            )
            entries.append(_Entry(
                relpath=p.relative_to(root).as_posix(),
                mode_marker=marker,
                content=p.read_bytes(),
            ))
        # else: directory (skipped — only file/symlink entries contribute)

    entries.sort(key=lambda e: e.relpath)
    return entries
