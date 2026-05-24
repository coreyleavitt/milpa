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


# Multihash-encoded identity (#34) — the canonical in-memory and on-
# disk form for milpa identity strings is `<algorithm>:<digest-hex>`.
# Currently only sha256 is supported. Adding a future algorithm:
#   1. Add to SUPPORTED_ALGORITHMS with its digest length
#   2. Update compute_content_hash branch (or add a sibling function)
#   3. During the migration window, lockfiles may carry BOTH the old
#      and new algorithm per dep; both are written, only the new one
#      is required to match for verification. (Not yet implemented;
#      content_hash today is a single string, not a list.)

SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"sha256"})

# Digest length in hex characters per algorithm
_DIGEST_HEX_LEN: dict[str, int] = {"sha256": 64}


class IdentityError(ValueError):
    """Raised by parse_identity when an identity string is malformed
    or uses an unsupported algorithm."""


def parse_identity(s: str) -> str:
    """Validate a multihash-encoded identity string.

    Accepts: `<algorithm>:<digest-hex>` where algorithm is in
    SUPPORTED_ALGORITHMS and the digest is the right length of
    lowercase hex characters.

    Returns the input string unchanged when valid (canonical form).
    Raises IdentityError naming the specific failure mode otherwise.
    """
    if not isinstance(s, str):
        raise IdentityError(
            f"identity must be a string, got {type(s).__name__}"
        )
    if ":" not in s:
        raise IdentityError(
            f"identity {s!r} is missing the algorithm prefix; "
            f"expected '<algorithm>:<digest>' (e.g. 'sha256:abc...')"
        )
    algorithm, _, digest = s.partition(":")
    if algorithm not in SUPPORTED_ALGORITHMS:
        allowed = ", ".join(sorted(SUPPORTED_ALGORITHMS))
        raise IdentityError(
            f"identity {s!r} uses unsupported algorithm {algorithm!r} "
            f"(supported: {allowed})"
        )
    expected_len = _DIGEST_HEX_LEN[algorithm]
    if len(digest) != expected_len:
        raise IdentityError(
            f"identity {s!r}: {algorithm} digest must be exactly "
            f"{expected_len} hex characters, got {len(digest)}"
        )
    if not all(c in "0123456789abcdef" for c in digest):
        raise IdentityError(
            f"identity {s!r}: digest must be lowercase hex characters "
            f"(0-9, a-f)"
        )
    return s


def compute_content_hash(path: Path) -> str:
    """Compute the sha256 content hash of the source tree at `path`.

    Returns the multihash-encoded identity string `sha256:<64-hex>`.
    Same input bytes always produce the same hash, regardless of
    host filesystem, clone location, or transport. The `sha256:`
    prefix is part of the canonical form (#34) — every layer that
    handles identity in milpa expects the prefix to be present.
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
    return f"sha256:{h.hexdigest()}"


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
