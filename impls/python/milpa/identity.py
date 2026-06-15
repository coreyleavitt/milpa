"""Content-addressed identity — sha256 of a source tree per spec/identity.md.

milpa's *identity* of a dep is the sha256 hash of its source tree, computed by
walking every file and symlink entry under the tree root and feeding a canonical
byte stream into sha256. The hash is transport-independent, provenance-independent,
and recomputable from the bytes on disk alone.

Canonical byte stream (identity.md §1.2):
    For each entry under `path` (excluding .git/ at any depth, §1.4):
        <relpath-bytes> 0x00 <mode-marker> 0x00 <content-bytes> 0x00
    Entries sorted by raw UTF-8 byte-order of their relpath (§1.3).
    mode-marker is a single byte:
        0x00 — regular file (Resolved Decision 1: exec bit excluded from identity)
        0x80 — symbolic link (content-bytes = link-target UTF-8)
    Empty directories contribute no bytes (§1.2).

Identity string (identity.md §2.1):
    sha256:<64-lowercase-hex-chars>

parse_identity five ordered checks (identity.md §2.2):
    1. Must be a string              → ID-NOT-A-STRING
    2. Must contain ':'              → ID-NO-ALGORITHM-PREFIX
    3. Algorithm in supported set    → ID-UNSUPPORTED-ALGORITHM
    4. Digest length correct         → ID-WRONG-DIGEST-LENGTH
    5. Digest all lowercase hex      → ID-NON-HEX-DIGEST
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from milpa.errors import (
    ID_NO_ALGORITHM_PREFIX,
    ID_NON_HEX_DIGEST,
    ID_NON_UTF8_RELPATH,
    ID_NON_UTF8_SYMLINK_TARGET,
    ID_NOT_A_STRING,
    ID_UNSUPPORTED_ALGORITHM,
    ID_WRONG_DIGEST_LENGTH,
    MilpaError,
)

# ---------------------------------------------------------------------------
# Algorithm table (identity.md §2.3 algorithm-agility dispatch)
# ---------------------------------------------------------------------------

#: The set of algorithm prefixes milpa currently accepts in identity strings.
#: Adding a new algorithm: add it here and to _DIGEST_HEX_LEN below; no other
#: changes required in this module.
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"sha256"})

#: Expected hex-character length of the digest part for each algorithm.
_DIGEST_HEX_LEN: dict[str, int] = {"sha256": 64}

# ---------------------------------------------------------------------------
# Mode markers (identity.md §1.2)
# ---------------------------------------------------------------------------

_MODE_REGULAR: bytes = b"\x00"   # regular file — exec bit excluded (Resolved Decision 1)
_MODE_SYMLINK: bytes = b"\x80"


# ---------------------------------------------------------------------------
# parse_identity — 5 ordered checks (identity.md §2.2)
# ---------------------------------------------------------------------------


def parse_identity(s: Any) -> str:
    """Validate a multihash-encoded identity string.

    Applies the five ordered checks from identity.md §2.2 in order.
    Returns the input string unchanged when valid (the canonical form IS the
    input itself).

    Raises:
        MilpaError(ID_NOT_A_STRING)            — input is not a str
        MilpaError(ID_NO_ALGORITHM_PREFIX)     — no ':' separator
        MilpaError(ID_UNSUPPORTED_ALGORITHM)   — algorithm not in SUPPORTED_ALGORITHMS
        MilpaError(ID_WRONG_DIGEST_LENGTH)     — digest length wrong for algorithm
        MilpaError(ID_NON_HEX_DIGEST)         — digest contains non-lowercase-hex chars
    """
    # Check 1: must be a string (identity.md §2.2 rule 1)
    if not isinstance(s, str):
        raise MilpaError(
            ID_NOT_A_STRING,
            f"identity must be a string, got {type(s).__name__!r}",
            got_type=type(s).__name__,
        )

    # Check 2: must contain ':' separator (identity.md §2.2 rule 2)
    if ":" not in s:
        raise MilpaError(
            ID_NO_ALGORITHM_PREFIX,
            f"identity {s!r} is missing the algorithm prefix; "
            f"expected '<algorithm>:<digest>' (e.g. 'sha256:abc...')",
            identity=s,
        )

    algorithm, _, digest = s.partition(":")

    # Check 3: algorithm must be supported (identity.md §2.2 rule 3)
    if algorithm not in SUPPORTED_ALGORITHMS:
        allowed = ", ".join(sorted(SUPPORTED_ALGORITHMS))
        raise MilpaError(
            ID_UNSUPPORTED_ALGORITHM,
            f"identity {s!r} uses unsupported algorithm {algorithm!r} "
            f"(supported: {allowed})",
            algorithm=algorithm,
            identity=s,
        )

    expected_len = _DIGEST_HEX_LEN[algorithm]

    # Check 4: digest length must be correct (identity.md §2.2 rule 4)
    if len(digest) != expected_len:
        raise MilpaError(
            ID_WRONG_DIGEST_LENGTH,
            f"identity {s!r}: {algorithm} digest must be exactly "
            f"{expected_len} hex characters, got {len(digest)}",
            algorithm=algorithm,
            expected=expected_len,
            got=len(digest),
            identity=s,
        )

    # Check 5: digest must be lowercase hex only (identity.md §2.2 rule 5)
    if not all(c in "0123456789abcdef" for c in digest):
        raise MilpaError(
            ID_NON_HEX_DIGEST,
            f"identity {s!r}: digest must be lowercase hex characters (0-9, a-f)",
            identity=s,
        )

    return s


# ---------------------------------------------------------------------------
# compute_content_hash (identity.md §1)
# ---------------------------------------------------------------------------


def compute_content_hash(path: Path) -> str:
    """Compute the sha256 content hash of the source tree at `path`.

    Returns the multihash-encoded identity string ``sha256:<64-hex>``.
    The ``sha256:`` prefix is the canonical form (identity.md §2.1).

    Same source bytes always produce the same hash regardless of how the tree
    was obtained (git, tarball, OCI, local copy) — identity is transport- and
    provenance-independent.

    Raises:
        MilpaError(ID_NON_UTF8_SYMLINK_TARGET) — a symlink's target cannot be
            encoded as UTF-8 (identity.md §1.5).
    """
    h = sha256()
    for entry in _enumerate_entries(path):
        h.update(entry.relpath.encode("utf-8"))
        h.update(b"\x00")
        h.update(entry.mode_marker)
        h.update(b"\x00")
        h.update(entry.content)
        h.update(b"\x00")
    return f"sha256:{h.hexdigest()}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Entry:
    """One file/symlink tree entry destined for the hash accumulator."""

    relpath: str     # POSIX relative path from tree root, UTF-8
    mode_marker: bytes  # one of _MODE_REGULAR / _MODE_SYMLINK
    content: bytes   # file bytes, or symlink-target UTF-8 bytes


def _enumerate_entries(root: Path) -> list[_Entry]:
    """Walk `root`, collecting one _Entry per file and symlink.

    Exclusions (identity.md §1.4):
      - Any path component named ``.git`` at any depth.
      - Directories themselves (only their file/symlink children contribute).
      - Empty directories (implicitly — they have no children to collect).

    Symlinks are NOT followed (identity.md §1.5): a symlink-to-directory is
    a leaf entry, not a recursion point.

    Entries are returned sorted by raw UTF-8 byte-order of their relpath
    (identity.md §1.3).
    """
    entries: list[_Entry] = []
    for p in root.rglob("*"):
        # §1.4: exclude .git and everything beneath it at any depth.
        if ".git" in p.parts:
            continue

        # §1.3 / spec/errors.md ID-NON-UTF8-RELPATH: the relpath is encoded
        # as UTF-8 in the canonical byte stream.  On POSIX, filenames are raw
        # byte sequences; Python surrogate-escapes non-UTF-8 bytes in the str
        # representation.  Pre-check that the relpath encodes cleanly; raise a
        # coded MilpaError instead of letting UnicodeEncodeError escape from
        # compute_content_hash (mirrors the ID-NON-UTF8-SYMLINK-TARGET pattern).
        relpath_str = p.relative_to(root).as_posix()
        try:
            relpath_str.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise MilpaError(
                ID_NON_UTF8_RELPATH,
                f"file path {relpath_str!r} is not valid UTF-8 "
                f"— cannot compute a content hash",
                relpath=relpath_str,
            ) from exc

        if p.is_symlink():
            # §1.5: hash the link-target string as UTF-8; do not follow.
            raw_target = os.readlink(p)
            try:
                content = raw_target.encode("utf-8")
            except UnicodeEncodeError as exc:
                # os.readlink() surrogate-escapes non-UTF-8 bytes on POSIX;
                # re-encoding to UTF-8 then fails.  A non-UTF-8 symlink target
                # cannot be represented in the canonical byte stream (§1.5 /
                # Normative surface rule 12).
                raise MilpaError(
                    ID_NON_UTF8_SYMLINK_TARGET,
                    f"symlink target at {relpath_str!r} is not valid UTF-8 "
                    f"— cannot compute a content hash",
                    relpath=relpath_str,
                ) from exc
            entries.append(
                _Entry(
                    relpath=relpath_str,
                    mode_marker=_MODE_SYMLINK,
                    content=content,
                )
            )
        elif p.is_file():
            # Resolved Decision 1: exec bit is NOT part of identity.
            # Regular files always use _MODE_REGULAR (0x00).
            entries.append(
                _Entry(
                    relpath=relpath_str,
                    mode_marker=_MODE_REGULAR,
                    content=p.read_bytes(),  # §1.6: raw bytes, no line-ending normalisation
                )
            )
        # else: directory — skip; empty dirs contribute nothing (§1.2).

    # §1.3: sort by raw UTF-8 byte-order of relpath.
    # Python's default str sort is lexicographic on Unicode code points.
    # For valid POSIX paths (which are pure ASCII or valid UTF-8 sequences)
    # this is equivalent to raw-byte order.
    entries.sort(key=lambda e: e.relpath)
    return entries
