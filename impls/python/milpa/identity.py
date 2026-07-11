"""Content-addressed identity — the canonical content Merkle DAG of a source tree.

milpa's *identity* of a dep is the ``dag-sha256:`` digest of the canonical content
Merkle DAG (spec/identity.md §1.8) of its source tree. The hash is
transport-independent, provenance-independent, and recomputable from the bytes on
disk alone.

Computation (identity.md §1.8, epoch 2 — the forever format):
    ``compute_content_hash(path)`` walks the on-disk tree into a buffered
    ``list[MaterializedEntry]`` (the **canonical disk walk**, ``enumerate_local_entries``)
    and feeds it to the pure Merkle-DAG builder
    (``milpa.dag_identity.compute_dag_identity``). The disk walk is the single
    source of truth for turning real on-disk bytes + POSIX mode bits into the
    materialize seam; every transport that lands a tree on disk (git, tarball,
    local) inherits this identity uniformly, and CAS verify re-hashes the stored
    tree through the same walk.

    Cross-cutting content rules (shared with the per-transport object-store seams):
      - `.git` excluded at any depth (§1.4 / §1.8.6).
      - symlinks hashed by their UTF-8 target string, never followed (§1.5).
      - raw bytes, no line-ending normalization (§1.6).
      - the executable bit is part of identity (epoch 2, §1.8.2 — mode-byte 0x01).
      - non-UTF-8 relpaths / symlink targets are coded errors (§1.5).

Identity string (identity.md §2.1):
    dag-sha256:<64-lowercase-hex-chars>

    The scheme prefix is ``dag-sha256`` and now names the *actual* canonical
    content Merkle DAG of §1.8 (the interim epoch-1 flat byte stream is retired).
    A stale ``sha256:`` prefix is rejected as ID-UNSUPPORTED-ALGORITHM at parse
    time — re-lock with `milpa fetch`.

parse_identity five ordered checks (identity.md §2.2):
    1. Must be a string              → ID-NOT-A-STRING
    2. Must contain ':'              → ID-NO-ALGORITHM-PREFIX
    3. Algorithm in CANONICAL_SCHEMES → ID-UNSUPPORTED-ALGORITHM
       (sha256: and all other prefixes are rejected; only dag-sha256: is canonical)
    4. Digest length correct         → ID-WRONG-DIGEST-LENGTH
    5. Digest all lowercase hex      → ID-NON-HEX-DIGEST
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from milpa.dag_identity import (
    MODE_EXECUTABLE,
    MODE_REGULAR,
    MODE_SYMLINK,
    MaterializedEntry,
    compute_dag_identity,
)
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
# Algorithm table (identity.md §2.2 two-tier scheme classification)
# ---------------------------------------------------------------------------

#: Canonical scheme set — the ONLY accepted prefixes in identity strings.
#: Stale sha256: and all other prefixes are rejected as ID-UNSUPPORTED-ALGORITHM.
#: Adding a future canonical scheme: add it here and to _DIGEST_HEX_LEN below.
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"dag-sha256"})

#: Expected hex-character length of the digest part for each canonical algorithm.
_DIGEST_HEX_LEN: dict[str, int] = {"dag-sha256": 64}


# ---------------------------------------------------------------------------
# parse_identity — 5 ordered checks (identity.md §2.2)
# ---------------------------------------------------------------------------


def split_identity_scheme(s: Any) -> tuple[str, str]:
    """Split an identity string into its raw ``(algorithm, digest)`` halves.

    Applies only the first two ordered checks from identity.md §2.2 — "must be
    a string" and "must contain a ``:`` separator" — WITHOUT enforcing the
    canonical-scheme allowlist (checks 3-5, ``SUPPORTED_ALGORITHMS``). This is
    the shared validation seam for callers that only need the raw scheme
    split and must not silently no-op on malformed input — currently
    ``parse_identity`` itself, and ``entry_trust.build_entry_subject``, which
    extracts a hex digest from a ``content_hash`` without needing (or
    wanting) to couple itself to ``SUPPORTED_ALGORITHMS``.

    Raises:
        MilpaError(ID_NOT_A_STRING)        — input is not a str
        MilpaError(ID_NO_ALGORITHM_PREFIX) — no ':' separator
    """
    if not isinstance(s, str):
        raise MilpaError(
            ID_NOT_A_STRING,
            f"identity must be a string, got {type(s).__name__!r}",
            got_type=type(s).__name__,
        )
    if ":" not in s:
        raise MilpaError(
            ID_NO_ALGORITHM_PREFIX,
            f"identity {s!r} is missing the algorithm prefix; "
            f"expected '<algorithm>:<digest>' (e.g. 'dag-sha256:abc...')",
            identity=s,
        )
    algorithm, _, digest = s.partition(":")
    return algorithm, digest


def parse_identity(s: Any) -> str:
    """Validate a milpa identity string (two-tier scheme check).

    Applies the five ordered checks from identity.md §2.2 in order.
    Returns the input string unchanged when valid (the canonical form IS the
    input itself).

    Only dag-sha256: is accepted (CANONICAL_SCHEMES = SUPPORTED_ALGORITHMS).
    sha256: and all other prefixes → ID-UNSUPPORTED-ALGORITHM (no legacy tier;
    re-lock with `milpa fetch`).

    Raises:
        MilpaError(ID_NOT_A_STRING)            — input is not a str
        MilpaError(ID_NO_ALGORITHM_PREFIX)     — no ':' separator
        MilpaError(ID_UNSUPPORTED_ALGORITHM)   — algorithm not in SUPPORTED_ALGORITHMS
                                                 (includes stale sha256: identities)
        MilpaError(ID_WRONG_DIGEST_LENGTH)     — digest length wrong for algorithm
        MilpaError(ID_NON_HEX_DIGEST)         — digest contains non-lowercase-hex chars
    """
    # Checks 1-2: must be a string, must contain ':' separator (identity.md
    # §2.2 rules 1-2) — delegated to the shared split_identity_scheme seam.
    algorithm, digest = split_identity_scheme(s)

    # Check 3: algorithm must be in the canonical scheme set (identity.md §2.2 rule 3).
    # Two-tier: CANONICAL_SCHEMES = {dag-sha256}; everything else (including the
    # legacy sha256: prefix) is rejected with no compatibility path — re-lock.
    if algorithm not in SUPPORTED_ALGORITHMS:
        allowed = ", ".join(sorted(SUPPORTED_ALGORITHMS))
        hint = (
            " (stale epoch-1 hash — re-lock with `milpa fetch`)"
            if algorithm == "sha256"
            else ""
        )
        raise MilpaError(
            ID_UNSUPPORTED_ALGORITHM,
            f"identity {s!r} uses unsupported algorithm {algorithm!r}"
            f"{hint} (supported: {allowed})",
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
# compute_content_hash (identity.md §1.8) — the production epoch-2 emitter
# ---------------------------------------------------------------------------


def compute_content_hash(path: Path) -> str:
    """Compute the canonical content Merkle-DAG identity of the tree at ``path``.

    Returns the identity string ``dag-sha256:<64-hex>`` (identity.md §2.1). The
    digest is the root of the canonical content Merkle DAG of §1.8: the on-disk
    tree is walked into a buffered ``list[MaterializedEntry]`` by
    ``enumerate_local_entries`` and folded by ``compute_dag_identity``.

    Same source bytes always produce the same hash regardless of how the tree
    was obtained (git, tarball, OCI, local copy) — identity is transport- and
    provenance-independent. The STEP-1 invariant (a git-materialized on-disk tree
    hashed here equals the git object-store enumeration) is what lets every
    transport, plus CAS verify, share this one identity site.

    Raises:
        MilpaError(ID_NON_UTF8_RELPATH)        — an on-disk name is not valid UTF-8.
        MilpaError(ID_NON_UTF8_SYMLINK_TARGET) — a symlink's target is not valid UTF-8.
        MilpaError(ID_NAME_TOO_LONG)           — a path component exceeds the
                                                  4096-byte leaf-name ceiling (§1.8.8).
    """
    return compute_dag_identity(enumerate_local_entries(Path(path)))


# ---------------------------------------------------------------------------
# enumerate_local_entries — the canonical on-disk walk (the local materialize seam)
# ---------------------------------------------------------------------------


def enumerate_local_entries(root: Path) -> list[MaterializedEntry]:
    """Walk an on-disk source directory into a buffered ``list[MaterializedEntry]``
    (spec §1.8.4) — the canonical disk walk that feeds the epoch-2 DAG builder.

    This is the single source of truth for turning real on-disk bytes + POSIX
    mode bits into the materialize seam. It is the universal identity walk:
    ``compute_content_hash`` uses it, and so does the local transport (the
    "local materialize seam" is exactly this walk applied to a local source dir,
    re-exported from ``milpa.fetchers.local`` for the per-transport sibling
    narrative). It is the local sibling of the object-store seams
    ``enumerate_git_entries`` / ``enumerate_tarball_entries``: a directory laid
    out from a git tree or a tarball reproduces the same ``dag-sha256:`` (spec §1.1).

    Mode mapping (spec §1.8.2.1):
      * regular file with any POSIX execute bit (``st_mode & 0o111``) → ``0x01``.
      * regular file with no execute bit → ``0x00``.
      * symlink → ``0x80``; content is the link-target string bytes (``readlink``),
        the link is not followed.
      * directories synthesise subtrees in the builder; a ``.git`` directory is
        skipped (not recursed) per §1.8.6.

    Args:
        root: Absolute path to the source directory to materialize. Symlinks within
              the tree are recorded as ``0x80`` leaves; the tree under ``root`` is
              walked without following symlinked directories.

    Returns:
        Buffered ``list[MaterializedEntry]`` (blobs + symlinks), POSIX relpaths.

    Raises:
        MilpaError(ID_NON_UTF8_RELPATH)        — an on-disk name is not valid UTF-8.
        MilpaError(ID_NON_UTF8_SYMLINK_TARGET) — a symlink target is not valid UTF-8.
    """
    root = Path(root)
    entries: list[MaterializedEntry] = []

    def _walk(dir_abs: str, prefix: str) -> None:
        with os.scandir(dir_abs) as it:
            children = sorted(it, key=lambda e: e.name)
        for entry in children:
            # §1.8.6 (inherits §1.4): exclude `.git` at any depth (skip recursing).
            if entry.name == ".git":
                continue
            relpath = _check_local_utf8(
                f"{prefix}{entry.name}",
                ID_NON_UTF8_RELPATH,
                f"local source path component {entry.name!r} is not valid UTF-8",
            )
            if entry.is_symlink():
                target = _check_local_utf8(
                    os.readlink(entry.path),
                    ID_NON_UTF8_SYMLINK_TARGET,
                    f"local symlink {relpath!r} target is not valid UTF-8",
                )
                entries.append(
                    MaterializedEntry(relpath, MODE_SYMLINK, target.encode("utf-8"))
                )
            elif entry.is_dir(follow_symlinks=False):
                _walk(entry.path, relpath + "/")
            elif entry.is_file(follow_symlinks=False):
                content = Path(entry.path).read_bytes()
                st_mode = entry.stat(follow_symlinks=False).st_mode
                mode_byte = MODE_EXECUTABLE if (st_mode & 0o111) else MODE_REGULAR
                entries.append(MaterializedEntry(relpath, mode_byte, content))
            # device nodes / FIFOs: silently skipped (never legitimate source).

    _walk(str(root), "")
    return entries


def _check_local_utf8(s: str, slug: str, message: str) -> str:
    """Return ``s`` if it round-trips through UTF-8, else raise ``MilpaError(slug)``.

    ``os.scandir`` / ``os.readlink`` decode names with ``surrogateescape``, so a
    non-UTF-8 byte sequence survives as lone surrogates that fail to re-encode.
    """
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MilpaError(
            slug, message, value=s.encode("utf-8", "backslashreplace").decode()
        ) from exc
    return s
