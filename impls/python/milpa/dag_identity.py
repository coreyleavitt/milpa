"""Epoch-2 canonical content Merkle-DAG identity — the production builder.

This module is milpa's **production** epoch-2 identity builder (spec/identity.md
§1.8), landed by RFC ``rfc-identity-conformance-authority`` slice B2. It is the
single source of truth for the canonical Merkle-DAG digest in the Python impl.

Two pieces live here:

* ``MaterializedEntry`` — the **materialize seam** type. Every per-transport
  materializer (git first, then tarball / local / oci) produces a *buffered,
  fully-collected* ``Sequence[MaterializedEntry]`` (spec §1.8.4: not a streaming
  hash feed). The DAG builder is a pure function over that sequence.
* ``compute_dag_identity`` — the pure builder: group the flat entry sequence by
  directory, build tree nodes **bottom-up**, sort each level's immediate
  children by **leaf name** (NOT full relpath — spec §1.8.3, the top cross-impl
  divergence risk), apply the empty-directory-omission rule, and return the root
  ``H_tree`` as ``dag-sha256:<hex>``.

DISCIPLINE — this builder is **independent** of the conformance oracle
(``conformance/spec-v1/_oracle/dag_sha256_reference.py``). It MUST NOT import the
oracle and the oracle MUST NOT import it: their agreement on the hand-frozen
pinned digests is the differential check (the differential-test blind spot — an
oracle that shares code with the impl cannot catch a shared bug). This file is
transcribed directly from the spec §1.8 byte tables.

Staging note (B2): epoch-2 is NOT yet the default emission. ``compute_content_hash``
in ``identity.py`` still emits the interim epoch-1 flat digest; this builder is
exercised only by the ``dag-oracle`` conformance tier until B-cutover flips the
default. The transient two-path state is intended (removed at cutover).

Byte encoding (spec/identity.md §1.8)
-------------------------------------
Blob node:  ``H_blob = sha256(content-bytes)`` — transport-neutral, NOT git's
            ``blob <len>\\0<content>``. For a symlink, ``content-bytes`` is the
            UTF-8 link-target string (§1.8.1).

Tree node entry, per immediate child, concatenated with no separators::

    <uint32-be name-length> <name-bytes> <mode-byte> <32-byte child-digest-raw>

  * ``name-bytes``      — UTF-8 *leaf* name (single path component, no ``/``).
  * ``mode-byte``       — 0x00 regular, 0x01 executable, 0x80 symlink, 0x40 tree.
  * ``child-digest-raw``— raw 32-byte sha256 of the child node (never the ASCII
                          ``dag-sha256:`` string).

Entries are concatenated in ascending UTF-8 byte order of the **leaf name**;
``H_tree = sha256(concat(entries))``. A zero-entry tree node contributes no
entry to its parent (applied recursively). The empty source tree is the
zero-entry root, whose digest is therefore ``sha256(b"")``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Iterable

from milpa.errors import ID_NAME_TOO_LONG, MilpaError

# ---------------------------------------------------------------------------
# Mode bytes (spec/identity.md §1.8.2.1 — the four-valued type tag)
# ---------------------------------------------------------------------------

MODE_REGULAR: int = 0x00
MODE_EXECUTABLE: int = 0x01
MODE_SYMLINK: int = 0x80
MODE_TREE: int = 0x40

#: Blob mode-bytes a materializer may emit (a tree byte is builder-internal).
_BLOB_MODE_BYTES: frozenset[int] = frozenset(
    {MODE_REGULAR, MODE_EXECUTABLE, MODE_SYMLINK}
)

#: Leaf-name byte ceiling (spec/identity.md §1.8.8 — ID-NAME-TOO-LONG).
NAME_BYTE_CEILING: int = 4096

#: Path component whose presence excludes an entry at any depth (spec §1.4/§1.8.6).
_GIT_COMPONENT: str = ".git"


# ---------------------------------------------------------------------------
# The materialize seam type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MaterializedEntry:
    """One materialized blob or symlink — the unit of the materialize seam.

    A per-transport materializer yields a buffered ``Sequence[MaterializedEntry]``
    for the whole tree; the DAG builder is a pure function over it (spec §1.8.4).
    The seam carries **only** blob/symlink leaves — subtree (mode ``0x40``) nodes
    are synthesised by the builder from the directory structure of the relpaths,
    never emitted by a materializer.

    Attributes:
        relpath:   POSIX relative path from the tree root (``/`` separators, no
                   leading ``/`` or ``./``), e.g. ``src/foo.nim``.
        mode_byte: One of ``MODE_REGULAR`` (0x00), ``MODE_EXECUTABLE`` (0x01), or
                   ``MODE_SYMLINK`` (0x80).
        content:   Raw blob bytes. For a symlink this is the UTF-8 link-target
                   string (§1.8.1); the symlink is not followed.
    """

    relpath: str
    mode_byte: int
    content: bytes


# ---------------------------------------------------------------------------
# Internal nested-tree model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Node:
    """A directory node under construction: leaf blobs + named subdirectories."""

    #: leaf name -> (mode_byte, content) for blob/symlink children
    blobs: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    #: leaf name -> child _Node for subdirectory children
    subdirs: dict[str, "_Node"] = field(default_factory=dict)


def _check_name(name: str) -> bytes:
    """UTF-8-encode a leaf name, enforcing the §1.8.8 byte ceiling."""
    name_bytes = name.encode("utf-8")
    if len(name_bytes) > NAME_BYTE_CEILING:
        raise MilpaError(
            ID_NAME_TOO_LONG,
            f"path component {name!r} is {len(name_bytes)} bytes, exceeding the "
            f"{NAME_BYTE_CEILING}-byte epoch-2 leaf-name ceiling (spec/identity.md §1.8.8)",
            name=name,
            length=len(name_bytes),
        )
    return name_bytes


def _insert(root: _Node, parts: list[str], mode_byte: int, content: bytes) -> None:
    """Insert one materialized entry into the nested tree at ``parts``."""
    node = root
    for component in parts[:-1]:
        _check_name(component)  # interior component names are entry names too
        node = node.subdirs.setdefault(component, _Node())
    leaf = parts[-1]
    _check_name(leaf)
    node.blobs[leaf] = (mode_byte, content)


def _encode_entry(name_bytes: bytes, mode_byte: int, child_digest: bytes) -> bytes:
    """Serialize one tree-node entry per the §1.8.2 byte layout."""
    return (
        len(name_bytes).to_bytes(4, "big")
        + name_bytes
        + bytes([mode_byte])
        + child_digest
    )


def _hash_tree(node: _Node) -> tuple[bytes, bool]:
    """Return ``(H_tree, is_empty)`` for a directory node (spec §1.8.2–§1.8.5).

    ``is_empty`` is ``True`` when the node has no entries after recursively
    omitting empty subdirectories — the signal a parent uses to drop it (§1.8.5).
    """
    # (leaf_name, name_bytes, mode_byte, child_digest_raw)
    items: list[tuple[bytes, int, bytes]] = []

    # Blob/symlink children: H_blob = sha256(content) (§1.8.1).
    for leaf, (mode_byte, content) in node.blobs.items():
        name_bytes = _check_name(leaf)
        items.append((name_bytes, mode_byte, sha256(content).digest()))

    # Subtree children (mode 0x40). Empty subtrees contribute NO entry (§1.8.5).
    for leaf, sub in node.subdirs.items():
        sub_digest, sub_empty = _hash_tree(sub)
        if sub_empty:
            continue
        name_bytes = _check_name(leaf)
        items.append((name_bytes, MODE_TREE, sub_digest))

    # §1.8.3: ascending UTF-8 byte order of the LEAF NAME (not the full relpath).
    items.sort(key=lambda it: it[0])

    blob = b"".join(_encode_entry(nb, mode, dig) for (nb, mode, dig) in items)
    return sha256(blob).digest(), (len(items) == 0)


# ---------------------------------------------------------------------------
# The public builder
# ---------------------------------------------------------------------------


def compute_dag_identity(entries: Iterable[MaterializedEntry]) -> str:
    """Compute the epoch-2 ``dag-sha256:`` identity of a materialized sequence.

    Pure function over a buffered ``Sequence[MaterializedEntry]`` (spec §1.8.4).
    Groups entries by directory, builds tree nodes bottom-up, sorts each level's
    children by leaf name (§1.8.3), omits empty subdirectories (§1.8.5), and
    returns the root ``H_tree`` as ``dag-sha256:<64-lowercase-hex>`` (§2.1).

    The empty source tree yields ``dag-sha256:`` + ``sha256(b"")`` (§1.8.5).

    Raises:
        MilpaError(ID_NAME_TOO_LONG): a path component exceeds 4096 bytes (§1.8.8).
    """
    root = _Node()
    for entry in entries:
        parts = entry.relpath.split("/")
        # §1.8.6 (inherits §1.4): drop any path with a `.git` component, any depth.
        if _GIT_COMPONENT in parts:
            continue
        if entry.mode_byte not in _BLOB_MODE_BYTES:
            raise ValueError(
                f"materialized entry {entry.relpath!r} has non-blob mode-byte "
                f"{entry.mode_byte:#04x}; materializers emit only 0x00/0x01/0x80"
            )
        _insert(root, parts, entry.mode_byte, entry.content)

    digest, _empty = _hash_tree(root)
    return f"dag-sha256:{digest.hex()}"
