#!/usr/bin/env python3
"""Standalone reference oracle for the epoch-2 ``dag-sha256:`` Merkle-DAG identity.

This file is the **frozen cross-impl oracle** for milpa identity epoch 2
(RFC ``rfc-identity-conformance-authority`` slice B1; ``spec/identity.md`` §1.8).
It implements ONLY the normative byte encoding of the canonical content
Merkle-DAG and nothing else.

NON-NEGOTIABLE DISCIPLINE
-------------------------
* This script MUST NOT import milpa (``identity.py``, the Rust core, or any
  implementation under test). An oracle that shares code with the impl cannot
  catch a shared bug (the differential-test blind spot). It transcribes the
  spec directly from the byte tables in ``spec/identity.md`` §1.8.
* The pinned digests this script produces are the **expected oracle values** for
  the epoch-2 conformance fixtures. Both milpa impls implement B2 against these
  hand-frozen pins, never against each other.

It is intentionally tiny and auditable: read it against ``spec/identity.md``
§1.8 line by line.

Encoding (spec/identity.md §1.8)
--------------------------------
Blob node:  ``H_blob = sha256(content-bytes)``  (transport-neutral; for a
            symlink the content is the UTF-8 target string).

Tree-node entry, per immediate child, exactly::

    <uint32-be name-length> <name-bytes> <mode-byte> <32-byte child-digest-raw>

  * ``name-bytes``  — the UTF-8 *leaf* name (single path component).
  * ``mode-byte``   — 0x00 regular, 0x01 executable, 0x80 symlink, 0x40 tree.
  * ``child-digest-raw`` — the RAW 32-byte sha256 of the child node (blob or
    tree). Never the ASCII ``dag-sha256:`` string.

Entries are concatenated in ascending UTF-8 byte order of the leaf name (NOT the
full relpath). ``H_tree = sha256(concat(entries))``.

A zero-entry tree contributes NO entry to its parent (applied recursively). The
empty source tree is the zero-entry root, whose digest is therefore
``sha256(b"")``.

The identity string is ``dag-sha256:`` + the lowercase hex of the root tree
digest.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Mode bytes (spec/identity.md §1.8 mode-byte table).
_MODE_REGULAR = 0x00
_MODE_EXECUTABLE = 0x01
_MODE_SYMLINK = 0x80
_MODE_TREE = 0x40

# String mode -> blob mode-byte (the fixture JSON carries the string form).
_BLOB_MODE_BYTE = {
    "regular": _MODE_REGULAR,
    "executable": _MODE_EXECUTABLE,
    "symlink": _MODE_SYMLINK,
}

# A leaf-name ceiling of 4096 bytes is normative (ID-NAME-TOO-LONG). The oracle
# enforces it so a fixture that violates the spec cannot be silently pinned.
_NAME_CEILING = 4096


def _h_blob(content: bytes) -> bytes:
    """Blob node digest: raw 32-byte sha256 of the content bytes."""
    return hashlib.sha256(content).digest()


def _encode_entry(name: str, mode_byte: int, child_digest: bytes) -> bytes:
    """Serialize one tree-node entry per the §1.8 byte layout."""
    name_bytes = name.encode("utf-8")
    if len(name_bytes) > _NAME_CEILING:
        raise ValueError(f"ID-NAME-TOO-LONG: {name!r} is {len(name_bytes)} bytes (> {_NAME_CEILING})")
    if len(child_digest) != 32:
        raise ValueError("child digest must be raw 32 bytes")
    return (
        len(name_bytes).to_bytes(4, "big")
        + name_bytes
        + bytes([mode_byte])
        + child_digest
    )


# A tree node is modelled as a nested dict:
#   {"files":  {leaf_name: (mode_str, content_bytes)},
#    "subdirs": {leaf_name: <tree node dict>}}
def _empty_node() -> Dict[str, Any]:
    return {"files": {}, "subdirs": {}}


def _insert(root: Dict[str, Any], parts: List[str], mode: str, content: bytes) -> None:
    """Insert a flat (relpath-parts, mode, content) entry into the nested tree."""
    *dirs, leaf = parts
    node = root
    for d in dirs:
        node = node["subdirs"].setdefault(d, _empty_node())
    node["files"][leaf] = (mode, content)


def _h_tree(node: Dict[str, Any]) -> bytes:
    """Tree node digest: bottom-up, children sorted by leaf-name byte order.

    Returns ``None`` (sentinel via empty-marker) is NOT used; instead a
    zero-entry tree returns the digest of the empty byte string, and the caller
    (a parent) decides whether to omit it. We return a (digest, is_empty) pair so
    the empty-dir-omission rule can be applied recursively.
    """
    # Collect candidate (leaf_name, mode_byte, child_digest) entries.
    entries: List[Tuple[str, int, bytes]] = []

    # Blob children (regular / executable / symlink).
    for leaf, (mode, content) in node["files"].items():
        entries.append((leaf, _BLOB_MODE_BYTE[mode], _h_blob(content)))

    # Subtree children (mode 0x40). Empty subtrees contribute NO entry (recursive).
    for leaf, sub in node["subdirs"].items():
        sub_digest, sub_empty = _h_tree_with_emptiness(sub)
        if sub_empty:
            continue  # omit empty subdirectory from the parent
        entries.append((leaf, _MODE_TREE, sub_digest))

    # Canonical order: ascending UTF-8 byte order of the leaf name.
    entries.sort(key=lambda e: e[0].encode("utf-8"))

    blob = b"".join(_encode_entry(name, mode_byte, dig) for name, mode_byte, dig in entries)
    return hashlib.sha256(blob).digest()


def _h_tree_with_emptiness(node: Dict[str, Any]) -> Tuple[bytes, bool]:
    """Return (tree_digest, is_empty_after_omission).

    A tree is empty when, after recursively omitting empty subdirectories, it has
    zero entries. ``is_empty`` is what the parent uses to decide omission.
    """
    # Determine emptiness: any file, or any non-empty subdir.
    has_entry = bool(node["files"])
    if not has_entry:
        for sub in node["subdirs"].values():
            _, sub_empty = _h_tree_with_emptiness(sub)
            if not sub_empty:
                has_entry = True
                break
    return _h_tree(node), (not has_entry)


def compute_dag_sha256(entries: List[Dict[str, Any]]) -> str:
    """Compute the ``dag-sha256:`` identity of a flat materialized entry sequence.

    ``entries`` is a list of ``{"relpath": str, "mode": str, "content": str}``
    dicts (the B2 materializer's ``(relpath, mode, bytes)`` triples). ``content``
    is interpreted as UTF-8 text in the fixture JSON; for a symlink it is the
    link target string.

    Any path component named ``.git`` excludes the entry (spec §1.4).
    """
    root = _empty_node()
    for e in entries:
        relpath = e["relpath"]
        parts = relpath.split("/")
        if ".git" in parts:
            continue  # §1.4 exclusion, applied before DAG construction
        mode = e["mode"]
        content = e["content"].encode("utf-8")
        _insert(root, parts, mode, content)

    digest, _empty = _h_tree_with_emptiness(root)
    return "dag-sha256:" + digest.hex()


def compute_for_fixture(fixture_dir: Path) -> str:
    """Read a ``dag-oracle.json`` fixture and return its computed identity."""
    spec = json.loads((fixture_dir / "dag-oracle.json").read_text(encoding="utf-8"))
    return compute_dag_sha256(spec.get("entries", []))


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: dag_sha256_reference.py <fixture-dir>", file=sys.stderr)
        return 2
    print(compute_for_fixture(Path(argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
