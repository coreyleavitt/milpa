"""DepDecl producer-side test helper — harness tooling only.

make_dep_decl_fixture(EdgeSet) → bytes

Emits a DepDecl artifact (KDL 2.0 bytes) for an EdgeSet following the
document shape specified in spec/dep-decl.md §2.  This helper is used by
S3b–S6 fixture generators to create DepDecl artifact files in
conformance/spec-v1/ dep-decl/ slots.

This is NOT a resolver component.  The resolver never serializes; it only
parses and hash-verifies.  See spec/dep-decl.md Appendix B.

The output is spec-conformant (correct document shape, field order, node
forms) but is NOT independently tested for byte-identity against the §2 rules
— that oracle role belongs to the hand-authored golden vector in
conformance/spec-v1/dep-decl-golden/v0/example.kdl.

Stdlib only — no 3rd-party deps.  This module MUST remain importable without
installing any impl or external library.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Union


# ---------------------------------------------------------------------------
# EdgeSet in-memory types
# (spec/dep-decl.md §1 — language-neutral; mirrored here for the harness)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NamedRequire:
    """A named (registry-resolved) requires entry."""
    name: str
    constraint_str: str   # raw declaration string, preserved as-written


@dataclass(frozen=True)
class UrlRequire:
    """A URL-based requires entry."""
    url: str
    ref: str


RequireEntry = Union[NamedRequire, UrlRequire]


@dataclass
class EdgeSet:
    """Language-neutral in-memory edge type (spec/dep-decl.md §1).

    Fields:
        requires  — ordered list of require entries (authored order)
        src_dir   — source directory string; "" when unset
        source    — fidelity tag (NOT serialized): "dep_decl" |
                    "milpa_kdl" | "nimble_fallback"
    """
    requires: list[RequireEntry] = field(default_factory=list)
    src_dir: str = ""
    source: str = "dep_decl"   # in-memory only; MUST NOT appear in output


# ---------------------------------------------------------------------------
# KDL 2.0 string escaping
# ---------------------------------------------------------------------------

def _kdl_str(value: str) -> str:
    """Return `value` as a KDL 2.0 double-quoted string literal.

    Applies the minimum required escaping:
      \\ for backslash, \" for double-quote, and \\n/\\r/\\t for the three
      most common control characters.  Other control chars use \\u{HHHH}.
    """
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{{{ord(ch):X}}}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


# ---------------------------------------------------------------------------
# canonical_serialize (spec/dep-decl.md §2)
# ---------------------------------------------------------------------------

def canonical_serialize(es: EdgeSet, schema_version: int = 0) -> bytes:
    """Serialize an EdgeSet to DepDecl artifact bytes per spec/dep-decl.md §2.

    Rules applied:
      §2 Rule 1 — Single dep_decl { … } node; 4-space child indent;
                  closing } on its own line; trailing newline.
      §2 Rule 2 — Field order: dep_decl_schema_version, src_dir, require nodes.
      §2 Rule 3 — require nodes in EdgeSet.requires authored order.
      §2 Rule 4 — require "<name>" "<constraint>"  for NamedRequire;
                  require (url)"<url>" ref="<ref>"  for UrlRequire.
      §2 Rule 5 — constraint_str verbatim (no normalization).
      §2 Rule 6 — src_dir always emitted (explicit "" when empty).
      §2 Rule 7 — All strings as KDL 2.0 double-quoted; source field NOT emitted.
    """
    lines: list[str] = []
    lines.append("dep_decl {")
    lines.append(f"    dep_decl_schema_version {schema_version}")
    lines.append(f"    src_dir {_kdl_str(es.src_dir)}")
    for entry in es.requires:
        if isinstance(entry, NamedRequire):
            lines.append(
                f"    require {_kdl_str(entry.name)} {_kdl_str(entry.constraint_str)}"
            )
        elif isinstance(entry, UrlRequire):
            lines.append(
                f"    require (url){_kdl_str(entry.url)} ref={_kdl_str(entry.ref)}"
            )
        else:
            raise TypeError(f"Unknown require entry type: {type(entry)!r}")
    lines.append("}")
    # trailing newline — the file ends with 0x0A after the closing }
    text = "\n".join(lines) + "\n"
    return text.encode("utf-8")


# ---------------------------------------------------------------------------
# dep_decl_hash (spec/dep-decl.md §3)
# ---------------------------------------------------------------------------

def dep_decl_hash(artifact_bytes: bytes) -> str:
    """Compute dep_decl_hash = "sha256:" + hex(sha256(artifact_bytes)).

    Same encoding as content_hash in spec/identity.md §2.1.
    """
    return "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Public fixture helper
# ---------------------------------------------------------------------------

def make_dep_decl_fixture(es: EdgeSet, schema_version: int = 0) -> bytes:
    """Produce DepDecl artifact bytes for an EdgeSet (fixture helper).

    Returns the UTF-8 bytes of a spec-conformant DepDecl KDL document.
    The `dep_decl_hash` of the returned bytes is:
        dep_decl_hash(make_dep_decl_fixture(es))

    Use this in S3b–S6 fixture generators to create DepDecl artifact files.
    This is NOT a resolver component (see spec/dep-decl.md Appendix B).
    """
    return canonical_serialize(es, schema_version=schema_version)
