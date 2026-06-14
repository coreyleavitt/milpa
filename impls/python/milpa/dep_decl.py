"""DepDecl artifact parser and EdgeSet type (S1 consumer side).

Implements the **consumer** half of `spec/dep-decl.md`:
  - `EdgeSet` — the single in-memory edge type (§1), with fidelity tag `source`.
  - `NamedRequire` / `UrlRequire` — the two entry variants (§1).
  - `EdgeSource` — the three fidelity-tag values (§1, in-memory only).
  - `parse_dep_decl(bytes) -> (EdgeSet, int)` — parse a DepDecl artifact (§2),
    returning the EdgeSet AND the schema version integer from the DOM.
  - `dep_decl_hash(bytes) -> str` — compute `"sha256:" + hex(sha256(bytes))` (§3).

**No serializer here.** The resolver never re-serializes; `canonical_serialize`
is a producer + harness obligation (spec Appendix B). See `harness/dep_decl.py`
for the producer-side harness helper.

**SSOT discipline:**
  - KDL parsing: reuses `kdl_io.parse_kdl` (the single kdl-py call site).
  - sha256: reuses `hashlib.sha256` exactly as `identity.py` does — same
    import, same encoding `"sha256:" + h.hexdigest()`.  No parallel hasher.

**S3b note:** error-raising wrappers for `TNG-DEPDECL-HASH-MISMATCH` and the
other four `TNG-DEPDECL-*` codes are S3b deliverables. This module is the
happy-path parse path; underlying KDL parse errors propagate as
`MilpaError(TNG-DEPDECL-PARSE-ERROR, …)` from `kdl_io.parse_kdl` naturally.
The hash helper is a pure compute+compare function; callers raise S3b errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Union

from milpa.kdl_io import (
    KdlNode,
    node_arg_str,
    node_arg_tag,
    node_arg_url,
    node_args,
    node_children,
    node_name,
    node_prop_str,
    nodes,
    parse_kdl,
    value_as_int,
)
from milpa.predicate import Predicate

# ---------------------------------------------------------------------------
# EdgeSource fidelity tag (spec/dep-decl.md §1)
# In-memory only — MUST NOT appear in any serialized artifact.
# ---------------------------------------------------------------------------


class EdgeSource(Enum):
    """Fidelity tag for an in-memory EdgeSet (spec/dep-decl.md §1).

    Identifies which source produced the EdgeSet so the resolver and
    diagnostics layer can distinguish fidelity at runtime. NOT serialized.

    Values are the three canonical strings from the spec:
        dep_decl        — parsed from a DepDecl artifact (this module)
        milpa_kdl       — parsed from a milpa.kdl manifest
        nimble_fallback — produced by the .nimble heuristic scanner
    """

    DEP_DECL = "dep_decl"
    MILPA_KDL = "milpa_kdl"
    NIMBLE_FALLBACK = "nimble_fallback"


# ---------------------------------------------------------------------------
# Require entry variants (spec/dep-decl.md §1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NamedRequire:
    """A named (registry-resolved) requires entry.

    `constraint_str` is the raw declaration string, whitespace preserved
    verbatim (spec §2 Rule 5). `">= 0.5.0"` and `">=0.5.0"` are distinct.

    `predicates` carries optional ``when``-gate annotations (S2 — RFC
    ``rfc-conditional-requires.md`` §3.3).  Defaults to an empty tuple
    (back-compat: unconditional requires are unaffected).  Nothing populates
    the field until S3b; ``frozen=True`` dataclass auto-derives ``__eq__``
    and ``__repr__`` that include it for free.
    """

    name: str
    constraint_str: str
    predicates: tuple[Predicate, ...] = ()


@dataclass(frozen=True)
class UrlRequire:
    """A URL-based requires entry (transport-resolved dep).

    `predicates` carries optional ``when``-gate annotations (S2 — RFC
    ``rfc-conditional-requires.md`` §3.3).  Defaults to an empty tuple
    (back-compat).
    """

    url: str
    ref: str
    predicates: tuple[Predicate, ...] = ()


RequireEntry = Union[NamedRequire, UrlRequire]

# ---------------------------------------------------------------------------
# EdgeSet — the single shared edge type (spec/dep-decl.md §1)
# ---------------------------------------------------------------------------


@dataclass
class EdgeSet:
    """Language-neutral in-memory edge type (spec/dep-decl.md §1).

    Single shared type consumed by the resolver regardless of which source
    supplied the edges. There MUST NOT be a parallel type duplicating this
    (spec §1 NORMATIVE).

    Fields:
        requires — ordered list of require entries, authored order preserved.
        src_dir  — source directory string; ``""`` when unset.
        source   — fidelity tag (EdgeSource); in-memory only, NOT serialized.
    """

    requires: list[RequireEntry] = field(default_factory=list)
    src_dir: str = ""
    source: EdgeSource = EdgeSource.DEP_DECL

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EdgeSet):
            return NotImplemented
        return (
            self.requires == other.requires
            and self.src_dir == other.src_dir
            and self.source == other.source
        )

    def __repr__(self) -> str:
        return (
            f"EdgeSet(requires={self.requires!r}, src_dir={self.src_dir!r}, "
            f"source={self.source!r})"
        )


# ---------------------------------------------------------------------------
# dep_decl_hash — §3 (SSOT: reuses hashlib.sha256 as identity.py does)
# ---------------------------------------------------------------------------


def dep_decl_hash(artifact_bytes: bytes) -> str:
    """Compute ``dep_decl_hash`` = ``"sha256:" + hex(sha256(artifact_bytes))``.

    Encoding is identical to ``content_hash`` in ``spec/identity.md §2.1``
    (same algorithm, same lowercase-hex format, same ``"sha256:"`` prefix).
    SSOT: uses ``hashlib.sha256`` — the same import as ``identity.py``.

    This is a **pure compute helper** for S1. The error-raising wrapper
    (``TNG-DEPDECL-HASH-MISMATCH`` on mismatch vs. the index pointer) is S3b.
    """
    return "sha256:" + sha256(artifact_bytes).hexdigest()


# ---------------------------------------------------------------------------
# parse_dep_decl — happy-path DepDecl artifact parser (§2)
# ---------------------------------------------------------------------------

#: Maximum dep_decl_schema_version this implementation understands (§4.3).
#: Only v0 is defined in this spec version.
MAX_DEP_DECL_SCHEMA_VERSION: int = 0


def parse_dep_decl(artifact_bytes: bytes) -> tuple[EdgeSet, int]:
    """Parse a DepDecl artifact from raw bytes into an ``(EdgeSet, schema_version)`` pair.

    Parses the KDL 2.0 document shape defined in ``spec/dep-decl.md §2``::

        dep_decl {
            dep_decl_schema_version 0
            src_dir "..."
            require "name" "constraint"
            require (url)"url" ref="ref"
        }

    Returns ``(EdgeSet, schema_version)`` where ``schema_version`` is the integer
    value of the ``dep_decl_schema_version`` KDL node, read from the **parsed DOM**
    (NOT from a secondary text-scan). When the node is absent, ``schema_version``
    defaults to ``0`` (forward-compat §4.3).

    **SSOT design:** the schema version is extracted once from the DOM and returned
    alongside the ``EdgeSet``. Callers (``DepDeclEdgeSource``) use this value for
    the §4.3 SCHEMA-UNSUPPORTED and §5 SCHEMA-MISMATCH checks without re-parsing
    the bytes.

    **KDL parsing** delegates to ``kdl_io.parse_kdl`` (the SSOT kdl-py call
    site). Any KDL syntax error propagates as
    ``MilpaError(TNG-DEPDECL-PARSE-ERROR, …)`` — the ``"dep_decl"`` context
    maps to that slug in ``kdl_io._CONTEXT_SLUG``.

    **Error raise sites for S3b** (NOT raised here):
        - ``TNG-DEPDECL-HASH-MISMATCH`` — hash verification before parse
        - ``TNG-DEPDECL-SCHEMA-UNSUPPORTED`` — schema version check §4.3
        - ``TNG-DEPDECL-SCHEMA-MISMATCH`` — consistency check §5

    Args:
        artifact_bytes: Raw UTF-8 bytes of a DepDecl artifact.

    Returns:
        A ``(EdgeSet, int)`` pair: the parsed edge set (``source = EdgeSource.DEP_DECL``)
        and the ``dep_decl_schema_version`` integer from the DOM (default 0 if absent).

    Raises:
        MilpaError(TNG-DEPDECL-PARSE-ERROR): KDL syntax error or structurally
            non-conformant document (propagated from ``kdl_io``).
    """
    text = artifact_bytes.decode("utf-8")
    doc = parse_kdl(text, context="dep_decl")

    top_nodes = nodes(doc)
    if len(top_nodes) != 1 or node_name(top_nodes[0]) != "dep_decl":
        from milpa.errors import MilpaError, TNG_DEPDECL_PARSE_ERROR

        raise MilpaError(
            TNG_DEPDECL_PARSE_ERROR,
            "DepDecl artifact must have a single top-level 'dep_decl' node",
        )

    dep_decl_node = top_nodes[0]
    children = node_children(dep_decl_node)

    src_dir = ""
    requires: list[RequireEntry] = []
    # Default per §4.3 forward-compat: treat missing version as v0.
    schema_version: int = 0

    for child in children:
        name = node_name(child)
        if name == "dep_decl_schema_version":
            # Read from DOM — the SSOT integer node value.
            # value_as_int handles kdl-py's float representation of large integers;
            # for very large values (> i64::MAX), kdl-py returns a float like 1e+20,
            # and int(1e+20) is a large positive integer — NOT 0 (fail-open).
            args = node_args(child)
            if args:
                raw_int = value_as_int(args[0])
                if raw_int is not None:
                    schema_version = raw_int
        elif name == "src_dir":
            val = node_arg_str(child, 0)
            if val is not None:
                src_dir = val
        elif name == "require":
            entry = _parse_require_node(child)
            if entry is not None:
                requires.append(entry)
        # Unknown child nodes: forward-compat ignore (schema evolution §1.1)

    return EdgeSet(requires=requires, src_dir=src_dir, source=EdgeSource.DEP_DECL), schema_version


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_require_node(node: KdlNode) -> RequireEntry | None:
    """Parse a single ``require`` child node into a ``RequireEntry``.

    Two forms (spec §2 Rule 4):
        ``require "<name>" "<constraint>"``       → ``NamedRequire``
        ``require (url)"<url>" ref="<ref>"``      → ``UrlRequire``

    Disambiguation: the URL form has a ``(url)`` KDL type annotation on the
    first positional arg. A bare double-quoted string (no annotation) is the
    named form. This mirrors spec Rule 4 exactly — the ``(url)`` annotation
    is the normative discriminator between the two forms.

    Returns ``None`` for unrecognized forms (forward-compat tolerance).
    """
    # Check whether the first positional arg carries a ``(url)`` annotation.
    first_tag = node_arg_tag(node, 0)  # None for bare strings, "url" for (url)"…"
    if first_tag == "url":
        # URL form: require (url)"<url>" ref="<ref>"
        url_val = node_arg_url(node, 0)
        if url_val is None:
            return None
        ref = node_prop_str(node, "ref") or ""
        return UrlRequire(url=str(url_val), ref=ref)

    # Named form: require "<name>" "<constraint>"
    name = node_arg_str(node, 0)
    if name is not None:
        constraint_str = node_arg_str(node, 1) or ""
        return NamedRequire(name=name, constraint_str=constraint_str)

    return None
