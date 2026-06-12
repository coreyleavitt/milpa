"""KDL 2.0 façade over kdl-py.

This is the ONLY module in milpa that imports ``kdl-py``.  Everything else
sees the typed DOM façade defined here (specified in §4.3 of the RFC).
A future swap to a PyPI release or a hand-rolled parser is contained to this
single module.

## Verified kdl-py commit SHA

    d9a220762fb9f55e4f59296256221084c26f54da  (main HEAD as of 2026-06-12)

## De-risk probe results (verified on the pinned SHA above, 2026-06-12)

**IMPORTANT:** Both probes require ``ParseConfig(nativeTaggedValues=False)`` so
that type-annotated values are returned as typed ``kdl.String/Bool/...`` objects
rather than being eagerly coerced to Python native types by kdl-py's built-in
converters.  Without this flag, ``(url)"..."`` becomes a
``urllib.parse.ParseResult`` (the URL annotation is consumed by kdl-py's default
converter and the tag is lost).  With ``nativeTaggedValues=False``, tagged values
carry a ``.tag`` and ``.value`` attribute — see §3 of the RFC for how
``kdl_io.py`` uses this.

Probe 1 — (url) type annotation + property syntax:

    >>> import kdl
    >>> pc = kdl.ParseConfig(nativeTaggedValues=False)
    >>> kdl.parse('foo git=(url)"https://example.com" ref="main"', pc)
    Document(nodes=[Node(name='foo', tag=None,
      entries=[('git', String(value='https://example.com', tag='url',
        multiline=False)), ('ref', 'main')], nodes=[])], printConfig=None)

    Expected: node ``foo`` with property ``git`` = String(value='https://example.com',
              tag='url') and property ``ref`` = 'main'.

    Status: VERIFIED GOOD — tag='url' and value='https://example.com' both present.

Probe 2 — positional args + #true boolean (KDL 2.0):

    >>> kdl.parse('bar "x" #true "extra"', pc)
    Document(nodes=[Node(name='bar', tag=None,
      entries=[(None, 'x'), (None, True), (None, 'extra')],
      nodes=[])], printConfig=None)

    Expected: node ``bar`` with positional args: str "x", bool True, str "extra".

    Status: VERIFIED GOOD — ``#true`` parses as Python ``True``; positional args
            (key=None) preserve correct types.

## Nesting-depth guard (§3, RFC)

Before calling ``kdl.parse()``, all untrusted input is pre-scanned by
``_check_nesting_depth()`` which tracks BOTH brace ``{ }`` depth and
block-comment ``/* */`` depth against ``KDL_MAX_NESTING_DEPTH=32``.
On overflow it raises the context-appropriate ``MilpaError(*-KDL-SYNTAX)``
before the pure-Python recursive-descent parser ever recurses.
``kdl.parse()`` is also wrapped in ``except RecursionError`` as a
belt-and-suspenders backstop.  ``sys.setrecursionlimit`` is NOT used
(process-global; unsafe in a ThreadPoolExecutor, per §3).
"""

from __future__ import annotations

from typing import Literal

import kdl as _kdl

from milpa.errors import (
    LOCK_KDL_SYNTAX,
    MAN_KDL_SYNTAX,
    TNG_KDL_SYNTAX,
    MilpaError,
)

# ---------------------------------------------------------------------------
# Public milpa-owned types (no kdl.* type crosses the boundary)
# ---------------------------------------------------------------------------

#: KDL 2.0 scalar value types (note: int is returned for integer literals
#: when possible; float for non-integer numerics).
KdlValue = str | int | float | bool | None


class UrlValue:
    """A URL-valued KDL scalar.

    Returned by ``node_arg_url``, ``node_prop_url``, and ``value_as_url``.
    Wraps both ``(url)``-annotated scalars and plain bare strings (which
    ``manifest-grammar.md`` §4 rule 4 permits as equivalent).  A non-string
    value (int, bool, …) yields ``None`` from the ``*_url`` extractors rather
    than a ``UrlValue``, so callers can raise ``MAN-*-ARG-TYPE`` precisely.
    """

    __slots__ = ("_raw",)

    def __init__(self, raw: str) -> None:
        self._raw = raw

    def __str__(self) -> str:
        return self._raw

    def __repr__(self) -> str:
        return f"UrlValue({self._raw!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UrlValue):
            return self._raw == other._raw
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._raw)


class NotValue:
    """A ``(not)``-annotated KDL string scalar.

    Used by ``format_manifest`` to emit negated predicate values, e.g.
    ``platform=(not)"windows"``.  ``build_node``/``_milpa_val_to_kdl``
    converts this to ``kdl.types.String(value=..., tag="not")`` so no
    ``kdl.*`` types cross the module boundary.
    """

    __slots__ = ("_raw",)

    def __init__(self, raw: str) -> None:
        self._raw = raw

    def __str__(self) -> str:
        return self._raw

    def __repr__(self) -> str:
        return f"NotValue({self._raw!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, NotValue):
            return self._raw == other._raw
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("not", self._raw))


class KdlNode:
    """Opaque wrapper around a single kdl-py ``Node``.  Never expose kdl.*."""

    __slots__ = ("_node",)

    def __init__(self, node: _kdl.Node) -> None:
        self._node = node


class KdlDocument:
    """Opaque wrapper around a kdl-py ``Document``.  Never expose kdl.*."""

    __slots__ = ("_doc",)

    def __init__(self, doc: _kdl.Document) -> None:
        self._doc = doc


# ---------------------------------------------------------------------------
# Depth guard constants and implementation
# ---------------------------------------------------------------------------

KDL_MAX_NESTING_DEPTH: int = 32

_CONTEXT_SLUG: dict[str, str] = {
    "manifest": MAN_KDL_SYNTAX,
    "lockfile": LOCK_KDL_SYNTAX,
    "registry": TNG_KDL_SYNTAX,
}

_PARSE_CONFIG = _kdl.ParseConfig(nativeTaggedValues=False)


def _check_nesting_depth(text: str, slug: str) -> None:
    """Pre-parse O(n) scan tracking both ``{ }`` and ``/* */`` depth.

    Over-counts (counts braces/comment delimiters inside string literals) so it
    is a safe upper bound: if the check passes, the true structural depth ≤ the
    reported value.  On overflow it raises ``MilpaError(slug, …)`` before the
    pure-Python recursive-descent parser ever recurses.

    Both vectors are independent accumulators; the check fails if EITHER
    exceeds ``KDL_MAX_NESTING_DEPTH``.
    """
    brace_depth: int = 0
    brace_max: int = 0
    comment_depth: int = 0
    comment_max: int = 0

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            brace_depth += 1
            if brace_depth > brace_max:
                brace_max = brace_depth
        elif ch == "}":
            if brace_depth > 0:
                brace_depth -= 1
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            comment_depth += 1
            if comment_depth > comment_max:
                comment_max = comment_depth
            i += 1  # skip the '*'
        elif ch == "*" and i + 1 < n and text[i + 1] == "/":
            if comment_depth > 0:
                comment_depth -= 1
            i += 1  # skip the '/'
        i += 1

    if brace_max > KDL_MAX_NESTING_DEPTH:
        raise MilpaError(
            slug,
            f"KDL input exceeds maximum brace nesting depth ({KDL_MAX_NESTING_DEPTH})",
        )
    if comment_max > KDL_MAX_NESTING_DEPTH:
        raise MilpaError(
            slug,
            f"KDL input exceeds maximum block-comment nesting depth ({KDL_MAX_NESTING_DEPTH})",
        )


# ---------------------------------------------------------------------------
# parse_kdl — the single kdl-py call site
# ---------------------------------------------------------------------------


def parse_kdl(
    text: str,
    *,
    context: Literal["manifest", "lockfile", "registry"],
) -> KdlDocument:
    """Parse KDL 2.0 text into a ``KdlDocument``.

    Runs the pre-parse depth guard (both ``{ }`` and ``/* */`` vectors) then
    calls ``kdl.parse(text, ParseConfig(nativeTaggedValues=False))``.  Any
    ``kdl.ParseError`` or ``RecursionError`` is wrapped as the
    context-appropriate ``MilpaError(*-KDL-SYNTAX)``.

    ``sys.setrecursionlimit`` is NOT used — it is process-global across all
    threads; the pre-scan + ``except RecursionError`` pair is the complete guard.
    """
    slug = _CONTEXT_SLUG[context]
    _check_nesting_depth(text, slug)
    try:
        doc = _kdl.parse(text, _PARSE_CONFIG)
    except _kdl.ParseError as exc:
        raise MilpaError(slug, f"KDL syntax error: {exc}") from exc
    except RecursionError as exc:
        raise MilpaError(slug, "KDL input caused parser recursion overflow") from exc
    return KdlDocument(doc)


# ---------------------------------------------------------------------------
# Node accessors
# ---------------------------------------------------------------------------


def node_name(n: KdlNode) -> str:
    """Return the node's name string."""
    return str(n._node.name)


def node_args(n: KdlNode) -> list[KdlValue]:
    """Return positional (key=None) arguments in order."""
    result: list[KdlValue] = []
    for key, val in n._node.entries:
        if key is None:
            result.append(_kdl_val_to_milpa(val))
    return result


def node_props(n: KdlNode) -> dict[str, KdlValue]:
    """Return named properties (key is not None)."""
    result: dict[str, KdlValue] = {}
    for key, val in n._node.entries:
        if key is not None:
            result[key] = _kdl_val_to_milpa(val)
    return result


def node_children(n: KdlNode) -> list[KdlNode]:
    """Return child nodes."""
    return [KdlNode(child) for child in n._node.nodes]


def nodes(doc: KdlDocument) -> list[KdlNode]:
    """Return the top-level nodes of a document."""
    return [KdlNode(n) for n in doc._doc.nodes]


# ---------------------------------------------------------------------------
# Node-level extractors (fold lookup + type-check into one call)
# ---------------------------------------------------------------------------


def node_arg_str(n: KdlNode, index: int = 0) -> str | None:
    """Return positional arg at *index* as ``str``, or ``None`` if absent/wrong type."""
    args = node_args(n)
    if index >= len(args):
        return None
    return value_as_str(args[index])


def node_arg_url(n: KdlNode, index: int = 0) -> UrlValue | None:
    """Return positional arg at *index* as ``UrlValue``, or ``None`` if absent/wrong type.

    Handles both plain strings and ``(url)``-annotated scalars.
    """
    # Must peek at the raw kdl entry to detect (url) tag before it's flattened
    raw_args = [entry for entry in n._node.entries if entry[0] is None]
    if index >= len(raw_args):
        return None
    return _kdl_entry_as_url(raw_args[index][1])


def node_prop_str(n: KdlNode, key: str) -> str | None:
    """Return property *key* as ``str``, or ``None`` if absent/wrong type."""
    return value_as_str(node_props(n).get(key))


def node_prop_url(n: KdlNode, key: str) -> UrlValue | None:
    """Return property *key* as ``UrlValue``, or ``None`` if absent/wrong type."""
    for entry_key, entry_val in n._node.entries:
        if entry_key == key:
            return _kdl_entry_as_url(entry_val)
    return None


def node_prop_int(n: KdlNode, key: str) -> int | None:
    """Return property *key* as ``int``, or ``None`` if absent/wrong type."""
    return value_as_int(node_props(n).get(key))


def node_prop_bool(n: KdlNode, key: str) -> bool | None:
    """Return property *key* as ``bool``, or ``None`` if absent/wrong type."""
    return value_as_bool(node_props(n).get(key))


def node_prop_tag(n: KdlNode, key: str) -> str | None:
    """Return the KDL type-annotation tag on property *key*, or ``None``.

    Returns ``None`` when:
    - the property is absent,
    - the value is an untagged literal (bare string/int/bool/null),
    - the kdl-py type does not carry a ``tag`` attribute.

    Examples::

        platform=(not)"linux"   → ``"not"``
        platform=(url)"linux"   → ``"url"``
        platform="linux"        → ``None``   (no annotation)
        ref="main"              → ``None``

    Used by predicate parsers to distinguish ``(not)``-negation from other
    annotations (``MAN-PREDICATE-UNSUPPORTED-ANNOTATION``) and from bare values.
    """
    for entry_key, entry_val in n._node.entries:
        if entry_key == key:
            tag = getattr(entry_val, "tag", None)
            return tag if isinstance(tag, str) else None
    return None


def node_arg_tag(n: KdlNode, index: int = 0) -> str | None:
    """Return the KDL type-annotation tag on positional arg *index*, or ``None``.

    Same semantics as ``node_prop_tag`` but for positional args.

    Used by predicate child-node parsers to check each arg for ``(not)``
    annotation vs. bare string (mixed-negation check) and non-string arg types
    (``MAN-PREDICATE-CHILD-ARG-TYPE``).
    """
    raw_args = [entry for entry in n._node.entries if entry[0] is None]
    if index >= len(raw_args):
        return None
    entry_val = raw_args[index][1]
    tag = getattr(entry_val, "tag", None)
    return tag if isinstance(tag, str) else None


# ---------------------------------------------------------------------------
# Scalar extractors (KdlValue → typed Python value or None)
# ---------------------------------------------------------------------------


def value_as_str(v: KdlValue) -> str | None:
    """Return *v* as ``str``, or ``None`` if it is not a string.

    Note: ``UrlValue`` objects are NOT ``KdlValue``; this function operates on
    already-converted values.  For the raw kdl entry path see ``_kdl_entry_as_url``.
    """
    if isinstance(v, str):
        return v
    return None


def value_as_int(v: KdlValue) -> int | None:
    """Return *v* as ``int``, or ``None`` if it is not a numeric integer.

    kdl-py returns all KDL numeric literals as ``float``.  This function
    converts whole-number floats to ``int`` (e.g. ``42.0 → 42``).
    """
    if isinstance(v, bool):  # bool is a subclass of int — must check first
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v == int(v):
        return int(v)
    return None


def value_as_bool(v: KdlValue) -> bool | None:
    """Return *v* as ``bool``, or ``None`` if it is not a boolean."""
    if isinstance(v, bool):
        return v
    return None


def value_as_url(v: KdlValue) -> UrlValue | None:
    """Return *v* as ``UrlValue``, or ``None`` if it is not a string.

    Both plain strings and ``(url)``-annotated scalars are accepted
    (``manifest-grammar.md`` §4 rule 4).  The ``(url)`` annotation is
    unwrapped ONLY here and in ``node_*_url``; callers cannot observe the
    distinction between a bare string and an annotated one.
    """
    if isinstance(v, str):
        return UrlValue(v)
    return None


# ---------------------------------------------------------------------------
# Builder + emitter
# ---------------------------------------------------------------------------


def build_node(
    name: str,
    args: tuple[KdlValue | UrlValue | NotValue, ...] = (),
    props: tuple[tuple[str, KdlValue | UrlValue | NotValue], ...] = (),
    children: tuple[KdlNode, ...] = (),
) -> KdlNode:
    """Construct a new ``KdlNode`` explicitly.

    Used by ``format_manifest`` to produce a fresh KDL 2.0 AST without
    mutating a parsed document.  Args and props accept ``KdlValue``,
    ``UrlValue``, and ``NotValue``; each is converted to the appropriate
    kdl-py representation:
    - ``UrlValue`` → ``(url)"…"`` (§2 normative URL annotation)
    - ``NotValue`` → ``(not)"…"`` (negated predicate annotation, §6.1)
    - ``KdlValue`` → passed through natively
    """
    entries: list[tuple[str | None, object]] = []
    for a in args:
        entries.append((None, _milpa_val_to_kdl(a)))
    for k, pv in props:
        entries.append((k, _milpa_val_to_kdl(pv)))
    child_nodes = [c._node for c in children]
    raw_node = _kdl.Node(name, entries=entries, nodes=child_nodes)
    return KdlNode(raw_node)


def emit_document(nodes_list: list[KdlNode]) -> str:
    """Serialize a list of ``KdlNode`` values to KDL 2.0 text.

    Uses kdl-py's printer as the final serializer of an explicitly-built
    document (never as a round-trip reserializer of a parsed document).
    """
    raw_nodes = [n._node for n in nodes_list]
    doc = _kdl.Document(nodes=raw_nodes)
    return doc.print()


def has_kdl_comments(text: str) -> bool:
    """Return ``True`` if *text* contains any KDL comment (``//``, ``/*``, or ``/-``).

    This is a conservative O(n) character scan run on the raw source text
    BEFORE parsing.  It over-counts (e.g. ``//`` inside a quoted string is
    flagged), making it a safe upper bound: if the check returns ``False``,
    the document definitely has no comments.  If ``True``, it probably does
    (the caller can emit the warning safely — no false negatives, rare false
    positives are acceptable per §8 which says the warning MUST NOT be
    suppressed when warranted).
    """
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt in ("/", "*", "-"):
                return True
        i += 1
    return False


# ---------------------------------------------------------------------------
# Internal helpers (not part of the public interface)
# ---------------------------------------------------------------------------


def _kdl_val_to_milpa(val: object) -> KdlValue:
    """Convert a raw kdl-py entry value to a ``KdlValue``.

    With ``nativeTaggedValues=False``, tagged scalars arrive as
    ``kdl.types.String`` (etc.) with ``.tag`` and ``.value``.  Untagged
    scalars arrive as Python builtins (``str``, ``float``, ``bool``, ``None``).

    Tagged strings (including ``(url)``-annotated ones) are stripped to their
    raw string value here — the tag information is only preserved via the
    ``_kdl_entry_as_url`` path used by ``node_*_url`` and ``value_as_url``.
    """
    if isinstance(val, _kdl.types.String):
        return val.value
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val
    if val is None:
        return None
    if isinstance(val, str):
        return val
    # Fallback: try to convert other kdl types (Bool, Null wrappers, etc.)
    raw = getattr(val, "value", val)
    if isinstance(raw, (str, int, float, bool)) or raw is None:
        return raw
    return None


def _kdl_entry_as_url(val: object) -> UrlValue | None:
    """Extract a ``UrlValue`` from a raw kdl-py entry value.

    Recognises three forms:
    1. ``kdl.types.String`` with ``tag == "url"`` — the normative annotated form.
    2. ``kdl.types.String`` with ``tag is None`` — plain string accepted as URL
       per ``manifest-grammar.md`` §4 rule 4.
    3. Plain Python ``str`` — bare untagged string (untagged-native path).

    Any non-string type (bool, float, None, etc.) returns ``None`` so the
    caller can raise ``MAN-*-ARG-TYPE``.
    """
    if isinstance(val, _kdl.types.String):
        # tag == "url" → normative form; tag is None → plain string; both OK
        if val.tag in ("url", None):
            return UrlValue(val.value)
        # Some other annotation — not a URL
        return None
    if isinstance(val, str):
        return UrlValue(val)
    return None


def _milpa_val_to_kdl(v: KdlValue | UrlValue | NotValue) -> object:
    """Convert a milpa value back to a kdl-py-compatible entry value."""
    if isinstance(v, UrlValue):
        return _kdl.types.String(value=str(v), tag="url")
    if isinstance(v, NotValue):
        return _kdl.types.String(value=str(v), tag="not")
    # For plain Python types kdl-py accepts them natively in entries
    return v
