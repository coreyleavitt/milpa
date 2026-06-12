"""Tests for milpa/kdl_io.py — the KDL 2.0 typed-DOM façade.

Stage-local validation (S2a): no CLI, no black-box harness.  We read corpus
fixture files directly and call ``parse_kdl`` to assert the exact slug raised.

Corpus fixtures exercised
-------------------------
fixture-001-man-kdl-syntax  → MAN-KDL-SYNTAX   (manifest context, syntax error)
fixture-066-lock-kdl-syntax → LOCK-KDL-SYNTAX  (lockfile context, syntax error)

Depth-guard tests (both vectors)
---------------------------------
- 33-deep ``{ }`` nesting → slug
- 33-deep ``/* */`` comment nesting → slug
- 32-deep ``{ }`` nesting → OK (boundary, must NOT raise)

URL surface tests
-----------------
- ``(url)``-annotated scalar → ``UrlValue`` (NOT urllib.parse.ParseResult)
- plain string scalar → ``UrlValue`` (bare string accepted per §4 rule 4)
- non-string scalar → ``None`` from node_*_url extractors

Type extractor tests
--------------------
- ``#true`` / ``#false`` → bool (KDL 2.0)
- integer literal → int (via value_as_int)
- wrong type → None from extractors

Builder / emitter tests
-----------------------
- round-trip: build_node + emit_document → valid KDL that re-parses
"""

from __future__ import annotations

import pathlib

import pytest

from milpa.errors import (
    LOCK_KDL_SYNTAX,
    MAN_KDL_SYNTAX,
    TNG_KDL_SYNTAX,
    MilpaError,
)
from milpa.kdl_io import (
    KdlDocument,
    KdlNode,
    UrlValue,
    build_node,
    emit_document,
    node_arg_str,
    node_arg_url,
    node_args,
    node_children,
    node_name,
    node_prop_bool,
    node_prop_int,
    node_prop_str,
    node_prop_url,
    node_props,
    nodes,
    parse_kdl,
    value_as_bool,
    value_as_int,
    value_as_str,
    value_as_url,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CONFORMANCE = pathlib.Path(__file__).parents[3] / "conformance" / "spec-v1"


def _fixture(name: str) -> pathlib.Path:
    p = CONFORMANCE / name
    assert p.exists(), f"Conformance fixture not found: {p}"
    return p


# ---------------------------------------------------------------------------
# Corpus fixtures: KDL syntax error → correct slug
# ---------------------------------------------------------------------------


class TestCorpusKdlSyntax:
    """Reads real corpus fixture input files and asserts the exact slug raised."""

    def test_fixture_001_man_kdl_syntax(self) -> None:
        """fixture-001-man-kdl-syntax: manifest with invalid KDL → MAN-KDL-SYNTAX."""
        text = (_fixture("fixture-001-man-kdl-syntax") / "milpa.kdl").read_text()
        expected_slug = (
            _fixture("fixture-001-man-kdl-syntax") / "expected" / "error"
        ).read_text().strip()
        assert expected_slug == MAN_KDL_SYNTAX

        with pytest.raises(MilpaError) as exc_info:
            parse_kdl(text, context="manifest")
        assert exc_info.value.slug == MAN_KDL_SYNTAX

    def test_fixture_066_lock_kdl_syntax(self) -> None:
        """fixture-066-lock-kdl-syntax: lockfile with invalid KDL → LOCK-KDL-SYNTAX."""
        text = (_fixture("fixture-066-lock-kdl-syntax") / "milpa.lock").read_text()
        expected_slug = (
            _fixture("fixture-066-lock-kdl-syntax") / "expected" / "error"
        ).read_text().strip()
        assert expected_slug == LOCK_KDL_SYNTAX

        with pytest.raises(MilpaError) as exc_info:
            parse_kdl(text, context="lockfile")
        assert exc_info.value.slug == LOCK_KDL_SYNTAX

    def test_registry_context_uses_tng_slug(self) -> None:
        """Same invalid KDL in 'registry' context → TNG-KDL-SYNTAX."""
        with pytest.raises(MilpaError) as exc_info:
            parse_kdl("not { valid kdl", context="registry")
        assert exc_info.value.slug == TNG_KDL_SYNTAX


# ---------------------------------------------------------------------------
# Depth guard — brace { } vector
# ---------------------------------------------------------------------------


class TestBraceDepthGuard:
    """Pre-parse brace depth guard: 33-deep → slug; 32-deep → OK."""

    @staticmethod
    def _build_brace_text(depth: int) -> str:
        """Build a KDL document with *depth* levels of node-children nesting."""
        inner = 'leaf "x"'
        text = inner
        for _ in range(depth):
            text = f"node {{\n{text}\n}}"
        return text

    def test_depth_33_raises_man_kdl_syntax(self) -> None:
        text = self._build_brace_text(33)
        with pytest.raises(MilpaError) as exc_info:
            parse_kdl(text, context="manifest")
        assert exc_info.value.slug == MAN_KDL_SYNTAX

    def test_depth_33_raises_lock_kdl_syntax(self) -> None:
        text = self._build_brace_text(33)
        with pytest.raises(MilpaError) as exc_info:
            parse_kdl(text, context="lockfile")
        assert exc_info.value.slug == LOCK_KDL_SYNTAX

    def test_depth_33_raises_tng_kdl_syntax(self) -> None:
        text = self._build_brace_text(33)
        with pytest.raises(MilpaError) as exc_info:
            parse_kdl(text, context="registry")
        assert exc_info.value.slug == TNG_KDL_SYNTAX

    def test_depth_32_is_ok(self) -> None:
        """Exactly KDL_MAX_NESTING_DEPTH=32 must NOT be rejected."""
        text = self._build_brace_text(32)
        doc = parse_kdl(text, context="manifest")
        assert isinstance(doc, KdlDocument)

    def test_depth_1_simple_document_is_ok(self) -> None:
        doc = parse_kdl('name "milpa"', context="manifest")
        assert isinstance(doc, KdlDocument)


# ---------------------------------------------------------------------------
# Depth guard — block comment /* */ vector
# ---------------------------------------------------------------------------


class TestBlockCommentDepthGuard:
    """Pre-parse block-comment depth guard: 33-deep → slug; 32-deep → OK."""

    @staticmethod
    def _build_comment_text(depth: int) -> str:
        """Build a string with *depth* levels of nested block comments."""
        inner = "/* innermost */"
        text = inner
        for _ in range(depth - 1):
            text = f"/* outer {text} */"
        # Wrap in a valid KDL document so the parser doesn't choke on content
        return f'name "milpa" {text}'

    def test_comment_depth_33_raises(self) -> None:
        text = self._build_comment_text(33)
        with pytest.raises(MilpaError) as exc_info:
            parse_kdl(text, context="manifest")
        assert exc_info.value.slug == MAN_KDL_SYNTAX

    def test_comment_depth_32_is_ok(self) -> None:
        """Exactly 32 nested block comments must NOT be rejected."""
        text = self._build_comment_text(32)
        doc = parse_kdl(text, context="manifest")
        assert isinstance(doc, KdlDocument)


# ---------------------------------------------------------------------------
# URL value surface — (url) tag does NOT leak as urllib.ParseResult
# ---------------------------------------------------------------------------


class TestUrlValue:
    """UrlValue is returned, never urllib.parse.ParseResult."""

    def _parse_url_prop(self, kdl_text: str, key: str) -> UrlValue | None:
        doc = parse_kdl(kdl_text, context="manifest")
        ns = nodes(doc)
        assert ns
        return node_prop_url(ns[0], key)

    def test_url_annotated_prop_returns_url_value(self) -> None:
        uv = self._parse_url_prop('foo git=(url)"https://github.com/x/y"', "git")
        assert uv is not None
        assert isinstance(uv, UrlValue)
        assert str(uv) == "https://github.com/x/y"

    def test_url_annotated_prop_is_not_parse_result(self) -> None:
        import urllib.parse
        uv = self._parse_url_prop('foo git=(url)"https://github.com/x/y"', "git")
        assert not isinstance(uv, urllib.parse.ParseResult)

    def test_bare_string_prop_returns_url_value(self) -> None:
        """A plain string (no annotation) also returns UrlValue per §4 rule 4."""
        uv = self._parse_url_prop('foo git="https://github.com/x/y"', "git")
        assert uv is not None
        assert isinstance(uv, UrlValue)
        assert str(uv) == "https://github.com/x/y"

    def test_wrong_type_prop_returns_none(self) -> None:
        """A non-string property returns None from node_prop_url."""
        uv = self._parse_url_prop("foo count=42", "count")
        assert uv is None

    def test_absent_prop_returns_none(self) -> None:
        uv = self._parse_url_prop('foo git="x"', "missing")
        assert uv is None

    def test_node_arg_url_with_url_annotation(self) -> None:
        doc = parse_kdl('dep (url)"https://example.com"', context="manifest")
        n = nodes(doc)[0]
        uv = node_arg_url(n, 0)
        assert uv is not None
        assert str(uv) == "https://example.com"

    def test_node_arg_url_with_plain_string(self) -> None:
        doc = parse_kdl('dep "https://example.com"', context="manifest")
        n = nodes(doc)[0]
        uv = node_arg_url(n, 0)
        assert uv is not None
        assert str(uv) == "https://example.com"

    def test_node_arg_url_wrong_type_returns_none(self) -> None:
        doc = parse_kdl("dep 42", context="manifest")
        n = nodes(doc)[0]
        uv = node_arg_url(n, 0)
        assert uv is None

    def test_value_as_url_with_str(self) -> None:
        uv = value_as_url("https://example.com")
        assert uv is not None
        assert str(uv) == "https://example.com"

    def test_value_as_url_with_non_str_returns_none(self) -> None:
        assert value_as_url(42) is None  # type: ignore[arg-type]
        assert value_as_url(True) is None  # type: ignore[arg-type]
        assert value_as_url(None) is None


# ---------------------------------------------------------------------------
# KDL 2.0 boolean literals (#true / #false)
# ---------------------------------------------------------------------------


class TestBooleans:
    """#true/#false parse as Python bool; wrong type → None from value_as_bool."""

    def _get_bool_prop(self, key: str, val_text: str) -> bool | None:
        doc = parse_kdl(f"node {key}={val_text}", context="manifest")
        n = nodes(doc)[0]
        return node_prop_bool(n, key)

    def test_true_literal(self) -> None:
        assert self._get_bool_prop("dev", "#true") is True

    def test_false_literal(self) -> None:
        assert self._get_bool_prop("dev", "#false") is False

    def test_string_is_not_bool(self) -> None:
        assert self._get_bool_prop("x", '"yes"') is None

    def test_integer_is_not_bool(self) -> None:
        assert self._get_bool_prop("x", "1") is None

    def test_value_as_bool_true(self) -> None:
        assert value_as_bool(True) is True

    def test_value_as_bool_false(self) -> None:
        assert value_as_bool(False) is False

    def test_value_as_bool_string_is_none(self) -> None:
        assert value_as_bool("true") is None


# ---------------------------------------------------------------------------
# Integer extraction
# ---------------------------------------------------------------------------


class TestIntegerExtraction:
    """value_as_int converts whole-number floats to int; bool → None."""

    def test_integer_literal_is_int(self) -> None:
        doc = parse_kdl("node x=42", context="manifest")
        n = nodes(doc)[0]
        v = node_prop_int(n, "x")
        assert v == 42
        assert isinstance(v, int)

    def test_float_literal_is_not_int(self) -> None:
        doc = parse_kdl("node x=3.14", context="manifest")
        n = nodes(doc)[0]
        assert node_prop_int(n, "x") is None

    def test_bool_is_not_int(self) -> None:
        # bool is a subclass of int in Python; value_as_int must guard this
        assert value_as_int(True) is None
        assert value_as_int(False) is None

    def test_value_as_int_from_float(self) -> None:
        assert value_as_int(42.0) == 42
        assert isinstance(value_as_int(42.0), int)

    def test_value_as_int_non_whole_float_none(self) -> None:
        assert value_as_int(3.14) is None


# ---------------------------------------------------------------------------
# node_name, node_args, node_props, node_children
# ---------------------------------------------------------------------------


class TestNodeAccessors:
    """node_name / node_args / node_props / node_children basics."""

    def test_node_name(self) -> None:
        doc = parse_kdl('hello "world"', context="manifest")
        n = nodes(doc)[0]
        assert node_name(n) == "hello"

    def test_node_args_positional(self) -> None:
        doc = parse_kdl('foo "a" "b" "c"', context="manifest")
        n = nodes(doc)[0]
        args = node_args(n)
        assert args == ["a", "b", "c"]

    def test_node_props_named(self) -> None:
        doc = parse_kdl('foo x="hello" y=42', context="manifest")
        n = nodes(doc)[0]
        props = node_props(n)
        assert props["x"] == "hello"
        assert props["y"] == 42.0  # kdl-py returns float

    def test_node_children(self) -> None:
        doc = parse_kdl("deps {\n  dep \"intonaco\"\n}", context="manifest")
        n = nodes(doc)[0]
        ch = node_children(n)
        assert len(ch) == 1
        assert node_name(ch[0]) == "dep"

    def test_node_arg_str_present(self) -> None:
        doc = parse_kdl('foo "bar"', context="manifest")
        n = nodes(doc)[0]
        assert node_arg_str(n) == "bar"

    def test_node_arg_str_absent(self) -> None:
        doc = parse_kdl("foo", context="manifest")
        n = nodes(doc)[0]
        assert node_arg_str(n) is None

    def test_node_arg_str_wrong_type(self) -> None:
        doc = parse_kdl("foo 42", context="manifest")
        n = nodes(doc)[0]
        assert node_arg_str(n) is None

    def test_node_prop_str_present(self) -> None:
        doc = parse_kdl('foo name="milpa"', context="manifest")
        n = nodes(doc)[0]
        assert node_prop_str(n, "name") == "milpa"

    def test_node_prop_str_absent(self) -> None:
        doc = parse_kdl("foo", context="manifest")
        n = nodes(doc)[0]
        assert node_prop_str(n, "missing") is None


# ---------------------------------------------------------------------------
# value_as_str
# ---------------------------------------------------------------------------


class TestValueAsStr:
    def test_str_is_str(self) -> None:
        assert value_as_str("hello") == "hello"

    def test_int_is_none(self) -> None:
        assert value_as_str(42) is None  # type: ignore[arg-type]

    def test_bool_is_none(self) -> None:
        assert value_as_str(True) is None  # type: ignore[arg-type]

    def test_none_is_none(self) -> None:
        assert value_as_str(None) is None


# ---------------------------------------------------------------------------
# build_node + emit_document round-trip
# ---------------------------------------------------------------------------


class TestBuildAndEmit:
    """build_node + emit_document produce valid KDL that re-parses correctly."""

    def test_simple_node_round_trips(self) -> None:
        n = build_node("hello", args=("world",))
        text = emit_document([n])
        doc = parse_kdl(text, context="manifest")
        ns = nodes(doc)
        assert len(ns) == 1
        assert node_name(ns[0]) == "hello"
        assert node_arg_str(ns[0]) == "world"

    def test_url_prop_emitted_with_annotation(self) -> None:
        """UrlValue props are emitted as (url)"…" in the KDL output."""
        uv = UrlValue("https://github.com/x/y")
        n = build_node("dep", props=(("git", uv),))
        text = emit_document([n])
        assert '(url)' in text
        # Re-parse and check it comes back as UrlValue
        doc = parse_kdl(text, context="manifest")
        ns = nodes(doc)
        assert node_prop_url(ns[0], "git") is not None
        assert str(node_prop_url(ns[0], "git")) == "https://github.com/x/y"  # type: ignore[arg-type]

    def test_bool_prop_round_trips(self) -> None:
        n = build_node("foo", props=(("dev", True),))
        text = emit_document([n])
        doc = parse_kdl(text, context="manifest")
        ns = nodes(doc)
        assert node_prop_bool(ns[0], "dev") is True

    def test_multiple_nodes(self) -> None:
        n1 = build_node("name", args=("milpa",))
        n2 = build_node("version", args=("0.1.0",))
        text = emit_document([n1, n2])
        doc = parse_kdl(text, context="manifest")
        ns = nodes(doc)
        assert len(ns) == 2
        assert node_arg_str(ns[0]) == "milpa"
        assert node_arg_str(ns[1]) == "0.1.0"

    def test_children_round_trip(self) -> None:
        child = build_node("dep", args=("intonaco",))
        parent = build_node("deps", children=(child,))
        text = emit_document([parent])
        doc = parse_kdl(text, context="manifest")
        ns = nodes(doc)
        ch = node_children(ns[0])
        assert len(ch) == 1
        assert node_arg_str(ch[0]) == "intonaco"


# ---------------------------------------------------------------------------
# Public interface type-boundary: no kdl.* types escape
# ---------------------------------------------------------------------------


class TestTypeBoundary:
    """Verify that the public interface never returns a kdl.* type."""

    def _all_public_return_values(self) -> list[object]:
        doc = parse_kdl(
            'foo git=(url)"https://example.com" x=42 flag=#true {\n  child "a"\n}\n',
            context="manifest",
        )
        ns = nodes(doc)
        n = ns[0]
        return [
            doc,
            ns,
            n,
            node_name(n),
            node_args(n),
            node_props(n),
            node_children(n),
            node_arg_str(n, 0),
            node_arg_url(n, 0),
            node_prop_str(n, "x"),
            node_prop_url(n, "git"),
            node_prop_int(n, "x"),
            node_prop_bool(n, "flag"),
        ]

    def test_no_kdl_types_in_return_values(self) -> None:

        def _check(val: object) -> None:
            """Recursively verify no kdl.* types appear."""
            if isinstance(val, (list, tuple)):
                for item in val:
                    _check(item)
            elif isinstance(val, dict):
                for k, v in val.items():
                    _check(k)
                    _check(v)
            else:
                # Allow basic Python types + our milpa types
                allowed = (str, int, float, bool, type(None), KdlDocument, KdlNode, UrlValue)
                if val is not None and not isinstance(val, allowed):
                    # Check it's not a kdl module type
                    mod = getattr(type(val), "__module__", "")
                    assert not mod.startswith("kdl"), (
                        f"kdl.* type {type(val)} leaked through public interface: {val!r}"
                    )

        for rv in self._all_public_return_values():
            _check(rv)
