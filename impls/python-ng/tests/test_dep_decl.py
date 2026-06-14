"""S1 conformance oracle for dep_decl.py — EdgeSet type + DepDecl parser.

Parses the S0 golden vector from conformance/spec-v1/dep-decl-golden/v0/
and asserts the resulting EdgeSet equals a hand-constructed expected value.
Also asserts the hash helper over the exact file bytes matches the recorded
dep_decl_hash.

spec/dep-decl.md §1 (EdgeSet type), §2 (document shape), §3 (hash algorithm).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from milpa.dep_decl import (
    EdgeSet,
    EdgeSource,
    NamedRequire,
    UrlRequire,
    dep_decl_hash,
    parse_dep_decl,
)

# ---------------------------------------------------------------------------
# Corpus path (mirrors test_conformance.py pattern)
# ---------------------------------------------------------------------------

_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[3]  # impls/python-ng/tests → repo root
_GOLDEN_DIR = _REPO_ROOT / "conformance" / "spec-v1" / "dep-decl-golden" / "v0"
_EXAMPLE_KDL = _GOLDEN_DIR / "example.kdl"
_META_JSON = _GOLDEN_DIR / "meta.json"

# ---------------------------------------------------------------------------
# S0 golden vector: hand-constructed expected values (spec/dep-decl.md §A)
# ---------------------------------------------------------------------------

# These are deliberately hard-coded — NOT read from meta.json — so a corrupted
# meta.json cannot mask a parser bug.  The meta.json cross-check below is a
# second assertion, not the only assertion.

EXPECTED_EDGE_SET = EdgeSet(
    requires=[
        NamedRequire(name="results", constraint_str=">= 0.5.0"),
        NamedRequire(name="stew", constraint_str=">= 0.1 & < 1.0"),
        UrlRequire(url="https://github.com/status-im/nim-chronos.git", ref="v3.2.0"),
    ],
    src_dir="src",
    source=EdgeSource.DEP_DECL,
)

EXPECTED_DEP_DECL_HASH = (
    "sha256:34a91f93fc03cadbd69379b97cdbac82110070ead8595038f0cc203e72d346bd"
)


# ---------------------------------------------------------------------------
# Sanity: corpus files exist
# ---------------------------------------------------------------------------


def test_golden_corpus_files_exist() -> None:
    """Fail fast if the S0 golden vector is missing from the corpus."""
    assert _EXAMPLE_KDL.is_file(), f"Golden KDL not found: {_EXAMPLE_KDL}"
    assert _META_JSON.is_file(), f"Meta JSON not found: {_META_JSON}"


# ---------------------------------------------------------------------------
# Oracle test: parse the S0 golden vector
# ---------------------------------------------------------------------------


def test_parse_dep_decl_golden_vector() -> None:
    """parse_dep_decl(golden_bytes) == hand-constructed EXPECTED_EDGE_SET."""
    raw = _EXAMPLE_KDL.read_bytes()
    es, _ = parse_dep_decl(raw)

    assert es == EXPECTED_EDGE_SET, (
        f"EdgeSet mismatch.\n  got: {es!r}\n  want: {EXPECTED_EDGE_SET!r}"
    )


def test_dep_decl_hash_golden_vector() -> None:
    """dep_decl_hash(golden_bytes) == EXPECTED_DEP_DECL_HASH."""
    raw = _EXAMPLE_KDL.read_bytes()
    computed = dep_decl_hash(raw)

    assert computed == EXPECTED_DEP_DECL_HASH, (
        f"Hash mismatch.\n  got:  {computed}\n  want: {EXPECTED_DEP_DECL_HASH}"
    )


def test_parse_dep_decl_source_tag_is_dep_decl() -> None:
    """EdgeSet produced by parse_dep_decl always has source = DEP_DECL."""
    raw = _EXAMPLE_KDL.read_bytes()
    es, _ = parse_dep_decl(raw)
    assert es.source == EdgeSource.DEP_DECL


# ---------------------------------------------------------------------------
# Cross-check meta.json (second oracle — a corrupted meta.json is caught here,
# not silently masked by using meta.json as the primary assertion)
# ---------------------------------------------------------------------------


def test_meta_json_dep_decl_hash_matches_golden_constant() -> None:
    """meta.json dep_decl_hash == EXPECTED_DEP_DECL_HASH (integrity check)."""
    meta = json.loads(_META_JSON.read_text(encoding="utf-8"))
    assert meta["dep_decl_hash"] == EXPECTED_DEP_DECL_HASH


def test_meta_json_expected_edge_set_matches_parse_result() -> None:
    """meta.json expected_edge_set matches what parse_dep_decl returns."""
    meta = json.loads(_META_JSON.read_text(encoding="utf-8"))
    raw = _EXAMPLE_KDL.read_bytes()
    result, _ = parse_dep_decl(raw)

    meta_es = meta["expected_edge_set"]

    # src_dir
    assert result.src_dir == meta_es["src_dir"]

    # requires: compare length and each entry
    assert len(result.requires) == len(meta_es["requires"]), (
        f"requires length: got {len(result.requires)}, want {len(meta_es['requires'])}"
    )
    for i, (got, want) in enumerate(zip(result.requires, meta_es["requires"])):
        if "name" in want:
            assert isinstance(got, NamedRequire), f"Entry {i}: expected NamedRequire"
            assert got.name == want["name"], f"Entry {i} name"
            assert got.constraint_str == want["constraint"], f"Entry {i} constraint"
        else:
            assert isinstance(got, UrlRequire), f"Entry {i}: expected UrlRequire"
            assert got.url == want["url"], f"Entry {i} url"
            assert got.ref == want["ref"], f"Entry {i} ref"


# ---------------------------------------------------------------------------
# Unit tests for edge-case parsing
# ---------------------------------------------------------------------------


def test_parse_dep_decl_empty_requires() -> None:
    """An EdgeSet with no requires and empty src_dir parses correctly."""
    kdl_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 0\n"
        b"    src_dir \"\"\n"
        b"}\n"
    )
    es, _ = parse_dep_decl(kdl_bytes)
    assert es == EdgeSet(requires=[], src_dir="", source=EdgeSource.DEP_DECL)


def test_parse_dep_decl_only_named_requires() -> None:
    """A DepDecl with only NamedRequire entries parses correctly."""
    kdl_bytes = (
        b'dep_decl {\n'
        b'    dep_decl_schema_version 0\n'
        b'    src_dir ""\n'
        b'    require "foo" ">= 1.0.0"\n'
        b'    require "bar" ""\n'
        b'}\n'
    )
    es, _ = parse_dep_decl(kdl_bytes)
    assert es.requires == [
        NamedRequire(name="foo", constraint_str=">= 1.0.0"),
        NamedRequire(name="bar", constraint_str=""),
    ]
    assert es.src_dir == ""


def test_parse_dep_decl_only_url_requires() -> None:
    """A DepDecl with only UrlRequire entries parses correctly."""
    kdl_bytes = (
        b'dep_decl {\n'
        b'    dep_decl_schema_version 0\n'
        b'    src_dir ""\n'
        b'    require (url)"https://example.com/pkg.git" ref="main"\n'
        b'}\n'
    )
    es, _ = parse_dep_decl(kdl_bytes)
    assert es.requires == [
        UrlRequire(url="https://example.com/pkg.git", ref="main"),
    ]


def test_dep_decl_hash_is_sha256_prefixed() -> None:
    """dep_decl_hash always returns a sha256:-prefixed string."""
    h = dep_decl_hash(b"any bytes")
    assert h.startswith("sha256:")
    digest = h.removeprefix("sha256:")
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_dep_decl_hash_deterministic() -> None:
    """dep_decl_hash is deterministic — same bytes → same hash."""
    data = b"dep_decl { dep_decl_schema_version 0\n    src_dir \"\" }\n"
    assert dep_decl_hash(data) == dep_decl_hash(data)


def test_dep_decl_hash_distinct_for_different_bytes() -> None:
    """Different bytes produce different hashes."""
    a = b"dep_decl { dep_decl_schema_version 0\n    src_dir \"\" }\n"
    b_ = b"dep_decl { dep_decl_schema_version 0\n    src_dir \"src\" }\n"
    assert dep_decl_hash(a) != dep_decl_hash(b_)


def test_edge_source_enum_values() -> None:
    """EdgeSource has the three required values."""
    assert EdgeSource.DEP_DECL.value == "dep_decl"
    assert EdgeSource.MILPA_KDL.value == "milpa_kdl"
    assert EdgeSource.NIMBLE_FALLBACK.value == "nimble_fallback"


# ---------------------------------------------------------------------------
# R3: parse_dep_decl surfaces schema version from DOM (not a re-scan)
# ---------------------------------------------------------------------------


def test_parse_dep_decl_returns_schema_version_from_dom() -> None:
    """parse_dep_decl returns (EdgeSet, schema_version) with the version from the DOM.

    R3: parse_dep_decl must return the schema_version integer sourced from the
    parsed KDL DOM node, NOT from a separate re-scan of the raw bytes.
    The return type is (EdgeSet, int).
    """
    kdl_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 0\n"
        b'    src_dir ""\n'
        b"}\n"
    )
    result = parse_dep_decl(kdl_bytes)
    # parse_dep_decl must return a 2-tuple (EdgeSet, int).
    assert isinstance(result, tuple), (
        "parse_dep_decl must return (EdgeSet, schema_version: int), got non-tuple"
    )
    es, schema_version = result
    assert isinstance(es, EdgeSet)
    assert schema_version == 0


def test_parse_dep_decl_returns_correct_schema_version() -> None:
    """parse_dep_decl returns the exact schema version declared in the artifact."""
    # Use a non-zero version to ensure we're reading from the DOM, not defaulting.
    kdl_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 7\n"
        b'    src_dir ""\n'
        b"}\n"
    )
    _, schema_version = parse_dep_decl(kdl_bytes)
    assert schema_version == 7


def test_parse_dep_decl_schema_version_absent_defaults_to_zero() -> None:
    """When dep_decl_schema_version node is absent, schema_version defaults to 0 (forward-compat).

    spec/dep-decl.md §4.3 forward-compat: treat missing version as v0.
    """
    kdl_bytes = (
        b"dep_decl {\n"
        b'    src_dir ""\n'
        b"}\n"
    )
    _, schema_version = parse_dep_decl(kdl_bytes)
    assert schema_version == 0


def test_parse_dep_decl_keyword_in_string_value_not_confused() -> None:
    """A dep_decl_schema_version keyword appearing in a string value does NOT confuse the version.

    R3 regression: a text-scan would match 'dep_decl_schema_version 99' inside
    a string value, returning 99 instead of the actual integer node value.
    The DOM-sourced implementation is immune to this.
    """
    # The src_dir STRING VALUE contains the keyword with a bogus number.
    # The actual dep_decl_schema_version node declares 0.
    kdl_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 0\n"
        b'    src_dir "dep_decl_schema_version 99"\n'
        b"}\n"
    )
    _, schema_version = parse_dep_decl(kdl_bytes)
    assert schema_version == 0, (
        "Schema version must be read from the DOM node, not from a text-scan "
        "that would find '99' inside the src_dir string value"
    )


def test_parse_dep_decl_keyword_in_require_name_not_confused() -> None:
    """A require entry whose name contains 'dep_decl_schema_version' does not confuse version.

    Additional R3 regression test: text-scan could match the keyword inside
    a require node argument string.
    """
    # The require node's name argument contains the keyword.
    kdl_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 0\n"
        b'    src_dir ""\n'
        b'    require "dep_decl_schema_version" "99"\n'
        b"}\n"
    )
    _, schema_version = parse_dep_decl(kdl_bytes)
    assert schema_version == 0, (
        "Schema version must be read from the DOM node, not from text-scan "
        "matching inside a require argument"
    )


def test_parse_dep_decl_golden_vector_returns_version_zero() -> None:
    """The S0 golden vector reports schema_version = 0 from parse_dep_decl."""
    raw = _EXAMPLE_KDL.read_bytes()
    es, schema_version = parse_dep_decl(raw)
    assert schema_version == 0
    # EdgeSet is still correct (existing golden oracle).
    assert es == EXPECTED_EDGE_SET


def test_parse_dep_decl_large_version_is_not_zero() -> None:
    """parse_dep_decl does NOT return 0 for a very large schema_version.

    R3 overflow fix (Python side): kdl-py returns very large integers as float
    (e.g. 99999999999999999999 → 1e+20).  value_as_int converts whole-number
    floats to int; the result may not be the exact decimal value but it MUST NOT
    be 0.  The caller (DepDeclEdgeSource) checks > MAX_DEP_DECL_SCHEMA_VERSION
    and raises TNG-DEPDECL-SCHEMA-UNSUPPORTED.  Returning 0 would be fail-open
    (that is the Rust text-scan bug: digits.parse::<i64>().unwrap_or(0)).
    """
    # 99999999999999999999 exceeds i64::MAX (9223372036854775807).
    # kdl-py represents it as float 1e+20; int(1e+20) = 100000000000000000000 > 0.
    kdl_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 99999999999999999999\n"
        b'    src_dir ""\n'
        b"}\n"
    )
    _, schema_version = parse_dep_decl(kdl_bytes)
    assert schema_version is not None
    assert schema_version > 0, (
        f"Large schema_version must NOT be 0; got {schema_version}. "
        "Returning 0 would be fail-open (text-scan overflow bug R3)."
    )
    # Must be > MAX_DEP_DECL_SCHEMA_VERSION=0 so the SCHEMA-UNSUPPORTED check fires.
    from milpa.dep_decl import MAX_DEP_DECL_SCHEMA_VERSION
    assert schema_version > MAX_DEP_DECL_SCHEMA_VERSION
