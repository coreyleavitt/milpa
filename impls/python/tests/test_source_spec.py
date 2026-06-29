"""Tests for milpa.source_spec.parse_source_spec (slice A0-parse)."""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.errors import CLI_SOURCE_SPEC_INVALID, MilpaError
from milpa.fetchers.git import GitProvenance
from milpa.fetchers.local import LocalProvenance
from milpa.fetchers.oci import OciProvenance
from milpa.source_spec import parse_source_spec

_VALID_DIGEST = "sha256:" + "a" * 64


# ---------------------------------------------------------------------------
# Test 1: git form with full commit SHA → GitProvenance
# ---------------------------------------------------------------------------


def test_git_form_commit_sha() -> None:
    """git=<url> ref=<40hex> → GitProvenance with url+ref, commit_sha=None."""
    sha = "a" * 40
    result = parse_source_spec([f"git=https://example.com/r.git", f"ref={sha}"])
    assert isinstance(result, GitProvenance)
    assert result.url == "https://example.com/r.git"
    assert result.ref == sha
    assert result.commit_sha is None


# ---------------------------------------------------------------------------
# Test 2: local form with absolute path → LocalProvenance
# ---------------------------------------------------------------------------


def test_local_form_absolute_path() -> None:
    """local=/abs/path → LocalProvenance with that absolute path."""
    result = parse_source_spec(["local=/abs/path/to/pkg"])
    assert isinstance(result, LocalProvenance)
    assert result.path == Path("/abs/path/to/pkg")


# ---------------------------------------------------------------------------
# Test 3: local form with relative path → resolved against base_dir
# ---------------------------------------------------------------------------


def test_local_form_relative_path_resolved_against_base_dir() -> None:
    """local=rel resolves against an injected base_dir."""
    base = Path("/workspace/root")
    result = parse_source_spec(["local=mypkg"], base_dir=base)
    assert isinstance(result, LocalProvenance)
    assert result.path == Path("/workspace/root/mypkg")


# ---------------------------------------------------------------------------
# Test 4: unknown key → MilpaError
# ---------------------------------------------------------------------------


def test_unknown_key_raises() -> None:
    """foo=bar → MilpaError with CLI_SOURCE_SPEC_INVALID."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec(["foo=bar"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID
    assert exc_info.value.context["key"] == "foo"


# ---------------------------------------------------------------------------
# Test 5: token without = → MilpaError
# ---------------------------------------------------------------------------


def test_token_without_equals_raises() -> None:
    """A token with no = → MilpaError."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec(["notakeyvalue"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID
    assert exc_info.value.context["token"] == "notakeyvalue"


# ---------------------------------------------------------------------------
# Test 6: git= without ref= → MilpaError
# ---------------------------------------------------------------------------


def test_git_missing_ref_raises() -> None:
    """git= present but ref= absent → MilpaError."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec(["git=https://example.com/r.git"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID
    assert "ref" in exc_info.value.context["missing"]


# ---------------------------------------------------------------------------
# Test 7: mixing git= and local= → MilpaError
# ---------------------------------------------------------------------------


def test_mixing_git_and_local_raises() -> None:
    """git= and local= together → MilpaError."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec(["git=https://example.com/r.git", "ref=main", "local=/some/path"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID
    assert "git" in exc_info.value.context["keys"]
    assert "local" in exc_info.value.context["keys"]


# ---------------------------------------------------------------------------
# Test 8: empty token list → MilpaError
# ---------------------------------------------------------------------------


def test_empty_tokens_raises() -> None:
    """Empty token list → MilpaError."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec([])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID


# ---------------------------------------------------------------------------
# Test 9: duplicate key → MilpaError
# ---------------------------------------------------------------------------


def test_duplicate_key_raises() -> None:
    """Duplicate key → MilpaError."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec(["git=https://a.com/r.git", "git=https://b.com/r.git", "ref=main"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID
    assert exc_info.value.context["key"] == "git"


# ---------------------------------------------------------------------------
# Test 10: symbolic ref is accepted (no over-rejection)
# ---------------------------------------------------------------------------


def test_symbolic_ref_accepted() -> None:
    """ref=main (symbolic) is accepted; commit_sha remains None."""
    result = parse_source_spec(["git=https://example.com/r.git", "ref=main"])
    assert isinstance(result, GitProvenance)
    assert result.ref == "main"
    assert result.commit_sha is None


# ---------------------------------------------------------------------------
# OCI form tests (oci=<registry>/<repository>@<digest>)
# ---------------------------------------------------------------------------


def test_oci_form_basic() -> None:
    """oci=ghcr.io/org/pkg@sha256:<64hex> → OciProvenance with correct fields."""
    result = parse_source_spec([f"oci=ghcr.io/org/pkg@{_VALID_DIGEST}"])
    assert isinstance(result, OciProvenance)
    assert result.registry == "ghcr.io"
    assert result.repository == "org/pkg"
    assert result.digest == _VALID_DIGEST


def test_oci_form_multi_slash_repository() -> None:
    """Repository with multiple slashes: registry=first segment, repository=rest."""
    result = parse_source_spec([f"oci=reg.io/a/b/c@{_VALID_DIGEST}"])
    assert isinstance(result, OciProvenance)
    assert result.registry == "reg.io"
    assert result.repository == "a/b/c"
    assert result.digest == _VALID_DIGEST


def test_oci_missing_at_raises() -> None:
    """oci= value without '@' → CLI-SOURCE-SPEC-INVALID."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec(["oci=ghcr.io/org/pkg"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID


def test_oci_two_at_raises() -> None:
    """oci= value with two '@' → CLI-SOURCE-SPEC-INVALID."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec([f"oci=ghcr.io/org/pkg@{_VALID_DIGEST}@extra"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID


def test_oci_no_slash_before_at_raises() -> None:
    """oci= value with no '/' before '@' → CLI-SOURCE-SPEC-INVALID."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec([f"oci=ghcr.io@{_VALID_DIGEST}"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID


def test_oci_invalid_digest_raises() -> None:
    """oci= with malformed digest → CLI-SOURCE-SPEC-INVALID (via OciProvenance validation)."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec(["oci=ghcr.io/org/pkg@notadigest"])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID


def test_oci_mixed_with_git_raises() -> None:
    """Mixing oci= with git= → CLI-SOURCE-SPEC-INVALID."""
    with pytest.raises(MilpaError) as exc_info:
        parse_source_spec([
            f"oci=ghcr.io/org/pkg@{_VALID_DIGEST}",
            "git=https://example.com/r.git",
            "ref=main",
        ])
    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID
