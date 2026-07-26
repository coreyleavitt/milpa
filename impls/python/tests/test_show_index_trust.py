"""Unit tests for ``milpa show --index-trust`` observability helpers.

Tests ``describe_index_bundle`` and ``format_index_trust_info`` in
``milpa.index_trust``.  These helpers are the single source of truth
for the ``show --index-trust`` output format (byte-identical between
the Python and Rust impls).

spec/cli-contract.md §5.3a.
"""

from __future__ import annotations

import json

import pytest

from milpa.index_trust import (
    IndexBundleInfo,
    describe_index_bundle,
    format_index_trust_info,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIGNER_SAN = (
    "https://github.com/coreyleavitt/tianguis/"
    ".github/workflows/attest-index.yaml@refs/heads/main"
)
_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_SUBJECT_SHA256 = "abc123deadbeefabc123deadbeefabc123deadbeefabc123deadbeefabc12345"

_MOCK_BUNDLE = {
    "verificationMaterial": {
        "tlogEntries": [
            {
                "integratedTime": "1735000000",
                "logIndex": "98765432",
            }
        ]
    },
    "_milpa_claims": {
        "signer_san": _SIGNER_SAN,
        "oidc_issuer": _OIDC_ISSUER,
        "subject_sha256": _SUBJECT_SHA256,
    },
}


def _bundle_bytes(d: dict) -> bytes:
    return json.dumps(d).encode()


# ---------------------------------------------------------------------------
# describe_index_bundle — positive cases
# ---------------------------------------------------------------------------


def test_describe_full_mock_bundle():
    """describe_index_bundle extracts all five fields from a mock bundle."""
    info = describe_index_bundle(_bundle_bytes(_MOCK_BUNDLE))
    assert info is not None
    assert info.integrated_time == 1_735_000_000
    assert info.rekor_log_index == "98765432"
    assert info.signer_san == _SIGNER_SAN
    assert info.oidc_issuer == _OIDC_ISSUER
    assert info.subject_sha256 == _SUBJECT_SHA256


def test_describe_integer_integrated_time():
    """integratedTime may also be a native JSON integer (not just a string)."""
    bundle = dict(_MOCK_BUNDLE)
    bundle["verificationMaterial"] = {
        "tlogEntries": [{"integratedTime": 1_735_000_000, "logIndex": "42"}]
    }
    info = describe_index_bundle(_bundle_bytes(bundle))
    assert info is not None
    assert info.integrated_time == 1_735_000_000
    assert info.rekor_log_index == "42"


def test_describe_no_milpa_claims_fields_are_none():
    """Without _milpa_claims, signer/issuer/subject_sha256 are None."""
    bundle = {
        "verificationMaterial": {
            "tlogEntries": [{"integratedTime": "1735000000", "logIndex": "1"}]
        }
    }
    info = describe_index_bundle(_bundle_bytes(bundle))
    assert info is not None
    assert info.signer_san is None
    assert info.oidc_issuer is None
    assert info.subject_sha256 is None
    assert info.rekor_log_index == "1"


def test_describe_missing_log_index_shows_not_available():
    """Missing logIndex surfaces as '(not available)', not an error."""
    bundle = {
        "verificationMaterial": {
            "tlogEntries": [{"integratedTime": "1735000000"}]
        }
    }
    info = describe_index_bundle(_bundle_bytes(bundle))
    assert info is not None
    assert info.rekor_log_index == "(not available)"


# ---------------------------------------------------------------------------
# describe_index_bundle — error / edge cases
# ---------------------------------------------------------------------------


def test_describe_not_json_returns_none():
    assert describe_index_bundle(b"not valid json!!!") is None


def test_describe_json_array_returns_none():
    assert describe_index_bundle(b'["not", "an", "object"]') is None


def test_describe_missing_integrated_time_returns_none():
    """Missing integratedTime (mandatory field) → None."""
    bundle = {"verificationMaterial": {"tlogEntries": [{"logIndex": "1"}]}}
    assert describe_index_bundle(_bundle_bytes(bundle)) is None


def test_describe_empty_tlog_entries_returns_none():
    bundle = {"verificationMaterial": {"tlogEntries": []}}
    assert describe_index_bundle(_bundle_bytes(bundle)) is None


def test_describe_missing_verification_material_returns_none():
    assert describe_index_bundle(b'{"mediaType": "fake"}') is None


def test_describe_empty_bytes_returns_none():
    assert describe_index_bundle(b"") is None


# ---------------------------------------------------------------------------
# format_index_trust_info — no bundle cached
# ---------------------------------------------------------------------------


def test_format_no_bundle():
    """No bundle cached: only 4 header lines, no claims block."""
    out = format_index_trust_info(
        index_url="https://example.com/index.kdl",
        policy="warn",
        index_cached=False,
        bundle_cached=False,
        info=None,
        now=1_735_001_000,
    )
    assert out == (
        "index-url:      https://example.com/index.kdl\n"
        "policy:         warn\n"
        "index-cached:   no\n"
        "bundle-cached:  no\n"
    )


def test_format_index_cached_bundle_not():
    """Index cached but no bundle."""
    out = format_index_trust_info(
        index_url="https://example.com/index.kdl",
        policy="strict",
        index_cached=True,
        bundle_cached=False,
        info=None,
        now=1_735_001_000,
    )
    assert out == (
        "index-url:      https://example.com/index.kdl\n"
        "policy:         strict\n"
        "index-cached:   yes\n"
        "bundle-cached:  no\n"
    )


# ---------------------------------------------------------------------------
# format_index_trust_info — bundle cached + freshness
# ---------------------------------------------------------------------------

_FRESH_INFO = IndexBundleInfo(
    integrated_time=1_735_000_000,
    rekor_log_index="98765432",
    subject_sha256=_SUBJECT_SHA256,
    signer_san=_SIGNER_SAN,
    oidc_issuer=_OIDC_ISSUER,
)


def test_format_fresh_bundle():
    """Fresh bundle (age = 1000 s < default max_age 604800)."""
    out = format_index_trust_info(
        index_url="https://mock.example.com/index.kdl",
        policy="warn",
        index_cached=True,
        bundle_cached=True,
        info=_FRESH_INFO,
        now=1_735_001_000,  # age = 1000 s
    )
    expected = (
        "index-url:      https://mock.example.com/index.kdl\n"
        "policy:         warn\n"
        "index-cached:   yes\n"
        "bundle-cached:  yes\n"
        f"signer:         {_SIGNER_SAN}\n"
        f"issuer:         {_OIDC_ISSUER}\n"
        "integrated:     1735000000\n"
        f"subject-sha256: {_SUBJECT_SHA256}\n"
        "rekor-entry:    98765432\n"
        "freshness:      fresh\n"
    )
    assert out == expected


def test_format_stale_bundle():
    """Stale bundle (age = 700000 s > default max_age 604800)."""
    out = format_index_trust_info(
        index_url="https://mock.example.com/index.kdl",
        policy="strict",
        index_cached=True,
        bundle_cached=True,
        info=_FRESH_INFO,
        now=1_735_700_000,  # age = 700000 s
    )
    assert out.endswith("freshness:      stale\n")
    assert "policy:         strict\n" in out


def test_format_custom_max_age():
    """Custom max_age: age 1000 s > max_age 500 s → stale."""
    out = format_index_trust_info(
        index_url="https://mock.example.com/index.kdl",
        policy="warn",
        index_cached=True,
        bundle_cached=True,
        info=_FRESH_INFO,
        now=1_735_001_000,
        max_age=500,
    )
    assert out.endswith("freshness:      stale\n")


def test_format_not_available_fields():
    """When _milpa_claims fields are None, '(not available)' is shown."""
    info = IndexBundleInfo(
        integrated_time=1_735_000_000,
        rekor_log_index="99",
        subject_sha256=None,
        signer_san=None,
        oidc_issuer=None,
    )
    out = format_index_trust_info(
        index_url="https://x.example.com/index.kdl",
        policy="warn",
        index_cached=True,
        bundle_cached=True,
        info=info,
        now=1_735_001_000,
    )
    assert "signer:         (not available)\n" in out
    assert "issuer:         (not available)\n" in out
    assert "subject-sha256: (not available)\n" in out


# ---------------------------------------------------------------------------
# Label-alignment invariant: each label+colon field is exactly 16 chars
# ---------------------------------------------------------------------------


def test_label_alignment_all_lines_same_column():
    """All value-bearing lines have their value starting at column 16."""
    out = format_index_trust_info(
        index_url="https://mock.example.com/index.kdl",
        policy="warn",
        index_cached=True,
        bundle_cached=True,
        info=_FRESH_INFO,
        now=1_735_001_000,
    )
    for line in out.rstrip("\n").splitlines():
        col = line.index(" ") + 1 if " " in line else len(line)
        # The first non-space char after the label+spaces starts at column 16.
        # All lines have a colon somewhere; value starts at position 16.
        assert len(line) > 16, f"Line too short: {line!r}"
        # Check that column 15 is the last space of the padding block.
        # i.e. line[:16] ends with at least one space.
        assert line[15] == " ", (
            f"Column 16 alignment broken on: {line!r}; "
            f"char at index 15 is {line[15]!r}"
        )


# ---------------------------------------------------------------------------
# format_index_trust_info — future-dated integratedTime (ITEM M10)
# ---------------------------------------------------------------------------


def test_format_future_dated_integrated_time_reports_fresh():
    """A future-dated ``integratedTime`` (integratedTime > now) MUST report 'fresh'.

    M10 Python pin test: ``age = now - integratedTime`` is NEGATIVE when
    integratedTime is in the future; negative age < max_age → 'fresh'.
    The freshness formula must NOT special-case negative ages — a negative age
    is simply a bundle signed in the future (unlikely in production but trivially
    possible in test fixtures), and it is unambiguously fresh.

    Rust is fixed to match this semantics.  Both impls must agree.
    """
    future_time = 9_999_999_999  # far future epoch
    now = 1_735_000_000  # a past "now"
    info = IndexBundleInfo(
        integrated_time=future_time,
        rekor_log_index="1",
        subject_sha256=None,
        signer_san=None,
        oidc_issuer=None,
    )
    out = format_index_trust_info(
        index_url="https://example.com/index.kdl",
        policy="warn",
        index_cached=True,
        bundle_cached=True,
        info=info,
        now=now,
        max_age=604800,
    )
    assert "fresh" in out, (
        f"M10: future-dated integratedTime (age = now - integratedTime < 0) must "
        f"report 'fresh'; age = {now} - {future_time} = {now - future_time}; output:\n{out}"
    )
    assert "stale" not in out, (
        f"M10: future-dated bundle must NOT report 'stale'; output:\n{out}"
    )
