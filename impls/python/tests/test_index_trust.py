"""Tests for index_trust.py — whole-index Sigstore verifier module (S3 gate).

RFC: docs/rfc-registry-trust-federation.md §11 S3.

S3 gate: ``uv run pytest tests/test_index_trust.py`` — MockVerifier unit tests ONLY.
The real ``SigstoreVerifier`` integration test against the ``_oracle/`` test bundle
is gated at S5 (RFC §12.2 — the full policy stack must be wired and the bundle
generation tooling validated end-to-end before the integration test is added).

What this file tests:
  1. ``MockVerifier`` passthrough — all 7 ``VerificationResult`` variants reachable.
  2. ``verify_index_bundle`` structural / non-crypto cases:
       - Malformed JSON → ``BundleMalformed`` (step 1).
       - Missing ``tlogEntries`` → ``BundleMalformed`` (step 2).
       - Missing ``integratedTime`` → ``BundleMalformed`` (step 2).
       - Stale ``integratedTime`` + finite ``max_age_seconds`` → ``BundleStale`` (step 3).
       - Same stale bundle + ``max_age_seconds=None`` → NOT ``BundleStale`` (step 3
         skipped — proves freshness is not re-asserted on pure cache reads).
  3. ``IndexTrustConfig`` interface: frozen, no ``verifier`` field, default max_age.
  4. ``TrustBundle`` factories: ``production()`` loadable, ``test()`` returns an instance.
  5. ``SigstoreVerifier`` structural typing check (Protocol satisfaction).
  6. ``VerificationResult`` enum: 7 variants, module-level aliases.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from milpa.errors import (
    MilpaError,
    TNG_INDEX_BUNDLE_MALFORMED,
    TNG_INDEX_BUNDLE_MISSING,
    TNG_INDEX_BUNDLE_STALE,
    TNG_INDEX_DIGEST_MISMATCH,
    TNG_INDEX_SIGNATURE_INVALID,
    TNG_INDEX_SIGNER_MISMATCH,
)
from milpa.index_trust import (
    BundleMalformed,
    BundleMissing,
    BundleStale,
    DigestMismatch,
    IndexBundleVerifier,
    IndexTrustConfig,
    MockVerifier,
    SigstoreVerifier,
    SignerMismatch,
    SigInvalid,
    Trusted,
    TrustBundle,
    VerificationResult,
    _reset_warned_urls,
    enforce_index_trust,
    verify_index_bundle,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_DUMMY_TRUST_BUNDLE = TrustBundle(raw_json=b'{"__test__": true}', label="test:dummy")

# Default pinned signer identity (RFC §3.2)
_DEFAULT_SIGNER = (
    "https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml@refs/heads/main"
)


def _make_minimal_bundle(integrated_time: int) -> bytes:
    """Build a minimal Sigstore bundle JSON with the given ``integratedTime``.

    Passes our OWN step-2 structural extraction (RFC §4 step 2 — extracting
    ``integratedTime``) but will NOT pass ``sigstore-python``'s bundle
    validation (``Bundle.from_json`` requires ``inclusionProof``), so
    ``_sigstore_verify`` returns ``BundleMalformed`` rather than making any
    network call.  This is intentional for staleness-path tests.
    """
    data: dict[str, Any] = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "integratedTime": str(integrated_time),
                    "logIndex": "0",
                    "logId": {"keyId": ""},
                    "inclusionPromise": {"signedEntryTimestamp": ""},
                    "canonicalizedBody": "",
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                }
            ]
        },
        "dsseEnvelope": {
            "payload": "",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [],
        },
    }
    return json.dumps(data).encode()


# ---------------------------------------------------------------------------
# MockVerifier — all 7 VerificationResult variants reachable via passthrough
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("expected", list(VerificationResult))
def test_mock_verifier_returns_configured_result(expected: VerificationResult) -> None:
    """MockVerifier returns exactly the result it was constructed with.

    Covers all 7 variants: Trusted, SigInvalid, DigestMismatch, SignerMismatch,
    BundleStale, BundleMissing, BundleMalformed.
    """
    mock = MockVerifier(expected)
    result = mock.verify(
        index_bytes=b"",
        bundle_bytes=b"",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,
    )
    assert result is expected


def test_mock_verifier_ignores_all_inputs() -> None:
    """MockVerifier ignores ALL parameters — only the constructor result matters.

    Even with a stale max_age_seconds (1 s) and wrong signer, the result
    is Trusted if that is what the MockVerifier was constructed with.  The
    policy state machine is what is being tested, not cryptography.
    """
    mock = MockVerifier(Trusted)
    result = mock.verify(
        index_bytes=b"some index bytes that do not match any bundle",
        bundle_bytes=b"not a bundle at all",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer="wrong@example.com",
        max_age_seconds=1,  # would be stale if freshness were evaluated
    )
    assert result is Trusted


def test_mock_verifier_trusted() -> None:
    assert MockVerifier(Trusted).verify(b"", b"", _DUMMY_TRUST_BUNDLE, "", None) is Trusted


def test_mock_verifier_sig_invalid() -> None:
    assert MockVerifier(SigInvalid).verify(b"", b"", _DUMMY_TRUST_BUNDLE, "", None) is SigInvalid


def test_mock_verifier_digest_mismatch() -> None:
    assert MockVerifier(DigestMismatch).verify(b"", b"", _DUMMY_TRUST_BUNDLE, "", None) is DigestMismatch


def test_mock_verifier_signer_mismatch() -> None:
    assert MockVerifier(SignerMismatch).verify(b"", b"", _DUMMY_TRUST_BUNDLE, "", None) is SignerMismatch


def test_mock_verifier_bundle_stale() -> None:
    assert MockVerifier(BundleStale).verify(b"", b"", _DUMMY_TRUST_BUNDLE, "", None) is BundleStale


def test_mock_verifier_bundle_missing() -> None:
    """BundleMissing is constructed by load_index on bundle-404; MockVerifier
    exercises the variant for total dispatch in enforce_index_trust (S5)."""
    assert MockVerifier(BundleMissing).verify(b"", b"", _DUMMY_TRUST_BUNDLE, "", None) is BundleMissing


def test_mock_verifier_bundle_malformed() -> None:
    assert MockVerifier(BundleMalformed).verify(b"", b"", _DUMMY_TRUST_BUNDLE, "", None) is BundleMalformed


# ---------------------------------------------------------------------------
# verify_index_bundle — structural / non-crypto cases
# ---------------------------------------------------------------------------


def test_verify_index_bundle_malformed_non_json() -> None:
    """Non-JSON bytes → BundleMalformed (step 1 — pre-crypto parse failure)."""
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=b"not json {{{garbage",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,
    )
    assert result is BundleMalformed


def test_verify_index_bundle_malformed_json_not_dict() -> None:
    """JSON array (not a dict) → BundleMalformed (step 1)."""
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=b"[1, 2, 3]",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,
    )
    assert result is BundleMalformed


def test_verify_index_bundle_malformed_missing_tlog_entries() -> None:
    """Bundle missing ``tlogEntries`` → BundleMalformed (step 2).

    We cannot extract ``integratedTime`` without ``tlogEntries``.
    """
    bundle = json.dumps({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {},  # no tlogEntries
        "dsseEnvelope": {"payload": "", "payloadType": "", "signatures": []},
    }).encode()
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=bundle,
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,
    )
    assert result is BundleMalformed


def test_verify_index_bundle_malformed_empty_tlog_entries() -> None:
    """Empty ``tlogEntries`` list → BundleMalformed (step 2 — IndexError)."""
    bundle = json.dumps({
        "verificationMaterial": {"tlogEntries": []},
        "dsseEnvelope": {},
    }).encode()
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=bundle,
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,
    )
    assert result is BundleMalformed


def test_verify_index_bundle_malformed_missing_integrated_time() -> None:
    """``tlogEntries`` present but no ``integratedTime`` → BundleMalformed (step 2)."""
    bundle = json.dumps({
        "verificationMaterial": {
            "tlogEntries": [{"logIndex": "0"}]  # integratedTime absent
        },
        "dsseEnvelope": {},
    }).encode()
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=bundle,
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,
    )
    assert result is BundleMalformed


def test_verify_index_bundle_malformed_integrated_time_not_int() -> None:
    """Non-numeric ``integratedTime`` → BundleMalformed (step 2 — ValueError)."""
    bundle = json.dumps({
        "verificationMaterial": {
            "tlogEntries": [{"integratedTime": "not-a-number"}]
        },
        "dsseEnvelope": {},
    }).encode()
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=bundle,
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,
    )
    assert result is BundleMalformed


def test_verify_index_bundle_stale_with_finite_max_age() -> None:
    """Old ``integratedTime`` + finite ``max_age_seconds`` → BundleStale (step 3).

    Proves the freshness check fires on the network-fetch path.
    ``integratedTime = 1000`` (epoch + 1000 s = 1970-01-01T00:16:40Z) is
    always stale vs any reasonable ``max_age_seconds``.
    """
    bundle = _make_minimal_bundle(integrated_time=1000)
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=bundle,
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=604800,  # 7 days
    )
    assert result is BundleStale


def test_verify_index_bundle_stale_skipped_with_none_max_age() -> None:
    """SAME stale bundle + ``max_age_seconds=None`` → NOT BundleStale (step 3 skipped).

    This is the key proof that freshness is NOT re-asserted on pure cache reads
    (States 1 and 3 — RFC §4 step 6, §7.2).  The offline/air-gapped use case
    depends on this: a validly-signed but old cached bundle must not trigger
    BundleStale when the network is not being consulted.

    With freshness skipped, the function proceeds to crypto steps 4–6.
    Since the minimal bundle is not cryptographically valid, the result will be
    BundleMalformed (sigstore rejects the minimal bundle at Bundle.from_json),
    never BundleStale.
    """
    bundle = _make_minimal_bundle(integrated_time=1000)  # epoch + 1000 s (very old)
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=bundle,
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=None,  # freshness skipped on cache reads
    )
    # Must NOT be BundleStale — freshness was not evaluated.
    assert result is not BundleStale


# ---------------------------------------------------------------------------
# IndexTrustConfig — interface and invariant checks
# ---------------------------------------------------------------------------


def test_index_trust_config_is_frozen() -> None:
    """``IndexTrustConfig`` is a frozen dataclass — mutation raises ``AttributeError``."""
    cfg = IndexTrustConfig(
        policy="warn",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
    )
    with pytest.raises(AttributeError):
        cfg.policy = "strict"  # type: ignore[misc]


def test_index_trust_config_has_no_verifier_field() -> None:
    """``IndexTrustConfig`` MUST NOT have a ``verifier`` field.

    The verifier is an explicit parameter of ``load_index(url, config, verifier,
    …)`` — NOT stored in config — so tests cannot silently run against real
    Sigstore when they forget to inject a mock (RFC §7.2, §10.1).
    """
    cfg = IndexTrustConfig(
        policy="strict",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
    )
    assert not hasattr(cfg, "verifier"), (
        "IndexTrustConfig must not carry a verifier field; see RFC §7.2 / §10.1"
    )


def test_index_trust_config_default_max_age_is_seven_days() -> None:
    """Default ``max_age_seconds`` is 604800 (= 7 days = ``MILPA_INDEX_MAX_AGE`` default)."""
    cfg = IndexTrustConfig(
        policy="warn",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
    )
    assert cfg.max_age_seconds == 604800


def test_index_trust_config_custom_max_age() -> None:
    """Custom ``max_age_seconds`` is stored correctly."""
    cfg = IndexTrustConfig(
        policy="strict",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=86400,  # 1 day
    )
    assert cfg.max_age_seconds == 86400


def test_index_trust_config_stores_policy_and_signer() -> None:
    """Sanity: policy, trust_bundle, expected_signer are stored as provided."""
    cfg = IndexTrustConfig(
        policy="off",
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer="test-signer@example.com",
    )
    assert cfg.policy == "off"
    assert cfg.trust_bundle is _DUMMY_TRUST_BUNDLE
    assert cfg.expected_signer == "test-signer@example.com"


# ---------------------------------------------------------------------------
# TrustBundle — factory methods
# ---------------------------------------------------------------------------


def test_trust_bundle_production_is_loadable() -> None:
    """``TrustBundle.production()`` loads the embedded placeholder without error."""
    bundle = TrustBundle.production()
    assert isinstance(bundle, TrustBundle)
    assert bundle.label == "production"
    assert isinstance(bundle.raw_json, bytes)
    assert len(bundle.raw_json) > 0


def test_trust_bundle_test_returns_instance() -> None:
    """``TrustBundle.test()`` returns a ``TrustBundle`` instance (placeholder if no oracle)."""
    bundle = TrustBundle.test()
    assert isinstance(bundle, TrustBundle)
    assert "test:" in bundle.label
    assert isinstance(bundle.raw_json, bytes)
    assert len(bundle.raw_json) > 0


def test_trust_bundle_is_frozen() -> None:
    """``TrustBundle`` is a frozen dataclass."""
    bundle = TrustBundle(raw_json=b"{}",  label="test:frozen")
    with pytest.raises(AttributeError):
        bundle.label = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# SigstoreVerifier — structural / Protocol satisfaction check
# ---------------------------------------------------------------------------


def test_sigstore_verifier_satisfies_protocol() -> None:
    """``SigstoreVerifier`` satisfies the ``IndexBundleVerifier`` Protocol.

    Structural typing check only — no actual crypto verification in S3.
    The integration test against the ``_oracle/`` bundle is gated at S5.
    """
    verifier: IndexBundleVerifier = SigstoreVerifier()
    assert callable(verifier.verify)


# ---------------------------------------------------------------------------
# VerificationResult — enum completeness and alias correctness
# ---------------------------------------------------------------------------


def test_verification_result_has_seven_variants() -> None:
    """``VerificationResult`` has exactly 7 variants as specified in RFC §6.5."""
    assert len(VerificationResult) == 7


def test_verification_result_module_aliases_are_enum_members() -> None:
    """Module-level aliases (``Trusted``, etc.) are the same objects as enum members."""
    assert Trusted is VerificationResult.TRUSTED
    assert SigInvalid is VerificationResult.SIG_INVALID
    assert DigestMismatch is VerificationResult.DIGEST_MISMATCH
    assert SignerMismatch is VerificationResult.SIGNER_MISMATCH
    assert BundleStale is VerificationResult.BUNDLE_STALE
    assert BundleMissing is VerificationResult.BUNDLE_MISSING
    assert BundleMalformed is VerificationResult.BUNDLE_MALFORMED


def test_verification_result_values_match_rfc_mock_result_strings() -> None:
    """Enum values match the RFC §10.2 ``mock_verifier_result`` strings.

    The conformance fixture ``env`` field uses these strings verbatim
    (e.g. ``mock_verifier_result: sig-invalid``).
    """
    assert VerificationResult.TRUSTED.value == "trusted"
    assert VerificationResult.SIG_INVALID.value == "sig-invalid"
    assert VerificationResult.DIGEST_MISMATCH.value == "digest-mismatch"
    assert VerificationResult.SIGNER_MISMATCH.value == "signer-mismatch"
    assert VerificationResult.BUNDLE_STALE.value == "bundle-stale"
    assert VerificationResult.BUNDLE_MISSING.value == "bundle-missing"
    assert VerificationResult.BUNDLE_MALFORMED.value == "bundle-malformed"


# ---------------------------------------------------------------------------
# enforce_index_trust — S5 policy dispatch (RFC §6.5, §11 S3/S5)
# ---------------------------------------------------------------------------

INDEX_URL = "https://example.test/index.kdl"


def setup_function() -> None:  # noqa: ANN201
    """Reset the per-invocation warn dedup set before each test."""
    _reset_warned_urls()


# --- off policy: always silent ---


def test_enforce_off_trusted_silent(capsys: pytest.CaptureFixture[str]) -> None:
    """off + Trusted → no raise, no warning."""
    enforce_index_trust(Trusted, "off", INDEX_URL)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("result", [
    BundleMissing, BundleMalformed, SigInvalid,
    DigestMismatch, SignerMismatch, BundleStale,
])
def test_enforce_off_failure_silent(
    result: VerificationResult, capsys: pytest.CaptureFixture[str]
) -> None:
    """off policy: ALL non-Trusted results are silent (verifier was not called)."""
    enforce_index_trust(result, "off", INDEX_URL)
    assert capsys.readouterr().err == ""


# --- warn policy: emits stderr warning, exit 0 ---


def test_enforce_warn_trusted_silent(capsys: pytest.CaptureFixture[str]) -> None:
    """warn + Trusted → no warning (verification succeeded)."""
    enforce_index_trust(Trusted, "warn", INDEX_URL)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("result,slug", [
    (BundleMissing, TNG_INDEX_BUNDLE_MISSING),
    (BundleMalformed, TNG_INDEX_BUNDLE_MALFORMED),
    (SigInvalid, TNG_INDEX_SIGNATURE_INVALID),
    (DigestMismatch, TNG_INDEX_DIGEST_MISMATCH),
    (SignerMismatch, TNG_INDEX_SIGNER_MISMATCH),
    (BundleStale, TNG_INDEX_BUNDLE_STALE),
])
def test_enforce_warn_emits_slug_in_stderr(
    result: VerificationResult,
    slug: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """warn policy: slug appears in stderr warning; no MilpaError raised."""
    enforce_index_trust(result, "warn", INDEX_URL)
    err = capsys.readouterr().err
    assert slug in err, (
        f"Expected {slug!r} in stderr for result={result!r}; got: {err!r}"
    )


def test_enforce_warn_does_not_raise(capsys: pytest.CaptureFixture[str]) -> None:
    """warn policy MUST NOT raise MilpaError (exit 0 — detection not prevention)."""
    for result in [BundleMissing, BundleMalformed, SigInvalid, DigestMismatch, SignerMismatch, BundleStale]:
        _reset_warned_urls()
        enforce_index_trust(result, "warn", INDEX_URL)  # must not raise


def test_enforce_warn_dedup_one_warning_per_url(
    capsys: pytest.CaptureFixture[str]
) -> None:
    """warn: at most ONE warning per unique index_url per invocation (RFC §6.1)."""
    _reset_warned_urls()
    enforce_index_trust(BundleMissing, "warn", INDEX_URL)
    enforce_index_trust(SigInvalid, "warn", INDEX_URL)  # same URL → deduplicated
    err = capsys.readouterr().err
    # Only one TNG-INDEX-BUNDLE-MISSING warning; the second call (same URL) is suppressed.
    assert err.count("TNG-INDEX-") == 1


def test_enforce_warn_separate_urls_get_separate_warnings(
    capsys: pytest.CaptureFixture[str]
) -> None:
    """warn: different URLs each get their own warning (one per URL)."""
    _reset_warned_urls()
    url_a = "https://registry-a.test/index.kdl"
    url_b = "https://registry-b.test/index.kdl"
    enforce_index_trust(BundleMissing, "warn", url_a)
    enforce_index_trust(BundleMissing, "warn", url_b)
    err = capsys.readouterr().err
    assert "registry-a.test" in err
    assert "registry-b.test" in err


def test_enforce_warn_bundle_missing_includes_remediation_hint(
    capsys: pytest.CaptureFixture[str]
) -> None:
    """BundleMissing warn warning MUST include a remediation hint (RFC §7.4)."""
    _reset_warned_urls()
    enforce_index_trust(BundleMissing, "warn", INDEX_URL)
    err = capsys.readouterr().err
    # Hint mentions --refresh-index or milpa.kdl off escape hatch.
    assert "refresh-index" in err or "milpa.kdl" in err


# --- strict policy: raises MilpaError with the correct slug ---


@pytest.mark.parametrize("result,expected_slug", [
    (BundleMissing,   TNG_INDEX_BUNDLE_MISSING),
    (BundleMalformed, TNG_INDEX_BUNDLE_MALFORMED),
    (SigInvalid,      TNG_INDEX_SIGNATURE_INVALID),
    (DigestMismatch,  TNG_INDEX_DIGEST_MISMATCH),
    (SignerMismatch,  TNG_INDEX_SIGNER_MISMATCH),
    (BundleStale,     TNG_INDEX_BUNDLE_STALE),
])
def test_enforce_strict_raises_correct_slug(
    result: VerificationResult, expected_slug: str
) -> None:
    """strict: 6-way dispatch raises MilpaError with the correct TNG-INDEX-* slug."""
    with pytest.raises(MilpaError) as exc_info:
        enforce_index_trust(result, "strict", INDEX_URL)
    assert exc_info.value.slug == expected_slug


def test_enforce_strict_trusted_no_raise() -> None:
    """strict + Trusted → no raise (all 6 steps passed)."""
    enforce_index_trust(Trusted, "strict", INDEX_URL)  # must not raise


def test_enforce_strict_error_contains_index_url() -> None:
    """strict: raised MilpaError context includes the index URL."""
    with pytest.raises(MilpaError) as exc_info:
        enforce_index_trust(SigInvalid, "strict", INDEX_URL)
    assert INDEX_URL in exc_info.value.message or \
           INDEX_URL in str(exc_info.value.context)


# ---------------------------------------------------------------------------
# S5 integration test with _oracle/ bundle — skipped until oracle generated
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason=(
        "real _oracle bundle gen deferred — needs Fulcio/Rekor or sigstore-python "
        "test infrastructure; tracked for S7 (conformance fixture generation). "
        "RFC registry-trust-federation §12.2."
    )
)
def test_sigstore_verifier_against_oracle_bundle() -> None:
    """Real SigstoreVerifier against the committed _oracle/ test bundle.

    Per RFC §12.2: this integration test is gated at S5 when the full policy stack
    is wired.  Skipped until the test-bundle generation tooling is validated
    end-to-end.  Freshness is disabled via max_age_seconds=None so the committed
    bundle never goes stale.
    """
    from pathlib import Path
    oracle_dir = Path(__file__).parent.parent.parent.parent / "conformance" / "spec-v1" / "_oracle"
    bundle_path = oracle_dir / "test_index.kdl.bundle"
    index_path = oracle_dir / "test_index.kdl"

    if not bundle_path.exists() or not index_path.exists():
        pytest.skip("oracle bundle not yet generated")

    trust_bundle = TrustBundle.test(oracle_dir)
    index_bytes = index_path.read_bytes()
    bundle_bytes = bundle_path.read_bytes()

    verifier = SigstoreVerifier()
    result = verifier.verify(
        index_bytes=index_bytes,
        bundle_bytes=bundle_bytes,
        trust_bundle=trust_bundle,
        expected_signer="test-signer@example.com",  # replace with oracle signer
        max_age_seconds=None,  # skip freshness — committed bundle must not go stale
    )
    assert result is Trusted
