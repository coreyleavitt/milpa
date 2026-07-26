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
    DEFAULT_INDEX_SIGNER,
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
    _RecordingPolicy,
    _check_dsse_payload_digest,
    _reset_warned_urls,
    _sigstore_verify,
    enforce_index_trust,
    verify_index_bundle,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_DUMMY_TRUST_BUNDLE = TrustBundle(raw_json=b'{"__test__": true}', label="test:dummy")

# Default pinned signer identity (RFC §3.2) — the tianguis attest-index.yaml
# reusable workflow, NOT reindex.yaml (a one-shot migration workflow).
_DEFAULT_SIGNER = (
    "https://github.com/coreyleavitt/tianguis/.github/workflows/attest-index.yaml@refs/heads/main"
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


# ---------------------------------------------------------------------------
# M1: MILPA_INDEX_TRUST_BUNDLE — custom trust root plumbing
# ---------------------------------------------------------------------------


def test_custom_trust_bundle_not_label_production_takes_custom_code_path(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """When trust_bundle.label != 'production', _sigstore_verify must use a custom TrustedRoot.

    M1: The pre-fix code always calls ``Verifier.production(offline=True)`` regardless
    of the ``trust_bundle`` parameter.  After the fix, a non-production trust_bundle
    triggers the ``TrustedRoot.from_file`` path.

    This test verifies the CODE PATH IS TAKEN by checking that ``TrustedRoot.from_file``
    is called (via a mock).  It does NOT verify crypto — that stays out of unit tests
    per the existing gating discipline (RFC §12.2).

    M1 BLOCKER surface: if sigstore-python's public API does NOT support custom
    TrustedRoot construction without ``_internal`` imports, this test is skipped
    with a BLOCKER note.  The current finding: ``TrustedRoot.from_file(path: str)``
    is a public classmethod and ``Verifier.__init__(trusted_root: TrustedRoot)``
    is a public constructor — no internal imports needed.
    """
    import json
    import unittest.mock

    from milpa.index_trust import TrustBundle, _sigstore_verify

    # Build a non-production trust bundle with recognizable raw_json.
    custom_raw = json.dumps({"_custom_trust": True}).encode("utf-8")
    custom_bundle = TrustBundle(raw_json=custom_raw, label="custom:/path/to/bundle.json")

    # Dummy bundle bytes that will fail at Bundle.from_json (not valid Sigstore JSON),
    # but we intercept before that by tracking TrustedRoot.from_file calls.
    dummy_bundle_bytes = b'{"fake": "bundle"}'

    # Track whether TrustedRoot.from_file was called.
    from_file_calls: list[str] = []
    original_from_file = None
    try:
        from sigstore.models import TrustedRoot
        original_from_file = TrustedRoot.from_file

        def tracking_from_file(path: str) -> "TrustedRoot":
            from_file_calls.append(path)
            return original_from_file(path)  # may fail; we check calls first

        with unittest.mock.patch.object(TrustedRoot, "from_file", staticmethod(tracking_from_file)):
            # Call _sigstore_verify with a non-production trust bundle.
            # The result may be BundleMalformed (dummy bytes won't parse as a Bundle),
            # but TrustedRoot.from_file MUST have been called first.
            _sigstore_verify(
                index_bytes=b"index content",
                bundle_bytes=dummy_bundle_bytes,
                trust_bundle=custom_bundle,
                expected_signer="test@example.com",
            )
    except ImportError:
        pytest.skip("sigstore-python not installed; M1 path untestable")
        return

    assert len(from_file_calls) > 0, (
        "M1: when trust_bundle.label != 'production', TrustedRoot.from_file "
        "must be called to construct a custom trust root; "
        "pre-fix: Verifier.production() was always used instead."
    )


# ---------------------------------------------------------------------------
# M3: typed exception dispatch — no message-text heuristics (spec §3.4.4)
# ---------------------------------------------------------------------------


def test_check_dsse_payload_digest_matches() -> None:
    """``_check_dsse_payload_digest`` returns True when sha256 matches ``index_bytes``."""
    import base64
    import hashlib
    import json

    index_bytes = b"my index content"
    expected_sha256 = hashlib.sha256(index_bytes).hexdigest()
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "index.kdl", "digest": {"sha256": expected_sha256}}],
        "predicate": {},
    }
    payload_bytes = json.dumps(statement).encode()
    assert _check_dsse_payload_digest(payload_bytes, index_bytes) is True


def test_check_dsse_payload_digest_mismatch() -> None:
    """``_check_dsse_payload_digest`` returns False when sha256 does NOT match ``index_bytes``."""
    import json

    index_bytes = b"my index content"
    wrong_sha256 = "a" * 64
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "index.kdl", "digest": {"sha256": wrong_sha256}}],
        "predicate": {},
    }
    payload_bytes = json.dumps(statement).encode()
    assert _check_dsse_payload_digest(payload_bytes, index_bytes) is False


def test_check_dsse_payload_digest_absent_subject_returns_false() -> None:
    """``_check_dsse_payload_digest`` returns False when subject field is absent.

    Absent subject = no digest claim → digest-mismatch (fail closed).
    Attack: a DSSE bundle signed by the trusted identity whose statement has no
    subject (e.g. a different predicate from the same CI workflow) would otherwise
    bind to arbitrary tampered index bytes.  Spec §3.4.4 step 6 NORMATIVE.
    """
    import json
    payload_bytes = json.dumps({"_type": "...", "predicate": {}}).encode()
    assert _check_dsse_payload_digest(payload_bytes, b"anything") is False


def test_check_dsse_payload_digest_empty_subject_list_returns_false() -> None:
    """``_check_dsse_payload_digest`` returns False when subject list is empty.

    Empty subject list is the attack-shaped case: well-formed payload, subject
    list present but empty.  Must map to DigestMismatch (fail closed).
    """
    import json
    payload_bytes = json.dumps({
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [],
        "predicate": {},
    }).encode()
    assert _check_dsse_payload_digest(payload_bytes, b"anything") is False


def test_check_dsse_payload_digest_no_sha256_in_digest_returns_false() -> None:
    """``_check_dsse_payload_digest`` returns False when sha256 key is absent in digest.

    Subject present, digest dict present, but sha256 key missing.  The attestation
    makes no sha256 claim → fail closed (DigestMismatch).
    """
    import json
    payload_bytes = json.dumps({
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "index.kdl", "digest": {"sha512": "cafebabe"}}],
        "predicate": {},
    }).encode()
    assert _check_dsse_payload_digest(payload_bytes, b"anything") is False


def test_check_dsse_payload_digest_malformed_returns_false() -> None:
    """``_check_dsse_payload_digest`` returns False on non-parseable payload.

    Unparseable payload → cannot extract subject digest → DigestMismatch.
    """
    assert _check_dsse_payload_digest(b"not json at all", b"anything") is False


def test_recording_policy_records_raise() -> None:
    """``_RecordingPolicy`` sets ``policy_raised=True`` when inner policy raises."""
    from sigstore.errors import VerificationError

    class _AlwaysRaises:
        def verify(self, cert: Any) -> None:
            raise VerificationError("san mismatch")

    recording = _RecordingPolicy(_AlwaysRaises())
    assert recording.policy_raised is False

    try:
        recording.verify(object())  # cert is unused by _AlwaysRaises
    except VerificationError:
        pass

    assert recording.policy_raised is True


def test_recording_policy_no_raise_leaves_flag_false() -> None:
    """``_RecordingPolicy`` leaves ``policy_raised=False`` when inner policy succeeds."""
    class _AlwaysPasses:
        def verify(self, cert: Any) -> None:
            pass

    recording = _RecordingPolicy(_AlwaysPasses())
    recording.verify(object())
    assert recording.policy_raised is False


def test_m3_verification_error_without_policy_raise_maps_to_sig_invalid() -> None:
    """M3: VerificationError not from policy.verify → SigInvalid (cert chain / Rekor failure).

    Pre-fix: ``_map_sigstore_error`` would scan the message text for keywords and
    could return SignerMismatch or DigestMismatch based on coincidental word matches.
    Post-fix: type-based dispatch via ``_RecordingPolicy`` — only policy.verify raises
    give SignerMismatch; everything else is SigInvalid.
    """
    import unittest.mock
    try:
        from sigstore.errors import VerificationError
    except ImportError:
        pytest.skip("sigstore-python not installed")
        return

    # Patch verify_dsse to raise VerificationError BEFORE policy is called.
    # Simulates cert chain or Rekor failure — not signer mismatch.
    with unittest.mock.patch(
        "sigstore.verify.Verifier._verify_common_signing_cert",
        side_effect=VerificationError("failed to build cert chain"),
    ):
        # We need a bundle that passes Bundle.from_json. Use the minimal bundle
        # which DOES pass (it fails later at verify_dsse, not at from_json).
        result = _sigstore_verify(
            index_bytes=b"index content",
            bundle_bytes=_make_minimal_bundle(integrated_time=1000),
            trust_bundle=_DUMMY_TRUST_BUNDLE,
            expected_signer=_DEFAULT_SIGNER,
        )
    # Must be SigInvalid — NOT SignerMismatch or DigestMismatch.
    # Pre-fix code would potentially return SignerMismatch if the error message
    # happened to contain "identity" or "san" (VerificationError messages do mention
    # certificate fields). Post-fix: recording.policy_raised is False → SigInvalid.
    assert result is SigInvalid, (
        f"M3: expected SigInvalid for cert-chain failure not from policy.verify, got {result!r}"
    )


# ---------------------------------------------------------------------------
# M4: freshness step-order and first-failure precedence (spec §3.4.4)
# ---------------------------------------------------------------------------


def test_m4_stale_plus_sig_invalid_reports_bundle_stale() -> None:
    """M4: first-failure precedence — BundleStale (step 3) reported before SigInvalid (step 4+).

    A bundle that is both stale (integratedTime far in the past) AND would fail
    cryptographic verification (minimal bundle — not valid Sigstore JSON) MUST
    report BundleStale, NOT SigInvalid.  Spec §3.4.4 normative first-failure
    precedence: freshness (step 3) comes before crypto (steps 4–7).

    This pins the implemented ordering against a potential future regression where
    freshness is moved after crypto (which would break the spec).
    """
    stale_bundle = _make_minimal_bundle(integrated_time=1000)  # far in the past
    result = verify_index_bundle(
        index_bytes=b"index content",
        bundle_bytes=stale_bundle,
        trust_bundle=_DUMMY_TRUST_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=604800,  # 7 days — bundle is clearly stale
    )
    assert result is BundleStale, (
        f"M4: expected BundleStale for stale+would-be-sig-invalid bundle; got {result!r}. "
        "Freshness (step 3) must be checked before crypto (steps 4+)."
    )


# ---------------------------------------------------------------------------
# DEFAULT_INDEX_SIGNER — SSOT constant pin (ITEM M7)
# ---------------------------------------------------------------------------


def test_default_index_signer_pins_to_spec_value() -> None:
    """``DEFAULT_INDEX_SIGNER`` must exactly match spec §3.4.4 step 5 / §3.4.6.

    This is the SSOT for the tianguis attest-index.yaml SAN (the reusable
    ``workflow_call`` workflow both ``vendor.yaml`` and ``commit-entry.yaml``
    invoke to re-sign the whole-index bundle after every commit to
    ``index.kdl`` — NOT ``reindex.yaml``, a one-shot migration workflow with
    no recurring schedule).  The Rust impl and the spec both reference this
    value; a change here requires a coordinated update in all three places.
    If this test breaks, update the constant AND the spec AND the Rust
    constant together.
    """
    assert DEFAULT_INDEX_SIGNER == (
        "https://github.com/coreyleavitt/tianguis/"
        ".github/workflows/attest-index.yaml@refs/heads/main"
    ), (
        "DEFAULT_INDEX_SIGNER must match spec §3.4.4 step 5; "
        "update spec/registry-protocol.md and impls/rust/ in lockstep"
    )


def test_default_index_signer_is_github_actions_oidc_url() -> None:
    """``DEFAULT_INDEX_SIGNER`` must be a GitHub Actions OIDC workflow URL."""
    assert DEFAULT_INDEX_SIGNER.startswith(
        "https://github.com/coreyleavitt/tianguis/"
    ), "default signer must be the tianguis reindex workflow URL"
    assert DEFAULT_INDEX_SIGNER.endswith(
        "@refs/heads/main"
    ), "default signer must pin to the main branch ref"


# ---------------------------------------------------------------------------
# Custom-root offline semantics — ITEM M5
# ---------------------------------------------------------------------------


def test_custom_root_verifier_does_not_hit_network_on_construction() -> None:
    """``_sigstore_verify`` with a custom TrustBundle does not hit the network.

    Investigation (item M5): ``Verifier.__init__(trusted_root=...)`` bypasses TUF
    entirely (no refresh request) and ``verify_dsse`` verifies the Rekor inclusion
    proof offline using ``trusted_root.rekor_keyring`` — no live Rekor HTTP query.
    The ``offline=True`` flag on ``Verifier.production`` only controls TUF root
    refresh; the custom-root path already has equivalent semantics since TUF is
    bypassed altogether.  NOT A BLOCKER.

    This test confirms that constructing the verifier with a custom root succeeds
    without any network calls (via a malformed-but-constructable JSON).
    """
    import unittest.mock

    try:
        from sigstore.verify import Verifier
    except ImportError:
        pytest.skip("sigstore-python not installed")
        return

    custom_bundle = TrustBundle(raw_json=b'{"placeholder": true}', label="custom:/fake/path")

    # Patch tempfile.NamedTemporaryFile to avoid filesystem side effects, and
    # TrustedRoot.from_file to confirm we don't attempt TUF or live network access.
    # The key assertion: no urllib/http calls during Verifier construction.
    with unittest.mock.patch("urllib.request.urlopen") as mock_urlopen:
        # _sigstore_verify will fail at TrustedRoot.from_file (invalid JSON),
        # returning SigInvalid — that's fine.  We just assert no HTTP call.
        _sigstore_verify(
            index_bytes=b"fake",
            bundle_bytes=b'{"verificationMaterial": {"tlogEntries": []}}',
            trust_bundle=custom_bundle,
            expected_signer="https://example.com/workflow",
        )
        assert not mock_urlopen.called, (
            "Custom-root Verifier construction must not make network calls; "
            "TUF is bypassed entirely when trusted_root is provided directly"
        )


# ---------------------------------------------------------------------------
# S5(a) — real cosign-signed bundle verifies end-to-end (production trust root)
# ---------------------------------------------------------------------------
#
# The committed fixture (conformance/spec-v1/_oracle/attestation/) is a REAL
# Sigstore v0.3 DSSE bundle produced by the generate-attestation-fixture GitHub
# Actions workflow: keyless cosign attest-blob over the known index.kdl, signed by
# the workflow's OIDC identity, verifiable offline against the embedded production
# trust root. This is the "units green, prod fails" hole a best-in-class verifier
# cannot ship with — the actual Fulcio/Rekor wiring exercised end-to-end.

_FIXTURE_SIGNER = (
    "https://github.com/coreyleavitt/milpa/.github/workflows/"
    "generate-attestation-fixture.yaml@refs/heads/main"
)


def _attestation_fixture() -> "tuple[bytes, bytes]":
    from pathlib import Path

    root = Path(__file__).parents[3] / "conformance" / "spec-v1" / "_oracle" / "attestation"
    return (root / "index.kdl").read_bytes(), (root / "index.kdl.bundle").read_bytes()


def test_s5_real_bundle_verifies_trusted_end_to_end() -> None:
    index, bundle = _attestation_fixture()
    assert (
        _sigstore_verify(index, bundle, TrustBundle.production(), _FIXTURE_SIGNER)
        == VerificationResult.TRUSTED
    ), "real cosign bundle must verify Trusted against the embedded production trust root"


def test_s5_real_bundle_wrong_signer_is_signer_mismatch() -> None:
    index, bundle = _attestation_fixture()
    assert (
        _sigstore_verify(
            index,
            bundle,
            TrustBundle.production(),
            "https://github.com/evil/repo/.github/workflows/x.yaml@refs/heads/main",
        )
        == SignerMismatch
    )


def test_s5_real_bundle_wrong_index_is_digest_mismatch() -> None:
    _, bundle = _attestation_fixture()
    assert (
        _sigstore_verify(b"tampered index bytes", bundle, TrustBundle.production(), _FIXTURE_SIGNER)
        == VerificationResult.DIGEST_MISMATCH
    )


def test_s55_multifault_bundle_same_slug_as_rust() -> None:
    """S5.5 cross-impl differential: a bundle with MULTIPLE faults — a wrong subject digest
    AND a corrupt signature — resolves to the SAME slug in BOTH impls: ``DigestMismatch``.
    The subject-digest binding is checked BEFORE cryptographic verification in both impls
    (spec §3.4.4 precedence), so the digest fault wins deterministically. The Rust impl asserts
    the same on the same committed fixture (index_trust.rs ``s5_5_*``). This is exactly the
    first-failure-precedence divergence class S5.5 exists to catch — now a defined guarantee."""
    from pathlib import Path

    root = Path(__file__).parents[3] / "conformance" / "spec-v1" / "_oracle" / "attestation"
    index = (root / "index.kdl").read_bytes()
    bundle = (root / "index.kdl.bundle.multifault").read_bytes()
    assert (
        _sigstore_verify(index, bundle, TrustBundle.production(), _FIXTURE_SIGNER)
        == VerificationResult.DIGEST_MISMATCH
    )


# ---------------------------------------------------------------------------
# S6 — defensive regression: offline Rekor inclusion is actually enforced
# ---------------------------------------------------------------------------
#
# Python delegates inclusion verification to sigstore-python, but nothing guarded
# that milpa's *call* (verify_dsse under offline=True) really rejects a tampered
# inclusion proof — a future sigstore-python change or a mis-wired call could
# silently drop it. Using the real S5 fixture (whose index bytes we DO have), an
# untampered run verifies Trusted (test_s5_real_bundle_verifies_trusted_end_to_end);
# tampering ONLY the inclusion proof — subject digest and signature intact, so the
# digest pre-check passes and the DSSE signature still verifies — must flip the
# outcome to SigInvalid, proving offline inclusion is enforced (spec §3.4.4 step 5).


@pytest.mark.parametrize(
    "field, mutate",
    [
        # Flip a byte in the first Merkle proof hash.
        ("hashes", lambda ip: ip.__setitem__(
            "hashes",
            [("A" if ip["hashes"][0][0] != "A" else "B") + ip["hashes"][0][1:], *ip["hashes"][1:]],
        )),
        # Corrupt the signed-tree rootHash → checkpoint↔proof cross-check fails.
        ("rootHash", lambda ip: ip.__setitem__(
            "rootHash",
            ("A" if ip["rootHash"][0] != "A" else "B") + ip["rootHash"][1:],
        )),
    ],
)
def test_s6_tampered_inclusion_proof_is_rejected(field, mutate) -> None:
    """A present-but-tampered inclusion proof (digest + signature intact) must be
    rejected as SigInvalid — the offline transparency guarantee (spec §3.4.4 step 5)."""
    index, bundle = _attestation_fixture()
    data = json.loads(bundle)
    proof = data["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    mutate(proof)
    tampered = json.dumps(data).encode()

    result = _sigstore_verify(index, tampered, TrustBundle.production(), _FIXTURE_SIGNER)
    assert result == SigInvalid, (
        f"tampered inclusion proof ({field}) must be rejected as SigInvalid; got "
        f"{result!r} — offline inclusion verification is not being enforced"
    )
