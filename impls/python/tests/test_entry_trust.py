"""Unit tests for entry_trust.py (P3a, RFC per-entry-attestation.md §5, §6).

Covers:
  - build_entry_subject: RFC §1 coordinate format
  - evaluate_entry_attestation: gate stages 0, 1, 1b, and delegation to the
    verifier for stages 2-7 (via MockEntryVerifier)
  - enforce_entry_trust: warn (dedup) / strict / off dispatch
  - MockEntryVerifier: keyed per-subject scripting + default
  - SigstoreEntryVerifier: pre-crypto malformed / digest-mismatch / subject-mismatch
    (no real bundle needed — these paths never reach crypto)
"""

from __future__ import annotations

import base64
import json

import pytest

from milpa.entry_bundle_store import FileEntryBundleStore
from milpa.entry_trust import (
    BundleMalformed,
    BundleMissing,
    DigestMismatch,
    MockEntryVerifier,
    SignatureInvalid,
    SignerMismatch,
    SigstoreEntryVerifier,
    SubjectMismatch,
    Trusted,
    Unattested,
    build_entry_subject,
    enforce_entry_trust,
    evaluate_entry_attestation,
    _reset_warned_entries,
)
from milpa.errors import (
    TNG_ENTRY_BUNDLE_MALFORMED,
    TNG_ENTRY_BUNDLE_MISSING,
    TNG_ENTRY_BUNDLE_PIN_MISMATCH,
    TNG_ENTRY_DIGEST_MISMATCH,
    TNG_ENTRY_SIGNATURE_INVALID,
    TNG_ENTRY_SIGNER_MISMATCH,
    TNG_ENTRY_SUBJECT_MISMATCH,
    TNG_ENTRY_UNATTESTED,
    MilpaError,
)
from milpa.index_trust import TrustBundle
from milpa.registry import AuthorSigned, EntryAttestation, MilpaVendored


@pytest.fixture(autouse=True)
def _reset_dedup():
    _reset_warned_entries()
    yield
    _reset_warned_entries()


# ---------------------------------------------------------------------------
# build_entry_subject
# ---------------------------------------------------------------------------


def test_build_entry_subject_format() -> None:
    subj = build_entry_subject("ns1", "foo", "1.2.3", "sha256:" + "a" * 64)
    assert subj.name == "pkg:tianguis/ns1/foo@1.2.3"
    assert subj.sha256 == "a" * 64


# ---------------------------------------------------------------------------
# evaluate_entry_attestation — stage 0 (UNATTESTED)
# ---------------------------------------------------------------------------


def test_stage0_unattested_when_no_attestation() -> None:
    result, cause = evaluate_entry_attestation(
        attestation=None,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=None,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
    )
    assert result is Unattested
    assert cause is None


# ---------------------------------------------------------------------------
# evaluate_entry_attestation — stage 1 (BUNDLE_MISSING)
# ---------------------------------------------------------------------------


def test_stage1_bundle_missing_no_pin() -> None:
    att = EntryAttestation(kind=MilpaVendored(), bundle_pin=None)
    result, cause = evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=None,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
    )
    assert result is BundleMissing
    assert cause == "no-pin"


def test_stage1_bundle_missing_unfetchable(tmp_path) -> None:
    att = EntryAttestation(kind=MilpaVendored(), bundle_pin="b" * 64)
    store = FileEntryBundleStore(tmp_path)  # empty dir: pin not present
    result, cause = evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=store,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
    )
    assert result is BundleMissing
    assert cause == "unfetchable"


def test_stage1b_bundle_pin_mismatch_propagates_unconditionally(tmp_path) -> None:
    """Stage 1b is a security invariant — it raises through, never caught."""
    pin = "c" * 64
    (tmp_path / f"{pin}.bundle").write_bytes(b"wrong-bytes")
    att = EntryAttestation(kind=MilpaVendored(), bundle_pin=pin)
    store = FileEntryBundleStore(tmp_path)
    with pytest.raises(MilpaError) as exc_info:
        evaluate_entry_attestation(
            attestation=att,
            content_hash="sha256:" + "a" * 64,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=store,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="bot",
        )
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_PIN_MISMATCH


# ---------------------------------------------------------------------------
# evaluate_entry_attestation — stages 2-7 delegate to the verifier
# ---------------------------------------------------------------------------


def _bundle_dir_with_pin(tmp_path, bundle_bytes: bytes) -> tuple[FileEntryBundleStore, str]:
    import hashlib

    pin = hashlib.sha256(bundle_bytes).hexdigest()
    (tmp_path / f"{pin}.bundle").write_bytes(bundle_bytes)
    return FileEntryBundleStore(tmp_path), pin


def test_stages_2_to_7_delegate_to_verifier_keyed_by_subject(tmp_path) -> None:
    store, pin = _bundle_dir_with_pin(tmp_path, b"any-bytes-mock-does-not-inspect")
    att = EntryAttestation(kind=AuthorSigned(signer="alice"), bundle_pin=pin)
    subject_name = "pkg:tianguis/ns1/foo@1.0.0"
    verifier = MockEntryVerifier(default=Trusted, by_subject={subject_name: SignerMismatch})

    result, cause = evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=verifier,
        bundle_store=store,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
    )
    assert result is SignerMismatch
    assert cause is None


def test_author_signed_expected_signer_is_record_signer(tmp_path) -> None:
    """AuthorSigned kind: expected_signer passed to verify() is the record's own signer."""
    store, pin = _bundle_dir_with_pin(tmp_path, b"bytes")
    att = EntryAttestation(kind=AuthorSigned(signer="alice-signer"), bundle_pin=pin)

    captured: dict[str, str] = {}

    class _Capturing:
        def verify(self, expected_subject, bundle_bytes, trust_bundle, expected_signer):
            captured["expected_signer"] = expected_signer
            return Trusted

    evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=_Capturing(),
        bundle_store=store,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot-default",
    )
    assert captured["expected_signer"] == "alice-signer"


def test_vendored_expected_signer_is_the_resolved_layer1_identity(tmp_path) -> None:
    """MilpaVendored kind: expected_signer is the CALLER-supplied vendor signer,
    never a second hardcoded copy (RFC §5 NORMATIVE)."""
    store, pin = _bundle_dir_with_pin(tmp_path, b"bytes")
    att = EntryAttestation(kind=MilpaVendored(), bundle_pin=pin)

    captured: dict[str, str] = {}

    class _Capturing:
        def verify(self, expected_subject, bundle_bytes, trust_bundle, expected_signer):
            captured["expected_signer"] = expected_signer
            return Trusted

    evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=_Capturing(),
        bundle_store=store,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="the-resolved-vendor-bot-identity",
    )
    assert captured["expected_signer"] == "the-resolved-vendor-bot-identity"


# ---------------------------------------------------------------------------
# enforce_entry_trust — policy dispatch
# ---------------------------------------------------------------------------


def test_enforce_off_never_raises_or_warns(capsys) -> None:
    enforce_entry_trust(DigestMismatch, "off", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err == ""


def test_enforce_trusted_never_raises_or_warns(capsys) -> None:
    enforce_entry_trust(Trusted, "strict", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err == ""


def test_enforce_strict_raises_mapped_slug() -> None:
    with pytest.raises(MilpaError) as exc_info:
        enforce_entry_trust(SubjectMismatch, "strict", namespace="ns1", name="foo", version="1.0.0")
    assert exc_info.value.slug == TNG_ENTRY_SUBJECT_MISMATCH


@pytest.mark.parametrize(
    "result,slug",
    [
        (Unattested, TNG_ENTRY_UNATTESTED),
        (BundleMissing, TNG_ENTRY_BUNDLE_MISSING),
        (BundleMalformed, TNG_ENTRY_BUNDLE_MALFORMED),
        (DigestMismatch, TNG_ENTRY_DIGEST_MISMATCH),
        (SubjectMismatch, TNG_ENTRY_SUBJECT_MISMATCH),
        (SignatureInvalid, TNG_ENTRY_SIGNATURE_INVALID),
        (SignerMismatch, TNG_ENTRY_SIGNER_MISMATCH),
    ],
)
def test_enforce_strict_all_slugs(result, slug) -> None:
    with pytest.raises(MilpaError) as exc_info:
        enforce_entry_trust(result, "strict", namespace="ns1", name="foo", version="1.0.0")
    assert exc_info.value.slug == slug


def test_enforce_warn_emits_one_warning(capsys) -> None:
    enforce_entry_trust(DigestMismatch, "warn", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert "entry-trust warning" in captured.err
    assert "TNG-ENTRY-DIGEST-MISMATCH" in captured.err


def test_enforce_warn_dedups_per_coordinate(capsys) -> None:
    enforce_entry_trust(DigestMismatch, "warn", namespace="ns1", name="foo", version="1.0.0")
    enforce_entry_trust(DigestMismatch, "warn", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err.count("entry-trust warning") == 1


def test_enforce_warn_does_not_dedup_across_different_coordinates(capsys) -> None:
    enforce_entry_trust(DigestMismatch, "warn", namespace="ns1", name="foo", version="1.0.0")
    enforce_entry_trust(DigestMismatch, "warn", namespace="ns1", name="bar", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err.count("entry-trust warning") == 2


def test_enforce_warn_bundle_missing_includes_cause(capsys) -> None:
    enforce_entry_trust(
        BundleMissing, "warn", namespace="ns1", name="foo", version="1.0.0", cause="no-pin"
    )
    captured = capsys.readouterr()
    assert "no-pin" in captured.err


# ---------------------------------------------------------------------------
# MockEntryVerifier
# ---------------------------------------------------------------------------


def test_mock_verifier_defaults_when_subject_not_keyed() -> None:
    v = MockEntryVerifier(default=Trusted, by_subject={"pkg:tianguis/ns1/other@1.0.0": SignerMismatch})
    subj = build_entry_subject("ns1", "foo", "1.0.0", "sha256:" + "a" * 64)
    assert v.verify(subj, b"", TrustBundle.test(), "signer") is Trusted


def test_mock_verifier_uses_keyed_result() -> None:
    subj_name = "pkg:tianguis/ns1/foo@1.0.0"
    v = MockEntryVerifier(default=Trusted, by_subject={subj_name: BundleMalformed})
    subj = build_entry_subject("ns1", "foo", "1.0.0", "sha256:" + "a" * 64)
    assert v.verify(subj, b"", TrustBundle.test(), "signer") is BundleMalformed


# ---------------------------------------------------------------------------
# SigstoreEntryVerifier — pre-crypto paths only (no real bundle needed)
# ---------------------------------------------------------------------------


def test_sigstore_verifier_malformed_json() -> None:
    v = SigstoreEntryVerifier()
    subj = build_entry_subject("ns1", "foo", "1.0.0", "sha256:" + "a" * 64)
    assert v.verify(subj, b"not json", TrustBundle.test(), "signer") is BundleMalformed


def _fake_bundle(subject_name: str, subject_sha256: str) -> bytes:
    payload = {"subject": [{"name": subject_name, "digest": {"sha256": subject_sha256}}]}
    payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    return json.dumps({"dsseEnvelope": {"payload": payload_b64}}).encode()


def test_sigstore_verifier_digest_mismatch_precrypto() -> None:
    v = SigstoreEntryVerifier()
    subj = build_entry_subject("ns1", "foo", "1.0.0", "sha256:" + "a" * 64)
    bundle_bytes = _fake_bundle("pkg:tianguis/ns1/foo@1.0.0", "b" * 64)  # wrong digest
    assert v.verify(subj, bundle_bytes, TrustBundle.test(), "signer") is DigestMismatch


def test_sigstore_verifier_subject_mismatch_precrypto() -> None:
    v = SigstoreEntryVerifier()
    subj = build_entry_subject("ns1", "foo", "1.0.0", "sha256:" + "a" * 64)
    # Right digest, wrong package coordinate — cross-package replay scenario (RFC §1).
    bundle_bytes = _fake_bundle("pkg:tianguis/ns2/mallory-widget@1.0.0", "a" * 64)
    assert v.verify(subj, bundle_bytes, TrustBundle.test(), "signer") is SubjectMismatch
