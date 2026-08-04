"""Unit tests for entry_trust.py (P3a, RFC per-entry-attestation.md §5, §6;
S-EpochGate, RFC attestation-v1-normative.md §6, D14/D17).

Covers:
  - build_entry_subject: RFC §1 coordinate format
  - evaluate_entry_attestation: gate stages 0, 1, 1b, and delegation to the
    verifier for stages 2-7 (via MockEntryVerifier); returns EntryGateOutcome (D9)
  - classify_epoch_membership / effective_epoch_policy: S-EpochGate membership
    classification + the warn-cap downgrade
  - enforce_entry_trust: warn (dedup) / strict / off dispatch, epoch-gated
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
    EntryGateOutcome,
    MockEntryVerifier,
    PostEpoch,
    PreEpoch,
    SignatureInvalid,
    SignerMismatch,
    SigstoreEntryVerifier,
    SubjectMismatch,
    Trusted,
    Unattested,
    build_entry_subject,
    classify_epoch_membership,
    effective_epoch_policy,
    enforce_entry_trust,
    evaluate_entry_attestation,
    _reset_warned_entries,
)
from milpa.epoch_commitment import Armed, ArmingInvalid, PreEpochIdentity, Unarmed
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


def _outcome(result, epoch_membership=PostEpoch, cause=None) -> EntryGateOutcome:
    """Test helper: build an ``EntryGateOutcome`` directly for
    ``enforce_entry_trust`` unit tests that don't need the full
    ``evaluate_entry_attestation`` pipeline.

    Defaults ``epoch_membership`` to ``PostEpoch`` — the configured policy
    applies unchanged (no S-EpochGate warn-cap in effect) — so the many
    pre-existing policy-dispatch tests in this file (which predate
    S-EpochGate and are about generic warn/strict/off behavior, not
    epoch-membership gating) keep exercising that behavior unperturbed. The
    dedicated S-EpochGate matrix below overrides this explicitly per row.
    """
    return EntryGateOutcome(result=result, epoch_membership=epoch_membership, cause=cause)


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


def test_build_entry_subject_rejects_missing_scheme_separator() -> None:
    # CR12/2: a content_hash with no ':' separator at all must surface a
    # clear ID-NO-ALGORITHM-PREFIX error, not silently build a subject with
    # an empty sha256 digest (which used to surface downstream as a
    # confusing TNG-ENTRY-DIGEST-MISMATCH instead).
    with pytest.raises(MilpaError) as exc_info:
        build_entry_subject("ns1", "foo", "1.2.3", "not-a-valid-identity")
    assert exc_info.value.slug == "ID-NO-ALGORITHM-PREFIX"


# ---------------------------------------------------------------------------
# evaluate_entry_attestation — stage 0 (UNATTESTED)
# ---------------------------------------------------------------------------


def test_stage0_unattested_when_no_attestation() -> None:
    outcome = evaluate_entry_attestation(
        attestation=None,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=None,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
        epoch_status=Unarmed(),
    )
    assert outcome.result is Unattested
    assert outcome.cause is None
    assert outcome.epoch_membership is None


# ---------------------------------------------------------------------------
# evaluate_entry_attestation — stage 1 (BUNDLE_MISSING)
# ---------------------------------------------------------------------------


def test_stage1_bundle_missing_no_pin() -> None:
    att = EntryAttestation(kind=MilpaVendored(), bundle_pin=None)
    outcome = evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=None,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
        epoch_status=Unarmed(),
    )
    assert outcome.result is BundleMissing
    assert outcome.cause == "no-pin"


def test_stage1_bundle_missing_unfetchable(tmp_path) -> None:
    att = EntryAttestation(kind=MilpaVendored(), bundle_pin="b" * 64)
    store = FileEntryBundleStore(tmp_path)  # empty dir: pin not present
    outcome = evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=store,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
        epoch_status=Unarmed(),
    )
    assert outcome.result is BundleMissing
    assert outcome.cause == "unfetchable"


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
            epoch_status=Unarmed(),
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

    outcome = evaluate_entry_attestation(
        attestation=att,
        content_hash="sha256:" + "a" * 64,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=verifier,
        bundle_store=store,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="bot",
        epoch_status=Unarmed(),
    )
    assert outcome.result is SignerMismatch
    assert outcome.cause is None


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
        epoch_status=Unarmed(),
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
        epoch_status=Unarmed(),
    )
    assert captured["expected_signer"] == "the-resolved-vendor-bot-identity"


# ---------------------------------------------------------------------------
# enforce_entry_trust — policy dispatch
# ---------------------------------------------------------------------------


def test_enforce_off_never_raises_or_warns(capsys) -> None:
    enforce_entry_trust(_outcome(DigestMismatch), "off", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err == ""


def test_enforce_trusted_never_raises_or_warns(capsys) -> None:
    enforce_entry_trust(_outcome(Trusted), "strict", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err == ""


def test_enforce_strict_raises_mapped_slug() -> None:
    with pytest.raises(MilpaError) as exc_info:
        enforce_entry_trust(
            _outcome(SubjectMismatch), "strict", namespace="ns1", name="foo", version="1.0.0"
        )
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
        enforce_entry_trust(_outcome(result), "strict", namespace="ns1", name="foo", version="1.0.0")
    assert exc_info.value.slug == slug


def test_enforce_warn_emits_one_warning(capsys) -> None:
    enforce_entry_trust(_outcome(DigestMismatch), "warn", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert "entry-trust warning" in captured.err
    assert "TNG-ENTRY-DIGEST-MISMATCH" in captured.err


def test_enforce_warn_dedups_per_coordinate(capsys) -> None:
    enforce_entry_trust(_outcome(DigestMismatch), "warn", namespace="ns1", name="foo", version="1.0.0")
    enforce_entry_trust(_outcome(DigestMismatch), "warn", namespace="ns1", name="foo", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err.count("entry-trust warning") == 1


def test_enforce_warn_does_not_dedup_across_different_coordinates(capsys) -> None:
    enforce_entry_trust(_outcome(DigestMismatch), "warn", namespace="ns1", name="foo", version="1.0.0")
    enforce_entry_trust(_outcome(DigestMismatch), "warn", namespace="ns1", name="bar", version="1.0.0")
    captured = capsys.readouterr()
    assert captured.err.count("entry-trust warning") == 2


def test_enforce_warn_bundle_missing_includes_cause(capsys) -> None:
    enforce_entry_trust(
        _outcome(BundleMissing, cause="no-pin"),
        "warn",
        namespace="ns1",
        name="foo",
        version="1.0.0",
    )
    captured = capsys.readouterr()
    assert "no-pin" in captured.err


# ---------------------------------------------------------------------------
# D6 remediation-hint audit (RFC attestation-v1-normative.md §6 S-Acq).
#
# Two changes under test:
#   1. Every "escape" hint that used to recommend the permanent kill-switch
#      'entry-trust "off"' now recommends the narrower 'entry-trust "warn"'
#      (preserves the audit trail strict exists to produce). This is a
#      DELIBERATE behavior change, not a regression — no prior test pinned
#      the old "off" text (grepped clean before this slice).
#   2. BundleMissing's hint now varies by (cause, bundle-store backend):
#      no-pin is backend-independent; unfetchable splits HTTP (transient,
#      "re-run fetch") vs File (operator-populated air-gapped mirror, NOT
#      transient) vs no-store-configured. '--refresh-index' is never
#      recommended — it bypasses the INDEX cache TTL only, a no-op for the
#      content-addressed bundle store.
# ---------------------------------------------------------------------------


def _hint_from_warning(capsys) -> str:
    return capsys.readouterr().err


def test_unattested_hint_recommends_warn_not_off(capsys) -> None:
    enforce_entry_trust(_outcome(Unattested), "warn", namespace="ns1", name="foo", version="1.0.0")
    err = _hint_from_warning(capsys)
    assert 'entry-trust "warn"' in err
    assert 'entry-trust "off"' not in err


def test_bundle_missing_no_pin_hint_recommends_warn_not_off(capsys) -> None:
    enforce_entry_trust(
        _outcome(BundleMissing, cause="no-pin"),
        "warn",
        namespace="ns1",
        name="foo",
        version="1.0.0",
    )
    err = _hint_from_warning(capsys)
    assert "has not published" in err
    assert 'entry-trust "warn"' in err
    assert 'entry-trust "off"' not in err
    assert "--refresh-index" not in err


def test_bundle_missing_unfetchable_http_backend_hint_is_transient(capsys) -> None:
    from milpa.entry_bundle_store import HttpEntryBundleStore

    store = HttpEntryBundleStore(base_url="https://example.com/registry/")
    enforce_entry_trust(
        _outcome(BundleMissing, cause="unfetchable"),
        "warn",
        namespace="ns1",
        name="foo",
        version="1.0.0",
        bundle_store=store,
    )
    err = _hint_from_warning(capsys)
    assert "re-run 'milpa fetch'" in err
    assert "--refresh-index" not in err
    assert 'entry-trust "off"' not in err


def test_bundle_missing_unfetchable_file_backend_hint_names_operator_mirror(
    capsys, tmp_path
) -> None:
    store = FileEntryBundleStore(tmp_path)
    enforce_entry_trust(
        _outcome(BundleMissing, cause="unfetchable"),
        "warn",
        namespace="ns1",
        name="foo",
        version="1.0.0",
        bundle_store=store,
    )
    err = _hint_from_warning(capsys)
    assert "MILPA_ENTRY_BUNDLE_DIR" in err
    assert "operator" in err
    # A genuinely-absent local mirror file is not transient: retrying
    # deterministically re-fails, so the hint must not suggest re-fetching.
    assert "re-run 'milpa fetch'" not in err
    assert 'entry-trust "off"' not in err


def test_bundle_missing_unfetchable_no_store_configured_hint(capsys) -> None:
    enforce_entry_trust(
        _outcome(BundleMissing, cause="unfetchable"),
        "warn",
        namespace="ns1",
        name="foo",
        version="1.0.0",
        bundle_store=None,
    )
    err = _hint_from_warning(capsys)
    assert "no attestation-bundle source is configured" in err
    assert 'entry-trust "off"' not in err


def test_hint_map_audit_no_static_hint_recommends_off():
    """Full ``_HINT_MAP`` audit (D6): none of the remaining static hints
    (``BundleMissing`` is dynamic, checked separately above) recommend the
    permanent kill-switch."""
    from milpa.entry_trust import _HINT_MAP

    for result, hint in _HINT_MAP.items():
        assert 'entry-trust "off"' not in hint, f"{result} hint still recommends off: {hint!r}"


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
