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
    EntrySubject,
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
from milpa.epoch_commitment import Armed, ArmingInvalid, PreEpochIdentity, Unarmed, canonical_preimage
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


# ---------------------------------------------------------------------------
# S6 — real-crypto strict-PASS fixtures (RFC rfc-attestation-v1-normative.md S6)
# ---------------------------------------------------------------------------
#
# The committed fixtures (conformance/spec-v1/_oracle/entry-attestation/) are REAL
# Sigstore v0.3 DSSE bundles minted by the generate-entry-attestation-fixtures GitHub
# Actions workflow, signed with sigstore-python's ``sign_dsse`` — the SAME signer
# toolchain tianguis production uses to mint per-entry bundles (RFC S6 prerequisite
# (i), signer-toolchain parity; the Go-cosign-vs-Python-sign_dsse byte-serialization
# risk is the #183 class of bug this fixture generation deliberately avoids).
# Verifiable offline against the embedded production trust root, mirroring the
# Layer-1 S5(a) real-bundle precedent above but for the per-entry (Layer-2) verifier
# and the arming-commitment sidecar (D15) — a THIRD artifact type sharing the same
# signer-parity requirement (round-3 addition).
#
# This is the per-impl real-crypto tier (not the shared mock ``conformance/`` corpus):
# real crypto cannot be byte-identical-shared or mock-mapped across implementations,
# so these fixtures are loaded directly here, same as the Layer-1 precedent.

_ENTRY_FIXTURE_SIGNER = (
    "https://github.com/coreyleavitt/milpa/.github/workflows/"
    "generate-entry-attestation-fixtures.yaml@refs/heads/main"
)

_ENTRY_FIXTURE_NAMESPACE = "testns"
_ENTRY_FIXTURE_NAME = "attested-pkg"
_ENTRY_FIXTURE_VERSION = "1.0.0"
_ENTRY_FIXTURE_CONTENT_HASH = (
    "dag-sha256:9141345c8bfa2251a85bd540e15f365d2dbdf02abd76d8b37d0ea727f5955772"
)


def _entry_fixture_dir():
    from pathlib import Path

    return Path(__file__).parents[3] / "conformance" / "spec-v1" / "_oracle" / "entry-attestation"


def _entry_fixture_subject() -> EntrySubject:
    return build_entry_subject(
        _ENTRY_FIXTURE_NAMESPACE,
        _ENTRY_FIXTURE_NAME,
        _ENTRY_FIXTURE_VERSION,
        _ENTRY_FIXTURE_CONTENT_HASH,
    )


def test_s6_real_entry_bundle_verifies_trusted_end_to_end() -> None:
    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    v = SigstoreEntryVerifier()
    assert (
        v.verify(_entry_fixture_subject(), bundle_bytes, TrustBundle.production(), _ENTRY_FIXTURE_SIGNER)
        is Trusted
    ), "real per-entry bundle must verify Trusted against the embedded production trust root"


def test_s6_real_entry_bundle_wrong_signer_is_signer_mismatch() -> None:
    """S7 preview (explicitly allowed in S6's scope — needs no new artifact and
    confirms the signer binding on the real bundle)."""
    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    v = SigstoreEntryVerifier()
    assert (
        v.verify(
            _entry_fixture_subject(),
            bundle_bytes,
            TrustBundle.production(),
            "https://github.com/evil/repo/.github/workflows/x.yaml@refs/heads/main",
        )
        is SignerMismatch
    )


def test_s6_real_commitment_bundle_verifies_trusted() -> None:
    """The arming-commitment sidecar (D15) is a whole-index-shaped bundle over the
    canonical preimage of the committed pre-epoch set S — verified via the SAME
    ``verify_index_bundle`` Layer-1 uses (the commitment is structurally a
    Layer-1-shaped artifact), proving signer-toolchain parity extends to this third
    artifact type (RFC S6 round-3 addition)."""
    from milpa.index_trust import VerificationResult, verify_index_bundle

    bundle_bytes = (_entry_fixture_dir() / "commitment.bundle").read_bytes()
    identities = [
        PreEpochIdentity(
            namespace="testns",
            name="legacy-pkg",
            version="0.9.0",
            content_hash=(
                "dag-sha256:862bb412668033e2f5665980220f9da2df20a3bb651dfe31b3cdae23725e06e4"
            ),
        )
    ]
    preimage = canonical_preimage(identities)
    assert (
        verify_index_bundle(
            preimage,
            bundle_bytes,
            TrustBundle.production(),
            _ENTRY_FIXTURE_SIGNER,
            max_age_seconds=None,
        )
        == VerificationResult.TRUSTED
    ), "real commitment bundle must verify Trusted over the canonical preimage of S"


def test_s6_real_bundle_resolves_under_strict_via_gate(tmp_path) -> None:
    """Higher-level composition proof: a post-epoch entry carrying this real bundle
    passes the FULL gate (``evaluate_entry_attestation`` + ``enforce_entry_trust``)
    under strict policy without raising — the actual end-to-end path a resolve
    exercises, not just the verifier in isolation."""
    import hashlib

    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    pin = hashlib.sha256(bundle_bytes).hexdigest()
    (tmp_path / f"{pin}.bundle").write_bytes(bundle_bytes)
    store = FileEntryBundleStore(tmp_path)

    att = EntryAttestation(kind=AuthorSigned(signer=_ENTRY_FIXTURE_SIGNER), bundle_pin=pin)
    outcome = evaluate_entry_attestation(
        attestation=att,
        content_hash=_ENTRY_FIXTURE_CONTENT_HASH,
        namespace=_ENTRY_FIXTURE_NAMESPACE,
        name=_ENTRY_FIXTURE_NAME,
        version=_ENTRY_FIXTURE_VERSION,
        verifier=SigstoreEntryVerifier(),
        bundle_store=store,
        trust_bundle=TrustBundle.production(),
        expected_vendor_signer="unused-author-signed-uses-record-signer",
        epoch_status=Unarmed(),
    )
    assert outcome.result is Trusted

    # Must not raise under strict — a real post-epoch entry with a valid
    # author-signed bundle resolves cleanly (RFC S6).
    enforce_entry_trust(
        outcome,
        "strict",
        namespace=_ENTRY_FIXTURE_NAMESPACE,
        name=_ENTRY_FIXTURE_NAME,
        version=_ENTRY_FIXTURE_VERSION,
    )


# ---------------------------------------------------------------------------
# S7 — real-crypto strict-FAIL matrix (RFC rfc-attestation-v1-normative.md S7)
# ---------------------------------------------------------------------------
#
# Every row below DERIVES from the two S6-minted real bundles
# (entry-attested-pkg.bundle, commitment.bundle) — no new fixture is minted.
# Each test states, in its docstring, whether it is:
#   UNMODIFIED  — the real bundle bytes, verified against a deliberately
#                  WRONG expected value (signer / digest / name / pin).
#   TAMPERED    — the real bundle bytes, byte-corrupted (JSON truncation or
#                  a single inclusion-proof byte flip), never re-signed.
#   GATE-LEVEL  — no bundle bytes touched at all; the outcome comes from the
#                  gate's own stage-0/stage-1/epoch-membership logic.
#
# Vector 10 (index-trust strict with a missing/forged whole-index bundle)
# is NOT duplicated here — it is already fully covered by the Layer-1
# ``test_index_trust.py`` real-bundle + parametrized-enforce suite
# (``test_s5_real_bundle_wrong_signer_is_signer_mismatch``,
# ``test_s6_tampered_inclusion_proof_is_rejected``, and the
# ``enforce_index_trust`` strict-dispatch parametrization).


def _real_armed_status():
    """Build a REAL ``Armed`` status from the minted ``commitment.bundle`` fixture,
    via ``evaluate_epoch_commitment`` — S7's pre-epoch/post-epoch rows need the
    genuine composed-verified S-EpochCommitment (real Fulcio/Rekor crypto), not a
    synthetic ``Armed(...)`` construction (that synthetic matrix already exists in
    ``test_epoch_gate.py``). ``S`` = ``{testns/legacy-pkg@0.9.0}`` (the single
    identity the S6 commitment bundle commits to)."""
    from milpa.epoch_commitment import commitment_digest, evaluate_epoch_commitment
    from milpa.index_trust import SigstoreVerifier

    identities = (
        PreEpochIdentity(
            namespace="testns",
            name="legacy-pkg",
            version="0.9.0",
            content_hash=(
                "dag-sha256:862bb412668033e2f5665980220f9da2df20a3bb651dfe31b3cdae23725e06e4"
            ),
        ),
    )
    pointer = commitment_digest(identities)
    bundle_bytes = (_entry_fixture_dir() / "commitment.bundle").read_bytes()
    sidecar_bytes = json.dumps(
        {
            "identities": [
                {
                    "namespace": i.namespace,
                    "name": i.name,
                    "version": i.version,
                    "content_hash": i.content_hash,
                }
                for i in identities
            ],
            "bundle": json.loads(bundle_bytes),
        }
    ).encode("utf-8")
    status = evaluate_epoch_commitment(
        pointer=pointer,
        sidecar_bytes=sidecar_bytes,
        fetch_failed=False,
        verifier=SigstoreVerifier(),
        trust_bundle=TrustBundle.production(),
        expected_signer=_ENTRY_FIXTURE_SIGNER,
    )
    assert isinstance(status, Armed), f"commitment fixture must arm; got {status!r}"
    return status


def test_s7_post_epoch_unattested_fails_strict_real_armed() -> None:
    """S7 vector 1: post-epoch unattested => TNG-ENTRY-UNATTESTED under strict.

    GATE-LEVEL (no bundle at all). The epoch classification comes from a REAL
    ``Armed`` status (the minted ``commitment.bundle``) so PostEpoch is genuine
    here, not synthetic — this candidate's identity is not in S={legacy-pkg}.
    """
    status = _real_armed_status()
    outcome = evaluate_entry_attestation(
        attestation=None,
        content_hash=_ENTRY_FIXTURE_CONTENT_HASH,
        namespace=_ENTRY_FIXTURE_NAMESPACE,
        name=_ENTRY_FIXTURE_NAME,  # "attested-pkg" — NOT a member of S
        version=_ENTRY_FIXTURE_VERSION,
        verifier=SigstoreEntryVerifier(),
        bundle_store=None,
        trust_bundle=TrustBundle.production(),
        expected_vendor_signer="unused",
        epoch_status=status,
    )
    assert outcome.result is Unattested
    assert outcome.epoch_membership is PostEpoch

    with pytest.raises(MilpaError) as exc_info:
        enforce_entry_trust(
            outcome,
            "strict",
            namespace=_ENTRY_FIXTURE_NAMESPACE,
            name=_ENTRY_FIXTURE_NAME,
            version=_ENTRY_FIXTURE_VERSION,
        )
    assert exc_info.value.slug == TNG_ENTRY_UNATTESTED


def test_s7_wrong_signer_fails_strict_real_bundle(tmp_path) -> None:
    """S7 vector 2: wrong-signer => TNG-ENTRY-SIGNER-MISMATCH under strict.

    UNMODIFIED real bundle, composed through the FULL gate + enforce pipeline
    (not just the verifier-level check S6 already asserts) against a wrong
    ``AuthorSigned`` signer identity. Uses the REAL Armed status (PostEpoch
    for this candidate — it is not a member of S) rather than ``Unarmed()``:
    under D14/D11 an Unarmed registry is warn-equivalent for EVERY policy
    value, which would silently swallow the strict failure this row exists
    to prove."""
    import hashlib

    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    pin = hashlib.sha256(bundle_bytes).hexdigest()
    (tmp_path / f"{pin}.bundle").write_bytes(bundle_bytes)
    store = FileEntryBundleStore(tmp_path)

    att = EntryAttestation(
        kind=AuthorSigned(
            signer="https://github.com/evil/repo/.github/workflows/x.yaml@refs/heads/main"
        ),
        bundle_pin=pin,
    )
    status = _real_armed_status()
    outcome = evaluate_entry_attestation(
        attestation=att,
        content_hash=_ENTRY_FIXTURE_CONTENT_HASH,
        namespace=_ENTRY_FIXTURE_NAMESPACE,
        name=_ENTRY_FIXTURE_NAME,
        version=_ENTRY_FIXTURE_VERSION,
        verifier=SigstoreEntryVerifier(),
        bundle_store=store,
        trust_bundle=TrustBundle.production(),
        expected_vendor_signer="unused-author-signed-uses-record-signer",
        epoch_status=status,
    )
    assert outcome.result is SignerMismatch
    assert outcome.epoch_membership is PostEpoch

    with pytest.raises(MilpaError) as exc_info:
        enforce_entry_trust(
            outcome,
            "strict",
            namespace=_ENTRY_FIXTURE_NAMESPACE,
            name=_ENTRY_FIXTURE_NAME,
            version=_ENTRY_FIXTURE_VERSION,
        )
    assert exc_info.value.slug == TNG_ENTRY_SIGNER_MISMATCH


def test_s7_bundle_pin_mismatch_real_bundle_wrong_pin(tmp_path) -> None:
    """S7 vector 3: bundle-pin-mismatch => TNG-ENTRY-BUNDLE-PIN-MISMATCH.

    UNMODIFIED real bundle bytes, served under a pin that does NOT match
    their own sha256 (delivery-path tampering / stale mirror) — stage 1b, a
    security invariant raised unconditionally, never policy-gated."""
    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    wrong_pin = "0" * 64  # deliberately NOT sha256(bundle_bytes)
    (tmp_path / f"{wrong_pin}.bundle").write_bytes(bundle_bytes)
    store = FileEntryBundleStore(tmp_path)

    att = EntryAttestation(kind=AuthorSigned(signer=_ENTRY_FIXTURE_SIGNER), bundle_pin=wrong_pin)
    with pytest.raises(MilpaError) as exc_info:
        evaluate_entry_attestation(
            attestation=att,
            content_hash=_ENTRY_FIXTURE_CONTENT_HASH,
            namespace=_ENTRY_FIXTURE_NAMESPACE,
            name=_ENTRY_FIXTURE_NAME,
            version=_ENTRY_FIXTURE_VERSION,
            verifier=SigstoreEntryVerifier(),
            bundle_store=store,
            trust_bundle=TrustBundle.production(),
            expected_vendor_signer="unused",
            epoch_status=Unarmed(),
        )
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_PIN_MISMATCH


def test_s7_bundle_malformed_real_bundle_truncated() -> None:
    """S7 vector 4: bundle-malformed => TNG-ENTRY-BUNDLE-MALFORMED.

    TAMPERED: the real bundle truncated mid-JSON so it no longer parses."""
    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    tampered = bundle_bytes[: len(bundle_bytes) // 2]
    v = SigstoreEntryVerifier()
    assert (
        v.verify(_entry_fixture_subject(), tampered, TrustBundle.production(), _ENTRY_FIXTURE_SIGNER)
        is BundleMalformed
    )


def test_s7_digest_mismatch_real_bundle_wrong_expected_digest() -> None:
    """S7 vector 5: digest-mismatch => TNG-ENTRY-DIGEST-MISMATCH.

    UNMODIFIED real bundle, verified against a WRONG expected content_hash
    (correct package name)."""
    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    wrong_subject = build_entry_subject(
        _ENTRY_FIXTURE_NAMESPACE,
        _ENTRY_FIXTURE_NAME,
        _ENTRY_FIXTURE_VERSION,
        "dag-sha256:" + "f" * 64,
    )
    v = SigstoreEntryVerifier()
    assert (
        v.verify(wrong_subject, bundle_bytes, TrustBundle.production(), _ENTRY_FIXTURE_SIGNER)
        is DigestMismatch
    )


def test_s7_subject_mismatch_real_bundle_wrong_expected_name() -> None:
    """S7 vector 6: subject-mismatch => TNG-ENTRY-SUBJECT-MISMATCH.

    UNMODIFIED real bundle, verified against the RIGHT digest but a WRONG
    expected package coordinate (cross-package replay scenario)."""
    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    wrong_subject = build_entry_subject(
        "testns", "totally-different-pkg", "1.0.0", _ENTRY_FIXTURE_CONTENT_HASH
    )
    v = SigstoreEntryVerifier()
    assert (
        v.verify(wrong_subject, bundle_bytes, TrustBundle.production(), _ENTRY_FIXTURE_SIGNER)
        is SubjectMismatch
    )


def test_s7_signature_invalid_real_bundle_tampered_inclusion_proof() -> None:
    """S7 vector 7: signature-invalid => TNG-ENTRY-SIGNATURE-INVALID.

    TAMPERED: mirrors the Layer-1 precedent (test_index_trust.py's
    ``test_s6_tampered_inclusion_proof_is_rejected``) — corrupt ONLY the
    Rekor inclusion proof's ``rootHash`` byte, leaving the DSSE payload
    (subject digest + name) and signature bytes untouched. Subject binding
    (stages 3-4) still matches the real fixture subject, so the failure is
    isolated to the crypto/inclusion stage rather than conflated with a
    subject-binding failure."""
    bundle_bytes = (_entry_fixture_dir() / "entry-attested-pkg.bundle").read_bytes()
    data = json.loads(bundle_bytes)
    proof = data["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    root_hash = proof["rootHash"]
    proof["rootHash"] = ("a" if root_hash[0] != "a" else "b") + root_hash[1:]
    tampered = json.dumps(data).encode()

    v = SigstoreEntryVerifier()
    result = v.verify(
        _entry_fixture_subject(), tampered, TrustBundle.production(), _ENTRY_FIXTURE_SIGNER
    )
    assert result is SignatureInvalid, (
        f"tampered inclusion proof must reject as SignatureInvalid, got {result!r} — "
        "offline Rekor inclusion is not being enforced"
    )


def test_s7_bundle_unfetchable_fails_strict_d2(tmp_path) -> None:
    """S7 vector 8: bundle-unfetchable-under-strict => TNG-ENTRY-BUNDLE-MISSING
    (cause unfetchable), D2 fail-closed.

    GATE-LEVEL: the attestation record carries a pin, but the store cannot
    produce the bytes (empty local mirror). Uses the REAL Armed status
    (PostEpoch for this candidate) rather than ``Unarmed()`` — see the
    wrong-signer test above for why Unarmed would silently downgrade this
    to warn instead of exercising D2's fail-closed strict behavior."""
    att = EntryAttestation(kind=AuthorSigned(signer=_ENTRY_FIXTURE_SIGNER), bundle_pin="a" * 64)
    store = FileEntryBundleStore(tmp_path)  # empty dir: pin not present
    status = _real_armed_status()
    outcome = evaluate_entry_attestation(
        attestation=att,
        content_hash=_ENTRY_FIXTURE_CONTENT_HASH,
        namespace=_ENTRY_FIXTURE_NAMESPACE,
        name=_ENTRY_FIXTURE_NAME,
        version=_ENTRY_FIXTURE_VERSION,
        verifier=SigstoreEntryVerifier(),
        bundle_store=store,
        trust_bundle=TrustBundle.production(),
        expected_vendor_signer="unused",
        epoch_status=status,
    )
    assert outcome.result is BundleMissing
    assert outcome.cause == "unfetchable"
    assert outcome.epoch_membership is PostEpoch

    with pytest.raises(MilpaError) as exc_info:
        enforce_entry_trust(
            outcome,
            "strict",
            namespace=_ENTRY_FIXTURE_NAMESPACE,
            name=_ENTRY_FIXTURE_NAME,
            version=_ENTRY_FIXTURE_VERSION,
            bundle_store=store,
        )
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_MISSING


def test_s7_pre_epoch_legacy_unattested_warns_not_fails_real_commitment(capsys) -> None:
    """S7 vector 9: pre-epoch legacy unattested => WARN, not fail, under strict.

    GATE-LEVEL classification, but driven by a REAL ``Armed`` status from the
    minted ``commitment.bundle`` (D14/D15/D17) — the row S7 explicitly calls
    out as needing S-EpochCommitment's real crypto (a ``published_at`` field
    alone can no longer produce it under D-Watermark)."""
    status = _real_armed_status()
    outcome = evaluate_entry_attestation(
        attestation=None,
        content_hash=(
            "dag-sha256:862bb412668033e2f5665980220f9da2df20a3bb651dfe31b3cdae23725e06e4"
        ),
        namespace="testns",
        name="legacy-pkg",  # member of S
        version="0.9.0",
        verifier=SigstoreEntryVerifier(),
        bundle_store=None,
        trust_bundle=TrustBundle.production(),
        expected_vendor_signer="unused",
        epoch_status=status,
    )
    assert outcome.result is Unattested
    assert outcome.epoch_membership is PreEpoch

    # Must NOT raise under strict — capped to warn by effective_epoch_policy.
    enforce_entry_trust(outcome, "strict", namespace="testns", name="legacy-pkg", version="0.9.0")
    err = capsys.readouterr().err
    assert "entry-trust warning" in err
    assert "TNG-ENTRY-UNATTESTED" in err
    assert "grandfathered" in err


def test_s7_interregnum_membership_ignores_publication_timing() -> None:
    """S7 vector 11 (interregnum, F-op): a candidate not in the committed set S
    classifies PostEpoch (mandated) regardless of when it was "published" —
    there is no third interregnum bucket. Membership is decided PURELY by
    set-containment against the real, composed-verified S (D17); neither
    ``classify_epoch_membership`` nor ``evaluate_entry_attestation`` accepts a
    ``published_at`` parameter at all, which is the structural proof this
    can't silently reintroduce a timing-based carve-out for an entry
    published after the epoch's own ``integrated_time`` but never added to S.
    """
    status = _real_armed_status()
    assert isinstance(status, Armed)

    # A hypothetical identity "published" long after the epoch's own Rekor SET
    # integrated_time (status.integrated_time) but never added to S.
    late_identity = PreEpochIdentity(
        namespace="testns",
        name="brand-new-pkg",
        version="9.9.9",
        content_hash="dag-sha256:" + "e" * 64,
    )
    assert late_identity not in status.identities

    membership = classify_epoch_membership(status, late_identity)
    assert membership is PostEpoch, (
        "a non-member identity must classify PostEpoch regardless of when it was "
        "published — membership is set-only (D17), not a published_at comparison"
    )

    import inspect

    assert "published_at" not in inspect.signature(classify_epoch_membership).parameters
    assert "published_at" not in inspect.signature(evaluate_entry_attestation).parameters
