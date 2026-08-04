"""Tests for the S-EpochCommitment index-gate phase (epoch_commitment.py).

RFC: docs/rfc-attestation-v1-normative.md §6 S-EpochCommitment, D14-D18.
Spec: spec/registry-protocol.md §3.4.8/§3.4.9.
"""

from __future__ import annotations

import json

import pytest

from milpa.epoch_commitment import (
    Armed,
    ArmingInvalid,
    PreEpochIdentity,
    Unarmed,
    canonical_preimage,
    check_epoch_ratchet_requirement,
    commitment_digest,
    enforce_epoch_commitment,
    evaluate_epoch_commitment,
    parse_sidecar_payload,
    sorted_deduped,
)
from milpa.errors import (
    TNG_INDEX_EPOCH_COMMITMENT_INVALID,
    TNG_INDEX_EPOCH_RATCHET_REQUIRED,
    MilpaError,
)
from milpa.index_trust import MockVerifier, TrustBundle, VerificationResult

# ---------------------------------------------------------------------------
# Sub-slice 1: canonical identity + commitment digest
# ---------------------------------------------------------------------------


def _id(namespace: str, name: str, version: str, content_hash: str) -> PreEpochIdentity:
    return PreEpochIdentity(namespace=namespace, name=name, version=version, content_hash=content_hash)


def test_known_small_set_has_stable_digest() -> None:
    s = [
        _id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64),
        _id("alice", "rightpad", "2.0.0", "dag-sha256:" + "b" * 64),
    ]
    digest1 = commitment_digest(s)
    digest2 = commitment_digest(list(s))
    assert digest1 == digest2
    assert len(digest1) == 64
    assert all(c in "0123456789abcdef" for c in digest1)


def test_dedup_removes_exact_duplicates() -> None:
    one = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    dup = one + one
    assert commitment_digest(one) == commitment_digest(dup)


def test_reordering_input_yields_same_digest() -> None:
    a = _id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)
    b = _id("bob", "rightpad", "2.0.0", "dag-sha256:" + "b" * 64)
    assert commitment_digest([a, b]) == commitment_digest([b, a])


def test_different_identity_changes_digest() -> None:
    a = _id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)
    b = _id("alice", "leftpad", "1.0.1", "dag-sha256:" + "a" * 64)  # version differs
    assert commitment_digest([a]) != commitment_digest([b])


def test_parse_equal_versions_are_totally_ordered() -> None:
    # Two DISTINCT identities sharing (namespace, name, content_hash) whose
    # version strings parse to the SAME precedence but differ as raw strings
    # ("1.0.0" vs "1.0.0+build" — build metadata is precedence-invisible).
    # The canonical sort MUST be total over the full 4-tuple, so C is
    # byte-identical regardless of input order (D16 cross-impl determinism).
    # Regressions the non-total sort (precedence key + content_hash only,
    # which ties here and leaves order input-dependent under a stable sort).
    from milpa.epoch_commitment import _version_sort_key

    a = _id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)
    b = _id("alice", "leftpad", "1.0.0+build", "dag-sha256:" + "a" * 64)
    assert _version_sort_key(a.version) == _version_sort_key(b.version)  # the tie precondition
    assert a != b  # yet distinct identities
    assert commitment_digest([a, b]) == commitment_digest([b, a])


def test_namespace_matters_cross_namespace_collision() -> None:
    """D16 REJECTED attack: mallory/leftpad byte-copies alice/leftpad's
    (name, version, content_hash) — namespace MUST distinguish them."""
    alice = _id("alice", "leftpad", "1.0.0", "dag-sha256:" + "c" * 64)
    mallory = _id("mallory", "leftpad", "1.0.0", "dag-sha256:" + "c" * 64)
    assert alice != mallory
    assert commitment_digest([alice]) != commitment_digest([mallory])
    # And a set containing both is NOT the same as a set containing either alone.
    assert commitment_digest([alice, mallory]) != commitment_digest([alice])


def test_empty_set_has_a_digest() -> None:
    digest = commitment_digest([])
    assert len(digest) == 64
    assert digest == commitment_digest([])


def test_version_ordering_not_ad_hoc_string_sort() -> None:
    """"2.0.0" must sort AFTER "10.0.0" is wrong under string order but right
    under semver order — verifies canonical_preimage uses Version ordering,
    not lexical string ordering, for the sort key (though the digest itself
    doesn't leak sort order, the *sorted_deduped* helper does)."""
    v2 = _id("ns", "pkg", "2.0.0", "dag-sha256:" + "a" * 64)
    v10 = _id("ns", "pkg", "10.0.0", "dag-sha256:" + "a" * 64)
    ordered = sorted_deduped([v10, v2])
    assert ordered == (v2, v10)  # semver: 2.0.0 < 10.0.0


def test_unparseable_version_sorts_after_parseable() -> None:
    good = _id("ns", "pkg", "1.0.0", "dag-sha256:" + "a" * 64)
    bad = _id("ns", "pkg", "not-a-version", "dag-sha256:" + "a" * 64)
    ordered = sorted_deduped([bad, good])
    assert ordered == (good, bad)


def test_canonical_preimage_has_domain_prefix() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    assert canonical_preimage(s).startswith(b"milpa-preepoch-v1:")


def test_canonical_preimage_empty_set_is_prefix_only() -> None:
    assert canonical_preimage([]) == b"milpa-preepoch-v1:"


# ---------------------------------------------------------------------------
# Sub-slice 4: EpochCommitmentStatus + composed verification (mock seam)
# ---------------------------------------------------------------------------

_TRUST_BUNDLE = TrustBundle.test()
_SIGNER = "https://example.invalid/rearm-signer"


def _sidecar_bytes(identities: list[PreEpochIdentity], integrated_time: int = 1700000000) -> bytes:
    bundle = {
        "verificationMaterial": {
            "tlogEntries": [{"integratedTime": integrated_time, "logIndex": 42}],
        },
        "dsseEnvelope": {"payload": ""},
    }
    payload = {
        "identities": [
            {
                "namespace": i.namespace,
                "name": i.name,
                "version": i.version,
                "content_hash": i.content_hash,
            }
            for i in identities
        ],
        "bundle": bundle,
    }
    return json.dumps(payload).encode("utf-8")


def test_absent_pointer_is_unarmed() -> None:
    status = evaluate_epoch_commitment(
        pointer=None,
        sidecar_bytes=None,
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, Unarmed)


def test_armed_on_valid_commitment() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s, integrated_time=1712345678)
    status = evaluate_epoch_commitment(
        pointer=c,
        sidecar_bytes=sidecar,
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, Armed)
    assert status.identities == frozenset(s)
    assert status.integrated_time == 1712345678


def test_arming_invalid_on_unfetchable_sidecar() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    status = evaluate_epoch_commitment(
        pointer=c,
        sidecar_bytes=None,
        fetch_failed=True,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)


def test_arming_invalid_on_malformed_sidecar() -> None:
    status = evaluate_epoch_commitment(
        pointer="a" * 64,
        sidecar_bytes=b"not json",
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)


def test_arming_invalid_on_hash_mismatch() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    wrong_c = "0" * 64
    sidecar = _sidecar_bytes(s)
    status = evaluate_epoch_commitment(
        pointer=wrong_c,
        sidecar_bytes=sidecar,
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)
    assert "hash(S)" in status.reason


def test_arming_invalid_on_bad_inclusion() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s)
    status = evaluate_epoch_commitment(
        pointer=c,
        sidecar_bytes=sidecar,
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.SIG_INVALID),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)


def test_arming_invalid_on_bad_cert_dsse() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s)
    status = evaluate_epoch_commitment(
        pointer=c,
        sidecar_bytes=sidecar,
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.DIGEST_MISMATCH),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)


def test_arming_invalid_on_wrong_signer() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s)
    status = evaluate_epoch_commitment(
        pointer=c,
        sidecar_bytes=sidecar,
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.SIGNER_MISMATCH),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)


def test_arming_invalid_on_malformed_pointer_shape() -> None:
    status = evaluate_epoch_commitment(
        pointer="not-hex",
        sidecar_bytes=b"{}",
        fetch_failed=False,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)


def test_bad_rekor_proof_or_wrong_signer_must_not_verify() -> None:
    """Regression guard for the D15 forgery concern: a MockVerifier scripted
    to fail crypto must never produce Armed."""
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s)
    for bad_result in (
        VerificationResult.SIG_INVALID,
        VerificationResult.SIGNER_MISMATCH,
        VerificationResult.DIGEST_MISMATCH,
        VerificationResult.BUNDLE_MALFORMED,
    ):
        status = evaluate_epoch_commitment(
            pointer=c,
            sidecar_bytes=sidecar,
            fetch_failed=False,
            verifier=MockVerifier(bad_result),
            trust_bundle=_TRUST_BUNDLE,
            expected_signer=_SIGNER,
        )
        assert not isinstance(status, Armed), f"{bad_result} must not verify"


# ---------------------------------------------------------------------------
# parse_sidecar_payload — direct unit tests
# ---------------------------------------------------------------------------


def test_parse_sidecar_payload_roundtrip() -> None:
    s = [_id("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    raw = _sidecar_bytes(s)
    parsed = parse_sidecar_payload(raw)
    assert parsed is not None
    identities, bundle_bytes = parsed
    assert identities == tuple(s)
    assert json.loads(bundle_bytes)["verificationMaterial"]["tlogEntries"][0]["integratedTime"] == 1700000000


def test_parse_sidecar_payload_rejects_malformed() -> None:
    assert parse_sidecar_payload(b"not json") is None
    assert parse_sidecar_payload(b"[]") is None
    assert parse_sidecar_payload(json.dumps({"identities": "nope", "bundle": {}}).encode()) is None
    assert parse_sidecar_payload(json.dumps({"identities": [], "bundle": "nope"}).encode()) is None
    assert (
        parse_sidecar_payload(
            json.dumps({"identities": [{"namespace": "a"}], "bundle": {}}).encode()
        )
        is None
    )


# ---------------------------------------------------------------------------
# enforce_epoch_commitment — unconditional raise
# ---------------------------------------------------------------------------


def test_enforce_unarmed_is_silent() -> None:
    enforce_epoch_commitment(Unarmed())  # must not raise


def test_enforce_armed_is_silent() -> None:
    enforce_epoch_commitment(Armed(identities=frozenset(), integrated_time=1))  # must not raise


def test_enforce_arming_invalid_raises() -> None:
    with pytest.raises(MilpaError) as exc_info:
        enforce_epoch_commitment(ArmingInvalid(reason="hash(S) != C"))
    assert exc_info.value.slug == TNG_INDEX_EPOCH_COMMITMENT_INVALID


# ---------------------------------------------------------------------------
# Sub-slice 5: D18 co-requirement
# ---------------------------------------------------------------------------


def test_d18_armed_strict_entry_trust_warn_index_history_raises() -> None:
    status = Armed(identities=frozenset(), integrated_time=1)
    with pytest.raises(MilpaError) as exc_info:
        check_epoch_ratchet_requirement(
            status, entry_trust_policy="strict", index_history_policy="warn"
        )
    assert exc_info.value.slug == TNG_INDEX_EPOCH_RATCHET_REQUIRED


def test_d18_armed_all_strict_is_ok() -> None:
    status = Armed(identities=frozenset(), integrated_time=1)
    check_epoch_ratchet_requirement(
        status, entry_trust_policy="strict", index_history_policy="strict"
    )  # must not raise


def test_d18_unarmed_never_fires() -> None:
    check_epoch_ratchet_requirement(
        Unarmed(), entry_trust_policy="strict", index_history_policy="warn"
    )  # must not raise


def test_d18_armed_warn_entry_trust_never_fires() -> None:
    status = Armed(identities=frozenset(), integrated_time=1)
    check_epoch_ratchet_requirement(
        status, entry_trust_policy="warn", index_history_policy="warn"
    )  # must not raise
