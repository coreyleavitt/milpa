"""Tests for epoch-commitment sidecar acquisition (S-EpochCommitment
sub-slice 3: registry-protocol §3.4.9). Content-addressed by C, no TTL.
"""

from __future__ import annotations

import json
from pathlib import Path

from milpa.epoch_commitment import Armed, ArmingInvalid, PreEpochIdentity, Unarmed, commitment_digest
from milpa.index_cache import derive_commitment_url, load_epoch_commitment_status
from milpa.index_trust import MockVerifier, TrustBundle, VerificationResult

_TRUST_BUNDLE = TrustBundle.test()
_SIGNER = "https://example.invalid/rearm-signer"


def _sidecar_bytes(identities: list[PreEpochIdentity], integrated_time: int = 1700000000) -> bytes:
    bundle = {
        "verificationMaterial": {
            "tlogEntries": [{"integratedTime": integrated_time, "logIndex": 1}],
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


def test_derive_commitment_url_default_index() -> None:
    assert (
        derive_commitment_url(
            "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl"
        )
        == "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl.epoch-commitment"
    )


def test_derive_commitment_url_preserves_query_and_fragment() -> None:
    assert (
        derive_commitment_url("https://host/index.kdl?ref=main#frag")
        == "https://host/index.kdl.epoch-commitment?ref=main#frag"
    )


def test_absent_pointer_never_fetches(tmp_path: Path) -> None:
    calls: list[str] = []

    def http_get(url: str) -> bytes:
        calls.append(url)
        raise AssertionError("must not be called")

    status = load_epoch_commitment_status(
        index_url="https://example.test/index.kdl",
        pointer=None,
        cache_dir=tmp_path,
        http_get=http_get,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, Unarmed)
    assert calls == []


def test_fetch_once_then_cached(tmp_path: Path) -> None:
    s = [PreEpochIdentity("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s)
    calls: list[str] = []

    def http_get(url: str) -> bytes:
        calls.append(url)
        return sidecar

    kwargs = dict(
        index_url="https://example.test/index.kdl",
        pointer=c,
        cache_dir=tmp_path,
        http_get=http_get,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )

    status1 = load_epoch_commitment_status(**kwargs)
    assert isinstance(status1, Armed)
    assert len(calls) == 1

    # Second call: served from the content-addressed cache, no second fetch.
    status2 = load_epoch_commitment_status(**kwargs)
    assert isinstance(status2, Armed)
    assert len(calls) == 1  # unchanged


def test_cache_file_is_content_addressed_by_pointer(tmp_path: Path) -> None:
    s = [PreEpochIdentity("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s)

    load_epoch_commitment_status(
        index_url="https://example.test/index.kdl",
        pointer=c,
        cache_dir=tmp_path,
        http_get=lambda url: sidecar,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert (tmp_path / f"{c}.epoch-commitment").is_file()


def test_arming_invalid_not_persisted_to_cache(tmp_path: Path) -> None:
    """A sidecar that fails verification must NOT be cached — the next
    invocation should re-fetch, not remember the bad result forever."""
    s = [PreEpochIdentity("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    sidecar = _sidecar_bytes(s)
    calls: list[str] = []

    def http_get(url: str) -> bytes:
        calls.append(url)
        return sidecar

    kwargs = dict(
        index_url="https://example.test/index.kdl",
        pointer=c,
        cache_dir=tmp_path,
        http_get=http_get,
        verifier=MockVerifier(VerificationResult.SIG_INVALID),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )

    status1 = load_epoch_commitment_status(**kwargs)
    assert isinstance(status1, ArmingInvalid)
    assert not (tmp_path / f"{c}.epoch-commitment").is_file()

    status2 = load_epoch_commitment_status(**kwargs)
    assert isinstance(status2, ArmingInvalid)
    assert len(calls) == 2  # re-fetched, not cached


def test_fetch_failure_yields_arming_invalid_no_loop(tmp_path: Path) -> None:
    s = [PreEpochIdentity("alice", "leftpad", "1.0.0", "dag-sha256:" + "a" * 64)]
    c = commitment_digest(s)
    calls: list[str] = []

    def http_get(url: str) -> bytes:
        calls.append(url)
        raise RuntimeError("network down")

    status = load_epoch_commitment_status(
        index_url="https://example.test/index.kdl",
        pointer=c,
        cache_dir=tmp_path,
        http_get=http_get,
        verifier=MockVerifier(VerificationResult.TRUSTED),
        trust_bundle=_TRUST_BUNDLE,
        expected_signer=_SIGNER,
    )
    assert isinstance(status, ArmingInvalid)
    assert len(calls) == 1  # exactly one attempt, no retry loop
