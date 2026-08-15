"""Pins for the S2a slice of RFC ``docs/rfc-trusted-index-invariant.md``:
the ``GatedIndex`` construction invariant, Python side.

Three things this slice specifically claims and must be proven, not merely
assumed to fall out of the mechanical retrofit:

1. Both resolver entry points (``resolve()`` AND ``resolve_workspace()``)
   actively REJECT a bare ``Index`` on ``env.index`` — asserting only
   ``resolve()`` would leave the workspace path gated by convention (the C1
   defect the RFC names, relocated one layer down).
2. The epoch-commitment fold (§2.2) preserves the pre-fold
   ``trust_active``-conditional EXACTLY: under index-trust ``off``, the fold
   must never run — not even when an epoch pointer is present in the index
   and an epoch verifier is (mis-)supplied — so ``epoch_commitment_status``
   stays ``Unarmed`` (the dataclass default), untouched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.registry import Index

# ---------------------------------------------------------------------------
# 1. Negative tests: a bare Index on env.index must be rejected at BOTH
#    resolve() and resolve_workspace() entry points.
# ---------------------------------------------------------------------------


def _minimal_standalone_env(tmp_path: Path, bare_index: Index) -> object:
    from milpa.cas import CAStore
    from milpa.context import MilpaEnv
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.fetchers.mocked import mocked_registry

    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    # bare_index is intentionally a plain Index — NOT a GatedIndex — proving
    # the runtime assert rejects it rather than silently accepting a
    # duck-typed lookalike (RFC §2.5's "runtime assertion" enforcement tier).
    return MilpaEnv(fetcher=fetcher, index=bare_index, store=store)  # type: ignore[arg-type]


def test_resolve_rejects_bare_index_on_env(tmp_path: Path) -> None:
    """``resolve()`` must reject a bare ``Index`` on ``env.index`` with a
    clear ``TypeError`` — not silently accept it, and not an assert that
    ``python -O`` would strip (RFC §2.5)."""
    from milpa.context import ResolveParams
    from milpa.manifest import parse_manifest
    from milpa.resolver import resolve

    manifest = parse_manifest('name "root"\nkind "library"\n')
    env = _minimal_standalone_env(tmp_path, Index())
    deps_dir = tmp_path / "_deps"

    with pytest.raises(TypeError, match="GatedIndex"):
        resolve(manifest, deps_dir, env, ResolveParams())


def test_resolve_workspace_rejects_bare_index_on_env(tmp_path: Path) -> None:
    """``resolve_workspace()`` must ALSO reject a bare ``Index`` on
    ``env.index`` — asserting only ``resolve()`` would leave the workspace
    path gated by convention (RFC §2.5, the C1 defect relocated one layer
    down)."""
    from milpa.context import ResolveParams
    from milpa.resolver import resolve_workspace
    from milpa.workspace import load_workspace

    ws_root = tmp_path / "ws"
    member_dir = ws_root / "member-a"
    member_dir.mkdir(parents=True)
    (ws_root / "milpa.kdl").write_text(
        'workspace {\n    member "member-a"\n}\n', encoding="utf-8"
    )
    (member_dir / "milpa.kdl").write_text(
        'name "member-a"\nkind "library"\n', encoding="utf-8"
    )
    workspace = load_workspace(ws_root)

    env = _minimal_standalone_env(tmp_path, Index())
    deps_dir = ws_root / "_deps"

    with pytest.raises(TypeError, match="GatedIndex"):
        resolve_workspace(workspace, deps_dir, env, ResolveParams())


# ---------------------------------------------------------------------------
# 2. Epoch-commitment fold pin: index-trust "off" must leave the fold
#    un-run, even if an epoch pointer is present and an epoch verifier is
#    supplied (RFC §2.2 HIGH: no trust root exists to build one from under
#    off — this MUST be preserved verbatim, not just "usually true").
# ---------------------------------------------------------------------------


def test_epoch_fold_never_runs_under_index_trust_off(tmp_path: Path) -> None:
    from milpa.epoch_commitment import (
        PreEpochIdentity,
        Unarmed,
        commitment_digest,
    )
    from milpa.gated_index import GatedIndex
    from milpa.index_cache import load_index_gated
    from milpa.index_trust import MockVerifier, VerificationResult

    identities = [
        PreEpochIdentity(
            namespace="alice", name="leftpad", version="1.0.0",
            content_hash="dag-sha256:" + "a" * 64,
        )
    ]
    commitment = commitment_digest(identities)

    index_text = (
        "schema_version 1\n\n"
        f'attestation-epoch-commitment "{commitment}"\n\n'
        'package "bar" {\n'
        '    namespace "example"\n'
        '    version "1.0.0" {\n'
        '        content_hash "sha256:' + "0" * 64 + '"\n'
        "        provenance {\n"
        '            kind "git"\n'
        '            url "https://example.com/bar.git"\n'
        '            ref "v1.0.0"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )

    cache_dir = tmp_path / "index-cache"

    gated = load_index_gated(
        url="https://example.invalid/index.kdl",
        cache_dir=cache_dir,
        http_get=lambda url: index_text.encode("utf-8"),
        ttl_seconds=3600,
        now_unix=1_700_000_000,
        # index-trust OFF: config/verifier both None.
        config=None,
        verifier=None,
        # Mis-supplied on purpose: an epoch verifier IS given, to prove the
        # guard is trust_active (config/verifier), not "epoch_verifier is
        # None" — a caller that got this wrong must still fail safe.
        entry_trust_policy="strict",
        epoch_verifier=MockVerifier(VerificationResult.TRUSTED),
        epoch_expected_signer="rearm@example.com",
    )

    assert isinstance(gated, GatedIndex)
    assert isinstance(gated.index.epoch_commitment_status, Unarmed)
    # off ⇒ no VerificationResult was ever computed either (§2.3's off case).
    assert gated.verification is None
    assert not gated.is_cryptographically_trusted()


# ---------------------------------------------------------------------------
# 3. S2b: GatedIndex.acquire — the cache-free mint the rerouted
#    tests/test_conformance.py::_build_env now uses instead of the test-only
#    for_test bypass. Behavioral RED->GREEN: before the reroute, nothing in
#    the in-process adapter ever called this gate for real.
# ---------------------------------------------------------------------------

_ACQUIRE_INDEX_TEXT = (
    "schema_version 1\n\n"
    'package "bar" {\n'
    '    namespace "example"\n'
    '    version "1.0.0" {\n'
    '        content_hash "sha256:' + "0" * 64 + '"\n'
    "        provenance {\n"
    '            kind "git"\n'
    '            url "https://example.com/bar.git"\n'
    '            ref "v1.0.0"\n'
    "        }\n"
    "    }\n"
    "}\n"
)


def test_acquire_strict_no_bundle_raises_bundle_missing() -> None:
    """``acquire`` under ``strict`` with no bundle raises
    ``TNG-INDEX-BUNDLE-MISSING`` — the #199 regression this RFC exists to
    pin, now proven directly at the primitive (not just via the reroute)."""
    from milpa.epoch_commitment import Unarmed
    from milpa.errors import MilpaError
    from milpa.index_cache import acquire
    from milpa.index_trust import IndexTrustConfig, MockVerifier, TrustBundle, VerificationResult

    config = IndexTrustConfig(
        policy="strict",
        trust_bundle=TrustBundle.test(),
        expected_signer="fixture-signer",
    )
    verifier = MockVerifier(VerificationResult.TRUSTED)

    with pytest.raises(MilpaError) as exc_info:
        acquire(
            _ACQUIRE_INDEX_TEXT,
            None,
            config,
            verifier,
            "file:///fake/index.kdl",
            Unarmed(),
        )
    assert exc_info.value.slug == "TNG-INDEX-BUNDLE-MISSING"


def test_acquire_warn_no_bundle_mints_with_bundle_missing_verification() -> None:
    """``acquire`` under ``warn`` with no bundle does NOT raise — it mints a
    ``GatedIndex`` carrying the ``BundleMissing`` verification outcome
    (warned-and-continued, RFC §2.3's ``warn`` case)."""
    from milpa.epoch_commitment import Unarmed
    from milpa.gated_index import GatedIndex
    from milpa.index_cache import acquire
    from milpa.index_trust import (
        BundleMissing,
        IndexTrustConfig,
        MockVerifier,
        TrustBundle,
        VerificationResult,
    )

    config = IndexTrustConfig(
        policy="warn",
        trust_bundle=TrustBundle.test(),
        expected_signer="fixture-signer",
    )
    verifier = MockVerifier(VerificationResult.TRUSTED)

    gated = acquire(
        _ACQUIRE_INDEX_TEXT,
        None,
        config,
        verifier,
        "file:///fake/index.kdl",
        Unarmed(),
    )

    assert isinstance(gated, GatedIndex)
    assert gated.verification is BundleMissing
    assert not gated.is_cryptographically_trusted()


def test_acquire_off_mints_without_verification() -> None:
    """``acquire`` with ``config=None, verifier=None`` (effective policy
    ``off``) mints a ``GatedIndex`` with ``verification is None`` — the
    verifier is never invoked (RFC §2.3's ``off`` case)."""
    from milpa.epoch_commitment import Unarmed
    from milpa.gated_index import GatedIndex
    from milpa.index_cache import acquire

    gated = acquire(
        _ACQUIRE_INDEX_TEXT,
        None,
        None,
        None,
        "file:///fake/index.kdl",
        Unarmed(),
    )

    assert isinstance(gated, GatedIndex)
    assert gated.verification is None
    assert not gated.is_cryptographically_trusted()
