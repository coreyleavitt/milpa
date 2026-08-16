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
# 0. What the ``_witness`` runtime guard actually proves, stated precisely
#    (R5): it raises unconditionally on NAIVE direct construction — a bare
#    ``GatedIndex(...)`` or one "guessing" the sentinel with a lookalike
#    ``object()`` — independent of the ``tests/test_gated_index_containment.py``
#    grep, which only covers call sites physically located under ``milpa/``.
#    That is a real, useful guarantee (it's the failure mode a careless
#    contributor actually hits) but it is NOT structural unforgeability:
#    the two tests after it prove that a first-party caller who imports
#    ``_MINT_SENTINEL`` directly, or who calls ``dataclasses.replace()`` on
#    an already-valid ``GatedIndex``, forges one anyway. Python has no
#    access-control mechanism that closes those off; the grep + code review
#    are the real backstop for first-party call sites, same as they are for
#    every other "don't do this inside milpa/" convention in this codebase.
# ---------------------------------------------------------------------------


def test_direct_construction_raises_type_error() -> None:
    """Bypassing ``_mint``/``empty``/``for_test`` and constructing
    ``GatedIndex`` directly — exactly the forgery the RFC's containment
    story exists to prevent — must raise ``TypeError`` unconditionally,
    even though this call site is itself outside ``milpa/`` (so the
    containment grep does not and cannot cover it)."""
    from milpa.gated_index import GatedIndex

    with pytest.raises(TypeError, match="production trust gate"):
        GatedIndex(_index=Index(), _verification=None, _bundle_info=None)


def test_direct_construction_with_forged_witness_still_raises() -> None:
    """A caller cannot forge the mint witness by *guessing* it: a
    freshly-constructed lookalike ``object()`` is a different identity from
    the real ``_MINT_SENTINEL``, so it fails ``__post_init__``'s ``is``
    check. This is a narrower guarantee than "unforgeable" — see the two
    tests below, which document that the exact sentinel IS reachable by a
    first-party caller through two other paths. The three tests together
    are the honest, complete statement of what ``_witness`` does and does
    not stop."""
    from milpa.gated_index import GatedIndex

    with pytest.raises(TypeError, match="production trust gate"):
        GatedIndex(
            _index=Index(),
            _verification=None,
            _bundle_info=None,
            _witness=object(),  # a lookalike, not the real sentinel
        )


def test_mint_sentinel_is_directly_importable() -> None:
    """KNOWN ESCAPE HATCH (documented, not a regression introduced here):
    ``_MINT_SENTINEL`` has a single leading underscore, which excludes it
    from ``from milpa.gated_index import *`` only — Python has no access
    modifier that blocks an explicit ``from milpa.gated_index import
    _MINT_SENTINEL``. Once imported, it satisfies ``__post_init__``
    exactly like a real mint, so a first-party caller can forge an
    arbitrary ``GatedIndex`` — including one that claims
    ``is_cryptographically_trusted() is True`` for an unverified index.

    This is not reachable from outside first-party Python source with
    import access to ``milpa.gated_index`` (and anyone with that access has
    strictly cheaper ways to defeat the trust gate, e.g. editing
    ``index_cache.py``). It is caught by
    ``tests/test_gated_index_containment.py`` (a static grep for raw
    ``GatedIndex(`` construction outside the gate module) and code review,
    not by any runtime mechanism — see the module docstring's ``_mint``
    containment section."""
    from milpa.gated_index import _MINT_SENTINEL, GatedIndex
    from milpa.index_trust import VerificationResult

    forged = GatedIndex(
        _index=Index(),
        _verification=VerificationResult.TRUSTED,
        _bundle_info=None,
        _witness=_MINT_SENTINEL,
    )
    assert forged.is_cryptographically_trusted() is True


def test_dataclasses_replace_bypasses_witness_guard() -> None:
    """KNOWN ESCAPE HATCH (documented, not a regression introduced here):
    ``dataclasses.replace()`` on an already-held, validly-minted
    ``GatedIndex`` succeeds and lets the caller override ``_index`` /
    ``_verification`` / ``_bundle_info`` freely, forging a "trusted" result
    over attacker-controlled content.

    Mechanism: ``dataclasses.replace(obj, **changes)`` fills in every field
    NOT named in ``changes`` by reading it straight off ``obj`` — including
    ``_witness`` — then calls ``obj.__class__(**all_fields)``.
    ``__post_init__`` sees the source object's already-valid sentinel and
    does not raise. This is exactly as true on the interpreter this test
    suite runs under (Python 3.13+, where ``__replace__``/``copy.replace``
    exist) as on any earlier one: ``dataclasses.replace()`` does not
    consult ``__replace__`` at all (only ``copy.replace()`` does, and nothing
    in this codebase calls ``copy.replace()``), so defining ``__replace__``
    on ``GatedIndex`` would not close this path — see the ``__post_init__``
    comment in ``milpa/gated_index.py`` for why it isn't defined here.

    ``dataclasses.replace()`` is not an obscure API — it's the idiom this
    codebase already uses throughout (``resolver.py``, ``cli.py``,
    ``lockfile.py``) for non-destructively updating frozen dataclasses, so
    this is the bypass a careless first-party contributor is most likely to
    reach for by habit. As with the sentinel-import bypass above, the
    backstop is the containment grep + code review, not a runtime check —
    ``tests/test_gated_index_containment.py`` greps for raw ``GatedIndex(``
    construction, which is exactly what ``dataclasses.replace()`` performs
    internally, so a ``replace()`` call site under ``milpa/`` outside the
    gate module is caught the same way a bare constructor call would be."""
    import dataclasses

    from milpa.gated_index import GatedIndex
    from milpa.index_trust import VerificationResult

    valid = GatedIndex.empty()
    assert valid.is_cryptographically_trusted() is False

    forged = dataclasses.replace(
        valid,
        _index=Index(),
        _verification=VerificationResult.TRUSTED,
    )
    assert forged.is_cryptographically_trusted() is True


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
            "off",
            "off",
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
        "off",
        "off",
    )

    assert isinstance(gated, GatedIndex)
    assert gated.verification is BundleMissing
    assert not gated.is_cryptographically_trusted()


# ---------------------------------------------------------------------------
# 4. R2 (MEDIUM code-review finding): ``acquire`` used to STAMP an injected
#    ``EpochCommitmentStatus`` onto the minted index without ever running the
#    D14/D18 enforcement ``_fold_epoch_commitment`` runs on the
#    cache-integrated path — so an ``ArmingInvalid`` status minted a
#    trusted-looking ``GatedIndex`` and succeeded. ``acquire`` now delegates
#    to the SAME ``_mint_enforced`` choke point ``_fold_epoch_commitment``
#    uses, so both mint paths enforce identically. These pin the RED->GREEN
#    behavior directly at the primitive.
# ---------------------------------------------------------------------------


def test_acquire_arming_invalid_raises_even_under_index_trust_off() -> None:
    """``acquire`` under index-trust ``off`` (config/verifier both ``None``)
    must still raise on an ``ArmingInvalid`` epoch status — proves
    enforcement is NOT gated behind the bundle-verification branch; it runs
    unconditionally over the injected ``epoch_status``, mirroring
    ``_fold_epoch_commitment``'s own unconditional-once-invoked
    enforcement."""
    from milpa.epoch_commitment import ArmingInvalid
    from milpa.errors import MilpaError
    from milpa.index_cache import acquire

    with pytest.raises(MilpaError) as exc_info:
        acquire(
            _ACQUIRE_INDEX_TEXT,
            None,
            None,
            None,
            "file:///fake/index.kdl",
            ArmingInvalid(reason="test: tampered sidecar"),
            "off",
            "off",
        )
    assert exc_info.value.slug == "TNG-INDEX-EPOCH-COMMITMENT-INVALID"


def test_acquire_arming_invalid_raises_under_active_index_trust() -> None:
    """``acquire`` under active (``strict``, bundle-verifies) index-trust
    must ALSO raise on ``ArmingInvalid`` — proves epoch-commitment
    enforcement is a SEPARATE gate from index-trust, not accidentally
    satisfied by it: a bundle that verifies fine must still not paper over
    an ``ArmingInvalid`` epoch status."""
    from milpa.epoch_commitment import ArmingInvalid
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
            b'{"fake":"bundle"}',
            config,
            verifier,
            "file:///fake/index.kdl",
            ArmingInvalid(reason="test: hash(S) != C"),
            "strict",
            "strict",
        )
    assert exc_info.value.slug == "TNG-INDEX-EPOCH-COMMITMENT-INVALID"


def test_acquire_epoch_ratchet_required_raises() -> None:
    """D18: ``Armed`` + ``entry-trust=strict`` requires ``index-history=strict``
    — ``acquire`` must enforce this co-requirement too, not just D14."""
    from milpa.epoch_commitment import Armed
    from milpa.errors import MilpaError
    from milpa.index_cache import acquire

    status = Armed(identities=frozenset(), integrated_time=1_700_000_000)

    with pytest.raises(MilpaError) as exc_info:
        acquire(
            _ACQUIRE_INDEX_TEXT,
            None,
            None,
            None,
            "file:///fake/index.kdl",
            status,
            "strict",
            "warn",  # NOT strict — violates the D18 co-requirement
        )
    assert exc_info.value.slug == "TNG-INDEX-EPOCH-RATCHET-REQUIRED"


def test_acquire_unarmed_is_unaffected_off_case_preserved() -> None:
    """The ``off``-case conditionality (RFC §2.2 HIGH) is preserved by
    convention at the caller (an ``off`` caller only ever has an ``Unarmed``
    status to inject) — ``Unarmed`` must remain a silent success through the
    SAME unconditional enforcement call, proving no special-casing of
    ``off`` was added inside ``acquire``."""
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
        "off",
        "off",
    )

    assert isinstance(gated, GatedIndex)
    assert gated.index.epoch_commitment_status == Unarmed()


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
        "off",
        "off",
    )

    assert isinstance(gated, GatedIndex)
    assert gated.verification is None
    assert not gated.is_cryptographically_trusted()
