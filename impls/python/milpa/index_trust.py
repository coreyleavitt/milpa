"""Whole-index Sigstore bundle verifier — RFC: registry-trust-federation §11 S3.

Public surface:

  ``VerificationResult``
      7-variant sealed enum; module-level aliases (``Trusted``, ``SigInvalid``,
      ``DigestMismatch``, ``SignerMismatch``, ``BundleStale``, ``BundleMissing``,
      ``BundleMalformed``) are provided for ergonomic pattern-match style use.

  ``IndexBundleVerifier``
      ``typing.Protocol``: the injected verifier seam.  Production code passes
      ``SigstoreVerifier()``; test/conformance code passes ``MockVerifier(result)``.
      ``trust_bundle`` and ``expected_signer`` are ORTHOGONAL seams (RFC §10.1).

  ``verify_index_bundle(index_bytes, bundle_bytes, trust_bundle, expected_signer,
                        max_age_seconds)``
      Pure verification function — no I/O, never raises.  Implements RFC §4
      steps 1–6.  Cert validity is checked at Rekor SET ``integratedTime``, NOT
      wall-clock now (§4 step 2).  Freshness is skipped when
      ``max_age_seconds is None`` (pure cache reads, offline safety — §4 step 6).

  ``SigstoreVerifier``
      Production ``IndexBundleVerifier`` using ``sigstore-python``.  Not exercised
      in S3 tests; the integration test against the ``_oracle/`` bundle is gated
      at S5 (RFC §12.2).

  ``MockVerifier(result)``
      Test ``IndexBundleVerifier``: returns the caller-supplied ``VerificationResult``
      and ignores all inputs.  The seam the S7 conformance corpus drives via
      ``mock_verifier_result``.

  ``IndexTrustConfig``
      Frozen dataclass: policy + trust_bundle + expected_signer + max_age_seconds.
      DOES NOT contain a ``verifier`` field — verifier is an explicit parameter of
      the future ``load_index(url, config, verifier, http_get, bundle_http_get)``
      so tests cannot silently run against real Sigstore (RFC §7.2).

  ``TrustBundle``
      Frozen dataclass distinguishing PRODUCTION (embedded via ``importlib.resources``
      over ``milpa/_trust/``) from TEST (``conformance/spec-v1/_oracle/
      test_trust_bundle.json``).  Factory methods: ``.production()`` / ``.test()``.

Slice boundary:
  - ``enforce_index_trust`` (slug-raising 6-way dispatch) is S5: it co-commits
    with the 6 ``TNG-INDEX-*`` codes and the Rust DEFERRED bucket.
  - ``errors.py`` / ``spec/errors.md`` are NOT modified in S3.

RFC: docs/rfc-registry-trust-federation.md §4, §6.5, §10.1, §11 S3.
"""

from __future__ import annotations

import dataclasses
import enum
import importlib.resources
import json
import time
from pathlib import Path
from typing import Any, Protocol

import sys as _sys

from milpa.errors import (
    MilpaError,
    TNG_INDEX_BUNDLE_MALFORMED,
    TNG_INDEX_BUNDLE_MISSING,
    TNG_INDEX_BUNDLE_STALE,
    TNG_INDEX_DIGEST_MISMATCH,
    TNG_INDEX_SIGNATURE_INVALID,
    TNG_INDEX_SIGNER_MISMATCH,
)
from milpa.trust import TrustPolicy


# ---------------------------------------------------------------------------
# VerificationResult — 7-variant sealed enum  (RFC §6.5)
# ---------------------------------------------------------------------------


class VerificationResult(enum.Enum):
    """7-variant result type for whole-index Sigstore bundle verification.

    RFC §6.5 maps each non-``TRUSTED`` variant to a ``TNG-INDEX-*`` error slug.
    The slug-raising dispatch (``enforce_index_trust``) lives in S5, not here.

    Variants
    --------
    TRUSTED
        All six verification steps passed.  The index bytes are trustworthy.
    SIG_INVALID
        Cryptographic verification failed: bad Fulcio cert chain, cert was
        expired AT ``integratedTime``, or Rekor inclusion proof invalid.
        A cert now-expired but valid at ``integratedTime`` MUST NOT trigger
        this variant (RFC §4 step 2 — cert-at-SET-time requirement).
    DIGEST_MISMATCH
        The bundle's DSSE in-toto ``subject[0].digest.sha256`` ≠
        ``sha256(index_bytes)``.  Indicates tampering after attestation.
    SIGNER_MISMATCH
        The bundle cert's SubjectAltName ≠ ``expected_signer``.
    BUNDLE_STALE
        ``now − integratedTime ≥ max_age_seconds``.  Cryptographically valid
        but beyond the freshness window; indicates a rollback attack or a
        frozen CDN.  Only returned when ``max_age_seconds is not None``.
    BUNDLE_MISSING
        No bundle sidecar was available alongside the index.  This variant is
        constructed by ``load_index`` (S5) when the bundle fetch 404s;
        ``verify_index_bundle`` is NOT called in that case.  The variant lives
        here so ``enforce_index_trust``'s dispatch is total over all 7 cases.
    BUNDLE_MALFORMED
        The bundle JSON is unparseable or structurally invalid (pre-crypto
        failure, before any signature check is attempted).
    """

    TRUSTED = "trusted"
    SIG_INVALID = "sig-invalid"
    DIGEST_MISMATCH = "digest-mismatch"
    SIGNER_MISMATCH = "signer-mismatch"
    BUNDLE_STALE = "bundle-stale"
    BUNDLE_MISSING = "bundle-missing"
    BUNDLE_MALFORMED = "bundle-malformed"


# Module-level aliases — match RFC variant names; allow ``result is Trusted`` idiom.
Trusted = VerificationResult.TRUSTED
SigInvalid = VerificationResult.SIG_INVALID
DigestMismatch = VerificationResult.DIGEST_MISMATCH
SignerMismatch = VerificationResult.SIGNER_MISMATCH
BundleStale = VerificationResult.BUNDLE_STALE
BundleMissing = VerificationResult.BUNDLE_MISSING
BundleMalformed = VerificationResult.BUNDLE_MALFORMED


# ---------------------------------------------------------------------------
# TrustBundle — PRODUCTION vs TEST trust root  (RFC §3.1)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class TrustBundle:
    """Fulcio CA root + Rekor public key bundle for offline bundle verification.

    Never construct directly; use the factory methods so callsites document
    which trust root they are intentionally using:

      ``TrustBundle.production()``
          Loads ``milpa/_trust/trust_bundle.json`` via ``importlib.resources``
          (wheel-included package data).  PRODUCTION CODE ONLY.
          NOTE: the current file is a PLACEHOLDER; replace with the real
          Sigstore public-instance bundle before S5 wires production use.
          See RFC §3.1 and §12.3.

      ``TrustBundle.test(oracle_dir)``
          Loads ``conformance/spec-v1/_oracle/test_trust_bundle.json``.
          TEST CODE ONLY (``#[cfg(test)]`` rule: production MUST NEVER
          reference the test bundle).  Populated in S5 alongside the
          integration test (RFC §12.2).

    RFC §3.1: the trust bundle is NOT fetched at runtime; it is embedded at
    build time and rotated only via an explicit milpa version update.
    TUF-based root rotation is a future extension (RFC §12.3).
    """

    raw_json: bytes
    """Raw JSON bytes of the Fulcio CA + Rekor public key bundle."""

    label: str
    """Human-readable source tag: ``'production'`` or ``'test:<oracle_dir>'``."""

    @classmethod
    def production(cls) -> "TrustBundle":
        """Load the embedded production trust bundle from ``milpa/_trust/``."""
        pkg = importlib.resources.files("milpa._trust")
        raw = pkg.joinpath("trust_bundle.json").read_bytes()
        return cls(raw_json=raw, label="production")

    @classmethod
    def test(cls, oracle_dir: Path | None = None) -> "TrustBundle":
        """Load the test trust bundle from the conformance oracle directory.

        Parameters
        ----------
        oracle_dir:
            Directory containing ``test_trust_bundle.json``.  Defaults to
            ``conformance/spec-v1/_oracle/`` relative to the repo root.
            Created and populated in S5 alongside the integration test.
        """
        if oracle_dir is None:
            here = Path(__file__).parent
            oracle_dir = here.parent.parent.parent / "conformance" / "spec-v1" / "_oracle"
        bundle_path = oracle_dir / "test_trust_bundle.json"
        if bundle_path.exists():
            raw = bundle_path.read_bytes()
        else:
            # Placeholder until S5 generates the oracle bundle.
            raw = b'{"__placeholder__": true}'
        return cls(raw_json=raw, label=f"test:{oracle_dir}")


# ---------------------------------------------------------------------------
# IndexBundleVerifier — Protocol  (RFC §10.1)
# ---------------------------------------------------------------------------


class IndexBundleVerifier(Protocol):
    """Injected verifier seam for whole-index attestation.

    Production code passes ``SigstoreVerifier()`` as the explicit ``verifier``
    parameter to ``load_index``; test/conformance code passes
    ``MockVerifier(result)``.

    The two orthogonal seams (RFC §10.1, §3.2):
      ``trust_bundle``    — Fulcio CA + Rekor key bundle (trust ROOT seam).
                            Overridable via ``MILPA_INDEX_TRUST_BUNDLE`` / ``index-trust-bundle``.
      ``expected_signer`` — SubjectAltName identity (signer IDENTITY seam).
                            Overridable via ``MILPA_INDEX_TRUST_SIGNER`` / ``index-trust-signer``.
    Changing one does not imply the other.

    ``max_age_seconds`` is passed as ``config.max_age_seconds`` on network-fetch
    paths, and as ``None`` on pure cache reads so committed test bundles never
    go stale 7 days after commit.  ``MockVerifier`` ignores it.
    """

    def verify(
        self,
        index_bytes: bytes,
        bundle_bytes: bytes,
        trust_bundle: TrustBundle,
        expected_signer: str,
        max_age_seconds: int | None,
    ) -> VerificationResult:
        """Verify the Sigstore bundle against ``index_bytes``.

        Parameters
        ----------
        index_bytes:
            Raw bytes of ``index.kdl`` (single-read invariant: the same object
            must be passed to ``parse_index`` — no second disk read).
        bundle_bytes:
            Raw bytes of the ``.bundle`` sidecar (Sigstore bundle JSON).
        trust_bundle:
            Fulcio CA + Rekor public key bundle (trust ROOT).
        expected_signer:
            Expected SubjectAltName: the GitHub Actions OIDC workflow URL or
            its configured override.
        max_age_seconds:
            Freshness window in seconds.  Pass ``None`` on pure cache reads
            to skip the wall-clock bound (offline/air-gapped safety — RFC §4
            step 6, §7.2).
        """
        ...


# ---------------------------------------------------------------------------
# Pure verification function — RFC §4 steps 1–6; no I/O, never raises
# ---------------------------------------------------------------------------


def verify_index_bundle(
    index_bytes: bytes,
    bundle_bytes: bytes,
    trust_bundle: TrustBundle,
    expected_signer: str,
    max_age_seconds: int | None,
) -> VerificationResult:
    """Verify a Sigstore bundle against ``index_bytes``; return a ``VerificationResult``.

    Implements RFC §4 verification steps:

    **Step 1** — Parse bundle JSON.  Non-JSON or wrong type → ``BundleMalformed``
    (pre-crypto failure, distinct from a cryptographic failure).

    **Step 2** — Extract ``integratedTime`` from
    ``verificationMaterial.tlogEntries[0].integratedTime``.  Missing or
    non-integer → ``BundleMalformed``.  This is the time used for cert
    validity checking (step 4) — NOT wall-clock ``now``.

    **Step 3** — Freshness check: ONLY when ``max_age_seconds is not None``.
    If ``now − integratedTime ≥ max_age_seconds`` → ``BundleStale``.
    Passing ``None`` skips this bound entirely (pure cache reads; see RFC §7.2
    rationale: the rollback attack is a network-delivery attack; defending at
    the fetch boundary fully closes it without breaking offline use).

    **Steps 4–6** — Delegated to ``sigstore-python`` via ``_sigstore_verify``:
      4. Decode cert chain and validate against Fulcio root AT ``integratedTime``
         (not wall-clock).  Fulcio issues ~10-minute certs; checking
         ``cert.NotAfter >= now`` is ALWAYS wrong and MUST NOT be implemented.
      5. Assert SubjectAltName == ``expected_signer`` → ``SignerMismatch``.
      6. Verify DSSE envelope signature; extract ``statement.subject[0].digest.sha256``
         and assert it equals ``sha256(index_bytes)`` → ``DigestMismatch``.
      7. Verify Rekor inclusion proof / signed entry timestamp offline → ``SigInvalid``.

    **Single-read invariant** (RFC §4, §7.2): the ``index_bytes`` object passed
    here MUST be the same in-memory object passed to ``parse_index`` — no second
    disk read between verification and parsing.

    Never raises; returns a ``VerificationResult`` for every input.
    """
    # Step 1: Parse bundle JSON.
    try:
        bundle_data: dict[str, Any] = json.loads(bundle_bytes)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return BundleMalformed

    if not isinstance(bundle_data, dict):
        return BundleMalformed

    # Step 2: Extract integratedTime from the first Rekor tlog entry.
    # This timestamp is the anchor for cert-at-SET-time checking (RFC §4 step 2).
    try:
        tlog_entries: list[Any] = bundle_data["verificationMaterial"]["tlogEntries"]
        integrated_time = int(tlog_entries[0]["integratedTime"])
    except (KeyError, IndexError, TypeError, ValueError):
        return BundleMalformed

    # Step 3: Freshness check — ONLY on the network-fetch path.
    # Pure cache reads (States 1 and 3) pass max_age_seconds=None: the
    # wall-clock bound is NOT re-asserted so offline/air-gapped invocations
    # never fail on staleness (RFC §4 step 6, §7.2).
    if max_age_seconds is not None:
        now = int(time.time())
        if (now - integrated_time) >= max_age_seconds:
            return BundleStale

    # Steps 4–6: Cryptographic verification via sigstore-python.
    return _sigstore_verify(
        index_bytes=index_bytes,
        bundle_bytes=bundle_bytes,
        trust_bundle=trust_bundle,
        expected_signer=expected_signer,
        integrated_time=integrated_time,
    )


def _sigstore_verify(
    index_bytes: bytes,
    bundle_bytes: bytes,
    trust_bundle: TrustBundle,
    expected_signer: str,
    integrated_time: int,  # noqa: ARG001 — reserved for cert-at-SET-time API in S5
) -> VerificationResult:
    """RFC §4 steps 4–6: cryptographic verification via sigstore-python.

    Cert validity is checked at ``integrated_time`` (the Rekor SET ``integratedTime``)
    by sigstore-python when the bundle carries a Rekor inclusion proof, satisfying
    the cert-at-SET-time normative requirement (RFC §4 step 2).

    NOTE: custom trust-root support (``TrustBundle.raw_json`` → ``TrustRoot``) is
    wired in S5 once the oracle bundle and ``TrustRoot`` API path are validated
    end-to-end.  Until then, ``Verifier.production()`` is used for all bundles.
    The test bundle path is exercised only after S5 generates the oracle.
    """
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
    except ImportError:
        # sigstore-python not installed; treat as signature invalid.
        return SigInvalid

    # Parse the Sigstore bundle.
    try:
        bundle = Bundle.from_json(bundle_bytes.decode("utf-8"))
    except Exception:
        return BundleMalformed

    # Build the verifier.
    # S5 TODO: when trust_bundle.label != "production" or is not the placeholder,
    # construct a Verifier from trust_bundle.raw_json via TrustRoot / from_file.
    # Build the verifier with offline=True: no live Rekor/TUF network call at
    # verify time (RFC §5.2 — offline verification MUST work without live Rekor
    # access; the bundle carries an inclusion proof verifiable offline).
    # S5 TODO: when trust_bundle.label != "production" or is not the placeholder,
    # construct a Verifier from trust_bundle.raw_json via TrustedRoot.from_file.
    try:
        verifier = Verifier.production(offline=True)
    except Exception:
        return SigInvalid

    # Signer identity policy: SubjectAltName must match expected_signer.
    # Default issuer is the GitHub Actions OIDC endpoint; S5 wires the per-URL
    # signer override when index-trust-signer / MILPA_INDEX_TRUST_SIGNER is set.
    identity_policy = Identity(
        identity=expected_signer,
        issuer="https://token.actions.githubusercontent.com",
    )

    try:
        # sigstore 4.x uses input_ (trailing underscore) as the parameter name.
        verifier.verify_artifact(
            input_=index_bytes,
            bundle=bundle,
            policy=identity_policy,
        )
    except Exception as exc:
        return _map_sigstore_error(str(exc))

    return Trusted


def _map_sigstore_error(error_msg: str) -> VerificationResult:
    """Heuristic mapping of a sigstore VerificationError message to a VerificationResult.

    Best-effort for S5 integration path.  The exact token set depends on the
    sigstore-python version; calibrate against real oracle-bundle error messages
    in S5.
    """
    msg = error_msg.lower()
    # Signer identity / SubjectAltName mismatch
    if any(tok in msg for tok in ("identity", "subject alternative", "san", "issuer", "certificate identity")):
        return SignerMismatch
    # DSSE subject digest mismatch (sha256 of index_bytes)
    if any(tok in msg for tok in ("digest", "sha256", "hash mismatch", "subject hash")):
        return DigestMismatch
    # All other failures: bad cert chain, invalid inclusion proof, etc.
    return SigInvalid


# ---------------------------------------------------------------------------
# SigstoreVerifier — production IndexBundleVerifier  (RFC §11 S3)
# ---------------------------------------------------------------------------


class SigstoreVerifier:
    """Production verifier using sigstore-python.

    Delegates directly to ``verify_index_bundle``.  Not exercised in S3 tests;
    the integration test against the ``_oracle/`` bundle is gated at S5
    (RFC §12.2 — the test-bundle generation tooling is validated end-to-end
    only when the full policy stack is wired in S5).

    RFC §10.1: production code passes ``SigstoreVerifier()`` as the explicit
    ``verifier`` parameter to ``load_index``; it is NOT stored on
    ``IndexTrustConfig``.
    """

    def verify(
        self,
        index_bytes: bytes,
        bundle_bytes: bytes,
        trust_bundle: TrustBundle,
        expected_signer: str,
        max_age_seconds: int | None,
    ) -> VerificationResult:
        """Verify via sigstore-python; delegates to ``verify_index_bundle``."""
        return verify_index_bundle(
            index_bytes=index_bytes,
            bundle_bytes=bundle_bytes,
            trust_bundle=trust_bundle,
            expected_signer=expected_signer,
            max_age_seconds=max_age_seconds,
        )


# ---------------------------------------------------------------------------
# MockVerifier — test IndexBundleVerifier  (RFC §10.1)
# ---------------------------------------------------------------------------


class MockVerifier:
    """Test verifier returning a caller-supplied ``VerificationResult``.

    The seam the S7 conformance corpus drives via the ``mock_verifier_result``
    field in fixture ``env``.  Ignores all parameters; result is externally
    driven by the fixture scenario.

    RFC §10.1: the shared corpus tests the POLICY STATE MACHINE only (not
    cryptographic correctness); ``MockVerifier`` is the contract test point.
    Deterministic offline-verifiable Sigstore bundles cannot be generated
    without live Fulcio/Rekor infrastructure; the policy seam is tested
    independently from the crypto implementation.
    """

    def __init__(self, result: VerificationResult) -> None:
        """
        Parameters
        ----------
        result:
            The ``VerificationResult`` returned for every ``verify`` call,
            regardless of inputs.
        """
        self._result = result

    def verify(
        self,
        index_bytes: bytes,
        bundle_bytes: bytes,
        trust_bundle: TrustBundle,
        expected_signer: str,
        max_age_seconds: int | None,
    ) -> VerificationResult:
        """Return the pre-configured result; all parameters are ignored."""
        return self._result


# ---------------------------------------------------------------------------
# IndexTrustConfig — config bundle for load_index (verifier NOT a field)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class IndexTrustConfig:
    """Config bundle passed as one parameter to ``load_index`` (wired in S5).

    Bundles the policy + trust root + expected signer + freshness window into
    a single frozen dataclass so ``load_index`` avoids parameter explosion
    (RFC §7.2 revised signature).

    **Verifier is NOT a field.**  The ``verifier: IndexBundleVerifier`` is an
    EXPLICIT parameter of ``load_index(url, config, verifier, http_get,
    bundle_http_get)`` — separate from ``IndexTrustConfig``.  Reason: embedding
    a production default in config would cause tests that forget to inject a
    mock to silently run against real Sigstore.  Explicit parameter makes the
    seam impossible to miss (RFC §7.2, §10.1).

    Does NOT import ``context.py``: this dataclass lives at the verifier layer,
    below the resolver layer, and must not create a circular import.
    """

    policy: TrustPolicy
    """Effective trust policy: ``'warn'``, ``'strict'``, or ``'off'``."""

    trust_bundle: TrustBundle
    """Fulcio CA + Rekor public key bundle (trust ROOT seam; orthogonal to signer)."""

    expected_signer: str
    """Expected SubjectAltName identity (signer IDENTITY seam; orthogonal to trust root)."""

    max_age_seconds: int = 604800
    """Freshness window in seconds (default: 7 days = 604800 s).

    ``load_index`` passes this value on network-fetch paths and ``None`` on
    pure cache reads (States 1 and 3) to skip the wall-clock freshness bound.
    Overridable via ``MILPA_INDEX_MAX_AGE`` env var (wired in S5).
    """


# ---------------------------------------------------------------------------
# enforce_index_trust — 6-way result→slug dispatch  (RFC §11 S3 / S5)
# ---------------------------------------------------------------------------

# Dedup key per invocation: at most one index-trust warning per unique index URL
# (RFC §6.1 "Warning dedup key"). This module-level set is per-process (which is
# per-invocation for a CLI); tests reset it explicitly when needed.
_warned_urls: set[str] = set()


def _reset_warned_urls() -> None:
    """Clear the per-invocation warn dedup set.  TEST USE ONLY."""
    _warned_urls.clear()


def enforce_index_trust(
    result: VerificationResult,
    policy: TrustPolicy,
    index_url: str,
) -> None:
    """6-way ``VerificationResult`` → ``TNG-INDEX-*`` slug dispatch (RFC §6.5).

    Policy semantics (RFC §6.1):

    - ``off``     → silent; verifier was not called; no warning, no raise.
    - ``Trusted`` → silent; all six verification steps passed.
    - ``warn``    → emit ONE machine-readable warning to stderr per unique
                    ``index_url`` per invocation (dedup key = ``index_url``);
                    exit 0 (RFC "detection but not prevention").
    - ``strict``  → raise ``MilpaError`` with the appropriate ``TNG-INDEX-*`` slug.

    Parameters
    ----------
    result:
        The ``VerificationResult`` returned by the verifier (or constructed by
        ``load_index`` for the ``BundleMissing`` case when the bundle 404s).
    policy:
        The effective trust policy for this invocation (after running through
        ``effective_trust_policy``).
    index_url:
        The index URL that triggered this verification — used as the dedup key
        for warn warnings and included in error messages.

    Raises
    ------
    MilpaError
        Under ``strict`` policy for any non-``Trusted`` result.
    """
    if policy == "off" or result is Trusted:
        return

    # Map VerificationResult → (slug, human_hint)
    _slug_map: dict[VerificationResult, tuple[str, str]] = {
        BundleMissing: (
            TNG_INDEX_BUNDLE_MISSING,
            "no attestation bundle for the index. "
            "Run 'milpa fetch --refresh-index' to re-fetch with attestation, "
            "or set 'index-trust \"off\"' in milpa.kdl to suppress.",
        ),
        BundleMalformed: (
            TNG_INDEX_BUNDLE_MALFORMED,
            "the Sigstore bundle is not valid JSON or missing required fields.",
        ),
        SigInvalid: (
            TNG_INDEX_SIGNATURE_INVALID,
            "cryptographic verification of the index Sigstore bundle failed.",
        ),
        DigestMismatch: (
            TNG_INDEX_DIGEST_MISMATCH,
            "the bundle's attested subject digest does not match the index bytes "
            "(tampering or mismatched bundle/index pair).",
        ),
        SignerMismatch: (
            TNG_INDEX_SIGNER_MISMATCH,
            "the bundle signer identity does not match the expected signer. "
            "Set 'index-trust-signer' in milpa.kdl or MILPA_INDEX_TRUST_SIGNER "
            "to configure the expected SubjectAltName for a custom registry.",
        ),
        BundleStale: (
            TNG_INDEX_BUNDLE_STALE,
            "the index attestation bundle is beyond the maximum allowed age "
            "(rollback attack or frozen CDN). "
            "Run 'milpa fetch --refresh-index' to force a fresh fetch, "
            "or increase MILPA_INDEX_MAX_AGE.",
        ),
    }

    slug, hint = _slug_map[result]

    if policy == "strict":
        raise MilpaError(
            slug,
            f"index-trust strict: {slug} for index {index_url!r} — {hint}",
            index_url=index_url,
        )

    # policy == "warn": emit at most ONE warning per unique index_url per invocation.
    if index_url not in _warned_urls:
        _warned_urls.add(index_url)
        print(
            f"milpa: index-trust warning ({slug}): {hint} "
            f"(index: {index_url!r})",
            file=_sys.stderr,
        )
