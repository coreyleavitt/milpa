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
      Pure verification function — no I/O, never raises.  Implements spec
      §3.4.4 steps 1–7.  Cert validity is checked at Rekor SET ``integratedTime``,
      NOT wall-clock now (§3.4.4 step 4).  Freshness is checked at step 3
      (after integratedTime extraction, before crypto) and skipped when
      ``max_age_seconds is None`` (pure cache reads, offline safety — §3.4.4 step 3).

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
        this variant (spec §3.4.4 step 4 — cert-at-SET-time requirement).
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

# Initialise after aliases are bound (forward references resolved).
# Both maps are module-level singletons; _init_* functions are called once here.
# pylint: disable=wrong-import-position  # aliases must precede init calls

# ---------------------------------------------------------------------------
# DEFAULT_INDEX_SIGNER — single source of truth for the tianguis signer SAN
# ---------------------------------------------------------------------------

#: The pinned default signer SubjectAltName for the tianguis whole-index
#: attestation workflow. This is the SOLE canonical definition — spec
#: §3.4.4 step 5, §3.4.6. cli.py imports this constant; tests pin it to the
#: exact spec value. Never duplicate this string: changing it here
#: propagates everywhere.
#:
#: This is `attest-index.yaml`, a REUSABLE (`workflow_call`) tianguis
#: workflow — NOT `reindex.yaml` (a one-shot, workflow_dispatch-only
#: migration workflow that doesn't run on any recurring schedule). Every
#: commit to `index.kdl` (the daily `vendor.yaml` cron AND every author
#: publish via `commit-entry.yaml`) calls into `attest-index.yaml` to
#: re-sign the bundle; because it's a `workflow_call` reusable workflow (not
#: a composite action), GitHub's Actions OIDC token records
#: `job_workflow_ref` as THIS workflow's path regardless of which top-level
#: workflow invoked it — giving every whole-index bundle the SAME signer
#: identity no matter which process produced it. A composite action would
#: NOT have this property (the SAN would still vary by caller).
DEFAULT_INDEX_SIGNER = (
    "https://github.com/coreyleavitt/tianguis/.github/workflows/attest-index.yaml@refs/heads/main"
)


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
# Pure verification function — spec §3.4.4 steps 1–7; no I/O, never raises
# ---------------------------------------------------------------------------


def verify_index_bundle(
    index_bytes: bytes,
    bundle_bytes: bytes,
    trust_bundle: TrustBundle,
    expected_signer: str,
    max_age_seconds: int | None,
) -> VerificationResult:
    """Verify a Sigstore bundle against ``index_bytes``; return a ``VerificationResult``.

    Implements spec §3.4.4 verification steps:

    **Step 1** — Parse bundle JSON.  Non-JSON or wrong type → ``BundleMalformed``
    (pre-crypto failure, distinct from a cryptographic failure).

    **Step 2** — Extract ``integratedTime`` from
    ``verificationMaterial.tlogEntries[0].integratedTime``.  Missing or
    non-integer → ``BundleMalformed``.  This is the anchor for cert-at-SET-time
    checking (step 4) — NOT wall-clock ``now``.

    **Step 3** — Freshness check: ONLY when ``max_age_seconds is not None``.
    If ``now − integratedTime ≥ max_age_seconds`` → ``BundleStale``.
    Freshness is checked HERE (after integratedTime extraction, before any
    crypto) because it needs only the parsed timestamp; failing fast on staleness
    is fail-closed regardless of which crypto failures may also be present.
    Passing ``None`` skips this bound entirely (pure cache reads; see RFC §7.2
    rationale: the rollback attack is a network-delivery attack; defending at
    the fetch boundary fully closes it without breaking offline use).

    **Steps 4–7** — Delegated to ``sigstore-python`` via ``_sigstore_verify``:
      4. Decode cert chain and validate against Fulcio root AT ``integratedTime``
         (not wall-clock).  Fulcio issues ~10-minute certs; checking
         ``cert.NotAfter >= now`` is ALWAYS wrong and MUST NOT be implemented.
      5. Assert SubjectAltName == ``expected_signer`` → ``SignerMismatch``
         (detected via ``policy.verify`` call-site recording, NOT message text).
      6. Verify DSSE envelope signature; extract ``statement.subject[0].digest.sha256``
         from the returned payload and assert it equals ``sha256(index_bytes)``
         → ``DigestMismatch`` (detected post-verify from payload, NOT message text).
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
    # This timestamp is the anchor for cert-at-SET-time checking (spec §3.4.4 step 4).
    try:
        tlog_entries: list[Any] = bundle_data["verificationMaterial"]["tlogEntries"]
        integrated_time = int(tlog_entries[0]["integratedTime"])
    except (KeyError, IndexError, TypeError, ValueError):
        return BundleMalformed

    # Step 3: Freshness check — ONLY on the network-fetch path.
    # Placed here (after integratedTime extraction, before crypto) because it
    # needs only the parsed timestamp and failing fast on staleness is fail-closed
    # regardless of crypto failures — spec §3.4.4 step 3 normative ordering.
    # Pure cache reads (States 1 and 3) pass max_age_seconds=None: the
    # wall-clock bound is NOT re-asserted so offline/air-gapped invocations
    # never fail on staleness (spec §3.4.4 step 3, RFC §7.2).
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
    )


class _RecordingPolicy:
    """Wraps a VerificationPolicy and records whether ``verify()`` raised.

    Used by ``_sigstore_verify`` to distinguish ``SignerMismatch`` (policy raised)
    from ``SigInvalid`` (cert chain or Rekor failed before/after the policy call).

    Dispatch is by CALL-SITE, not by exception message text — spec §3.4.4
    normative failure-slug-mapping clause.  ``sigstore.errors.VerificationError``
    is the single exception type raised for ALL cryptographic failures; there are
    no distinct subclasses for signer mismatch vs cert-chain failure, so the only
    reliable signal is whether the failure originated inside ``policy.verify``.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.policy_raised: bool = False

    def verify(self, cert: Any) -> None:
        """Call inner policy; set ``policy_raised`` if it raises, then re-raise."""
        try:
            self._inner.verify(cert)
        except Exception:
            self.policy_raised = True
            raise


def _check_dsse_payload_digest(payload_bytes: bytes, index_bytes: bytes) -> bool:
    """Check that the in-toto payload's subject sha256 matches ``sha256(index_bytes)``.

    Called after a successful ``verify_dsse`` — the DSSE envelope signature is
    already verified, so ``payload_bytes`` is trusted bytes from the signed
    attestation.  Compares ``statement.subject[0].digest.sha256`` to
    ``sha256(index_bytes)`` (spec §3.4.4 step 6 — digest mismatch detection
    from the verified payload, NOT from exception message text).

    Returns ``True`` ONLY when the sha256 field is present AND matches
    ``sha256(index_bytes)`` — the definitive trust signal.

    Returns ``False`` (→ ``DigestMismatch``) in ALL other cases:
      - The payload is not parseable as JSON.
      - The subject list is absent or empty.
      - ``subject[0].digest.sha256`` is absent.
      - The sha256 field is present but does not match.

    Rationale: the subject digest is the SOLE binding between the attestation
    and the index bytes.  Absence of the subject or its digest means the
    attestation makes NO claim about the index content — any DSSE bundle signed
    by the trusted identity whose statement lacks a sha256 subject (e.g. a
    different predicate from the same CI workflow) would otherwise bind to
    arbitrary tampered index bytes.  Spec §3.4.4 step 6 NORMATIVE: a payload
    whose subject digest is absent or unextractable MUST produce
    TNG-INDEX-DIGEST-MISMATCH.
    """
    import hashlib
    try:
        payload_json = json.loads(payload_bytes)
        subjects = payload_json.get("subject", [])
        if not subjects:
            return False
        sha256_claim = subjects[0].get("digest", {}).get("sha256")
        if sha256_claim is None:
            return False
        expected = hashlib.sha256(index_bytes).hexdigest()
        return sha256_claim == expected
    except Exception:
        return False


def _sigstore_verify(
    index_bytes: bytes,
    bundle_bytes: bytes,
    trust_bundle: TrustBundle,
    expected_signer: str,
) -> VerificationResult:
    """Spec §3.4.4 steps 4–7: cryptographic verification via sigstore-python.

    Cert validity is checked at the Rekor SET ``integratedTime`` embedded in
    the bundle by sigstore-python, satisfying the cert-at-SET-time requirement
    (§3.4.4 step 4).  No ``integrated_time`` parameter is needed here — the
    library reads it from the bundle's tlog entry directly.

    Failure-to-variant mapping is TYPE-BASED, not message-text heuristic (spec
    §3.4.4 normative failure-slug-mapping clause):

    - ``VerificationError`` raised BEFORE ``policy.verify`` (cert chain / Rekor)
      → ``SigInvalid``.
    - ``VerificationError`` raised BY ``policy.verify`` (SAN mismatch)
      → ``SignerMismatch`` (detected via ``_RecordingPolicy`` call-site recording).
    - ``VerificationError`` raised AFTER ``policy.verify`` (sig or Rekor)
      → ``SigInvalid``.
    - Payload digest ≠ ``sha256(index_bytes)`` after successful ``verify_dsse``
      → ``DigestMismatch`` (detected from returned payload, not from exception text).

    Uses ``verify_dsse`` (not ``verify_artifact``) — the whole-index attestation
    bundle is a DSSE-enveloped in-toto statement, not a bare hashedrekord bundle.

    Offline semantics (RFC §5.2, item M5):
    - Production path: ``Verifier.production(offline=True)`` — no TUF refresh.
    - Custom-root path: ``Verifier(trusted_root=...)`` bypasses TUF entirely;
      the root is provided directly, so no network access occurs for TUF.
      Rekor inclusion proof verification in both paths is fully offline: the
      bundle carries the inclusion proof and ``_verify_common_signing_cert``
      verifies it against ``trusted_root.rekor_keyring`` without any live
      Rekor HTTP query.  The custom-root path is therefore already offline
      — there is no public API to add an extra offline flag because TUF is
      already bypassed.
    """
    try:
        from sigstore.errors import VerificationError
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
    except ImportError:
        # sigstore-python not installed; treat as signature invalid.
        return SigInvalid

    # Build the verifier FIRST (before parsing the bundle — construction is
    # independent of bundle content and must complete to test the TrustedRoot path).
    #
    # RFC §5.2: offline verification MUST work without live Rekor access;
    # the bundle carries an inclusion proof verifiable offline.
    #
    # M1 fix: when trust_bundle.label != "production", use a custom TrustedRoot
    # constructed from trust_bundle.raw_json via TrustedRoot.from_file (public API;
    # no _internal imports).  The production path uses Verifier.production(offline=True).
    try:
        if trust_bundle.label == "production":
            verifier = Verifier.production(offline=True)
        else:
            # Custom trust root: write raw_json to a temp file and load via
            # TrustedRoot.from_file (the public API; no _internal imports needed).
            import tempfile
            from sigstore.models import TrustedRoot
            with tempfile.NamedTemporaryFile(
                suffix=".json", delete=False, mode="wb"
            ) as tmp:
                tmp.write(trust_bundle.raw_json)
                tmp_path = tmp.name
            try:
                trusted_root = TrustedRoot.from_file(tmp_path)
                verifier = Verifier(trusted_root=trusted_root)
            finally:
                import os as _os
                _os.unlink(tmp_path)
    except Exception:
        return SigInvalid

    # Parse the Sigstore bundle.
    try:
        bundle = Bundle.from_json(bundle_bytes.decode("utf-8"))
    except Exception:
        return BundleMalformed

    # Step 6 (subject-digest binding) — PRE-CHECKED here, BEFORE cryptographic verification
    # (spec §3.4.4 NORMATIVE precedence). A bundle whose in-toto subject does not match
    # sha256(index_bytes) is attesting a DIFFERENT artifact, so it is rejected as
    # TNG-INDEX-DIGEST-MISMATCH deterministically — even when the signature is ALSO invalid.
    # This gives cross-impl slug parity with the Rust impl, whose crate collapses digest and
    # signature failures into one opaque error and therefore MUST pre-check (RFC §4).
    # Reading the UNVERIFIED payload is sound: we only ask "does this bundle even claim our
    # index?", we do not trust its contents. The post-verify digest check below remains as
    # belt-and-suspenders on the cryptographically-verified payload.
    import base64
    try:
        _pre_payload = base64.b64decode(json.loads(bundle_bytes)["dsseEnvelope"]["payload"])
    except Exception:
        return BundleMalformed
    if not _check_dsse_payload_digest(_pre_payload, index_bytes):
        return DigestMismatch

    # Signer identity policy: SubjectAltName must match expected_signer.
    # Default issuer is the GitHub Actions OIDC endpoint; S5 wires the per-URL
    # signer override when index-trust-signer / MILPA_INDEX_TRUST_SIGNER is set.
    inner_policy = Identity(
        identity=expected_signer,
        issuer="https://token.actions.githubusercontent.com",
    )
    # Wrap in a recording policy so we can distinguish SignerMismatch (policy
    # raised inside _verify_common_signing_cert) from SigInvalid (other failures
    # before or after the policy call) — spec §3.4.4 failure-slug-mapping clause.
    recording = _RecordingPolicy(inner_policy)

    # Steps 4-5, 7: cert chain + signer identity + Rekor via verify_dsse.
    # verify_dsse runs _verify_common_signing_cert (cert chain at integratedTime,
    # then policy.verify for SAN check) followed by DSSE envelope sig verification
    # and Rekor consistency.  Returns (payload_type, payload_bytes) on success.
    try:
        _, payload_bytes = verifier.verify_dsse(bundle=bundle, policy=recording)
    except VerificationError:
        if recording.policy_raised:
            return SignerMismatch
        return SigInvalid
    except Exception:
        return SigInvalid

    # Step 6: digest comparison from the verified in-toto payload.
    # The DSSE sig is already confirmed valid, so payload_bytes is trusted.
    # Compare statement.subject[0].digest.sha256 to sha256(index_bytes).
    if not _check_dsse_payload_digest(payload_bytes, index_bytes):
        return DigestMismatch

    return Trusted


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
# IndexBundleInfo + describe_index_bundle — pure JSON observability helper
# ---------------------------------------------------------------------------
#
# ``describe_index_bundle`` extracts observable CLAIMS from a Sigstore bundle's
# JSON without performing any cryptographic verification and without any network
# access.  It is the single source of truth for the ``milpa show --index-trust``
# output format; both the Python CLI and the Rust CLI call this logic, producing
# byte-identical output for the same bundle bytes.
#
# Fields extracted by pure JSON parsing:
#   ``integrated_time``   — ``verificationMaterial.tlogEntries[0].integratedTime``
#   ``rekor_log_index``   — ``verificationMaterial.tlogEntries[0].logIndex``
#   ``subject_sha256``    — ``_milpa_claims.subject_sha256`` (test/mock bundles)
#   ``signer_san``        — ``_milpa_claims.signer_san`` (test/mock bundles)
#   ``oidc_issuer``       — ``_milpa_claims.oidc_issuer`` (test/mock bundles)
#
# The ``_milpa_claims`` section is written into conformance fixture mock bundles so
# the describe helper can surface all five fields from pure JSON (no X.509 parsing).
# Real Sigstore bundles produced by ``cosign attest-blob`` do NOT contain
# ``_milpa_claims``; those fields are surfaced as ``(not available)`` in both impls
# until a dedicated X.509 extraction path is added in a future slice.


@dataclasses.dataclass(frozen=True)
class IndexBundleInfo:
    """Observable claims extracted from a Sigstore bundle — pure JSON, no crypto.

    RFC: ``docs/rfc-registry-trust-federation.md``.
    """

    integrated_time: int
    """Rekor SET ``integratedTime`` (unix epoch seconds).

    Extracted from ``verificationMaterial.tlogEntries[0].integratedTime``.
    Used to compute the freshness/staleness of the cached bundle.
    """

    rekor_log_index: str
    """Rekor transparency-log entry index.

    Extracted from ``verificationMaterial.tlogEntries[0].logIndex``.
    Identifies the specific Rekor tlog entry that anchors this attestation.
    """

    subject_sha256: str | None
    """SHA-256 digest of the attested subject (index.kdl bytes).

    Extracted from ``_milpa_claims.subject_sha256`` in test/mock bundles.
    ``None`` when the field is absent (production bundles pending a future slice).
    """

    signer_san: str | None
    """SubjectAltName from the signing certificate (signer IDENTITY).

    Extracted from ``_milpa_claims.signer_san`` in test/mock bundles.
    ``None`` when the field is absent (production bundles pending a future slice).
    """

    oidc_issuer: str | None
    """OIDC issuer from the signing certificate.

    Extracted from ``_milpa_claims.oidc_issuer`` in test/mock bundles.
    ``None`` when the field is absent (production bundles pending a future slice).
    """


def describe_index_bundle(bundle_bytes: bytes) -> "IndexBundleInfo | None":
    """Parse a Sigstore bundle JSON and extract observable claims.

    Pure JSON extraction — no cryptographic operations, no network access.
    Returns ``None`` if the bytes are not parseable as a JSON object or if the
    mandatory ``integratedTime`` field is absent/invalid (pre-crypto bundle parse
    failure; the same condition that ``verify_index_bundle`` maps to
    ``BundleMalformed``).

    The five fields and their JSON paths:

    * ``integrated_time`` — ``verificationMaterial.tlogEntries[0].integratedTime``
    * ``rekor_log_index`` — ``verificationMaterial.tlogEntries[0].logIndex``
    * ``subject_sha256``  — ``_milpa_claims.subject_sha256``
    * ``signer_san``      — ``_milpa_claims.signer_san``
    * ``oidc_issuer``     — ``_milpa_claims.oidc_issuer``

    Both Python and Rust impls use the SAME JSON paths so the output of
    ``format_index_trust_info`` is byte-identical across impls for any given
    bundle bytes.
    """
    try:
        data: dict[str, Any] = json.loads(bundle_bytes)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None

    # Extract integratedTime (mandatory — same logic as verify_index_bundle step 2/spec §3.4.4 step 2).
    # Proto3 JSON encodes int64 as a string; accept both string and native integer forms.
    try:
        raw_it = data["verificationMaterial"]["tlogEntries"][0]["integratedTime"]
        integrated_time = int(raw_it)
    except (KeyError, IndexError, TypeError, ValueError):
        return None

    # Extract logIndex (Rekor entry reference).
    try:
        raw_li = data["verificationMaterial"]["tlogEntries"][0]["logIndex"]
        rekor_log_index = str(int(raw_li))  # normalise to plain int string
    except (KeyError, IndexError, TypeError, ValueError):
        rekor_log_index = "(not available)"

    # Extract signer/issuer/subject from _milpa_claims (test/mock section).
    # Real Sigstore bundles do not carry this section; those fields surface as None.
    claims = data.get("_milpa_claims")
    if not isinstance(claims, dict):
        claims = {}
    subject_sha256: str | None = claims.get("subject_sha256")
    signer_san: str | None = claims.get("signer_san")
    oidc_issuer: str | None = claims.get("oidc_issuer")

    return IndexBundleInfo(
        integrated_time=integrated_time,
        rekor_log_index=rekor_log_index,
        subject_sha256=subject_sha256,
        signer_san=signer_san,
        oidc_issuer=oidc_issuer,
    )


def format_index_trust_info(
    *,
    index_url: str,
    policy: str,
    index_cached: bool,
    bundle_cached: bool,
    info: "IndexBundleInfo | None",
    now: int,
    max_age: int = 604800,
) -> str:
    """Format the ``milpa show --index-trust`` observability output.

    Produces a fixed-width label block where every label (including the colon)
    is exactly 16 characters so values align in a column.  This exact layout is
    byte-identical between the Python and Rust impls — see the Rust counterpart
    ``milpa_core::index_trust::format_index_trust_info``.

    Parameters
    ----------
    index_url:
        The index URL being described (from ``MILPA_INDEX_URL`` or the default).
    policy:
        The effective index-trust policy (``warn`` / ``strict`` / ``off``).
    index_cached:
        Whether the index file is present in the local cache.
    bundle_cached:
        Whether the Sigstore bundle sidecar is present in the local cache.
    info:
        The parsed claims from the cached bundle, or ``None`` when no bundle is
        cached or the bundle is not parseable.
    now:
        Current time as unix epoch seconds.  Injected for test determinism.
    max_age:
        Bundle freshness window in seconds (default: 7 days = 604800 s).

    Returns
    -------
    str
        The formatted output string with a trailing newline.  All fields use
        POSIX ``\\n`` line endings.
    """
    lines: list[str] = []
    lines.append(f"index-url:      {index_url}")
    lines.append(f"policy:         {policy}")
    lines.append(f"index-cached:   {'yes' if index_cached else 'no'}")
    lines.append(f"bundle-cached:  {'yes' if bundle_cached else 'no'}")

    if info is not None:
        lines.append(f"signer:         {info.signer_san or '(not available)'}")
        lines.append(f"issuer:         {info.oidc_issuer or '(not available)'}")
        lines.append(f"integrated:     {info.integrated_time}")
        lines.append(f"subject-sha256: {info.subject_sha256 or '(not available)'}")
        lines.append(f"rekor-entry:    {info.rekor_log_index}")
        age = now - info.integrated_time
        freshness = "fresh" if age < max_age else "stale"
        lines.append(f"freshness:      {freshness}")

    return "\n".join(lines) + "\n"


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


def result_to_slug(result: "VerificationResult") -> str:
    """Map a non-Trusted ``VerificationResult`` to its ``TNG-INDEX-*`` error slug.

    Single source of truth for the VerificationResult → slug bijection (M5).
    Called by ``enforce_index_trust``, conformance runners, and any code that
    needs the slug without performing enforcement.

    Raises ``KeyError`` for ``VerificationResult.TRUSTED`` — callers must
    guard against passing ``Trusted`` (which has no slug by design).
    """
    _map: dict[VerificationResult, str] = {
        BundleMissing: TNG_INDEX_BUNDLE_MISSING,
        BundleMalformed: TNG_INDEX_BUNDLE_MALFORMED,
        SigInvalid: TNG_INDEX_SIGNATURE_INVALID,
        DigestMismatch: TNG_INDEX_DIGEST_MISMATCH,
        SignerMismatch: TNG_INDEX_SIGNER_MISMATCH,
        BundleStale: TNG_INDEX_BUNDLE_STALE,
    }
    return _map[result]


def enforce_index_trust(
    result: VerificationResult,
    policy: TrustPolicy,
    index_url: str,
) -> None:
    """6-way ``VerificationResult`` → ``TNG-INDEX-*`` slug dispatch (RFC §6.5).

    Policy semantics (RFC §6.1):

    - ``off``     → silent; verifier was not called; no warning, no raise.
    - ``Trusted`` → silent; all seven verification steps passed (spec §3.4.4).
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

    slug = result_to_slug(result)

    # Human-readable hints per result variant (enforce_index_trust only; not exported).
    _hint_map: dict[VerificationResult, str] = {
        BundleMissing: (
            "no attestation bundle for the index. "
            "Run 'milpa fetch --refresh-index' to re-fetch with attestation, "
            "or set 'index-trust \"off\"' in milpa.kdl to suppress."
        ),
        BundleMalformed: "the Sigstore bundle is not valid JSON or missing required fields.",
        SigInvalid: "cryptographic verification of the index Sigstore bundle failed.",
        DigestMismatch: (
            "the bundle's attested subject digest does not match the index bytes "
            "(tampering or mismatched bundle/index pair)."
        ),
        SignerMismatch: (
            "the bundle signer identity does not match the expected signer. "
            "Set 'index-trust-signer' in milpa.kdl or MILPA_INDEX_TRUST_SIGNER "
            "to configure the expected SubjectAltName for a custom registry."
        ),
        BundleStale: (
            "the index attestation bundle is beyond the maximum allowed age "
            "(rollback attack or frozen CDN). "
            "Run 'milpa fetch --refresh-index' to force a fresh fetch, "
            "or increase MILPA_INDEX_MAX_AGE."
        ),
    }
    hint = _hint_map[result]

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
