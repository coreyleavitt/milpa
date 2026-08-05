"""Per-entry Sigstore attestation gate — RFC per-entry-attestation.md, P3a.

Public surface:

  ``EntryVerificationResult``
      8-variant sealed enum (``Trusted`` + 7 slugged failure states).  NOT an
      extension of ``index_trust.VerificationResult`` — see "Type reuse
      decision" below.

  ``EntrySubject``
      ``{name, sha256}`` — the two-coordinate subject binding (RFC §1):
      package identity (``pkg:tianguis/<namespace>/<name>@<version>``) AND
      the entry's ``content_hash`` (hex, no ``sha256:`` prefix).

  ``EntryBundleVerifier``
      ``typing.Protocol``: the injected verifier seam (RFC §6).  Production
      code passes ``SigstoreEntryVerifier()``; test/conformance code passes
      ``MockEntryVerifier(...)``.  Deliberately narrower than
      ``IndexBundleVerifier``: no ``max_age_seconds`` parameter (RFC §6 — a
      per-entry bundle binds an immutable subject, so a freshness window
      would only manufacture spurious failures) and takes ``expected_subject``
      instead of raw index bytes.

  ``SigstoreEntryVerifier``
      Production ``EntryBundleVerifier`` using ``sigstore-python``.  Real-crypto
      strict-fail tests are P3b/P4-gated (no real per-entry bundles exist
      before the tianguis delivery ships) — this class is written now (parity
      with the ``SigstoreVerifier`` S3→S5 precedent: written before its
      integration test existed) but only exercised here by malformed/mismatch
      unit tests, not a real-bundle happy path.

  ``MockEntryVerifier(default, by_subject=None)``
      Test ``EntryBundleVerifier``: keyed per-subject outcome scripting (RFC
      Conformance section) — a mixed resolve needs different verdicts per
      entry.  ``by_subject`` maps the subject ``name`` string (the
      ``pkg:tianguis/...`` coordinate) to a result; entries not in the map get
      ``default``.

  ``EntryTrustConfig``
      Frozen dataclass: policy + trust_bundle + expected_vendor_signer.

  ``EpochMembership``
      ``PreEpoch | PostEpoch`` — spec §3.6.3 NORMATIVE.  See
      ``classify_epoch_membership``.

  ``EntryGateOutcome``
      The D9 composed gate diagnostic (spec §3.6.3): ``{result,
      epoch_membership, cause}`` — the SOLE shape ``evaluate_entry_attestation``
      returns.

  ``classify_epoch_membership(status, identity)``
      S-EpochGate (RFC §6, D14/D17): maps an ``EpochCommitmentStatus`` +
      candidate identity to ``PreEpoch | PostEpoch | None`` — a local set
      lookup against the already-verified ``Armed`` set, nothing else.

  ``effective_epoch_policy(policy, membership)``
      S-EpochGate: caps the configured ``entry-trust`` policy at ``warn`` for
      ``PreEpoch``/``None`` (Unarmed) membership; ``PostEpoch`` gets the
      configured policy unchanged (the mandate applies).

  ``evaluate_entry_attestation(...)``
      Runs gate stages 0–7 (RFC §5 table) for one selected registry-resolved
      dep: I/O via ``bundle_store`` + ``verifier``.  Returns an
      ``EntryGateOutcome`` (D9) — ``cause`` is only meaningful for
      ``BundleMissing`` (``"no-pin"`` | ``"unfetchable"``).  Stage 1b
      (``TNG-ENTRY-BUNDLE-PIN-MISMATCH``) is NOT representable in the return
      value — it is a security invariant raised directly by
      ``entry_bundle_store.py`` and propagates unconditionally (see that
      module's docstring); this function does not catch it.

  ``enforce_entry_trust(...)``
      warn/strict slug dispatch (mirrors ``index_trust.enforce_index_trust``);
      applies the S-EpochGate policy downgrade via ``effective_epoch_policy``
      before dispatching.

Type reuse decision (RFC §6: "``VerificationResult``... extends from Part 1"):
  Rather than adding entry-only variants (``UNATTESTED``, ``SUBJECT_MISMATCH``)
  onto the shared ``index_trust.VerificationResult`` enum, this module defines
  its OWN ``EntryVerificationResult`` with the same PATTERN (sealed enum +
  module-level aliases + ``result_to_slug`` map + ``enforce_*`` dispatch +
  keyed ``MockVerifier``) but a domain proper to entries. Two of index's seven
  variants (``BUNDLE_STALE``, and index's own digest/signer semantics) do not
  transplant cleanly — entries need subject-NAME binding (§1) that
  whole-index verification has no concept of, and freshness is structurally
  inapplicable (§6). Extending the shared enum with entry-only members would
  make ``index_trust.py`` (Part 1, already shipped and battle-tested) carry
  states its own dispatch tables can never produce. A parallel type with the
  identical shape gives the "extends from Part 1" reuse at the PATTERN level
  the RFC calls for, without polluting Part 1's sealed domain.

Extract-or-decline decision (RFC §6: "the real ``EntryBundleVerifier`` shares
~90% of the just-shipped ``SigstoreVerifier`` internals... P3 MUST either
extract the shared core or record an explicit decision not to"):
  DECLINED for P3a. ``SigstoreEntryVerifier`` below duplicates the
  bundle-parse / cert-chain / DSSE / Rekor-inclusion verification shape from
  ``index_trust._sigstore_verify`` rather than extracting a shared helper.
  Rationale: no real per-entry bundle exists yet to differential-test an
  extraction against (P4-gated); refactoring ``index_trust.py``'s
  already-shipped, real-bundle-tested crypto path now, driven only by
  entry_trust's currently-mock-only test suite, would risk regressing Part 1
  for zero test-coverage gain in P3a. The extraction is owed and tracked for
  P3b, when real bundles exist on both sides to validate the unification
  against (the same point at which ``SigstoreVerifier`` itself first got a
  real-bundle integration test, per its own docstring).

RFC: docs/rfc-per-entry-attestation.md §1, §5, §6, §7.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import sys as _sys
from typing import Any, Protocol

from milpa import identity
from milpa.epoch_commitment import Armed, EpochCommitmentStatus, PreEpochIdentity, Unarmed
from milpa.errors import (
    TNG_ENTRY_BUNDLE_MALFORMED,
    TNG_ENTRY_BUNDLE_MISSING,
    TNG_ENTRY_DIGEST_MISMATCH,
    TNG_ENTRY_SIGNATURE_INVALID,
    TNG_ENTRY_SIGNER_MISMATCH,
    TNG_ENTRY_SUBJECT_MISMATCH,
    TNG_ENTRY_UNATTESTED,
    MilpaError,
)
from milpa.index_trust import TrustBundle
from milpa.trust import TrustPolicy


# ---------------------------------------------------------------------------
# EntryVerificationResult — 8-variant sealed enum (RFC §5 table)
# ---------------------------------------------------------------------------


class EntryVerificationResult(enum.Enum):
    """8-variant result type for per-entry Sigstore bundle verification.

    RFC §5 maps each non-``TRUSTED`` variant to a ``TNG-ENTRY-*`` slug. Stage
    1b (``BUNDLE_PIN_MISMATCH``) has no variant here — see module docstring.
    """

    TRUSTED = "trusted"
    UNATTESTED = "unattested"
    BUNDLE_MISSING = "bundle-missing"
    BUNDLE_MALFORMED = "bundle-malformed"
    DIGEST_MISMATCH = "digest-mismatch"
    SUBJECT_MISMATCH = "subject-mismatch"
    SIGNATURE_INVALID = "signature-invalid"
    SIGNER_MISMATCH = "signer-mismatch"


Trusted = EntryVerificationResult.TRUSTED
Unattested = EntryVerificationResult.UNATTESTED
BundleMissing = EntryVerificationResult.BUNDLE_MISSING
BundleMalformed = EntryVerificationResult.BUNDLE_MALFORMED
DigestMismatch = EntryVerificationResult.DIGEST_MISMATCH
SubjectMismatch = EntryVerificationResult.SUBJECT_MISMATCH
SignatureInvalid = EntryVerificationResult.SIGNATURE_INVALID
SignerMismatch = EntryVerificationResult.SIGNER_MISMATCH


def result_to_slug(result: "EntryVerificationResult") -> str:
    """Map a non-Trusted ``EntryVerificationResult`` to its ``TNG-ENTRY-*`` slug.

    Raises ``KeyError`` for ``TRUSTED`` — callers must guard against passing
    ``Trusted`` (which has no slug by design).
    """
    _map: dict[EntryVerificationResult, str] = {
        Unattested: TNG_ENTRY_UNATTESTED,
        BundleMissing: TNG_ENTRY_BUNDLE_MISSING,
        BundleMalformed: TNG_ENTRY_BUNDLE_MALFORMED,
        DigestMismatch: TNG_ENTRY_DIGEST_MISMATCH,
        SubjectMismatch: TNG_ENTRY_SUBJECT_MISMATCH,
        SignatureInvalid: TNG_ENTRY_SIGNATURE_INVALID,
        SignerMismatch: TNG_ENTRY_SIGNER_MISMATCH,
    }
    return _map[result]


# ---------------------------------------------------------------------------
# EntrySubject — the two-coordinate subject binding (RFC §1)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class EntrySubject:
    """``{name, sha256}`` subject binding for one selected registry entry.

    ``name`` — ``pkg:tianguis/<namespace>/<name>@<version>`` (RFC §1).
    ``sha256`` — hex digest of ``content_hash`` (NO ``sha256:`` prefix).
    """

    name: str
    sha256: str


def build_entry_subject(namespace: str, name: str, version: str, content_hash: str) -> EntrySubject:
    """Build the ``EntrySubject`` for one selected entry (RFC §1 coordinate format).

    ``content_hash`` is milpa's canonical identity string, ``dag-sha256:<64-hex>``
    (identity.md §2.1) — NOT ``sha256:<64-hex>`` (a stale prefix in the RFC's own
    prose; ``identity.py``'s ``parse_identity`` is the actual canonical scheme,
    ``dag-sha256`` only, no legacy ``sha256:`` tier).  Extraction uses
    ``identity.split_identity_scheme``, the same scheme-agnostic split
    ``parse_identity`` itself uses (never a hardcoded
    ``removeprefix("sha256:")``, which would silently no-op on the real
    ``dag-sha256:`` form and leak the algorithm prefix into the subject digest).
    Unlike ``parse_identity``, this does NOT enforce ``SUPPORTED_ALGORITHMS`` —
    building a subject coordinate doesn't need that coupling — but a
    ``content_hash`` with no ``:`` separator at all is genuinely malformed and
    must raise ``MilpaError(ID_NO_ALGORITHM_PREFIX)``, not silently produce an
    empty digest (which used to surface downstream as a confusing
    TNG-ENTRY-DIGEST-MISMATCH instead of a clear ID-* error).

    Raises:
        MilpaError(ID_NOT_A_STRING)        — ``content_hash`` is not a str
        MilpaError(ID_NO_ALGORITHM_PREFIX) — ``content_hash`` has no ``:`` separator
    """
    _, hex_digest = identity.split_identity_scheme(content_hash)
    return EntrySubject(
        name=f"pkg:tianguis/{namespace}/{name}@{version}",
        sha256=hex_digest,
    )


# ---------------------------------------------------------------------------
# EpochMembership — S-EpochGate (RFC §6, D14/D17; spec §3.6.3 NORMATIVE)
# ---------------------------------------------------------------------------


class EpochMembership(enum.Enum):
    """``PreEpoch | PostEpoch`` — spec §3.6.3 NORMATIVE (``EpochMembership``).

    Populated (non-``None``) only when the index's ``EpochCommitmentStatus``
    is ``Armed(S, E)``; ``Unarmed`` maps to ``None`` (no third variant — see
    ``classify_epoch_membership``).
    """

    PRE_EPOCH = "pre-epoch"
    POST_EPOCH = "post-epoch"


PreEpoch = EpochMembership.PRE_EPOCH
PostEpoch = EpochMembership.POST_EPOCH


def classify_epoch_membership(
    status: EpochCommitmentStatus,
    identity_tuple: PreEpochIdentity,
) -> "EpochMembership | None":
    """S-EpochGate membership classification (RFC §6 D14/D17; spec §3.4.8
    NORMATIVE "membership is a local set lookup" + §3.6.3 NORMATIVE
    ``EpochMembership``).

    ``Armed(S, E)`` + ``identity_tuple in S`` -> ``PreEpoch`` (a plain local
    set-containment test against the already-verified ``S`` — no
    recomputation, no proof machinery, D17). ``Armed(S, E)`` +
    ``identity_tuple not in S`` -> ``PostEpoch``. ``Unarmed`` -> ``None``:
    "no commitment is armed" is a fact about the INDEX, already fully
    captured by ``EpochCommitmentStatus`` itself, not a per-entry
    classification (D14) — every entry from that registry is then
    warn-equivalent under the SAME D1/D11 rule §3.4.8 states normatively for
    the whole registry (see ``effective_epoch_policy``).

    ``ArmingInvalid`` never reaches this function in production — spec
    §3.6.4 NORMATIVE cross-axis precedence: an ``ArmingInvalid`` aborts the
    WHOLE resolve (``TNG-INDEX-EPOCH-COMMITMENT-INVALID``) before any
    candidate is selected, so the entry gate never runs on that resolve at
    all. Defensively treated identically to ``Unarmed`` (``None``) here
    anyway, rather than raising, so this function stays total and pure —
    matching ``evaluate_epoch_commitment``'s own "never raises" discipline.
    """
    if not isinstance(status, Armed):
        return None
    return PreEpoch if identity_tuple in status.identities else PostEpoch


def effective_epoch_policy(
    policy: TrustPolicy, membership: "EpochMembership | None"
) -> TrustPolicy:
    """S-EpochGate policy downgrade (RFC §6; spec §3.6.3 NORMATIVE).

    ``PostEpoch`` -> the configured policy, UNCHANGED (the mandate applies:
    under ``strict`` an unattested/unverifiable post-epoch entry hard-fails).

    ``PreEpoch`` or ``None`` (``Unarmed``) -> capped at ``warn``: ``strict``
    downgrades to ``warn``, ``warn`` stays ``warn``, ``off`` stays ``off``.
    "``PreEpoch`` stays warn-territory even under entry-trust 'strict'" (a
    fixed, shrinking grandfathered population) and "``Unarmed`` ... is
    warn-equivalent for every candidate from that registry" (spec §3.6.3
    NORMATIVE ``EpochMembership``).

    SECURITY RATIONALE (why this downgrade cannot be exploited): membership
    is decided over the frozen, composed-verified set ``S``, keyed on the
    full ``(namespace, name, version, content_hash)`` identity tuple —
    ``content_hash`` included. Tampering with a grandfathered entry's bytes
    changes its ``content_hash``, so the tampered identity no longer matches
    any member of ``S`` and reclassifies as ``PostEpoch`` on the next
    resolve, where the mandate applies in full. A pre-epoch entry can only
    ever be the SAME bytes the registry committed to at arming time.
    """
    if membership is PostEpoch:
        return policy
    return "off" if policy == "off" else "warn"  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# EntryBundleVerifier — Protocol (RFC §6)
# ---------------------------------------------------------------------------


class EntryBundleVerifier(Protocol):
    """Injected verifier seam for per-entry attestation (RFC §6).

    Deliberately narrower than ``IndexBundleVerifier``: no freshness
    parameter (a per-entry bundle binds an immutable subject — RFC §6), and
    the caller supplies the expected *subject* (name + digest) rather than
    raw bytes to hash.  Expected-signer derivation (pinned ``signed_by`` vs
    the resolved vendor-bot identity) stays in the gate (``evaluate_entry_
    attestation`` below), not the verifier — so the verifier stays
    kind-agnostic.
    """

    def verify(
        self,
        expected_subject: EntrySubject,
        bundle_bytes: bytes,
        trust_bundle: TrustBundle,
        expected_signer: str,
    ) -> EntryVerificationResult:
        """Verify the Sigstore bundle against ``expected_subject``.

        Returns one of ``{TRUSTED, BUNDLE_MALFORMED, DIGEST_MISMATCH,
        SUBJECT_MISMATCH, SIGNATURE_INVALID, SIGNER_MISMATCH}`` — never
        ``UNATTESTED`` or ``BUNDLE_MISSING`` (gate-level states the caller
        never asks the verifier about).
        """
        ...


# ---------------------------------------------------------------------------
# SigstoreEntryVerifier — production EntryBundleVerifier (RFC §6)
# ---------------------------------------------------------------------------


class SigstoreEntryVerifier:
    """Production verifier using sigstore-python.

    See the module docstring's "Extract-or-decline decision" for why this
    duplicates (rather than shares) ``index_trust._sigstore_verify``'s shape.
    Not exercised against a real bundle in P3a (no real per-entry bundles
    exist before the tianguis delivery ships — P3b/P4); tested here only on
    malformed-JSON / pre-crypto subject-mismatch inputs, which do not require
    a real signature.
    """

    def verify(
        self,
        expected_subject: EntrySubject,
        bundle_bytes: bytes,
        trust_bundle: TrustBundle,
        expected_signer: str,
    ) -> EntryVerificationResult:
        # Step 2 (stage 2 of the RFC §5 pipeline): parse bundle JSON.
        try:
            bundle_data: dict[str, Any] = json.loads(bundle_bytes)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return BundleMalformed
        if not isinstance(bundle_data, dict):
            return BundleMalformed

        # Pre-crypto subject checks (stages 3 + 4 — RFC §1 NORMATIVE: BOTH
        # coordinates are checked BEFORE any cryptographic verification).
        # Reads the UNVERIFIED DSSE payload — sound because we only ask "does
        # this bundle even claim our subject?", mirroring index_trust.py's
        # pre-check rationale (§3.4.4 precedent).
        import base64

        try:
            payload_bytes = base64.b64decode(bundle_data["dsseEnvelope"]["payload"])
            payload_json = json.loads(payload_bytes)
        except Exception:
            return BundleMalformed

        subjects = payload_json.get("subject", [])
        if not subjects:
            return DigestMismatch
        claimed_sha256 = subjects[0].get("digest", {}).get("sha256")
        if claimed_sha256 is None or claimed_sha256 != expected_subject.sha256:
            return DigestMismatch
        claimed_name = subjects[0].get("name")
        if claimed_name is None or claimed_name != expected_subject.name:
            return SubjectMismatch

        # Steps 5-7: cryptographic verification via sigstore-python.
        return _sigstore_verify_entry(bundle_bytes, trust_bundle, expected_signer)


def _sigstore_verify_entry(
    bundle_bytes: bytes,
    trust_bundle: TrustBundle,
    expected_signer: str,
) -> EntryVerificationResult:
    """Stages 5-7: cert chain + DSSE signature + signer SAN + Rekor inclusion.

    Failure-to-variant mapping mirrors ``index_trust._sigstore_verify``'s
    type-based (not message-text) dispatch — see that function's docstring
    for the full rationale, duplicated here per the extract-or-decline
    decision above.
    """
    try:
        from sigstore.errors import VerificationError
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
    except ImportError:
        return SignatureInvalid

    try:
        if trust_bundle.label == "production":
            verifier = Verifier.production(offline=True)
        else:
            import tempfile

            from sigstore.models import TrustedRoot

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="wb") as tmp:
                tmp.write(trust_bundle.raw_json)
                tmp_path = tmp.name
            try:
                trusted_root = TrustedRoot.from_file(tmp_path)
                verifier = Verifier(trusted_root=trusted_root)
            finally:
                import os as _os

                _os.unlink(tmp_path)
    except Exception:
        return SignatureInvalid

    try:
        bundle = Bundle.from_json(bundle_bytes.decode("utf-8"))
    except Exception:
        return BundleMalformed

    inner_policy = Identity(
        identity=expected_signer,
        issuer="https://token.actions.githubusercontent.com",
    )

    class _RecordingPolicy:
        def __init__(self, inner: Any) -> None:
            self._inner = inner
            self.policy_raised = False

        def verify(self, cert: Any) -> None:
            try:
                self._inner.verify(cert)
            except Exception:
                self.policy_raised = True
                raise

    recording = _RecordingPolicy(inner_policy)

    try:
        verifier.verify_dsse(bundle=bundle, policy=recording)
    except VerificationError:
        if recording.policy_raised:
            return SignerMismatch
        return SignatureInvalid
    except Exception:
        return SignatureInvalid

    return Trusted


# ---------------------------------------------------------------------------
# MockEntryVerifier — keyed per-subject outcome scripting (RFC Conformance)
# ---------------------------------------------------------------------------


class MockEntryVerifier:
    """Test ``EntryBundleVerifier``: keyed per-subject outcome scripting.

    RFC Conformance section, seam extension (i): "the mock's outcome becomes
    a keyed per-subject map (today [Part 1] it is one fixed result — a mixed
    resolve needs different verdicts per entry)".
    """

    def __init__(
        self,
        default: EntryVerificationResult = Trusted,
        by_subject: "dict[str, EntryVerificationResult] | None" = None,
    ) -> None:
        self._default = default
        self._by_subject = dict(by_subject) if by_subject else {}

    def verify(
        self,
        expected_subject: EntrySubject,
        bundle_bytes: bytes,
        trust_bundle: TrustBundle,
        expected_signer: str,
    ) -> EntryVerificationResult:
        """Return the scripted result for ``expected_subject.name``, or the default."""
        return self._by_subject.get(expected_subject.name, self._default)


# ---------------------------------------------------------------------------
# EntryTrustConfig — config bundle threaded through ResolveParams (RFC §4)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class EntryTrustConfig:
    """Config bundle for the entry-trust gate — one field on ``ResolveParams``.

    Bundles policy + trust root + expected vendor-bot signer + verifier +
    bundle store into a single frozen dataclass, threaded through
    ``resolve()`` / ``resolve_workspace()`` (RFC §3 — the gate fires at the
    selection step, inside the resolver, unlike index-trust which gates at
    index load, before the resolver runs).

    ``verifier`` and ``bundle_store`` are explicit fields here (unlike
    ``IndexTrustConfig``, which keeps ``verifier`` as a separate parameter) —
    the entry-trust gate has no single call site analogous to ``load_index``,
    so bundling everything the gate needs into one threadable object is the
    seam that avoids parameter explosion across ``resolve()`` /
    ``resolve_workspace()`` / ``_build_graph``.
    """

    policy: TrustPolicy
    trust_bundle: TrustBundle
    expected_vendor_signer: str
    verifier: "EntryBundleVerifier"
    bundle_store: "object | None"  # EntryBundleStore protocol; None disables acquisition
    #: Break-glass (#196): forces a transient unfetchable-bundle outage through
    #: under strict (loud, per-entry). True ONLY when both
    #: MILPA_ENTRY_TRUST_BREAK_GLASS and --i-know-this-is-insecure are set.
    break_glass: bool = False


# ---------------------------------------------------------------------------
# EntryGateOutcome — the D9 composed gate diagnostic (spec §3.6.3 NORMATIVE)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class EntryGateOutcome:
    """The gate's SOLE return shape (D9, spec §3.6.3 NORMATIVE
    ``EntryGateOutcome``) — one composed diagnostic, not independently
    threaded ``(result, cause)`` fields.

    ``result``
        ``EntryVerificationResult`` — ``Trusted`` or one of the seven
        ``TNG-ENTRY-*`` failure variants.

    ``epoch_membership``
        ``EpochMembership | None`` — see ``classify_epoch_membership``.

    ``cause``
        Populated only when ``result`` is ``BundleMissing``
        (``"no-pin"`` | ``"unfetchable"``).
    """

    result: EntryVerificationResult
    epoch_membership: "EpochMembership | None"
    cause: "str | None" = None


# ---------------------------------------------------------------------------
# evaluate_entry_attestation — the gate pipeline (RFC §5 stages 0-7)
# ---------------------------------------------------------------------------


def evaluate_entry_attestation(
    *,
    attestation: "Any | None",  # EntryAttestation | None (registry.py) — Any avoids import cycle
    content_hash: str,
    namespace: str,
    name: str,
    version: str,
    verifier: "EntryBundleVerifier",
    bundle_store: "object | None",
    trust_bundle: TrustBundle,
    expected_vendor_signer: str,
    epoch_status: EpochCommitmentStatus,
) -> EntryGateOutcome:
    """Run gate stages 0-7 for one selected registry-resolved dep.

    Returns an ``EntryGateOutcome`` (D9) — ``cause`` is populated only for
    ``BundleMissing`` (``"no-pin"`` when the entry is attested but carries no
    ``bundle`` pin yet; ``"unfetchable"`` when a pin is present but the
    bundle could not be fetched).

    ``epoch_status`` (S-EpochGate, RFC §6 D14/D17): the once-per-resolve
    ``EpochCommitmentStatus`` this candidate's registry produced
    (``Index.epoch_commitment_status``) — classified into
    ``EntryGateOutcome.epoch_membership`` via ``classify_epoch_membership``,
    using the identity ``(namespace, name, version, content_hash)`` (spec
    §3.4.8's identity tuple, byte-exact per S2/D16 hygiene). Classification
    runs unconditionally, BEFORE stage 0 — membership is a fact about the
    candidate's identity alone, independent of whether it happens to carry
    an attestation record at all (an ``Unattested`` post-epoch entry is
    still ``PostEpoch``, which is exactly the row the mandate must catch).

    Stage 1b (``TNG-ENTRY-BUNDLE-PIN-MISMATCH``) is NOT caught here — the
    bundle store raises it unconditionally (SECURITY INVARIANT, RFC §5); it
    propagates straight out of this function, bypassing warn/strict policy
    entirely (mirrors ``TNG-DEPDECL-HASH-MISMATCH``'s severity model).
    """
    from milpa.entry_bundle_store import EntryBundleStore  # noqa: F401 (typing only)
    from milpa.errors import TNG_ENTRY_BUNDLE_PIN_MISMATCH
    from milpa.registry import AuthorSigned

    membership = classify_epoch_membership(
        epoch_status,
        PreEpochIdentity(
            namespace=namespace, name=name, version=version, content_hash=content_hash
        ),
    )

    # Stage 0: attestation record absent (or collapsed to unattested at parse time).
    if attestation is None:
        return EntryGateOutcome(result=Unattested, epoch_membership=membership)

    # Stage 1: bundle acquisition.
    if attestation.bundle_pin is None:
        return EntryGateOutcome(result=BundleMissing, epoch_membership=membership, cause="no-pin")
    if bundle_store is None:
        return EntryGateOutcome(
            result=BundleMissing, epoch_membership=membership, cause="unfetchable"
        )
    try:
        bundle_bytes = bundle_store.get(attestation.bundle_pin)  # type: ignore[attr-defined]
    except MilpaError as exc:
        if exc.slug == TNG_ENTRY_BUNDLE_PIN_MISMATCH:
            raise  # stage 1b: unconditional hard error, never policy-gated
        return EntryGateOutcome(
            result=BundleMissing,
            epoch_membership=membership,
            cause=exc.context.get("cause", "unfetchable"),
        )

    # Stages 2-7: bundle parse + subject binding + crypto, delegated to the verifier.
    subject = build_entry_subject(namespace, name, version, content_hash)
    expected_signer = (
        attestation.kind.signer
        if isinstance(attestation.kind, AuthorSigned)
        else expected_vendor_signer
    )
    result = verifier.verify(subject, bundle_bytes, trust_bundle, expected_signer)
    return EntryGateOutcome(result=result, epoch_membership=membership)


# ---------------------------------------------------------------------------
# enforce_entry_trust — warn/strict slug dispatch (mirrors enforce_index_trust)
# ---------------------------------------------------------------------------

# Dedup key per invocation: at most one entry-trust warning per unique
# (namespace, name, version) per invocation (mirrors index-trust's per-URL
# dedup, RFC §5: "each failing selected entry emits exactly one warning line,
# deduplicated per (namespace, name, version) per invocation").
_warned_entries: set[tuple[str, str, str]] = set()


def _reset_warned_entries() -> None:
    """Clear the per-invocation warn dedup set.  TEST USE ONLY."""
    _warned_entries.clear()


# ---------------------------------------------------------------------------
# no-epoch-armed observability notice (Dsgn-H2, RFC attestation-v1-
# normative.md §6 S5, round-3 addition (ii))
# ---------------------------------------------------------------------------

#: The literal notice text (RFC S5): deliberately audience-agnostic (br10) —
#: the SAME ``Unarmed`` state means "attestation is rolling out" to a
#: flagship-registry consumer mid-migration and "this registry does not
#: attest" to a self-hosted/air-gapped operator who never plans to; milpa has
#: no signal to distinguish the two (both present as an absent field), so the
#: notice states the mechanical fact and names both readings.
NO_EPOCH_ARMED_NOTICE = (
    'milpa: entry-trust is "strict", but this registry has not armed a '
    "pre-epoch commitment — no entry is currently mandated to carry an "
    "attestation (every entry is treated as warn-equivalent). If this "
    "registry is rolling out attestation, this is expected until it arms an "
    'epoch; if this registry does not attest at all, "strict" enforces '
    "nothing here until it does."
)

#: Dedup flag: at most one no-epoch-armed notice per invocation (mirrors
#: ``_warned_entries``'s per-invocation dedup discipline), regardless of how
#: many registries/candidates are classified ``Unarmed`` this run.
_no_epoch_armed_notice_shown = False


def _reset_no_epoch_armed_notice() -> None:
    """Clear the once-per-invocation no-epoch-armed notice flag.  TEST USE ONLY."""
    global _no_epoch_armed_notice_shown
    _no_epoch_armed_notice_shown = False


def maybe_emit_no_epoch_armed_notice(
    policy: TrustPolicy, status: "EpochCommitmentStatus"
) -> None:
    """Emit ``NO_EPOCH_ARMED_NOTICE`` to stderr, once per invocation, when
    effective entry-trust is ``"strict"`` but the loaded index carries no
    epoch commitment (``Unarmed``) — otherwise strict silently degrades to
    warn-equivalent (D11) with zero signal, a false-confidence gap for an
    operator who believes "strict" is actively enforcing something.

    Informational only: never raises, never affects the exit code. Called
    from BOTH the fetch/lock gate (``_enforce_epoch_commitment_phase``) and
    ``milpa verify``'s offline re-derivation
    (``reverify_cached_epoch_commitment_status``) — the same fact, the same
    wording, regardless of which command surfaced it.
    """
    global _no_epoch_armed_notice_shown
    if policy != "strict" or not isinstance(status, Unarmed):
        return
    if _no_epoch_armed_notice_shown:
        return
    _no_epoch_armed_notice_shown = True
    print(NO_EPOCH_ARMED_NOTICE, file=_sys.stderr)


#: Static hints for results whose remediation text does not depend on
#: ``cause``/bundle-store backend. ``BundleMissing`` is deliberately absent —
#: its hint is cause- and backend-dependent (see ``_bundle_missing_hint``,
#: D6). D6 audit: every "escape" hint below recommends the NARROWER
#: ``entry-trust "warn"`` (preserves the audit trail strict exists to
#: produce), never the permanent kill-switch ``entry-trust "off"`` — reserve
#: ``"off"`` language for genuinely-permanent deliberate opt-outs, which none
#: of these are.
_HINT_MAP: dict[EntryVerificationResult, str] = {
    Unattested: (
        "no attestation record for this entry. "
        "Set 'entry-trust \"warn\"' in milpa.kdl to accept it without an "
        "attestation while still recording a warning, or wait for the "
        "author/vendor-bot to publish an attested entry."
    ),
    BundleMalformed: "the per-entry Sigstore bundle is not valid JSON or missing required fields.",
    DigestMismatch: (
        "the bundle's attested subject digest does not match this entry's "
        "content_hash (tampering or mismatched bundle/entry pair)."
    ),
    SubjectMismatch: (
        "the bundle's attested subject package identity does not match this "
        "entry's coordinate (possible cross-package replay)."
    ),
    SignatureInvalid: "cryptographic verification of the per-entry Sigstore bundle failed.",
    SignerMismatch: (
        "the bundle signer identity does not match the expected signer for "
        "this entry's attestation kind."
    ),
}


def _bundle_missing_hint(cause: "str | None", bundle_store: "object | None") -> str:
    """D6 cause × store-backend hint for ``BundleMissing`` (RFC S-Acq).

    ``cause == "no-pin"``: the registry itself has not published a bundle for
    this entry yet — independent of which store backend is configured.

    ``cause == "unfetchable"``: the remediation depends on the store backend
    that failed to produce bytes:

    - ``HttpEntryBundleStore`` (production mirror): a fetch failure is
      usually a transient network condition — retrying via ``milpa fetch``
      is meaningful remediation. ``--refresh-index`` is NOT recommended here:
      it only bypasses the INDEX cache TTL and is a no-op for the
      content-addressed bundle store (which has no TTL to bypass).
    - ``FileEntryBundleStore`` (``MILPA_ENTRY_BUNDLE_DIR``, air-gapped): a
      genuinely-absent local file is NOT transient — retrying deterministically
      re-fails. The hint names the operator-populated mirror, not "re-run fetch".
    - No store configured at all (``bundle_store is None`` — ``--no-index``,
      an explicitly-empty ``MILPA_INDEX_URL``, and no
      ``MILPA_ENTRY_BUNDLE_DIR``): neither retrying nor an operator mirror
      applies — the hint says to configure a source.
    """
    from milpa.entry_bundle_store import FileEntryBundleStore, HttpEntryBundleStore

    if cause == "no-pin":
        return (
            "the registry has not published a Sigstore bundle for this entry "
            "yet. Set 'entry-trust \"warn\"' in milpa.kdl, or wait for the "
            "registry's attestation backfill to publish one."
        )
    if isinstance(bundle_store, FileEntryBundleStore):
        return (
            "the attestation bundle is missing from the local mirror "
            "(MILPA_ENTRY_BUNDLE_DIR); this will not resolve itself — ask "
            "the operator to populate the mirror with this entry's bundle, "
            "or set 'entry-trust \"warn\"' in milpa.kdl to suppress."
        )
    if isinstance(bundle_store, HttpEntryBundleStore):
        return (
            "the attestation mirror was unreachable; this is usually "
            "transient — re-run 'milpa fetch'. If it keeps failing, set "
            "'entry-trust \"warn\"' in milpa.kdl to suppress."
        )
    return (
        "no attestation-bundle source is configured for this invocation (no "
        "index, and MILPA_ENTRY_BUNDLE_DIR is unset) — configure one, or set "
        "'entry-trust \"warn\"' in milpa.kdl to suppress."
    )


def _verify_bundle_missing_hint(cause: "str | None", bundle_store: "object | None") -> str:
    """``milpa verify``'s OWN ``BundleMissing`` remediation (RFC
    attestation-v1-normative.md §6 S5, D6/D12) — distinct from
    ``_bundle_missing_hint``'s fetch-path cause/backend split.

    ``verify`` re-checks bundles already resident on disk and NEVER fetches
    (spec cli-contract.md §5.4). So a lockfile minted under the pre-flip
    ``warn`` default (or one whose bundle was never cached for any other
    reason) has nothing to re-verify — the ONLY recovery is to run `milpa
    fetch` first, which `verify` itself cannot do. Unlike the fetch path,
    this hint does NOT distinguish `no-pin` from `unfetchable` (both reduce
    to the same "there is nothing cached here" fact from `verify`'s offline
    vantage point) — it DOES keep the operator-mirror split for
    ``FileEntryBundleStore`` (air-gapped mirrors are populated by an
    operator, not by `milpa fetch`).
    """
    from milpa.entry_bundle_store import FileEntryBundleStore

    if isinstance(bundle_store, FileEntryBundleStore):
        return (
            "no cached attestation bundle for this entry, and 'milpa verify' "
            "never fetches. Ask the registry operator to populate "
            "MILPA_ENTRY_BUNDLE_DIR with this entry's bundle, then re-run "
            "'milpa verify'; or set 'entry-trust \"warn\"' in milpa.kdl to "
            "suppress."
        )
    return (
        "no cached attestation bundle for this entry — 'milpa verify' only "
        "re-checks bundles already on disk and never fetches. Run 'milpa "
        "fetch' to acquire the bundle, then re-run 'milpa verify'; or set "
        "'entry-trust \"warn\"' in milpa.kdl to suppress."
    )


def _epoch_membership_hint_suffix(membership: "EpochMembership | None") -> str:
    """Pinned remediation prose keyed by epoch membership (RFC §6 S-EpochGate).

    ``PostEpoch``: the mandate-context sentence a strict failure needs — WHY
    this particular entry is not eligible for the grandfathered downgrade.
    ``PreEpoch``: the symmetric explanation for why a failing pre-epoch entry
    stays a warning even under ``entry-trust "strict"`` (observability for
    the capped-policy case — not itself a failure explanation). ``None``
    (``Unarmed``): no epoch context to add.
    """
    if membership is PostEpoch:
        return (
            " This version is not in the registry's committed pre-epoch "
            "set, so it must carry a verifiable attestation."
        )
    if membership is PreEpoch:
        return (
            " This version is in the registry's committed pre-epoch "
            "(grandfathered) set, so this stays a warning even under "
            'entry-trust "strict".'
        )
    return ""


def enforce_entry_trust(
    outcome: EntryGateOutcome,
    policy: TrustPolicy,
    *,
    namespace: str,
    name: str,
    version: str,
    bundle_store: "object | None" = None,
    verify_context: bool = False,
    break_glass: bool = False,
) -> None:
    """warn/strict slug dispatch for one selected entry's gate outcome (D9).

    - ``off``     → silent; the caller should not even invoke the gate, but
                    this guard makes the function total regardless.
    - ``Trusted`` → silent.
    - ``warn``    → emit ONE warning to stderr per unique
                    ``(namespace, name, version)`` per invocation; exit 0.
    - ``strict``  → raise ``MilpaError`` with the appropriate ``TNG-ENTRY-*`` slug.

    S-EpochGate (RFC §6, spec §3.6.3 NORMATIVE): before dispatching, the
    configured ``policy`` is passed through ``effective_epoch_policy`` with
    ``outcome.epoch_membership`` — ``PostEpoch`` keeps the configured policy
    (the mandate applies); ``PreEpoch``/``None`` (``Unarmed``) caps it at
    ``warn`` (a fixed, shrinking grandfathered population never hard-fails).

    ``bundle_store`` is the concrete store instance the gate acquired bytes
    (or failed to acquire bytes) from — passed through ONLY so a
    ``BundleMissing`` result can select the D6 cause × backend hint text
    (``_bundle_missing_hint``); it has no bearing on any other result.

    ``verify_context`` (RFC attestation-v1-normative.md §6 S5, D6/D12):
    ``True`` only when the caller is ``milpa verify``'s offline reverify path
    (``_reverify_cached_entry_attestations``). Selects
    ``_verify_bundle_missing_hint`` in place of ``_bundle_missing_hint`` for a
    ``BundleMissing`` outcome — ``verify`` cannot self-heal a missing bundle
    (it never fetches), so its remediation is "run `milpa fetch`, then
    re-verify" rather than the fetch path's cause/backend-split hint.
    """
    if policy == "off" or outcome.result is Trusted:
        return

    effective_policy = effective_epoch_policy(policy, outcome.epoch_membership)
    if effective_policy == "off" or outcome.result is Trusted:
        return

    slug = result_to_slug(outcome.result)
    coordinate = f"pkg:tianguis/{namespace}/{name}@{version}"
    if outcome.result is BundleMissing:
        hint = (
            _verify_bundle_missing_hint(outcome.cause, bundle_store)
            if verify_context
            else _bundle_missing_hint(outcome.cause, bundle_store)
        )
    else:
        hint = _HINT_MAP[outcome.result]
    if outcome.cause is not None:
        hint = f"{hint} (cause: {outcome.cause})"
    hint = f"{hint}{_epoch_membership_hint_suffix(outcome.epoch_membership)}"

    # Break-glass (RFC attestation-v1-normative.md, D1 resolved-with-recommendation
    # block; #196): a TRANSIENT attestation-mirror outage (``BundleMissing`` with
    # cause ``unfetchable``) under ``strict`` may be forced through ONLY when the
    # caller resolved ``break_glass`` from BOTH ``MILPA_ENTRY_TRUST_BREAK_GLASS``
    # and the explicit ``--i-know-this-is-insecure`` flag. It is deliberately
    # NARROW: it never bypasses a present-but-invalid attestation
    # (digest/subject/signature/signer mismatch = tampering) nor a
    # ``no-pin``/``Unattested`` gap — only the "the mirror is unreachable right
    # now" class — and it is loud + per-entry (never silent).
    if (
        break_glass
        and effective_policy == "strict"
        and outcome.result is BundleMissing
        and outcome.cause == "unfetchable"
    ):
        print(
            f"milpa: INSECURE — entry-trust break-glass engaged for {coordinate!r}: "
            f"proceeding despite an unfetchable attestation bundle ({slug}). This "
            "bypasses the strict mandate for a transient mirror outage only; unset "
            "MILPA_ENTRY_TRUST_BREAK_GLASS and drop --i-know-this-is-insecure, then "
            "re-run once the mirror recovers.",
            file=_sys.stderr,
        )
        return

    if effective_policy == "strict":
        raise MilpaError(
            slug,
            f"entry-trust strict: {slug} for {coordinate!r} — {hint}",
            namespace=namespace,
            name=name,
            version=version,
            cause=outcome.cause,
        )

    key = (namespace, name, version)
    if key not in _warned_entries:
        _warned_entries.add(key)
        print(
            f"milpa: entry-trust warning ({slug}): {hint} (entry: {coordinate!r})",
            file=_sys.stderr,
        )


# ---------------------------------------------------------------------------
# format_entry_trust_info — `show --entry-trust` observability (RFC
# attestation-v1-normative.md §6 S5, R8/R10: minimal parity with `show
# --index-trust`'s convention)
# ---------------------------------------------------------------------------


def format_entry_trust_info(
    *,
    policy: str,
    index_url: str,
    epoch_commitment_pointer: "str | None",
) -> str:
    """Format the ``milpa show --entry-trust`` observability output.

    Fixed-width label block, SAME 16-character label convention as
    ``index_trust.format_index_trust_info`` — byte-identical between the
    Python and Rust impls (see the Rust counterpart
    ``milpa_core::entry_trust::format_entry_trust_info``).

    CLAIMS ONLY (mirrors ``format_index_trust_info``'s discipline): the
    epoch-commitment row reports whether the CACHED index text carries an
    ``attestation-epoch-commitment`` pointer field — read straight off disk,
    no composed cryptographic verification. Actually classifying
    ``Armed``/``ArmingInvalid`` requires running that crypto, which is
    `fetch`/`lock`/`verify`'s job, not a passive `show` audit view's.

    Parameters
    ----------
    policy:
        The effective entry-trust policy (``warn`` / ``strict`` / ``off``).
    index_url:
        The registry entry-trust operates against.
    epoch_commitment_pointer:
        The raw ``attestation-epoch-commitment`` hex pointer read off the
        cached index text, or ``None`` when the field is absent (or nothing
        is cached yet).

    Returns
    -------
    str
        The formatted output string with a trailing newline.
    """
    lines: list[str] = []
    lines.append(f"entry-trust:    {policy}")
    lines.append(f"index-url:      {index_url}")
    if epoch_commitment_pointer is not None:
        lines.append(
            f"epoch-commit:   claimed ({epoch_commitment_pointer[:12]}...), "
            "cached claim only, not verified by show"
        )
    else:
        lines.append(
            "epoch-commit:   not armed (no attestation-epoch-commitment "
            "field on the cached index)"
        )
    return "\n".join(lines) + "\n"
