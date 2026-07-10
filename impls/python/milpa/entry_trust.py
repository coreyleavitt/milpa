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

  ``evaluate_entry_attestation(...)``
      Runs gate stages 0–7 (RFC §5 table) for one selected registry-resolved
      dep: I/O via ``bundle_store`` + ``verifier``.  Returns
      ``(EntryVerificationResult, cause)`` — ``cause`` is only meaningful for
      ``BundleMissing`` (``"no-pin"`` | ``"unfetchable"``).  Stage 1b
      (``TNG-ENTRY-BUNDLE-PIN-MISMATCH``) is NOT representable in the return
      value — it is a security invariant raised directly by
      ``entry_bundle_store.py`` and propagates unconditionally (see that
      module's docstring); this function does not catch it.

  ``enforce_entry_trust(...)``
      warn/strict slug dispatch (mirrors ``index_trust.enforce_index_trust``).

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
    ``dag-sha256`` only, no legacy ``sha256:`` tier).  Extraction uses the same
    ``str.partition(":")`` the identity module itself uses, so this is correct
    regardless of which algorithm prefix is in force — never a hardcoded
    ``removeprefix("sha256:")``, which would silently no-op on the real
    ``dag-sha256:`` form and leak the algorithm prefix into the subject digest.
    """
    _, _, hex_digest = content_hash.partition(":")
    return EntrySubject(
        name=f"pkg:tianguis/{namespace}/{name}@{version}",
        sha256=hex_digest,
    )


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
) -> "tuple[EntryVerificationResult, str | None]":
    """Run gate stages 0-7 for one selected registry-resolved dep.

    Returns ``(result, cause)``. ``cause`` is populated only for
    ``BundleMissing`` (``"no-pin"`` when the entry is attested but carries no
    ``bundle`` pin yet; ``"unfetchable"`` when a pin is present but the
    bundle could not be fetched).

    Stage 1b (``TNG-ENTRY-BUNDLE-PIN-MISMATCH``) is NOT caught here — the
    bundle store raises it unconditionally (SECURITY INVARIANT, RFC §5); it
    propagates straight out of this function, bypassing warn/strict policy
    entirely (mirrors ``TNG-DEPDECL-HASH-MISMATCH``'s severity model).
    """
    from milpa.entry_bundle_store import EntryBundleStore  # noqa: F401 (typing only)
    from milpa.errors import TNG_ENTRY_BUNDLE_PIN_MISMATCH
    from milpa.registry import AuthorSigned

    # Stage 0: attestation record absent (or collapsed to unattested at parse time).
    if attestation is None:
        return Unattested, None

    # Stage 1: bundle acquisition.
    if attestation.bundle_pin is None:
        return BundleMissing, "no-pin"
    if bundle_store is None:
        return BundleMissing, "unfetchable"
    try:
        bundle_bytes = bundle_store.get(attestation.bundle_pin)  # type: ignore[attr-defined]
    except MilpaError as exc:
        if exc.slug == TNG_ENTRY_BUNDLE_PIN_MISMATCH:
            raise  # stage 1b: unconditional hard error, never policy-gated
        return BundleMissing, exc.context.get("cause", "unfetchable")

    # Stages 2-7: bundle parse + subject binding + crypto, delegated to the verifier.
    subject = build_entry_subject(namespace, name, version, content_hash)
    expected_signer = (
        attestation.kind.signer
        if isinstance(attestation.kind, AuthorSigned)
        else expected_vendor_signer
    )
    result = verifier.verify(subject, bundle_bytes, trust_bundle, expected_signer)
    return result, None


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


_HINT_MAP: dict[EntryVerificationResult, str] = {
    Unattested: (
        "no attestation record for this entry. "
        "Set 'entry-trust \"off\"' in milpa.kdl to suppress, or wait for the "
        "author/vendor-bot to publish an attested entry."
    ),
    BundleMissing: (
        "the entry is attested but its Sigstore bundle is unavailable. "
        "Run 'milpa fetch --refresh-index' to retry, or set "
        "'entry-trust \"off\"' in milpa.kdl to suppress."
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


def enforce_entry_trust(
    result: EntryVerificationResult,
    policy: TrustPolicy,
    *,
    namespace: str,
    name: str,
    version: str,
    cause: "str | None" = None,
) -> None:
    """warn/strict slug dispatch for one selected entry's gate outcome.

    - ``off``     → silent; the caller should not even invoke the gate, but
                    this guard makes the function total regardless.
    - ``Trusted`` → silent.
    - ``warn``    → emit ONE warning to stderr per unique
                    ``(namespace, name, version)`` per invocation; exit 0.
    - ``strict``  → raise ``MilpaError`` with the appropriate ``TNG-ENTRY-*`` slug.
    """
    if policy == "off" or result is Trusted:
        return

    slug = result_to_slug(result)
    coordinate = f"pkg:tianguis/{namespace}/{name}@{version}"
    hint = _HINT_MAP[result]
    if cause is not None:
        hint = f"{hint} (cause: {cause})"

    if policy == "strict":
        raise MilpaError(
            slug,
            f"entry-trust strict: {slug} for {coordinate!r} — {hint}",
            namespace=namespace,
            name=name,
            version=version,
            cause=cause,
        )

    key = (namespace, name, version)
    if key not in _warned_entries:
        _warned_entries.add(key)
        print(
            f"milpa: entry-trust warning ({slug}): {hint} (entry: {coordinate!r})",
            file=_sys.stderr,
        )
