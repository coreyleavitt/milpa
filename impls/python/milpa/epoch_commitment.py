"""Epoch-commitment phase — the index-gate pre-epoch set arming check.

RFC: ``docs/rfc-attestation-v1-normative.md`` §6 slice **S-EpochCommitment**,
decisions D14-D18.  Spec: ``spec/registry-protocol.md`` §3.4.8 (the phase)
and §3.4.9 (sidecar acquisition).

This module is **pure computation** — no filesystem I/O, no network — the
same discipline ``index_ratchet_seam.py`` and ``index_trust.verify_index_bundle``
follow.  Acquisition (fetching and caching the commitment sidecar) is a
separate, injected-I/O concern layered on top by the caller (``cli.py`` /
``index_cache.py``); this module answers "given the on-index pointer and the
(already-fetched) sidecar bytes, what is the verified status" as data.

Public surface
---------------
``PreEpochIdentity``
    ``(namespace, name, version, content_hash)`` — the D16 identity tuple.

``canonical_preimage(identities)`` / ``commitment_digest(identities)``
    The D16/D17 canonical construction — see "Canonical construction" below.
    This is the SINGLE most cross-impl-critical piece of this module: the
    Rust mirror MUST reproduce ``canonical_preimage`` byte-for-byte.

``EpochCommitmentStatus``
    ``Unarmed | Armed(identities, integrated_time) | ArmingInvalid(reason)``
    — a closed union of three frozen dataclasses (mirrors ``registry.py``'s
    ``AttestationKind = AuthorSigned | MilpaVendored`` pattern).

``parse_sidecar_payload(payload_bytes)``
    Pure JSON parse of the acquired sidecar: the enumerated identity list
    ``S`` plus the embedded Sigstore bundle JSON.  Returns ``None`` on any
    structural malformation (pre-crypto failure).

``evaluate_epoch_commitment(...)``
    The phase itself: pointer + (already-fetched) sidecar bytes + an
    injected ``IndexBundleVerifier`` (the SAME protocol/composition
    ``index_trust.verify_index_bundle`` uses — see "Composed verification
    reuse" below) -> ``EpochCommitmentStatus``.  Computed once per resolve
    by the caller.

``enforce_epoch_commitment(status)``
    Unconditional (no policy parameter — D-Watermark's "never downgrades
    under any entry-trust policy value" reads as "this axis has no warn
    tier at all"): raises ``TNG-INDEX-EPOCH-COMMITMENT-INVALID`` on
    ``ArmingInvalid``; no-op otherwise.

``check_epoch_ratchet_requirement(status, entry_trust_policy, index_history_policy)``
    The D18 co-requirement: ``Armed`` + ``entry-trust=strict`` requires
    ``index-history=strict``, else ``TNG-INDEX-EPOCH-RATCHET-REQUIRED``.

Canonical construction (D16/D17, spec §3.4.8 NORMATIVE — the frozen set S
and its commitment C)
-----------------------------------------------------------------------------
::

    C = sha256("milpa-preepoch-v1:" ++ canonical_bytes(sorted_deduped(S)))

``sorted_deduped(S)``: exact-duplicate ``PreEpochIdentity`` records removed
(structural equality on the 4-tuple), the remainder sorted by:

  1. ``namespace`` — lexicographic (Python ``str`` ``<``, i.e. by Unicode
     code point — both impls compare the UTF-8-decoded string, not raw
     bytes, so this is well-defined for non-ASCII namespaces too).
  2. ``name`` — lexicographic, same rule.
  3. ``version`` — ``version.py``'s ``Version`` PRECEDENCE ORDER when the
     raw string parses as a valid semver (``parse_version`` succeeds);
     NEVER an ad-hoc string sort.  A raw version string that fails to parse
     sorts AFTER every parseable version, and unparseable versions among
     themselves are ordered by their raw string bytes (a corner case not
     expected in a real frozen pre-epoch set — registry entries are
     semver-validated at publish time — but must still be deterministic
     for cross-impl parity).
  4. ``content_hash`` — lexicographic, final tiebreak.

``canonical_bytes``: each identity record is encoded as
``namespace + "\\x1f" + name + "\\x1f" + version + "\\x1f" + content_hash``
(UTF-8) — the SAME closed-field-set convention
``index_ratchet_seam._provenance_canonical_raw`` already uses elsewhere in
this codebase (``\\x1f`` UNIT SEPARATOR between fields).  Records are joined,
IN SORTED ORDER (not re-sorted by their encoding — the sort key above is
computed on TYPED values, not on the encoded string), by ``"\\x1e"`` RECORD
SEPARATOR.  An empty ``S`` encodes as ``b""`` (the domain prefix alone).

The ``"milpa-preepoch-v1:"`` domain-separation prefix (D16 "hash hygiene")
ensures ``C`` cannot collide with a hash of the same bytes computed for an
unrelated purpose elsewhere in the system.

**Rust mirror requirement**: ``canonical_preimage`` must reproduce this
exact byte sequence for the same logical ``S`` — field order, separator
bytes, sort key, domain prefix, and the empty-``S`` case — for ``C`` to be
byte-identical across implementations (spec §3.4.8 NORMATIVE).

Composed verification reuse (D15)
-----------------------------------
The commitment MUST be authenticated by the SAME composed pipeline
(Fulcio cert-chain + DSSE + Rekor inclusion) ``index_trust.py`` uses for
the whole-index bundle — inclusion-proof-only is forgeable (any OIDC
identity can write to Rekor).  Rather than re-implementing that pipeline,
this module reuses ``index_trust.verify_index_bundle`` / the
``IndexBundleVerifier`` protocol DIRECTLY: the canonical preimage bytes
(``canonical_preimage(S)``, INCLUDING the domain prefix) are passed as
``verify_index_bundle``'s ``index_bytes`` parameter.  Because
``verify_index_bundle`` already checks
``sha256(index_bytes) == DSSE_subject_digest`` (both PRE-crypto, from the
unverified payload, and POST-crypto, from the verified payload — see that
function's docstring), passing the canonical preimage as ``index_bytes``
makes ``sha256(index_bytes) == C`` by construction, and
``verify_index_bundle``'s existing digest check becomes EXACTLY the
"confirm the verified statement's subject digest equals C" step spec
§3.4.9 requires — zero new crypto code, and the SAME
``SigstoreVerifier`` / ``MockVerifier`` classes serve both whole-index and
epoch-commitment verification (only ``expected_signer`` differs — a
dedicated re-arm signer identity, D15).  ``max_age_seconds`` is always
``None``: per §3.4.9, a verified commitment "never needs re-verification
against a wall-clock bound" (S is frozen, E is a fixed historical
timestamp) — there is no freshness axis for this artifact class.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from milpa.errors import (
    TNG_INDEX_EPOCH_COMMITMENT_INVALID,
    TNG_INDEX_EPOCH_RATCHET_REQUIRED,
    MilpaError,
)
from milpa.index_trust import TrustBundle, Trusted, describe_index_bundle, verify_index_bundle
from milpa.version import parse_version

if TYPE_CHECKING:
    from milpa.index_trust import IndexBundleVerifier
    from milpa.trust import TrustPolicy

# ---------------------------------------------------------------------------
# DEFAULT_REARM_SIGNER — placeholder pending tianguis's commitment-emission
# workflow (RFC §6 S-EpochCommitment: "coordinate before this slice" — the
# cross-repo prerequisite is NOT part of this Python-side build).  Mirrors
# index_trust.DEFAULT_INDEX_SIGNER's naming convention with a DEDICATED
# workflow path (D15: "distinct from the whole-index signer identity").
# Replace with the real re-arm workflow's OIDC job_workflow_ref once
# tianguis ships it.
# ---------------------------------------------------------------------------

DEFAULT_REARM_SIGNER = (
    "https://github.com/coreyleavitt/tianguis/.github/workflows/"
    "attest-epoch-commitment.yaml@refs/heads/main"
)

#: Domain-separation prefix (D16 hash hygiene).
_DOMAIN_PREFIX = b"milpa-preepoch-v1:"

_FIELD_SEP = "\x1f"
_RECORD_SEP = "\x1e"

_COMMITMENT_POINTER_RE = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Identity + canonical construction (D16/D17)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class PreEpochIdentity:
    """``(namespace, name, version, content_hash)`` — the D16 identity tuple.

    ``namespace`` MUST be included (D16): dropping it lets an attacker
    publish a byte-for-byte copy of another namespace's package under a
    different namespace and free-ride on its pre-epoch (grandfathered)
    status via an identical ``(name, version, content_hash)`` tuple —
    see spec §3.4.8's REJECTED-attack note.
    """

    namespace: str
    name: str
    version: str
    content_hash: str


def _version_sort_key(version: str) -> tuple[Any, ...]:
    """Sort key for ``version`` — ``version.py``'s ``Version`` precedence
    order when parseable, never an ad-hoc string sort (spec §3.4.8
    NORMATIVE). Unparseable strings sort after every parseable version, via
    a leading discriminator tag (``0`` = parseable, ``1`` = not) so the two
    buckets are never directly compared element-by-element."""
    v = parse_version(version)
    if v is not None:
        return (0, *v._precedence_key())
    return (1, version)


def _identity_sort_key(identity: PreEpochIdentity) -> tuple[Any, ...]:
    # The raw ``version`` string is the FINAL tiebreak so the order is TOTAL
    # over the full 4-tuple. Without it the key is non-total: two distinct
    # identities that share ``(namespace, name, content_hash)`` and parse to
    # the SAME version precedence but differ in raw version string (e.g.
    # ``"1.0"`` vs ``"1.0.0"`` on identical bytes) would collide on the sort
    # key, making the order input-dependent and ``C`` non-byte-identical
    # across impls — defeating D16's cross-impl determinism guarantee. The
    # Rust mirror MUST append the same raw-string tiebreak.
    return (
        identity.namespace,
        identity.name,
        _version_sort_key(identity.version),
        identity.content_hash,
        identity.version,
    )


def sorted_deduped(identities: "list[PreEpochIdentity] | tuple[PreEpochIdentity, ...]") -> tuple[PreEpochIdentity, ...]:
    """Exact-duplicate removal + the D16/§3.4.8 sort order.

    Deduplication is structural equality on the full 4-tuple (a dataclass's
    default ``__eq__``) — two records differing in ANY field are distinct.
    """
    deduped = list(dict.fromkeys(identities))  # stable, hashable-dataclass dedup
    return tuple(sorted(deduped, key=_identity_sort_key))


def _encode_identity(identity: PreEpochIdentity) -> str:
    return _FIELD_SEP.join(
        (identity.namespace, identity.name, identity.version, identity.content_hash)
    )


def canonical_bytes(identities: "list[PreEpochIdentity] | tuple[PreEpochIdentity, ...]") -> bytes:
    """``sorted_deduped(S)`` encoded per the module docstring's "Canonical
    construction" — NOT including the domain-separation prefix (see
    ``canonical_preimage`` for the full preimage)."""
    ordered = sorted_deduped(identities)
    return _RECORD_SEP.join(_encode_identity(i) for i in ordered).encode("utf-8")


def canonical_preimage(identities: "list[PreEpochIdentity] | tuple[PreEpochIdentity, ...]") -> bytes:
    """The full ``C`` preimage: domain prefix ++ ``canonical_bytes(S)``."""
    return _DOMAIN_PREFIX + canonical_bytes(identities)


def commitment_digest(identities: "list[PreEpochIdentity] | tuple[PreEpochIdentity, ...]") -> str:
    """``C = sha256(canonical_preimage(S))`` — lowercase hex, 64 chars."""
    return hashlib.sha256(canonical_preimage(identities)).hexdigest()


# ---------------------------------------------------------------------------
# EpochCommitmentStatus — closed union (D14), mirrors registry.AttestationKind
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Unarmed:
    """``attestation-epoch-commitment`` absent from the index root — the
    natural, unconditional default (spec §3.4.8 NORMATIVE (EpochCommitmentStatus))."""


@dataclasses.dataclass(frozen=True)
class Armed:
    """The commitment is present, fetched, and composed-verified.

    ``identities`` — the verified enumerated pre-epoch set ``S`` (D17):
    membership is a plain local set-containment test against this set, no
    recomputation, no proof machinery.

    ``integrated_time`` — ``E``, the Rekor SET ``integratedTime`` of the
    fully-verified commitment entry (unix epoch seconds) — NOT an
    operator-supplied date.
    """

    identities: frozenset[PreEpochIdentity]
    integrated_time: int


@dataclasses.dataclass(frozen=True)
class ArmingInvalid:
    """The commitment is present but failed to verify: unfetchable,
    malformed, ``hash(S) != C``, or a composed-verification failure (bad
    cert chain, bad DSSE signature, bad Rekor inclusion, wrong signer).

    ``reason`` is a short machine-stable tag for diagnostics; it is NOT
    itself part of the cross-impl contract (only the ``ArmingInvalid``
    variant + the raised slug are).
    """

    reason: str


#: Closed set (spec §3.4.8 NORMATIVE (EpochCommitmentStatus)).
EpochCommitmentStatus = Unarmed | Armed | ArmingInvalid


# ---------------------------------------------------------------------------
# Sidecar payload parsing (§3.4.9) — pure, pre-crypto
# ---------------------------------------------------------------------------


def parse_sidecar_payload(
    payload_bytes: bytes,
) -> "tuple[tuple[PreEpochIdentity, ...], bytes] | None":
    """Parse the acquired sidecar bytes into ``(S, sigstore_bundle_bytes)``.

    Wire shape (this consumer's contract — the byte-exactness requirement
    for cross-impl parity applies to ``canonical_preimage``, NOT to this
    envelope; both impls parse this JSON into the same typed
    ``PreEpochIdentity`` tuples and independently recompute the canonical
    encoding, so the envelope itself has freedom of shape as long as both
    impls agree on it)::

        {
          "identities": [
            {"namespace": "...", "name": "...", "version": "...", "content_hash": "..."},
            ...
          ],
          "bundle": { ...Sigstore bundle JSON, §3.4.3 shape... }
        }

    Returns ``None`` on ANY structural malformation (not a JSON object,
    missing/malformed ``identities``, missing/non-object ``bundle``) — the
    caller maps this to ``ArmingInvalid`` (pre-crypto parse failure, mirrors
    ``index_trust.verify_index_bundle``'s ``BundleMalformed`` step 1).
    """
    try:
        payload: dict[str, Any] = json.loads(payload_bytes)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    raw_identities = payload.get("identities")
    if not isinstance(raw_identities, list):
        return None

    identities: list[PreEpochIdentity] = []
    for entry in raw_identities:
        if not isinstance(entry, dict):
            return None
        try:
            namespace = entry["namespace"]
            name = entry["name"]
            version = entry["version"]
            content_hash = entry["content_hash"]
        except KeyError:
            return None
        if not all(isinstance(f, str) for f in (namespace, name, version, content_hash)):
            return None
        identities.append(
            PreEpochIdentity(
                namespace=namespace, name=name, version=version, content_hash=content_hash
            )
        )

    raw_bundle = payload.get("bundle")
    if not isinstance(raw_bundle, dict):
        return None
    try:
        bundle_bytes = json.dumps(raw_bundle).encode("utf-8")
    except (TypeError, ValueError):
        return None

    return tuple(identities), bundle_bytes


# ---------------------------------------------------------------------------
# The phase itself (D14) — pure: caller has already fetched sidecar bytes
# ---------------------------------------------------------------------------


def evaluate_epoch_commitment(
    *,
    pointer: "str | None",
    sidecar_bytes: "bytes | None",
    fetch_failed: bool,
    verifier: "IndexBundleVerifier",
    trust_bundle: TrustBundle,
    expected_signer: str,
) -> EpochCommitmentStatus:
    """The full §3.4.8/§3.4.9 phase, given already-acquired inputs.

    Parameters
    ----------
    pointer:
        The on-index ``attestation-epoch-commitment`` value, or ``None`` if
        the root field is absent.
    sidecar_bytes:
        The acquired (cached-or-fetched) sidecar payload bytes, or ``None``
        when acquisition was never attempted (``pointer is None``) or
        failed.
    fetch_failed:
        ``True`` when the caller attempted to acquire the sidecar (network
        fetch or cache read) and it failed — distinct from
        ``pointer is None`` (never attempted).
    verifier, trust_bundle, expected_signer:
        The SAME ``IndexBundleVerifier`` protocol / composition
        ``index_trust.py`` uses (see module docstring, "Composed
        verification reuse") — ``expected_signer`` is the DEDICATED re-arm
        signer identity (D15), never the whole-index signer.

    Returns
    -------
    ``Unarmed`` when ``pointer is None``. ``ArmingInvalid`` on any
    acquisition, parse, digest, or crypto failure. ``Armed`` only when
    every step succeeds.

    Never raises — mirrors ``verify_index_bundle``'s "pure, never raises"
    discipline; the caller (``enforce_epoch_commitment``) converts
    ``ArmingInvalid`` to the raised slug.
    """
    if pointer is None:
        return Unarmed()

    if not _COMMITMENT_POINTER_RE.match(pointer):
        return ArmingInvalid(reason="malformed commitment pointer")

    if fetch_failed or sidecar_bytes is None:
        return ArmingInvalid(reason="sidecar unfetchable")

    parsed = parse_sidecar_payload(sidecar_bytes)
    if parsed is None:
        return ArmingInvalid(reason="sidecar malformed")
    identities, bundle_bytes = parsed

    computed = commitment_digest(identities)
    if computed != pointer:
        return ArmingInvalid(reason="hash(S) != C")

    preimage = canonical_preimage(identities)
    result = verifier.verify(
        index_bytes=preimage,
        bundle_bytes=bundle_bytes,
        trust_bundle=trust_bundle,
        expected_signer=expected_signer,
        max_age_seconds=None,  # never a freshness axis for this artifact (§3.4.9)
    )
    if result is not Trusted:
        return ArmingInvalid(reason=result.value)

    info = describe_index_bundle(bundle_bytes)
    if info is None:  # pragma: no cover — verify_index_bundle already parsed integratedTime
        return ArmingInvalid(reason="sidecar bundle malformed")

    return Armed(identities=frozenset(identities), integrated_time=info.integrated_time)


# ---------------------------------------------------------------------------
# Enforcement (fail-closed, never a downgrade — spec §3.4.8 NORMATIVE
# (fail-closed abort, never a downgrade))
# ---------------------------------------------------------------------------


def enforce_epoch_commitment(status: EpochCommitmentStatus) -> None:
    """Raise ``TNG-INDEX-EPOCH-COMMITMENT-INVALID`` on ``ArmingInvalid``.

    Unconditional — no policy parameter. Spec §3.4.8 NORMATIVE: this
    failure MUST NOT downgrade to a warning "under any entry-trust policy
    value"; a corrupted index-scoped fact has no warn tier to degrade into
    (mirrors D4/D11's index-scoped-vs-entry-scoped asymmetry). ``Unarmed``
    and ``Armed`` are both silent successes at this call.
    """
    if isinstance(status, ArmingInvalid):
        raise MilpaError(
            TNG_INDEX_EPOCH_COMMITMENT_INVALID,
            "epoch-commitment verification failed "
            f"({status.reason}) — the registry's pre-epoch set commitment "
            "could not be authenticated; this aborts the resolve "
            "unconditionally (not policy-gated)",
            reason=status.reason,
        )


def check_epoch_ratchet_requirement(
    status: EpochCommitmentStatus,
    *,
    entry_trust_policy: "TrustPolicy",
    index_history_policy: "TrustPolicy",
) -> None:
    """The D18 co-requirement: ``Armed`` + ``entry-trust=strict`` requires
    ``index-history=strict``, else ``TNG-INDEX-EPOCH-RATCHET-REQUIRED``.

    Rationale (spec §3.4.8 NORMATIVE (D18 co-requirement)): Rekor gives
    immutability, never exclusivity — nothing in the composed-verification
    check stops a compromised registry from logging a SECOND valid
    commitment over a different ``S``. "Only the first commitment counts"
    is a set-once property enforced ONLY by the ``index-history`` ratchet's
    ``Append-once`` dominance fold applied to this phase's own root field.
    Arming under ``entry-trust=strict`` without ``index-history=strict`` is
    a configuration that ships a false security claim.

    ``Unarmed`` never triggers this check (an unarmed registry is
    unaffected on the ``index-history`` axis, spec non-goal preserved).
    """
    if not isinstance(status, Armed):
        return
    if entry_trust_policy != "strict":
        return
    if index_history_policy == "strict":
        return
    raise MilpaError(
        TNG_INDEX_EPOCH_RATCHET_REQUIRED,
        "entry-trust \"strict\" combined with an armed epoch commitment "
        "requires index-history \"strict\" for this registry — the "
        "commitment's set-once guarantee is enforced only by the "
        "index-history ratchet's Append-once dominance fold; arming under "
        "a weaker index-history policy would ship a false security claim "
        "(spec §3.4.8 D18 co-requirement)",
        entry_trust_policy=entry_trust_policy,
        index_history_policy=index_history_policy,
    )
