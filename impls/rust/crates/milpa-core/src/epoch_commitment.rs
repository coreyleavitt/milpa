//! Epoch-commitment phase — the index-gate pre-epoch set arming check.
//!
//! RFC: `docs/rfc-attestation-v1-normative.md` §6 slice **S-EpochCommitment**,
//! decisions D14-D18. Spec: `spec/registry-protocol.md` §3.4.8 (the phase)
//! and §3.4.9 (sidecar acquisition). Mirrors `impls/python/milpa/epoch_commitment.py`
//! field-for-field.
//!
//! This module is **pure computation** — no filesystem I/O, no network — the
//! same discipline `index_ratchet_seam.rs` and `index_trust::verify_index_bundle`
//! follow. Acquisition (fetching and caching the commitment sidecar) is a
//! separate, injected-I/O concern layered on top by `index_cache.rs` / the CLI.
//!
//! # Canonical construction (D16/D17, spec §3.4.8 NORMATIVE) — the SINGLE most
//! cross-impl-critical piece of this module: [`canonical_preimage`] MUST
//! reproduce `epoch_commitment.py::canonical_preimage` byte-for-byte.
//!
//! ```text
//! C = sha256("milpa-preepoch-v1:" ++ canonical_bytes(sorted_deduped(S)))
//! ```
//!
//! `sorted_deduped(S)`: exact-duplicate [`PreEpochIdentity`] records removed
//! (structural equality on the 4-tuple), the remainder sorted by:
//!
//!   1. `namespace` — lexicographic (Unicode code point / UTF-8 byte order —
//!      both coincide for well-formed UTF-8 `String` comparison).
//!   2. `name` — lexicographic, same rule.
//!   3. `version` — the [`milpa_types::Version`] PRECEDENCE ORDER when the raw
//!      string parses (`milpa_solver::parse_version` succeeds); NEVER an
//!      ad-hoc string sort. An unparseable raw version string sorts AFTER
//!      every parseable version (two disjoint buckets, tagged so they never
//!      compare element-wise), and unparseable versions among themselves are
//!      ordered by their raw string.
//!   4. `content_hash` — lexicographic, next tiebreak.
//!   5. the RAW `version` string — the FINAL tiebreak making the order TOTAL.
//!      Without it, `1.0.0` vs `1.0.0+build` (precedence-equal, distinct)
//!      collide on the sort key, making `C` input-order-dependent and
//!      non-byte-identical across impls — defeating D16's cross-impl
//!      determinism guarantee.
//!
//! `canonical_bytes`: each identity record is encoded as
//! `namespace + "\x1f" + name + "\x1f" + version + "\x1f" + content_hash`
//! (UTF-8) — the same closed-field-set convention
//! `index_ratchet_seam::provenance_canonical_raw` uses elsewhere (`\x1f` UNIT
//! SEPARATOR between fields). Records are joined, IN SORTED ORDER, by
//! `"\x1e"` RECORD SEPARATOR. An empty `S` encodes as `b""` (the domain
//! prefix alone).
//!
//! The `"milpa-preepoch-v1:"` domain-separation prefix (D16 hash hygiene)
//! ensures `C` cannot collide with a hash of the same bytes computed for an
//! unrelated purpose elsewhere in the system.
//!
//! # Composed verification reuse (D15)
//!
//! The commitment MUST be authenticated by the SAME composed pipeline
//! (Fulcio cert-chain + DSSE + Rekor inclusion) `index_trust.rs` uses for the
//! whole-index bundle — inclusion-proof-only is forgeable. This module
//! reuses the [`crate::index_trust::IndexBundleVerifier`] trait directly: the
//! canonical preimage bytes ([`canonical_preimage`], INCLUDING the domain
//! prefix) are passed as the verifier's `index_bytes` parameter. Because the
//! composed verifier already checks `sha256(index_bytes) == DSSE_subject_digest`,
//! passing the canonical preimage as `index_bytes` makes
//! `sha256(index_bytes) == C` by construction — zero new crypto code. Only
//! `expected_signer` differs (a dedicated re-arm signer identity, D15).
//! `max_age_seconds` is always `None` — per §3.4.9, a verified commitment
//! never needs re-verification against a wall-clock bound (`S` is frozen, `E`
//! is a fixed historical timestamp). R3-g: this holds the `S`/`C` preimage
//! locally, so the unpatched `verify_digest` composition already works —
//! no dependency on the (unbuilt) S-RustCrypto D7 patch.

use std::collections::HashSet;

use milpa_manifest::TrustPolicy;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, MilpaError};
use crate::index_trust::{describe_index_bundle, IndexBundleVerifier, TrustBundle, VerificationResult};

fn tng(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::Tianguis(code, message.into()))
}

// ---------------------------------------------------------------------------
// DEFAULT_REARM_SIGNER — placeholder pending tianguis's commitment-emission
// workflow (RFC §6 S-EpochCommitment: the cross-repo prerequisite is NOT
// part of this build). Mirrors `index_trust::DEFAULT_INDEX_SIGNER`'s naming
// convention with a DEDICATED workflow path (D15: "distinct from the
// whole-index signer identity"). Byte-identical to the Python constant.
// ---------------------------------------------------------------------------

pub const DEFAULT_REARM_SIGNER: &str = "https://github.com/coreyleavitt/tianguis/.github/workflows/\
     attest-epoch-commitment.yaml@refs/heads/main";

/// Domain-separation prefix (D16 hash hygiene).
const DOMAIN_PREFIX: &[u8] = b"milpa-preepoch-v1:";
const FIELD_SEP: char = '\u{1f}';
const RECORD_SEP: char = '\u{1e}';

// ---------------------------------------------------------------------------
// Identity + canonical construction (D16/D17)
// ---------------------------------------------------------------------------

/// `(namespace, name, version, content_hash)` — the D16 identity tuple.
///
/// `namespace` MUST be included (D16): dropping it lets an attacker publish
/// a byte-for-byte copy of another namespace's package under a different
/// namespace and free-ride on its pre-epoch (grandfathered) status via an
/// identical `(name, version, content_hash)` tuple — see spec §3.4.8's
/// REJECTED-attack note.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreEpochIdentity {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub content_hash: String,
}

/// Sort key for `version` — the [`milpa_types::Version`] precedence order
/// when parseable, never an ad-hoc string sort (spec §3.4.8 NORMATIVE).
/// `Parseable` always sorts before `Unparseable` (derived `Ord` compares by
/// declaration order first) — the two-bucket tag Python encodes as a leading
/// `(0, ...)` / `(1, ...)` discriminator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum VersionSortKey {
    Parseable(u64, u64, u64, u8, Vec<milpa_types::PreId>),
    Unparseable(String),
}

fn version_sort_key(version: &str) -> VersionSortKey {
    match milpa_solver::parse_version(version) {
        Some(v) => {
            let is_release: u8 = if v.pre.is_empty() { 1 } else { 0 };
            VersionSortKey::Parseable(v.major, v.minor, v.patch, is_release, v.pre.clone())
        }
        None => VersionSortKey::Unparseable(version.to_string()),
    }
}

/// The full identity sort key `(namespace, name, version_precedence, content_hash,
/// RAW version string)`. The raw `version` string is the FINAL tiebreak so the
/// order is TOTAL over the full 4-tuple (see module docstring).
fn identity_sort_key(id: &PreEpochIdentity) -> (String, String, VersionSortKey, String, String) {
    (
        id.namespace.clone(),
        id.name.clone(),
        version_sort_key(&id.version),
        id.content_hash.clone(),
        id.version.clone(),
    )
}

/// Exact-duplicate removal + the D16/§3.4.8 sort order. Deduplication is
/// structural equality on the full 4-tuple; the FIRST occurrence of a
/// duplicate is kept (stable), mirroring Python's `dict.fromkeys`.
pub fn sorted_deduped(identities: &[PreEpochIdentity]) -> Vec<PreEpochIdentity> {
    let mut seen: HashSet<&PreEpochIdentity> = HashSet::new();
    let mut deduped: Vec<PreEpochIdentity> = Vec::new();
    for id in identities {
        if seen.insert(id) {
            deduped.push(id.clone());
        }
    }
    deduped.sort_by_key(identity_sort_key);
    deduped
}

fn encode_identity(id: &PreEpochIdentity) -> String {
    format!("{}{FIELD_SEP}{}{FIELD_SEP}{}{FIELD_SEP}{}", id.namespace, id.name, id.version, id.content_hash)
}

/// `sorted_deduped(S)` encoded per the module docstring's "Canonical
/// construction" — NOT including the domain-separation prefix (see
/// [`canonical_preimage`] for the full preimage).
pub fn canonical_bytes(identities: &[PreEpochIdentity]) -> Vec<u8> {
    let ordered = sorted_deduped(identities);
    let joined: String = ordered.iter().map(encode_identity).collect::<Vec<_>>().join(&RECORD_SEP.to_string());
    joined.into_bytes()
}

/// The full `C` preimage: domain prefix ++ `canonical_bytes(S)`.
pub fn canonical_preimage(identities: &[PreEpochIdentity]) -> Vec<u8> {
    let mut out = DOMAIN_PREFIX.to_vec();
    out.extend(canonical_bytes(identities));
    out
}

/// `C = sha256(canonical_preimage(S))` — lowercase hex, 64 chars.
pub fn commitment_digest(identities: &[PreEpochIdentity]) -> String {
    hex::encode(Sha256::digest(canonical_preimage(identities)))
}

// ---------------------------------------------------------------------------
// EpochCommitmentStatus — closed union (D14), mirrors registry::AttestationKind
// ---------------------------------------------------------------------------

/// `Unarmed | Armed(identities, integrated_time) | ArmingInvalid(reason)` —
/// spec §3.4.8 NORMATIVE (EpochCommitmentStatus). `Default` is `Unarmed` —
/// `Index::parse` itself never computes this (parsing is pure, offline,
/// crypto-free); the caller that owns sidecar acquisition + composed
/// verification (`index_cache.rs` / the CLI, once per resolve) overwrites
/// this field with the real computed status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EpochCommitmentStatus {
    /// `attestation-epoch-commitment` absent from the index root — the
    /// natural, unconditional default.
    #[default]
    Unarmed,
    /// The commitment is present, fetched, and composed-verified.
    ///
    /// `identities` — the verified enumerated pre-epoch set `S` (D17):
    /// membership is a plain local set-containment test, no recomputation,
    /// no proof machinery.
    ///
    /// `integrated_time` — `E`, the Rekor SET `integratedTime` of the fully-
    /// verified commitment entry (unix epoch seconds) — NOT an
    /// operator-supplied date.
    Armed { identities: HashSet<PreEpochIdentity>, integrated_time: i64 },
    /// The commitment is present but failed to verify: unfetchable,
    /// malformed, `hash(S) != C`, or a composed-verification failure (bad
    /// cert chain, bad DSSE signature, bad Rekor inclusion, wrong signer).
    ///
    /// `reason` is a short machine-stable tag for diagnostics; it is NOT
    /// itself part of the cross-impl contract (only the `ArmingInvalid`
    /// variant + the raised slug are).
    ArmingInvalid { reason: String },
}

// ---------------------------------------------------------------------------
// Sidecar payload parsing (§3.4.9) — pure, pre-crypto
// ---------------------------------------------------------------------------

/// Parse the acquired sidecar bytes into `(S, sigstore_bundle_bytes)`.
///
/// Wire shape:
///
/// ```text
/// {
///   "identities": [
///     {"namespace": "...", "name": "...", "version": "...", "content_hash": "..."},
///     ...
///   ],
///   "bundle": { ...Sigstore bundle JSON, §3.4.3 shape... }
/// }
/// ```
///
/// Returns `None` on ANY structural malformation (not a JSON object,
/// missing/malformed `identities`, missing/non-object `bundle`) — the caller
/// maps this to `ArmingInvalid` (pre-crypto parse failure, mirrors
/// `index_trust`'s `BundleMalformed` step 1). The envelope's byte shape
/// (re-serialization) is NOT part of the cross-impl byte-exactness contract
/// — only `canonical_preimage` is; both impls independently parse this JSON
/// into typed [`PreEpochIdentity`] values and recompute the canonical
/// encoding themselves.
pub fn parse_sidecar_payload(payload_bytes: &[u8]) -> Option<(Vec<PreEpochIdentity>, Vec<u8>)> {
    let payload: serde_json::Value = serde_json::from_slice(payload_bytes).ok()?;
    let obj = payload.as_object()?;

    let raw_identities = obj.get("identities")?.as_array()?;
    let mut identities: Vec<PreEpochIdentity> = Vec::with_capacity(raw_identities.len());
    for entry in raw_identities {
        let entry_obj = entry.as_object()?;
        let namespace = entry_obj.get("namespace")?.as_str()?.to_string();
        let name = entry_obj.get("name")?.as_str()?.to_string();
        let version = entry_obj.get("version")?.as_str()?.to_string();
        let content_hash = entry_obj.get("content_hash")?.as_str()?.to_string();
        identities.push(PreEpochIdentity { namespace, name, version, content_hash });
    }

    let raw_bundle = obj.get("bundle")?;
    if !raw_bundle.is_object() {
        return None;
    }
    let bundle_bytes = serde_json::to_vec(raw_bundle).ok()?;

    Some((identities, bundle_bytes))
}

// ---------------------------------------------------------------------------
// The phase itself (D14) — pure: caller has already fetched sidecar bytes
// ---------------------------------------------------------------------------

/// `attestation-epoch-commitment` pointer shape: 64 lowercase hex chars.
fn is_valid_commitment_pointer(pointer: &str) -> bool {
    pointer.len() == 64 && pointer.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The full §3.4.8/§3.4.9 phase, given already-acquired inputs.
///
/// - `pointer`: the on-index `attestation-epoch-commitment` value, or `None`
///   if the root field is absent.
/// - `sidecar_bytes`: the acquired (cached-or-fetched) sidecar payload
///   bytes, or `None` when acquisition was never attempted (`pointer is
///   None`) or failed.
/// - `fetch_failed`: `true` when the caller attempted to acquire the
///   sidecar (network fetch or cache read) and it failed — distinct from
///   `pointer.is_none()` (never attempted).
/// - `verifier`, `trust_bundle`, `expected_signer`: the SAME
///   [`IndexBundleVerifier`] / composition `index_trust.rs` uses (see module
///   docstring, "Composed verification reuse") — `expected_signer` is the
///   DEDICATED re-arm signer identity (D15), never the whole-index signer.
///
/// Returns `Unarmed` when `pointer is None`. `ArmingInvalid` on any
/// acquisition, parse, digest, or crypto failure. `Armed` only when every
/// step succeeds. Never panics — mirrors `verify_index_bundle`'s "pure,
/// never raises" discipline.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_epoch_commitment(
    pointer: Option<&str>,
    sidecar_bytes: Option<&[u8]>,
    fetch_failed: bool,
    verifier: &dyn IndexBundleVerifier,
    trust_bundle: &TrustBundle,
    expected_signer: &str,
) -> EpochCommitmentStatus {
    let Some(pointer) = pointer else {
        return EpochCommitmentStatus::Unarmed;
    };

    if !is_valid_commitment_pointer(pointer) {
        return EpochCommitmentStatus::ArmingInvalid { reason: "malformed commitment pointer".to_string() };
    }

    if fetch_failed || sidecar_bytes.is_none() {
        return EpochCommitmentStatus::ArmingInvalid { reason: "sidecar unfetchable".to_string() };
    }
    let sidecar_bytes = sidecar_bytes.unwrap();

    let Some((identities, bundle_bytes)) = parse_sidecar_payload(sidecar_bytes) else {
        return EpochCommitmentStatus::ArmingInvalid { reason: "sidecar malformed".to_string() };
    };

    let computed = commitment_digest(&identities);
    if computed != pointer {
        return EpochCommitmentStatus::ArmingInvalid { reason: "hash(S) != C".to_string() };
    }

    let preimage = canonical_preimage(&identities);
    let result = verifier.verify(&preimage, &bundle_bytes, trust_bundle, expected_signer, None);
    if result != VerificationResult::Trusted {
        return EpochCommitmentStatus::ArmingInvalid { reason: result.value().to_string() };
    }

    let Some(info) = describe_index_bundle(&bundle_bytes) else {
        // pragma: unreachable in practice — verify_index_bundle already parsed integratedTime.
        return EpochCommitmentStatus::ArmingInvalid { reason: "sidecar bundle malformed".to_string() };
    };

    EpochCommitmentStatus::Armed { identities: identities.into_iter().collect(), integrated_time: info.integrated_time }
}

// ---------------------------------------------------------------------------
// Enforcement (fail-closed, never a downgrade — spec §3.4.8 NORMATIVE
// (fail-closed abort, never a downgrade))
// ---------------------------------------------------------------------------

/// Raise `TNG-INDEX-EPOCH-COMMITMENT-INVALID` on `ArmingInvalid`.
///
/// Unconditional — no policy parameter. Spec §3.4.8 NORMATIVE: this failure
/// MUST NOT downgrade to a warning "under any entry-trust policy value"; a
/// corrupted index-scoped fact has no warn tier to degrade into (mirrors
/// D4/D11's index-scoped-vs-entry-scoped asymmetry). `Unarmed` and `Armed`
/// are both silent successes.
pub fn enforce_epoch_commitment(status: &EpochCommitmentStatus) -> Result<(), MilpaError> {
    if let EpochCommitmentStatus::ArmingInvalid { reason } = status {
        return Err(tng(
            "TNG-INDEX-EPOCH-COMMITMENT-INVALID",
            format!(
                "epoch-commitment verification failed ({reason}) — the registry's \
                 pre-epoch set commitment could not be authenticated; this aborts \
                 the resolve unconditionally (not policy-gated)"
            ),
        ));
    }
    Ok(())
}

/// The D18 co-requirement: `Armed` + `entry-trust "strict"` requires
/// `index-history "strict"`, else `TNG-INDEX-EPOCH-RATCHET-REQUIRED`.
///
/// Rationale (spec §3.4.8 NORMATIVE (D18 co-requirement)): Rekor gives
/// immutability, never exclusivity — nothing in the composed-verification
/// check stops a compromised registry from logging a SECOND valid
/// commitment over a different `S`. "Only the first commitment counts" is a
/// set-once property enforced ONLY by the `index-history` ratchet's
/// `Append-once` dominance fold applied to this phase's own root field.
/// Arming under `entry-trust "strict"` without `index-history "strict"` is a
/// configuration that ships a false security claim.
///
/// `Unarmed` never triggers this check (an unarmed registry is unaffected on
/// the `index-history` axis, spec non-goal preserved).
pub fn check_epoch_ratchet_requirement(
    status: &EpochCommitmentStatus,
    entry_trust_policy: &TrustPolicy,
    index_history_policy: &TrustPolicy,
) -> Result<(), MilpaError> {
    if !matches!(status, EpochCommitmentStatus::Armed { .. }) {
        return Ok(());
    }
    if *entry_trust_policy != TrustPolicy::Strict {
        return Ok(());
    }
    if *index_history_policy == TrustPolicy::Strict {
        return Ok(());
    }
    Err(tng(
        "TNG-INDEX-EPOCH-RATCHET-REQUIRED",
        "entry-trust \"strict\" combined with an armed epoch commitment requires \
         index-history \"strict\" for this registry — the commitment's set-once \
         guarantee is enforced only by the index-history ratchet's Append-once \
         dominance fold; arming under a weaker index-history policy would ship a \
         false security claim (spec §3.4.8 D18 co-requirement)",
    ))
}

#[cfg(test)]
#[path = "epoch_commitment_tests.rs"]
mod epoch_commitment_tests;
