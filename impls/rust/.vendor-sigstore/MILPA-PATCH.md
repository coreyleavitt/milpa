# Vendored, patched `sigstore` (v0.14.0) — TEMPORARY

This is the upstream `sigstore` crate v0.14.0 (Apache-2.0; original LICENSE retained)
with **two** milpa bug-fixes, consumed via `[patch.crates-io]` in `impls/rust/Cargo.toml`.

## Change 1 (subtractive) — `envelopeHash` re-serialization check
`src/bundle/verify/models.rs`, `CheckedBundle::tlog_entry_for_dsse`: the DSSE
`envelopeHash` consistency check is **removed**. Upstream compared the Rekor tlog
`envelopeHash` to `sha256(serde_json::to_vec(&dsse))`. The tlog value is Rekor's sha256
over the RAW client-submitted envelope bytes; for real `cosign attest-blob
--new-bundle-format` v0.3 bundles those are cosign's Go `json.Marshal` form
(payloadType-first field order, `"keyid":""` present), whereas re-serializing the
protobuf `DsseEnvelope` produces the protobuf-JSON form (payload-first tag order, `keyid`
omitted). The two byte-strings differ, so the check false-rejects valid cosign bundles
with `Signature(Transparency)` — bundles sigstore-python's reference verifier accepts
(it skips `envelopeHash` entirely).

The problem is **not** that the hash is "unreproducible": it reproduces exactly on
protojson-path bundles (image-signing / sigstore-go). It is that (a) Rekor hashes
un-canonical, un-spec-pinned client bytes that vary across cosign's own code paths, and
(b) the check is **redundant**. The entry↔bundle binding (CVE-2022-36056) is fully
preserved by the checks that remain: payloadHash == sha256(payload), tlog signature ==
bundle signature, and tlog verifier cert == bundle cert, plus the DSSE signature over the
PAE (which canonically binds payloadType + payload). So it is dropped rather than
recomputed against a different serialization.

Executable regression (in milpa's real suite, not this crate's dead test module):
milpa-core `index_trust::tests::s5_real_bundle_verifies_trusted_end_to_end` verifies a
real cosign v0.3 bundle end-to-end and goes red if this check is ever restored.

## Change 2 (additive) — raw-digest verify entry point
`src/bundle/verify/verifier.rs`: the crate's only public verify entry points
(`Verifier::verify_digest` / `Verifier::verify`, both async and `blocking::`) require the
caller to seed a live `Sha256` hasher with the artifact's REAL preimage bytes — the
digest is computed internally via `.finalize()`. milpa's per-entry attestation gate
(`entry_trust.rs`, RFC `rfc-attestation-v1-normative.md` D7/S-RustCrypto) only ever holds
the dep's already-resolved `content_hash` **digest** — not the source tree — so it cannot
supply a hasher whose `finalize()` would equal that digest (seeding a hasher with the
digest itself would be a preimage attack, not a re-derivation).

This is **additive**, unlike Change 1: nothing is removed or weakened. `verify_digest`'s
body (everything after `.finalize()`) is extracted into a private `verify_digest_bytes`
helper parameterized over `&[u8]`; `verify_digest` now finalizes and calls the helper
(unchanged behavior, unchanged signature); a new public `verify_raw_digest(&self, digest:
&[u8], bundle, policy, offline)` calls the same helper directly, on both the async
`Verifier` and the `blocking::Verifier` wrapper (milpa's entry-trust gate uses the
blocking one). Every cryptographic check inside the helper — Fulcio cert-chain
verification, SCT, DSSE/message-signature verification, subject-digest consistency,
policy (SAN/issuer) — is byte-for-byte the same code `verify_digest` already ran; only the
hasher-finalize API step is bypassed. `verify_digest`'s own behavior (and hence Layer-1's
`index_trust.rs` call path) is unchanged.

TODO(milpa): delete `verify_raw_digest` (both variants) if/when sigstore-rs exposes a
raw-digest verify entry point upstream. Track as a distinct upstream item — separate from
#183's `envelopeHash` fix (Change 1, above) and from sigstore-rs#285 (Rekor
inclusion-proof wiring, tracked in `milpa-core::rekor_adapter`) — this is a third,
independent upstream gap. No issue has been filed upstream yet; this comment (mirrored at
the `verify_raw_digest` definitions) is the tripwire until one is.

## Why vendored (for now)
RFC `rfc-attestation-verifier` S5 (Change 1) / `rfc-attestation-v1-normative` S-RustCrypto
(Change 2). Self-contained so milpa + CI build without an external fork. TO BE REPLACED by
upstream sigstore-rs PRs; once merged/released, delete this directory and the `[patch]`
stanza. Regenerate the base from
`git clone --branch v0.14.0 https://github.com/sigstore/sigstore-rs` and re-apply the diff.
