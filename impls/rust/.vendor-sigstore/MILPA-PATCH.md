# Vendored, patched `sigstore` (v0.14.0) — TEMPORARY

This is the upstream `sigstore` crate v0.14.0 (Apache-2.0; original LICENSE retained)
with **one** milpa bug-fix, consumed via `[patch.crates-io]` in `impls/rust/Cargo.toml`.

## The single change
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

## Why vendored (for now)
RFC `rfc-attestation-verifier` S5. Self-contained so milpa + CI build without an external
fork. TO BE REPLACED by an upstream sigstore-rs PR (folds into S7); once merged/released,
delete this directory and the `[patch]` stanza. Regenerate the base from
`git clone --branch v0.14.0 https://github.com/sigstore/sigstore-rs` and re-apply the diff.
