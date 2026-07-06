# Vendored, patched `sigstore` (v0.14.0) — TEMPORARY

This is the upstream `sigstore` crate v0.14.0 (Apache-2.0; original LICENSE retained)
with **one** milpa bug-fix, consumed via `[patch.crates-io]` in `impls/rust/Cargo.toml`.

## The single change
`src/bundle/verify/models.rs`, `CheckedBundle::tlog_entry_for_dsse`: the DSSE
`envelopeHash` consistency check is **removed**. Upstream compared the Rekor tlog
`envelopeHash` to `sha256(serde_json::to_vec(&dsse))` — a protobuf-serde re-serialization
that does NOT reproduce the canonical DSSE envelope bytes Rekor hashed for real
`cosign attest-blob --new-bundle-format` v0.3 bundles, causing false
`Signature(Transparency)` rejections of valid bundles (which sigstore-python accepts).
The entry↔bundle binding (CVE-2022-36056) is fully preserved by the checks that remain:
payloadHash == sha256(payload), tlog signature == bundle signature, and tlog verifier
cert == bundle cert, plus the DSSE signature over the PAE (covering payloadType).

## Why vendored (for now)
RFC `rfc-attestation-verifier` S5. Self-contained so milpa + CI build without an external
fork. TO BE REPLACED by an upstream sigstore-rs PR (folds into S7); once merged/released,
delete this directory and the `[patch]` stanza. Regenerate the base from
`git clone --branch v0.14.0 https://github.com/sigstore/sigstore-rs` and re-apply the diff.
