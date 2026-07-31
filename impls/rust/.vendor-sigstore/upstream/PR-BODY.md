# Do not verify DSSE `envelopeHash` against protobuf re-serialization

Fixes #608.

## Problem

`CheckedBundle::tlog_entry_for_dsse` compares the Rekor tlog `spec.envelopeHash` to `sha256(serde_json::to_vec(&dsse))`. Rekor's `envelopeHash` is the sha256 of the **raw client-submitted** envelope bytes; for `cosign attest-blob --new-bundle-format` v0.3 bundles those are cosign's Go `json.Marshal` form (`payloadType`-first, `keyid` always present), which differs from the protobuf-JSON serialization this crate recomputes (`payload`-first, `keyid` omitted). The bytes differ, so the hashes differ, and valid bundles are rejected with a transparency-log error. sigstore-python accepts the same bundles because it does not perform this check. See the linked issue for a fully reproduced case (Rekor logIndex 2086326142).

## Change

Remove the `envelopeHash` cross-check and the now-unused `envelope_json` field it required (the field was only ever read to feed this check). The entry↔bundle binding (CVE-2022-36056) is fully preserved by the checks that remain in the same function — `payloadHash == sha256(payload)`, tlog signature == bundle signature, tlog verifier cert == bundle cert — plus the DSSE signature verified over the PAE, which canonically binds `payloadType` and `payload`. `envelopeHash` was a serialization-coupled duplicate of those bindings, so removing it opens no attack surface.

This brings the verifier in line with both reference clients: sigstore-python and sigstore-go each verify a `dsse/0.0.1` entry via payload-hash + signature and neither checks `envelopeHash`. sigstore-python's source even documents why — the dsse entry "record[s] an envelope hash that we *cannot* verify (the envelope is uncanonicalized JSON)". See the linked issue for the citations.

If you would prefer to keep the check as a non-fatal `warn!` rather than remove it, I am happy to adjust.

## Also

- Removes an orphaned doc comment above `mod tests` that described a non-existent envelopeHash-canonicalization function.
- Drops the two `#[case]`s in `dsse_tlog_entry_rejects_tampered_body` that asserted rejection on a tampered `envelopeHash` (no longer applicable). The retained cases still cover the binding-carrying checks 2–4, and `dsse_tlog_entry_accepts_real_fixture` continues to pass.

## Testing

Against this branch (rustc 1.95.0):

- `cargo clippy --lib` — clean, no new warnings.
- `cargo test --lib bundle::verify` — `20 passed; 0 failed` (including `dsse_tlog_entry_accepts_real_fixture` and the retained `dsse_tlog_entry_rejects_tampered_body` cases covering checks 2–4).
- `rustfmt --edition 2024 --check` — clean on the touched files.

Verified end-to-end downstream: a real `cosign attest-blob --new-bundle-format` bundle that this crate rejected before this change now verifies successfully, with the DSSE signature, payloadHash, signature, certificate, and offline Rekor inclusion all still checked. The false-rejection reproduces against a real public Rekor entry, logIndex 2086326142 (see the linked issue).
