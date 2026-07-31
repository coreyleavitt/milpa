# DSSE bundle verification rejects valid `cosign attest-blob` v0.3 bundles (envelopeHash re-serialization mismatch)

**Component:** `sigstore::bundle::verify` (`CheckedBundle::tlog_entry_for_dsse`)
**Version:** 0.14.0 (also present on `main` at time of writing)
**Impact:** valid, real-world keyless DSSE bundles fail verification with a transparency-log error.

## Summary

`CheckedBundle::tlog_entry_for_dsse` cross-checks the Rekor transparency-log entry's `spec.envelopeHash` against a locally recomputed `sha256(serde_json::to_vec(&dsse))`, where `dsse` is the decoded protobuf `DsseEnvelope`. That recomputation does **not** reproduce the bytes Rekor actually hashed for DSSE bundles produced by `cosign attest-blob --new-bundle-format`, so the check fails and the bundle is rejected — even though the bundle is authentic and every cryptographic binding is intact. sigstore-python's reference verifier does not perform this check and accepts the same bundles.

## Root cause

Rekor's `dsse` entry type sets `spec.envelopeHash` to the sha256 of the **raw client-submitted envelope bytes** — it does not canonicalize them. For `cosign attest-blob`, those bytes are cosign's Go `encoding/json` marshalling of the DSSE envelope (`github.com/secure-systems-lab/go-securesystemslib/dsse`): field order **payloadType, payload, signatures**, and `signatures[].keyid` is **always present** (`""` when empty — the struct field has no `omitempty`).

`serde_json::to_vec(&dsse)` on the prost-generated `DsseEnvelope` produces a different byte string: field order follows the protobuf field tags (**payload, payloadType, signatures**), and `keyid` is **omitted** when empty.

Different bytes ⇒ different sha256 ⇒ the equality check fails.

(This is specific to the client serialization, not a Rekor defect. Bundles produced via the image-signing / sigstore-go path already emit protojson and happen to round-trip through this check, which is why the bug only shows up on some cosign code paths.)

## Reproduction

A real, publicly logged fixture (keyless GitHub-Actions OIDC, `cosign attest-blob --new-bundle-format`):

- **Rekor logIndex:** `2086326142`
- **Recorded `envelopeHash`:** `d66676bef2f8207987d1063f66a56892c62e7bbe975ea3b245681d25820e977d`

Hashing the two candidate serializations of that bundle's envelope:

| Serialization | sha256 | matches Rekor |
|---|---|:-:|
| cosign Go `json.Marshal` (payloadType-first, `keyid` present) | `d66676bef2f8207987d1063f66a56892c62e7bbe975ea3b245681d25820e977d` | yes |
| protobuf-JSON (payload-first, `keyid` omitted) — what this crate recomputes | `3e4b489b6b9186c8e5acd74b2eaf8baecb0230c04796b1354a8c299339391b44` | no |

Minimal check against any such bundle JSON:

```python
import base64, hashlib, json
b = json.load(open("bundle.json"))
rec = json.loads(base64.b64decode(
    b["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"]))["spec"]["envelopeHash"]["value"]
env = b["dsseEnvelope"]
pt, payload = env["payloadType"], env["payload"]
s = env["signatures"][0]
go = ('{"payloadType":"%s","payload":"%s","signatures":[{"keyid":"%s","sig":"%s"}]}'
      % (pt, payload, s.get("keyid",""), s.get("sig",""))).encode()
print(hashlib.sha256(go).hexdigest() == rec)  # True — Rekor hashed the Go form
```

Any bundle from `cosign attest-blob --new-bundle-format <blob>` (keyless or key-based) reproduces the rejection when passed through `Bundle` verification on 0.14.0.

## Why the check is safe to drop / soften

The `envelopeHash` cross-check is redundant. The entry↔bundle binding that matters (CVE-2022-36056: a tlog entry must correspond to *this* envelope, not a substituted one) is already fully carried, in the same function, by the serialization-independent checks that follow:

1. `spec.payloadHash == sha256(payload_bytes)` — binds the payload;
2. `spec.signatures[0].signature == bundle signature` — binds the signature;
3. `spec.signatures[0].verifier == bundle signing certificate` — binds the signer;

together with the DSSE signature itself, which is verified over the PAE (`DSSEv1 <len> <payloadType> <len> <payload>`), canonically binding `payloadType` **and** `payload`. Every component `envelopeHash` covers is already bound by a canonical check. `envelopeHash` adds a serialization-coupled duplicate of those bindings and nothing else.

### The reference clients agree — they deliberately skip envelopeHash

This is not a novel interpretation. Both reference Sigstore clients verify a `dsse/0.0.1` transparency-log entry using exactly the payload-hash + signature checks above, and neither checks `envelopeHash` (zero references to it in their verification code):

- **sigstore-python** handles this exact entry type in `_validate_dsse_v001_entry_body` (`sigstore/verify/verifier.py`): it checks `payload_hash == sha256(payload)` and that the entry's signature list matches the bundle, and nothing else. Its own source comment states the reason directly:

  > *Rekor v1 used a dsse/0.0.1 entry … dsse entries record an envelope hash that we **cannot** verify (the envelope is uncanonicalized JSON), so we manually pick apart the entry body and verify the parts we can (payload hash and signature list).*

- **sigstore-go** does the same in `pkg/verify/tlog.go` (the `EnvelopeContent` branch): it compares `sha256(payload)` to the entry's DSSE payload hash and the entry signature to the bundle signature — no `EnvelopeHash` handling anywhere in `pkg/`.

So `cosign attest-blob --new-bundle-format` bundles are a normal, first-class verification path in the reference implementations, and this crate's `envelopeHash` re-check is the outlier that makes them fail here.

## Proposed remedies (maintainers' call)

1. **Remove the check** (matches sigstore-python). Simplest; loses nothing per the redundancy argument above. A patch implementing exactly this is attached to the PR.
2. **Make it non-fatal** — `warn!` on mismatch instead of returning `None`. Keeps the signal for protojson-path bundles without rejecting valid Go-form ones.
3. **Reproduce Rekor's client bytes** — recompute `envelopeHash` over the exact submitted serialization. This is brittle (it must track cosign's Go marshalling precisely, across versions) and, given (1), buys no additional security.

Recommendation: (1), with (2) as a conservative alternative.

## Drive-by

The doc comment immediately above `#[cfg(test)] mod tests` in `models.rs` ("Builds the canonical JSON representation of a DSSE envelope that Rekor uses when computing `envelopeHash` …") documents a function that does not exist — it is an orphaned doc comment attached to the test module. The attached PR removes it.

## Related

- #596 — a separate DSSE bundle-verification false-rejection (multi-subject statements: only the first `subject` digest is checked). Distinct root cause, same `bundle/verify` module.

---

*Reported from the [milpa](https://github.com/coreyleavitt/milpa) project, which vendors a one-line patch of this fix to consume real `cosign attest-blob` attestations. Happy to adjust the PR to whichever remedy you prefer.*
