# Session handoff — 2026-07-27 (compaction point)

Active thread = the sigstore `envelopeHash` upstream contribution. Everything else
this session is DONE or PARKED (see "Session state" at the bottom). Repo HEADs:
milpa `origin/main` (see below — handoff/RFC-doc commits pending), tianguis + nkdl +
softlink all pushed/live.

---

## ⏩ RESUME HERE — sigstore `envelopeHash` upstream (milpa #183 / rfc-attestation-verifier S7)

### Verdict (PROVEN + independently re-verified by the control loop)
Upstream sigstore-rs's DSSE `envelopeHash` tlog check (`sha256(serde_json::to_vec(&dsse))`
in `.vendor-sigstore/src/bundle/verify/models.rs`, `CheckedBundle::tlog_entry_for_dsse`)
**false-rejects real `cosign attest-blob --new-bundle-format` bundles.** milpa's vendored
patch that REMOVES the check was correctly diagnosed. Removal meets the PhD/best-in-class
bar — it's not "no fix so give up," it's that the check is **redundant**.

### Hard evidence (not hand-waved)
- Decisive bundle: `conformance/spec-v1/_oracle/attestation/index.kdl.bundle` (real cosign
  `attest-blob --new-bundle-format`, keyless GHA-OIDC, from `.github/workflows/generate-attestation-fixture.yaml`).
- Live public Rekor entry: **logIndex 2086326142**, recorded `envelopeHash = d66676be…977d`.
- Control-loop's own 12-line Python check on that fixture (no Rust, no subagent):
  - `sha256(cosign Go form)` = `d66676be…977d` → **MATCH** (payloadType-first field order, `"keyid":""` present)
  - `sha256(protobuf-JSON form)` = `3e4b489b…1b44` → **NO MATCH** (payload-first tag order, `keyid` omitted)
  - i.e. Rekor hashed cosign's Go `json.Marshal` bytes; sigstore-rs recomputes the protobuf-JSON
    form the `.bundle` stores; the two differ ⇒ guaranteed mismatch on cosign's default `dsseEntry` path.
- Mechanism traced to source: cosign (`sigstore/pkg/signature/dsse` + secure-systems-lab
  `dsse.Signature{keyid,sig}` with NO `omitempty`) → Rekor `dsse/v0.0.1 entry.go` hashes the raw
  submitted bytes (no canonicalization) → vs `sigstore-protobuf-specs` `Serialize_proto` →
  `prost_reflect` DynamicMessage (tag order, skip-default). Earlier PoC bundles matched only because
  they were produced via a *different* cosign code path (image-signing / sigstore-go) that already
  emits protojson — proof the check is serialization-fragile across cosign's own commands.

### Why removal is best-in-class (redundancy, verified in code)
The entry↔bundle binding (CVE-2022-36056) is fully carried by the RETAINED, serialization-
INDEPENDENT checks in `tlog_entry_for_dsse` + the DSSE signature verification:
- DSSE sig verified over the **PAE** (`compute_pae`, models.rs:49): `DSSEv1 <len(t)> <t> <len(p)> <p>` — canonically binds payloadType + payload.
- payloadHash == sha256(payload); tlog signature == bundle signature; tlog verifier cert == bundle cert.
- crate rejects any DSSE envelope with ≠1 signature (models.rs:110) → no multi-sig residue.
`envelopeHash` = sha256(JSON of {payloadType, payload, signatures}) — every component already
bound by the above. It's a serialization-coupled DUPLICATE of a canonical binding. Removing it
opens no attack surface. **sigstore-python's reference verifier skips `envelopeHash` too** (grep:
zero references) — independent convergence.

### NEXT STEPS (awaiting Corey's pick — was mid-decision at compaction)
1. **Draft the upstream sigstore-rs ISSUE + PR** (this is now a concrete bug report, not a soft
   soundness argument): repro = the cosign fixture bundle + Rekor logIndex 2086326142 + the
   Go-`json.Marshal`-vs-protojson diff; ask = make `envelopeHash` non-fatal / remove it, per
   sigstore-python; justification = redundant with the canonical PAE binding (see above). Once
   merged+released: drop `.vendor-sigstore/` + the `[patch.crates-io]` stanza in `impls/rust/Cargo.toml`.
2. **Three local-hygiene fixes to `.vendor-sigstore` (do regardless of upstreaming):**
   - (i) Correct the WRONG rationale — `models.rs:452` comment + `MILPA-PATCH.md` say "unreproducible";
     that's empirically false (it reproduces on protojson-path bundles). Real reason: Rekor hashes
     un-canonical, un-spec-pinned client bytes, and the check is redundant with the PAE binding.
   - (ii) Delete the now-dead `envelope_json` (computed in `TryFrom<Bundle>`, never read — dead_code).
   - (iii) Fix the vendored crate's broken tests: it isn't a workspace member + its fixtures are
     missing, so its `#[cfg(test)]` never runs; two orphaned tests (`case_2_envelope_hash_mismatch`,
     `case_3_unsupported_envelope_hash_algo`) still assert the OLD behavior and fail. Add a real
     regression test (reproduce-then-explain-why-skip) that actually runs.
- Control-loop recommendation at compaction: do the 3 local fixes now; file the upstream issue+PR
  with the cosign repro; keep the local `[patch]` until upstream merges.
- PoC scratch (ephemeral, job tmp — may not survive): `$CLAUDE_JOB_DIR/tmp/dsse-poc/` +
  `dsse-poc2/` (Rust harness `vendor-copy/`, downloaded bundles, `cargo_test_poc_*.log`). The
  durable record is the fixture bundle path + logIndex + hashes above.

---

## Session state (2026-07-27) — the other threads

**ALL DONE + LIVE:**
- **milpa publish revival** (rfc-distribution-and-publishing Phase 3): stages 3+4 complete
  (11 slices + 3-round code-review to floor), committed + pushed. Handoff:
  `docs/rfc-distribution-and-publishing.handoff.md`.
- **tianguis#42 E2E CLOSED**: softlink v0.11.0 published end-to-end (author→publish→dispatch→
  commit-entry→ratchet) and LIVE in the registry — tianguis index commit `7930002`,
  `content_hash dag-sha256:8ffc81bb…`, author-signer = softlink's own per-repo SAN (SAN-collapse
  bombshell fixed), attestation bundle pinned. Flushed out + fixed 7 real CI bugs.
- **milpa + nkdl are now PUBLIC** (Corey approved; both scanned clean).
- **3 follow-ups DONE:** (1) Rust OCI-consumer parity — Rust already had it, added confirming tests
  + fixed the PUBLISH-* error-catalog bijection regression (milpa `5dcf56f`); (2) OCI mocked-fetch
  conformance format §2.3.5 + `fixture-414` (milpa `8c9a8c8`); (3) index-bundle: `DEFAULT_INDEX_SIGNER`
  repin (milpa `f854fcd`) + tianguis `attest-index.yaml` reusable workflow + `attest-index-statement`
  CLI (tianguis `474d160`). **attest-index VALIDATED LIVE** — ran green on a real vendor pass;
  `index.kdl.bundle` served at the raw path, `subject.sha256 == sha256(index.kdl)` confirmed
  (`TNG-INDEX-BUNDLE-MISSING` resolved).
- **License: Apache-2.0 throughout** — milpa Rust `Cargo.toml` MIT→Apache-2.0 (milpa `592e4e5`);
  tianguis got an Apache-2.0 LICENSE + README line (was TBD/absent).
- **READMEs** professionalized (dropped the storytelling) — milpa `162eb31`, tianguis, then the
  license/polish commits.
- **Dependabot:** merged tianguis #43/#44/#45 + nkdl #44; tianguis **#41** (checkout) had a rebase
  requested + **auto-merge armed** — CHECK it landed.
- **Issue audit:** 13 stale/consolidation issues closed (milpa #117/#126/#132/#172/#107, tianguis #19,
  nkdl #23/#12/#22/#20/#19/#24/#25).

**PARKED — awaiting Corey's call (the 4 issue partials):**
- milpa **#45** (OCI): transport + registry-consumer + `hash oci=` all shipped; only the direct
  *manifest* `oci=` dep grammar isn't wired → close, or narrow to that grammar gap?
- milpa **#96** (publish auto-discover): `--name` auto-derives now; `--version` still required →
  narrow to "`--version` from git tag"?
- tianguis **#7** (R4 milpa-reads-registry): done; the fallback + live-net-test sub-items superseded
  → close-as-superseded?
- tianguis **#9** (`min_attestation` grammar): not built; entry-trust-policy (warn/strict, real crypto)
  shipped as a stronger, differently-shaped mechanism → close-as-superseded, or keep for reject-by-kind?

**Standing code-review Lows (deliberately left, through-Medium mandate):** milpa L3 (unbounded
`pack_source` mem-buffer), R2-L4 (non-UTF8 milpa.kdl→MILPA-INTERNAL).

**Uncommitted at compaction (all handoff/doc, no code):** this file (new), + `docs/rfc-distribution-and-publishing.handoff.md`,
`docs/rfc-registry-trust-federation.handoff.md` (RFC-note edits from the #3 work), memory files.
`.claude/scheduled_tasks.lock` (D) + `docs/rfc-per-entry-attestation.handoff.md` (M) are pre-existing
drift, NOT this session — leave them.
