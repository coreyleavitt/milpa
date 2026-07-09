# rfc-registry-append-only — handoff

- **Stage:** 1 (RFC draft + slicing) COMPLETE (2026-07-09). Draft written from
  the design conversation of 2026-07-08/09 (audit of the Part-2 cross-repo
  blocker → first-principles re-derivation). Slices A1–A5 defined.
- **Resume:** `/architect docs/rfc-registry-append-only.md round 1`
  **Review scope note for the rounds:** include the 2026-07-09 amendment
  deltas to `docs/rfc-per-entry-attestation.md` (§2 `bundle_pin`, §5 stage 1b
  + eight-slug taxonomy, §7 delivery/acquisition, open questions 1+2 resolved,
  §4 granularity subsumption) — those sections were written AFTER that RFC's
  three review rounds completed and are otherwise review-naked. One design
  surface, one review.

## Origin (why this RFC exists)

Corey challenged the OQ1 delivery recommendation ("are we letting the existing
design drive a less elegant solution?"). The audit found the delivery answer
survives (hash-pinned content-addressed leaves = TUF/cargo/OCI/Go-sumdb
convergence point, not path-dependence) but exposed the real inherited
weakness: **the whole-index signature re-signs history on every publish** —
nothing checks that a new verified index is a valid *successor* of the
previous one. A compromised/buggy bot can rewrite any historical entry
(content_hash swap, dep_decl swap, attestation strip/re-attribution, version
deletion) and produce a maximally-fresh valid index. Freshness
(`TNG-INDEX-BUNDLE-STALE`) cannot see any of it.

## Key decisions (Stage 1)

- **Monotone-entry lattice** (normative): frozen (content_hash, dep_decl,
  published_at, rekor, entry existence) / monotone-upgrade-only (attestation:
  None→vendored→author legal; strip/re-attribute/downgrade illegal) /
  append-only (provenance set; order advisory) / advisory-mutable (yanked).
- **No in-band correction path** — fix = yank + new version (Go-sumdb
  position over crates.io admin-patch). Operator rewrites = out-of-band
  migration events; consumers alarm and must explicitly reset baselines.
- **Sticky baseline** sidecar (`<key>.index.kdl.baseline`), advances only on
  clean ratchet — NOT the served cache, else warn-mode alarm-once poisoning
  (attacker history self-heals into the baseline).
- **Rides the `index-trust` axis** (same object: index-document integrity);
  no fourth policy axis. off/warn/strict per Part 1 semantics; strict =
  fail closed, cache not advanced.
- **Seam:** index-acquisition State 2, after Layer-1 verify, before atomic
  cache write (both impls' index_cache).
- **Two slugs:** `TNG-INDEX-ROLLBACK` (disappearance; wins precedence) +
  `TNG-ENTRY-MUTATED` (lattice violation). Land with raise sites (A2/A3).
- **`yanked`/`yank_reason`** version-node fields — the sanctioned removal
  story; advisory-mutable (cargo unyank precedent); enumeration excludes
  yanked from NEW resolution; frozen path untouched (A5).
- **Watermark dividend:** baseline gives a publication watermark → backdated
  new entries consumer-detectable → underwrites Part 2's epoch-based strict
  (its OQ2, resolved 2026-07-09). Backdate *enforcement* lands with Part 2 P3.
- **Semantic, not byte-level:** ratchet compares parsed entry maps;
  re-serialization always legal.

## Slices
- [ ] A1 — spec: registry-protocol.md §3.5 (lattice+ratchet+precedence+
      watermark), §3.2 yanked, §6 baseline; Part 1 RFC amendment note. No slugs.
- [ ] A2 — Python: yanked parse; ratchet + baseline lifecycle in State-2 seam;
      slugs in errors.md + errors.py + Rust all_codes() same change; unit
      tests per lattice row.
- [ ] A3 — Rust parity (index_cache.rs State 2); drop any DEFERRED entries.
- [ ] A4 — shared conformance fixtures (seeded-baseline matrix) + differential.
- [ ] A5 — yank selection semantics (both impls + §5.2 + fixtures).

## Related work landed alongside (same session)
- `docs/rfc-per-entry-attestation.md` amended: OQ1 → DECIDED (pinned
  content-addressed sidecar; `attestation/<sha256_hex>.bundle`; generalized
  artifact store extracted from HttpDepDeclStore), OQ2 → RESOLVED
  (epoch-based strict; recommended root-level `attestation-epoch` index
  field, frozen under this RFC's lattice), §2 `bundle_pin`, §5 stage 1b
  `TNG-ENTRY-BUNDLE-PIN-MISMATCH` (taxonomy now 8 + WS = 9 at P3).
- Tracking issues: **milpa#185** (this RFC) + **tianguis#42** (delivery
  prerequisite: bundle tree + pin emission + backfill dispatch + publish-time
  epoch gate).

## Open forks (awaiting Corey)
- None. Design resolved under the best-in-class bar (2026-07-09 conversation);
  three open questions in the RFC carry positions + recommendations, to be
  pressure-tested by the architect rounds.

## Review ledger (stages 2/4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (rounds not started) | — | — |
