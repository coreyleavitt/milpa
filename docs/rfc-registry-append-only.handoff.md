# rfc-registry-append-only — handoff

- **Stage:** architect round 1 COMPLETE (2026-07-09) — 4-lens team (depth /
  breadth / design / feasibility) + a dedicated 5th reviewer for the
  review-naked Part-2 amendment deltas (per the scope note below, now
  discharged). All findings resolved under the bar and applied; **no open
  forks**. Stage 1 (draft + slicing) was 2026-07-09 same day.
- **Resume:** `/architect docs/rfc-registry-append-only.md round 2` — hunt
  what's *still* weak, not the round-1 issues (ledger below). Round 2 should
  particularly pressure-test the round-1 *additions* themselves (they are the
  newest, least-reviewed text): the root-field class, the `index-history`
  axis wiring, `milpa index accept` semantics, the set-once Frozen carve-out,
  and the new-vs-recurring warn mechanism.
- After round 2: `/loop` grind (per-entry P1–P3a + append-only A1–A5;
  A6 waits on Part-2 P2).

## Origin (why this RFC exists)

Corey challenged the OQ1 delivery recommendation ("are we letting the existing
design drive a less elegant solution?"). The audit found the delivery answer
survives (hash-pinned content-addressed leaves = TUF/cargo/OCI/Go-sumdb
convergence point) but exposed the real inherited weakness: **the whole-index
signature re-signs history on every publish** — nothing checks that a new
verified index is a valid *successor* of the previous one. Freshness
(`TNG-INDEX-BUNDLE-STALE`) cannot see rewrites.

## Key decisions (post round 1)

- **Dominance over a product partial order** (round 1 reformulation): entry
  key `(namespace, name, raw version string)`; presence is a component
  (`absent < present`), so rollback = the same dominance failure as a frozen
  change. One generic `dominates()` fold in both impls, fields tagged with
  order kinds. **Frozen = set-once** (`absent/empty → value` legal exactly
  once — legacy `content_hash`/`dep_decl` backfill stays possible; any
  `value → value′`/`→ absent` violates).
- **Root-field class** (round 1, from the Part-2 delta review):
  `schema_version` monotone non-decreasing; `attestation-epoch` **set-once**
  (raising it would nullify the mandate while staying "non-decreasing") →
  `TNG-INDEX-ROOT-MUTATED`.
- **Own policy axis `index-history`** (off/warn/strict, default warn; env
  `MILPA_INDEX_HISTORY`; root authority + `WS-INDEX-HISTORY-ON-MEMBER`) —
  the draft's ride-`index-trust` position failed Part 2's own
  axis-separation test (fails/remediated independently); unsigned-registry
  and migration-window configs need the split.
- **Reset = dedicated `milpa index accept` verb, v1** — the draft's
  cache-clean story was doubly false (`clean` is spec-FORBIDDEN from touching
  the index cache and never has) and a hygiene-command reset is a
  silent-rewrite hole. Baseline corrupt-vs-absent: absent → TOFU;
  present-but-unparseable → `TNG-INDEX-BASELINE-CORRUPT` hard-fail regardless
  of policy.
- **Ratchet covers BOTH fetch seams** (`load_index` State 2 AND
  `_refetch_with_recovery`) and gates **before any cache mutation including
  the bundle-sidecar write** (torn-write hazard); baseline written atomically
  AFTER the index; sidecar trio `<key>.index.kdl.baseline{,.at,.reported}`
  in the glob family.
- **Sticky baseline** + warn habituation defense (new-vs-recurring via
  `.reported` digest). Serve-base/compare-base split factored as reusable
  `ratchet.py` primitive (Part 3 owner-registry reuse).
- **Four ratchet slugs** with ONE composite precedence
  `(class_rank: ROOT=0, ROLLBACK=1, MUTATED=2; ns, name, version)`;
  structured `violations=` payload with sub-class kinds (incl.
  `monotone-repinned` for same-kind `bundle_pin` swap); remediation hints
  required.
- **Yank aligned with tianguis#13**: `yanked`/`yanked_at`/`yanked_reason`
  (draft's `yank_reason` was an accidental fork); advisory-mutable-but-
  SURFACED (every transition a stderr notice — un-yank of a CVE-yanked entry
  is never silent); `--allow-yanked` deliberately dropped (recorded on #13);
  exclusion in BOTH `resolve_named_all` and `resolve_named_all_qualified`.
- **Watermark defined**: `T(baseline) = max(published_at)` over baseline
  entries (never consumer wall-clock), explicit skew tolerance (~24h),
  indexer-ordering assumption recorded on tianguis#42; omission dodge closed
  in Part 2 (post-epoch entries lacking `published_at` treated post-epoch,
  fail-closed).
- **Staged enforcement**: lattice complete in spec day one; rekor +
  attestation + epoch rows enforce at A6 (post Part-2 P2 parse); the pinned
  no-rekor regression test is inverted deliberately at A6.
- **No in-band correction path** — fix = yank + new version (Go-sumdb
  position). Migration events alarm and require explicit `index accept`.

## Part-2 delta review (scope note DISCHARGED 2026-07-09)

The review-naked Part-2 amendment sections were reviewed by a dedicated agent;
fixes applied to `rfc-per-entry-attestation.md`:
- stage 1b `TNG-ENTRY-BUNDLE-PIN-MISMATCH` → **unconditional hard error**
  (was policy-gated while citing the unconditional `TNG-DEPDECL-HASH-MISMATCH`
  precedent); `BUNDLE-MISSING` gains a `cause` payload discriminator.
- OQ2: `published_at` mandatory post-epoch (fail-closed omission rule +
  tianguis#42 publish gate); epoch set-once under the root-field class.
- P3a honest tail added: `entry-trust strict` is code-complete at P3a but
  non-functional against the live registry until P4 backfills (100%
  BUNDLE-MISSING in the window).
- Minors: bundle size-cap sizing note; `MILPA_ENTRY_BUNDLE_DIR` named.
- OQ3(ii) amended: continuity ratchet = this RFC's monotone order (ownership
  split: Part 2 owns the type, this RFC owns the order).

## Slices
- [ ] A1 — spec: registry-protocol §3.5 (key + dominance + lattice + root
      fields + staging + placement/ordering + precedence + payload + notices
      + watermark), §3.2 yank triple + published_at amendment, §5.2, §6
      baseline trio + accept; cli-contract verb + env + axis; Part 1 note.
- [ ] A2 — Python: parse ext (published_at, yank triple); dominance fold
      (`ratchet.py`); baseline lifecycle; BOTH seams; `index-history` axis;
      root-field check (schema_version); `milpa index accept`; 5 slugs
      (Python raise-site-complete same change; Rust `all_codes()`+DEFERRED).
- [ ] A3 — Rust parity (both seams; PartialEq/Eq derives on provenance
      types); drop DEFERRED.
- [ ] A4a — harness baseline-seeding extension (fixture schema
      `baseline.index.kdl` + BOTH runners incl. Python in-process adapter).
- [ ] A4b — fixture matrix + differential (slugs AND payload ordering).
- [ ] A5 — yank selection (both lookup paths), notices, NO-SATISFYING
      message naming, fixtures.
- [ ] A6 — post-Part-2-P2: attestation/rekor/epoch rows, no-rekor test
      inversion, staged fixtures.

## Cross-repo / issues
- **milpa#185** (this RFC) · **milpa#186** yanked-but-locked advisory
  (filed r1) · **milpa#187** Rekor auditor / cross-consumer baseline diff
  (filed r1) · **tianguis#13** yank contract aligned + `--allow-yanked` delta
  commented (r1) · **tianguis#42** indexer-ordering assumption commented (r1).

## Open forks (awaiting Corey)
- None. Round 1 resolved everything under the bar; two draft positions were
  REVERSED with grounds (reset-verb-not-clean; own-axis-not-index-trust) —
  flagged in the round-1 report for veto.

## Review ledger

| id | sev | finding (lens) | status | resolution |
|----|-----|----------------|--------|------------|
| R1-1 | blocker | `clean` reset story spec-forbidden + code-false (all 4 lenses) | FIXED | `milpa index accept` verb, v1 (§2, OQ1 resolved) |
| R1-2 | blocker | lattice fields not parsed (`published_at`/`rekor`/attestation) — "no new parser" false (feas/design) | FIXED | staged enforcement + A2 parse ext + A6; §3.2 amendment listed |
| R1-3 | blocker | yank outside lattice reopens rollback both directions (design/depth) | FIXED | advisory-mutable-but-surfaced; transition notices (§3/§5) |
| R1-4 | blocker | `attestation-epoch` had no lattice home; non-decreasing insufficient (delta review) | FIXED | root-field class, set-once, `TNG-INDEX-ROOT-MUTATED` |
| R1-5 | blocker | stage 1b policy-gated vs unconditional precedent (delta review) | FIXED | unconditional in Part 2 §5 |
| R1-6 | sig | recovery-refetch seam unratcheted; torn bundle write on strict reject (feas/depth) | FIXED | §2 placement: both seams, gate before any write |
| R1-7 | sig | baseline corruption→TOFU = silent reset (breadth/depth) | FIXED | corrupt≠absent; BASELINE-CORRUPT hard-fail |
| R1-8 | sig | axis conflation w/ index-trust (design/depth) | FIXED | `index-history` axis (draft position reversed) |
| R1-9 | sig | watermark T undefined; clock-anchor unsound; ordering assumption unstated (depth) | FIXED | §4 max(published_at)+skew; tianguis#42 note |
| R1-10 | sig | published_at optional dodges watermark (breadth) | FIXED | Part 2 OQ2 fail-closed mandate |
| R1-11 | sig | frozen forbids legacy backfill (depth) | FIXED | set-once semantics |
| R1-12 | sig | unclassified: namespace/dep_decl_schema_version/signed_by/bundle_pin same-kind (depth/delta) | FIXED | entry key + lattice rows + monotone-repinned |
| R1-13 | sig | precedence two-rules ambiguity (depth) | FIXED | composite sort key + worked example |
| R1-14 | sig | harness can't seed baselines; "same shape" claim false (feas) | FIXED | A4a slice |
| R1-15 | sig | tianguis#13 silent fork (breadth) | FIXED | field alignment + delta recorded on #13 |
| R1-16 | sig | warn habituation (depth) | FIXED | `.reported` new-vs-recurring |
| R1-17 | sig | P3a strict usability overstated (delta) | FIXED | Part 2 honest tail |
| R1-18 | min | provenance diff semantics implicit (depth) | FIXED | multiset-by-value + in-place-mutation fixture |
| R1-19 | min | remediation hints, command table, TOFU wording, sidecar glob, structured payload, bare-name DoS honesty, OQ3 identity-gate rationale, baseline observability (various) | FIXED | §§2/3/6 + threat model |
| R1-20 | min | yanked-but-locked UX; auditor tooling unrealized (breadth) | DEFERRED | issues #186, #187 filed |
