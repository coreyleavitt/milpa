# rfc-per-entry-attestation — handoff

- **Stage 3 (tdd grind) IN PROGRESS (2026-07-09):** part of the combined
  `/loop` grind with `rfc-registry-append-only.md` (queue: P1–P3a then
  A1, A2a–A2e, A3, A4a(+rs), A4b, A5; A6 gated on P2… see that RFC's
  handoff). **Resume:** the standing `/loop` grind command.

## Slices (implementation)

- [x] P1 — spec-only (2026-07-09): registry-protocol §3.2 clauses inverted
      → `EntryAttestation` tagged record (closed set, conservative
      collapse w/ diagnostic, subject binding, `bundle` pin field,
      normative-surface item 6 carve-out, §3.4 orthogonality rewrite);
      lockfile-schema §3.9 attestation block (claim-not-outcome, no
      schema-version bump, collapse-on-read posture). No slugs (P3).
      Gate: full pytest green (2633 passed).
- [x] P2 — attribution surfacing w/o gating (2026-07-10): `EntryAttestation`
      parse-to-typed in BOTH impls ((typed, diagnostics) boundary; Python
      via registry.py's existing warnings seam, Rust via `[milpa] warning:`
      eprintln); lockfile claim block (LockAttestation, no bundle_pin,
      after active_flags); resolver candidate carry-through; `milpa show`
      "claims author-signed by X" wording; BONUS bug fixed in both impls —
      frozen path wasn't carrying the claim (RFC §8 table), pinned with
      regression tests. Gates: pytest 2660 green; dev-rust workspace green.
- [x] P3a — mock-gated gate (2026-07-10), BOTH impls: `entry-trust` axis
      (root-scoped + WS-ENTRY-TRUST-ON-MEMBER), post-solve selection gate
      (stages 0–7; PIN-MISMATCH unconditional even under warn), 9 slugs
      w/ raise sites + spec/errors.md, EntryBundleVerifier + keyed
      MockEntryVerifier (MILPA_ENTRY_TRUST_MOCK_MAP/_DEFAULT) +
      EntryBundleStore (MILPA_ENTRY_BUNDLE_DIR file + HTTP), verify
      offline re-verify, all four online verbs wired (fetch/lock/add/
      update), fixtures 367–377 + both runners, Rust hold-opens emptied.
      §6 extract-or-decline: DECLINED sharing SigstoreVerifier internals
      (recorded in module docstrings; revisit at P3b). Judgment calls made:
      (a) subject digest binds dag-sha256 scheme-agnostically (RFC §1
      prose corrected — said sha256:); (b) LockAttestation gained
      bundle_pin+namespace beyond P1 §3.9 (offline verify needs them;
      spec updated); (c) IndexVersion.namespace added. P3b note: Rust
      SigstoreEntryVerifier fails closed after pre-crypto stages —
      sigstore-rs exposes no verify-against-known-digest primitive
      (pub(crate) only); needs the vendored-patch decision at P3b.
      Gates: pytest 2723 green; dev-rust workspace + conformance green.
- [ ] P3b — real-crypto strict-fails (lands with P4).
- [~] P4 — cross-repo tianguis bundle delivery. **STARTED 2026-07-11 in the
      tianguis repo (/home/corey/projects/tianguis) via /tdd, tracking issue
      coreyleavitt/tianguis#42.** Five deliverables: (1) content-addressed
      `attestation/<sha256>.bundle` tree (sibling of `dep-decl/`); (2) index
      `bundle sha256=` pin emission per attested entry; (3) DSSE subject binds
      digest AND `pkg:tianguis/<ns>/<name>@<version>`; (4) batched backfill
      workflow (doubles as milpa P4 real-crypto fixture source); (5)
      publish-time epoch gate via root `attestation-epoch` (rides #185 ratchet
      so it can't be backdated/stripped). milpa-side contract: RFC §7 + §1.
      Planning in progress; tianguis will get its own handoff doc. milpa-side
      P3b (real-crypto strict wiring, incl. the Rust sigstore-rs
      verify-against-known-digest vendored-patch decision) lands after this.
      **Plan + handoff:** `tianguis/docs/rfc-attestation-delivery.handoff.md`
      (9 slices S1–S9; full author-signed scope chosen). Grinding: S1 bundle
      pin, S2 root attestation-epoch, S3 in-toto statement builder DONE +
      committed in tianguis (`6d5ba94`/`54f8baf`/pending-S3); milpa-side wire
      formats verified against registry.py/entry_trust.py. Gate = nim 2.2.0
      podman container (recipe in the tianguis handoff).
      **Progress 2026-07-11:** S1–S7a DONE + gate-green in tianguis (bundle
      pin field, root attestation-epoch, in-toto statement builder, CAS bundle
      store, publish-time epoch gate, GH-Pages serve step, bundle-pin admission
      wiring). **CI boundary reached:** S7b (vendored minting workflow), S8
      (author-signed protocol redesign — dispatch Cloud Function + author
      tooling, carries an open design sub-decision), S9 (backfill) are all
      GH-Actions/cosign/cross-service — NOT local-gate-able, need CI + Corey's
      S8 design call. Details in the tianguis handoff's "CI boundary" section.
- [ ] P5 — Part 3 owner registry (future).

- **AMENDED 2026-07-09 (post-review):** open questions 1 and 2 RESOLVED after
  Corey's elegance challenge on the cross-repo blocker. OQ1 = content-addressed
  pinned bundle sidecar (§7 rewritten; §2 gains `bundle_pin`; §5 gains stage 1b
  `TNG-ENTRY-BUNDLE-PIN-MISMATCH` — taxonomy now 8 TNG-ENTRY-* + WS = 9 at P3).
  OQ2 = epoch-based strict, underwritten by the NEW
  `docs/rfc-registry-append-only.md` (Part 1 amendment: monotone-entry lattice
  + consumer ratchet; closes the R5 stripping/rollback class structurally).
  §4 granularity caveat subsumed. **These deltas are review-naked** — they must
  be covered by the append-only RFC's architect rounds (scope note in
  `rfc-registry-append-only.handoff.md`). P3a now fully unblocked; P3b/P4
  blocked only on tianguis *implementation* (prerequisite issue filed).
- **Stage:** doc review COMPLETE (3 rounds, 2026-07-08). The RFC was upgraded Stub → Draft
  under the fix mandate (fix through Medium); "fix" = edit the RFC text (no implementation
  exists). Round 3 hit the floor: 1 Medium (P3a/P3b wording contradiction, fixed inline +
  grep-swept) + 2 Lows. ALL findings now fixed — Corey extended the mandate to the Lows
  (L1/L2, 2026-07-08); zero open/deferred items remain. Tracking issue **#184** filed.
  NOT committed — awaiting Corey's commit approval alongside the other uncommitted docs.
- **Round 1:** 4 lenses (accuracy/staleness, security/trust-model, design & ergonomics,
  completeness/consistency), findings adversarially verified against the repo before ledgering.
- **Round 2:** standing security + design lenses on the rewritten Draft → R22–R34 (all fixed).
- **Round 3:** combined verification lens → R35 fixed; round-3 factual re-checks all green
  (pipeline order matches Part 1 §3.4.4 effective order; name-binding referenced consistently;
  MockVerifier single-result claim, MILPA_INDEX_TRUST_SIGNER override, slug bookkeeping all
  verified against code).

## Review ledger (doc review, 2026-07-08)

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R1 | Critical | Attestation SUBJECT unspecified: RFC never says what bytes the per-entry bundle signs over (content_hash? tarball sha256? entry bytes?) and has no digest-binding check/code — a valid-but-stale bundle passes signer+sig checks while the entry points at different bytes (reopens per-entry the hole Part 1 §4 step 6 closes for the whole index) | fixed | doc read: no subject mentioned anywhere; no TNG-ENTRY-DIGEST-MISMATCH |
| R2 | High | Prerequisites §3 + line 36 STALE: Rust real SigstoreVerifier SHIPPED (attestation-verifier RFC complete; vendored sigstore-rs patch; TNG-INDEX-VERIFY-UNSUPPORTED deleted; nothing rides MockVerifier in prod). "Fresh spike needed" false | fixed | rfc-attestation-verifier.handoff.md (all 10 slices DONE) |
| R3 | High | Gate-placement conflation: cited seam `resolve_named_all` is the enumerate-ALL-candidates step (constraint=None, pre-PubGrub), not "per selected dep". Filter-at-enumeration (silent downgrade, N×versions verifications, §5.5 precedence unaddressed) vs check-final-pick (late hard fail) have opposite UX/perf/security profiles; RFC must pick | fixed | resolver.py:1176–1203 `_enumerate_named_stubs` |
| R4 | High | Frozen/lockfile hole: milpa.lock records NO attestation/signed_by/rekor (grep: 0 hits in lockfile.py); frozen path never loads the index → per-entry coverage silently evaporates on every frozen/CI resolve. OQ5 understates — needs a lockfile-schema decision, not just "does verify re-run" | fixed | lockfile.py grep; frozen.py takes no index |
| R5 | High | Stripping/rollback unaddressed: bot omitting attestation ⇒ UNATTESTED ⇒ warn passes (trivial bypass); no monotonicity/rollback story (author-signed → later unattested undetected); no strict-flip criteria | fixed | doc omission confirmed |
| R6 | High | Policy-axis "default: reuse" contradicts Part 1's own axis-separation precedent ("Only the mechanism is unified", Part 1 L500) and silently changes `index-trust "strict"` semantics for existing users | fixed | rfc-registry-trust-federation.md:500 |
| R7 | High | "Extends directly" glosses a real seam change: `IndexBundleVerifier` is 1 bundle / 1 pinned expected_signer / index-load lifecycle; per-entry needs N bundles, per-kind signer resolution (pinned vs signed_by), no freshness analog, selection-time call site | fixed | index_trust.py:221 |
| R8 | High | Error-taxonomy/table incompleteness: §2 gate table cannot produce TNG-ENTRY-SIGNATURE-INVALID (unreachable row); no MALFORMED, no BUNDLE-MISSING (attested entry, bundle 404), no DIGEST-MISMATCH (→R1), no staleness analog; author-signed-with-absent-signed_by cell uncovered | fixed | doc §2/§3 cross-check |
| R9 | Medium | Sequencing: P4 (declared crux) last; promote OQ4 (attribution surfacing w/o gating — the only cross-repo-unblocked slice) to committed v1 scope; make P1–P2 explicitly delivery-agnostic | fixed | design judgment, verified P4 is sole blocker |
| R10 | Medium | No caching story for per-entry verification results across resolves (Part 1 §7.2 precedent exists) | fixed | doc omission |
| R11 | Medium | Stringly-typed attestation kind; unknown→UNATTESTED stated only as a table cell — needs a normative closed-set forward-compat rule (unknown kinds MUST NOT verify as attested) | fixed | doc §1/§2 |
| R12 | Medium | 3 independently-nullable IndexVersion fields vs a single optional tagged attestation record; correlation invariants (author-signed ⇒ signed_by) unrepresentable/unstated | fixed | doc §1 |
| R13 | Medium | Workspace authority for entry-trust unaddressed (Part 1 solved root-scoping the hard way; a separate axis re-inherits that whole design problem) | fixed | doc omission |
| R14 | Medium | No tracking GH issue for Part 2 despite Part 1's explicit instruction (L1272 "A tracking GitHub issue (adjacent to #91) should be filed against that stub") + defer-file-now discipline | fixed | gh issue list: none |
| R15 | Medium | Conformance-corpus strategy one line vs Part 1's §10 depth (N-bundle mixed scenarios needed) | fixed | doc §Slice sketch |
| R16 | Medium | `Index::satisfying_versions` fabricated — no such fn in either impl; Rust seam is `resolve_named_all` (registry.rs:285) | fixed | repo grep: 0 hits |
| R17 | Medium | milpa-vendored branch is VACUOUS vs vendor-bot compromise (same signer as Layer 1) — the one adversary the gate implies it addresses; author-signed is where the value is. OQ3 partially acknowledges but doesn't state the asymmetry | fixed | trust-model analysis |
| R18 | Low | "#91 (index availability follow-on)" loose — actual: "Publisher-side self-mirror declarations" | fixed | gh issue view 91 |
| R19 | Low | Line refs point at the IndexVersion data model; the parser needing changes is `_parse_version_node` (registry.py:605) / `parse_version_node` (registry.rs:453) | fixed | grep |
| R20 | Low | "RekorRef dataclass" is a Nim object; "parses-and-ignores" overstates (fields fall through the forward-compat skip; Rust has no rekor-tolerance test) | fixed | tianguis model.nim:13; registry greps |
| R21 | Low | OQ5 should cite the SHIPPED Sv `reverify_cached_index` pattern as the answer template | fixed | attestation-verifier handoff Sv |
| R22 | High | ROUND 2 (security): cross-package attestation replay — content_hash is name-independent, so a digest-only subject lets a byte-identical republish under another namespace point at the original author's GENUINE bundle and pass digest+crypto+signer → "author-signed by alice" for mallory/widget-pro | fixed | §1 now binds subject[0].name = pkg:tianguis/<ns>/<name>@<version> alongside the digest; new TNG-ENTRY-SUBJECT-MISMATCH (stage 4); replay conformance fixture added; threat-model claim annotated |
| R23 | Medium | ROUND 2 (security): vendored expected-signer source ambiguous — a re-hardcoded default would spuriously fail self-hosted indexes | fixed | §5 normative: reuses Layer 1's EFFECTIVE (env/flag/manifest-resolved) signer, not a second constant |
| R24 | High | ROUND 2 (design B1): lockfile said "records the attestation outcome" but P2 has only a CLAIM (no crypto run); schema couldn't distinguish | fixed | §7 normative: lockfile records the CLAIM, verification always re-derived never persisted; show renders "claims author-signed by X" until P3 |
| R25 | High | ROUND 2 (design B2): root-scoping decided by analogy whose premise (one document/invocation) doesn't transfer to per-dep outcomes; contradicted OQ2 | fixed | §4: knob placement stays decided root-scoped; granularity (per-member/scoped strict) folded into OQ2, resolve before P3. Agent called it a fork; resolved under the operational test (confident recommend) |
| R26 | High | ROUND 2 (design B3): P1 "spec-only, no raise sites" vs "land slugs same change" contradiction — bijection lints red for the whole P3-blocked window; count was 6 not 7(+WS) | fixed | slugs (8 incl WS-ENTRY-TRUST-ON-MEMBER) land at P3 with raise sites; §5 is design SSOT meanwhile |
| R27 | Medium | ROUND 2 (design B4): §5 pipeline order diverged from Part 1 §3.4.4 full effective order (inclusion lumped before signer) — S5.5-class cross-impl asymmetry | fixed | table reordered: malformed→digest→subject-name→cert+sig→signer→inclusion; normative mirror of Part 1 |
| R28 | Medium | ROUND 2 (design B5): third trust axis unacknowledged (attestation-policy never mentioned) | fixed | §4 three-axes paragraph; trust{} grouping named cosmetic follow-up |
| R29 | Medium | ROUND 2 (design B6): no-freshness asserted not derived; revocation residual unnamed | fixed | §6: derivation (mutable rolling doc vs immutable subject) + named residual (no revocation, intrinsic to keyless model) |
| R30 | Medium | ROUND 2 (design B7): cache had no invalidation story; P2-era lockfiles → BUNDLE-MISSING wave unacknowledged | fixed | §7: no negative caching (P4 backfill reaches consumers); wave acknowledged, pre-v1 one-shot re-lock |
| R31 | Medium | ROUND 2 (design B8): collapse warning had no channel (parsers pure); forensic loss unstated | fixed | §2: parse returns (typed index, collapse diagnostics); persisted state doesn't distinguish, index snapshot = forensic record |
| R32 | Medium | ROUND 2 (design B9): strict + floating constraints = upstream publish breaks ^-range consumers, unnamed | fixed | OQ2 names the resolution-availability hazard |
| R33 | Medium | ROUND 2 (design B10): EntryBundleVerifier shares ~90% of SigstoreVerifier internals; unify-vs-duplicate unaddressed | fixed | §6: P3 MUST extract or explicitly decline (audit-for-duplication) |
| R34 | Medium | ROUND 2 (design c1/c4): conformance lacked keyed mock map, acquisition mock surface, replay/enumeration-negative/round-trip/WS fixtures; P3 real-crypto tail P4-gated; CI dispatch batching | fixed | Conformance section + P3a/P3b split + one-batched-dispatch + signed_by=workflow-SAN note |
| R35 | Medium | ROUND 3: P3a/P3b split (R34) left four stale "blocked before P3 / gates P3+" statements (status line, prereq 1, §4 caveat, OQ1 heading) contradicting the carve-out — a reader would idle unblocked P3a work | fixed | all four spots + P3 slice header + L437 phrase aligned: P1–P3a unblocked (P3a needs OQ2 scoping), P3b/P4 blocked on OQ1; grep-swept |
| L2 | Low | ROUND 3 Lows: (i) two-stages→SIGNATURE-INVALID mapping implicit in table; (ii) "never negatively cache BUNDLE-MISSING" vs Part 1's .no-bundle+TTL precedent | fixed | (i) §5 explicit NORMATIVE callout + warn-dedup UX; (ii) §7 reframed as bootstrap-window policy, P4 revisits with bounded-TTL marker |
| L1 | Low | ROUND 2 Lows: rekor field factorable out of both variants; multi-provenance same-content_hash invariant unstated; BUNDLE_STALE unreachable-for-entries unmapped; lockfile schema-version statement; §6.7-style command-coverage section; warn-mode aggregation UX | fixed | Corey extended the mandate (2026-07-08): §2 rekor factored into the record envelope; §1 mirror-invariant stated w/ §3.3 cite; §6 stale-variant-unreachable note; §7 no-bump statement (dep_decl precedent + parser hard-fail rationale); new §8 command-coverage table + registry-only scope boundary; §5 warn one-line-per-entry dedup rule |
| X1 | — | "Two incompatible mechanisms (string-compare vs crypto)" framing | refuted | chained trust supplies expected_signer TO real bundle verification; table gap survives as R8 |
| X2 | — | "Stub mislabels S4b (real wiring was S2)" | refuted | stub uses Part 1's slice numbering where S4b = Rust real verifier; agent confused it with the attestation-verifier RFC's own S4b |
| X3 | — | Completeness agent's "#91 is about availability — checks out" | refuted | actual title is self-mirror declarations; superseded by R18 |

## Verified correct (spot-checks that passed)
Terminology byte-exact (`IndexBundleVerifier`, `MockVerifier`, `TrustPolicy`,
`effective_trust_policy`, warn/strict/off); §3.2 "four clauses" count; §5.2 pointer resolves;
`test_rekor_block_is_tolerated_and_ignored` exists (test_registry.py:152); Python
`resolve_named*` L264–360 accurate; IndexVersion line ranges exact in both impls; RekorRef
exists in tianguis; TNG-ENTRY-* naming convention consistent, no collisions; #103 closed as
described; sigstore-rs #285/v0.14.0 claims consistent with handoff.
