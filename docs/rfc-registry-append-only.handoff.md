# rfc-registry-append-only — handoff

- **Stage:** CODE REVIEW (rfc-flow stage 4) **COMPLETE** (2026-07-10) —
  3 rounds, terminated at the floor (0 Critical/High/Medium). 10 findings
  fixed across 8 commits (`b4c4f8f`→`f2480f1`), each gated on full pytest
  + `dev-rust test --workspace`. CR7 deferred → #189; CR8–CR14, CR18 left
  as Lows per mandate. **All committed; NOTHING PUSHED** (awaiting Corey).
- **Resume:** RFC #185 is fully implemented + reviewed. Next: Corey's
  call — push the branch, or address the residual Lows (CR8–CR14/CR18) in
  a follow-up. P3b/P4 of Part 2 still blocked on tianguis delivery.
  (Architect rounds 1+2 COMPLETE 2026-07-09.)
- **Grind history:** `/loop` TDD GRIND COMPLETE (2026-07-10). DONE+committed:
  Part-2 P1 (3b920ac), P2 (d4404ad), P3a (baad9a4); A1 (fb6e707),
  A2a (4f607a5), A2b (a53afd7), A2c (cbe1682), A2d (bdc419e),
  A2e (3911cdd), A3 (22e07db), A4a (76dcc63), A4b (224ca14),
  A5 (b9a620e), A6 (b3211bf) = 14/14 — **ALL SLICES DONE**. A6
  flipped the staged rows (`attestation`/`rekor`/`attestation-epoch`) to
  live in both impls, closed the attestation/`rekor` canonical-rendering
  spec gap, wired the previously-unparsed `attestation-epoch` root field,
  and inverted fixture 389 + added 404–410. RFC #185 is now fully
  implemented in both impls. **Next stage: `/code-review` over the RFC
  scope** (rfc-flow stage 4; typically 2–3 rounds, ship at 0
  critical/high). P3b/P4 of Part 2 remain blocked on tianguis delivery.

## Origin (why this RFC exists)

Corey challenged the OQ1 delivery recommendation ("are we letting the existing
design drive a less elegant solution?"). The audit found the delivery answer
survives (hash-pinned content-addressed leaves = TUF/cargo/OCI/Go-sumdb
convergence point) but exposed the real inherited weakness: **the whole-index
signature re-signs history on every publish** — nothing checks that a new
verified index is a valid *successor* of the previous one. Freshness
(`TNG-INDEX-BUNDLE-STALE`) cannot see rewrites.

## Key decisions (post round 2)

- **Dominance over a product partial order**: entry key
  `(namespace, name, raw version string)`; presence is a component
  (`absent < present`). **One literal fold** (round 2): root fields ride the
  same fold as a synthesized reserved entry under the empty key — no
  parallel root code path. Order-kind tags are **disjoint by name**
  (round 2): set-once / attestation-monotone / append-only-multiset /
  advisory-mutable / ordinal-non-decreasing (`schema_version`) — the two
  "monotone"s are different comparators and must not share a tag.
- **Set-once is per-observed-history** (round 2): "exactly once" is
  relative to the current baseline; every trust-anchor re-establishment
  (TOFU, `index accept`, corrupt recovery) re-anchors it — named as a
  threat-model residual (the TOFU bound generalized), not a new hole.
  `index-history off` does NOT create a gap (off freezes but never deletes
  the baseline).
- **Root-field class**: `schema_version` ordinal non-decreasing (absent ≡
  spec default 1; `TNG-SCHEMA-UNKNOWN` preempts the ratchet for
  newer-than-supported candidates); `attestation-epoch` set-once →
  `TNG-INDEX-ROOT-MUTATED`.
- **Own policy axis `index-history`** (off/warn/strict, default warn; env
  `MILPA_INDEX_HISTORY`; root authority + `WS-INDEX-HISTORY-ON-MEMBER`).
  Round 2: `off` neither reads nor writes the baseline but **preserves**
  it (re-enable resumes from the frozen baseline — expected alarms);
  corrupt-baseline hard-fail ranges over warn|strict (can't fire under
  off). **A1 extracts a generic policy-axis model (§3.4.0)** — authority
  formula + off-rule + member-error pattern stated once, instantiated by
  index-trust / entry-trust / index-history (spec-prose SSOT; Part 2 §4
  gets a cross-ref amendment).
- **`milpa index` verb family** (round 2 split): `status` (read-only, no
  writes ever; `--refresh` = dry-run diff; exit code = pending-violations
  gate for CI) + `accept` (same fetch, prints diff, **atomic** baseline
  swap as its only mutation; loud distinct error on write failure; three
  explicit branches — present→diff, absent→TOFU-establishment message,
  corrupt→re-establishment message; epoch-change acceptance must print the
  blast-radius consequence sentence). Non-interactive by design (no
  `--yes`); idempotent; per-URL; member-dir delegates to root (S11e);
  `--no-index` → error; `index-history off` → works + warns;
  `index-trust off` → honest no-crypto-basis caveat. Full verb-spec blocks
  land in cli-contract at A1. Nested subparser = third instance of the
  `workspace`/`store` pattern.
- **Sidecar pair, not trio** (round 2): `<key>.index.kdl.baseline` +
  `.baseline.meta` (KDL: `established_at`, `reported_digest`,
  `reported_at`) — one atomic write, kills the independent-tear class;
  `.meta` is advisory/self-healing (missing/stale → reported-set unset).
- **Canonical violation digest (normative, round 2)**: sha256 over
  composite-sorted tab-joined lines
  `(class, ns, name, version, field, kind, candidate_value-raw)`;
  candidate_value included so same-field re-mutation (V₂→V₃) reads as NEW,
  not recurring; digest equality added to the cross-impl differential.
- **Composite key gains trailing `field`** (round 2): breaks
  root-vs-root ties (`attestation-epoch` before `schema_version`).
- **Concurrency (round 2)**: sticky-advance makes baseline poisoning
  impossible under races (advances only on clean diff); no lock file; the
  fixed-`.tmp`-name torn-write hazard (pre-existing Part-1 latent) is
  fixed at the root in A2d (unique temp names for all index-cache writes).
- **Parse-at-gate behavior change named + pinned** (round 2): unparseable
  candidate no longer clobbers a good cache; fixture asserts byte-identity.
- **Ephemeral CI position** (round 2): frozen path is immune (lockfile
  content_hash pins = the go.sum analog); resolving CI jobs need
  `$XDG_CACHE_HOME/milpa/index/` persisted (guidance ships with A2);
  committable baseline anchor = **#188** (filed round 2, couples to OQ2's
  compact form).
- **Baseline schema-skew** (round 2): unparseable-includes-schema-unknown →
  `TNG-INDEX-BASELINE-CORRUPT` (skew named in message), never raw
  `TNG-SCHEMA-UNKNOWN`; all baseline parse errors map to BASELINE-CORRUPT.
- **`[milpa] warning:` prefix** for yank notices (round 2) — the codebase's
  single non-fatal stderr convention; round-1's invented `notice:` tier
  dropped (a two-tier taxonomy would be a CLI-contract RFC).
- **`ratchet.py` monomorphic** (round 2):
  `Baseline.check(candidate) → RatchetOutcome(violations, advanced)` — the
  violations list IS the verdict; genericity deferred to Part 3 =
  consumer #2 in hand.
- **Strict-masks-yank-notice trade-off named** (round 2, threat model):
  fail-closed delays a bundled legitimate CVE-yank notice until the
  unrelated violation resolves.
- **Yank aligned with tianguis#13** (round 1): `yanked`/`yanked_at`/
  `yanked_reason`; surfaced transitions; no `--allow-yanked`; both lookup
  paths. **Watermark** = max(published_at) over baseline + ~24h skew
  (tianguis#42). **No in-band correction path** (Go-sumdb position).
- **Staged enforcement**: lattice complete day one; rekor/attestation/epoch
  rows enforce at A6 (post Part-2 P2; pinned no-rekor test inverted there).
- **Baseline GC**: accepted non-goal (noted in §6 `clean` row); belongs to
  the future store-gc mini-RFC, not `clean`.

## Slices

- [x] A1 (2026-07-10, `fb6e707`) — spec: §3.4.0 policy-axis model landed +
      §3.4.5/§3.4.7 rewritten as instantiations + Part 2 §4 cross-ref;
      §3.5.1–3.5.4 full ratchet; §3.2 yank triple + published_at typed;
      §5.2 yank exclusion (staged A5); §6 baseline pair + verbs + clean-row
      GC non-goal; cli-contract §5.12 verb blocks + §8.7 MILPA_INDEX_HISTORY
      + Appendix B + normative item 19; Part-1 RFC note. Slugs referenced
      as "(lands with implementation slice)". Gate: pytest green.
- [x] A2a (2026-07-10) — Python parse ext: IndexVersion +published_at/yanked/yanked_at/yanked_reason (typed, malformed→None/False no-diagnostic posture); 18 tests; raw-string retention deliberately NOT added (ratchet raw candidate_value = A2b/A2d extraction concern). Gate: pytest 2736 green.
- [x] A2b (2026-07-10) — `ratchet.py` standalone: Baseline.check →
      RatchetOutcome(violations, advanced, transitions); RawField(value,
      raw) input shape (caller supplies raw-as-served — A2d seam concern);
      staged=True rows (attestation/rekor/epoch) excluded by default,
      include_staged=True proves A6-readiness; whole-entry rollback
      convention (field="", kind=frozen-unset) PINNED IN SPEC §3.5.3 by
      orchestrator; 30 in-memory tests incl. hand-computed digest vectors.
      Gate: pytest 2766 green.
- [x] A2c (2026-07-10) — `index-history` axis plumbing: manifest field
      (root-scoped, both parsers+serializers), WS-INDEX-HISTORY-ON-MEMBER
      (slug + spec/errors.md + all 3 workspace-construction sites),
      `_build_index_history` returns bare TrustPolicy str via
      effective_trust_policy (off is a real value — A2d must distinguish
      off from gate-absent); context.py untouched (no consumer yet); Rust
      DEFERRED hold-open re-opened for the 1 WS slug ("A3/A4a parity
      pending"). 24 tests. Gates: pytest 2793 + rust-conformance green.
- [x] A2d (2026-07-10) — seam wiring + baseline lifecycle: new
      index_ratchet_seam.py (build_index_state w/ raw re-walk only for
      published_at; parse_baseline→BASELINE-CORRUPT; evaluate_gate pure);
      index_cache.py gates BOTH seams (load_index State-2 +
      _refetch_with_recovery) post-Layer-1 pre-write; parse-at-gate
      no-clobber UNCONDITIONAL (incl. off); unique temp names (PID+random)
      for all writes; baseline+.meta = two separate atomic writes (spec
      read: pair ≠ cross-file transaction — no blocker); 4 slugs
      (ROOT-MUTATED/ROLLBACK/ENTRY-MUTATED/BASELINE-CORRUPT) + Rust
      DEFERRED extended; policy default "off" at the load_index param so
      ~150 existing call sites unchanged, CLI threads real policy. 32
      tests. Gates: pytest 2825 + rust-conformance green.
- [x] A2e (2026-07-10) — `milpa index status|accept` verb family:
      nested subparser (3rd workspace/store instance); status read-only
      (byte-checked) w/ --refresh dry-run; accept 3 branches + idempotent
      + epoch blast-radius sentence (unit-tested vs renderer — row staged
      to A6); member-dir delegation structural (URL-keyed sidecars);
      2 new slugs TNG-INDEX-NOT-CONFIGURED + TNG-INDEX-BASELINE-WRITE-
      FAILED (+ Rust DEFERRED); index_cache gains baseline_sidecar_paths /
      fetch_verified_candidate_text / write_baseline_pair (no diff-logic
      duplication); cli-contract §5.12 column-width self-contradiction
      fixed (19-char). index-trust-off caveat only on FETCHING verbs
      (defensible reading, flagged). NOTE: agent violated NO-GIT once
      (stash/pop, recovered clean, disclosed). 24 tests. Gates: pytest
      2849 + rust-conformance green.
- [x] A3 (2026-07-10) — Rust parity for A2a–A2e complete: ratchet.rs
      (30 tests, Python digest vectors ported VERBATIM — byte equality),
      index_ratchet_seam.rs (simpler: IndexVersion carries published_at_raw
      so no re-walk), registry.rs typed parse + hand-rolled ISO-8601,
      index-history axis + WS check, load_index_with_history (single
      is_recovery seam, ~35 call sites untouched via Off-default wrapper),
      unique temp names for ALL sidecar writes, full index status/accept
      verbs byte-exact; all 7 slugs live; DEFERRED emptied. ⚠ A4b
      MUST-RESOLVE: provenance-violation digest fallback rendering is
      impl-specific (Python str(value) repr vs Rust rendering) — the spec
      pins raw-as-served only for document strings; any provenance-removed
      differential fixture will force a normative rendering definition +
      both-impl alignment (spec sharpening belongs to A4b). Gates: rust
      workspace + conformance + pytest 2849 all green.
- [x] A4a (2026-07-10) — harness seeding, both runners: fixture keys
      MILPA_INDEX_HISTORY_MANIFEST/_HISTORY env pair, baseline-seed/
      (logical names), expected/baseline-state (unchanged|advanced|absent)
      + optional expected/baseline exact bytes; logical→hashed via the
      PRODUCTION baseline_sidecar_paths in both impls (no hand-rolled
      hashing); smoke fixtures 378 (clean advance) + 379 (violation-warn
      frozen). Real bug caught by TDD: Python runner seeded XDG root, not
      _default_cache_dir()'s milpa/index/ subpath — fixed. Rust runner
      note: run_index_history_ratchet drives evaluate_gate + real file I/O
      directly (fd2 capture unsafe under parallel harness) rather than
      load_index_with_history — seam wiring covered by A3's unit/CLI
      tests; A4b may revisit if differential needs full-path fidelity.
      Gates: pytest 2851 + rust workspace/conformance green.
- [x] A4b (2026-07-10) — fixture matrix 380–399 (each pins a distinct
      §3.5 clause; 399 = the literal aaa/zzz worked example w/ digest) +
      differential digest equality via expected/digest + expected/recurring
      runner keys (structured digest source: MilpaError.context["digest"] /
      new CoreError::RatchetViolation{digest} — Rust previously exposed the
      digest only in message text). MUST-RESOLVE closed at the root: new
      §3.5.3 NORMATIVE canonical rendering for non-scalar candidate_value
      (sorted \x1f/\x1e element encodings, never repr/Debug; provenances
      instantiated now, attestation named-deferred to A6); both seams
      supply explicit raw; hand-derived vector 2d659ca5… pinned in both
      unit suites + fixture 386. Gates: pytest 2874 + rust workspace green.
- [x] A5 (2026-07-10) — yank selection: _filter_candidates SSOT shared by
      resolve_named_all + resolve_named_all_qualified (both impls), yank
      excluded BEFORE constraint matching per §5.2; transition notices
      turned out already-landed in A2d (_print_yank_notice both impls);
      NO-SATISFYING = payload/message enrichment of the EXISTING slug
      (spec-mandated; Python context["yanked_excluded"], Rust message
      segment — harness asserts .code() only); frozen path proven
      structurally unaffected (fixture 403); spec/errors.md
      NO-SATISFYING entry sharpened. Fixtures 400–403. Gates: pytest 2889
      + rust workspace green.
- [x] A6 (2026-07-10) — staged enforcement flip, both impls: LATTICE
      `staged`/`include_staged` removed entirely (clean cutover);
      attestation/rekor/attestation-epoch extraction wired at the seam
      (epoch previously had NO parser anywhere — new root re-walk, both
      impls); spec gains the `attestation-epoch` node definition (§1) +
      `rekor` canonical-rendering instantiation (§3.5.3), both previously
      missing/deferred; A5-era stale staging prose (2 spots) also fixed
      while sweeping. Fixture 389 inverted in place (staged-clean ->
      violation-warn); fixtures 404-410 added (strip/re-attribution/
      repin+digest/upgrade-clean/rekor-changed/epoch-strict/root-vs-root
      composite tie). No standalone ratchet-level "no-rekor" test existed
      to invert — the parse-level one was already inverted at Part-2 P2;
      the actual pre-A6 pin was `test_attestation_unenforced_by_default_
      pre_a6`, inverted directly. Digest vector `2c02fbe9…3323` hand-
      derived + pinned in both unit suites + fixture 406. Gates: pytest
      green; rust workspace green.

## Cross-repo / issues

- **milpa#185** (this RFC) · **#186** yanked-but-locked advisory (r1) ·
  **#187** Rekor auditor / cross-consumer baseline diff (r1) ·
  **#188** committable baseline anchor for ephemeral CI (r2) ·
  **tianguis#13** yank contract aligned + `--allow-yanked` delta (r1) ·
  **tianguis#42** indexer-ordering assumption (r1).

## Open forks (awaiting Corey)

- None. Rounds 1+2 resolved everything under the bar. Round-2 reversals of
  round-1 positions, flagged for veto: (a) `.at`/`.reported` merged into
  one `.meta` sidecar; (b) `notice:` prefix dropped for the standard
  `[milpa] warning:`; (c) accept split into `status`+`accept` family;
  (d) `Baseline[T]` generic dropped to monomorphic.

## Code-review ledger — stage 4, round 1 (2026-07-10)

Scope: full grind diff `3b920ac~1..b3211bf` (spec + both impls + conformance).
6 reviewers (Python-correctness, Rust-correctness, spec-fidelity/cross-impl,
security, design, coverage) → 5 adversarial verifiers on all C/H + subtle
digest-integrity mediums. Status legend: open / fixed / deferred / wontfix / refuted.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| CR1 | High | Rust `rekor` (and `provenances`) frozen/multiset dominance compares the `\x1f`/`\x01`-**joined** string, not the structured value → a boundary-shifted mutation passes Rust's ratchet while Python (structured compare) flags it. Cross-impl divergence + tamper-detection bypass for Rust users under strict. `\u{1f}` escapes reach the fields through both KDL parsers (verified). `FieldValue::Attestation` next to it shows the correct pattern. | fixed | CONFIRMED (verifier a37205b, end-to-end). Bounded: attacker must shape baseline bytes in advance (TOFU/sticky-advance). Fix: `FieldValue::Rekor(RekorRef)` + structured provenance-list variant in Rust; keep `raw` digest-only. |
| CR2 | Med | Canonical-digest **delimiter injection**: `namespace`/`version`/provenance `url`/`ref`/`registry`/`repository` are not charset-validated, so KDL-escaped `\t`/`\n`/`\x1f` collide distinct violation sets to one sha256 and forge lines in `index status`/`accept` output. Spec §3.3/§3.5.3 gap present identically in both impls. | fixed | CONFIRMED (verifier a41011, real seam exploit). Bounded to warn-mode habituation/report fidelity; strict still hard-fails. Root-cause fix (shared with CR1): reject control/delimiter bytes in registry string fields at parse boundary + spec §3.3/§3.5.3. |
| CR3 | Med | **Lockstep-group digest masking**: the `dep_decl`/`dep_decl_schema_version` group reports `candidate_value` as only `dep_decl`'s text, so a second mutation that changes only `dep_decl_schema_version` yields a byte-identical digest → mislabeled "recurring" not "new", defeating §3.5.3's stated purpose. Both impls. | fixed | CONFIRMED (verifier a41011, digest `ec345fa3` reproduced twice). Warn-mode only. Fix: fold schema-version into the group's reported `candidate_value` in both impls + sharpen §3.5.3. |
| CR4 | Med | `HttpEntryBundleStore` uses a **fixed** `.bundle.tmp` sibling name — the exact race `index_cache._unique_temp_path` was added in this same diff to fix. Both impls (Rust `entry_bundle_store.rs:198`); also pre-existing in `dep_decl_store.py`. A crash-mid-race leaves a torn cache file that later reads as a hard, un-self-healing `TNG-ENTRY-BUNDLE-PIN-MISMATCH` (permanent poison until manual delete). | **fixed** `6411da7` | Shared `atomic_cache` helper (index_cache + bundle + dep-decl stores unified onto it); read-path self-heal (discard locally-corrupt cache, re-fetch; server-mismatch stays hard). Tests both impls. |
| CR5 | Med | `milpa index status`/`accept` **manifest-error divergence**: Python swallows a syntactically-broken `milpa.kdl` (broad `except (OSError, MilpaError)` → warn) and prints a normal status block; Rust hard-fails with the `MAN-*` slug. Spec (§5.12 soft-fail is scoped to *local trust state*, not manifest parse) backs **Rust**; Python is the bug. Pre-existing pattern shared across the trust axes (§5.3a). | **fixed** `723d260` | Narrowed all 3 Python trust-axis loaders to MAN-NO-MANIFEST-only via shared `_manifest_absent` predicate; broken-manifest hard-fail tests both impls. |
| CR6 | Med | Mock verifier env seam: `MILPA_ENTRY_TRUST_MOCK_DEFAULT` **fails open to `Trusted`** on an unrecognized value in **both** impls — directly contradicting the adjacent "Test seam must never fail-open silently" guard on `MOCK_MAP`. Plus a 6-vs-8 wire-string coverage gap (Python's map omits `unattested`/`bundle-missing`; Rust accepts all 8, letting the verifier emit states its own trait forbids). | **fixed** `2221f05` | Fail-loud on unknown MOCK_DEFAULT in 4 sites (incl. both conformance adapters); Rust tightened to 6-value verifier domain (from_verifier_value). file:// gate intact. |
| CR7 | Med | Rust CLI does **not reject unknown flags/args** for `index accept`/`status` (`milpa index accept --refresh` silently runs the mutating flow); spec §3 requires exit 2. | deferred | CONFIRMED (verifier a7a0d04); re-scoped pre-existing **CLI-wide** Rust looseness (all `rest`-slice verbs). Filed **#189** — out of RFC scope; partial fix would make the CLI inconsistent. |
| CR8 | Low-Med | `evaluate_gate` docstring claims "performs no I/O" but prints to stderr itself; `GateDecision.warn_message` (designed for the caller to print after writes) is **dead** in production (only the Rust conformance runner reads it). Both impls. | open | CONFIRMED (verifier a5b54f9). No spec-backed ordering requirement; narrow observability window (warn printed before a later write could fail). Fix: either move the print to the documented post-write point via `warn_message`, or drop the field + correct the docstring. |
| CR9 | Low-Med | `WS-ENTRY-TRUST-ON-MEMBER` has **zero unit tests** in either impl (only conformance fixture-376); sibling `WS-INDEX-HISTORY-ON-MEMBER` has dedicated coverage. Stale "mirror the entry-trust tests above" comment in `workspace_tests.rs` points at nonexistent tests. | open | Coverage gap (reviewer ad8b4cd). Fix: mirror `TestWorkspaceMemberIndexHistoryRejected` in `test_ws_security_parity.py` + `workspace_tests.rs`. |
| CR10 | Low-Med | Non-scalar violation `candidate_value`/`baseline_value` rendering (provenance multiset, rekor/attestation) is never asserted against an independently-derived **string** — only opaque cross-impl digest equality (fixtures 386/408). Classic differential blind spot ([[testing_differential_blind_spot]]): a shared misrendering passes. | open | Coverage gap. Fix: pin the literal rendered strings in both unit suites. |
| CR11 | Low | Coverage asymmetries: Rust CLI verb tests miss the corrupt-baseline `accept`/`status` branch, plain-`status` exit-1, and member-dir delegation (all present in Python); `TNG-INDEX-BASELINE-WRITE-FAILED` untested in Rust (Python's test is `skipif root`, silently skipped in-container); `unique_temp_path` has no Rust analog; yank exclusion untested at the `add`/`update` CLI layer. | open | Coverage gaps (reviewer ad8b4cd). Batchable. |
| CR12 | Low | Design/hygiene cluster: `MilpaEnv.index_trust_config` confirmed-dead, touched-but-not-removed this diff; `entry_bundle_store` duplicates `dep_decl_store` line-for-line (P3a-declined extraction — ensure P3b/P4 actually does it); `build_entry_subject` reimplements the identity split instead of `identity.parse_identity` (silent empty digest on malformed input). | open | Design (reviewer afa3f3d). Root-cause per [[feedback_audit_for_duplication]]. |
| CR13 | Low | Correctness/polish cluster: `frozen.py` `_reconstruct_from_locked` drops `LockAttestation.namespace` (benign today, latent for future subject-rebuild-from-graph); `yanked_excluded` diagnostic lists non-constraint-satisfying yanked versions (noisy); bundle-pin diagnostics fire even with no `attestation` node; Rust `ResolvedDep`/`LockedDep.attestation` doc comments claim `bundle_pin` dropped (P3a carries it through — comment is now false). | open | Correctness/doc (reviewers ac0292a/a403219). |
| CR14 | Low | Spec-doc integrity: §3.4 says entry-trust is out-of-scope while §3.4.0 + errors.md fully specify it (contradiction); §3.5.1 Frozen table doesn't signal that *presence* routes to `TNG-INDEX-ROLLBACK` not `TNG-ENTRY-MUTATED`; §5.2 carries a stale "not yet enforced — lands at A5" note (A5 landed `b9a620e`); §3.2 doesn't mandate `published_at` raw-text capture that §3.5.3 relies on; entry-trust stages 0–7 have no single enumeration. `.baseline.meta established_at` empty-vs-absent self-heal diverges (Python regenerates `""`, Rust preserves) — advisory, output-only. | open | Spec/doc (reviewer a5bd648). Batch spec-text pass. |

**Not a finding — tracked deferral:** Rust `SigstoreEntryVerifier` stages 5–7 unconditionally return `SignatureInvalid` (real crypto not wired) while Python calls real `sigstore-python`. This is the **P3b judgment call already awaiting your veto** (sigstore-rs lacks a verify-against-known-digest primitive). Live divergence only once tianguis serves real bundles. Coverage reviewer's "HIGH: real-crypto path has zero coverage" is the same deferral — not actionable pre-P3b.

**Round-1 verdict:** 0 Critical, 1 High (CR1), 6 Medium, rest Low/doc. Nothing above High.
Awaiting Corey's fix mandate before any change.

## Review ledger — round 2

| id | sev | finding (lens) | status | resolution |
|----|-----|----------------|--------|------------|
| R2-1 | blocker | `accept` undefined for 2 of its 3 use cases (absent/corrupt baseline have no diffable state) (depth) | FIXED | three explicit branches w/ distinct messages |
| R2-2 | blocker | ephemeral CI = permanent TOFU; ratchet never activates on merge-gating runners (breadth) | FIXED | §2 Ephemeral environments (frozen-path immunity, cache persistence guidance, #188 filed) + threat-model cross-ref |
| R2-3 | sig | `accept` partial-failure looks like success; no preview; fourth CLI shape (design+breadth) | FIXED | `index status` (read-only; `--refresh` dry-run) + `accept` (atomic swap only, loud write-failure error); noun-verb family precedent |
| R2-4 | sig | `accept` contract surface unspecified (exit codes, stdout, --yes, URL, refresh-failure, idempotency, workspace, off/--no-index/trust-off, epoch blast radius) (breadth+depth) | FIXED | contract-points block; full verb-spec blocks at A1 |
| R2-5 | sig | `off` contradicts "regardless of policy"; re-enable semantics undefined (depth) | FIXED | off never reads/writes, preserves baseline; corrupt check ranges warn\|strict |
| R2-6 | sig | `.at`/`.reported` torn-write; no first-reported date storage; no canonical digest form (design+depth×2) | FIXED | merged `.meta` (established_at, reported_digest, reported_at); normative digest incl. raw candidate_value; digest in differential |
| R2-7 | sig | "monotone" names two different comparators — tag-collision footgun (design) | FIXED | attestation-monotone vs ordinal-non-decreasing, disjoint tags mandated |
| R2-8 | sig | root fields = second fold path (design) | FIXED | reserved empty-key synthetic entry; one literal fold |
| R2-9 | sig | "exactly once" overstates two-state enforcement (depth) | FIXED | per-observed-history note; anchor-re-establishment residual in threat model |
| R2-10 | sig | policy-axis spec prose duplicated 3× ("mirrors X" chains) (design) | FIXED | §3.4.0 generic axis model extraction at A1 + Part 2 cross-ref amendment |
| R2-11 | sig | no concurrency story; fixed `.tmp` name torn-write (pre-existing, tripled here) (breadth) | FIXED | §2 Concurrency (no-poisoning argument; no lock; unique temp names at A2d) |
| R2-12 | sig | A4a "both runners" false for Rust (no cache path in conformance runner); wrong-adapter trap; hashed-name mapping (feas) | FIXED | Conformance rewrite: asymmetry named, A4a-rs, logical→hashed mapping, post-state comparison |
| R2-13 | sig | A2 monolith ~6 pieces; bijection-lint "no deferred window" claim false (feas) | FIXED | A2a–A2e split; ID_NAME_TOO_LONG precedent cited, norm per-sub-slice |
| R2-14 | min | baseline schema-skew (older milpa vs newer baseline) crashes as TNG-SCHEMA-UNKNOWN (breadth) | FIXED | corrupt-includes-schema-unknown; parse errors map to BASELINE-CORRUPT |
| R2-15 | min | no read-only inspection surface for the new axis's state (breadth) | FIXED | `index status` (merged into R2-3 split) |
| R2-16 | min | root-vs-root composite tie undefined (depth) | FIXED | trailing `field` key component + A6 fixture |
| R2-17 | min | TNG-SCHEMA-UNKNOWN precedence + absent-vs-explicit-1 unstated (depth) | FIXED | schema_version row amended |
| R2-18 | min | strict fail-closed delays bundled legitimate yank notice (depth) | FIXED | named trade-off in threat model |
| R2-19 | min | `[milpa] notice:` prefix invented; codebase uses `warning:` uniformly (design) | FIXED | reuse `[milpa] warning:`; taxonomy change = separate CLI-contract RFC |
| R2-20 | min | `Baseline[T]` generic on 1 proven consumer; tuple can't carry violations (design) | FIXED | monomorphic RatchetOutcome(violations, advanced) |
| R2-21 | min | parse-at-gate is an unstated behavior change (feas) | FIXED | named + no-clobber fixture pinned |
| R2-22 | min | A3 misdirects (Rust one seam; derives present; MilpaEnv dead field) (feas) | FIXED | A3/A2c wording corrected |
| R2-23 | min | no GC surface for accumulated per-URL sidecars (breadth) | ACCEPTED | §6 clean-row note; future store-gc mini-RFC owns it |

## Review ledger — round 1

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
| R1-16 | sig | warn habituation (depth) | FIXED | `.reported` new-vs-recurring (superseded by R2-6's `.meta`) |
| R1-17 | sig | P3a strict usability overstated (delta) | FIXED | Part 2 honest tail |
| R1-18 | min | provenance diff semantics implicit (depth) | FIXED | multiset-by-value + in-place-mutation fixture |
| R1-19 | min | remediation hints, command table, TOFU wording, sidecar glob, structured payload, bare-name DoS honesty, OQ3 identity-gate rationale, baseline observability (various) | FIXED | §§2/3/6 + threat model |
| R1-20 | min | yanked-but-locked UX; auditor tooling unrealized (breadth) | DEFERRED | issues #186, #187 filed |

## Part-2 delta review (round 1, scope note DISCHARGED)

Fixes applied to `rfc-per-entry-attestation.md` in round 1: stage 1b
unconditional; OQ2 published_at mandatory post-epoch + epoch set-once;
P3a honest tail; bundle size-cap note; `MILPA_ENTRY_BUNDLE_DIR`; OQ3(ii)
amended (Part 2 owns the type, this RFC owns the order). Round 2 found no
new Part-2 staleness (checked: `index-history`/`accept`/ratchet
terminology consistent).

**Round-2 verdict:** 1 High (CR15) + 2 Med (CR16/CR17) + 1 Low (CR19) fixed; CR18 left (Low, test-only seam).

## Code-review ledger — stage 4, ROUND 3 (terminating, 2026-07-10)

Re-review of round-2 fix diff `2221f05..HEAD` (CR15 + CR16/CR17/CR19). Two agents (security+completeness, correctness+design). **CLEAN — 0 Critical/High/Medium. Loop terminates at the floor.** Security independently re-derived the CR15 field enumeration from first principles and confirmed completeness; correctness confirmed the wrapper/primitive refactors preserved all invariants (regression suites green), no dead code, cross-impl symmetry intact.

**Stage 4 (code review) COMPLETE.** Fixed this stage: CR1–CR6 (round 1) + CR15/CR16/CR17/CR19 (round 2) = 10 findings across 8 commits (`b4c4f8f`→`f2480f1`), each gated on full pytest + `dev-rust test --workspace`. Deferred: CR7 → #189 (CLI-wide arg validation). Left as Lows per mandate: CR8–CR14 (round-1 doc/coverage/polish), CR18 (from_verifier type-split — test-only seam). Every fix committed; nothing pushed.
