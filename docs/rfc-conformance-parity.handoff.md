# rfc-conformance-parity — handoff

- **Stage:** 4 (/code-review) **ROUND 1 IN FLIGHT** — Phase 2 scope (commits 077093e..24846eb). 5 review agents launched (correctness/quality/security/design/parity) on harness/ + new fixtures 289/290/291 + S4a fetcher changes (mocked.py, fetchers.rs) + cmd_show change + spec edits. Awaiting agent completion → adversarial verify → consolidate → present.
- **Resume:** if interrupted, re-run `/code-review docs/rfc-conformance-parity.md` (scope = Phase 2 commits 077093e..24846eb). Phase-1 ledger below is COMPLETE (floor reached prior session). S5 (#146) DESCOPED, D4 Low deferred, c4 routed to #110 (no code pending). Do NOT wrap /code-review in /loop.

## Phase 2 Layer B
- [x] **S6** — `fixture-289-ws-dev-deps-resolve`: 2-member workspace, member-a has regular dep (extlib) + dev-dep (devtool), member-b has member ref + dev-dep (testhelper); 3 external deps via mocked-fetches. Both impls BYTE-IDENTICAL (lock alpha-sorted per lockfile-schema; member-a nim.cfg = own deps, member-b = ws-wide union per 213/214/257; _deps_structure = 3 externals). harness 280/280 div NONE, py 2150 pass (auto-discovered in-process), harness 278 pass. DONE.
- [x] **S7** — `fixture-290-show-cond-requires` (#135): LIVENESS fixture (cmd=show → exit-0 + non-empty stdout, empty expected/; pre-seeded root milpa.lock per fixture-122 pattern; `when platform=linux` cond-require). SURFACED a real gap: Rust `cmd_show` had NO cond_requires loop (Python did) — fixed in milpa-cli/src/main.rs (data was already in LockedDep.cond_requires; purely a missing display loop). show is non-normative so needn't byte-match, but #135's purpose is the feature working in BOTH impls. harness 281/281 div NONE, rust conformance 2 pass, py 2150 pass. DONE.

**LAYER B COMPLETE** (S6, S7).

## Phase 2 Layer C (gated)
- [x] **S4a** — mocked-fetcher RAW-BYTES mode (mechanism for S4). Trigger: `mocked-fetches/<url-key>/archive` file (raw bytes), precedence over `format`/`archive_sha256`. Reads raw bytes → feeds through the REAL extractor via the SAME injection build-mode uses (Python `_run_bytes_through_real_fetcher` SSOT helper shared with build-mode; Rust shared macro over `fetch_tarball`). Valid→extracts+archive_sha256=sha256(bytes); corrupt→real path raises FETCH-EXTRACT-FAILED (wrapped FETCH-ALL-FAILED at resolver). Spec documents `archive`. 6 unit tests (3 py + 3 rust). py 2153 pass, rust milpa-core 417 pass, harness 281/281 div NONE. DONE.
  - ⚠️ **CAUTION for S4:** the corrupt archive MUST use compression-magic + corrupt body (e.g. `\x1f\x8b` gzip magic + garbage) so BOTH impls reject it via the real decoder → FETCH-EXTRACT-FAILED. PURE garbage (no magic byte) is treated as uncompressed tar and may diverge cross-impl (Python tarfile raises ReadError; Rust tar crate may treat as empty/EOF) — if S4 needs to assert on pure-garbage, that's a latent cross-impl divergence to investigate as a FINDING, not to paper over.
- [ ] **S4** — corrupt-tar fixture (#148): author a `conformance/spec-v1/` fixture using an `archive` file (compression-magic + corrupt body) so both impls surface FETCH-ALL-FAILED (the §7 wrapper slug). Entry (S4a) now MET.

S5 (#146) DESCOPED, D4 Low deferred.

## Phase 2 Layer A — slices (chosen direction; recorded 2026-06-21)
- [x] **S-A1** — D1 normative-surfaces SSOT: `harness/surfaces.py` (FileSurface + named role constants LOCK_FILE/ROOT_NIMCFG/MANIFEST_FILE/DEPS_STRUCTURE_FILE/CERTIFICATE_FILE; NORMATIVE_FILES built from them; LIVENESS_CMDS/EXPECTED_EXIT_CODE/ABSENT_PATHS_SURFACE) + assertions.py derives (no surface literal inline) + test_surfaces.py SSOT proof + spec prose normative block strengthened. Pure refactor; harness 279/279 both impls div NONE, py 2149 pass, harness 196 pass. DONE.
- [x] **S-A1b** — D1 new enforcement: EMPTY_STDOUT_VERBS (7 verbs, strict stdout=="") + NORMATIVE_EXIT_CODES {0,1,2} wired as baseline range-check at the assert_conformance chokepoint + module-load invariant (EXPECTED_EXIT_CODE ⊆ NORMATIVE_EXIT_CODES). Both impls already conform — harness stayed 279/279 div NONE (no new divergence surfaced). Spec prose now asserts both normatively. py 2149 pass, harness 224 pass. DONE.
- [x] **S-A2** — `certificate.json` canonicalization SPEC'D (conformance-fixtures.md §2.7.3). Reality: harness comparison is already STRUCTURAL (parse-then-compare; message excluded as non-normative; refutation set-equality by (package,constraint); resolved/witness order-sensitive) — STRONGER than plain JCS. Impls emit different BYTES (py json.dumps indent=2 vs rust hand-built single-line) but compare-equal; no serializer change needed. Spec cites RFC 8785 JCS for the primitive layer + the domain rules; emission key-order determinism = SHOULD (normative gate is structural; both impls already consistent; MUST would burden Rust for zero gate value). 27 tests; harness 279/279 div NONE, py 2149 pass, harness 251 pass. DONE.
- [x] **S-A3** — static corpus lint (fixture-rot guard) `harness/corpus_lint.py`: `lint_corpus(root, errors_md)→[LintViolation]`. Check (a) expected/error slug ∈ errors.md; (b) if dir-name-after-`fixture-NNN-` uppercased IS a known slug it MUST equal expected/error (descriptive names exempt — 55+ use them). Reuses corpus._discover_fixtures + an errors.md slug parser (SSOT). SURFACED 3 real rot findings (035/090/199 stale dir names) — fixed via rename in `a2851c7`; 090 rename exposed TNG-NO-SATISFYING-VERSION coverage gap → filed #174. Real corpus now lints clean. 16 lint tests; harness 267 pass, py 2149 pass, harness 279/279 div NONE. CI wiring into §3.6 job DEFERRED with the rest of the CI redesign (standing rule). DONE.
- [x] **S-A4** — `pin.py` ergonomics: `python3 -m harness pin <dir>` one-command flow. `pin_flow(input_dir, descriptors, choose_winner, candidate_dir, timeout)→Path` with injectable chooser (testable non-interactively); runs both impls, detects divergence (reuses corpus._detect_divergences — SSOT), emits candidate dir + expected/ from winner + divergence.json, confirms via re-run. `__main__.py` gains `pin` subcommand; bare invocation still runs corpus. Old `pin_candidate(FixtureSpec,...)` (generative tier) left intact — distinct use case. 11 tests; harness 278 pass, py 2149 pass, harness 279/279 div NONE. DONE.

**LAYER A COMPLETE** (S-A1, S-A1b, S-A2, S-A3, S-A4). Commits: 077093e, 18ace44, ca6694f, a2851c7+6796a09, +S-A4. Issue #174 filed (TNG coverage gap). Next: Layer B (S6 #166, S7 #135), then Layer C gated (S4a→S4 #148). S5 (#146) + D4 deferred.

## CURRENT STATE (2026-06-21) — BLACK-BOX HARNESS FULLY GREEN
`python PASS=279 FAIL=0 known_failing=EMPTY`, `rust PASS=279 FAIL=0 known_failing=EMPTY`,
cross-impl divergences NONE. Every black-box fixture passes for both impls with ZERO
per-impl skips. Only 6 structural KNOWN_LIMITATIONS remain (cmd has no CLI surface:
roundtrip fixtures; ws member nim.cfg layout; + c4 255/256 routed to #110).
Commits this arc: ea136d0 (SSOT seam) · 1fcca68 (Lows) · 4c5d4fc (fixture-150 cert parity).

### Forks — RESOLVED
- Fork 1 (cert): 127/128 were stale skips (Python passes). 150 = real parity bug, FIXED
  (4c5d4fc) — Python writes kind:failure cert for non-solver failures. known_failing empty.
- Fork 2 (c4 partial-profile 255/256): routed to #110 (comment 4763087221). CLI host-defaults
  absent axes by deliberate §8 design; conservative fix = empty-string=None three-way, awaits
  #110 decision. 255/256 stay in-process-deferred.

### Phase 2 — direction decided
- **Layer A (infra) FIRST** — chosen. Three pieces: (1) D1 normative-surfaces SSOT
  (`harness/surfaces.py` + spec prose; assertions.py hard-codes it today) INCLUDING the
  open cert-JSON canonicalization gap (propose RFC 8785 JCS — now extra-relevant post-150);
  (2) static corpus lint (fixture-rot guard: slug exists in errors.md + matches dir name);
  (3) pin.py ergonomics (`python3 -m harness pin <dir>`). NOT gated.
- **Layer B** (unblocked, deferred to after A): S6 ws+dev-deps fixture (#166), S7 show-liveness (#135).
- **Layer C** (genuinely gated): S4a raw-bytes mock mode → S4 corrupt-tar (#148).
- **S5 bz2 byte-equality — DESCOPED** to #146 (comment 4763536040); needs S4a + bz2 decode
  (neither impl has bz2; not a real Nim need). S4a still wanted for S4.
- NEXT ACTION: slice Layer A into /tdd slices (architect rounds already done for the whole RFC),
  then grind. Layer A start point: D1 surfaces SSOT extraction is the mechanical, highest-leverage first slice.

## Stage-4 OUTCOME (2026-06-21)
Code review: 5 lenses + adversarial verify, 3 fix rounds to floor, Low pass. Commits:
`ea136d0` (SSOT seam: H1/H2/M1-M6 unified), `1fcca68` (Lows: project-dir confine,
lock-regex tighten, dead-code). Both "active divergence" candidates REFUTED. All gates
green. D4 (harness→pyproject path-dep) deferred — premature vs unstable harness.

**Forks resolved:**
- Fork 1 (cert 127/128/150): handoff's "Python --certificate unimplemented" was STALE.
  Python has the full cert stack. 127/128 PASS today (stale skip — REMOVED from
  known_failing, verified). 150 = small real parity bug (Python doesn't write a
  kind:failure cert for non-solver RES-UNATTESTED-METADATA; Rust does). DECISION: fix now.
  **Fix agent IN FLIGHT** (a91a115c...): implements non-solver-failure cert write in
  cli.py, un-skips 150, target python PASS=279/0 known_failing empty. NOT yet committed.
- Fork 2 (c4 partial-profile 255/256): genuine spec fork. CLI host-defaults absent axes
  by deliberate §8/§3.C design. DECISION: routed to #110 (universal-resolution RFC) —
  comment posted (issue #110 comment 4763087221) capturing the absent-axis CLI surface +
  the conservative empty-string=None three-way option. 255/256 stay in-process-deferred
  until #110 decides. No code pending.

## PHASE 1 COMPLETE (2026-06-21)

Black-box differential harness GREEN: `python PASS=276 FAIL=0`, `rust PASS=279
FAIL=0`, cross-impl divergences NONE. Both in-process adapters' skip/known-failing
sets reduced to genuine CLI-only + spec-deferred items. All implementable Phase-1
slices landed: 0, A, B, C(c1–c4 + 205), E, 1, D, F, 2, 3, + fixture-114
un-quarantine. Commits f0fc3e7 → c77cfd3.

Remaining (NOT implementable autonomously — forks/gated):
1. **cert fixtures 127/128/150** — Python `--certificate` unimplemented (rust passes
   them black-box). A real feature, not a parity bug. Scope fork: implement in this
   RFC, or file as a separate Python-feature issue? (parked in descriptors.py
   python_known_failing.)
2. **c4 spec fork** (#159/#160/#110) — should the CLI express an explicitly-absent
   profile axis? (255/256 deferred to KNOWN_LIMITATIONS.) See RFC §4 c4.
3. **Phase 2** (S4a/S4/S5/S6/S7) — gated on the differential-harness RFC + S4a
   raw-bytes mock mode.

Older state (Slice C "205"): **BLACK-BOX HARNESS GREEN** (`HARNESS_EXIT=0`).
`python PASS=275 FAIL=0 (3 cert SKIP)`, `rust PASS=278 FAIL=0 SKIP=0`,
CROSS-IMPL DIVERGENCES = NONE (`/tmp/harness_after_205.txt`). The only remaining
parked items are 3 cert fixtures (127/128/150 = Python --certificate
unimplemented). Phase 1's primary exit criterion (harness green for both impls)
is MET; remaining = in-process adapter alignment (Slices 2/3) + the cert scope call.

## Slices
- [x] Slice 0 — baseline protocol (`f0fc3e7`).
- [x] Slice A — divergence detector flags pass/fail asymmetry (`e3f2c44`).
- [x] Slice B — runner honors `MILPA_CLI_FEATURES` family (`7c8ede6`); exposed Slice F.
- [x] Slice C c1/c2 — `<TARBALL-SHA256>` + local-dep symlink (`6e14648`); greened 181/182/183.
- [x] Slice C c3 — impl-neutral CAS seed for frozen (`81a1609`); greened 177/208/251.
- [x] Slice C c4 — partial-profile 255/256 deferred to KNOWN_LIMITATIONS (`94268da`);
      spec fork flagged (see Open forks).
- [x] Slice E — python ws flag-union -d: defines into member nim.cfg (`3854f8b`); greened 213/214/282.
- [ ] **Slice C "205"** — local-override transitive (py✗ rust✗, both-fail).
      Passes IN-PROCESS, fails black-box: `MockedLocalFetcher` (mocked.py:320)
      raises FETCH-MOCK-MISSING because it requires a `mocked-fetches/<url_key>/`
      entry, but the fixture supplies the override target as a REAL dir
      (`mylib-fork/`) in the fixture root. In-process resolves it directly (TBD how
      — trace local-override materialization in resolver vs CLI fetcher routing).
      Likely fix: MockedLocalFetcher falls back to reading the real path when
      `Path(p.path).is_dir()` and no mock entry exists. Verify the in-process path
      first to converge both. Needs care (don't rush). *(Python/impl.)*
- [x] Slice 1 — fixture-099 rust RES-PROVENANCE-CONFLICT (`f766d78`); closes #154.
- [x] Slice D — fixture-252 + 212 frozen active-flags-check ordering (`e59e6a1`).
- [x] Slice F — single-package fetch honors --features (`d238a5d`); greened
      209/210/211/216/228/230/244. **Divergences → NONE.**
- [x] Slice C "205" — local deps use real LocalFetcher in mock mode, both impls
      (`2578076`); removed dead MockedLocalFetcher (py) + its tests. **Black-box GREEN.**
- [x] Slice 2 — fixture-144 in-process adapters: DONE (code-review H1 SSOT
      `dep_decl_store_from_paths`; `_NOT_YET_WIRED_FIXTURE_NAMES` empty; closed #153).
- [x] Slice 3 — `project-dir` control file: DONE (spec §2.8.1 normative control input;
      both adapters honor via `harness/inputs.py::resolve_project_dir`; closed #167).
- [x] cert fixtures 127/128/150 — 127/128 were STALE (Python passes); 150 fixed (4c5d4fc).
- [x] Phase 2 Layer A: S-A1/S-A1b/S-A2/S-A3/S-A4 — DONE.
- [x] Phase 2 Layer B: S6 (#166) / S7 (#135) — DONE.
- [x] Phase 2 Layer C: S4a / S4 (#148) — DONE.
- [—] S5 (#146) DESCOPED; D4 (Low) DEFERRED; c4 → #110 (no code pending).

NOTE: fixture-114's KNOWN_LIMITATIONS reason ("stdlib harness cannot compute the
identity hash") is now STALE — Slice C c3 proved impl-neutral seeding via the lock
identity works. Re-evaluate fixture-114 for un-quarantining (it tests
FROZEN-LEGACY-REGISTRY-PROVENANCE / #115; may need its own handling).

Rust batch (1/D/F) all need `./dev-rust` (container image
`ghcr.io/coreyleavitt/milpa-rust`); gate each via `./dev-rust test -p milpa-conformance`.

## Open forks (awaiting Corey)
- RESOLVED 2026-06-21: "fold everything here" — all findings are in-scope Phase-1
  parity work in THIS RFC (not routed to #172).

## Key decisions (this session)
- Committed round-2 RFC (`c0cb5df`); Slice 0 (`f0fc3e7`); Slice A (`e3f2c44`); Slice B.
- "Fold everything here": expanded Phase-1 slice list (A–F) recorded in RFC §4.
- Slice B revealed the Rust CLI `--features` gap (Slice F) — runner gap was masking it.

## Review ledger (stage 4)
Round 1 — 5 review agents (correctness/quality/security/design/parity) + 3 adversarial verifiers.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| H1 | High | dep_decl_store selection logic triplicated (cli.py:425 `_build_dep_decl_store` ↔ test_conformance.py:411 `_build_env` ↔ runner.rs:549) — SSOT; diverges on next S3b change | open | verified CONFIRMED; Python copy avoidable via shared path-based helper, Rust copy unavoidable (lang) |
| H2 | High | `_compare_certificate_json` duplicated (harness/assertions.py:161 via `_canonical_certificate` ↔ test_conformance.py:467 inlined) | open | verified CONFIRMED; test_conformance can import harness version |
| M1 | Med | fixture-input translation triplicated; CURRENT divergence: `_feature_argv` strips whitespace on MILPA_CLI_FEATURES (runner.py:249), `_fixture_cli_features` does not | open | design+quality; whitespace-only value diverges black-box vs in-process |
| M2 | Med | deps-structure normalization duplicated (`_normalize_deps_structure` assertions.py:52 ↔ `_read_deps_structure` test_conformance.py:1318) | open | quality F4 |
| M3 | Med | tarball-sha256 redaction duplicated w/ divergent regexes (assertions.py:108 free-floating ↔ test_conformance.py:1278 line-anchored) | open | quality F5 |
| M4 | Med | env-file re-parsed inline in `_fixture_require_attested_metadata`+`_fixture_profile` instead of `_fixture_env_vars` | open | quality F3 |
| M5 | Med | Rust verify pre-phase DepDecl uses two-way check (no index.kdl→Http), ignores fx.no_index; resolve path is three-way | open | parity; verified HARMLESS on current corpus (Rust CLI verify uses no dep_decl_store) but LATENT — future index.kdl-only verify fixture would diverge |
| M6 | Med | `load_workspace(fixture_dir)` not `project_root` in frozen/verify paths (py test_conformance.py:744; rust runner.rs:648,786,838,889) | open | correctness Issue 2; resolve path was fixed, frozen/verify latent for project-dir+ws |
| L1 | Low | `_DEP_IDENTITY_RE` brittle (identity-first assumption undocumented) + quadratic on adversarial lockfile | open | mispairing-bug REFUTED (non-greedy fails to match, seeder skips absent name); brittleness+DoS residue harness-only |
| L2 | Low | project-dir not confined to scratch (runner.py:463) + spec allows absolute/`..` escape (conformance-fixtures.md §2.8.1) | open | security F2 + design F3; harness/authoring safety only |
| L3 | Low | `output_file="<conformance-verdict>"` string sentinel leaks verdict-vs-diff distinction into a path-typed field | open | design F5; suggest `is_verdict_asymmetry: bool` |
| L4 | Low | mocked.py:15 docstring still lists deleted MockedLocalFetcher | open | quality F6; one-line |
| L5 | Low | double `load_workspace` in `_execute_verify` (test_conformance.py:1062,1078; runner.rs:838,889) | open | quality F7 |
| L6 | Low | redundant `cmd` file reads in Fixture.__init__ (test_conformance.py:149-169) | open | quality F8 |
| R1 | — | Slice F divergence (root default=false dep, no profile/features: Rust includes, Python prunes) | refuted | resolver.py:830 passthrough fast path exits before flag gate; both return manifest unchanged |
| R2 | — | `_DEP_IDENTITY_RE` mispairs local-dep name to next dep's identity | refuted | non-greedy `.*?` simply fails to match a block w/ no identity; `_seed` skips name not in map |
| R3 | — | Verify-path asymmetry as a CURRENT normative divergence | refuted→M5 | Rust CLI verify uses no dep_decl_store; adapter can't diverge from absent CLI behavior on current corpus (kept as latent M5) |

### Round 1 fixes (uncommitted working tree)
H1 `dep_decl_store_from_paths` in milpa/dep_decl_store.py (CLI+adapter call it) · H2 adapter imports harness `_compare_certificate_json` · M1 `parse_fixture_cli_features`/`_env_flag` shared from harness.runner (+test_feature_flag_parity.py) · M2 adapter uses harness `_normalize_deps_structure` · M3 adapter uses harness `_apply_lock_placeholders` (opt-in) · M4 `_fixture_profile`/`_fixture_require_attested_metadata` call `_fixture_env_vars` · M5 Rust `fixture_dep_decl_store(fx)` three-way, resolve+verify · M6 frozen/verify use project_root (py+rust). GATES: py 2148 pass/0 fail; rust 21 pass; **black-box harness GREEN (py 276/0, rust 279/0, divergences NONE)**. R1 security/correctness/parity re-review: clean.

### Round 2 findings (re-review of the SSOT seam)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| D1 | Med | env-file parser STILL duplicated one layer down (`harness/runner.py:_read_env_file` ↔ `test_conformance.py:_fixture_env_vars`, byte-identical) — SSOT chain incomplete | open | design R2 F1 |
| D2 | Med | `_env_flag`/`parse_fixture_cli_features` are fixture-input concerns living in runner.py (subprocess-driver); naming asymmetry (one public, one private) | open | design R2 F2; fix via harness/inputs.py |
| D3 | Low | 3 harness.assertions helpers imported cross-package while underscore-private (false "internal" signal) | open | design R2 F3; promote to public |
| D4 | Low | `sys.path.insert(parents[3])` in test_conformance.py instead of a pyproject path-dep on harness | defer | design R2 F4 — infra; reviewer says defer until harness stabilizes |
| — | — | R2 security re-review | clean | no new surface; pure unification |
| — | — | R2 correctness/parity re-review | clean | no regressions; all env combos behavior-preserving |

### Round 2 fixes (uncommitted)
D1/D2/D3 → new `harness/inputs.py` owns `read_env_file`/`env_flag`/`parse_cli_features` (public); last duplicate env parser removed; 3 assertions helpers promoted to public (`normalize_deps_structure`/`apply_lock_placeholders`/`compare_certificate_json`). GATES green (py 2148/0; harness py 276/0 rust 279/0 div NONE). D4 deferred (Low infra).

### Round 3 re-review (FLOOR REACHED — 0 C/H/M)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| D5 | Low | dead import `parse_cli_features` in runner.py + false docstring in `_feature_argv` | fixed | inline cleanup (control loop); gates re-run green |
| D6 | Low | `_fixture_env_vars` is a pure pass-through wrapper (7 call sites could call `read_env_file` directly) | open (Low) | design R3 F2; left per fix-through-Med mandate |
| — | — | R3 design re-review | clean | SSOT chain complete; no remaining dup defs; deps sane; no circular |
| — | — | R3 security re-review | clean | pure move+rename; no new surface; pre-existing 2 Lows untouched |

**FLOOR:** Round 3 found 0 Critical/High/Medium.

### Low cleanup pass (all fixed except D4, uncommitted→committed)
| id | finding | status | proof |
|----|---------|--------|-------|
| D6 | `_fixture_env_vars` pass-through wrapper | fixed | deleted; 5 call sites → `read_env_file` directly |
| L1 | `_DEP_IDENTITY_RE` brittle/quadratic | fixed | `[^}]*?` (no DOTALL); spec-grounded (lockfile-schema §2.4: identity first, provenance last); ALSO fixed a real latent mispairing (old `.*?` crossed blocks, masked because unused) |
| L2 | project-dir not confined | fixed | `harness/inputs.py::resolve_project_dir` (SSOT) rejects absolute/escape; py runner+adapter + rust `fixture_project_root` call it; spec §2.8.1 normative sentence added |
| L3 | `<conformance-verdict>` sentinel | fixed | `DivergenceRecord.is_verdict_asymmetry: bool` discriminant |
| L4 | mocked.py stale docstring | fixed | MockedLocalFetcher bullet removed |
| L5 | double load_workspace in verify | fixed | load once, reuse (py + rust) |
| L6 | redundant cmd read | fixed | `Fixture.__init__` parses cmd once |
| D4 | sys.path→pyproject harness dep | DEFERRED | packaging change against unstable harness; reviewer-flagged premature; revisit at harness stabilization |

GATES after Low pass: py 2148 pass/0 fail; rust conformance ok; black-box harness OVERALL PASS, divergences NONE.

**Two pre-existing parked FORKS (awaiting Corey — next topic):** cert fixtures 127/128/150 (Python `--certificate` unimplemented), c4 partial-profile absent-axis (#159/#160/#110).

---

## Review ledger — STAGE 4 PHASE 2 (Round 1)
Scope: Phase 2 commits 077093e..24846eb (harness/ + fixtures 289/290/291 + S4a fetcher changes + cmd_show + spec). 5 lenses (correctness/quality/security/design/parity) + direct adversarial verification of every C/H/M against the cited code.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| P2-1 | Med | Python `_run_bytes_through_real_fetcher` (mocked.py:234) builds `TarballProvenance(url=url)` → drops `strip_components`; Rust macro (fetchers.rs:814) threads `*strip_components`. Latent cross-impl divergence in NEW S4a code | open | VERIFIED: both py call sites (290,304) pass only `p.url`; Rust passes `*strip_components`. No current fixture sets strip_components>0, so harness green today |
| P2-2 | Med | `_divergence_records_from_runs` (pin.py:141) dead + hardcodes cmd="resolve" fallback (would misclassify show/add fixtures if ever called) | open | VERIFIED dead: zero call sites; pin_flow uses `_detect_divergences(_read_cmd(...))` directly. 3-lens converge (quality/correctness/design) |
| P2-3 | Med | `_write_expected_from_run` (pin.py:248) hardcodes ("milpa.lock","nim.cfg","milpa.kdl") + "_deps_structure.txt" — bypasses surfaces.py SSOT (the very thing S-A1 built) | open | VERIFIED: literals present; surfaces.LOCK_FILE.name etc. exist. 2-lens converge (quality/design) |
| P2-4 | Med | Rust `resolve_tarball_mock_key` (fetchers.rs:947) dead `pub fn`, near-duplicate of `resolve_tarball_mock_key_dir` (980); duplicated FETCH-MOCK-MISSING error path | open | VERIFIED: only `_dir` variant called (800); not re-exported in lib.rs; no test calls it. 2-lens converge |
| P2-5 | Med | `parse_spec_slugs` (corpus_lint.py:46) re-implements `test_errors.py::_parse_spec_slugs` (regex vs startswith) — two parsers for errors.md slug header; docstring falsely claims "mirrors exactly" | open | VERIFIED both exist; SSOT split |
| P2-6 | Low | pin.py:55 dead `import tempfile` | open | VERIFIED never used (colocated w/ P2-2/P2-3) |
| P2-7 | Low | fetchers.rs:1010 dead `let buf: Vec<u8>` + drop(buf) at 1047/1068 | open | VERIFIED vestigial (colocated w/ P2-4) |
| P2-8 | Low | surfaces.py:73 `FileSurface.required` field never read by any enforcement path (false-SSOT signal) | open | VERIFIED only in def+docstring; assertions.py has parallel per-file logic |
| P2-9 | Low | assertions.py:899 `expected/absent` paths not confined to scratch — `scratch/rel_path` w/ `..` probes host paths (harness-only; corpus trusted; 1-line fix mirrors resolve_project_dir) | open | VERIFIED no guard; security lens, harness-side only |
| P2-10 | Low | assertions.py:277,634,611 `clean` verb as inline literal while liveness derives from surfaces.LIVENESS_CMDS — dispatch asymmetry | open | VERIFIED; minor SSOT-consistency |
| P2-11 | Low | `milpa show` format drift py↔rust (identity char count; Rust omits provenance line; active_flags spacing 1 vs 2). NON-NORMATIVE surface (won't break harness); #135 cond-req line itself IS byte-identical | open | VERIFIED by parity lens; show is non-normative for v1.0 |
| P2-12 | Low | pin.py `_write_expected_from_run` doesn't scaffold `certificate.json` for check-certificate fixtures → pin on such a fixture aborts unhelpfully | open | correctness lens; pin ergonomics gap |
| P2-13 | Low | spec/conformance-fixtures.md: cas-seed §2.10 NOTE documents a known impl BUG as spec behavior; `expected/milpa.kdl` only in NOTE not the normative surface table; `update` MUST-NOT-mutate buried in compound sentence | open | design lens; spec-prose polish |
| P2-14 | Low | mocked.py MockedOciFetcher stores `self._dir` but fetch() unconditionally raises (dead field); corpus_lint/pin deferred private imports (`_discover_fixtures`,`_extract_slug`) | open | quality/design; minor |
| I-1 | Med→issue | LATENT: pure-garbage archive bytes <512B with NO compression magic → Rust extractor returns Ok(empty dir), Python raises FETCH-EXTRACT-FAILED. fixture-291 SIDESTEPS (uses gzip magic + garbage). Underlying Rust extractor robustness gap, arguably pre-existing | open | VERIFIED by parity lens + handoff prior warning; FILE ISSUE not fix-in-loop (Rust safe_extract hardening, separable) |
| S-pre | — | OCI compressed body read into memory before cap (fetchers.rs:595) | wontfix-here | PRE-EXISTING, not Phase 2; OCI Tier-3 |

**Refuted/SAFE (recorded, not presented):** security verified the PRODUCTION raw-bytes→real-extractor path preserves ALL protections (size caps, zip-slip, symlink-escape, decompression-bomb via member.size) identically in both impls; corrupt-archive→FETCH-ALL-FAILED chain correct both impls; url_key byte-identical; precedence (archive>format>archive_sha256) holds both impls; archive_sha256 computation identical; fixture-289 semantically correct + both impls agree (lock alpha-sort, dev-dep merge, CAS omits members); fixture-290/291 sound; no command/flag injection (--end-of-options + leading-dash guards).

**Severity calls:** reviewers graded several dead-code/SSOT items "High"; downgraded to Medium — none cause incorrect runtime behavior on the current corpus (all are latent / dead / harness-only). No Critical/High after verification.

### Round 1 fixes (mandate: fix through Med + colocated Lows P2-6/P2-7 + security P2-9; file I-1)
Applied via 3 parallel sonnet agents (disjoint files). Status updates:
- **P2-1** fixed — `mocked.py::_run_bytes_through_real_fetcher` gained `strip_components` param; both call sites pass `p.strip_components`; 2 regression tests (raw-bytes + build mode) RED→GREEN. Now symmetric w/ Rust.
- **P2-2** fixed — deleted dead `_divergence_records_from_runs` (pin.py); zero refs remain.
- **P2-3** fixed — `_write_expected_from_run` now derives all surface names from `surfaces.LOCK_FILE/ROOT_NIMCFG/MANIFEST_FILE/DEPS_STRUCTURE_FILE` (.name byte-identical).
- **P2-4** fixed — deleted dead `pub fn resolve_tarball_mock_key` (fetchers.rs) + stale doc xref.
- **P2-5** fixed — new `harness/errors_md.py` is the single home for `parse_spec_slugs`; corpus_lint.py + test_errors.py both import it; second parser removed.
- **P2-6** fixed — removed dead `import tempfile` (pin.py).
- **P2-7** fixed — removed dead `buf` var + `drop(buf)` (fetchers.rs build_archive_bytes).
- **P2-9** fixed — assertions.py absent-loop now rejects absolute + `..`-escape before `.exists()` (mirrors inputs.py::resolve_project_dir SSOT); 3 new tests (2 RED→GREEN).
- **I-1** → filed as **#175** (Rust extractor pure-garbage <512B robustness; separable, not fixed in-loop).
- **DEFERRED Lows (left per mandate):** P2-8 FileSurface.required dead field, P2-10 clean-dispatch literal, P2-11 show drift (non-normative), P2-12 cert scaffold in pin, P2-13 spec prose polish, P2-14 OciFetcher dead field / deferred private imports. S-pre OCI mem-cap pre-existing.

GATES after Round 1: harness unit **281 pass**; impls/python pytest **2157 pass / 30 skip**; rust milpa-core **417 pass**; **black-box differential harness OVERALL PASS — python 282/0, rust 282/0, divergences NONE** (Rust release binary rebuilt before the run).

### Round 2 re-review (FLOOR REACHED — 0 C/H/M)
3 lenses on the changed scope (design/quality + security + correctness/parity).
- **Correctness/parity: CLEAN.** Empirically verified: slug parser identical 195-slug set (old vs new); strip_components now symmetric py↔rust in both raw-bytes + build modes; absent-confinement no false-positive on real corpus (fixture-278/279/280 `member-a/milpa.lock` still passes); regression tests non-tautological.
- **Security: CLEAN.** P2-9 correctly closed; validate-then-probe ordering; no TOCTOU/symlink bypass; safe_extract validates absolute paths BEFORE stripping so strip_components threading can't bypass path-escape. No new surface.
- **Design/quality:** 0 C/H/M; **2 new Lows, both residue of Round-1 fixes → fixed (not deferred):**
  - **R2-L1** assertions.py re-implemented the inputs.py confinement algorithm → unified into `inputs.confine(root, rel_path)->Path` SSOT; resolve_project_dir + absent-loop both delegate. *(One brittle sub-pattern the agent introduced — branching on confine's exception message string — fixed inline: classify by `Path(rel_path).is_absolute()`, not message text.)*
  - **R2-L2** Rust `resolve_tarball_mock_key_dir` returned vestigial `Result<((),PathBuf)>` (symmetry residue of deleted P2-4 sibling) → now `Result<PathBuf>`; call site updated.

**FLOOR:** Round 2 found 0 Critical/High/Medium. Remaining items are all deferred Lows (P2-8, P2-10, P2-11 non-normative, P2-12, P2-13, P2-14) + I-1→#175 + S-pre OCI pre-existing.

GATES after Round 2 (FINAL): harness unit **281 pass**; impls/python pytest **2157 pass / 30 skip**; rust milpa-core **417 pass**; **black-box differential harness OVERALL PASS — python 282/0, rust 282/0, divergences NONE** (Rust release binary rebuilt against final source).

### Low cleanup pass (all remaining deferred Lows — DONE, via 4 parallel agents)
- **P2-8** — dropped dead `FileSurface.required` field (surfaces.py): never read by any enforcement path (fixtures opt in via expected/<file>); removed from dataclass + 5 constructions + 7 test assertions. (harness tests 281→274 = the 7 dead-field tests.)
- **P2-10** — added `surfaces.CLEAN_CMD` constant; replaced 3 inline `"clean"` literals in assertions.py (dispatch, EXPECTED_EXIT_CODE key, _assert_empty_stdout). Symmetric w/ LIVENESS_CMDS.
- **P2-11** — aligned Rust `show` → Python (reference): identity `algo:digest[:8]`, added per-record provenance lines (`format_provenance_record`, all 6 variants), active_flags spacing 1-space. No Rust model change (provenances already in LockedDep). milpa-cli 64 pass.
- **P2-12** — pin.py `_write_expected_from_run` now scaffolds `expected/certificate.json` from `run.cert_path` (→ `surfaces.CERTIFICATE_FILE.name`); +2 tests.
- **P2-13 a/b/c** — spec prose: cas-seed §2.10 NOTE → NORMATIVE idempotency contract + points to **#176**; `expected/milpa.kdl` promoted to the surface table; `update` MUST-NOT-mutate is its own NORMATIVE paragraph.
- **P2-14** — dropped dead `MockedOciFetcher._dir`; promoted deferred private imports to public (`_discover_fixtures`→`discover_fixtures` in corpus.py; `_extract_slug`→`extract_slug` in runner.py) — deferred-import-in-function-body pattern gone.
- **#176** filed (cas-seed move-not-copy adapter bug; Low/latent).

### STAGE-4 PHASE-2 OUTCOME — COMPLETE
Code review complete: 5 lenses + adversarial verify (Round 1) → 1 fix round (3 agents) → fix-completion round (2 agents) → FLOOR (0 C/H/M, Round 2) → full Low cleanup pass (4 agents). All 14 P2 findings resolved (5 Med, 9 Low) + 2 round-2 residue Lows (R2-L1/L2) + 1 inline brittle-pattern fix. Issues filed: **#175** (Rust pure-garbage extractor, deferred), **#176** (cas-seed copy-not-move, deferred). S-pre (OCI mem-cap) pre-existing, out of scope.

**FINAL GATES:** harness unit **274 pass**; impls/python pytest **2157 pass / 30 skip**; rust **milpa-cli 64 + milpa-core 417**; **black-box differential harness OVERALL PASS — python 282/0, rust 282/0, divergences NONE** (binary rebuilt against final source).

**No commits yet — awaiting Corey's approval to commit.** Working tree (17 files): harness/{assertions,corpus,corpus_lint,inputs,pin,runner,surfaces,test_harness,test_pin_flow,test_surfaces}.py + NEW harness/errors_md.py; impls/python/milpa/fetchers/mocked.py + tests/{test_errors,test_mocked_fetchers}.py; impls/rust/crates/milpa-{cli/src/main.rs,core/src/fetchers.rs}; spec/conformance-fixtures.md; + handoff doc.
