# rfc-conformance-parity — handoff

- **Stage:** 3 (/tdd) — Phase 2 Layer A. SLICED (S-A1..S-A4 in RFC §5). Grinding.
- **Resume:** `/tdd slice S-A1` (D1 surfaces SSOT) → S-A2 (cert JCS) → S-A3 (corpus lint) → S-A4 (pin.py). Then Layer B (S6 #166, S7 #135); Layer C gated (S4a→S4 #148). D4 Low + S5 (#146) stay deferred.

## Phase 2 Layer A — slices (chosen direction; recorded 2026-06-21)
- [x] **S-A1** — D1 normative-surfaces SSOT: `harness/surfaces.py` (FileSurface + named role constants LOCK_FILE/ROOT_NIMCFG/MANIFEST_FILE/DEPS_STRUCTURE_FILE/CERTIFICATE_FILE; NORMATIVE_FILES built from them; LIVENESS_CMDS/EXPECTED_EXIT_CODE/ABSENT_PATHS_SURFACE) + assertions.py derives (no surface literal inline) + test_surfaces.py SSOT proof + spec prose normative block strengthened. Pure refactor; harness 279/279 both impls div NONE, py 2149 pass, harness 196 pass. DONE.
- [x] **S-A1b** — D1 new enforcement: EMPTY_STDOUT_VERBS (7 verbs, strict stdout=="") + NORMATIVE_EXIT_CODES {0,1,2} wired as baseline range-check at the assert_conformance chokepoint + module-load invariant (EXPECTED_EXIT_CODE ⊆ NORMATIVE_EXIT_CODES). Both impls already conform — harness stayed 279/279 div NONE (no new divergence surfaced). Spec prose now asserts both normatively. py 2149 pass, harness 224 pass. DONE.
- [ ] **S-A2** — `certificate.json` JCS (RFC 8785) canonicalization: spec it; verify both impls already JCS-equal (150 passes) else align serializers; compare canonically.
- [ ] **S-A3** — static corpus lint (fixture-rot guard): slug∈errors.md + dir-name match; runs without impls; wire into §3.6 CI job.
- [ ] **S-A4** — `pin.py` ergonomics: `python3 -m harness pin <dir>` one-command flow.

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
- [ ] Slice 2 — fixture-144 in-process adapters (rust + python). Black-box already
      passes it; align the two in-process adapters to the CLI's
      MILPA_INDEX_URL→HttpDepDeclStore logic (RFC §4 Slice 2). *(Not a black-box failure.)*
- [ ] Slice 3 — `project-dir` control file (#167) — spec it + teach both in-process adapters.
- [ ] cert fixtures 127/128/150 — Python `--certificate` not implemented (parked in
      descriptors.py python_known_failing). Separate Python feature; decide if in-scope.
- [ ] Phase 2: S4a/S4/S5/S6/S7 (gated on differential-harness RFC).

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
