# differential conformance harness — handoff

- **✅ #123 KDL 2.0 MIGRATION COMPLETE (2026-06-09, Rust+spec+corpus; Python out per Corey).** The harness (#3)
  caught a foundational oversight: milpa was ALWAYS meant to target **KDL 2.0** (align with nkdl). DONE:
  - **Rust → KDL 2.0:** 3 parse sites `parse_v1()`→native `parse()` (milpa-manifest lib.rs:450, milpa-core
    lockfile.rs:34, registry.rs:162); dropped the `v1` Cargo feature (it pulled in kdl 4.7.1 — source of the #122
    bug); emitter `format.rs` bare `true`/`false`→`#true`/`#false`; ~6 inline-test KDL literals updated.
  - **#122 RESOLVED:** under kdl 6.7.1 v2, `¼` (U+00BC, cat No) IS a valid ident → Rust returns
    MAN-UNKNOWN-TOP-LEVEL (conformant), matching Python 1.0's acceptance. The v1 4.7.1 `is_initial_char`
    `char::is_numeric()` bug is gone with the v1 feature. Pinned `kdl2_quarter_fraction_is_unknown_top_level`.
  - **Robustness regression root-caused (NOT worked around):** kdl 6.7.1 v2 `parse()` SIGABRTs (OS stack
    overflow, uncatchable) at depth ~50 (debug); no built-in limit. A subagent had hidden this by lowering the
    fuzz cap 200→50 — REJECTED per [[feedback_no_workarounds]]. Real fix: one shared `kdl_brace_depth()` helper +
    `KDL_MAX_NESTING_DEPTH=32` guard (6× real-world max, safely below overflow) at ALL THREE untrusted-input
    parse entry points (manifest→MAN-KDL-SYNTAX, lockfile→LOCK-KDL-SYNTAX, registry/index→TNG-KDL-SYNTAX; no new
    codes). Fuzz caps RESTORED to 1000 to *prove* deep input becomes a clean catalog Err, never a crash.
  - **Spec → KDL 2.0:** manifest-grammar.md, lockfile-schema.md, registry-protocol.md (grep `spec/` for "kdl 1" = none).
  - **Corpus:** 4 fixtures used bare bools as flag values (027/038/040/045) → `#true`/`#false` (bare `true` is a
    KDL-2.0 reserved-word parse error, so this preserves the arity/duplicate/unknown-props/undeclared-ref intent).
    These are now KDL-2.0-only → Python (stays 1.0 until rewrite #6) marked `known_failing` in harness/descriptors.py
    (NOT a Python fix). Grep corpus for stray bare bools = none.
  - **GATES:** Rust `--workspace` **267 green**; `python3 -m harness` exit 0 — **Python PASS=110 / Rust PASS=114 /
    118 fixtures / ZERO divergence** (110 = 114 − 4 KDL-2.0-only known_failing). All uncommitted (Corey-gated).
  - **Tiny follow-up deferred:** `impls/python/pyproject.toml` comment mislabels kdl-py as "KDL v2" (it's 1.0) —
    left untouched per "rust only"; fix at Python rewrite (#6).
- **⚠ 3e DECISION NOW LIVE (consequence of mixed spec versions — surface to Corey):** with Rust=2.0 and Python=1.0,
  the two impls conform to DIFFERENT spec versions until the Python rewrite (#6). The differential **agreement
  oracle is only valid across same-version impls**, so TIER-1 (arbitrary-KDL syntactic) generation will now flag
  1.0△2.0 differences as "divergences" that are actually expected → the 3e "1000-example no-new-divergence" bar is
  not honestly claimable for tier-1 until #6. TIER-2 (semantic graphs in the 1.0∩2.0 common subset) still agrees AND
  each impl's per-impl structural/conflict oracle (version-independent) holds → tier-2 saturation IS valid now.
  **Recommendation: run 3e saturation on TIER-2 (operational bar) now; gate tier-1 saturation on #6.** Awaiting Corey.
- **Stage:** 3 (tdd / implement slices)   •   **Round:** —
- **Resume:** the `/loop` grind command at the bottom. **#1 ✓ #4 ✓ #2 ✓ — ALL 8 HARNESS-FOUND BUGS FIXED
  (#118 R1-R4 + #119 P1).** Harness now FULLY GREEN: Python PASS=113/0, Rust PASS=113/0, known-failing=0 both,
  zero cross-impl divergence, 4 KNOWN_LIMITATIONS skipped. Rust workspace suite 262 green; Python 944.
  **NEXT = #3** (generator harness — has a design-in-loop tier-2 semantic-graph fork; start tier-1 infra, PAUSE
  at the fork). The loop runs autonomously (~10min gaps, [[feedback_loop_keep_going]]). #120 (spec gap,
  RES-NO-INDEX black-box) is a filed escalation for Corey — non-blocking, deferred via KNOWN_LIMITATIONS.
  **Everything uncommitted (Corey-gated).** Authority throughout = the spec, NOT the Python impl (the rewrite vehicle).

## ✅ #2 Phase B COMPLETE (2026-06-09) — the standalone black-box harness is built + found real bugs
`harness/` = standalone python3-stdlib (no `import milpa`, no 3rd-party deps): `descriptors.py`
(ImplDescriptor + python/rust descriptors, all Direct), `runner.py` (per-(fixture,impl) subprocess +
slug extraction), `assertions.py` (error/success gate + §2.6 normalization), `corpus.py` (corpus runner +
divergence record + summary + KNOWN_LIMITATIONS), `__main__.py` (`python3 -m harness`), `test_harness.py`
(13 unittest tests B1-B4, all green; run `python3 -m unittest discover -s harness -p 'test_*.py'`).
cmd→argv: resolve→fetch, frozen→--frozen fetch, parse-lockfile→show. Env per fixture: LC_ALL=C, isolated
MILPA_CACHE_DIR, MILPA_INDEX_URL=file://<scratch>/index.kdl (file:// blessed in cli-contract §8.1),
MILPA_MOCKED_FETCHES=<scratch>/mocked-fetches. **Full corpus black-box: Python 106 pass / Rust 96 pass /
ZERO cross-impl divergence among passing fixtures.** Rust release binary rebuilt + runs Direct on host.
- **KNOWN_LIMITATIONS (skipped all impls, logged):** 112,113 (RES-NO-INDEX not black-box expressible → #120);
  114 (cas-seed needs identity-hash reimpl in stdlib harness — deferred); 117 (workspace multi-member output).
- **Findings = the RFC payoff (real bugs the in-process adapters hid), filed + set known_failing in
  descriptors.py:** #118 Rust (R1 mocked CLI no CAS symlink→empty _deps_structure ×7; R2 maybe_index().ok()
  swallows TNG-*→RES-NO-INDEX ×7; R3 no MILPA_TARGET_* conditional filtering ×1; R4 frozen-workspace error
  detection missing ×2). #119 Python (find_workspace_root swallows workspace ManifestError→wrong slug ×7).
- **To validate a bug fix:** delete the fixture(s) from that impl's `known_failing` in `harness/descriptors.py`
  and run `python3 -m harness` (exits non-zero on any gate failure or divergence).

### Fix plan (NEXT rounds, ordered: clear bugs first)
- [x] **#118 R1 DONE (2026-06-09, spec-grounded root-cause).** Was deeper than "mocked CLI": Rust's LIVE
  `DefaultRegistry` fetch path admitted to CAS / symlinked `_deps/<name>` NOWHERE — a violation of
  `spec/identity.md` item 9 + §3.5 (relative symlink into CAS after admit) and `spec/plugin-contract.md`
  S10 items 7-8 + §4 (registry computes identity post-fetch + admits gated on `cas_admissible`). The harness
  couldn't see it (mocked-only) but it was real. Fix: one registry-layer orchestration `CasAdmittingFetcher`
  in `milpa-core/src/fetchers.rs` — stage→hash→`cas_admissible()`-gated admit+RELATIVE symlink; Local/editable
  (`cas_admissible=false`) stays a real working dir. Both `cmd_fetch` branches (real `DefaultRegistry` + mocked
  `MockedFetcher`) wrapped in it. Conformance `FakeFetcher` now delegates (zero parallel orchestration; only
  call-recording). runner.rs `seed_cas()` left (distinct concern: pre-seeds CAS for frozen, no `_deps` symlink).
  Single source of truth confirmed. Rust suite 255 green; harness Rust 96→**103** PASS, zero divergence.
  **Design note (Corey's UX Q):** kept the spec design — it's best-in-class. `cas_admissible`-gating gives
  integrity+dedup+stable-`nim.cfg`-paths for immutable deps AND live in-place editability for local deps;
  beats Cargo/Go (churny configs), copy-into-_deps (no dedup), pnpm hardlinks (Win/cross-fs pain). Authority
  = spec, NOT the Python impl (which is the rewrite vehicle, not the oracle).
- [x] **#118 R2 DONE.** `maybe_index()` used `load_index(...).ok()` → swallowed `TNG-*` validation errors to
  `None` → resolver wrongly raised `RES-NO-INDEX`. Spec `registry-protocol.md` (all field validators MUST apply
  during parse_index) → TNG-* must surface. Fix: `maybe_index() -> Result<Option<Index>, MilpaError>`; `Ok(None)`
  ONLY for infra sentinels `MILPA-INDEX-UNREACHABLE`/`MILPA-INTERNAL-IO`, propagate all else (incl. TNG-*) via `?`.
  +2 unit tests. Rust suite 257; harness Rust 103→**110**, zero divergence. Fixtures 087,093-098 expected
  TNG-SCHEMA-UNKNOWN/BAD-COMMIT-SHA/BAD-OCI-DIGEST/UNSAFE-{REF,URL,NAME,OCI-FIELD}.
- [x] **#119 P1 DONE.** `find_workspace_root` (workspace.py:106) `except ManifestError` was too broad —
  swallowed workspace-validation errors → fell through to package parse → wrong slug. Fix: new
  `manifest.kdl_has_workspace_block(text)` probe; if workspace-shaped → parse without catch (validation errors
  propagate); else keep walking. Parallel to R2 (only true absence → fallback). +6 tests; no new codes (all 7
  already in catalog). Python suite 944; harness Python 106→**113**, zero divergence. Fixtures 010/055/105
  MAN-WORKSPACE-HAS-DEPS-OR-KIND, 056 UNKNOWN-NODE, 057 MEMBER-ARITY, 058 MEMBER-DUPLICATE, 059 UNKNOWN-TOP-LEVEL.
- [x] **#118 R3 DONE.** Not missing machinery — `filter_manifest_by_profile`/`predicate_satisfied` already in
  milpa-core (conformance runner built the profile too); only the CLI binary passed `None` for profile. Fix:
  `profile_from_env()` in main.rs reads `MILPA_TARGET_{PLATFORM,ARCH,NIM,...}`, passed to both resolve paths.
  +3 unit tests. harness Rust 110→**111**, zero divergence. Fixture 115: `platform "windows"` dep excluded on
  linux profile (empty lock/cfg, never fetched). Spec manifest-grammar §6.2/6.4/6.6. ⚠ R3 subagent reported
  "161 passed" (looks per-crate, not `--workspace` 257) → FINAL GATE: re-run `./dev-rust test --workspace` after R4.
- [x] **#118 R4 DONE.** Workspace branch of `cmd_fetch` ignored the `frozen` flag entirely — always ran the
  slow `resolve_workspace` (network+solver); `resolve_workspace_frozen` (in frozen.rs) existed but was never
  wired into the CLI workspace path. Fix: workspace branch checks `frozen` → `resolve_workspace_frozen` (+ same
  `FROZEN-NO-LOCKFILE` guard as single-package). +2 unit tests. Rust `--workspace` **262 green** (confirms R3's
  per-crate "161" was not a regression); harness Rust 111→**113**, zero divergence. Fixture 085
  FROZEN-MEMBER-NOT-IN-WORKSPACE (lockfile member not in ws), 086 FROZEN-MEMBER-IDENTITY-DRIFT (on-disk hash ≠
  lockfile identity). Spec resolver-semantics §7 conditions 9-10.

**✅ ALL 8 HARNESS-FOUND BUGS FIXED.** Harness fully green (Py 113/0, Rust 113/0, 0 known-failing, 0 divergence).
NEXT = **#3** (generator). #120 (spec) awaits Corey.

## ✅ RESOLVED ESCALATION #2 (2026-06-09) — CLI mocked transport built (Phase A of #2)
Corey signed off: env var **`MILPA_MOCKED_FETCHES=<dir>`** (presence-activates), single source of truth
(promote fake-fetcher to production; adapters delegate). DONE both impls + spec:
- **Python** (938 passed/6 skip): `milpa/fetchers/mocked.py` (`MockedFetcher` + `url_key`); CLI activation
  in `cli.py` (`_mocked_fetcher_registry()` @ ~1217, used @ ~1238); `FETCH-MOCK-MISSING` slug added;
  `test_conformance.py` ConformanceFetcher DELETED, delegates to production. Tests: test_mocked_fetcher.py
  (10) + test_mocked_transport_cli.py (2).
- **Rust** (253 passed): `milpa-core/src/fetchers.rs` (`MockedFetcher` + `url_key` + `resolve_mock_key`/
  `stage_mock_content` SSOT); CLI activation in `milpa-cli/src/main.rs` cmd_fetch (~200-210);
  `FETCH-MOCK-MISSING` in `FetchError::all_codes()`; `milpa-conformance` delegates (urlkey.rs re-exports).
- **Spec:** cli-contract §8.4 (`MILPA_MOCKED_FETCHES` normative transport) + normative-surface item 13;
  conformance-fixtures §2.3 normative note (directory convention = CLI transport, adapter delegates);
  errors.md has FETCH-MOCK-MISSING (regenerated). Bijection/doc-match lints green both sides.
- **⚠ Cross-impl divergence CAUGHT + resolved during build** (the RFC thesis, again): the two Phase-A
  subagents disagreed on the missing-key CLI slug — Python re-raised inner `FETCH-MOCK-MISSING`, Rust
  wrapped as `FETCH-ALL-FAILED`. **Spec §8a is explicit** (candidate list always includes the primary;
  any exhausted list → FETCH-ALL-FAILED; inner cause folded into the human message). Rust conformed; the
  Python subagent's `fetch_any` "fix" had REGRESSED Python against spec → REVERTED `types.py` + fixed the
  test to assert FETCH-ALL-FAILED. No Corey escalation needed — spec was the arbiter (§2c). Documented the
  rule in cli-contract §8.4.

### Phase B (remaining #2) — the standalone stdlib harness (NEXT)
A `python3`-stdlib program (new top-level `harness/` per repo layout; imports stdlib only, drives impls as
black-box subprocesses, never imports milpa). Sub-slices: **B1 fixture runner** (ImplDescriptor + run ONE
fixture × ONE impl Direct: deep-copy inputs to isolated scratch, isolated MILPA_CACHE_DIR + MILPA_MOCKED_FETCHES
+ MILPA_INDEX_URL + LC_ALL=C, invoke `<argv> -C <scratch> <cmd>`, capture outputs + the `milpa-error:` slug;
tracer test vs one python fixture). **B2 corpus runner** (iterate fixtures × impls; §2.6 `<CAS_ROOT>`
normalization on `_deps_structure.txt`; byte-diff vs `expected/`). **B3 divergence** (cross-impl detection +
JSON record `{fixture,cmd,output_file,impls:{…}}` + summary grouped by `(cmd,output_file,shape)`). **B4 wire
both descriptors** (python Direct via `uv run`; rust Direct via prebuilt binary — REBUILD release first:
`./dev-rust build --release`, binary at impls/rust/target/release/milpa runs on host @0.0006s) + run full
117-fixture corpus through the black-box path for both, confirm byte-identical. All impls `invoke_via: Direct`
per the §2a build/run split — no per-fixture container.

## ⚠ OLD ESCALATION #2 text (for the record) — black-box CLI can't consume `mocked-fetches/`
The whole point of #2 is running the corpus through the CLI as a **subprocess**. But the deterministic
transport (`mocked-fetches/`) is only consumable **in-process** today: Python's fake fetcher is injected
via the `fetcher=` kwarg in tests; Rust's lives in `milpa-conformance/src/fake_fetcher.rs`. The production
CLI selects `default_registry` (real git/tarball/oci) — **no env var/flag activates the mocked transport.**
So the subprocess CLI cannot fetch deterministically → can't run any resolve fixture black-box. **#2 is
therefore NOT "infrastructure only / no novel signal" as the RFC claims** — it needs real production code
in BOTH CLIs + a new normative public surface. RFC issue-#2 line + the "#2 is infrastructure only" note
need correction once the design settles.
**Recommended design (awaiting sign-off):** add a CLI-activatable mocked transport selected by env var
`MILPA_MOCKED_FETCHES=<dir>` (presence-activates; value = path to a `mocked-fetches/` tree). When set, the
FetcherRegistry routes every fetch to a MockedFetcher reading `<dir>/<url@ref-key>/` per conformance-
fixtures §2.3 (return `sha`, copy `content/` + `<name>.nimble` into dest, admit to CAS); unmocked key →
hard error+slug; zero network. **Anti-duplication:** PROMOTE the existing FakeFetcher logic into the
production fetcher package (single source of truth) and have the in-process adapters delegate to it, rather
than keep a parallel copy ([[feedback_audit_for_duplication]]). Spec: new cli-contract subsection + promote
conformance-fixtures §2.3 from "adapter behavior" to "CLI transport." Sub-decisions for Corey: (1) env-var
shape (single presence-var vs `MILPA_FETCH_TRANSPORT=mocked`+dir); (2) OK to make a conformance/testing
transport a permanent public CLI surface (only active when explicitly set); (3) promote-and-delegate vs
keep separate.
- **NOTHING COMMITTED YET** (mono-repo restructure + all #1 + #4 work uncommitted; Corey-gated commit).

## ✅ RESOLVED ESCALATION (2026-06-09) — RFC §2a container design corrected (round 3)
Corey approved the three-option rewrite. §2a now documents the **build-time/run-time split**: build each
impl's runtime artifact once in its toolchain container, then run the harness ONCE in a single env holding
all artifacts, every impl `invoke_via: Direct`. `Container` demoted to optional escape hatch. Edits landed
in the RFC: round-2 header note + a "Round 3" note; §2a rust bullet + new "Build-time/run-time split"
subsection; corollary (no wrapper script); §2e (harness env DOES contain the python impl → no-import is a
review discipline, not physical absence; toolchains still excluded); acceptance criterion; issue-#2 line.
**#2 fork (wrapper-script vs precompile / podman benchmark) is DISSOLVED.** Original analysis kept below.

### Original analysis (for the record)
Corey challenged the per-fixture-`podman run` framing. He's right; §2a conflated *toolchain
container* with *harness container* and picked the worse of two options, missing the third:
- **(1) host harness + per-fixture `podman run` for Rust** — what §2a chose. MEASURED **~0.54s/fixture**
  (container startup; milpa ~0.02s of it) → ~63s/117-fixture run, LINEAR in fixture count → #3's
  generator loop = minutes of pure podman startup.
- **(2) harness inside the Rust *toolchain* container** — §2a rejected correctly (no Python there).
- **(3) one harness env holding every impl's *runtime artifact*, all `invoke_via: Direct`** ← RIGHT.
  Harness needs built artifacts, never toolchains. Build each artifact once in its toolchain container
  (build-time); run the harness once in a single env that has all artifacts (CI = one multi-stage image
  COPYing in each impl's binary; local = host). Container cost paid ONCE per run, not per fixture.
  MEASURED: container-built Rust binary runs **directly on host at 0.0006s/invocation** (~900× faster
  than `podman run`); the artifact is portable, the per-fixture wrapper was the whole cost.
**Resolution proposed (awaiting Corey):** rewrite §2a "container-vs-host tension resolved" para + the
round-2 header note that records it → three-option framing; demote `invoke_via: Container` from
"first-class Rust path" to optional escape hatch; add the build/run split. Descriptor struct unchanged.
**This DISSOLVES the #2 fork** (wrapper-script vs precompile / podman benchmark — moot). Once §2a is
revised, #2 proceeds with all-`Direct` descriptors and no per-fixture container in the hot path.
- **RFC:** `docs/rfc-differential-conformance-harness.md` (architect rounds 1+2 applied)
- **Lands on:** `main` for Gap-1 (spec + edits to *existing* CLIs — not a new impl).
  New *implementations* (the Python rewrite, Nim) go in branches.

## Context (this session)
- Rust port merged to `main` (FF). Mono-repo restructure done + committed
  (`9de7a90` layout, `15e7466` RFC): `impls/{python,rust}/`, top-level `spec/` +
  `conformance/`. Both suites green: Python 906, Rust 117/117. **Not pushed.**

## Slices (issue order; #1 blocks #2)
- [x] **#1 Gap-1 — terminal `milpa-error: <SLUG>` line — COMPLETE** (Python 920+6skip, Rust 233 green)
  - [x] 1a spec text: `spec/cli-contract.md` §3 (R1–R4 + no-`milpa-error:`-prefix rule, exit-2 usage class);
        `spec/conformance-fixtures.md` §5 item 4 + §3.1 reword. Added `MILPA-INTERNAL`
        + `INTERNAL-PANIC` (category INTERNAL) via `milpa/error_codes/internal_codes.py`;
        regenerated `spec/errors.md`. test_error_catalog green.
  - [x] 1b Python `impls/python/milpa/cli.py`: **DONE** (920 passed/6 skipped). See "#1 PYTHON SIDE COMPLETE" below.
        Added `_emit_error_slug(code)` helper; `MILPA-INTERNAL` catch-all in `main()` (now wraps
        `_dispatch(args)`; `except Exception` only, SystemExit propagates → argparse exit-2 intact);
        threaded `.code`/`getattr(e,"code",None)` through every typed+broad except in resolve/verify/
        add/update/remove/mirror; no-lockfile (show+verify) → `LOCK-FILE-NOT-FOUND`. Tests:
        `tests/test_error_channel.py` (5: MAN-KDL-SYNTAX, exit-0 no-line, no-lockfile, MILPA-INTERNAL
        catch-all, argparse exit-2). Python argparse ALREADY exits 2 (sub-problem 2 satisfied).
        **REMAINING → blocked on fork below (1e).**
  - [x] **1e (audit, RFC bullet #1e) — DONE.** All slug-less exit-1 paths now carry slugs; forks
        resolved by Corey. See "#1 PYTHON SIDE COMPLETE" below for the full landed inventory.
  - [x] 1c Rust `impls/rust/crates/milpa-cli/src/main.rs`: **DONE** (./dev-rust test --workspace = 233 green).
        Panic hook→`milpa-error: INTERNAL-PANIC`+exit 1; main() Err path now appends `milpa-error: <code>`;
        parse-fail/unknown-verb/add-no-name/add-no-flag/remove-no-name → exit 2 (no slug); verify missing-_deps→
        VERIFY-DEPS-DIR-MISSING + divergence→LOCK-GRAPH-MISMATCH (inline Ok(1)); remove-absent→MAN-REMOVE-DEP-ABSENT;
        add-duplicate pre-check→Err(MAN-ADD-DEP-EXISTS); frozen no-lockfile→FROZEN-NO-LOCKFILE. Added new slugs to
        Rust `CoreError::all_codes()` + `MAN_CODES` (bijection green). Binary smoke-verified: exit1+1 slug / exit2 no
        line / exit0 no line. **Known cross-impl divergences (acceptable; add/mirror not yet conformance-tested, →#5;
        harness #2/#3 will surface):** FROZEN-NO-CAS structurally unrepresentable in Rust (always builds a CaStore);
        MILPA-INTERNAL declared-not-emitted (INTERNAL-PANIC covers untyped); MAN-MIRROR-EDITABLE-PROVENANCE declared
        but add_mirror still emits MAN-ADD-MIRROR-IDENTITY-MISMATCH for local/member — needs targeted fix in
        manifest_writer.rs add_mirror.
  - [x] 1d Python bijection lints + errors.md doc-match GREEN. (Rust corpus.rs lints pending under 1c.)
        No corpus `expected/` files change.
- [x] **#4 parser fuzz — COMPLETE** (Python 926+6skip, Rust 246). Python: `tests/test_parser_fuzz.py`
      (4a parser-direct fuzz of parse_manifest/parse_lockfile/parse_index via Hypothesis + 4b CLI bytes
      fuzz via `main(["show"])`). Rust: `milpa-manifest/src/fuzz_tests.rs` + `milpa-core/src/parser_fuzz_tests.rs`
      (seeded xorshift64 loops, 2000 inputs/parser, no new dep). **Cross-impl divergence FOUND + fixed**
      (the RFC's thesis in action): malformed-KDL into the index parser → Python leaked raw
      `kdl.errors.ParseError`; Rust mislabeled it `TNG-SCHEMA-UNKNOWN`. Both now emit new **`TNG-KDL-SYNTAX`**
      (Python: tianguis_codes.py + tianguis_client.py:380 wrap; Rust: registry.rs:162 + CoreError::all_codes()).
      spec/errors.md regenerated; bijection lints green both sides; 2 Python regressions pinned.
- [x] **#2 neutral CLI black-box runner — COMPLETE** (Phase A mocked transport + Phase B harness). Built,
      operational, found 8 real conformance bugs (#118/#119) + 1 spec gap (#120). Python 106 / Rust 96 black-box
      pass, zero divergence among passing. See "✅ #2 Phase B COMPLETE" above.
- [ ] **fix harness-found conformance bugs** (#118 Rust, #119 Python) — NEXT; ordered fix plan above. Not an
      RFC slice per se, but the conformance payoff #2 exists to enable; do before #3 so new signal isn't drowned.
- [~] **#3 generator harness — IN PROGRESS (3a,3b done; 3c,3d,3e remain).**
  **Architecture (settled, not a fork — RFC resolved the tier-2 oracle = structural post-hoc check):** the
  Hypothesis GENERATOR lives on the impls/python side (the env with Hypothesis) under
  `impls/python/tests/differential/`, importing the repo-root stdlib `harness/` via a sys.path bridge
  (`__init__.py` + `conftest.py`, repo root = 4 parents up). The neutral serializer/pin layer stays stdlib in
  `harness/spec.py`. Gated by `MILPA_DIFFERENTIAL_TESTS=1` + rust-binary-present (mirrors integration-test
  skipif) so normal `uv run pytest` is unaffected.
  - [x] **3a** `harness/spec.py` (stdlib): `FixtureSpec`/`DepSpec`/`FetchEntry`/`IndexRow`/`IndexVersionEntry`
    + `serialize(spec,dest)` + `url_key()`. Consistency invariant (every git dep has a FetchEntry → drop-dep-
    drops-fetch safe for shrinking). url_key verified byte-identical vs real fixture-003. 35 harness tests green.
    TODO(3c): frozen-lock (`milpa.lock`) emit + multi-provenance (OCI/tarball) index rows.
  - [x] **3b** tier-1 syntactic generator + differential loop. `tests/differential/{strategies,loop,
    test_tier1_syntactic}.py`. Raw-bytes path (NOT FixtureSpec — parse fails pre-fetch, no FetchEntry needed).
    `run_all_impls()` + `agreement()` oracle = exit-CLASS (success/error:<slug>/crash) equality across impls;
    `Divergence` dataclass (§2e JSON shape). Ran 50 malformed-manifest examples × both impls: **ZERO
    divergence** (both agree MAN-UNKNOWN-TOP-LEVEL/MAN-NAME-MISSING/MAN-KDL-SYNTAX). Gate-off 944/7skip.
  - [~] **3c-1 DONE — tier-2 SATISFIABLE generator + structural oracle (the operational bar) OPERATIONAL.**
    `tests/differential/{strategies.satisfiable_graph_st, test_tier2_semantic}.py` + `loop.structural_oracle`.
    Construct-by-known-solution (pick solution versions → acyclic DAG → constraints containing the solution →
    project to FixtureSpec w/ real content hashes). `harness/spec.py` extended: `compute_content_hash_from_files`
    (stdlib sha256 per identity.md), `index_fetch_map`, `validate()` (every index version has a fetch; every
    named dep in index; every requires-edge names a known pkg). Structural oracle = stdlib lock parse +
    semver `_satisfies_constraint` + completeness check, applied to EACH impl independently (catches "both wrong").
    30 examples, both impls agree + pass oracle. Harness unittest 35→45. Gate-off 944/8skip. 2 GENERATOR bugs
    fixed (bare-version constraint invalid; content_hash must include `<name>.nimble`).
    **⚠ ESCALATION → #121 FILED (spec/catalog gap; loop's "pause on wrong-spec escalation" trigger).** The
    generator-bug-#1 trigger surfaced a REAL both-impls-wrong divergence: a malformed version constraint in a
    MANIFEST NamedDep (root/member/transitive milpa.kdl) → Python leaks `MILPA-INTERNAL` (4 unwrapped
    `from_constraint` sites: resolver.py 519/1216/1702 + frozen.py 184), Rust mislabels `MAN-NIMBLE-CONSTRAINT`
    (spec-scoped to .nimble only). NO catalog code exists for manifest-constraint-malformed. Case A (.nimble
    requires) = NO divergence (both correct). Fix = NEW code (proposed `MAN-DEP-CONSTRAINT`) + Python SSOT
    `_from_manifest_constraint()` wrapper + Rust from_constraint() call-site distinction.
    **✅ #121 RESOLVED (Corey said go; parse-boundary best-in-class design, NOT the patch).** Root-cause both
    impls: constraint parsed → typed VersionSet at the MANIFEST-PARSE boundary, resolver holds only typed sets,
    leak structurally impossible. Python: `NamedDep.__post_init__` parses (raises MAN-DEP-NAMED-CONSTRAINT),
    ZERO from_constraint on manifest deps (949 pass). Rust: `parsed_constraint`/typed `Item::Named.constraint`
    through BFS, `from_constraint`→`from_nimble_constraint` (1 .nimble site) (264 pass). Broadened existing
    `MAN-DEP-NAMED-CONSTRAINT` (no new code); errors.md regen; lints green. Pinned `fixture-119-man-dep-named-
    constraint-bad-string` (expected MAN-DEP-NAMED-CONSTRAINT). Harness now **Python 114 / Rust 114 / 118
    fixtures / ZERO divergence**. Case A (.nimble) unchanged-correct. **NEXT = resume loop at 3c-2.**
  - [x] **3c-2 DONE — tier-2 UNSATISFIABLE generator + conflict oracle.** `unsatisfiable_graph_st()` →
    `(FixtureSpec, ConflictWitness)`; construct-by-known-conflict (root→A,B; A requires C>=2.0.0, B requires
    C<2.0.0, C index={1.0.0,2.0.0} → empty intersection by construction). `loop.conflict_oracle` asserts both
    impls exit-1 `SOLVE-CONFLICT` (stronger than agreement — catches both-wrong-same-way). 30 examples, both
    SOLVE-CONFLICT, no findings. **Tier 2 (operational bar) COMPLETE.**
  - [x] **3d DONE — shrink→pin + dedup + seeded-divergence detection.** `harness/pin.py` `pin_candidate(spec,
    record, dest)` (serialize inputs + `divergence.json`, NO expected/ per §2c human-gate). `harness/dedup.py`
    `behavioral_class()=(cmd,output_file,frozenset(impl_outcomes))` + `DivergenceCollector` (summary-first §2e
    ordering, ≤1 repr/class). Seeded test (`test_seeded_divergence.py`): hermetic broken-impl shim + Hypothesis
    `find()` → minimal diverging FixtureSpec → pin candidate. Harness unittest 45→63; gate-off 950/13skip.
    **⚠ FINDING → #122 FILED (tier-1 KDL divergence, clear spec verdict but upstream + resolution fork):**
    input `¼` (U+00BC) → Python `MAN-UNKNOWN-TOP-LEVEL` (accepts, conformant), Rust `MAN-KDL-SYNTAX` (rejects).
    Spec = KDL 1.0 (manifest-grammar.md normative); per KDL 1.0 ¼ IS a valid ident → **Rust non-conformant via
    UPSTREAM `kdl-rs 4.7.1` bug** (`is_initial_char` uses `char::is_numeric()` = Nd+Nl+No, over-blocks fractions/
    superscripts/Roman/Arabic-Indic). milpa delegates KDL parse → can't TDD-fix internally. Both impls use KDL 1.0
    (Python kdl-py 1.2.0; Rust kdl 6.7.1 parse_v1→4.7.1). **3e SATURATION BAR is COUPLED** (can't claim 1000-ex
    no-new-divergence while #122 open) → needs Corey's resolution-path call (rec: file upstream + log as known-
    divergence interim) + KDL-1.0-vs-2.0 strategy question. **LOOP PAUSED on #122 (fork + saturation coupling).**
  - [ ] ~~**3c**~~ (split into 3c-1 done / 3c-2) tier-2 SEMANTIC generator (satisfiable + unsatisfiable via named deps +
    multi-version index rows + transitive nimble requires) + structural post-hoc oracle (RFC §2c: each impl's
    lockfile — every locked version satisfies every manifest constraint; unsat → both exit-1 SOLVE-CONFLICT +
    record conflict pair). The OPERATIONAL BAR. Strategy = construct-by-known-outcome (pick a solution then
    consistent constraints for sat; inject known conflict for unsat). ⚠ highest design risk — if genuine
    ambiguity/divergence emerges, triage (spec-arbitrate) or PAUSE for Corey.
  - [ ] **3d** shrink→pin-candidate (Hypothesis shrinks the FixtureSpec value; serialize minimized → pin
    candidate dir; human-gated promotion to conformance/) + behavioral-class dedup (§2c: ≤1 issue per
    `(cmd,output_file,shape)`).
  - [x] **3e DONE** — saturation/coverage on the SPEC-CONFORMANCE bar (Corey reframe: spec is the only authority;
    cross-impl divergence is a *finder* not the pass/fail criterion; no Python investment). `harness/coverage.py`
    (`CLAUSE_INVENTORY` = 45 normative MUST clauses, 43 black-box-observable; `coverage_report()` → covered/gap
    lists via log, never fails on gaps) + `harness/test_coverage.py` (9 tests). Coverage: **37/43 covered (86%)**;
    6 gaps all known (cli.show-no-lock, cli.verify-no-lock, resolver.dev-deps-root-only, + cli.add-git/remove/update
    = §2f → #5). Saturation: `impls/python/tests/differential/test_saturation.py` (gated; `MILPA_SATURATION_EXAMPLES`
    default 1000, 50/50 sat/unsat), each impl validated against the spec via its oracle, divergences triaged (KDL
    1.0-vs-2.0 artifacts excluded, genuine spec violation = blocker + pin). **Full run: tier-2 SAT 500 ex / 0 oracle
    fail / 0 divergence; tier-2 UNSAT (4 unique variants) / 0 fail; ~103s; ZERO new spec violations.** Tier-1 NOT in
    the bar (no independent per-impl spec oracle — parse robustness already covered by #4 fuzz per-impl). **Known
    follow-up (flagged, not blocking): unsat generator yields only ~4 structurally-distinct graphs (Hypothesis
    dedups) → widen diversity later.** Harness unittest 63→72; gate-off 946 (4 KDL-2.0 known_failing)/6 skip.
  **✅ #3 COMPLETE (3a–3e). Only #5 remains.**
- [x] **#5 fixture-format extension — COMPLETE.** Corey's 2 decisions: `show`/`--version` = LIVENESS-ONLY (exit 0
      + non-empty stdout, format non-frozen per cli-contract §5.3); mutation verbs = extend mocked transport to
      resolve refs→SHA (reuse mock entry `sha`, SSOT). Landed:
  - **Spec:** conformance-fixtures.md §2.7.1 (mutation selectors `add <n> git=<u> ref=<r>`/`remove <n>`/`update [<n>]`
    + `expected/milpa.kdl`+`expected/milpa.lock` slots), §2.7.2 (liveness), §2.3.3 + cli-contract §8.4 (mocked
    ref-resolution from the mock entry, SSOT). No new error codes.
  - **Rust:** `mocked_default_branch()` in fetchers.rs (ref-resolution via the same mock entry `resolve_mock_key`
    reads — SSOT); `cmd_add --git` rewritten to §5.6 (discover branch mock/real, full resolve, atomic write both
    files). **Then made `remove`/`update` SPEC-CONFORMANT (the subagent had scoped fixtures AROUND their gaps =
    impl-as-oracle; rejected):** `cmd_remove` now §5.7 (reject undeclared, full re-resolve over manifest-minus-dep,
    atomic write both, on-fail unmodified); `cmd_update` now §5.8 (no-arg=drop-all+re-resolve; scoped `update <dep>`
    = reject-not-in-lock, drop only that pin, pass rest as `prior_lockfile`, re-resolve, write lock, never touch
    milpa.kdl). Resolver's `prior` param already supported scoped update — no faked behavior.
  - **Harness:** runner `_cmd_to_cli` maps mutation/liveness cmds to real argv; assertions byte-compare
    `expected/milpa.kdl`(+lock) w/ §2.6 norm, liveness = exit 0 + non-empty stdout (no stdout byte-compare).
  - **Corpus:** fixture-120-add-git-dep, 121-remove-dep (+expected/milpa.lock), 122-show-liveness (passes BOTH
    impls), 123-update-all (no-arg), 124-update-scoped (`update foo`, retains `bar`'s pin). 120/121/123/124
    python_known_failing (KDL-2.0 emitter / Python mutation verbs lack mock transport — fixed at rewrite #6); 122 not.
  - **Python pytest green-keeping** (tests only, impl frozen): test_conformance.py skips the 4 KDL-2.0-only fixtures
    (`_KDL_2_0_ONLY`) mirroring the harness descriptor → `uv run pytest` 946 passed / 24 skip / 0 fail.
  - **GATES:** Rust `--workspace` **275 green**; `python3 -m harness` exit 0 — **Python PASS=111 / Rust PASS=119 /
    123 fixtures / ZERO divergence**; harness unittest **90**; Python pytest 946/24skip/0fail.

## 🏁 RFC FULLY IMPLEMENTED (2026-06-10) — #1 ✓ #4 ✓ #2 ✓ #3 (3a–3e) ✓ #5 ✓. Loop stop-condition met.
Everything uncommitted (Corey-gated) — this is the natural commit point for the whole differential-harness +
KDL-2.0-migration + #5 body of work. **Known follow-ups (NOT blocking; candidates to file):**
- unsat generator yields only ~4 structurally-distinct conflict graphs (Hypothesis dedups) → widen diversity.
- 3 coverage gaps lack fixtures: cli.show-no-lock, cli.verify-no-lock, resolver.dev-deps-root-only.
- Python `pyproject.toml` comment mislabels kdl-py as "KDL v2" (it's 1.0) — fix at rewrite #6.
- Python in-process conformance adapter auto-skips ALL mutation/liveness verbs (CLI-only); they're covered only by
  the black-box harness against Rust — full Python coverage of those verbs lands with the rewrite (#6).
- [ ] **#6 Python rewrite** tracking (folds in 1b; the rewrite proper is a *branch*).

## #1 PYTHON SIDE COMPLETE (1a+1b+1d+1e) — 2026-06-09. Python suite 920 passed / 6 skipped.
Both 1e forks RESOLVED by Corey: (1) non-argparse usage errors → **exit 2** + §5.6 amended; (2) finish
1e now in #1, code set **approved as proposed**. What landed:
- **Catalog (regenerated spec/errors.md):** new `MILPA-INTERNAL`,`INTERNAL-PANIC` (cat INTERNAL, 1a);
  `FROZEN-NO-LOCKFILE`,`FROZEN-NO-CAS`; `VERIFY-DEPS-DIR-MISSING` (new cat VERIFY); `LOCK-DEP-NOT-FOUND`;
  `MAN-ADD-DEP-EXISTS`,`MAN-REMOVE-DEP-ABSENT`,`MAN-MIRROR-EDITABLE-PROVENANCE`. Broadened
  `LOCK-GRAPH-MISMATCH` desc to cover disk-vs-lock (verify reuses it). Files:
  error_codes/{internal,verify}_codes.py (new) + frozen/lockfile/manifest_codes.py edits + __init__.py.
- **cli.py:** `_emit_error_slug(code)` helper; `MILPA-INTERNAL` catch-all (`main` wraps `_dispatch`,
  `except Exception` only so argparse SystemExit(2) propagates); `.code` threaded through ALL typed+broad
  excepts; `_try_frozen`/`_try_workspace_frozen` now return code-carrying `NotFrozen` (not bare str);
  frozen `--frozen` exit-1 emits its code; verify missing-_deps→VERIFY-DEPS-DIR-MISSING, divergence→
  LOCK-GRAPH-MISMATCH; add dep-exists→MAN-ADD-DEP-EXISTS; add-no-flag→**exit 2 no slug**; remove-absent→
  MAN-REMOVE-DEP-ABSENT; update no-kdl→MAN-NO-MANIFEST/no-lock→LOCK-FILE-NOT-FOUND/dep-not-in-lock→
  LOCK-DEP-NOT-FOUND; mirror no-lock→LOCK-FILE-NOT-FOUND/not-in-lock→LOCK-DEP-NOT-FOUND/editable→
  MAN-MIRROR-EDITABLE-PROVENANCE. no-lockfile show→LOCK-FILE-NOT-FOUND.
- **Tests:** tests/test_error_channel.py (13 via main()+capsys, slug-line assertions). New bijection lint
  `test_every_emit_error_slug_literal_is_in_catalog` in test_error_catalog.py. KNOWN_UNTESTED += FROZEN-NO-CAS
  (defensive), MAN-MIRROR-EDITABLE-PROVENANCE (costly setup). Doc-match green.
- **Spec:** cli-contract §3 rewritten (exit 0/1/2; §3.1 R1–R4); §5.6 add-no-flag→exit 2; normative-surface
  item 7; conformance-fixtures §3.1+§5 item 4 reworded `.code`→terminal-line.

## REMAINING for #1: only **1c (Rust)** — `impls/rust/crates/milpa-cli/src/main.rs`
Mirror the Python contract: terminal `milpa-error: <SLUG>` line iff exit 1; parse/usage → exit 2;
top-level panic handler → `milpa-error: INTERNAL-PANIC` before exit 1; fix `cmd_verify`/`cmd_add`/
`cmd_remove` `Ok(1)` prose-only paths to carry slugs; reuse the SAME slugs the Python side emits for
the equivalent conditions (incl. the 1e additions). Keep Rust corpus.rs bijection/exempt lists green.
Run via `./dev-rust test --workspace` from repo root (container). Was 117/117.

## Open forks (awaiting Corey — the loop will pause here)
- **#2: SUPERSEDED by the §2a escalation above** (the per-fixture-podman fork dissolves under option 3). ACTIVE: awaiting go-ahead to revise §2a.
- #3: semantic-graph generator strategy (oracle = structural post-hoc validity check, per RFC §2c).
- #5: mutation-verb fixture grammar + `show` freeze-or-liveness.

## Key decisions (this session)
- Gap-1 = terminal `milpa-error: <SLUG>` line (NOT inline rustc-style); position-independent (R2). [[spec_versioning_deferred]]
- No corpus regen (error fixtures store bare slug; runners read `.code`). Gap-1 = spec + both CLIs only.
- Mono-repo, normalized layout; 3-pronged impl plan stands; new impls in branches.

## Review ledger (stage 4 — not started)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (stage 4 not started) | — | — |

---
**Resume command:**
```
/loop implement the next unimplemented slice of docs/rfc-differential-conformance-harness.md
with /tdd, in issue order (#1 Gap-1 → #4 → #2 → #3 → #5), Gap-1 on main; after each slice
report one progress line (e.g. "1b done, slices remaining: 1c,1d,#4…"); pause on any fork or
wrong-spec escalation; stop when every slice is implemented
```
