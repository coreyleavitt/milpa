# Clean-room Python rewrite — handoff

- **Stage:** 3 (tdd) — **LOOP PAUSED (2026-06-12): all autonomous implementation slices DONE. Awaiting Corey for the gated final mile** (see "LOOP PAUSED" below).

## ⏸ LOOP PAUSED — awaiting Corey (the implementation is COMPLETE + fully conformant)
**Done:** Stages 0–10 — the entire clean-room rewrite. `MILPA_PYTHON_NG=1 python -m harness` → python-ng 121/121, FAIL=0, known-failing=0, **ZERO divergence vs Rust**. pytest 1171/5/0, mypy --strict + ruff clean. **COMMITTED to main as `f4f54e2`** (2026-06-12, not pushed) — impls/python-ng/ + gated harness descriptor + RFC docs + §7.1 spec scope. Frozen impl untouched.

**Remaining work is all Corey-gated — the loop correctly stopped rather than do it autonomously:**
1. **COMMIT (recommended first):** the whole rewrite is uncommitted. Natural checkpoint before the swap. Suggest committing `impls/python-ng/` + the gated `harness/descriptors.py` change as a `feat(python-ng):` commit (frozen impl untouched, so nothing breaks).
2. **`--certificate` flag** (RFC §8 external MUST): **SPEC SECTIONS DONE — committed `6c683d9`** (cli-contract.md §2.5 `--certificate <path>` flag, both-outcomes design, exact JSON schema + deterministic ordering; conformance-fixtures.md §2.7.3 `check-certificate` fixture type w/ canonical comparison). REMAINING (S10b): wire the flag in cli.py (serializer `certificate_to_json` exists in solver.py, SSOT) + author check-certificate corpus fixtures + **reconcile certificate_to_json's array order to the spec-mandated order** (resolved lexicographic-by-package; witness by package then satisfied_by) — verify the serializer emits exactly that, fix if not (spec is oracle). Cross-impl: Rust must emit the same JSON + pass the new fixtures.
3. **11b saturation:** run `harness/coverage.py` MUST-clause map against the new impl; produce the ~50-no-fixture-slug 3-bucket partition (black-box-testable / network-only / type-enforced-unreachable) as the deliverable (no silent gaps); file NEW corpus fixtures for the black-box-testable bucket (FETCH-SHA256-MISMATCH, FETCH-MOCK-MISSING, VERIFY-DEPS-DIR-MISSING, MAN-NO-MANIFEST, mutation-verb slugs). **Cross-impl — Rust must also pass any new shared fixture (run ./dev-rust).**
4. **11c THE SWAP (irreversible — needs explicit go):** atomic `git mv impls/python-ng → impls/python` (frozen impl out); regenerate `spec/errors.md` FROM the new `errors.py` (gains the 2 pending codes FETCH-REF-DISCOVERY-FAILED + MILPA-INDEX-UNREACHABLE); land the Rust companion (catalog entry + DEFERRED→implemented + raise sites for those 2 codes); remove the `MILPA_PYTHON_NG=1` harness gate (python-ng IS python); update CLAUDE.md + MEMORY.md. Follow RFC §6 swap checklist as ONE atomic commit.

**Open findings to resolve during the above (in handoff, see below):** format_manifest is now byte-exact hand-rolled (RFC §3 wording stale; possibly-dead kdl_io build_node/emit_document/NotValue/UrlValue to prune); verify-at-live-fresco: default tianguis index fallback when MILPA_INDEX_URL unset; verify-at-gate: Rust lockfile control-char escaping (\\u{NNNN} vs named) + certificate JSON shape match.

**Resume after Corey decides:** re-run `/loop …` (or `/tdd` a specific item). The grind itself is done.

- **Stage (orig):** 3 (tdd) — `/loop` grinding slices with `/tdd`
- **Resume:** `/loop implement the next unimplemented RFC slice … with /tdd` — next is **Stage 11 (saturation + swap)** + the deferred **--certificate flag** (write its cli-contract + conformance-fixtures spec sections FIRST, §8 follow-on). Stage 11 sequencing: 11a full harness/triage (already ~there — known-failing empty, 0 divergence), 11b coverage.py MUST-clause + the ~50 no-fixture-slug 3-bucket partition + new fixtures for black-box-testable ones, 11c the SWAP (atomic git mv python-ng→python; regenerate errors.md from new errors.py; Rust companion for the 2 pending codes; un-gate the harness descriptor; CLAUDE.md/memory update).
- **Progress:** Stages 0–10 COMPLETE. **🎉 ENTIRE CONFORMANCE CORPUS PASSES THE NEW IMPL VIA ITS REAL CLI: `MILPA_PYTHON_NG=1 python -m harness` → python-ng PASS=121 / FAIL=0 / known-failing=0, ZERO divergence vs Rust, OVERALL PASS.** Default harness unchanged. python-ng pytest: 1171 pass / 5 skip / 0 fail, mypy --strict clean, ruff clean. ALL uncommitted (Corey-gated).
- **format_manifest RFC-assumption CORRECTION (10d, surfaced to Corey):** RFC §3/3e said the manifest rewrite is "semantic round-trip only via the kdl-py printer". The mutation fixtures (120/121/123/124) assert BYTE-EXACT milpa.kdl, so format_manifest was rewritten as a **hand-rolled byte-exact serializer matching Rust `milpa-manifest::format_manifest`** (canonical: header comment, names double-quoted, 4-space indent, kind last, _kdl_str escaping). Still the SSOT serializer (manifest_writer calls it); strictly stronger than the round-trip property (which still passes). **Cleanup for S11:** kdl_io `build_node`/`emit_document`/`NotValue`/`UrlValue` may now be dead (format_manifest no longer uses them) — audit + prune if unused. **RFC §3 wording is now stale** (manifest rewrite IS byte-exact, like the lockfile) — note at swap.
- **cli.py built:** 8 verbs + --version + global flags (-C/-j/-s/--frozen); top-level MilpaError→`milpa-error: <slug>` R1–R4 discipline; MilpaEnv built once/process (MILPA_MOCKED_FETCHES→mocked_registry+CasAdmittingFetcher else build_registry); fetch (honors --frozen + 2 CLI guards FROZEN-NO-CAS/FROZEN-NO-LOCKFILE, writes lock+nim.cfg, prior for §8), lock (always full-resolve, prior reuse, no nim.cfg), show/verify/clean. `harness/descriptors.py` python_ng_known_failing trimmed to the 4 mutation stubs.
- **⚠ VERIFY AT LIVE-FRESCO (S11):** cli `_load_index_for_verb` made index loading OPT-IN on `MILPA_INDEX_URL` (unset → index=None → RES-NO-INDEX). Correct for air-gapped corpus + matches Rust on all fixtures, BUT real `milpa fetch` with named transitives (fresco's tree: results/stew/etc.) needs the DEFAULT tianguis index when MILPA_INDEX_URL unset. Confirm the default-index fallback works for real usage at the live-fresco e2e gate; if it's been removed, restore it (the corpus never exercises the live default).
- **Resolve-error batch fixes (done):** adapter `_build_env` was swallowing `parse_index` TNG-* errors (bare except → RES-NO-INDEX) — now propagates MilpaError (covered all 7 TNG fixtures); resolve() catches SolverError→SOLVE-CONFLICT (062); TNG-NO-SATISFYING-VERSION pre-check at registry layer (090); **nimble.py dedup changed from name-only to (name,git,ref)** — name-only was MASKING provenance conflicts; now RES-PROVENANCE-CONFLICT surfaces per §10.3 (099). All un-parked.
- **resolver.py `resolve()` is implemented** (~1360 lines): URL-dep fetch→CAS symlink, predicate filtering (_filter_manifest_by_profile before solver), named-dep Phase-A enum + Phase-B materialize, BFS transitive expansion w/ §4.2.1 ordering invariant (solver entry order == BFS package order P, declaration order, first-occurrence dedup), root-authority provenance precedence (§10), dev-deps (root-only, transitive excluded). The _Provider implements solver's PackageProvider.
- **Modules built:** context, workspace, resolver (SKELETON — resolve/resolve_workspace raise NotImplementedError), frozen (SKELETON — resolve_frozen/resolve_workspace_frozen raise NotImplementedError, take MilpaEnv only), + all of S0–S8. **resolver.py/frozen.py signatures:** `resolve(manifest, deps_dir, env, params)`, `resolve_frozen(manifest, lockfile, env, deps_dir)`. **Still to build:** fill resolver.resolve (9b-1..9c), resolve_workspace + frozen + real format_workspace_nimcfgs (9d), manifest_writer + cli (S10), saturation/swap (S11).
- **Conformance adapter:** `tests/test_conformance.py`; corpus at `Path(__file__).parents[3]/"conformance"`; xfail(strict=False) parks unimplemented fixtures; as 9b-* land, REMOVE the matching fixtures from the park list so they assert green (mirror Rust known_failing policy).

## Stage 10 sequencing (CLI — after the resolve-error batch)
- **10a-0** bootstrap CLI: minimal argparse running `milpa fetch -C <dir>`, load/discover manifest, emit `milpa-error: <SLUG>` on manifest parse error BEFORE any fetch (first lights the black-box manifest-parse harness fixtures).
- **10a** cli.py skeleton: argparse 8 verbs + `--version` (print `milpa <version>` stdout exit 0, cli-contract §9) + global flags (-C/--directory, -j, -s, --frozen); exit-code + R1–R4 slug discipline; `MilpaEnv` built once/process (`MILPA_MOCKED_FETCHES` wired here) + per-verb `ResolveParams` (§4.4).
- **10b** fetch/lock. fetch honors --frozen (fast-path + the 2 CLI-level FROZEN-NO-CAS/FROZEN-NO-LOCKFILE guards) + passes ResolveParams.prior. lock ALWAYS full-resolve (cli-contract §5.2: --frozen=false) but still passes loaded prior for §8 reuse; emits no nim.cfg. **Also at S10b: the result-certificate `--certificate <path>` flag (exit-0 no-slug) + check-certificate fixtures — but FIRST write the cli-contract §flag + conformance-fixtures §check-certificate spec sections (the §8 follow-on; see Verify-at-gate). Then confirm cert JSON matches Rust.**
- **10c** show/verify/clean.
- **10d** manifest_writer.py (mutate_manifest_file calls manifest.format_manifest for serialization, does ONLY file I/O — no duplicated KDL AST build; add_mirror; comment-drop warning). Atomic writes (sibling tmp + os.replace) for BOTH milpa.kdl and milpa.lock (cli-contract §5.6).
- **10e** add/remove/update with mocked transport. **Mocked ref-resolution:** MILPA_MOCKED_FETCHES set + --ref omitted → discover default branch from mocked transport (fixes frozen fixture-120 gap). Error paths (test each; harness fixture if black-box-observable else unit+issue): add --git dup→MAN-ADD-DEP-EXISTS; add --mirror→MAN-ADD-MIRROR-IDENTITY-MISMATCH/MAN-MIRROR-EDITABLE-PROVENANCE; remove absent→MAN-REMOVE-DEP-ABSENT; update <dep> not in lock→LOCK-DEP-NOT-FOUND; update <dep> no lockfile→LOCK-FILE-NOT-FOUND; update with NO <dep> passes prior=None (drops pins §4.4); non-mocked add --git ref-discovery failure→FETCH-REF-DISCOVERY-FAILED (§8, honors R3). These un-park the 5 CLI-verb skip fixtures.

## Stage 9 sequencing (resume here — the big stage; do NOT over-parallelize, lots of shared resolver.py)
- [x] **9a** context.py + workspace.py (incl. load_or_discover_manifest loader, WS-*, orphan warning) + nimble cleanup DONE + resolver/frozen skeletons.
- [x] **9a-pre** tests/test_conformance.py in-process adapter DONE (125 discovered, 95 green, 39 xfail, 5 skip).
- **9b-1** resolve URL-only serial, no prior/predicates. Gate: fixture-003.
- **9b-2** predicate filtering (_filter_manifest_by_profile before solver). Gate: fixture-115.
- **9b-3a** named-dep Phase-A enum + Phase-B lazy materialization (single). Gate: fixture-061.
- **9b-3b** BFS transitive expansion (two-hop named dep via .nimble).
- **9b-3c** canonical-solution selection (resolver-semantics §4.2.1) — relocated from S6. NORMATIVE ordering invariant (state in code): solver entry order == BFS package order P (root decl order; depth-d before depth-d+1; named dep takes position of first introducer). Gate: fixture-063 variant A; pin variant B.
- [x] **9b-4** provenance precedence (§10) DONE — fixture-065 green. (NOTE: RES-PROVENANCE-CONFLICT non-root-conflict fixture still parked — confirm it's covered.)
- [x] **9b-5** dev-deps (§9) DONE — fixture-064 green. (workspace-member dev-deps land with 9d resolve_workspace.)
- **9b-6** local-dep arm (no fetch, symlink-in-place).
- **9b-7** parallel fetch (ThreadPoolExecutor) + determinism property (same manifest+strategy → byte-identical lock regardless of -j).
- **9c** §8 prior-lockfile pin reuse in resolver.py (NOT frozen.py); tarball TOFU re-assertion (#116) full mechanism per RFC lines 590-602. Gate: fixtures 125 (record) + 126 (refetch-mismatch).
- **9d** resolve_workspace (union members, cross-member constraint accumulation §11) + frozen.py (resolve_frozen/resolve_workspace_frozen — 10 resolve-path FROZEN-* codes; the 2 CLI-level guards FROZEN-NO-CAS/FROZEN-NO-LOCKFILE go in cli.py at S10b) + real format_workspace_nimcfgs (was stubbed at 4d). Gates: fixtures 116/117 + workspace fixtures.
- **S7 integration note:** parallel wave-2 agents duplicated `*Provenance`/`*Receipt` in mocked.py + each fetcher module; unified to SSOT (canonical = fetcher modules, mocked.py imports them; tarball field reconciled to `expected_sha256`). Cross-dispatch regression test added (`tests/test_fetcher_dispatch.py`) proving real+mocked recognize the same canonical provenance. `_BUILTIN_FACTORIES` = {Git,Tarball,Local,Oci}Fetcher (no-arg ctors use production network seams; tests use mocked_registry). **Lesson: parallel agents over a shared package need an explicit "define shared types ONCE in module X; others import" rule up front, or an integration/unify pass after.**

## Verify-at-gate items (potential Rust non-conformances to confirm, not python-ng bugs)
- **Lockfile control-char escaping:** spec `lockfile-schema.md` §2.4 mandates U+0000–U+001F
  as `\u{NNNN}`; python-ng follows it. The FROZEN impl used named escapes (`\n`,`\t`). fixture-118
  exercises only `"`/`\`, NOT control chars, so the form is corpus-untested. At the byte-match-Rust
  gate (S9 differential / S11 live-fresco): confirm Rust also emits `\u{NNNN}`; if Rust uses named
  escapes it's a Rust non-conformance to FILE+fix (spec is the oracle, not an impl), not a python-ng change.

- **Result-certificate JSON shape:** 6b-3 built `certificate_to_json` (SSOT). The solver agent
  corrected a `.complement()` in the frozen impl's certificate display path (`.versions` IS the
  required range) — unit-validated via the §5.1 witness predicate. At S10b when the `check-certificate`
  fixtures + `--certificate` flag land (needs the cli-contract + conformance-fixtures spec sections
  written first, per §8), confirm the emitted JSON matches Rust's certificate shape; reconcile to spec
  §5 if they diverge.

## Carry-forward cleanup (address when consumer lands — NOT a fork)
- [x] **S9 loader nimble cleanup DONE (9a):** `.nimble` file-read moved to `workspace._load_nimble_file`
  raising `MilpaError(NIMBLE-FILE-NOT-FOUND/UNREADABLE)`; `NimbleParseError`+`load_nimble` deleted;
  `parse_nimble(text)` pure scanner stays in nimble.py.

## De-risk outcome (S0a, 2026-06-12)
kdl-py probe **PASSED** on pinned SHA `d9a220762fb9f55e4f59296256221084c26f54da`
(tabatkins/kdlpy main HEAD). Both probes parse correctly. **Critical constraint
recorded in RFC §4.3:** `parse_kdl` MUST use `kdl.ParseConfig(nativeTaggedValues=False)`
or the `(url)` tag is silently coerced to `urllib.parse.ParseResult` (the very leak the
façade exists to prevent). Hand-rolled-parser fallback NOT needed.

## RFC
- `docs/rfc-python-clean-room-rewrite.md` — drafted, sliced (Stages 0–11).

## Slices (high level — see RFC §5 for the full list)
- [x] Stage 0 scaffold — 0a + 0b DONE (2026-06-12)
- [x] Stage 1 errors+version — 1a (errors.py, 161 slugs incl. 2 pending), 1b+1c (version.py: Version/parse/format/Strategy + VersionSet algebra; lo=None merge gap FIXED + 4 counterexamples pinned) DONE
- [x] Stage 2 KDL façade + identity — 2a (kdl_io.py full §4.3 façade; depth guard over `{}` AND `/* */`; `nativeTaggedValues=False`; UrlValue not ParseResult) + 2b (identity.py; compute_content_hash byte-compat w/ Rust oracle; parse_identity 5 ordered checks) DONE
- [x] Stage 3 manifest — 3a (dataclasses+profile data), 3b (#121 constraint pre-typing), 3c-1..9 (all dep forms + mirrors/overrides/predicates-as-data/flags/top-level), 3d (workspace grammar), 3e (format_manifest round-trip + comment-drop warning), 3f (nimble.py total-scan, 4 requires forms) DONE. Stage-local manifest-parse gate green (~all MAN-* slugs covered).
- [x] Stage 4 lockfile+nimcfg — 4a (6-variant ProvenanceRecord + LockedDep/Lockfile; ResolvedDep/ResolvedGraph defined HERE to avoid resolver.py cycle, S9 imports+produces), 4b (parse_lockfile, strategy/maxver fallback, self_mirrors, LOCK-*), 4c (from_graph + hand-rolled byte-exact format_lockfile + _kdl_str SSOT; fixture-118 byte-exact passes), 4d (nimcfg §7.1-7.4 byte-exact vs 4 fixtures; §7.5 deferred #23; format_workspace_nimcfgs stubbed→S9d), 4e (verify) DONE.
- [x] Stage 5 CAS — 5a (cas.py: atomic admit/idempotent, relative symlink link, contains, default_store 4-tier [MILPA_CACHE_DIR→manifest cas{}→XDG→~/.cache], _scratch/<uuid> BaseException cleanup; CAS-IDENTITY-MISMATCH/CAS-NOT-IN-STORE) DONE
- [x] Stage 6 solver — 6a (Term/Incompatibility/PartialSolution/Assignment/PackageProvider, frozen PubGrub ported verbatim), 6b-1 (solve()+SolverError conflict chain, diamond-conflict RED→GREEN), 6b-2 (MAXVER/MINVER/SEMVER dispatch), 6b-3 (result certificate §5 SUCCESS {resolved,witness} + §5.2 refutation; certificate_to_json SSOT serializer) DONE. NOTE: canonical-solution selection (§4.2.1) deferred to S9b-3c per RFC.
- [x] Stage 7 fetchers — ALL DONE: 7a (types.py base/registry/discovery), 7e (FETCH-RECEIPT-EMPTY + FETCH-ALL-FAILED 3-part fallback), 7d-2 (safe_extract ZIP-SLIP/SYMLINK-ESCAPE/SIZE-LIMIT), 7b (CasAdmittingFetcher cas_admissible gating), 7c (mocked_registry + url_key SSOT), 7d-1 (GitFetcher subprocess, FETCH-GIT-FAILED/COMMIT-ABSENT), 7d-3 (TarballFetcher injected http_get, archive_sha256/TOFU, FETCH-SHA256-MISMATCH), 7d-4 (LocalFetcher cas_admissible=False), 7d-5 (OciFetcher TNG-* parse-path + digest verify) + SSOT unification + _BUILTIN_FACTORIES/registry integration.
- [x] Stage 8 registry+index cache — 8a (registry.py: parse_index/Index, 7 TNG-* validators [UNSAFE-NAME/BAD-COMMIT-SHA/UNSAFE-URL/UNSAFE-REF/BAD-OCI-DIGEST/UNSAFE-OCI-FIELD/SCHEMA-UNKNOWN] + 4 resolution errors; versions sorted desc at parse), 8b (index_cache.py: 4 states [fresh/stale/missing/offline-fallback] w/ injected HttpGet+now_unix clock + sidecar .at stamp; state-4→MILPA-INDEX-UNREACHABLE; state-3 warning has NO milpa-error: line per R3; file:// support; atomic os.replace writes) DONE.
- [x] Stage 9 resolver — ALL slices DONE (9a..9d): resolve() [URL/named/transitive/predicate/provenance/dev-deps/local-dep/parallel-fetch+determinism/§8-prior-pin/#116-tarball-TOFU], resolve_workspace (§11 union+cross-member), frozen.py (10 FROZEN-* resolve-path codes), format_workspace_nimcfgs (§7.6). 115/125 fixtures green. REMAINING (resolve-path ERROR fixtures, 10): see Stage-9-error list at top.
- [x] Stage 10 CLI — 10a-0/10a/10b/10c/10d/10e DONE. cli.py (8 verbs + --version + global flags + R1–R4 discipline), manifest_writer.py (atomic os.replace writes, format_manifest SSOT), add/remove/update (mocked ref-resolution §2.3.3, FETCH-REF-DISCOVERY-FAILED, update-no-dep→prior=None). **Full corpus green via CLI: 121/0/0, zero divergence.** REMAINING (not a verb): --certificate flag + its 2 spec sections.
- [ ] Stage 11 conformance saturation + swap (11a–11c)

## Key decisions (this session)
- **From scratch, NOT a port** of the frozen impl (Corey, 2026-06-11). Frozen =
  read-only lessons source. ([[multi_impl_strategy]] step 3 sharpened.)
- **KDL 2.0 via git-pinned `kdl-py` main** (Corey, 2026-06-11), swap to PyPI
  `kdl-py>=2.0` when published. (My rec was hand-roll; Corey chose git-pin.)
- **Lockfile emitter hand-rolled** for S5 byte-identity; `kdl-py` printer only for
  the semantic-round-trip manifest rewrite.
- Package name stays `milpa`; develop at `impls/python-ng/`, swap at parity.

## Round 1 (applied) — what changed
4-lens team (depth/breadth/design/feasibility). All §7 open questions resolved
(now §7 "settled"); ~30 clear-best fixes applied. Highlights:
- **Reslice** (~30→~45 slices): VersionSet moved to Stage 1 (was forward-dep on
  S6); S3c split into 3c-1..9; S9b split into 9b-1..7; S7d split into 7d-1..5;
  S5 merged; added **S10a-0 bootstrap CLI** + stage-local manifest-parse test so
  the Stage-3 gate isn't blocked on the full CLI.
- **#116 tarball-TOFU mechanism** spelled out + relocated to resolver.py (9c), NOT
  frozen.py (which now explicitly never fetches).
- **kdl_io façade interface specified** (§4.3) — `(url)`→plain str, no ParseResult
  leak; **pre-parse** depth guard (post-parse would RecursionError before slug).
- **MilpaContext** execution-context seam (§4.4) replaces per-verb fetcher/index
  kwarg threading (root-cause for the dropped-MILPA_MOCKED_FETCHES bug).
- **format_manifest** = explicit AST build (url annotations, spec-version
  round-trip, comment-drop warning), not AST round-trip.
- Added unscheduled spec features: §9 dev-deps exclusion, §10 provenance
  precedence, §4.2 canonical solution + §5 result certificate, self_mirrors 3rd
  candidate, --version, file:// index URL, orphan warning, strategy node,
  _kdl_str escaping (fixture-118), plugin entry-point discovery + FetcherConfig.
- Added: ruff/type policy, live-fresco e2e gate (byte-match Rust), swap pre-flight
  checklist, CLAUDE.md/memory update at swap, property tests per stage + continuous
  counterexample pinning.
- **REJECTED** (contradict the mirror-Rust principle / blessed decisions, verified
  against impls/rust): merge frozen→resolver, merge registry→index_cache, delete
  CasAdmittingFetcher. Rust keeps all separate + uses `CasAdmittingFetcher<R>`.

## Round 2 (applied) — what changed
4-lens team again (depth/breadth/design/feasibility). ~22 clear-best fixes applied.
Highlights:
- **MilpaContext split → `MilpaEnv` (DI seams: fetcher/index/store) + `ResolveParams`
  (strategy/max_parallel/profile/prior).** Mirrors Rust's actual cut; makes "frozen
  never fetches" enforceable by signature; settles `prior` threading + eager (not lazy)
  index load.
- **kdl_io façade hardened:** depth guard scans `/* */` comment nesting too (not just
  `{}`); `setrecursionlimit` dropped (thread-global hazard) for `except RecursionError`;
  added `node_arg_str/url`, `node_prop_*` helpers + `UrlValue` wrapper (kills 40+
  isinstance sites, distinguishes wrong-type from absent).
- **errors.py:** slugs as importable named constants (typo → load-time NameError).
- **profile.py:** subprocess I/O moved to cli.py; `from_environment(nim_version=…)`.
- **MockedFetcher → `mocked_registry()` factory** of per-kind fakes (no duplicated
  dispatch).
- **Slice splits:** 6b→6b-1/2/3 (canonical-selection relocated to resolver 9b-3c with an
  explicit ordering invariant); 9b-3→9b-3a/b/c; added **9a-pre** (the in-process
  conformance adapter is its own slice).
- **Gate fixes:** S2a/S4c restated as stage-local unit tests (fixtures unreachable at
  those stages); S0b descriptor gated behind `MILPA_PYTHON_NG=1` (stub would break CI);
  S0a adds kdl-py probe + `mypy --strict`; fixture-116/117 gated at 9d.
- **Coverage:** S11b partitions the ~50 no-fixture slugs into 3 buckets; §7.5/§7.6 nimcfg
  scope stated; mutation-verb error paths enumerated (10e); atomic manifest writes (10d);
  CI `python-ng` job from S3; swap checklist rewritten as one atomic commit with explicit
  `git mv` ordering.

## 3 round-2 escalations — RESOLVED by Corey (2026-06-11)
All three were spec catalog/wording gaps where the Rust reference is itself
non-conformant (RFC §8). Decisions:
1. **Result certificate** stays an **external MUST** (Corey: settle v1 right, doesn't
   need an immediate consumer). RFC reworked: certificate emitted via a
   `--certificate <path>` CLI flag (cli-contract.md addition, exit-0 no-slug) + a new
   `check-certificate` conformance fixture type; SSOT serializer in solver.py. Built at
   6b-3 / S10b. **Follow-on spec work:** write the cli-contract §flag + conformance
   fixture-type sections before S10b.
2. **`FETCH-REF-DISCOVERY-FAILED`** — new v1 catalog code, raised at S10e (+ Rust fix).
3. **`MILPA-INDEX-UNREACHABLE`** — new v1 catalog code, raised at S8b.
   - **Wiring constraint discovered:** `errors.md` is *generated* ("do not edit by
     hand") from the frozen impl's `error_catalog.py`, and the bijection test needs a
     raise site + trigger test per code. So 2 & 3 are NOT hand-added now (would break the
     frozen suite the dev plan keeps green); they enter `errors.md` via the **new impl's
     `errors.py`** (S1a), which becomes the generator at swap, Rust companion alongside.
     A premature hand-edit to errors.md + Rust was made and **reverted** for this reason.

## Prior escalation — RESOLVED (round 1, 2026-06-11)
**Spec §7.1 FROZEN closed-list scope.** Fixed in `spec/resolver-semantics.md §7.1`
(12 codes total: 10 resolve-path + 2 CLI-level guards). No behavior change.

## Next
RFC is ready for `/tdd`. Implement: `/loop` grind the slices with `/tdd`,
starting Stage 0 (0a kdl-py de-risk probe + mypy, 0b gated descriptor).
One non-blocking spec follow-on: write the cli-contract `--certificate` flag +
`check-certificate` conformance fixture-type sections before reaching S10b.

## Review ledger (stage 4) — not started
