# Clean-room Python rewrite — handoff

- **Stage:** 3 (tdd) — **RESUMED 2026-06-14: Stage 11b grind (fork resolved).** Corey's call on the
  nimble-role fork = **finish #6, defer b/c** (b→issue #132 registry-requires-graph, largely subsumed by
  DepDecl; c→issue #133 `milpa adopt`). Transitive `.nimble` parsing stays (irreducible: URL/git deps bypass
  the registry). The swap (11c) still needs Corey's explicit go.

## ✅ 11b COMPLETE (2026-06-14) — awaiting Corey's explicit go for 11c (the swap)
All 11b items done, all gates green, zero divergence (see consolidated gate). Summary:
- **MAN-NIMBLE-CONSTRAINT fixed** (fixture-152): was a SILENT-DROP (not MILPA-INTERNAL) — python-ng
  dropped the dep + resolved without it; now `NimbleEdgeSource` raises (matches Rust's NimbleFallback-only).
- **10 of 12 black-box error fixtures authored** (153 MAN-NO-MANIFEST, 154 MAN-NIMBLE-AMBIGUOUS,
  155 TNG-KDL-SYNTAX, 156 FROZEN-NO-LOCKFILE, 157 LOCK-FILE-NOT-FOUND via show, 159 LOCK-GRAPH-MISMATCH,
  160 LOCK-DEP-NOT-FOUND, 161 MAN-ADD-DEP-EXISTS, 162 MAN-REMOVE-DEP-ABSENT, 163 FETCH-REF-DISCOVERY-FAILED
  [Rust known_failing until 11c]). **2 found structurally UNREACHABLE → §4 exemptions**: VERIFY-DEPS-DIR-MISSING
  (mkdir-always), MAN-MUTATE-WORKSPACE-REFUSED (shadowed by package-parse precheck). (158 unused.)
- **spec/conformance-fixtures.md §4 reconciled**: un-exempted LOCK-FILE-NOT-FOUND + LOCK-GRAPH-MISMATCH;
  added 2 new exemptions + 5 structured exemption categories (router-shadowed/fetch-wrapping/ID-wrapping/
  swallow/dead-catalog/permission-race). Verified: every catalog code is fixture-covered OR §4-exempt.
- **coverage.py false gaps fixed** 5→2 (remaining documented: cli.verify-no-lock, resolver.dev-deps-root-only).
- **5c index fallback fixed** (the design call): three-way `MILPA_INDEX_URL` semantics — absent→DEFAULT_INDEX_URL,
  present-empty→no-index, present-nonempty→that-url — in BOTH CLIs; harness always sets it (empty when air-gapped);
  spec cli-contract §8.1 + conformance-fixtures §2.2 sharpened. Harness pass counts UNCHANGED (proves no fixture
  outcome changed); real `milpa fetch` now defaults to the registry.
- **kdl_io dead-code pruned** (NotValue/build_node/emit_document/_milpa_val_to_kdl) + RFC §3 byte-exact wording fixed.

**Candidate follow-ups (non-blocking):** workspace `milpa add` UX (gets MAN-WORKSPACE-HAS-DEPS-OR-KIND, not a
clear refused-message); coverage gaps cli.verify-no-lock + resolver.dev-deps-root-only.

## ⏭ 11c — THE SWAP (Corey-gated, irreversible — needs explicit go). One atomic commit (RFC §6 checklist):
1. `git mv impls/python-ng → impls/python` (frozen impl moves out / is replaced).
2. Regenerate `spec/errors.md` FROM the new `errors.py` (now the generator) — gains FETCH-REF-DISCOVERY-FAILED +
   MILPA-INDEX-UNREACHABLE + the DepDecl codes.
3. Rust companion: implement the 2 pending raise sites (FETCH-REF-DISCOVERY-FAILED slug + MILPA-INDEX-UNREACHABLE)
   so fixture-163 leaves Rust known_failing.
4. Drop the `MILPA_PYTHON_NG=1` harness gate (python-ng IS python); update `harness/descriptors.py`.
5. Update CLAUDE.md + MEMORY.md (architecture table, dev workflow).
NOTE: this session's DepDecl + 11b work all lives in python-ng, so the swap carries it (all conformant + green).

## 11b worklist (RE-GROUNDED 2026-06-14 against post-DepDecl state)
DepDecl already did: the `verify` harness cmd token (DONE) + §4 new-codes block. Remaining:
1. **Fix MAN-NIMBLE-CONSTRAINT (correctness divergence, FIRST).** Re-verified: python-ng does NOT leak
   MILPA-INTERNAL — it **silently drops the dep** (`nimble.py:253` `except ValueError: return None`) and
   resolves successfully WITHOUT it; Rust raises MAN-NIMBLE-CONSTRAINT (only on `EdgeSource::NimbleFallback`;
   MilpaKdl/DepDecl widen to full(), which python-ng `edge_sources.py:551` path-B already matches). Fix =
   move constraint validation out of `nimble._build_dep`'s silent drop into `NimbleEdgeSource` so it RAISES.
   Doubles as the MAN-NIMBLE-CONSTRAINT black-box fixture.
2. **Author the 12 black-box error-path fixtures** (ALL still missing, ALL reachable in current python-ng CLI;
   raise-sites confirmed): MAN-NO-MANIFEST, MAN-NIMBLE-AMBIGUOUS, TNG-KDL-SYNTAX, FROZEN-NO-LOCKFILE,
   LOCK-FILE-NOT-FOUND, LOCK-DEP-NOT-FOUND, MAN-ADD-DEP-EXISTS, MAN-REMOVE-DEP-ABSENT,
   MAN-MUTATE-WORKSPACE-REFUSED, FETCH-REF-DISCOVERY-FAILED, VERIFY-DEPS-DIR-MISSING, LOCK-GRAPH-MISMATCH.
   Each must PASS python-ng AND Rust; FETCH-REF-DISCOVERY-FAILED → Rust `known_failing` until 11c.
3. **Reconcile `spec/conformance-fixtures.md §4`**: un-exempt LOCK-FILE-NOT-FOUND + LOCK-GRAPH-MISMATCH (now
   black-box reachable); add type/flow-unreachable exemption categories (fetch-wrapping, ID-wrapping,
   MILPA-INDEX-UNREACHABLE swallow, dead-catalog, permission/race-only).
4. **coverage.py false gaps**: list fixtures 120/121/123/124 under cli.add-git/remove/update; optional
   `kdl_io` build_node/emit_document/NotValue dead-code prune.
5. **Index fallback (5c) — RESOLVED under the bar (Corey may override):** production unset `MILPA_INDEX_URL`
   → `DEFAULT_INDEX_URL` (restore frozen-impl behavior; `cli.py:_load_index_for_verb` early-return guard is
   the regression); keep corpus hermetic via an explicit harness air-gapped signal (don't overload
   "absence = no index"); small `spec/conformance-fixtures.md §2.2` sharpening. Confirm at live-fresco gate.
6. Then **11c THE SWAP** (Corey-gated): `git mv impls/python-ng → impls/python`, regenerate errors.md from new
   errors.py (gains FETCH-REF-DISCOVERY-FAILED + MILPA-INDEX-UNREACHABLE + the DepDecl codes), Rust companion,
   drop `MILPA_PYTHON_NG=1` gate, CLAUDE.md/MEMORY update.

## ⏸ (historical) LOOP PAUSED — awaiting Corey (the implementation is COMPLETE + fully conformant)

## ⏸ LOOP PAUSED — awaiting Corey (the implementation is COMPLETE + fully conformant)
**Done:** Stages 0–10 — the entire clean-room rewrite. `MILPA_PYTHON_NG=1 python -m harness` → python-ng 121/121, FAIL=0, known-failing=0, **ZERO divergence vs Rust**. pytest 1171/5/0, mypy --strict + ruff clean. **COMMITTED to main as `f4f54e2`** (2026-06-12, not pushed) — impls/python-ng/ + gated harness descriptor + RFC docs + §7.1 spec scope. Frozen impl untouched.

**Remaining work is all Corey-gated — the loop correctly stopped rather than do it autonomously:**
1. **COMMIT (recommended first):** the whole rewrite is uncommitted. Natural checkpoint before the swap. Suggest committing `impls/python-ng/` + the gated `harness/descriptors.py` change as a `feat(python-ng):` commit (frozen impl untouched, so nothing breaks).
2. **`--certificate` flag — ✅ DONE** (spec `6c683d9`; impl `9057d06`). End-to-end both impls: python-ng + Rust `--certificate` flag (fetch/lock; success cert exit-0/no-slug, failure refutation cert exit-1+SOLVE-CONFLICT; atomic; orthogonal R1–R4); serializers reconciled to spec order; corpus fixtures 127 (success)/128 (conflict); harness + in-process adapter check-certificate canonical comparison. `MILPA_PYTHON_NG=1 harness`: python-ng 123/0, rust 123/0, **Cross-impl divergences NONE**. Rust --workspace 281 green. Frozen python parks 127/128 (rides the swap).
3. **11b saturation — ANALYSIS DONE 2026-06-12, fixture-authoring PAUSED on a design fork (see below).**
   **Partition (54 no-fixture slugs), grounded in raise-site + wrapping investigation:**
   - **BLACK-BOX (reachable terminally via the black-box CLI harness → need fixtures): 12** —
     MAN-NO-MANIFEST (empty dir), MAN-NIMBLE-AMBIGUOUS (2×.nimble), TNG-KDL-SYNTAX (bad index.kdl),
     FROZEN-NO-LOCKFILE (cmd=frozen, no lock), LOCK-FILE-NOT-FOUND (cmd=parse-lockfile, no lock),
     LOCK-DEP-NOT-FOUND (cmd=update <absent>), MAN-ADD-DEP-EXISTS (cmd=add dup),
     MAN-REMOVE-DEP-ABSENT (cmd=remove absent), MAN-MUTATE-WORKSPACE-REFUSED (cmd=add in workspace),
     FETCH-REF-DISCOVERY-FAILED (cmd=add, mocked, no matching url, no ref);
     **+ needs a small harness `verify` cmd token:** VERIFY-DEPS-DIR-MISSING, LOCK-GRAPH-MISMATCH.
   - **TYPE/FLOW-UNREACHABLE: 41** — fetch family ALL wrapped by FETCH-ALL-FAILED at `fetchers/types.py:383`
     (`except (MilpaError,FetchError,Exception)`); EXTRACT-* wrapped by FETCH-EXTRACT-FAILED; ID-* wrapped
     by LOCK-DEP-IDENTITY-INVALID at the lockfile layer; permission/race-only (MAN-FILE-*, LOCK-FILE-UNREADABLE,
     NIMBLE-FILE-*, WS-NO-MANIFEST/NOT-A-WORKSPACE, MAN-MUTATE-FILE-NOT-FOUND); MILPA-INDEX-UNREACHABLE
     **swallowed** at `cli.py:268` (→ index=None → RES-NO-INDEX); dead/reserved catalog entries with NO raise
     site in python-ng (FROZEN-NO-CAS [default_store always valid], MAN-WORKSPACE-IN-PACKAGE [parse routes away],
     TNG-BAD-VERSION [reserved future strict-parse], MAN-NIMBLE-PARSE [total scanner — matches Rust], MILPA-INTERNAL/
     INTERNAL-PANIC [catch-all/Rust-only]).
   - **NETWORK-ONLY: 0** (everything transport-bound is ALSO wrapped → folds into unreachable).
   - **Partition's normative home = `spec/conformance-fixtures.md §4`** ("structurally unreachable" exemption ledger).
     It was written against the OLD in-process runner; 11b must RECONCILE it to the new black-box CLI harness:
     un-exempt the now-reachable codes (LOCK-FILE-NOT-FOUND, LOCK-GRAPH-MISMATCH) + add the new exemption
     reasons (fetch-wrapping, ID-wrapping, swallow, dead-catalog). This §4 update IS the deliverable, not a new doc.
   - **SATURATION FINDING (cross-impl gap): MAN-NIMBLE-CONSTRAINT.** Rust raises it (`resolver.rs:1419`, passing
     test) when a transitive named-dep `.nimble` has a malformed version constraint; python-ng's nimble path is
     total → the constraint `ValueError` leaks as MILPA-INTERNAL. Black-box reachable (named dep + mocked .nimble
     with bad constraint) → fixture would PASS Rust, FAIL python-ng. Real python-ng bug to fix.
   - **Cross-impl:** every new fixture MUST pass BOTH impls (run `./dev-rust` / the rust harness descriptor);
     a Rust divergence on any new fixture is a separate escalation, not papered over.
   - **Investigation evidence:** raise-site/wrapping table in the agent transcript (a69fbc9f145fe608e); spec §4
     read at handoff time.
4. **11c THE SWAP (irreversible — needs explicit go):** atomic `git mv impls/python-ng → impls/python` (frozen impl out); regenerate `spec/errors.md` FROM the new `errors.py` (gains the 2 pending codes FETCH-REF-DISCOVERY-FAILED + MILPA-INDEX-UNREACHABLE); land the Rust companion (catalog entry + DEFERRED→implemented + raise sites for those 2 codes); remove the `MILPA_PYTHON_NG=1` harness gate (python-ng IS python); update CLAUDE.md + MEMORY.md. Follow RFC §6 swap checklist as ONE atomic commit.

**Open findings to resolve during the above (in handoff, see below):** format_manifest is now byte-exact hand-rolled (RFC §3 wording stale; possibly-dead kdl_io build_node/emit_document/NotValue/UrlValue to prune); verify-at-live-fresco: default tianguis index fallback when MILPA_INDEX_URL unset; verify-at-gate: Rust lockfile control-char escaping (\\u{NNNN} vs named) + certificate JSON shape match.

**⏸ OPEN FORK (2026-06-12, awaiting Corey) — nimble's role:** Corey questioned whether `.nimble` should be
supported only via a "translate to milpa" command. Clarified the TWO paths: (1) **root auto-promotion** (silent
fallback when no milpa.kdl — genuinely optional, could become an explicit `milpa adopt`/translate command);
(2) **transitive .nimble parsing** (load-bearing — URL/git-pinned deps like fresco→intonaco→chronos bypass the
tianguis registry and MUST be read live; this is milpa's founding charter, chained URL requires). Corey floated
"pause and make tianguis encode full requires graphs" to resolve it. **My analysis: it does NOT resolve the mess** —
URL deps are outside the registry so they still need live transitive parsing, and the .nimble parser merely relocates
to tianguis ingest-time (same MAN-NIMBLE-* error surface). It's a good additive **Tier 3 RFC** (registry-encoded
requires graph) for the NAMED-dep subset, not a replacement for the parser. **My recommendation to Corey (awaiting
his pick, independent options):** (a) resume 11b + fix the MAN-NIMBLE-CONSTRAINT python-ng gap (transitive parsing
stays regardless); (b) file the Tier 3 registry-requires RFC first; (c) separately pull on root-auto-promotion →
`milpa adopt`. Transitive parsing stays no matter what.

**Resume after Corey decides:** if (a) → resume 11b: reconcile `spec/conformance-fixtures.md §4`, add `verify` cmd
token to the harness, author the 12 black-box fixtures (each verified PASS on BOTH python-ng + Rust), fix
MAN-NIMBLE-CONSTRAINT in python-ng, update §4 + handoff. Then 11c (the swap). The grind itself is done.

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
