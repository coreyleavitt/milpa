# resolver→tianguis swap (milpa#97) — handoff

- **Stage:** 3 /tdd grind — **ALL SLICES (S0–S7) DONE (587 passed + 5 gated integration green against live tianguis)**; next = **Stage 4 (`/code-review`)**
- **Resume:** `/loop implement the next unimplemented RFC slice from docs/rfc-resolver-tianguis-swap.md with /tdd, following the standing rules; report one progress line per slice; stop when every slice is implemented`
- **RFC:** `docs/rfc-resolver-tianguis-swap.md`   •   **Deferrals filed:** #98 (strategy), #99 (add-by-name), #100 (constraint accumulation), #101 (fetch observability), #102 (fetch_any mismatch warn)

## Slices (gate = full suite green each slice)
> Round-2 sharpened each slice — **RFC §Slices is authoritative**. New **S2.7** (typed
> provenance dispatch, pure refactor, Option A) sits between S2.5 and S3. Deltas: S1 prepends the
> additive `GitProvenance.commit_sha` field + load_index hardening; S2.5 adds a
> `make_repo_with_history` fixture + branches on `p.commit_sha`; S3 adds the lockfile `kind
> "oci"` PARSER arm + frozen `NotFrozen` arm; S4 drops `strategy=`, adds the pin guard +
> lazy-import cleanup + the 2 named-test migrations. S0 covers `_extract_from_milpa_kdl`'s two
> call sites.
- [x] S0 — dead-param cleanup (dropped unused `registry`/`list_tags` from `_build_terms`/`_process_url`/`_process_tarball`/`_process_local`/`_extract_from_milpa_kdl` + their submit closures; `_process_named` kept live; `resolve`/`resolve_workspace` `registry` made optional; stripped empty `registry={}`/`list_tags=lambda url: []` kwargs from 15 test files — apply_manifest_change_with_resolve calls retain `list_tags` (S4/S5 scope)). Pure refactor, **578 passed** (== baseline).
- [x] S1 — `tianguis_client` provenance-agnostic. `GitProvenance.commit_sha` added (additive); `_parse_version_node` dispatches git/oci (unknown kind skipped); `Version.provenances: tuple[Provenance,...]` pref-ordered + `canonical_provenance`; empty-prov guard `TNG-NO-PROVENANCE`; `schema_version` int check (kdl lib parses bare ints as float — handled) `TNG-SCHEMA-UNKNOWN`; `TianguisError(code=,message=)` + `_TNG_CODES` bijection; partition sort; dup-version dedupe+warn; `load_index` timeout=30 + atomic os.replace + `DEFAULT_INDEX_URL`. +11 tests, 589 passed.
- [x] S2 — registered `OciFetcher()` in default_registry; `_select` routes oci→OciFetcher, git→GitFetcher (disjoint isinstance, first-match). +2 tests, 591 passed.
- [x] S2.5 — `GitFetcher.fetch` honors `p.commit_sha` (clone → `_ensure_commit_present` cat-file/targeted-fetch/unshallow fallback → checkout exact commit); `None` keeps legacy ref-tip. `make_repo_with_history` helper added. +2 tests, 593 passed.
- [x] S3 — lockfile `OciProvenanceRecord` add-only: dataclass + union member; `_provenance_from_resolved` OciProvenance type arm; `_format_provenance_fields` + `_parse_provenance_block` `kind "oci"` (write→parse round-trip); `cmd_show` oci branch + legacy-registry `(legacy)` display; `frozen._source_from_provenance` oci branch + RegistryProvenanceRecord → actionable `NotFrozen` (no fabricated URL). RegistryProvenanceRecord kept (read-compat). +4 tests, 598 passed.
- [x] S4+S5 — **MERGED** (per the slice-boundary escalation below; Corey approved). resolver `resolve`/`resolve_workspace`/`_process_named` take `index:` (drop `registry`/`list_tags`); `parse_version` on the raw index version (coded `TNG-BAD-VERSION` on None); typed `provenance` recorded on the candidate, `source`=git url / `oci:<reg>/<repo>` display-only; `fetch_any(version.provenances, expected_identity=version.content_hash)`. **`_pin_for_named_dep` DELETED** (deliberate deviation from RFC §S4 — see note): exploration proved it vacuous (the predicate returns either `version.content_hash` or None, so `pinned or content_hash` ≡ `content_hash`). The index content_hash IS the named-dep identity gate and subsumes the lockfile pin; `_pin_for_url/tarball_dep` stay (transports the index doesn't vouch for). CLI: `IndexLoader` Protocol + `_default_index_loader` + `tianguis_client.default_index_cache_dir()` (global XDG, single source); cmd_fetch/lock/update/add/remove + workspace + `manifest_writer` build an `Index` and pass `index=`. Lockfile dead `registry:` source-string arm removed (named deps carry typed git/oci provenance). New `tests/indexkdl.make_index` (routes through real `parse_index`). New `tests/test_resolver_index.py` (+6: typed-git record, v-prefixed version, unparseable→coded error, R2 hash-parity pass + mismatch reject, TNG-NOT-FOUND). 9 test files migrated to synthetic `Index`. **604 passed.**
- [x] S6 — deleted `registry.py` + `test_registry.py`; fixtures already migrated to synthetic `Index` in S4+S5; `test_integration.py` updated (stale registry comments → tianguis index; dropped `RegistryProvenanceRecord` from the isinstance check — named deps write git records now); CLAUDE.md architecture table + identity/provenance model + testing-kwargs line updated; comparison doc registry row updated; grep-clean (only historical-prose `list_tags` mentions remain). **586 passed** (−18 from the deleted registry test module).
- [x] S7 — gated live integration: `test_named_dep_fetched_at_index_pinned_commit_sha` resolves a bare NamedDep (`results`) through the LIVE tianguis index and asserts (1) lockfile git record commit_sha == index pin (S2.5), (2) lockfile identity == index content_hash (R2), (3) `milpa verify` passes. **This caught a real bug**: the live index annotates URLs `(url)"…"` (the milpa KDL url convention), which the kdl lib parses as a urllib ParseResult — `_scalar_child` only accepted `str`, so every git-vendored entry read url="" → `git clone ''`. Fixed `_scalar_child` to recover ParseResult via `.geturl()`; pinned a unit regression (`test_git_url_with_url_type_annotation_parses`). All 5 gated integration tests green against live tianguis (incl. fresco's full transitive tree). Updated `test_integration.py` docstring/isinstance for the index path.

## Open forks (awaiting Corey)
- **`_pin_for_named_dep` deletion (deviation from RFC §S4, executed).** RFC §S4 said
  "rewrite `_pin_for_named_dep` to the identity predicate." Implementing it revealed the
  function is **vacuous** under the new design: its predicate returns `locked.identity` only
  when `locked.identity == version.content_hash`, so `expected_identity = pin or content_hash`
  reduces to `content_hash` in every case. The index content_hash is the immutable named-dep
  identity gate and fully subsumes the old lockfile pin (which floated to maxver anyway). Per
  [[feedback_no_workarounds]] + single-source-of-truth, kept dead code is a bug → deleted it
  and set `expected_identity = version.content_hash or None` directly, with a comment.
  `_pin_for_url_dep`/`_pin_for_tarball_dep` are untouched (those transports the index doesn't
  vouch for). Flag for Stage-4 /code-review confirmation. Note: RFC §Design-decision #3
  ("a lock is a lock") is now only literally true for URL/tarball/local; named deps re-resolve
  index-maxver each fetch (unchanged from the registry era) and `milpa update` is the advance path.
- ~~**S4/S5 SLICE-BOUNDARY ESCALATION**~~ RESOLVED — Corey approved merging S4+S5 into one
  green step; executed (see Slices above). Original note retained below for provenance.
- **S4/S5 SLICE-BOUNDARY ESCALATION (resolved).** The RFC assumes S4
  (resolver `_process_named` swap) lands green migrating only the 2 RegistryEntry named
  tests, with CLI index-wiring deferred to S5. Exploration shows that's unworkable: the
  moment `_process_named` routes through `index` instead of `registry`/`list_tags`, **every**
  named-dep test goes red until its caller supplies an index — and several route through the
  **CLI** (`cmd_fetch` → `resolve`), whose index-wiring is S5: `test_cli_commands.py:228`
  (named `bar` via `registry_loader`), `test_nimble_compat.py:126/158`,
  `test_workspace_resolver.py:275` (workspace named), plus `test_resolver.py:160` +
  `test_resolver_pins.py:253` (direct). So **S4 cannot be green without S5**.
  **Recommendation: merge S4+S5 into one green step** (resolver swap + `cmd_fetch`/`lock`/
  `update`/`add`/`remove` + workspace + `manifest_writer` index wiring + the
  `_default_index_loader`/`IndexLoader` Protocol), migrating all named-dep tests to a
  synthetic `Index` in the same step; S6 stays the `registry.py` deletion + grep-clean; S7
  stays gated integration. This is a re-slice, not a design change — Option A and every
  settled decision hold. Awaiting confirm before executing the merged step.
- ~~Fork 1~~ resolved → **Option A (full typed provenance dispatch)**. New pure-refactor
  slice **S2.7** carries `provenance: Provenance | None` on `_Candidate`/`ResolvedDep` and
  type-dispatches `_provenance_from_resolved` (string-prefix arms deleted); `source` demoted to
  display/member-marker, no longer parsed. RFC §Design-decisions #6 records it. S3/S4 add typed
  arms on top.
- Round 1's provenance-vocabulary fork remains SETTLED (reuse fetcher `Provenance`).

## Round-2 decisions (settled this round — see RFC)
- **`GitProvenance` gains `commit_sha: str | None = None`** (pre-S1, additive). The type had
  only `(url, ref)` — round 1's "ref carries the SHA" was unworkable (can't keep human ref +
  immutable pin both, and GitFetcher couldn't tell exact-commit from tip). GitFetcher branches
  on `p.commit_sha`.
- **Read-compat keeps `RegistryProvenanceRecord` as its OWN type** — round 1's remap to
  `GitProvenanceRecord(url="")` was a latent corruption (empty url → bogus `url ""` git record
  via frozen path). `frozen` raises actionable `NotFrozen`; `show` prints legacy arm; `verify`
  is provenance-blind.
- **Index cache → global XDG** (`~/.cache/milpa/index/`), not per-project; `milpa clean`
  doesn't touch it (a registry isn't project state).
- **S0 dead-param scope sharpened:** `_extract_from_milpa_kdl` has TWO call sites (≈499, ≈1073);
  `_process_named` stays LIVE through S0 (signature + submit site untouched until S4).
- **S4 absorbs:** drop `strategy=` arg, pin-predicate provenance-kind guard, remove the
  `RegistryProvenanceRecord` lazy import, migrate the 2 `RegistryEntry`-constructing named tests
  (was S6). Hard-depends on S3 (oci writer+parser) — don't reorder.
- **Hardening baked in:** `load_index` `timeout=30` + atomic `os.replace` write;
  `DEFAULT_INDEX_URL` + `TIANGUIS_INDEX_SCHEMA_VERSION` constants; `_TNG_CODES` bijection set
  (TNG-BAD-VERSION moved into tianguis_client); `IndexLoader` Protocol; `canonical_provenance`
  property; partition sort (no `(-1,)` sentinel); duplicate-version dedupe.
- **3 deferrals filed:** #100 constraint accumulation, #101 observability, #102 fetch_any warn.

## Round-1 decisions (settled — see RFC §Design decisions / §Migration)
- **Provenance vocab:** reuse fetcher `Provenance` (not new index-domain types). Import
  `tianguis_client → fetchers.types` is acyclic.
- **Re-lock = a lock is a lock:** `_pin_for_named_dep` returns locked identity iff
  `locked.identity == version.content_hash`; only `milpa update` advances pins. Immutable
  `commit_sha` pin removes the mutable-`ref` friction from the nkdl migration.
- **Migration:** keep `kind "registry"` as a READ-compat alias → `GitProvenanceRecord`;
  writer never emits it again; dataclass removal deferred (not in #97 critical path).
- **Crash fixes baked into slices:** version string via `parse_version` (not `int(split)`);
  empty-provenance guard; `source`=fetch-origin so lockfile dispatch needs no `registry:` arm.
- **Blast radius caught:** `manifest_writer.py`, `cmd_show`, `frozen.py`, +3 extra test files
  (`test_conditional_deps`/`test_manifest_mirrors`/`test_lockfile_v2`) all now in the slices.

## Key decisions (settled prior session — do NOT re-open)
- **Provenance-agnostic resolution, no privileged transport.** The issue's "OCI from provenances[0]"
  is stale — real index is 2613 git / 1 oci. Resolver dispatches on the index-recorded kind; git-heavy
  is an incidental distribution fact, NOT a design lean. Mixed index supported; OCI migrates in with zero
  resolver change. (User was explicit: zero emphasis on "git-primary".)
- **Index supplies identity+provenance+version-set, NOT graph edges.** `Version` has no `requires`;
  transitive edges still come from parsing each fetched dep's manifest (unchanged).
- **Verified compatible:** `compute_content_hash` returns `"sha256:<hex>"` == index `content_hash` format
  → `expected_identity = version.content_hash` direct. No `list_tags`. **(SUPERSEDED by round 2:**
  "`GitProvenance.ref` accepts a commit SHA" was wrong — `GitProvenance` had no SHA field at all;
  round 2 adds `commit_sha: str | None`. Fetch by `commit_sha`, keep `ref` for provenance.)
- **Scope reality:** 6 test files touch registry fixtures (not ~20 as the issue estimated).

## Risks (tracked in RFC)
- R1 arbitrary `commit_sha` checkout under shallow clone (validate S7; fix isolated to GitFetcher).
- R2 content_hash recompute parity vendor↔resolver (pin a canary test).
- R3 ignore index `ref` for checkout, record it for provenance only.

## Context
- Dev loop: `uv run pytest` (~6s); `MILPA_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py` (gated).
- Grounding map (registry/resolver/tianguis_client/fetchers/lockfile/cli + fixture sizing) gathered by an
  Explore agent this session; captured in the RFC's Surface section with file:line anchors.

---

## Stage 4 — /code-review (review ledger)

5-agent panel (correctness, quality, security, design, test-coverage) over the
#97 source scope. Findings adversarially verified against the cited code +
old registry.py before presenting. Status: `open` until fixed.

### Refuted (dropped from presentation)
- **CORR-1 "named-dep solver regression" — REFUTED.** Claim: #97 materializes
  only one version (vs all tags before) so the solver can't backtrack. False:
  old `registry.resolve_named` → `resolve_version` picked a SINGLE
  max-satisfying tag and old `_process_named` built ONE `_Candidate`. The
  eager single-version provider predates #97 (BFS-model property), not a swap
  regression. (Pre-existing limitation; out of #97 scope — backlog if
  multi-version backtracking is ever wanted.)

### High
- **H1** (sec-crit + corr + cov converge) `resolver.py:1347` `version.content_hash or None` →
  empty `content_hash` silently disables the identity gate (`types.py:205`). Violates Invariant 1.
  Fix: empty content_hash on a git/oci named dep = hard error, not silent pass. — **fixed** (test_security_hardening.py)
- **H2** (sec) `fetchers/git.py:58,69,76,102,113` git argv has no `--` end-of-options guard and no
  format validation → `commit_sha`/`ref`/`url` = `--upload-pack=…` is flag/arg injection → RCE if
  index or transport compromised. Fix: validate commit_sha=40-hex, reject leading `-`, add `--`. — **fixed** (test_security_hardening.py)
- **H3** (sec) `resolver.py:1351,1051,228` + `_name_from_url:1445` path traversal via dep `name`
  (`deps_dir / name` with `..`/abs escapes `_deps/`; also reaches `shutil.rmtree`). Fix: validate
  dep names at index-parse + url-derived. — **fixed** (test_security_hardening.py)

### Medium
- **M1** (sec) `fetchers/oci.py:52,84,109` OCI fields unvalidated → oras flag injection; digest format
  unchecked; receipt records input digest. (oras DOES verify the pinned `@digest`, so content integrity
  is covered — this is injection/validation hardening.) — **fixed** (test_security_hardening.py)
- **M2** (sec) `tianguis_client.py:280,323` index fetched w/o signature/hash check; stale-cache fallback
  enables poison-then-block. Rekor attest exists in publish flow but isn't enforced at parse.
  — **DEFERRED → milpa#103** (consumer-side index attestation = new trust subsystem w/ design forks;
  own RFC. User-approved defer.)
- **M3** (qual SSOT) `frozen.py:234` `_parse_version` duplicates `solver.parse_version`. Fix: import + delete. — **fixed**
- **M4** (qual+corr+design) `lockfile.py:224-246` typed `LocalProvenance` arm unreachable + Path/str
  mismatch; isinstance ladder → `Provenance.to_record()`. Fix: delete dead arm; consider to_record(). — **fixed** (dead arm deleted; isinstance dispatch kept in serialization layer per layering)
- **M5** (qual+corr) `resolver.py:60,104` `ResolvedDep.tag`/`_Candidate.tag` vestigial post-registry
  (always None; "registry deps only" comment stale). Fix: remove field or fix comment. — **fixed**
- **M6** (design) `cli.py:159` `IndexLoader` Protocol mislocated; `manifest_writer` types it as a comment.
  Move to `tianguis_client` as the canonical type. — **fixed** (IndexLoader → tianguis_client)
- **M7** (design) `resolver.py:287,571` `index=None` default → misleading `TNG-NOT-FOUND` when manifest
  has named deps but no index supplied. Fix: require non-None index when NamedDeps present. — **fixed**
- **M8** (cov) OCI named-dep path never driven through the resolver in-process (only gated integration);
  `from_graph` OCI→`OciProvenanceRecord` dispatch untested. Add in-process test w/ fake OciFetcher. — **fixed** (in-process OCI resolver test + from_graph OCI unit test)

### Low
- **L1** cov: empty-content_hash gate test (moot if H1 → hard-error; then test the error). — **fixed** (covered by test_security_hardening H1 TNG-NO-IDENTITY)
- **L2** cov/corr: `TNG-BAD-VERSION` (`resolver.py:1332`) unreachable (same `parse_version` twice); weak
  `in {…}` assertion in the existing test. Resolve dead-code question. — **fixed**
- **L3** qual: redundant re-imports `resolver.py:1173,1114,1017` (`_VS`, `ManUrlDep/ManNamedDep`, deferred
  `OciProvenance`). — **fixed**
- **L4** qual: `cli.py:816` `cmd_add_mirror` `relock` vestigial param. — **fixed**
- **L5** qual: `(url)`→ParseResult coercion duplicated in `tianguis_client._scalar_child` + `lockfile`. — **fixed** (shared kdl_util.url_value_to_str)
- **L6** design: `source` field doubles as display + lookup key (`update_pending`) + reconstruction fallback. — **fixed** (update_pending param source→git_url + URL-dep-only comment; investigated — not actually ambiguous)
- **L7** design: `_Candidate.provenance` default `None` + `getattr` soft-landing at `_build_graph:1503`. — **fixed** (getattr soft-landing removed; None-cases documented)
- **L8** design: `FetcherRegistry._select` open-world dispatch over a closed Provenance hierarchy. — **fixed** (ambiguous-dispatch guard)
- **L9** design: `tianguis_client.Version` name collides w/ `solver.Version` → rename `IndexVersion`. — **fixed** (Version→IndexVersion)
- **L10** corr/sec: no commit re-check after unshallow → misleading error (largely covered by H2's 40-hex). — **fixed** (test_security_hardening.py)
- **L11** cov: frozen-OCI path, `_ensure_commit_present` branches b/c, duplicate-version warn,
  missing-schema_version tolerated — coverage gaps. — **fixed** (frozen-OCI, dup-version warn, missing schema_version, _ensure_commit_present fallback)
- **L12** corr: silent drop of malformed package name (no warning) `tianguis_client.py:215`. — **fixed** (test_security_hardening.py)

### Re-review round 2 (post-fix) — new findings
Fresh Security + Design + Correctness over the fix-loop delta (`git diff HEAD`). Correctness: clean.
Security: all controls HOLD; no Critical/High. New items below (all Low/Med):
- **RS1** (sec, Low) `tianguis_client.py:71,99` validators use `re.match` not `re.fullmatch` → a trailing `\n`
  passes (`$` matches before final newline). Not injectable (single argv C-string) but malformed data slips
  the gate then fails at git/oras. Fix: `re.fullmatch` (or `\Z`). + regression test. — **fixed**
- **RD1** (design/SSOT, Med) `manifest.py` still has ~4 inline `(url)`→ParseResult duplicates (≈691,707-708,977,1167)
  not unified with `kdl_util.url_value_to_str`; L5 extraction half-done. Unify where semantics match (note:
  `_url_arg` is strict/raises vs helper returns ""). — **fixed**
- **RD2** (design, Med) `resolver._name_from_url` reaches into private `tianguis_client._RE_UNSAFE_NAME` + raises
  `ValueError` while index path raises `TianguisError(TNG-UNSAFE-NAME)`. Promote a PUBLIC safe-name predicate
  (single source), keep context-appropriate exception types. — **fixed**
- **RD3** (test, Low) lockfile `_provenance_from_resolved` new `else: raise ValueError` arm has no pinned test
  ([[feedback_no_invariant_dismissal]]). — **fixed**
- **RD4** (cleanup, Low) `lockfile.py:348` redundant isinstance guard before `url_value_to_str` + misleading
  "filter those out" comment. — **fixed**
