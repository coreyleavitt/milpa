# resolver→tianguis swap (milpa#97) — handoff

- **Stage:** 3 /tdd grind — **S0–S3 DONE (green, 598 passed)**; next = **S4** (resolver `_process_named` swap — HARD-depends on S3)
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
- [ ] S4 — resolver `_process_named` swap (inject `index:` incl. `apply_manifest_change_with_resolve`; `parse_version` on raw index version; `source`=git url / `oci:` prefix; `_pin_for_named_dep` → `locked.identity == version.content_hash`; hash-parity unit fixture)
- [ ] S5 — CLI `_default_index_loader`; cmd_fetch/lock/update/add/remove + workspace + `manifest_writer` pass `index=`
- [ ] S6 — delete `registry.py` + `test_registry.py`; migrate fixtures (synthetic Index via `parse_index(inline_kdl)`) across 7 files incl. `test_integration.py` import; update CLAUDE.md + comparison doc; grep-clean
- [ ] S7 — gated live integration: transitive tree, git fetch at `commit_sha`, content_hash verify (validates S2.5)

## Open forks (awaiting Corey)
- **NONE.** Fork 1 resolved → **Option A (full typed provenance dispatch)**. New pure-refactor
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
