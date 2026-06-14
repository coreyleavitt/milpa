# rfc-conditional-requires (#26) — handoff

- **Stage:** 2 (architect) — **round 1 applied**; BLOCKED on R1 fork → Corey   •   **Round:** 1 done
- **Resume (after R1 decided):** apply R1 resolution to §3.4/§5/§6/§9, then `/architect docs/rfc-conditional-requires.md round 2`

## ⚠ BLOCKING FORK — R1 (§8 of the RFC)
Host-filtering transitive edges makes `milpa.lock` platform-specific → breaks the
reproducible-build lockfile + `--frozen` cross-host + collides with **#110** (universal
resolution). Options: (a) host-specific lockfiles now; (b) universal lockfile +
build-time activation (uv model, = #110 scope); (c) reduce #26 to recognize+attach+
annotate, defer activation to #110. **Recommend (c).** Awaiting Corey.

## Round 1 — applied fixes (fork-independent)
- §3.1 table: +`win`, +three-tuple/operator/two-sided `nim` forms; **dropped `posix`**
  (under-include risk); renamed fn `parse_when_condition`, `None`=UNRECOGNIZED + never-empty postcondition.
- §3.2: real state machine (not regex), single-line-colon form, multiple-requires/branch,
  chain-poisoning, `parse_when_branches` standalone.
- §3.3: predicates on `RequireEntry` via `_nimble_edges` bridge (NOT shared NamedDep/UrlDep); eliminate double-parse.
- §3.4: `predicates.py` SSOT, filter in `edgeset_to_terms(profile=)`, `Profile=None` guard, `active_flags=frozenset()`.
- §6: do NOT mutate fixture-138 (retained-unchanged rule) — new fixtures 139+; added URL/dev-deps/workspace/overrides/multi-require scenarios; coverage clauses atomic.
- §9: split S3→S3a (state machine, updates TestWhenBlockPolicy IN-slice) + S3b (wiring); S4+ gated on R1; no spec-version bump.
- Resolved forks: F1/F6 (table closed), F4 (unrecognized), F5 (one matcher). Open: F2, F3(#134), F7(diagnostic).

## Core design (one-line)
Route `.nimble` `when` blocks into milpa's EXISTING `Predicate`/`Profile` matcher —
translate a closed recognizable subset to predicates, attach to fallback edges, filter
transitive edges with the same matcher. Unrecognized → today's over-include + warn.

## Slices
- [ ] S1 — `nimscript_when_to_predicates(cond)` pure fn (both impls) — the §3.1 table
- [ ] S2 — `RequireEntry.predicates` data-model field (both impls)
- [ ] S3 — scanner `when/elif/else` branch tracking + attach predicates
- [ ] S4 — resolver transitive-edge predicate filter (single matcher, F5)
- [ ] S5 — spec: dep-decl §7.5 + §1, manifest-grammar §5.3, resolver-semantics
- [ ] S6 — conformance fixtures + coverage clauses
- S7 DEFERRED → filed as **#134** (DepDecl artifact schema v1 predicates, cross-repo)

## Open forks (awaiting architect review / Corey) — §8 of the RFC
- F1 recognizable subset boundary (rec: ship the table as-is)
- F2 flat chains only; nested when → UNRECOGNIZED (rec: yes)
- F3 attested-artifact predicates → deferred (#134 filed)
- F4 defined(release/js/custom) → UNRECOGNIZED for now (flag-map is future, needs #23)
- F5 one matcher helper, two call sites (rec: factor in S4)
- F6 posix → which OSes (confirm vs manifest-grammar §6 vocab)

## Key decisions (this session)
- Reuse the predicate model, NOT a new features system (#23 is a different axis). → SSOT.
- Fallback path only; attested stays publisher-curated. → minimal-over-completeness.
- Strictly additive: unrecognized conditions = today's behavior exactly. → no breakage.

## Four-runner discipline (from pre-Nim handoff — carry forward)
Every slice gates on: `cd impls/python && uv run pytest` AND `./dev-rust test --workspace`
AND `python3 -m harness` (rebuild rust RELEASE first: `./dev-rust build --release -p milpa-cli`).
Four runners: python CLI, rust CLI, python in-process, rust in-process.
