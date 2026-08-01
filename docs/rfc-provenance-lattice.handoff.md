# Provenance authority — validate-against-registry (#193) — handoff

- **Stage:** COMPLETE — shipped in BOTH impls, byte-identical. Closes #193.
- **Final suites GREEN:** Python 3465/0-fail/33-skip; Rust workspace exit 0
  (milpa-core 921, milpa-cli 162, milpa-conformance 224, bijection + conformance
  corpus ok). Nothing committed — awaiting Corey.

## The design (final, Corey-approved as the best-in-class answer)

The frame is **authority**, not source-type. milpa's identity is content-hash;
provenance (url vs registry) is orthogonal metadata — so ranking source-*types*
into fixed tiers is arbitrary. The real question is *who is authorized to decide
a non-root name's source, and what happens when they disagree.*

```
Tier 1  Root      — explicit per-build human choice (deps / overrides)
Tier 2  Registry  — trusted DEFAULT (tianguis index), not an explicit choice
Tier 3  Self-declared url/tarball
```

**Core principle: milpa MUST NOT silently resolve a genuine source disagreement
over a non-root name.** It either accepts an *agreeing* claim or escalates to the
root.

- **Root (tier 1)** — declared the source; a disagreeing transitive is silently
  suppressed. Correct: it honors an explicit human choice, not a guess.
- **Registry (tier 2) — VALIDATE, don't win.** For a non-root name in the index,
  a transitive self-declared `git=`/`tarball=` source is validated against the
  registry's recorded source:
  - **agrees** (same repo — a different `ref` is still agreement, it just picks a
    version) → accepted, resolves normally (content-hash dedup unifies it with any
    registry-version candidate);
  - **disagrees** (different repo, or incomparable transport e.g. `git=` vs an
    OCI-only entry) → `RES-PROVENANCE-CONFLICT`; remedy = root-declare the name.
    Never silently redirect to the registry (would override a legit fork), never
    silently honor the transitive (would let a transitive substitute a registry
    name's source).
- **Not in registry (tier 3)** — one claim stands; two disagreeing → conflict.
- Orthogonal to the **attestation policy** (which governs *how much* to trust a
  registry resolution — strict / RES-UNATTESTED-METADATA). Do not fold it in.

**Why this beats the alternatives** (both explored + built, then rejected):
- *disagreement-only* (registry wins only if a competing named claim also exists):
  silently honors a lone transitive substitution, and had an unclosable mid-solve
  residual (a named-of-named claim revealed only during solve).
- *membership-based* (registry silently wins for any registry-known name):
  silently overrides a library's legitimate fork.
  Both make a **silent** choice on a genuine ambiguity. Validate-against-registry
  is the only one that never does — agree→accept, disagree→root-arbitrates. It
  also closes the residual **by construction**: validation is a static gate-time
  check vs the loaded index record, so a disagreeing tier-3 claim is conflicted at
  its own discovery and never becomes a candidate for a late claim to collide with.

## Mechanism (both impls, byte-identical)
- `validate_transitive_url_against_registry(name, url, pkg)` — gathers the git
  source urls recorded across ALL of the package's index versions; none (OCI-only /
  no provenance) → conflict (incomparable); else `normalize_git_source_url` (strip
  trailing `/` and `.git`, lowercase scheme+host, preserve path case) both sides and
  membership-check; match → accept, else → `RES-PROVENANCE-CONFLICT` (message names
  both sources + the root-declare remedy). Never compares `ref`/`commit_sha`.
- Wired at the url gate/dispatch point for a transitive (non-root) name that
  `lookup_bare`s to a definite `Package`; **agree bypasses the single-claim gate**
  so two agreeing pins at different refs coexist as distinct candidates. Ambiguous
  index result → named enumeration (TNG-AMBIGUOUS-NAME, orthogonal). Root names
  never validated (tier 1 silently wins). Transitive tarball/local never reach the
  BFS (M2 security gate) → not applicable.
- Python: `impls/python/milpa/resolver.py` (`_validate_transitive_url_against_registry`,
  `_normalize_git_source_url`, `_registry_git_provenances`; call site in the
  `kind == "url"` branch of `_run_bfs_wave_loop`). A latent concurrency bug surfaced
  (two same-name eager fetches racing on `deps_dir/<name>`, previously impossible
  because the gate serialized them) was root-cause-fixed: `_process_url_worker` takes
  an explicit `dest`, disambiguated per-wave only for a 2nd+ same-name claim.
- Rust: `impls/rust/crates/milpa-core/src/resolver.rs` (mirror; `gate_only` validates
  before the tier gate). Synchronous BFS → no dest race. The prior interim mechanisms
  (disagreement-only pre-solve `reconcile_tier2_over_tier3` sweep) are REMOVED in both.

## Fixtures + tests
- `conformance/spec-v1/fixture-448-url-agrees-with-registry-accepted` (agree → resolves)
  and `fixture-449-url-disagrees-with-registry-conflict` (disagree → RES-PROVENANCE-CONFLICT),
  blessed from the Python oracle, Rust byte-matches. Corpus: 0 regressions.
- Python `tests/test_provenance_lattice.py` (31 tests) + Rust `resolver_tests.rs`
  lattice tests: agree/disagree (both discovery orderings), mid-solve residual closed,
  lone-agrees / lone-disagrees, two-agreeing-pins-coexist, root-beats-both,
  url-vs-url-no-registry conflict, + normalize/validate unit tests. A4's transitive
  case updated (disagreeing transitive → conflict).

## Not done
- Nothing committed (spec §10, both impls, fixtures 448/449, tests, the concurrency
  fix, this handoff). Awaiting Corey.
