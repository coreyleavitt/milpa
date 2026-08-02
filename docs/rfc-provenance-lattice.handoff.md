# Provenance authority — validate-against-registry (#193) — handoff

## SHIPPED to milpa main (both impls, byte-identical, green)
- `1feffe4` resolution-semantics RFC · `1ff17bd` #193 provenance lattice · `f889621` OCI content-hash fallback · `31454de` root-satisfies-own-name (spec §14) + OCI source-URL provenance validation (registry-protocol §3.3, resolver-semantics §10 3-step, cli-contract §10.2).
- Final: Python 3498/0-fail; Rust workspace exit 0 (milpa-core 945, milpa-cli 162, milpa-conformance 224, bijection + corpus ok).

## ALL CODE SHIPPED (milpa + tianguis)
- milpa main: `31454de` (root-satisfies-own-name §14 + OCI source-URL data/resolver/publish), `79be709` (§3.5.3 OCI digest source inclusion). Python 3500/0-fail; Rust workspace exit 0 (946 milpa-core, bijection+corpus ok).
- tianguis main: `2770d3d` (OCI source write-path: model/kdl_io/addentry/cli + dispatch/handler.go + publish action + commit-entry workflow). Full Nim suite green. index.kdl untouched. Rebased cleanly over the daily vendor/attest bot commits.

## REMAINING — ONE live-CI step, Corey's to trigger
- **Publish a new softlink version through its (now source-recording) publish CI.** softlink's existing tianguis entry (0.11.0) has no `source` and can't be cleanly backfilled (mergeVendored idempotency discards a same-version re-add; a hand-edit is a ratchet mutation). A NEW version's first admission carries `source` as an ordinary append. This is a live OCI push + GH Actions + dispatch chain I can't run.
- **Then amoxtli resolves:** its transitive git-references softlink@main; once tianguis's softlink entry records `source`, milpa source-URL-matches git@main → agree → softlink resolves (no conflict). Then re-resolve amoxtli → commit ONLY its milpa.lock.
- **Bonus cleanup (softlink repo, Corey):** softlink can now DROP `overrides { pkg "softlink" local="." }` — root-satisfies-own-name (§14) makes it unnecessary.

## (historical) earlier remaining-notes
- **amoxtli STILL blocked on softlink:** the milpa RESOLVER now supports OCI source-URL match, but amoxtli won't resolve until softlink's tianguis OCI entry actually RECORDS its source url. Getting it there needs a LIVE tianguis-registry op: (a) manual backfill of tianguis index.kdl (may trip the append-only ratchet TNG-ENTRY-MUTATED), or (b) re-publish softlink via the new milpa publish (records source) + update the tianguis composite action to WRITE the source field into the index entry. Both are cross-repo, live-registry — confirm approach with Corey before mutating the registry. Interim alt: root-declare softlink in amoxtli milpa.kdl (tier-1) — but Corey said stay off amoxtli's milpa.kdl.
- **§3.5.3 ratchet-digest source inclusion (flagged by the OCI-data agent):** the oci canonical-violation digest doesn't include `source` — violation DETECTION is unaffected (full typed compare), only the habituation-suppression digest coalesces source-only-differing violations. Both impls, lockstep + differential fixture. Touches the LIVE ratchet's canonical digest (one-time re-alert side effect). Small; do-not-defer candidate but interacts with the tianguis work.
- **Follow-ups (Corey-gated GH issues):** workspace member required by an external transitive → TNG-NOT-FOUND (pre-existing, found by the root-self agent).


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

## Post-ship extension (in flight): OCI content-hash fallback
- SHIPPED core #193 committed+pushed as `1ff17bd` (feat: validate transitive provenance).
- **Real gap found by amoxtli:** a package published to tianguis via **OCI** (from a git
  repo) then referenced by that **git URL** by a transitive → the "incomparable transport
  (git vs OCI) → conflict" rule fires (softlink: amoxtli's crisol/nkdl chain git-references
  it; tianguis has it as OCI). git-softlink and OCI-softlink are the SAME package.
- **Fix (in flight, add1857439, Python-first):** when the registry entry has no comparable
  git source, validate by CONTENT IDENTITY instead of conflicting — compare the git source's
  `content_hash` (milpa already hashes every fetch) to the registry's recorded
  `IndexVersion.content_hash`. Same identity → accept; different → conflict; unavailable
  (legacy/empty) → conflict. Confirmed: `IndexVersion.content_hash` exists; OCI entry has no
  source URL. Spec §10 gets the incomparable-transport clause updated. Rust mirror after.
- **amoxtli lock: BLOCKED on this fix** — re-resolving amoxtli with shipped milpa (incl #193)
  fails RES-PROVENANCE-CONFLICT on softlink; once the OCI fallback lands, re-resolve → real
  versions → commit ONLY amoxtli's milpa.lock (Corey: their in-progress code-review work
  touches neither milpa.lock nor milpa.kdl, so the lock change is isolated).

## IN PROGRESS (Corey: "do 1 [OCI source-url] but do root-satisfies-own-name now as well")
Amoxtli finding: the OCI content-hash fallback (`f889621`) does NOT fix amoxtli —
softlink@main (git, content `2f1a4cfb`, v0.3.3) genuinely differs from the registry's
OCI softlink (`8ffc81bb`, v0.11.0); content-hash is version-specific so it can't tell
"same package newer version" from "different package". Root cause: `OciIndexProvenance`
records no SOURCE repo url. Two features now in flight:
- **Task 1 — OCI source-url (systemic fix for amoxtli):** record the source git url in
  OCI index entries (milpa publish → registry-protocol → tianguis backfill); resolver
  validates git-vs-OCI by SAME-REPO URL match (content-hash only as last resort). Then
  softlink@main url-matches the registry's softlink source → same package → version-solve,
  no conflict. Data layer: a05a58e5 (registry.py/publishing.py/registry-protocol.md).
  Resolver layer: AFTER root-satisfies-own-name frees resolver.py. tianguis backfill of
  softlink's source url + amoxtli re-resolve are the final (cross-repo) steps.
- **Task 2 — root-satisfies-own-name:** af03e9ce (resolver.py/resolver-semantics.md) —
  standalone root satisfies transitive requires on its own name (mirrors workspace member
  self-satisfy); retires softlink's `overrides { pkg "softlink" local="." }`.
Sequence: [A root-self-satisfy Py] + [B OCI-data Py] parallel → [Task1 resolver-validate Py]
→ Rust mirrors of both → tianguis softlink source-url backfill → amoxtli re-resolve + commit lock.

## Follow-up (now being done): root-satisfies-own-name
- softlink's own milpa.kdl needs `overrides { pkg "softlink" local="." }` because a transitive
  (proptest) `requires "softlink"` fetches a SECOND softlink instead of binding the root tree
  under build. milpa has member-satisfies-own-name (workspace, #25) but NOT root-satisfies-
  own-name (standalone) — a workspace-symmetry gap. With the rule the override is unnecessary.
  Subtlety: root's declared version must satisfy the transitive's constraint on its own name,
  else inconsistent-build ERROR (not fetch-a-second-copy). FILE as a GH issue (Corey-gated).
