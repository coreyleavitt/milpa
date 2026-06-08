# RFC: identity-and-resolution completion (milpa + tianguis, one ordered plan)

**Status:** draft (rfc-flow stage 2 — **architect rounds 1+2 applied**; ready for `/tdd`; supersedes
`tianguis/docs/rfc-identity-completion.md`, which was architect-reviewed rounds 1+2;
all of its hardened content is carried forward here)
**Spans:** tianguis (Nim registry + dispatch) **and** milpa (Python resolver) — cross-repo
**Supersedes:** `tianguis/docs/rfc-identity-completion.md` (identity half, P0–P2 below)
**Completes / touches:** tianguis #32 (identity), #37 (recorded out-of-scope), #38 (author-
signed spoofing); milpa #28 (PubGrub perf), #100 (constraint-accumulation — P3.2 prerequisite for
multi-constraint diamonds), #103 (index attestation — binds to the P1.4 trust anchor)

---

## 0. Why this is one RFC

Three bodies of work were drifting as separate threads:

1. **tianguis #32 identity completion** — finish the deferred live-index migration, wire the
   immutability guard, correct the spec.
2. **tianguis #38 author-signed security** — close the namespace-spoofing surface.
3. **milpa resolver core** — bring the *resolution* layer up to the same best-in-class bar the
   *identity* layer already meets.

They are one RFC because the **ordering** is the entire point, and the ordering is cross-repo.
A review session (architect) validates orderings; three documents would each hide the edges
that cross the repo boundary. The honest framing that motivates the whole plan:

> milpa's **identity/trust layer is best-in-class** (content-hash identity, multi-provenance,
> offline verification). Its **resolution core is not** — PubGrub is implemented as topology
> without its payoff (no derivation-tree narration), the version model isn't semver
> (prereleases dropped, no `~`/`^`), and `Strategy` is dead for named deps. "Best-in-class
> resolver" requires *both* halves. This RFC finishes the identity foundation, closes the one
> open security hole, and then brings the resolution core to the bar — in that order, because
> the identity substrate is the hard-to-change foundation and the resolver work depends on the
> migrated index + the milpa-side parse restructure.

There is exactly **one cross-repo synchronization point**: the migrated-index commit
(P1.4). Everything before it is independent prep; everything after consumes it.

---

## 1. Master ordering (the spine)

```
PHASE 0 — foundations & honesty (no cross-deps; do first)
  P0.1 (milpa)  fix VersionSet.all() latent crash                  ─┐ independent
  P0.2 (docs)   correct comparison-vs-nimble-atlas over-claims      │ independent
  P0.3 (tian)   SSOT deriveVersionNamespace proc                    │ unblocks P1.1, P1.3
  P0.4 (tian)   delete checkOidcGitAgreement (dead code)            │ cleanup
  P0.5 (tian)   correct S6 spec (rfc-package-identity + index-fmt) ─┘ precondition for P1.3

PHASE 1 — identity migration (#32 finish)            ┌─ P1.2 is the milpa gate that makes
  P0.3 ─────────────► P1.1 immutability guard+MergeAlert    the migrated index consumable;
  P0.3,P0.5 ────────► P1.3 pure migrateIndex                it must land before P1.5.
  P0.3 ─────────────► P1.3 pure migrateIndex
  P1.3 ──► P1.4 [host/org-reject guard lands first, same commit] run migration + COMMIT
                                                   ◄═══ THE cross-repo sync point
  P1.2 (milpa parse_index tuple-key) ──┐
  P1.4 ────────────────────────────────┴► P1.5 post-migration cross-repo smoke + consumer-impact
  P1.4 ─────────────► P1.6 yank stale coreyleavitt/nimkdl

PHASE 2 — supply-chain hardening (#38); right after P1.4 (window already shut by P1.4's guard)
  P1.4 ─► P2.1 author-signed namespace from verified OIDC SAN (binary+workflow; promotes guard)
          P2.2 delete the Go dispatch deriveNamespace (4th impl) + drop workflow input
          P2.3 conformance corpus SAN cases + normative signed_by format

PHASE 3 — resolution core to the bar (milpa headline; after identity is stable + P1.2 lands)
  P3.1a (Version type swap → real semver; prereleases parsed-but-dropped; suite stays green)
    ├─► P3.1b (prerelease ordering + opt-in inclusion, cargo-style)
    └─► P3.1c (operators ~ ^ != bare-= + || disjunction)
  P1.2, P3.1c ─► P3.2 multi-version named-dep provider (provider-contract change) ─► P3.3
  P3.3 strategy + backtracking for named deps (validates existing _pick_version wiring)
  P3.3 ─► P3.4 PubGrub cause-chain narration (SEQUENTIAL, same file; closes the P0.2 doc loop)
  (P3.5 conflict-learning + backjumping — perf, DEFERRED to #28)
```

**Why this order (the edges that matter):**

- **P0 before everything.** P0.1 is a latent `AttributeError` — fix before it bites. P0.2 is
  honesty (stop claiming unbuilt features). P0.3/P0.4/P0.5 are pure/cleanup/doc and unblock the
  migration without touching live data.
- **P1.2 (milpa parse) must land — and be *deployed* — before P1.4 commits, not merely before
  P1.5 (R2 breadth, critical).** The migrated index is only *verifiably* good if a consumer that
  tuple-keys can read it without dropping the collision pair. But the hazard is sharper than
  "P1.2 gates P1.5": milpa's gated integration suite fetches the **live `main`** index
  (`tests/test_integration.py:171` + `tests/test_tianguis_integration.py:37`, both hardcode the
  `raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl` URL, neither pins a commit),
  and the `commit-entry.yaml` workflow **clones milpa** to run `parse_index` during publish. So the
  instant P1.4 lands on `main`, any *pre-P1.2* milpa (in CI or in the workflow clone) silently
  drops one `nimkdl` entry (bare-name collision) — no hard failure, just wrong data.
  **Hard ordering constraint:** P1.2 must be merged to milpa `main` **and** the workflow's milpa
  checkout must resolve to the post-P1.2 commit **before** P1.4 is executed. Mechanism: pin the
  workflow's milpa checkout to a tag/SHA (or add a `milpa_sha` input) ≥ the P1.2 commit; P1.4's
  operator runbook verifies this pin first. P1.2 is milpa-side and independent of the tianguis
  chain, so it can run anytime in Phase 0/1 — but this deploy-ordering edge is a release gate, not
  just a logical dep.
- **P3.1 (all milpa, no tianguis dep until P3.2) can run in parallel with the Phase 0/1 tianguis
  chain (R2 feasibility).** The entire P3.1a→b→c chain touches only milpa Python and depends on
  nothing in P0.3→P1.1→P1.3→P1.4; it can proceed on a separate branch to shorten wall-clock if the
  RFC spans weeks. The first cross-phase join is P3.2 (needs P1.2 + P3.1c).
- **P1.4 is the sync point and the new trust anchor.** Nothing downstream (P1.5, P1.6, all of
  Phase 2) can proceed until the migrated index is committed.
- **The transition window is shut by P1.4 itself, not by Phase 2.** The window where a publish on
  the old path could write an org-only namespace back into the freshly-migrated index opens the
  instant P1.4 commits — so the `host/org`-form reject guard in `cmdAddEntry` (a ~3-line check)
  **lands in the same commit as P1.4**, not deferred to P2.1 (R1 feasibility: P2.1 is a multi-hour
  SAN-extraction slice; gating the window on it leaves a real attack window during its review).
  Phase 2 then *promotes* that guard from a coarse "must contain `/`" reject to deriving the
  namespace from the verified OIDC SAN.
- **Phase 3 follows identity** for two reasons: (a) CLAUDE.md's "de-risk the identity model
  first" — identity is the hard-to-change foundation; (b) the resolver-core named-dep work
  (P3.2/P3.3) builds directly on P1.2's `tianguis_client` parse restructure, so doing it before
  P1.2 would mean reworking the same module twice.
- **Within Phase 3, the semver model (P3.1) is the foundation** — a multi-version provider that
  drops prereleases materializes an incomplete candidate set, so P3.1 precedes P3.2. P3.1 is **not
  one slice**: it's a wide type replacement (`Version` touches `solver.py`, `tianguis_client.py`,
  `resolver.py`, `lockfile.py`, and every `VersionSet` property test). It splits into P3.1a (atomic
  type swap, suite stays green by parsing-and-dropping prereleases as today), P3.1b (prerelease
  ordering+opt-in), P3.1c (operators+disjunction) — each green (R1 feasibility, critical).
- **P3.4 narration is sequential after P3.3, not parallel.** It rewrites the same
  `_format_conflict_chain` that P3.2/P3.3 churn around; "parallel, same file" invites conflicts.
  Run it on the same branch right after P3.3.

---

## 2. What is already done (do not re-touch)

| Slice | Landed artifact (tianguis unless noted) |
|---|---|
| #32 S1 | `namespace.nim` — `deriveNamespace -> Result[ForgeRef, DerivationError]` (structured parse→normalize→serialize; forges + case policy + SSH residue + percent-decode + gitlab-depth>2 fail + no-org fail). Model promoted to `(namespace,name)`. |
| #32 S1/S4 | `checkIdentityStable` (wired here, P1.1), `checkOidcGitAgreement` (**deleted** here, P0.4). |
| #32 S2 | `docs/spec/index-format.md` host/org model + `spec/fixtures/derive-namespace.json` (40-case corpus). |
| #32 S3 | kdl_io host/org round-trip; the two-`nimkdl` pair survives parse→emit as two entries. |
| #32 S4 | `buildVendoredEntry -> Result` (hard-reject underivable provenance); intra-org leaf collision → reject-new/preserve-existing; tuple-keyed denylist; `tianguis show <url>`. |
| #32 S5 | `vendor/resolve.nim` pure bare→qualified require mapping; `Version.partiallyResolved`. |
| milpa #97 | resolver→tianguis-index swap (S0–S7), code-reviewed, ship-ready. Named deps carry typed git/oci provenance; index supplies identity+provenance+version-set. **This RFC builds on the post-#97 milpa.** |

---

## 3. Audit facts grounding the migration (live `index.kdl`, 2613 packages)

- **All 2509 non-empty namespaces are stale *org-only*** (`nim-lang`, `status-im`, …) — **zero**
  are `host/org`. "Preserve verbatim" would leave 2509 entries as invalid host-less identities;
  immutability protects *valid #32* identities and **there are none yet** (every entry is a
  pre-#32 form: org-only or empty).
- **0 entries lack a derivable git provenance URL.** All 104 zero-namespace entries have a
  structurally valid `pkGit` `provenance.url` (the zero was the old `namespaceOf()` only handling
  `github.com`, not an absent URL). All 2509 org-only entries have `github.com` provenance, so
  `github.com/<stored_org>` is the correct output in every case. No version is OCI-only without a
  derivable git URL or a `signed_by` OIDC SAN. 2508/2509 org-only values already equal the
  derived org.
- **The 1 mismatch is `nimkdl` (the #32 artifact):** v2.1.0 (git `github.com/greenm01/nimkdl`,
  vendored) is greenm01's; v0.1.4 (OCI `ghcr.io/coreyleavitt/nimkdl`, author-signed) is
  coreyleavitt's, conflated under namespace `coreyleavitt`. greenm01's version data survived
  intact → the repair is a **deterministic per-version split by provenance**, no re-ingest.
- **0 gitlab nested-group URLs** (all 64 gitlab refs are clean `gitlab.com/org/repo`) → **#37 is
  not a migration blocker**; stays additive/future.
- **#38 hole confirmed live:** `addentry.nim:91` stamps `namespace: args.namespace` from the
  untrusted `--namespace` flag (`commit-entry.yaml:124`); `signedBy` is captured but unused for
  identity. `dispatch/handler.go:115,157` is a **second org-only `deriveNamespace`** feeding the
  same workflow.

---

## 4. Cross-cutting mechanisms (defined once, used across slices)

### 4.1 SSOT — `deriveVersionNamespace` (P0.3)
The "pick the attestation anchor, then derive" rule is needed wherever a *version object* must
yield its identity (P1.1 re-ingest guard, P1.3 migration). One shared pure proc in
`namespace.nim`; **discriminant = provenance-presence, not the freeform `attestation` string**
(legacy entries predate the string constants, so string-branching mis-derives them):

```nim
proc deriveVersionNamespace*(v: Version): Result[string, DerivationError] =
  ## SSOT per-version anchor rule. Returns the serialized "host/org" string
  ## (`namespaceString`, namespace.nim:31) — every call site compares against the
  ## stored `namespace` *string* or regroups by it; the intermediate `ForgeRef` is
  ## never inspected, so returning it is structural noise (R1 design finding). First
  ## pkGit provenance → its url; else signedBy (OIDC SAN); else err(derrUnparseable).
  ## `upstream` is NEVER an anchor.
  for prov in v.provenances:
    if prov.kind == pkGit:
      return deriveNamespace(prov.url).map(namespaceString)
  if v.signedBy.len > 0:
    return deriveNamespace(v.signedBy).map(namespaceString)
  err[string, DerivationError](derrUnparseable)
```

Verified against `model.nim`: `Version.provenances` is a `seq[Provenance]` (case object; `pkGit`
carries `url`), **not** a scalar `provenance.url`; author-signed versions are `pkOci`-only with
the SAN in `signedBy`, so "no `pkGit` ⇒ use `signedBy`" is the exact vendored/author-signed split.
A typed `AttestationAnchor` sum was considered and rejected: the deeper reason (not just "2 kinds")
is that **`Version` is already the data** — deriving from it on demand needs no construction site
and no cache-invalidation, whereas an anchor wrapper is either a redundant thin shell or a cached
derivation needing invalidation. Even at 3+ kinds, recover from the `Version`. **#38 (P2.1) is not
a caller** — at add-entry time the anchor is statically the OIDC SAN, so it calls
`deriveNamespace(extractedSan)` directly.

**Vendored-anchor consistency invariant (verified; pinned in P0.3 as a *falsifiable property
test*, not a prose claim):** `buildVendoredEntry` sets `package.upstream` and `provenances[0].url`
from the same `pkg.url`, so for **every** well-formed vendored entry `e`:
`e.version.provenances[0].kind == pkGit ∧ deriveVersionNamespace(e.version) ==
deriveNamespace(e.package.upstream).map(namespaceString)`. **Why this is load-bearing (R1 depth):**
the `signedBy` fallthrough must *never* fire for a vendored entry — a vendored entry's `signedBy`
is the milpa-bot identity (`github.com/coreyleavitt`, the index owner), so if a future bug stripped
the `pkGit` provenance the fallthrough would mis-derive **every** vendored package's namespace to
the index owner's. The property test (P0.3) is what guards that, not the invariant's assertion.

### 4.2 `MergeOutcome` as a closed sum (P1.1)
`MergeOutcome` today carries `drift: Option[DriftAlert]` + `collision: Option[IntraOrgCollision]`
(merge.nim:35–38); adding a third parallel optional for identity-drift makes an 8-state space with
5 reachable states — a shallow interface whose "at-most-one" invariant lives only in control flow.
**Make the outcome a case object** so the invariant is structural (exactly one outcome per merge,
*by construction*) and the caller's `case` is **compiler-checked exhaustive** — strictly better
than an `Option[MergeAlert]` sum that still leaves the caller writing `if alert.isSome: case
alert.get.kind` with no help on the no-alert path (R1 design, critical):

```nim
type
  MergeOutcomeKind* = enum
    mokAdded          ## new package or new version inserted
    mokIdempotent     ## identical re-ingest; index unchanged
    mokIdentityDrift  ## stored host/org namespace != re-derived (immutability violation; reject)
    mokCollision      ## intra-org leaf-name collision, different repo (reject-new/preserve-existing)
    mokContentDrift   ## same (namespace,name,version), different content_hash (reject incoming, warn)
  MergeOutcome* = object
    ## Pure classification of WHAT happened — carries no index (R2 design). The
    ## post-merge index is returned alongside, never bundled in: bundling it in
    ## every variant (incl. the three rejects, where index == input) is a footgun —
    ## a caller could `commitIndex(outcome.index)` and silently commit a no-op on a
    ## *rejected* merge. Separating them forces the caller to actively decide whether
    ## to use the returned index, which on a reject they must not.
    case kind*: MergeOutcomeKind
    of mokAdded, mokIdempotent: discard
    of mokIdentityDrift: identity*:  IdentityDrift      ## stays defined in namespace.nim
    of mokCollision:     collision*: IntraOrgCollision  ## stays defined in vendor/merge.nim
    of mokContentDrift:  content*:   DriftAlert         ## stays defined in vendor/merge.nim

proc mergeVendored*(idx: Index, entry: VendoredEntry): tuple[index: Index, outcome: MergeOutcome]
  ## index == idx unchanged on mokIdentityDrift/mokCollision/mokContentDrift (reject);
  ## the mutated index only on mokAdded/mokIdempotent. Caller commits iff outcome.kind
  ## in {mokAdded} (mokIdempotent is a no-op write that's safe to skip).
```

**Each payload type stays in its home module** (R1 design, high) — `IdentityDrift` in
`namespace.nim`, `DriftAlert`/`IntraOrgCollision` in `merge.nim`. The case object *references*
them (merge.nim already imports namespace.nim for `deriveNamespace`), so `checkIdentityStable`
still returns a standalone `IdentityDrift` usable by future non-merge callers (e.g. a read-path
verifier on `tianguis show`) without importing merge.nim. The `alerts.kdl` sink dispatches via
**overloaded** `formatAlert(d: DriftAlert)` / `formatAlert(c: IntraOrgCollision)` /
`formatAlert(i: IdentityDrift)` selected by `outcome.kind` — Nim overloading, no sum-wrapper.

**At-most-one holds by construction** (R1 depth): `mergeVendored` reaches exactly one outcome via
mutually-exclusive exit paths; the case object makes that the type, not a comment. Firing priority
is fixed in P1.1.

### 4.3 `MigrationHalt` variant (P1.3)
```nim
type
  MigrationHaltKind* = enum mhkDerivationFailed, mhkUnexpectedSplit
  MigrationHalt* = object
    case kind*: MigrationHaltKind
    of mhkDerivationFailed:
      packageName*:   string
      version*:       string
      provenanceUrl*: string         ## the anchor that failed to derive (self-contained diagnosis)
      error*:         DerivationError
    of mhkUnexpectedSplit:
      ## each entry self-contained: which package, into which namespaces, and the
      ## (version, provenanceUrl) pairs that produced each — so the operator can
      ## diagnose an unexpected split without re-opening the index (R1 design).
      splits*: seq[tuple[name: string,
                         namespaces: seq[string],
                         sources: seq[tuple[version: string, provenanceUrl: string]]]]
```

---

## 5. Slices

Gate = the relevant repo's full suite green unless noted (tianguis: container Nim suite per
handoff; milpa: `uv run pytest`).

### PHASE 0 — foundations & honesty

#### P0.1 — fix `VersionSet.all()` latent crash  *(milpa, /tdd)*
`resolver.py:1210` (`_extract_from_milpa_kdl`, transitive milpa.kdl path) calls
`VersionSet.all()`; the method is `full()` (solver.py:100; verified the *only* occurrence). Latent
`AttributeError` on any NamedDep-without-constraint in a transitive milpa.kdl — latent because every
current transitive is a URL dep from a `.nimble`, so no live fixture exercises it. Fix to `full()`;
pin a regression test that **drives the `_extract_from_milpa_kdl` transitive path specifically**
(a transitive `milpa.kdl` with a bare, unconstrained `NamedDep`), not merely `from_constraint(None)`
(a different code path that would leave the bug uncovered). **Independent; do first.**

#### P0.2 — correct the comparison doc  *(milpa docs; edit-only, no /tdd — no RED state)*
`docs/comparison-vs-nimble-atlas.md` lists prerelease opt-in, build metadata, caret/tilde, and
"derivation chain / proof-certificate narration" as milpa capabilities. They are unbuilt. Move
each to an explicit *planned (this RFC, Phase 3)* state so the doc stops over-claiming against
the PhD bar. Honesty precondition — a reviewer would otherwise ding the version model on sight.

#### P0.3 — SSOT `deriveVersionNamespace`  *(tianguis, /tdd; precedes P1.1 & P1.3)*
Land §4.1 in `namespace.nim`, returning `Result[string, DerivationError]` (the serialized
`host/org`; see §4.1 for why `ForgeRef` would be structural noise). Pure addition, no call sites
yet → lands green. **Behaviors:** pkGit→provenance url; pkOci-only + GH-Actions `signedBy`→
`github.com/<owner>`; neither→`err(derrUnparseable)`; both→prefers pkGit. **Vendored-anchor
invariant pinned as a falsifiable property test** (not a prose claim): over generated well-formed
`VendoredEntry`s, `entry.version.provenances[0].kind == pkGit` **and** `deriveVersionNamespace(
entry.version) == deriveNamespace(entry.package.upstream).map(namespaceString)` — this is what
guarantees the `signedBy` fallthrough never mis-derives a vendored package to the index owner
(§4.1).

#### P0.4 — delete `checkOidcGitAgreement`  *(tianguis)*
It only does work for a version carrying **both** a git provenance and an OIDC SAN; the add-entry
path is `pkOci`-only, so no such version exists and wiring it would re-create dead code (its own
docstring says "wire this in when that combination becomes possible"). **#38 closes without it.**
Delete the proc (`namespace.nim`, ~line 290–303) **and `tests/test_namespace_oidc.nim`** (the file
that tests it — verified present). Record in `rfc-package-identity.md` that the cross-path
git↔OIDC agreement check is deferred until a both-provenance path exists. **Follow-on filed:
tianguis #39** (per the defer-file-now rule); distinct from #36 (post-rename *unification*, not
same-version dual-anchor agreement).

#### P0.5 — correct the S6 spec  *(tianguis docs; edit-only, no /tdd; precondition for P1.3, human sign-off)*
Edit `rfc-package-identity.md`: replace preserve-verbatim with **derive-all-per-version +
regroup** (§3); org-only/empty are pre-#32 forms the migration derives **once**, immutability
binds *after*; nimkdl repair is a deterministic per-version split; restate gate #4 as achievable
by the migration alone. Update `docs/spec/index-format.md` (normative): the per-version
attestation-anchor algorithm + the normative `signed_by` format (see P2.3). No code; verification
= review + §3 audit + sign-off. **Named deliverable in the gate (else it slips):** milpa repo
`docs/identity-and-provenance.md` updated with the org-rename consequence (per the corrected §P2.1
note — a rename creates a *new* entry, it is **not** "rejected"; #36 is the fix).

### PHASE 1 — identity migration

#### P1.1 — immutability guard + `MergeOutcome` sum  *(tianguis, /tdd; needs P0.3)*
Deliver the §4.2 `MergeOutcome` case-object refactor and wire `checkIdentityStable` into
`mergeVendored` (`merge.nim`).

**Firing point + explicit priority (resolves the R1 ambiguity).** The guard fires **once**, inside
the `foundPkgIdx >= 0` branch, as the **first** check — before the intra-org collision check and
before the per-version content-drift loop. Because `MergeOutcome` is now a closed sum (exactly one
outcome per call), the order *is* a priority: `mokIdentityDrift` ▸ then `mokCollision` ▸ then
`mokContentDrift` ▸ then `mokAdded`/`mokIdempotent`. Identity drift is the most severe (an
immutability violation), so it wins; this is a deliberate, stated choice, not an accident of
control flow. Re-derive via `deriveVersionNamespace(entry.version)` and compare (string ==) to
`packages[foundPkgIdx].namespace`. **Guard condition:** fire only when the stored namespace is
already `host/org` (contains `/`); pre-P1.3 org-only values are skipped (firing before P1.3 would
false-positive). Post-P1.3 every stored namespace is `host/org` and the guard is unconditional.

**What this guard actually catches (honest scoping — R1 depth, critical).** Given the §4.1
vendored-anchor invariant, a *well-formed vendored entry can never trigger it*: the lookup is keyed
on the entry's own derived namespace, so a found package's stored namespace already equals the
re-derivation. Its real value is **defense-in-depth**: it catches a *corrupted or manually-edited*
stored namespace, a serialization regression, and the **future** `pkOci` author-signed re-ingest
path (a path whose derived namespace could disagree with an existing `pkGit`-established
`(namespace,name)`). It does **NOT** catch an org rename — a rename derives a *new* namespace, so
the lookup misses and `mergeVendored` creates a *new* package entry (the stale old one persists;
#36 is the fix). The slice keeps the guard (cheap, trust-critical, forward-compatible) but states
this scope so no one mistakes it for rename-handling.

**Blast radius (atomic; R1 feasibility, R2-confirmed).** The `MergeOutcome` field change forces
simultaneous edits to **six** files — they must land in one slice: `vendor/merge.nim` (5
construction sites + the new `tuple[index, outcome]` return), `vendor/orchestrate.nim` (the split
where `drift`→`appendAlert` but `collision` is formatted inline → one `case outcome.kind` dispatch
to overloaded `formatAlert`; also unpacks the new return tuple and commits the index only on
`mokAdded`), `vendor/alerts.nim` (`formatAlert` overloads), and tests `test_vendor_merge.nim`,
`test_vendor_alerts.nim`, `test_vendor_orchestrate.nim` (all construct/inspect `MergeOutcome` by the
old field names). `realdriver.nim` does **not** reference `MergeOutcome` (R2 feasibility — verified;
the six-file list is complete). The new `alerts.nim`→`namespace.nim` import edge (for the
`formatAlert(IdentityDrift)` overload) is **acyclic**: `namespace.nim` imports only
`std/[strutils, options]` + `nkdl`, no vendor modules (R2 feasibility — verified). The
all-six-at-once edit is genuinely atomic (the type change breaks compilation everywhere
simultaneously — there is no incremental red-green seam; this is inherent to a Nim variant-type
change with no external consumers, and is acceptable: write all six, then drive the suite green).
*Allowed — no external consumers, pre-1.0.* identity-drift emits a distinct `alerts.kdl` node
(`identity-drift name=… stored=… rederived=…`). Never overwrites, never silently passes.
**Behaviors:** same derived ns→`mokIdempotent`/`mokAdded`, no alert; org-only stored→guard skipped;
corrupted/different stored ns (post-migration) → `mokIdentityDrift`, stored unchanged;
content-drift→`mokContentDrift`; collision→`mokCollision`; all three alert kinds round-trip through
`alerts.kdl`; identity-drift+collision on one entry → `mokIdentityDrift` wins (priority pinned).

#### P1.2 — milpa `parse_index` tuple-key  *(milpa, /tdd; gates P1.5; independent of the tianguis chain)*
In `tianguis_client.py` (≈ line 376) key `packages` on `(namespace, name)` not bare `name`:
- **(0) FIRST step — register `TNG-AMBIGUOUS-NAME` in `_TNG_CODES`** (the hardcoded `frozenset`,
  tianguis_client.py:38–51) **and** update the error-catalog **bijection lint** test that asserts
  the catalog is complete. `TianguisError.__init__` asserts code membership (line 143), so any
  raise written before this lands `AssertionError`s — making the RED step confusing. Do this
  before any raise site exists.
- (a) add a `namespace` field to the `Package` dataclass (absent today);
- (b) rekey the internal store to `dict[tuple[str,str], Package]`;
- (c) **Make qualified lookup the primary API** (R1 design): `lookup(namespace: str, name: str)`
  is the real entry point for a `(namespace,name)`-keyed registry. `lookup_bare(name: str)` is the
  convenience that fans out — but it **returns a typed result, it does not raise** (R2 design):
  `lookup_bare(name) -> Package | AmbiguousName` where `AmbiguousName` is a frozen dataclass
  `(name: str, namespaces: list[str])`. **Why a typed result, not a raise:** the eventual P3.2/P3.3
  multi-version provider asks the registry to *enumerate* candidates while backtracking — a raise
  inside `versions()` is a hard stop mid-solve, whereas a typed `AmbiguousName` lets the provider
  return an empty/structured candidate set the solver can reason about (and #100's
  collect-all-constraints pass needs the same enumerate-don't-throw shape). Raising from
  `lookup_bare` would collapse the caller's decision space at the wrong layer and force a signature
  change later; the typed result pays nothing extra today and ages into P3.2 unchanged. **Scope
  guard:** this slice adds neither manifest-level `namespace=` syntax nor row-selection — those stay
  deferred (the consumer disambiguation concern). Exposing the qualified path + typed-ambiguity now
  just keeps that door open instead of closing it.
- (d) `resolve_named` calls `lookup_bare`; on `AmbiguousName` it **raises** the coded
  `TNG-AMBIGUOUS-NAME` (the raise lives at the resolution call site, the policy layer — not in the
  registry primitive), rather than silently picking.
**Behaviors:** `TNG-AMBIGUOUS-NAME` is in `_TNG_CODES` and the bijection lint passes; a
two-`nimkdl`-blocks fixture string parses to **2** packages; `lookup(ns, name)` returns the one
package; `lookup_bare` returns the `Package` when unambiguous; `lookup_bare` on a collision pair
returns `AmbiguousName(name, [ns1, ns2])` (does not raise); `resolve_named` on that collision pair
raises `TNG-AMBIGUOUS-NAME`.

#### P1.3 — pure `migrateIndex`  *(tianguis, /tdd; needs P0.3, P0.5)*
`proc migrateIndex(idx: Index): Result[Index, MigrationHalt]` — no disk I/O. Per version: derive
`host/org` via `deriveVersionNamespace`, regroup by `(namespace, name)`, split `nimkdl`, and
**`canonicalize` the output before returning** (deterministic order — `Index ==` is seq-order-
sensitive and `canonicalize` is idempotent). No fallback; a non-deriving version or an unexpected
split beyond `nimkdl` → `err(MigrationHalt)` (§4.3). **Gates (pure assertions on the output value;
testable on a small synthetic index — org-only, empty-ns, the two-`nimkdl` pair, an already-
`host/org` entry — the live file is NOT needed):**
1. **In-memory** KDL round-trip: `formatKdl(out)` re-parses (`parseKdl`) byte-identically and
   `formatJson(out)` matches — the *pure* analog of `tianguis project --check` (which is a
   disk/subprocess command and belongs to P1.4, not this no-I/O proc; R1 feasibility).
1b. **Full field-level round-trip identity:** `migrateIndex(parseKdl(formatKdl(out))) == out` — the
    `Index ==` operator covers *every* field (`partiallyResolved`, `signedBy`, `publishedAt`,
    `requires`), catching a silent drop that gate 1's KDL/JSON parity would miss (R1 depth).
2. zero `namespace ""` entries remain.
3. every namespace matches `^[a-z0-9.-]+/[a-zA-Z0-9_.~-]+$`.
4. the `nimkdl` pair → **two** `package` blocks, different `namespace`, each carrying its own
   versions intact (per-version split, no re-ingest).
5a. `output_package_count >= input_package_count` (only splits/preserves, never drops).
5b. **version conservation (bijection, not count):** build a multiset keyed on
    `(version_string, content_hash)` — the immutable identity, which survives the namespace change —
    over all input versions and all output versions; assert the two multisets are **equal** (every
    input version appears in **exactly one** output package; catches both drops *and* double-emits,
    which a total count cannot). **Note (R2 depth — corrected):** the real `nimkdl` pair (`v2.1.0`
    vs `v0.1.4`) is distinguished by `version_string` *alone*; the live index has no two entries
    sharing `version_string` with different `content_hash`, so the content-hash component of the key
    is **not** exercised by any real data. The fixture must therefore **synthesize** a
    same-`version_string`/different-`content_hash` pair to exercise that component (it guards the
    *general* version-conservation property — e.g. a future re-publish of the same version string
    from a different source — not the specific `nimkdl` split, which `version_string` already
    separates).
6. idempotency: `migrateIndex(migrateIndex(idx)) == migrateIndex(idx)`.
6b. **canonicalization is the mechanism, not luck:** `migrateIndex(reverse(out.packages)) ==
    migrateIndex(out)` — a deliberately mis-ordered input must converge, pinning the `canonicalize`
    call rather than relying on the input happening to be canonical (R1 design).

#### P1.4 — run migration + commit  *(tianguis, operational; needs P1.3)*  ◄ CROSS-REPO SYNC / NEW TRUST ANCHOR
A `tianguis migrate` subcommand, **`{.deprecated: "one-time #32 migration".}`** (one-shot; don't
let it become permanent CLI surface). **UX (R1 design — a `{.deprecated.}` pragma is a *compile*
warning, invisible to the operator running the binary, so make safety runtime-explicit):**
`--dry-run` is the default and prints the full diff + every split diagnostic to stdout ending in an
explicit `DRY RUN — no changes written` line, exit 0; mutation requires an explicit **`--execute`**
flag (not `--no-dry-run`); without `--execute` also emit a one-line stderr notice
(`one-time #32 migration; re-run with --execute to commit`).

**Both index artifacts regenerated atomically by `--execute` itself (R2 depth, high).** The
"staging file + rename" atomicity must cover **both** `index.kdl` *and* `index.json` — not just the
KDL. `tianguis migrate --execute` regenerates `index.json` **internally** (the same code path
`tianguis project` runs) into a staging file, then renames both into place before printing
`migration complete`. The operator must **not** be told to "remember to run `tianguis project`
afterward": a crash between the KDL rename and a manual JSON regen would leave a committed-but-broken
state that only `parity.yaml` CI catches post-hoc. Pre-run `index.kdl`→`index.kdl.bak` (local aid
only, **not** a repo recovery artifact). `tianguis project --check` green is then the *post-commit
CI verify*, not a manual operator step.

**Migration audit record (R2 breadth, medium — this is a new trust anchor; treat it like one).** A
trust-anchor-establishing mutation must leave an auditable trace, the way vendor-en-absentia runs
already append to `alerts.kdl`. `--execute` writes a machine-readable migration record (a committed
`docs/spec/migrations/0001-32-identity.json` or an `alerts.kdl` append) capturing: package count
before/after, the exact split set (expect `{nimkdl}`), and the resulting `(name → [namespaces])`
for every split. This is the provenance of the anchor itself; milpa#103's index attestation binds
to this commit and benefits from a self-describing record.

**Window-closing guard lands in THIS commit (R1 feasibility, high), not P2.1 — and it is
deliberately *fail-closed* (R2 breadth, important).** The instant the migrated index commits, a
publish on the old path could write an org-only namespace back (failing gate #3). Add the ~3-line
`host/org`-form reject to `cmdAddEntry` (reject any namespace lacking `/`) **here**, atomically with
the migration. **Consequence — an intentional author-publish freeze, not a bug:** the *only* writer
of an org-only namespace is the dispatch path, where the Go `deriveNamespace` emits org-only
(`handler.go:162` returns `tail[:i]`, **not** `github.com/…`). So between P1.4 and P2.1 **every
author-signed publish via dispatch is rejected** by this guard. This is the **correct fail-closed
posture**: until P2.1 wires *verified-SAN* derivation, the only available namespace source for an
author publish is the **untrusted** `--namespace`/provenance input — which is exactly the #38 hole.
Blocking author publishes is strictly safer than trusting untrusted input for a few days. **Vendored
publishing is unaffected** — `buildVendoredEntry` derives `host/org` from the trusted provenance and
passes the guard; only author self-publish is frozen. **Mitigation:** sequence P2.1 promptly after
P1.4 (it is the next slice); document the freeze in the P1.4 runbook so an author publish attempted
in the window gets an explained rejection, not a mystery. P2.1 later *promotes* this coarse guard to
deriving the namespace from the verified OIDC SAN, lifting the freeze. (The guard is testable Nim —
write it TDD even though the migration run itself is operational. **Existing-test note (R2
feasibility):** `tests/test_cmd_add_entry.nim` currently exercises an org-only `namespace:
"coreyleavitt"` fixture (≈ line 51/66) that this guard will now reject — that case must be converted
to a guard-rejection assertion and a new `host/org`-accepted case added, or the implementer will see
existing tests fail with no explanation.)

Operator runs `--dry-run`, reviews splits (expect exactly `nimkdl`), re-runs with `--execute`,
commits. The post-migration commit is the **new trust anchor** (consumer-side index attestation
binds here — milpa#103, deferred). **Rollback (R2 breadth — `git revert` alone is insufficient):**
`git revert <P1.4-sha>` reverts to the pre-migration index, which **does not know** any entry
committed *after* P1.4 — both vendor-en-absentia additions **and** (once P2.1 lifts the freeze)
author-signed `host/org` publishes landed in the interim are lost by a blind revert. Correct
rollback: `git revert` then **re-apply every interim entry** from the git log / `alerts.kdl` of the
P1.4→revert window onto the re-migrated index (a cherry-pick-and-re-migrate, not a blind revert).
During the freeze window (before P2.1) only vendored additions can occur, narrowing this — but state
it so a later rollback after P2.1 doesn't silently drop author publishes. **Done when:** the
`host/org` guard is in `cmdAddEntry` (with the converted test fixture), real index migrated, gates
1–6b hold, `index.json` regenerated *by `--execute`*, migration record committed, `tianguis project
--check` green.

#### P1.5 — post-migration cross-repo smoke + consumer-impact  *(cross-repo, manual; needs P1.4 + P1.2)*
milpa `parse_index` on the committed migrated index drops no entry and the `nimkdl` pair reads as
two `Package`s. Cannot be a Nim unit gate (needs the milpa repo + the committed index) — a manual
end-to-end check. Also: milpa's gated integration suite (fresco's tree) still green against the
migrated index.

**Existing-consumer impact (R1 breadth, critical — settled, documented here, not a fork).** milpa
lockfiles store **bare** dep names + provenance; P1.2 does *not* change the lockfile format, and
#97 deleted `_pin_for_named_dep` (named-dep prior-pin is vacuous), so there is no per-dep namespace
recorded to disambiguate against. Settled behavior:
- `milpa verify` is **unaffected** — verification is content-hash vs `_deps/`, provenance-blind
  (lockfile.py:574–611).
- `milpa fetch`/`update` **re-resolve** the bare name against the migrated index via `lookup_bare`.
  For an ordinary unique name this is transparent. For a name that now maps to >1 namespace it
  raises `TNG-AMBIGUOUS-NAME` — the consumer's escape is to switch that dep to a URL dep (precise
  provenance), which is the correct disambiguation pre-#100/manifest-`namespace=`.
- **`nimkdl` re-resolution after P1.6:** a consumer that had resolved `nimkdl` to the OCI
  `coreyleavitt` entry will, post-split+yank, re-resolve the bare name to greenm01's surviving
  entry (different URL/content). This is *correct* — the coreyleavitt entry was the conflated-
  identity artifact #32 repairs. Document in `docs/identity-and-provenance.md` (owned by P0.5):
  anyone who genuinely wants the old OCI artifact pins it as an explicit URL/OCI dep.
This subsection is documentation + the manual smoke, not new resolver code; the only code is P1.2's
`lookup_bare` raise, already gated there.

#### P1.6 — yank stale `coreyleavitt/nimkdl` v0.1.4  *(tianguis; needs P1.4)*
After P1.4 splits `nimkdl`, the coreyleavitt entry is a dead pre-rename publish (project is now
`nkdl`). **Mechanism: a direct KDL edit (delete the `package` block), NOT a yank-flag operation**
— #13 yank semantics are unimplemented (no `cmdYank`; `yanked*` fields parsed-but-unenforced), so
"per #13" would mean building the yank subsystem (out of scope). `tianguis project --check` catches
JSON staleness. Hard-remove is safe: the `github.com/coreyleavitt/nimkdl` identity only exists as
of P1.4, so no qualified-key lockfile can reference it; the milpa consumer soft-cutover warns on
stale bare-name entries anyway. **Done when:** no `coreyleavitt/nimkdl` entry remains; greenm01's
`nimkdl` untouched; `project --check` green.

### PHASE 2 — supply-chain hardening (#38)

#### P2.1 — author-signed namespace from verified OIDC SAN  *(tianguis, /tdd; right after P1.4)*
Derive the author-signed `namespace` from the **verified** OIDC signer, not `--namespace`. This
alone closes #38, and it **promotes** the coarse `host/org`-reject guard already shipped in P1.4
to true SAN-derivation. **Spans two components with two gates** (R1 breadth — the Nim suite cannot
catch a workflow regression):

- **Ownership architecture (R1 breadth — state it explicitly).** The SAN extraction lives in the
  **workflow** (`commit-entry.yaml`), the derivation+enforcement lives in the **binary**
  (`addentry.nim`). Today `commit-entry.yaml` uses the caller-supplied `signed_by` only as a regexp
  *prefix* in `cosign verify --certificate-identity-regexp="^${SIGNED_BY}@"` — a prefix match ≠ the
  verified SAN. The workflow must capture the *actual* cert SAN from cosign and pass **that** to the
  binary; the binary then trusts only the workflow-extracted SAN. (Self-authenticating the binary —
  running cosign inside `addentry` — is heavier and out of scope; the trust boundary is the
  workflow, documented as such.)
- **SAN extraction (workflow):** `cosign verify … --output json | jq -r '.[0].optional.Subject'`.
  ⚠ **The jq path is unverified against the pinned cosign (v2.4.0) — verify before coding** (R1
  depth): run it on a real GH-Actions-OIDC-signed artifact, record the actual field path in the
  slice, and make the step **fail loudly** if the extracted SAN is empty (an empty SAN →
  `deriveNamespace("")` → silent hard-reject of every author publish). The P2.1 SAN-parse test uses
  a fixture JSON mirroring the real v2.4.0 output shape.
- **Derivation (binary):** `addentry.nim` sets `namespace = deriveNamespace(extractedSan)` (full GH
  Actions SAN `https://github.com/owner/repo/.github/workflows/publish.yaml@refs/heads/main` →
  `github.com/owner`); **hard-reject** if derivation fails (never namespace "").
- **Observable rejection signal (R2 breadth).** A hard-reject must be *visible*, not a silent exit:
  today `cmdAddEntry` only writes stderr on OCI-pull/parse failure and `discard`s the merge outcome
  (`addentry.nim` ~line 109–114). Post-P2.1, a derivation/guard rejection must emit a **distinct
  non-zero exit code** + a structured stderr line (`reject: namespace-underivable signed_by=…`)
  **and** an `alerts.kdl` entry, so the GH Actions log shows *why* a publish was refused and the
  refusal is auditable in-repo. The freeze-window rejections (P1.4 guard) use the same signal.
- **Drop `--namespace` everywhere (R1 breadth):** remove the flag from `addentry.nim`; remove the
  `--namespace=…` argument from the `commit-entry.yaml` add-entry step (≈ line 122 — a stale flag
  there fails the binary with `unknown option`); remove the `namespace` `workflow_dispatch` **input**
  (≈ line 32) so manual dispatch no longer shows a dead field. Store the **extracted** SAN as
  `signed_by` (not the input prefix).
- **Org-rename consequence (corrected — R1 depth, critical; the prior text was wrong).** A new
  version whose anchor derives a *different* namespace (org rename / repo transfer) is **not**
  rejected by the P1.1 guard — it derives a new namespace, the `(namespace,name)` lookup misses, and
  a **new** package entry is created while the old one persists stale. Handling this continuity is
  exactly #36 (deferred). User-facing note in `docs/identity-and-provenance.md` (milpa repo, owned
  by P0.5) must say "creates a new entry; the old one goes stale; #36 is the fix" — **not**
  "rejected".

**Gate A (Nim suite):** full SAN→`github.com/<owner>`; underivable `signed_by`→hard reject;
`--namespace` removed (binary errors if passed); non-`host/org` namespace reaching `cmdAddEntry`→
rejected (the promoted guard); extracted SAN stored as `signed_by`.
**Gate B (workflow, manual — *no offline path*; R2 feasibility).** `commit-entry.yaml` no longer
passes `--namespace`; `workflow_dispatch` `namespace` input gone; a publish extracts a real SAN and
lands the derived `host/org` namespace. **There is no "replayed fixture" for Gate B** — a real
`cosign verify … --output json` response requires a genuine Fulcio cert + Rekor entry, which cannot
be faked offline. The Nim unit test (Gate A) — driven by a fixture JSON mirroring the v2.4.0 output
shape — is the **automatable** gate; Gate B is a **one-time manual smoke**: trigger the updated
workflow on a branch (or a real signed publish) and confirm the derived namespace. The
`jq` SAN-extraction path (flagged above) is verified as part of this manual step, not a unit test.
Do not block the slice waiting for offline workflow-test infra that does not exist.

#### P2.2 — delete the Go dispatch `deriveNamespace`  *(tianguis, Go)*
`dispatch/handler.go:157` is a **fourth** `deriveNamespace` (emits org-only) feeding the same
`commit-entry.yaml` workflow. Once P2.1 derives namespace from the verified SAN inside
`addentry`, the workflow's `namespace` input is redundant. **Delete** the Go `deriveNamespace`,
drop the `"namespace"` key from the dispatch inputs map (`handler.go:115`), and fix the one test
that references it (`handler_test.go:526` hardcodes `"namespace": "coreyleavitt"`). Note:
`function_test.go` has **zero** namespace references (verified) — do not chase it. **The Go impl is
not merely redundant — it is semantically *wrong* relative to the post-P0.3 SSOT (R2 breadth):** it
emits **org-only** (`handler.go:162` returns `tail[:i]`, e.g. `coreyleavitt`), never the `host/org`
the SSOT requires (`github.com/coreyleavitt`). So P2.2 is a *correctness* fix (deleting a
divergent fourth derivation), not just dead-code cleanup; frame it that way. Net: four identity
impls → three (Nim, Python-but-see-below, future-Rust), all governed by `derive-namespace.json`.
*(Scope note: milpa has **no** Python `deriveNamespace` — `parse_index` reads the `namespace` field
verbatim from the index; Python is not a `deriveNamespace` conformance consumer. The governed impls
are Nim today + Rust later.)*

#### P2.3 — conformance corpus + normative `signed_by` format  *(tianguis docs/fixtures; edit-only unless a corpus runner exercises the JSON)*
Add OIDC SAN cases to `spec/fixtures/derive-namespace.json` (verified: currently 40 cases, **all**
git/SSH clone URLs — zero OIDC SAN inputs, so this is real fixture work, not a one-liner). Concrete
cases: (a) a full canonical GH Actions SAN
`https://github.com/owner/repo/.github/workflows/publish.yaml@refs/heads/main` → `github.com/owner`
(the repo path, workflow suffix, and `@<ref>` fragment are discarded; host/org kept);
(c) malformed/empty SAN → derivation error (`derrUnparseable`) — guards the empty-SAN
silent-hard-reject path flagged in P2.1.

**No "non-github → error" case.** An earlier draft proposed *(b) a non-`github.com` SAN → derivation
error* to "bound the GH-Actions-OIDC-only assumption." That was a **spec error**, dropped during
implementation (validated against the live `deriveNamespace`): derivation is **forge-agnostic by
design** — `https://example.com/owner/repo` → `example.com/owner` via the generic fallback; it does
NOT gate on `github.com`. The github-only-ness is an entirely separate, *temporary* **OIDC-issuer
trust scope** enforced at the cosign-verify step in `commit-entry.yaml`
(`--certificate-oidc-issuer="https://token.actions.githubusercontent.com"`, expandable as other
issuers are validated), orthogonal to namespace derivation. Cementing "non-github → reject" into the
`deriveNamespace` conformance oracle would wrongly fuse the two; identity derivation answers "whose
namespace?", the verify gate answers "is this signer's issuer trusted?".

Specify the normative `signed_by` format per attestation kind in `index-format.md`: author-signed =
a parseable identity SAN URL from a **trusted keyless-OIDC issuer** (Fulcio cert + Rekor inclusion,
cosign-verified at ingest), load-bearing for `deriveNamespace`; the canonical GH Actions form is
`https://github.com/<org>/<repo>/.github/workflows/<wf>.yaml@<ref>`. milpa-vendored = freeform
provenance string, **not** an identity anchor (vendor-en-absentia uses the git `provenance.url`).
Note the forge-agnostic-derivation / issuer-trust-gate separation explicitly so it is not re-conflated.

### PHASE 3 — resolution core to the bar (milpa)

#### P3.1 — proper semver model  *(milpa; three /tdd sub-slices, each suite-green)*
Replacing `Version = tuple[int,int,int]` is a **wide type swap**, not one slice (R1 feasibility,
critical). The type flows through `solver.py`, `tianguis_client.py` (`parse_version` is the
`parse_index` sort key + `resolve_named`'s filter), `resolver.py` (`_normalize_constraint`,
`_URL_DEP_VERSION` sentinel, `_Candidate.version`), `lockfile.py` (`_format_version`), and every
`test_versionset_properties.py` invariant. **All of these are in-scope and must be named in each
sub-slice.** This is the single biggest correctness gap vs the PhD bar — split so the suite stays
green at every step:

**P3.1a — atomic type swap (behavior-preserving).** Introduce the real semver `Version` type and a
`parse_version` that **still parses-and-drops** prereleases/build-metadata exactly as today, so all
existing tests stay green. **Implementation vehicle = a `NamedTuple` (R2 feasibility, high).** Make
the new `Version` a `NamedTuple` (e.g. `(major, minor, patch, pre, build)` with `pre`/`build` empty
in P3.1a), **not** a plain `@dataclass`: a `NamedTuple` preserves the existing `v[0]`/`v[1]`/`v[2]`
index access and tuple comparison that call sites and the `_URL_DEP_VERSION = (0,0,1)` sentinel rely
on, so the swap is a genuine drop-in and the suite stays green *without* touching every accessor.
This keeps P3.1a a single atomic slice rather than forcing a second sub-split for accessor renames.
Update simultaneously: `VersionSet` interval boundaries (`Version|None` element type),
`_URL_DEP_VERSION` sentinel (a valid instance of the new type — trivially, as a NamedTuple of the
same leading shape), `tianguis_client.parse_index` sort key + `resolve_named` filter,
**`lockfile._format_version`** (today hardcoded `f"{v[0]}.{v[1]}.{v[2]}"` — must format the new type;
until P3.1b it emits the release triple, but the formatter is now type-correct), **and every
Hypothesis strategy that builds versions as raw 3-tuples** in `test_versionset_properties.py` (R2
feasibility — these `st.tuples(...)` / `builds` strategies must emit the new type in the *same*
slice, else the property suite type-mismatches the moment `VersionSet` expects the new element).

**`VersionSet.eq()` boundary is explicitly *frozen* at `(M, m, p+1)` in P3.1a (R2 depth, high).**
`eq(v)` today is the half-open point `[v, (v[0],v[1],v[2]+1))` (`solver.py:124–127`). P3.1a
**retains** this `patch+1` next-point boundary — it does **not** introduce any prerelease-aware
successor. The implementer must resist "fixing" `eq()` for the new type here: doing so prematurely
(before the prerelease total order exists) would change the lattice algebra with no test to anchor
it. The `eq()` boundary is **revisited in P3.1b** (see the soundness fix there), which is the slice
that introduces the ordering that makes the old boundary unsound. Decide+document the lockfile
**version-field policy**: it is display-only; `verify_against_graph` compares `identity`/
`content_hash`, not the version string (so a future prerelease in the field is non-load-bearing for
verification — but must still round-trip losslessly once P3.1b lands).

**P3.1b — prerelease ordering + opt-in inclusion.** Full semver-2.0 prerelease ordering
(`1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta < 1.0.0`; numeric vs alphanumeric identifier rules) and
build-metadata parsed-and-ignored-for-ordering. **Opt-in mechanism (R1 design+depth — nail it down,
cargo-style):** encode the prerelease as part of the `Version`'s total order such that any
prerelease of `(M,m,p)` sorts **below** the release `(M,m,p)`. Then "a constraint `>=1.0.0` does not
admit `1.0.0-rc.1`" falls out of the ordering — `1.0.0-rc.1 < 1.0.0` is below the floor — with **no
predicate parameter on `VersionSet.contains()`**. A constraint with an explicit prerelease floor
(`>=1.0.0-alpha`) admits prereleases at/above it; `>1.0.0-rc.1` admits everything strictly above
that rc (later rc's of `1.0.0`, the `1.0.0` release, and up) — also a pure consequence of the order,
no predicate. `lockfile._format_version` now emits the full prerelease string and **round-trips
losslessly** (regression test). This is exactly cargo's model (single total-order `Version`,
prerelease below release, opt-in via the constraint floor); PEP 440's separate `pre` specifier flag
is the legacy wart cargo avoided — we follow cargo.

**CRITICAL — `VersionSet.eq(v)` must become a true singleton, NOT `[v, (M,m,p+1))` (R2 depth,
critical; verified against `solver.py:124–127`).** The total order alone is **not** sufficient for
lattice soundness. `eq(v)` is the half-open interval `[v, v_next)` with `v_next = (M,m,p+1)`, and
**every solver decision plus every `==` constraint goes through it** (`add_decision` →
`VersionSet.eq(version)`). Under the new ordering `1.0.0 < 1.0.1-rc.1 < 1.0.1`, so the interval
`[1.0.0, 1.0.1)` now **contains `1.0.1-rc.1`** — a *decision* to use `1.0.0` would match a *different
version* `1.0.1-rc.1`, and the constraint lattice becomes unsound (a decision is no longer a
singleton set). **Fix:** P3.1b must make `eq(v)` represent the genuine singleton `{v}`. Two
acceptable shapes (implementer's choice — both sound):
  - (a) extend the interval domain to support **closed points** (a `[v, v]` closed-closed interval
    kind) so `eq(v)` is `{v}` structurally; or
  - (b) keep half-open intervals but compute `v_next` as the **immediate successor of `v` in the
    version domain** — for a release `(M,m,p)` that is the *smallest possible prerelease of the next
    patch*, `(M,m,p+1)-0` (which sorts above `(M,m,p)` and below every real `(M,m,p+1)` prerelease),
    and for a prerelease input the next-identifier successor. (a) is cleaner; (b) preserves the pure
    half-open representation. Either way, **the lattice change is a named P3.1b deliverable** with
    its own property test: `eq(v).contains(w) ⟺ w == v` over generated `(release, prerelease)`
    pairs, *including* a `v=1.0.0`, `w=1.0.1-rc.1` case that the current `[v,v_next)` wrongly admits.
This keeps the `VersionSet` lattice sound; the total order is necessary but the singleton fix is what
makes `eq` correct under it.

**P3.1c — operator set.** Add `~` (tilde), `^` (caret), `!=`, and bare `=` (nimble's
`requires "x = 1.0"`) to `_parse_clause` (**`solver.py`**); add `||`/`|` disjunction to
`from_constraint` (currently `&`-only). **Fact correction (R1 depth):** OR constraints today do
**not** silently drop — `_parse_clause` *raises `ValueError`*, aborting resolution for any package
whose `.nimble` declares a disjunctive require (the only silent-drop path is the unrelated
`_version_satisfies` bare-except). Also fix **`_normalize_constraint` (`resolver.py`)**: it strips
`~`/`^`/`!=` via regex today but must **pass them through** to the now-capable `_parse_clause`
(esp. `!=`, currently stripped to nothing). Name both files in the slice.

**Behaviors (across a/b/c):** type swap leaves suite green; prerelease ordering table;
build-metadata parse+ignore; `_format_version` lossless round-trip of a prerelease; each new
operator resolves; disjunctive constraint keeps both arms (and no longer raises); `1.0.0-rc.1`
selectable iff the constraint admits it.

#### P3.2 — multi-version named-dep provider  *(milpa, /tdd; needs P1.2 + P3.1c)*
Today `tianguis_client.resolve_named` returns ONE pre-chosen (maxver) `IndexVersion`, so the
solver has a single candidate per named package — strategy is dead and backtracking is impossible
for named deps (the #97 review's "CORR-1" — refuted as a *swap* regression but real as a
*pre-existing* limitation). Surface **all** satisfying `IndexVersion`s; the resolver materializes
them as candidates so the solver can choose and backtrack. Builds on P1.2's tuple-keyed parse.

**This is a provider-contract change, not an additive tweak (R1 design+feasibility).** Name the
blast radius: `resolve_named`'s return type goes from one `IndexVersion` to `list[IndexVersion]`;
`_process_named` (`resolver.py`) stops materializing a single `_Candidate` and feeds the candidate
*set* into the provider the solver consumes (today there is only `_MaterializedProvider` — there is
no `_NamedDepProvider`; R2 design — do not imply one already exists). Settle the provider contract
here — P3.3 then rides it with no further structural change.

**The real shape is a BFS re-architecture: enumerate-then-solve, not fetch-on-encounter (R2
design+feasibility, high — this is bigger than "a return-type change").** Today `_process_named` is a
BFS worker that **fetches immediately** — `resolve_named` + `fetcher.fetch_any` + nimble-parse all
happen in one call, producing one fully-materialized `_Candidate` (with `sha`, `identity`, and
`dep_terms` from the parsed nimble). You **cannot** add N *un-fetched* candidates to the provider:
the solver needs `provider.dependencies(package, version)`, which requires that version's nimble to
have been fetched + parsed. So multi-version named deps force a **two-phase** model. **Decision
(cargo/npm-standard, chosen — not a fork): enumerate-then-solve with a transitive fixpoint.**
  - **Phase A (enumerate, no fetch):** from the tuple-keyed index (P1.2), register *lightweight
    version stubs* (the satisfying `IndexVersion`s as metadata: version + provenance, no fetch) into
    the provider as the candidate set.
  - **Phase B (fetch the winner):** when the solver selects a version, fetch + nimble-parse **only
    that** version; its transitives enter the graph late. Because late transitives can introduce new
    named deps not yet in the constraint set, Phase A/B iterate to a **fixpoint** (re-enumerate for
    any newly-discovered dep, re-solve) — the standard cargo/npm resolve loop.
  - Rejected alternative — **fetch-all-candidates** (call `_process_named` N times, fetch all N
    before solving): keeps the current architecture but hits the network N× per named dep and fetches
    versions the solver will never pick. Wasteful; not best-in-class. We do **not** take it.
This makes P3.2 a real structural slice (index-lookup phase separated from fetch phase + the fixpoint
loop), and the TDD slices must reflect that — not a one-line return-type edit. P3.3 then rides the
settled Phase-A/B provider contract.

**`_deps/` + nim.cfg semantics (R1 breadth).** "Multi-version candidate set" is a *solver-time*
notion; PubGrub still selects exactly **one** version per package, so only one `_deps/<name>` dir is
ever fetched and `nimcfg.py` (keyed on bare `name`) is unaffected. State this explicitly so
"multi-version" isn't read as two on-disk copies.

**Multi-constraint boundary (R1 depth — state it, don't fix here).** The BFS dedups named deps by
name (`seen_named`), so the constraint used to select the candidate set is the **first encounter's**
constraint. For a diamond where two consumers put *different* floors on the same named dep, P3.2's
candidate set can be incomplete — this is **milpa #100** (collect-all-constraints-before-resolving),
which must land before P3.2's backtracking is sound for multi-constraint diamonds. P3.2 fully fixes
the single-constraint case; #100 is the documented prerequisite for the multi-constraint case (not a
P3.2 regression — a pre-existing BFS limitation). Record #100 in §Deferred.

**Behaviors:** a named dep with N satisfying index versions yields N candidates; a single-constraint
conflict forces the solver to try a lower version; ambiguous bare name still raises
`TNG-AMBIGUOUS-NAME`.

#### P3.3 — strategy + backtracking for named deps  *(milpa, /tdd; needs P3.2)*
With a real candidate set, `Strategy` (MAXVER/MINVER/SEMVER) applies to named deps via the same
`_pick_version` path as URL deps (it's currently dead for them). **Likely a thin slice (R1
feasibility):** the `strategy` parameter already flows `resolve()` → `_decide` → `_pick_version`,
so once P3.2 populates the candidate set this is mostly *validation* that the existing wiring
selects correctly for named deps — possibly with no new selection code. Keep it a distinct slice
for the test coverage; it may collapse to "confirm + pin". **Watch (R1 design):** the SEMVER
strategy's same-major filter must compose with P3.1b's prerelease opt-in — a `>=1.0.0` constraint
must not let `_pick_semver` surface a `1.0.0-rc` that opt-in already excluded; add a test that pins
this interaction. **Behaviors:** MINVER/SEMVER through the full `resolve()` stack pick the expected
named-dep version; a diamond conflict over a named dep backtracks to a compatible version; SEMVER +
prerelease opt-in pick the expected non-prerelease.

#### P3.4 — PubGrub cause-chain narration  *(milpa, /tdd; SEQUENTIAL after P3.3, same file)*
PubGrub's headline feature — the reason to use it over generic SAT — is human-readable derivation
proofs. `_format_conflict_chain` today prints flat raw term-sets. Produce:
*"Because foo ≥1.2 depends on bar <2.0 and baz ≥2.0 depends on bar ≥2.0, foo ≥1.2 is incompatible
with baz ≥2.0."*

**Algorithm — corrected twice (R1 then R2 depth+design).** This is **not** a pointer walk.
`Assignment.cause` is `Incompatibility | None` (one level up) but `Incompatibility.cause` is a
**structured `str` tag** (e.g. `"dependency:foo@1.2.0"`, `"root"`, `"no-versions-of-bar"`) — there
is no `Incompatibility→Incompatibility` link to dereference. **R2 correction — index by the term's
package, NOT by the cause tag.** A reverse index keyed on the *cause tag* (`{cause_tag →
Incompatibility}`) answers "which package's *decision* produced this incompat" — the **wrong**
question. To render "Because foo ≥1.2 depends on bar <2.0 **and** baz ≥2.0 depends on bar ≥2.0, bar
has no version", you need the incompatibilities that *constrain bar* — i.e. those whose **terms**
contain `bar`. So build the index **`{package_name → list[Incompatibility]}` keyed on each package
appearing in an incompat's `terms`** (not its cause). For each package in the conflict, look it up,
filter to `cause` starting with `dependency:`, and compose the sentence from those antecedents'
terms. The current single-level-backtrack solver surfaces dependency-constraint incompatibilities
directly (cause = `dependency:…`), so the antecedents are present in `incompats`. *(A typed
`cause: str | tuple[Incompatibility, Incompatibility]` would only be needed for full
conflict-driven learning — that's P3.5/#28, deferred; do not add it here.)*

**Return a structured `ConflictChain`, not a flat string (R2 design+depth — separates derivation
from rendering).** `_format_conflict_chain` today returns a `str` (`solver.py:675`), embedded
directly in `SolverError`. The RFC's own requirement — "tests assert *structural* message quality,
not substring presence" — **cannot be met against a flat string** without exactly the brittle
substring matching it forbids. The PubGrub payoff is a *structured* derivation that can be rendered
multiple ways (prose, multi-line CLI, future JSON/IDE). So:
  - `_format_conflict_chain` (rename: `build_conflict_chain`) returns a `ConflictChain` dataclass —
    an ordered list of `ConflictStep` (each: the consequent package/version + its antecedent terms),
    not a string.
  - `SolverError` **carries the `ConflictChain`** (structured), not just a rendered string. Tests
    assert on the chain's fields (specific packages/versions, antecedent structure) — real
    structural assertions, no substring hacks.
  - A separate `render_conflict_chain(chain) -> str` produces the multi-line "Because…and…, …" prose.
  - **CLI display (R1 breadth):** `cli.py:_resolve_or_error` (today `f"resolution failed: {e}"`)
    calls `render_conflict_chain` and prints it **line-wise, indented**, so the derivation reads as a
    proof, not one wrapped line. The structural guarantee is thus **both** test-internal (on the
    `ConflictChain`) **and** CLI-rendered.

**Behaviors:** a 2-level diamond conflict produces a `ConflictChain` naming the specific
packages/versions with the correct antecedents; tests assert on the **chain structure** (specific
packages + the "because" antecedent set), not substring presence; `render_conflict_chain` emits the
English "because…and…, …" form; the CLI prints it multi-line. This is the differentiator
`comparison-vs-nimble-atlas.md` claims — P3.4 makes the claim true.

**Closing doc update (R2 breadth — close the loop P0.2 opened).** P0.2 moved prerelease opt-in,
build metadata, caret/tilde, and proof-certificate narration to *planned (Phase 3)*. As the final
step of P3.4 (the last Phase-3 slice), **flip those entries in `docs/comparison-vs-nimble-atlas.md`
from "planned" to "built"** — otherwise the doc corrected in P0.2 stays permanently understated once
the features ship. (One-line deliverable; bundle into P3.4's commit.)

#### Deferred (recorded, not silently dropped)
- **P3.5 — conflict-driven incompatibility learning + multi-level backjumping** (milpa #28).
  *Performance*, not correctness — the solver terminates correctly today (one-level backtrack +
  single-version exclusion), just with more backtracks than optimal. Defer to #28; not on the
  best-in-class-*correctness* critical path. Narration (P3.4) is the high-value PubGrub payoff and
  is in-scope; learning is the perf payoff and can follow.
- **#37 gitlab nested groups** — 0 in the live index; additive/future.
- **#36 cross-identity unification after rename** — the general alias/supersede mechanism stays
  out of scope; P1.6 is a one-off hard-remove, not the general mechanism. **This is also where the
  org-rename "new stale entry" problem (corrected in P1.1/P2.1) is handled** — P1.1's guard does
  *not* catch renames.
- **milpa #100 — collect-all-constraints-before-resolving.** Prerequisite for P3.2's backtracking
  to be sound on multi-constraint diamonds (different floors on the same named dep). P3.2 fixes the
  single-constraint case; #100 the multi-constraint case.
- **milpa #103 — consumer-side index attestation.** A new trust subsystem (verify the migrated
  index's signature/Rekor attestation at resolve time) with its own design forks; **P1.4's commit
  is the trust anchor it will bind to.** Own RFC.
- **Cross-path git↔OIDC namespace-agreement check** (was `checkOidcGitAgreement`, deleted in P0.4)
  — re-introduce only when a single version can carry *both* a git provenance and an OIDC SAN.
  Follow-on issue filed (P0.4); distinct from #36.
- **Transitive `LocalDep`/`TarballDep`/`MemberDep` in milpa.kdl** and profile-aware transitive
  filtering — pre-existing milpa scope-outs, untouched here.
- **Lockfile `namespace` field (R2 breadth — settled position, no slice).** `LockedDep`
  (`lockfile.py:133–155`) keys deps by **bare name**, no `namespace`. This stays so: ambiguity is a
  *resolution-time* concern (P1.2 raises `TNG-AMBIGUOUS-NAME` before an ambiguous name ever reaches
  a lockfile), and after P1.6 only one `nimkdl` survives, so bare-name re-resolution is
  unambiguous. `milpa verify` is content-hash/provenance based, not name-resolution based, so it
  needs no namespace. A future lockfile-format bump *may* record `namespace` for fully-explicit
  disambiguation, but it is not required by this RFC and is deferred until manifest-`namespace=`
  / #100 land — recorded here so the silence is a decision, not an omission.

---

## 6. Open forks (for architect / Corey)

All identity decisions settled (carried from the twice-reviewed identity-completion RFC):
derive-all; namespace from the per-version attestation anchor (no fallback); `parse_index` now;
hard-remove the stale entry; **delete `checkOidcGitAgreement`** (resolved — P0.4; follow-on
tianguis #39); **#38 folded in, not split out** (this RFC). Resolver-core decisions: semver model
is the foundation; narration in, backjumping deferred to #28.

**Architect rounds 1+2 — both complete; no escalations.** Each round ran four lenses
(depth/breadth/design/feasibility), all findings source-verified against both repos; every
clear-best fix applied directly. The fork test resolved every judgment call with a recommendation,
so nothing reaches Corey. Carried glances from round 1 still stand (P1.1 guard is defense-in-depth
not rename-handling, #36 owns rename; existing milpa.lock consumers re-resolve bare names; the
window-closing guard lives in P1.4).

**Three round-2 items worth a glance (resolved, not forks):**
1. **`VersionSet.eq()` was unsound under the new prerelease order (the critical find).** `eq(v)` is
   the half-open `[v, (M,m,p+1))`; once `1.0.0 < 1.0.1-rc < 1.0.1`, that interval wrongly contains
   `1.0.1-rc` — and *every* decision + `==` goes through `eq()`. P3.1b now makes `eq()` a true
   singleton (closed point or domain-successor `v_next`), with a property test
   `eq(v).contains(w) ⟺ w==v`. The total order was necessary but not sufficient; this closes it.
2. **Intentional author-publish freeze in the P1.4→P2.1 window.** The coarse `host/org` guard + the
   org-only Go dispatch mean every author publish via dispatch is rejected until P2.1 derives from
   the verified SAN. Reframed as the **correct fail-closed posture** (the only pre-P2.1 namespace
   source is untrusted input — the #38 hole). Vendored publishing is unaffected; sequence P2.1
   promptly; document the freeze in the P1.4 runbook.
3. **P3.2 is a BFS re-architecture, not a return-type change.** Multi-version named deps force
   enumerate-then-solve with a transitive fixpoint (cargo/npm-standard, chosen over wasteful
   fetch-all). The slice scope grew accordingly.

**Round-2 changelog (applied):** §1 added the P1.2-deploy-before-P1.4 CI ordering gate (milpa
integration tests hit live `main`) + the P3.1-can-run-parallel note; §4.2 `MergeOutcome` no longer
bundles `index` (footgun) → `mergeVendored` returns `(index, outcome)`; P1.1 acyclicity + complete
6-file blast radius confirmed; P1.2 `lookup_bare` returns `Package|AmbiguousName` (typed, doesn't
raise) — ages into P3.2/#100; P1.3 gate 5b corrected motivating example (synthetic fixture needed);
P1.4 both-artifacts-atomic regen by `--execute` + migration audit record + author-signed rollback +
test-fixture conversion note + freeze reframe; P2.1 observable rejection signal + Gate B
manual-only (no offline path); P2.2 Go impl is semantically wrong (org-only) not just redundant +
Python-has-no-deriveNamespace note; P2.3 concrete SAN fixture cases + edit-only marker; P0.2/P0.5
edit-only markers; P3.1a NamedTuple vehicle + Hypothesis strategies + frozen `eq()` boundary; P3.1b
**critical `eq()` singleton soundness fix** + `>1.0.0-rc.1` example + cargo-vs-PEP440 note; P3.2
enumerate-then-solve fixpoint architecture (rejected fetch-all); P3.4 structured `ConflictChain`
(not flat string) + index-by-term-package (not cause tag) + closing comparison-doc flip; Deferred
+lockfile-namespace settled position.

**Status:** rounds 1+2 done → **ready for stage 3 (`/tdd`)**. Suggested entry:
`/loop implement the next unimplemented RFC slice from docs/rfc-identity-and-resolution-completion.md
with /tdd, following the standing rules; report one progress line per slice; stop when every slice is
implemented`. Mind the edit-only slices (P0.2/P0.5/P2.3 — no RED state) and the deploy-ordering gate
(P1.2 before P1.4).
