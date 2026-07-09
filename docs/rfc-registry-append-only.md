# RFC: registry append-only invariant & consumer ratchet (Part 1 amendment)

**Status**: Draft — Stage 1 (2026-07-09). Amends `rfc-registry-trust-federation.md`
(Part 1) and `spec/registry-protocol.md`. Tracking issue: **#185**. Part of
the #107 registry-trust umbrella.

## Why this RFC exists

Part 1's whole-index gate verifies that the served `index.kdl` was signed by
the expected identity, recently (`TNG-INDEX-BUNDLE-STALE` bounds the age of the
snapshot). What nothing verifies — anywhere in the stack — is that the new
index is a **valid successor** of the previous one. The vendor-bot re-signs the
*entire history* on every publish, so a compromised or buggy bot can rewrite
any historical entry and produce a perfectly fresh, perfectly valid signed
index:

- swap a published version's `content_hash` (new resolvers trust it; the
  identity gate only protects consumers who already hold a lockfile pin);
- swap a `dep_decl` pin, silently changing a published version's dependency
  edges;
- strip or re-attribute an attestation record (Part 2's R5 stripping hole is
  one instance of this class);
- delete an entry or a whole package (rollback / targeted downgrade: hide
  `1.4.3-security-fix` so constraint resolution selects the vulnerable
  `1.4.2`).

The freshness check cannot see any of this — every one of these attacks ships
in a **brand-new, maximally-fresh** index. The structural fact is: *the
registry's history is mutable, and every signature launders it*.

Prior art names the fix. Go's checksum database (sum.golang.org) is built on
the principle that a registry must be **verifiably append-only**; TUF dedicates
two roles (snapshot, timestamp) to rollback protection; git's object model
makes history rewriting detectable by construction. milpa can have the
property nearly for free, because the ingredients already exist:

- the four-state index cache already retains the previous verified index on
  disk (`index_cache.py` / `index_cache.rs`);
- every signed index state is already Rekor-logged (Part 1 §3.4), so the full
  chain of published states is globally reconstructable by any auditor.

What is missing is (1) a normative statement of *what may change between
successive index states*, and (2) a consumer-side check that enforces it at
refresh time. That is this RFC.

## Threat model

**Stops (detection, not prevention):**

- Vendor-bot key/identity compromise used to rewrite history — any mutation of
  a published entry alarms every consumer with a baseline on next refresh.
- Registry-infrastructure compromise serving a mutated-but-freshly-signed
  index (same detection path; the signature being valid is exactly the point).
- Accidental bot regressions — an index-generator bug that mutates
  `content_hash`es or `dep_decl` pins of already-published versions surfaces
  as a loud cross-consumer alarm instead of silent corruption.
- Targeted rollback: removing versions/packages to steer resolution to older
  code.

**Does not stop (named plainly):**

- Malicious content in *new* entries — the bot vouching for bad new packages
  is Part 2's (attestation) and Part 3's (owner registry) territory.
- First-contact forgery: the ratchet is TOFU — a consumer's *first* fetch of
  an index has no baseline. The Rekor chain covers this globally (an auditor
  can verify append-only-ness across all published states), but not
  consumer-locally at first contact.
- Split-view attacks (serving different histories to different consumers,
  each internally append-only). Each victim's ratchet is self-consistent;
  detection requires cross-consumer comparison — the Rekor-logged chain makes
  the split *auditable* (two signed states with the same freshness window and
  divergent content), but no consumer-side check in this RFC catches it.
  Recorded as a residual; gossip/witness protocols are out of scope.

## Design

### 1. The monotone-entry invariant (normative field lattice)

A published `(namespace, name, version)` entry is not a mutable record. Its
fields fall into three normative classes:

| Class | Fields | Legal transitions |
|---|---|---|
| **Frozen** | `content_hash`; `dep_decl` pin; `published_at`; `rekor` block; the *existence* of the version node; the *existence* of the package node | none — any change or disappearance is a violation |
| **Monotone (upgrade-only)** | attestation record (`attestation` + `signed_by`, Part 2's `EntryAttestation` incl. its `bundle` pin) | `None → MilpaVendored`, `None → AuthorSigned(s)`, `MilpaVendored → AuthorSigned(s)` (backfill/upgrade). Illegal: any `→ None` (stripping), `AuthorSigned(s₁) → AuthorSigned(s₂)` (re-attribution), `AuthorSigned → MilpaVendored` (downgrade) |
| **Append-only** | provenance **set** | records may be added (mirrors, #91); removal is a violation. Preference **order** is advisory-mutable (reordering is legal — the identity gate makes every provenance of an entry byte-equivalent, `registry-protocol.md §3.3`, so order affects availability, not identity) |
| **Advisory-mutable (outside the lattice)** | `yanked` (§5, new), package-level descriptive fields | both directions legal |

Two derived rules, stated explicitly:

- **No in-band correction path exists.** The sanctioned fix for a
  mis-published entry is: yank it (§5) and publish a corrected *new version*.
  This is the Go-sumdb position, chosen over the crates.io admin-patch
  position: an extraction bug that produced a wrong `dep_decl` is a mutation
  of resolution-relevant history like any other, and a "trusted correction"
  path is indistinguishable, consumer-side, from the attack this RFC exists to
  detect.
- **A registry migration event** (catastrophic operator-side rewrite) is
  out-of-band by definition: consumers WILL alarm, and each must explicitly
  reset its baseline (§2) to accept the new history. That friction is the
  feature — history rewrites must never be silently absorbable.

The invariant is **semantic, not byte-level**: it constrains the parsed entry
map, never the serialization. Re-serializing, re-ordering, or re-formatting
the document is always legal.

### 2. The consumer ratchet

**Where:** the index-acquisition State 2 path (network fetch succeeded),
**after** Layer-1 bundle verification and **before** the atomic cache write —
the previous state is still on disk, and only *verified* successor candidates
are ever ratchet-checked.

**Baseline:** a new cache sidecar, `<key>.index.kdl.baseline` — the last index
that passed the ratchet cleanly. The baseline advances **only on a clean
diff**. It is deliberately *not* the served cache file:

> Under `warn`, the served cache advances to the new index (warn is
> observability, matching Part 1 semantics) — but if the *comparison base*
> also advanced, a single warning would be the attack's entire cost, and the
> mutated history would become the new baseline (ratchet poisoning:
> alarm-once, then self-heal into the attacker's history). With a sticky
> baseline, every subsequent refresh re-alarms until the mutation is reverted
> upstream or the operator explicitly resets.

**Check:** parse baseline and candidate (the existing `parse_index`; no new
parser), diff the entry maps, evaluate the §1 lattice per entry. All
violations are collected; the raised/warned diagnostic reports the first in
canonical order (namespace, name, version) and carries the full list in the
message.

**Enforcement rides the `index-trust` axis** — no fourth policy axis. The
ratchet checks index-document *history* integrity; Layer 1 checks
index-document *state* integrity; same object, same posture, same knob:

- `off` — no ratchet, no baseline maintenance.
- `warn` — warn (every refresh, per stickiness above); serve the new index;
  baseline does **not** advance.
- `strict` — hard fail; the new index is **not** written to the cache
  (fail closed; the cached previous index remains, but the resolve that
  triggered the refresh fails with the ratchet slug — silently serving the
  old index would mask an active attack).

**TOFU:** no baseline present → write the (verified) new index as baseline,
no check. Baselines are per-URL, keyed like every other cache artifact.
A changed `MILPA_INDEX_URL` is a fresh TOFU, by construction.

**Pure cache reads and offline fallback** (States 1 and 3) never run the
ratchet — there is no new state to compare. `milpa verify`'s offline
`reverify_cached_index` is likewise out of scope (single-state, nothing to
diff).

**Baseline reset:** clearing the index cache (existing `clean` surface) resets
the baseline (TOFU on next fetch). No dedicated reset verb in v1 — a
deliberate friction floor for migration events; a dedicated
`milpa index accept` surface is deferred until a real migration event proves
the need (see open questions).

### 3. Error taxonomy

Two new slugs, landing with their raise sites (bijection discipline):

| Slug | Condition |
|---|---|
| `TNG-INDEX-ROLLBACK` | A package or version present in the baseline is absent from the candidate index (disappearance — the rollback/deletion class). |
| `TNG-ENTRY-MUTATED` | An entry present in both violates the §1 field lattice (frozen-field change, monotone downgrade, provenance removal). |

Both are policy-gated by `index-trust` (§2). When a diff contains both
classes, `TNG-INDEX-ROLLBACK` wins (disappearance is the blunter, more
urgent signal; precedence stated so both impls converge — the S5.5 lesson).

### 4. Publication watermark (dividend for Part 2)

A clean baseline ratcheted at time T is a *watermark*: any entry not present
in it was necessarily published after T. Therefore a **new** entry claiming
`published_at < T(baseline)` is backdated — the lie is consumer-detectable
without trusting the bot. This is what makes Part 2's epoch-based `strict`
(open question 2 there, now resolved) robust: a compromised bot cannot dodge
the post-epoch attestation mandate by backdating `published_at`. The
enforcement (a `TNG-ENTRY-BACKDATED`-class check) **lands with Part 2's P3**,
where entry-level policy machinery exists; this RFC only guarantees the
baseline semantics that make it possible. Recorded here so the baseline
lifecycle (§2) is not later weakened in a way that breaks it.

### 5. `yanked` — the sanctioned removal story

The invariant makes deletion a violation, so the registry needs an in-band,
lattice-legal way to retire an entry. New optional version-node field:

```
version "1.4.2" {
    content_hash "dag-sha256:…"
    yanked #true
    yank_reason "ships a vulnerable bearssl pin"   // optional
    …
}
```

- **Lattice status:** advisory-mutable — yank and un-yank are both legal
  (cargo precedent; a mistaken yank must be reversible). The entry's frozen
  fields remain frozen while yanked: yank hides nothing and rewrites nothing.
- **Selection semantics:** candidate enumeration excludes yanked versions
  from *new* resolution. The frozen path is untouched (it never consults the
  index), so existing lockfiles keep working — yank steers new selection,
  never breaks reproduction. If every satisfying version is yanked, the
  existing `TNG-NO-SATISFYING-VERSION` fires (the diagnostic message should
  name the yanked-but-excluded candidates).
- **Forward-compat:** an older milpa that predates this field tolerates and
  ignores it (the §3.2 unknown-child discipline) — degraded gracefully to
  pre-yank behavior.

### 6. What this changes in the spec

- `spec/registry-protocol.md` — new **§3.5 Append-only invariant & refresh
  ratchet** (the §1 lattice table, §2 check placement + baseline + TOFU +
  policy wiring, §3 precedence, §4 watermark note); `§3.2` gains `yanked` /
  `yank_reason`; `§5.2` constraint filtering gains the yanked-exclusion
  clause; `§6` index caching gains the baseline sidecar + its lifecycle;
  Appendix A gains the two slugs.
- `spec/errors.md` — `TNG-INDEX-ROLLBACK`, `TNG-ENTRY-MUTATED` (with raise
  sites, per slice sequencing).
- Part 1 RFC — a short amendment note pointing here (the "what Layer 1 does
  not check" §4 caveat gains its answer).

## Conformance strategy

The mock-verifier fixture tier (338–365 precedent) extends naturally — these
fixtures need a **seeded baseline** plus a served index, which is the same
cache-seeding shape the existing index-trust fixtures already use:

- legal transitions pass silently: pure append (new version, new package),
  provenance append, provenance reorder, attestation upgrade
  (None→vendored, None→author, vendored→author), yank, un-yank,
  re-serialization/reordering of the document;
- each violation class, × {warn, strict}: `content_hash` swap, `dep_decl`
  swap, `published_at` change, version disappearance, package disappearance,
  attestation strip, signer re-attribution, attestation downgrade, provenance
  removal;
- rollback-beats-mutated precedence (one fixture with both);
- TOFU (no baseline → pass + baseline written);
- warn stickiness: two successive refreshes over an unreverted mutation both
  warn (baseline did not advance);
- strict fail-closed: cache file unchanged after the failed refresh;
- yank selection: yanked version excluded from enumeration; all-yanked →
  `TNG-NO-SATISFYING-VERSION`; frozen path unaffected.

Differential: both impls produce identical slugs across the matrix (S5.5
precedent).

## Prerequisites

1. **Part 1 shipped** — ✅ (#103).
2. **Nothing cross-repo.** The ratchet is purely consumer-side; tianguis
   already satisfies the invariant vacuously (it appends). The *yank* field
   needs tianguis emission eventually, but the milpa-side parse + selection
   semantics are testable from fixtures alone.

## Open questions

1. **Baseline reset surface.** Position taken: cache-clean is the v1 reset;
   a dedicated `milpa index accept` verb is deferred until a real migration
   event proves the need. Revisit if the architect rounds find a hole in
   using `clean` (granularity: does `clean` have a cache-only mode that
   doesn't nuke `_deps/`?).
2. **Baseline growth.** The baseline is a full index copy per URL (~the size
   of the cache itself — trivial today). If the index ever grows large, the
   baseline could store the parsed entry map in a compact form instead;
   explicitly a transport/representation question, not a semantics question.
3. **Provenance removal.** Position taken: append-only, no removal — dead
   mirrors are harmless (fetchers fall through in order). The alternative
   (tombstoned removal) adds lattice complexity for an unproven need.

## Slices

- **A1** spec: `registry-protocol.md` §3.5 (lattice + ratchet + precedence +
  watermark note), §3.2 `yanked`/`yank_reason`, §6 baseline sidecar; Part 1
  RFC amendment note. No slugs yet (they land with raise sites).
- **A2** Python: `yanked` parse-to-typed; ratchet check (semantic diff +
  lattice evaluation, canonical-order reporting) wired into the State-2 seam;
  baseline sidecar lifecycle (sticky-advance, TOFU, atomic write ordering);
  policy enforcement via the existing `index-trust` machinery; the two slugs
  in `spec/errors.md` + `errors.py` + Rust `all_codes()` in the same change
  (Rust raise sites follow in A3; use the corpus `DEFERRED` mechanism if the
  window needs it); unit tests for every lattice row.
- **A3** Rust parity: same seam (`index_cache.rs` State 2), same tests; drop
  any A2 `DEFERRED` entries.
- **A4** shared conformance fixtures (the matrix above) + cross-impl
  differential.
- **A5** yank selection semantics: enumeration excludes yanked (both impls),
  `§5.2` spec clause, `TNG-NO-SATISFYING-VERSION` message names yanked
  candidates, fixtures (excluded / all-yanked / frozen-path-unaffected).

## Connections

- **Part 1** (`rfc-registry-trust-federation.md`) — amends: adds the
  successor-validity check Layer 1 lacks. The index signature now means
  "a valid state *and* a valid successor", not just "a valid state".
- **Part 2** (`rfc-per-entry-attestation.md`) — closes the R5
  stripping/rollback residual structurally (stripping is now a lattice
  violation); the §4 watermark underwrites Part 2's epoch-based `strict`
  (its open question 2).
- **Part 3** — the continuity ratchet ("was author-signed, must stay
  author-signed") stops being a separate trust system: it is *already* the §1
  monotone rule; Part 3 shrinks to the owner registry.
- **Prior art** — Go sumdb (append-only transparency), TUF snapshot/timestamp
  (rollback protection), cargo (yank semantics), git (history immutability by
  construction).
