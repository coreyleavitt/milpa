# RFC: registry append-only invariant & consumer ratchet (Part 1 amendment)

**Status**: Draft — Stage 1 (2026-07-09); architect round 1 applied
(2026-07-09). Amends `rfc-registry-trust-federation.md` (Part 1) and
`spec/registry-protocol.md`. Tracking issue: **#185**. Part of the #107
registry-trust umbrella.

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
makes history rewriting detectable by construction. milpa has most of the
ingredients already:

- the four-state index cache already retains the previous verified index on
  disk (`index_cache.py` / `index_cache.rs`);
- every signed index state is already Rekor-logged (Part 1 §3.4), so the full
  chain of published states is globally reconstructable by any auditor.

What is missing is (1) a normative statement of *what may change between
successive index states*, (2) a consumer-side check that enforces it at
refresh time, and (3) a small parse extension — the current parse boundary
deliberately discards several of the fields the invariant constrains
(`published_at`, the attestation record, the `rekor` block are parsed-and-
ignored today, spec §3.2). "Nearly free" is honest about the check, not about
the parse: §7 stages enforcement to match what each slice makes parseable.

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

**Surfaces (visible, not blocked):**

- Yank-state steering — yanking a security fix (downgrade pressure) or
  un-yanking a CVE-yanked version (restore pressure) is *legal* (§5) but
  never silent: every yank-state transition between baseline and candidate
  is reported as a ratchet notice (§3).

**Does not stop (named plainly):**

- Malicious content in *new* entries — the bot vouching for bad new packages
  is Part 2's (attestation) and Part 3's (owner registry) territory.
- First-contact forgery: the ratchet is TOFU — a consumer's *first* fetch of
  an index has no baseline. The Rekor chain covers this globally (an auditor
  can verify append-only-ness across all published states), but not
  consumer-locally at first contact. Auditor tooling that reconstructs the
  chain is tracked in #187 (filed with this round) — until it exists this
  mitigation is unrealized.
- Split-view attacks (serving different histories to different consumers,
  each internally append-only). Each victim's ratchet is self-consistent;
  detection requires cross-consumer comparison — the Rekor-logged chain makes
  the split *auditable* (two signed states with the same freshness window and
  divergent content), but no consumer-side check in this RFC catches it.
  Recorded as a residual (#187); gossip/witness protocols are out of scope.
- Bare-name ambiguity denial: adding a wholly new package under a *new*
  namespace that shares a bare `name` with an existing package is a legal
  append, yet it flips every unqualified consumer of that name into
  `TNG-AMBIGUOUS-NAME` on next resolve (registry-protocol §5.1). An
  availability nuisance reachable through legal appends; qualified deps are
  the existing remedy. Named here for honesty, not blocked.

## Design

### 1. The monotone-entry invariant (dominance over a product order)

**Entry key.** The diff compares entries keyed by
`(namespace, name, raw version string exactly as it appears in the document)`.
Keying on the raw version string means a cosmetic re-spelling
(`"1.4.2"` → `"01.4.2"`) is a disappearance plus an appearance — caught as
rollback, not silently matched. A `namespace` change is likewise a package
disappearance under the old key: `namespace` needs no field class of its own
because it is *inside* the key.

**The invariant, in one sentence.** For every entry key present in the
baseline, the candidate's entry must **dominate** the baseline's entry in the
product partial order over the field classes below; entry *presence* is itself
a component of that product (`absent < present`, and `present → absent` is
never legal), so version/package disappearance is the same dominance failure
as a frozen-field change — not a separate rule.

Each field is tagged with one of four component orders:

| Class (order) | Fields | Legal transitions |
|---|---|---|
| **Frozen** (set-once: `absent < v`; distinct values incomparable) | `content_hash`; `dep_decl` **together with** `dep_decl_schema_version` (they move in lockstep — mutating the schema version alone re-interprets the pin and is a violation); `published_at`; `rekor` block; presence of the version node; presence of the package node | `absent/empty → value` is legal **exactly once** (legacy backfill: an entry with an empty `content_hash` is unresolvable anyway (`TNG-NO-IDENTITY`), so backfilling it is semantically a first publication and the identity gate still guards the bytes; same shape for `dep_decl` rollout). `value → value′` and `value → absent` are violations. |
| **Monotone** (the attestation order) | attestation record (Part 2's `EntryAttestation` incl. its `bundle` pin). **Ownership split**: Part 2 owns the *type*; this RFC owns the *order* over its values. | `None → MilpaVendored`, `None → AuthorSigned(s)`, `MilpaVendored → AuthorSigned(s)` (backfill/upgrade). Illegal: any `→ None` (stripping), `AuthorSigned(s₁) → AuthorSigned(s₂)` (re-attribution), `AuthorSigned → MilpaVendored` (downgrade). `MilpaVendored → MilpaVendored` with a changed `signed_by` (bot workflow identity rotation) is **unconstrained** — stated explicitly; vendored attestation is a bug ratchet, not a security boundary (Part 2 §3). Within an otherwise-unchanged `(kind, signer)`, the record's `bundle` pin MUST be structurally equal — a same-kind `bundle_pin` swap is a violation (payload kind `monotone-repinned`); the pin may change only as part of a legal kind/signer upgrade transition. Scope split with Part 2's stage 1b: `TNG-ENTRY-BUNDLE-PIN-MISMATCH` checks *served bytes* against the current snapshot's pin (acquisition-time transport integrity); this row checks the *pin's history* across snapshots (ratchet-time). Different checks; they cannot collide. |
| **Append-only** (multiset inclusion) | provenance **multiset**, compared by full-field value equality — never by list position | records may be added (mirrors, #91); removal is a violation. In-place mutation of one record's fields (e.g. `commit_sha`) manifests under multiset comparison as removal + addition — caught as removal. Preference **order** is advisory-mutable (reordering is legal — the identity gate makes every provenance of an entry byte-equivalent, `registry-protocol.md §3.3`, so order affects availability, not identity). |
| **Advisory-mutable** (trivial order — everything comparable) | `yanked` / `yanked_at` / `yanked_reason` (§5) — mutable both directions but **every transition is surfaced as a ratchet notice**, never silent; package-level descriptive fields (`upstream`) — mutable and silent | both directions legal |

The dominance framing is not just exposition: both impls implement **one**
generic `dominates(baseline_entry, candidate_entry) → violations` fold over
field/order-kind tags, instead of four hand-coded comparison branches plus
special-cased disappearance rules. Adding a field later means tagging it with
an order kind, not writing a new prose carve-out. (This is the
audit-for-duplication discipline applied prospectively.)

**Root-level fields (outside the entry map).** The entry lattice cannot
classify document-root fields; they get their own two-row table under the
same dominance machinery, keyed by field name:

| Root field | Order | Legal transitions |
|---|---|---|
| `schema_version` | monotone non-decreasing | increase legal (schema evolution); decrease is a violation |
| `attestation-epoch` (Part 2 OQ2) | **set-once** | `absent → E` legal exactly once; any change thereafter is a violation. Set-once, not merely non-decreasing: *raising* the epoch reclassifies every published entry as pre-epoch/legacy and nullifies the attestation mandate while staying technically non-decreasing. |

Root-field violations raise `TNG-INDEX-ROOT-MUTATED` (§3). Ownership follows
the attestation-order rule: this RFC owns root-field orders; the documents
that introduce the fields own their types. Staging: `schema_version` is
parseable today (A2); the `attestation-epoch` row enforces when Part 2's P3
introduces the field.

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
  accept the new history via `milpa index accept` (§2). That friction is the
  feature — history rewrites must never be silently absorbable.

The invariant is **semantic, not byte-level**: it constrains the parsed entry
map, never the serialization. Re-serializing, re-ordering, or re-formatting
the document is always legal.

**Staged enforcement.** The lattice above is complete in the spec from day
one, but two rows constrain fields the current parse boundary discards
(`rekor`, the attestation record — spec §3.2 mandates parsed-and-ignored, and
a pinned regression test asserts `IndexVersion` has no `rekor` attribute).
Enforcement of a row lands with the slice that makes its fields
parse-to-typed: `content_hash` / `dep_decl` / `dep_decl_schema_version` /
presence / provenances are parseable today (A2); `published_at` and the yank
fields gain parse-to-typed in A2 (a deliberate amendment of the §3.2
ignore-clauses); the attestation record and `rekor` rows enforce in A6, after
Part 2's P2 parser change lands (the no-rekor regression pin is inverted
*there*, deliberately, not silently). Fixtures are staged identically (§
Conformance).

### 2. The consumer ratchet

**Where:** on **every code path that persists a network-fetched index** —
the State-2 body of `load_index` *and* the bounded crash-recovery refetch
(`_refetch_with_recovery` / Rust analog). A candidate arriving via crash
recovery is exactly as untrusted as a State-2 fetch; leaving it unratcheted
would make forced cache corruption a smuggling channel. The check runs
**after** Layer-1 bundle verification succeeds and **before any cache
mutation begins — including the bundle-sidecar write**. (The current write
order is bundle-sidecar-first, then index rename; gating only the index
rename would leave a strict-rejected fetch having already overwritten
`.bundle`, a torn state that the next read would misdiagnose as crash
corruption and burn the bounded recovery refetch on.)

**Pure cache reads and offline fallback** (States 1 and 3) never run the
ratchet — there is no new state to compare. `milpa verify`'s offline
`reverify_cached_index` is likewise out of scope (single-state, nothing to
diff).

**Baseline:** a new cache sidecar pair —

- `<key>.index.kdl.baseline` — the last index that passed the ratchet
  cleanly (full copy, atomically written: temp + rename);
- `<key>.index.kdl.baseline.at` — when the baseline was established or last
  advanced (TOFU/advance stamp; the observability answer to "when did this
  consumer first trust this URL");
- `<key>.index.kdl.baseline.reported` — digest of the last-warned violation
  set (see *warn* below).

All three are part of the `<key>.index.kdl*` sidecar family (Part 1 §7.2's
"one glob cleans all" invariant extends to them).

The baseline advances **only on a clean diff**. It is deliberately *not* the
served cache file:

> Under `warn`, the served cache advances to the new index (warn is
> observability, matching Part 1 semantics) — but if the *comparison base*
> also advanced, a single warning would be the attack's entire cost, and the
> mutated history would become the new baseline (ratchet poisoning:
> alarm-once, then self-heal into the attacker's history). With a sticky
> baseline, every subsequent refresh re-alarms until the mutation is reverted
> upstream or the operator explicitly accepts (below).

The serve-base / comparison-base split is a reusable primitive, not one-off
plumbing: implement it as a small generic module (Python `ratchet.py`:
`Baseline[T].check(candidate, dominates) → (verdict, advanced)`), because
Part 3's owner-registry ratchet needs the same sticky-baseline mechanics and
must not re-derive the poisoning fix.

**Write ordering:** ratchet gate → bundle sidecar → index rename → freshness
stamp → baseline (+ `.at`) last. The baseline is written strictly **after**
a successful index write, so it only ever reflects content actually served; a
crash in the window between them costs one redundant re-diff on the next
refresh (clean, safe), whereas the reverse order could advance trust past
content that was never served.

**Baseline corruption is not TOFU.** *Absent* baseline (no file) = legitimate
first contact → TOFU. *Present but unparseable/truncated* baseline = either
an interrupted write or an adversary erasing the trust anchor — the
implementation MUST hard-fail with `TNG-INDEX-BASELINE-CORRUPT` **regardless
of policy** (mirroring Part 1 §7.2's second-mismatch discipline). Silently
degrading a corrupt baseline to TOFU would make "corrupt the baseline file"
a free ratchet reset. Recovery from this state is the explicit verb below.

**Check:** parse baseline and candidate with the shared index parser
(extended per §1's staged-enforcement note), diff the entry maps, evaluate
the §1 dominance per entry. All violations are collected into a structured
list (§3); the diagnostic reports them in canonical order and the baseline
does not advance.

**Enforcement gets its own policy axis: `index-history`** (manifest node) /
`MILPA_INDEX_HISTORY` (env), values `off | warn | strict`, default `warn`.
The draft's "ride `index-trust`, no fourth axis" position does not survive
Part 2's own axis-separation test (Part 2 §4: separate axis when the checks
*fail independently* and are *remediated independently*): a validly-signed,
maximally-fresh index can still be an invalid successor (independent
failure), and the fixes differ entirely (re-fetch a bundle vs revert upstream
/ accept a migration). Two concrete configurations the single-knob design
cannot express, both first-class scenarios of this very RFC:

- an **unsigned private registry** (`index-trust "off"`, Part 1's documented
  escape hatch) still deserves history-integrity detection — the ratchet is
  a pure content diff with no Sigstore dependency;
- a **known migration window** wants `index-trust "strict"` (signatures stay
  hard) with `index-history "warn"` (acknowledged churn), instead of
  dropping document authenticity to warn just to tolerate the migration.

Effective-policy computation, root authority, and the member-declaration
error mirror `index-trust` exactly (§3.4.5/§3.4.7): manifest `off` is
unconditional and manifest-only; otherwise `max(manifest or "warn", env)`;
declared only on the resolution root; a member declaring `index-history`
raises `WS-INDEX-HISTORY-ON-MEMBER` (sibling of `WS-INDEX-TRUST-ON-MEMBER`,
per-axis slug precedent from Part 2). When `index-trust` is `off`, the
ratchet still runs under its own axis — it then compares Layer-1-unverified
documents (weaker, but detects CDN tampering and bot bugs; stated so the
residual is explicit).

Per-policy behavior:

- `off` — no ratchet, no baseline maintenance.
- `warn` — warn; serve the new index; baseline does **not** advance. To
  resist habituation, the warning distinguishes **new** violations from
  **recurring** ones: the violation-set digest is compared against
  `<key>.baseline.reported`; unchanged set → "recurring (first reported
  <date>)", changed set → the delta is called out first. A chronic
  unresolved alarm must not be able to mask a second, later mutation.
- `strict` — hard fail; **no cache mutation at all** (no bundle write, no
  index write, no stamp advance — fail closed; the cached previous index
  remains, but the resolve that triggered the refresh fails with the ratchet
  slug — silently serving the old index would mask an active attack).
  Because the freshness stamp never advances, every subsequent invocation
  re-enters State 2 and re-alarms until the index is reverted upstream or
  the operator explicitly accepts. That is the *intended* day-after story,
  and the error text says so (§3 remediation).

**TOFU:** baselines are per-URL, keyed like every other cache artifact, and
**persistent**: returning to a previously-used `MILPA_INDEX_URL` reuses that
URL's existing baseline. TOFU applies only to a URL with *no baseline file* —
first contact ever, not "the URL changed this invocation".

**Baseline accept (the reset surface): `milpa index accept`.** The draft's
position — "cache-clean is the v1 reset" — was wrong twice over:
`registry-protocol.md §6` normatively forbids `milpa clean` from touching the
index cache (and `cmd_clean` indeed never has), and overloading a disk-hygiene
command as a trust-reset would let any script that cleans caches for unrelated
reasons silently absorb a history rewrite — the exact "silently absorbable"
outcome this RFC exists to prevent. The reset must be a dedicated, loud,
explicit verb, so it is v1 scope:

- `milpa index accept` — force-refreshes the index (Layer 1 verified under
  the effective `index-trust` policy), prints the full violation diff between
  the old baseline and the fetched index (what you are accepting), and
  rewrites the baseline. Per-URL (defaults to the effective index URL).
  This is the sanctioned exit from a migration event, a strict lockout, and
  a `TNG-INDEX-BASELINE-CORRUPT` state.
- `milpa clean` remains exactly as spec'd: it never touches the index cache
  or any baseline sidecar. No change to its contract.

### 3. Error taxonomy & diagnostics

Four new slugs, landing with their raise sites (bijection discipline):

| Slug | Condition | Policy |
|---|---|---|
| `TNG-INDEX-ROOT-MUTATED` | A document-root field violates the §1 root-field class (`schema_version` decrease; `attestation-epoch` change once set). | gated by `index-history` |
| `TNG-INDEX-ROLLBACK` | A package or version present in the baseline is absent from the candidate index (presence-component dominance failure — the rollback/deletion class). | gated by `index-history` |
| `TNG-ENTRY-MUTATED` | An entry present in both violates the §1 field lattice (frozen-field change, monotone downgrade/strip/re-attribution/re-pin, provenance removal). | gated by `index-history` |
| `TNG-INDEX-BASELINE-CORRUPT` | The baseline sidecar exists but is unparseable/truncated. | **hard fail regardless of policy** |

**Ordering and precedence — one rule, not two.** All violations are sorted by
the composite key `(class_rank, namespace, name, version)` where
`TNG-INDEX-ROOT-MUTATED` has rank 0 (document-level semantics beat entry-level
— it is the bluntest signal), `TNG-INDEX-ROLLBACK` rank 1, and
`TNG-ENTRY-MUTATED` rank 2 (root-field violations sort with an empty entry
key); the raised or
warned diagnostic carries the *first* element as its slug and the full sorted
list in its payload. Worked example (the S5.5 lesson, pre-answered): package
`aaa` has a frozen-field mutation, package `zzz` has a version disappearance —
the reported slug is `TNG-INDEX-ROLLBACK` (rank wins over alphabetical
position), the primary-named entry is `zzz`'s, and `aaa`'s mutation appears in
the payload list. Both impls MUST produce this identical outcome.

**Structured payload, not prose.** `MilpaError` already carries structured
kwargs (precedent: `names=` in `attestation.py`); the ratchet attaches
`violations=[…]` where each element carries
`(class, entry_key, field, kind, baseline_value, candidate_value)` and `kind`
is the sub-class: `frozen-changed | frozen-unset | monotone-stripped |
monotone-reattributed | monotone-downgraded | monotone-repinned |
provenance-removed | root-field-changed`. The
sub-class lives in the payload, not in more slugs: Part 1's slug collapses
were forced by verification-library ambiguity; these sub-classes are
deterministic products of the lattice, so one raise site with a
machine-readable discriminator preserves both the bijection discipline and
the incident-response distinction (a rollback suggests takedown; a
`content_hash` swap suggests live substitution; an attestation downgrade may
be a backfill-tool bug).

**Remediation hints are required** (Part 1 §7.4 precedent): both the warn
text and the strict error text MUST name the two sanctioned exits — revert
upstream, or `milpa index accept` after out-of-band confirmation that the
rewrite is legitimate.

**Yank-transition notices are not errors.** A yank-state change between
baseline and candidate (either direction) is reported on stderr with the
stable prefix `[milpa] notice: yank-state changed:` naming
`<namespace>/<name>@<version>`, the direction, and `yanked_reason` when
present. Un-yank of an entry that carried a `yanked_reason` is the case this
exists for (restoring a CVE-yanked version must not be silent). Notices fire
under `warn` and `strict` alike, do not affect exit codes, and do not block
the baseline from advancing (the transition is legal). Since a legal
transition advances the baseline, the notice naturally fires once per
transition, not forever.

### 4. Publication watermark (dividend for Part 2)

**Definition.** `T(baseline) := max(published_at)` over entries present in
the baseline (entries without `published_at` contribute nothing). The anchor
is *verified index content*, never the consumer's wall clock — a
consumer-clock anchor would add a trust dependency on exactly the party
(local environment) this design otherwise avoids, and defends nothing extra.

A clean baseline is then a *watermark*: any entry not present in it was
necessarily published after the baseline was established. Therefore a **new**
entry claiming `published_at < T(baseline) − skew` is backdated — the lie is
consumer-detectable without trusting the bot. `skew` is an explicit tolerance
(reference default: 24 h) absorbing indexing-pipeline jitter; the check
otherwise assumes tianguis's indexer appends in non-decreasing `published_at`
order, which must be confirmed as an operational guarantee on the tianguis
side (recorded on tianguis#42) — without it, legitimate out-of-order indexing
(parallel CI, retries) would false-positive.

Two scope caveats, cross-linked from the threat model: the watermark is
**per-consumer** (a TOFU/first-contact consumer has no baseline and gets no
backdate protection from this mechanism), and an entry that simply **omits**
`published_at` dodges the check — closing that requires `published_at` to be
mandatory for post-epoch entries, which is precisely Part 2's epoch mandate
(P3) and is recorded there as a dependency on this section. The enforcement
(a `TNG-ENTRY-BACKDATED`-class check) **lands with Part 2's P3**, where
entry-level policy machinery exists; this RFC only guarantees the baseline
semantics that make it possible. Recorded here so the baseline lifecycle (§2)
is not later weakened in a way that breaks it.

### 5. `yanked` — the sanctioned removal story

The invariant makes deletion a violation, so the registry needs an in-band,
lattice-legal way to retire an entry. New optional version-node fields —
**aligned with tianguis#13's contract** (`yanked` + `yanked_at` +
`yanked_reason`; the draft's `yank_reason` spelling was an accidental fork):

```
version "1.4.2" {
    content_hash "dag-sha256:…"
    yanked #true
    yanked_at "2026-07-01T12:00:00Z"                    // optional
    yanked_reason "ships a vulnerable bearssl pin"      // optional
    …
}
```

- **Lattice status:** advisory-mutable-but-surfaced — yank and un-yank are
  both legal (cargo precedent; a mistaken yank must be reversible), and both
  are ratchet notices (§3), never silent. The entry's frozen fields remain
  frozen while yanked: yank hides nothing and rewrites nothing.
- **Selection semantics:** candidate enumeration excludes yanked versions
  from *new* resolution — in **both** lookup paths (`resolve_named_all` and
  its S5b qualified twin `resolve_named_all_qualified`; named explicitly
  because the qualified path is exactly where a parallel-logic miss happened
  before). The frozen path is untouched (it never consults the index), so
  existing lockfiles keep working — yank steers new selection, never breaks
  reproduction. If every satisfying version is yanked, the existing
  `TNG-NO-SATISFYING-VERSION` fires and its message names the
  yanked-but-excluded candidates.
- **No `--allow-yanked` in milpa v1** — a deliberate delta from tianguis#13's
  sketch, recorded there. Reproduction of an already-locked yanked version is
  fully covered by the frozen path; a resolution-time escape hatch would
  reintroduce, as a user flag, the exact silent-downgrade selection the yank
  notice exists to surface. Revisit on demonstrated need.
- **Yanked-but-locked advisory** (deferred, filed as #186): the population
  that most needs `yanked_reason` is consumers already pinned to the yanked
  version, and the frozen path never shows it to them. A non-blocking
  advisory in `milpa verify`/`show` when a locked registry version is yanked
  in the current index (cargo surfaces exactly this) is follow-up scope —
  it must not touch resolution behavior.
- **Forward-compat:** an older milpa that predates these fields tolerates and
  ignores them (the §3.2 unknown-child discipline) — degraded gracefully to
  pre-yank behavior.

### 6. Command coverage

| Surface | Ratchet interaction |
|---|---|
| `fetch` / `lock` / `add` / `update` | Ratchet runs whenever the shared index-load path performs a network fetch (State 2 or recovery refetch). Workspace member-dir `add`/`update` delegate to the root (S11e), so they hit the root's effective URL and its baseline — one baseline per URL, no member-level state. |
| `show` | Only when it actually loads the index (same rule as the Layer-1 gate). |
| `verify` | Out of scope — `reverify_cached_index` is single-state offline audit; nothing to diff. (The yanked-but-locked advisory, #186, is the future `verify`-side surface.) |
| `clean` | Never touches the index cache or baseline sidecars (unchanged normative clause). |
| frozen path / `--no-index` | No index load, no ratchet. |
| `milpa index accept` | The explicit baseline-accept verb (§2). |

### 7. What this changes in the spec

- `spec/registry-protocol.md` — new **§3.5 Append-only invariant & refresh
  ratchet**: the §1 entry key + dominance statement + field/order table +
  staged-enforcement note, §2 check placement (both fetch paths, gate before
  any write) + baseline sidecar trio + write ordering + corrupt-vs-absent +
  TOFU + `index-history` policy wiring, §3 composite ordering + structured
  payload + notices, §4 watermark definition. `§3.2` gains `yanked` /
  `yanked_at` / `yanked_reason` and **amends the parsed-and-ignored clauses**:
  `published_at` becomes parse-to-typed at A2; the `rekor` and attestation
  ignore-clauses (and the pinned no-rekor regression test) are inverted at A6
  with Part 2's P2, not before. `§5.2` constraint filtering gains the
  yanked-exclusion clause (both lookup paths). `§6` index caching gains the
  baseline sidecar trio + lifecycle + the accept verb's cache semantics.
  Appendix A gains the four slugs.
- `spec/cli-contract.md` — `milpa index accept` verb; `MILPA_INDEX_HISTORY`
  env var; `index-history` manifest node with root-authority +
  `WS-INDEX-HISTORY-ON-MEMBER` member-declaration error (mirrors §3.4.7).
- `spec/errors.md` — `TNG-INDEX-ROOT-MUTATED`, `TNG-INDEX-ROLLBACK`,
  `TNG-ENTRY-MUTATED`, `TNG-INDEX-BASELINE-CORRUPT`,
  `WS-INDEX-HISTORY-ON-MEMBER` (with raise sites, per slice sequencing).
- Part 1 RFC — a short amendment note pointing here (the "what Layer 1 does
  not check" §4 caveat gains its answer).
- Part 2 RFC — OQ3(ii) amendment note: the continuity ratchet is this RFC's
  §1 monotone order, not Part-3 territory (applied with this round).

## Conformance strategy

**Harness extension first (A4a):** the existing index-trust fixture tier
(338–365) always runs against a fresh, empty `XDG_CACHE_HOME` — every current
fixture is implicitly TOFU, and no plumbing exists to pre-seed a baseline.
The fixture schema gains a `baseline.index.kdl` seed file (plus optional
seeded cache/stamp/bundle where a scenario needs a pre-populated cache), and
**both** runners — the Rust CLI-driven runner *and* the Python in-process
adapter (`test_conformance`), per the gate-on-active-impl discipline —
pre-seed the sidecars before invoking the loader. Only then the matrix
(A4b):

- legal transitions pass silently and advance the baseline: pure append (new
  version, new package), provenance append, provenance reorder, attestation
  upgrade (None→vendored, None→author, vendored→author — staged to A6),
  frozen set-once backfill (empty `content_hash` → value; absent `dep_decl` →
  value), re-serialization/reordering of the document;
- yank / un-yank pass **with notice** (baseline advances; notice text
  asserted; un-yank-with-reason case included);
- each violation class, × {warn, strict}: `content_hash` swap, `dep_decl`
  swap, `dep_decl_schema_version` solo change, `published_at` change,
  version disappearance, package disappearance, in-place provenance mutation
  (distinct from removal), provenance removal, `schema_version` decrease
  (root-field), attestation strip / signer re-attribution / downgrade /
  same-kind `bundle_pin` swap / `attestation-epoch` change (staged to A6);
- composite ordering: one fixture with a mutation on an alphabetically-early
  entry AND a rollback on a late entry → slug is `TNG-INDEX-ROLLBACK`,
  payload lists both in composite-key order;
- TOFU (no baseline → pass + baseline + `.at` written); per-URL persistence
  (returning to a URL reuses its baseline — no re-TOFU);
- warn stickiness + habituation: two successive refreshes over an unreverted
  mutation both warn, baseline did not advance, second warning marks the
  violation set as recurring; a third refresh adding a *new* violation calls
  out the delta;
- strict fail-closed: index, bundle, stamp, and baseline all byte-identical
  to their pre-fetch state after the failed refresh;
- recovery-refetch path is ratcheted (corrupt bundle sidecar → recovery fetch
  serving a mutated index → same slug as State 2);
- baseline corrupt (truncated file) → `TNG-INDEX-BASELINE-CORRUPT` hard-fails
  under `warn` too;
- `milpa index accept`: prints the diff, rewrites baseline, next refresh
  clean;
- yank selection: yanked version excluded from enumeration (bare and
  qualified lookup), all-yanked → `TNG-NO-SATISFYING-VERSION` naming yanked
  candidates, frozen path unaffected.

Differential: both impls produce identical slugs AND identical
composite-ordered violation payloads across the matrix (S5.5 precedent).

## Prerequisites

1. **Part 1 shipped** — ✅ (#103).
2. **Part 2's P2 gates only A6** (attestation + rekor lattice-row
   enforcement) — everything else in A1–A5 is independent of Part 2.
3. **Nothing cross-repo blocks the ratchet.** tianguis already satisfies the
   invariant vacuously (it appends). The *yank* fields need tianguis emission
   eventually (tianguis#13, contract aligned by this RFC); milpa-side parse +
   selection semantics are testable from fixtures alone. The §4 watermark's
   indexer-ordering assumption is recorded on tianguis#42.

## Open questions

1. ~~Baseline reset surface.~~ **RESOLVED (round 1):** dedicated
   `milpa index accept` verb in v1. The draft's cache-clean position was
   doubly wrong: `registry-protocol.md §6` normatively forbids `clean` from
   touching the index cache, and a hygiene command must never double as a
   trust-reset (silent-reset hole).
2. **Baseline growth.** The baseline is a full index copy per URL (~the size
   of the cache itself — trivial today). If the index ever grows large, the
   baseline could store the parsed entry map in a compact form instead. Note
   the drift hazard the dominance framing exposes: a compact representation
   needs a per-class digest that must stay in lockstep with the §1 order
   definitions — a second surface at risk of divergence, which is why v1
   stays a full copy.
3. **Provenance removal.** Position taken: append-only, no removal — and the
   real safety argument is the identity gate, stated explicitly: a
   *compromised* mirror serving different bytes already fails at fetch time
   (`registry-protocol.md §3.3` byte-equivalence), independent of the
   ratchet; a merely *dead* mirror is harmless (ordered fall-through). The
   alternative (tombstoned removal) adds lattice complexity for an unproven
   need.

## Slices

- **A1** spec: `registry-protocol.md` §3.5 (entry key + dominance + lattice +
  staged enforcement + ratchet placement/ordering + precedence + payload +
  notices + watermark), §3.2 `yanked`/`yanked_at`/`yanked_reason` +
  `published_at` ignore-clause amendment, §5.2 yank exclusion, §6 baseline
  trio + accept-verb cache semantics; `cli-contract.md` verb + env + axis;
  Part 1 RFC amendment note. (Part 2 OQ3 note already applied this round.)
  No slugs yet (they land with raise sites).
- **A2** Python: parse-to-typed extension (`published_at`, yank triple);
  the generic dominance fold (`ratchet.py` — `Baseline` + `dominates` with
  field/order tags, structured violations, composite ordering); baseline
  sidecar lifecycle (sticky-advance, TOFU, per-URL persistence, atomic
  write-after-index ordering, corrupt→hard-fail, reported-digest); wiring
  into **both** `load_index` State 2 and `_refetch_with_recovery`;
  `index-history` axis plumbing (manifest + env + root authority + member
  error); the root-field check (`schema_version` row; `attestation-epoch`
  row waits for the field, A6); `milpa index accept`; the five slugs in
  `spec/errors.md` +
  `errors.py` (Python's bijection lint has **no deferred window** — raise
  sites land in the same change) + Rust `all_codes()` with corpus `DEFERRED`
  entries for the Rust raise sites; unit tests for every lattice row
  parseable at this stage.
- **A3** Rust parity: same two seams (`index_cache.rs` State 2 + recovery),
  same tests; check/add `PartialEq`/`Eq` derives on the provenance types
  (multiset diff needs them); drop the A2 `DEFERRED` entries.
- **A4a** harness baseline-seeding extension: fixture schema
  (`baseline.index.kdl` + optional cache seeds) + both runners, including
  the Python in-process adapter.
- **A4b** shared conformance fixtures (the matrix above, minus A6-staged
  rows) + cross-impl differential over slugs and payload ordering.
- **A5** yank selection semantics: enumeration excludes yanked in **both**
  `resolve_named_all` and `resolve_named_all_qualified` (both impls), `§5.2`
  spec clause, `TNG-NO-SATISFYING-VERSION` message names yanked candidates,
  yank-transition notices, fixtures (excluded / all-yanked / qualified-path /
  frozen-path-unaffected / notice text).
- **A6** (post-Part-2-P2): attestation-record + `rekor` lattice-row
  enforcement — parse lands with Part 2's P2; this slice adds the dominance
  tags, inverts the pinned no-rekor regression test deliberately, and lands
  the staged fixtures (attestation strip / re-attribution / downgrade /
  same-kind `bundle_pin` swap / `rekor` mutation / `attestation-epoch`
  change, × {warn, strict}).

## Connections

- **Part 1** (`rfc-registry-trust-federation.md`) — amends: adds the
  successor-validity check Layer 1 lacks. The index signature now means
  "a valid state *and* a valid successor", not just "a valid state".
- **Part 2** (`rfc-per-entry-attestation.md`) — closes the R5
  stripping/rollback residual structurally (stripping is now a lattice
  violation); the §4 watermark underwrites Part 2's epoch-based `strict`
  (its open question 2), and Part 2's epoch mandate must make `published_at`
  required post-epoch to close the omission dodge (§4). Ownership split:
  Part 2 owns the `EntryAttestation` *type*; this RFC owns the *order* over
  its values (Part 2 OQ3(ii) amended accordingly).
- **Part 3** — the continuity ratchet ("was author-signed, must stay
  author-signed") stops being a separate trust system: it is *already* the §1
  monotone rule; Part 3 shrinks to the owner registry.
- **tianguis#13** — the yank contract this RFC's §5 aligns with
  (`yanked`/`yanked_at`/`yanked_reason`); the `--allow-yanked` delta is
  recorded there. **tianguis#42** — gains the indexer-ordering note for §4.
- **#186** — yanked-but-locked advisory in `verify`/`show` (filed this
  round). **#187** — Rekor chain auditor / cross-consumer baseline diff
  tooling (filed this round; the TOFU and split-view residuals stay
  theoretical until it exists).
- **Prior art** — Go sumdb (append-only transparency), TUF snapshot/timestamp
  (rollback protection), cargo (yank semantics + yanked-but-locked warning),
  git (history immutability by construction).
