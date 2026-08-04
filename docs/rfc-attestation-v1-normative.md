# RFC: Strict attestation (both trust axes), normative in v1 — reconcile, complete, flip

**Status:** draft (Stage 1 — RFC + slicing; **architect rounds 1–3 applied; all forks
resolved**). Round 3 was the first adversarial review of D-Watermark itself (it entered via
dialogue after the round-2 team ran); it applied the mechanism-agnostic hardening (D14–D16) and
its two escalated forks are now **resolved** (Corey, 2026-08-04): **F1 → enumerated committed
set `S`, membership `∈ S` (D17)**; **F2 → arming requires `index-history=strict`, a scoped
co-requirement not a default flip (D18)**; F-op → grandfather-all-at-re-arm. Ready for `/tdd`
from S1; S-EpochCommitment additionally needs tianguis re-arm coordination before it can go
green. See §8c "Round-3 escalations — RESOLVED".)
**Author:** Corey Leavitt
**Tracking:** #184 (Registry trust Part 2), #185 (append-only), #182 (real-bundle claim extraction)
**Depends on (all landed):** `rfc-per-entry-attestation.md` (Part 2 design; open
Q1/Q2 resolved 2026-07-09), `rfc-registry-append-only.md` (the ratchet that
underwrites epoch-based strict), `rfc-attestation-verifier.md` (real
`SigstoreVerifier` — see §1 for the precise, per-layer, per-impl build state,
which architect round 1 corrected).

## 1. Why this RFC exists — and the corrected premise

milpa is heading for a **v1 that a third implementation (the Nim dogfood) can be
built against**. Per [[v1_critical_path]], v1 is a *spec-completeness* bar, not a
feature-parity bar: the spec must be complete, unambiguous, and settled for what
is in scope, with a conformance corpus dense enough that "passes the corpus"
means "correct."

Registry attestation is the single most substantial area where the spec, the
implementations, and the intended v1 posture are out of alignment. v1's posture
(Corey, 2026-08-03) is **full strict attestation** — and, after architect round 1
(Corey, same day), **on both trust axes**: whole-index (`index-trust`) *and*
per-entry (`entry-trust`) default to `strict` in v1.

> **Premise correction (architect round 1).** The draft of this RFC claimed the
> work was *"not new design — reconciliation, promotion, and coverage"* on the
> basis that *"the code is built… in both impls."* Exploration falsified that on
> three independent, code-verified counts. The direction (D1–D3 below) is sound
> and unchanged; what was wrong is the **starting state** and therefore the
> **slicing**. The corrected state:

- **Layer 1 (`index-trust`) crypto is genuinely built in both impls.** Python via
  `sigstore-python`; Rust via the vendored `sigstore-rs` + `rekor_adapter`
  offline-inclusion path (`index_trust.rs:77`). Flipping `index-trust` to strict
  is therefore a default + conformance-corpus migration, not a build.
- **Layer 2 (`entry-trust`) crypto is built in Python only.** Rust's
  `SigstoreEntryVerifier::verify` (`entry_trust.rs:329`) returns
  `SignatureInvalid` **unconditionally** after the pre-crypto subject checks —
  stages 5–7 (cert chain / DSSE signature / Rekor inclusion) are stubbed as
  "P3b-gated." No real per-entry bundle can verify Trusted in Rust today. This
  needs a **second** `sigstore-rs` vendor patch — a "verify a DSSE envelope
  against an already-known subject digest" entry point — **distinct from #183**
  (which is the whole-index `envelopeHash` fix). Flipping `entry-trust` to strict
  without this build hard-fails every registry-resolved dep in the Rust binary.
- **The epoch classification (D1's central mechanism) is unimplemented in *both*
  impls.** `EntryTrustConfig` carries no epoch field; `evaluate_entry_attestation`
  never reads `IndexVersion.published_at` or the index `attestation-epoch` root
  field (grep-confirmed: zero epoch/`published_at` hits in either impl's gate path).
  The gate is a flat `warn`/`strict` switch today. `attestation-epoch` is consumed
  **only** by the append-only ratchet (mutation detection across snapshots), never
  by the gate. So "pre-epoch legacy stays warn, post-epoch is mandated" — the
  property that makes strict *adoptable* (open Q2) — has no code and no normative
  gate table (`rfc-per-entry-attestation.md §5`'s table has no epoch column). This
  is **new normative design + new cross-cutting plumbing + new fixtures**, not
  "wiring." Concretely (architect round 2, feasibility-verified): `attestation-epoch`
  is today an *entirely unparsed* document-root string — `parse_index` does not
  surface it; the only extractor is `index_ratchet_seam._raw_attestation_epoch`, a
  raw byte-string differ built for the ratchet's set-once mutation check, never a
  comparable instant. And `published_at` (which `IndexVersion` does carry) is never
  threaded onto `_Candidate` (9 construction sites in `resolver.py`). S-Epoch must
  therefore *build a typed epoch/`published_at` comparison path that does not exist*
  — a new typed `Index` field (unified with the raw ratchet extractor per the
  single-source-of-truth discipline, not a second parallel parser) plus dataclass
  plumbing across all `_Candidate` sites — before any "threading to the gate" is
  possible.
- **Bundle acquisition has never been exercised end-to-end through milpa's resolve
  path.** The live `milpa fetch` that reportedly emitted many
  `TNG-ENTRY-BUNDLE-MISSING (cause: unfetchable)` warnings against the
  fully-backfilled registry hit a **five-line wiring bug**, not an
  acquisition-robustness gap: `_build_entry_trust` (`cli.py:1131`) and its Rust
  twin (`main.rs:3492`) collapse an *absent* `MILPA_INDEX_URL` to `None`, so
  `entry_bundle_store_from_paths(None, …)` returns `None` and **no HTTP request is
  ever attempted** — for the normal no-override case, on every attested entry,
  independent of the registry's backfill state. The sibling `_build_dep_decl_store`
  (`cli.py:748`) implements the correct three-way `absent → DEFAULT_INDEX_URL /
  empty → None / non-empty → URL` semantics; the bundle store must match it (both
  artifacts are served from the same §3.3 base URL). D2's fail-closed posture is
  correct, but it cannot be validated until this bug is fixed.

**Therefore v1's attestation work is reconcile + complete + flip:** reconcile the
spec to the resolved design and to both-axes-strict; *build* the three unbuilt
pieces (epoch classification both impls; Rust Layer-2 crypto; the acquisition
wiring fix); densify conformance with real-crypto fixtures; then flip both defaults,
proven by those fixtures. The design decisions are settled and are **not** reopened
here.

## 2. Goals

- Make **strict attestation the normative v1 behavior on both axes**
  (`index-trust` and `entry-trust`), fail-closed, epoch-gated for the per-entry
  axis.
- **Build the three unbuilt pieces** that the default flip depends on: (a) epoch
  classification in both impls; (b) real Rust Layer-2 cryptographic verification
  (second `sigstore-rs` vendor patch); (c) the `MILPA_INDEX_URL` acquisition
  wiring fix in both impls.
- Reconcile `spec/registry-protocol.md`, `spec/cli-contract.md`,
  `spec/manifest-grammar.md`, `spec/lockfile-schema.md`, `spec/errors.md`,
  and `docs/comparison-vs-nimble-atlas.md` to the resolved design — **zero
  dangling forward-references** (not just "open question 2").
- Pin the **verification algorithm** in normative prose at a precision a
  clean-room Nim impl implements without inventing, carrying forward the known
  cert-chain caveat rather than overstating the guarantee.
- **Densify conformance** with real-crypto strict PASS + FAIL fixtures on both
  axes, and add the attestation surface to the differential harness.

## 3. Non-goals

- **Part 3 owner registry** (open Q3(i): independent `(namespace,name)→signer`
  registry). Post-v1. Chained trust taking `signed_by` on the bot's word is a
  known, documented residual.
- **Two independent upstream `sigstore-rs` items, not one.** (a) milpa **#183 →
  sigstore-rs#608 / PR #609** is the whole-index DSSE `envelopeHash`
  re-serialization fix; the vendored `.vendor-sigstore` patch already satisfies
  Layer 1's offline path, so #183 is a "delete the vendor patch when upstream
  ships" cleanup, not a v1 gate. (b) **sigstore-rs#285** (Rekor inclusion not
  wired into the crate's own bundle verifier) is what `rekor_adapter.rs` stands in
  for; deleting the adapter is gated on *that* issue, tracked separately. These
  close independently — do not conflate them (the draft did). Note: the **new**
  Rust Layer-2 vendor patch (§1, "verify against a known digest") is a *third*,
  milpa-authored gap; §6's build slice files its own upstream tracking issue under
  the same forcing-function discipline as sigstore-rs#285.
- **New verification design.** The algorithm is decided
  (`rfc-attestation-verifier.md §5`: delegate-not-hand-roll). This RFC lifts it
  into spec and *completes its Rust implementation for Layer 2*; it does not
  redesign it. The **epoch-aware gate table** (§3.6) is new normative *content*,
  but it composes the already-decided pipeline stages with the already-decided
  epoch semantics (open Q2) — no new verification primitive.
- **The third-party fetcher plugin factory signature hole**
  (`plugin-contract.md:718`) is a *sibling* v1 task, tracked separately.
- **`index-history` (append-only ratchet) default flip.** The **default** stays `warn` in v1.
  **Round-3 nuance (D18):** this non-goal is about the *default*, and it is preserved — but
  arming an epoch commitment under `entry-trust=strict` carries a **scoped co-requirement** that
  `index-history=strict` *for that registry* (the ratchet's `SET_ONCE` is the only thing
  enforcing the commitment's uniqueness; without it the malicious-registry-safety claim is
  hollow). This is a coupling invariant, not a blanket flip: a registry that arms no commitment
  is untouched and stays warn-equivalent. The earlier "backdate protection is index-history-gated
  residual" is now *resolved* by this coupling rather than left open (§8c F2/D18).

## 4. Decisions ratified by this RFC

D1–D3 are the settled design posture (unchanged from the draft). D4–D8 are the
build/scope calls architect round 1 forced once the corrected premise (§1) landed.
D9–D13 are round 2. **D-Watermark (§8c, Corey 2026-08-04) supersedes the epoch
*classification mechanism* below** — "post-epoch" is now determined by a Rekor-anchored
pre-epoch set commitment, not `published_at ≥ E`; wherever D1/D5 say `published_at ≥ E`
or `published_at < E`, read "not in / in the verified pre-epoch set." The *policy* (D1's
strict-default, fail-closed posture, warn-equivalent when un-armed) is unchanged; only
the boundary oracle changes.

- **D1 (central) — `entry-trust` default flips `warn` → `strict` in v1, epoch-gated.**
  A **post-epoch** entry (D-Watermark: *not in the verified pre-epoch set*) MUST
  carry a verifiable attestation, or the resolve fails (`exit 1`, the relevant
  `TNG-ENTRY-*` slug). **Pre-epoch** legacy entries (in the verified set) stay
  warn-territory even under `strict` — a fixed, shrinking set. **When the index declares
  no epoch commitment at all** (self-hosted / air-gapped / pre-arming), every entry is
  pre-epoch, so `entry-trust "strict"` is behaviorally warn-equivalent for that registry
  — stated normatively (§3.6), not left to inference. `entry-trust "warn"`/`"off"` remain
  explicit, auditable, **manifest-only** opt-outs (generic effective-policy formula,
  `registry-protocol.md §3.4.0`: a manifest `off` is unconditional; env can only
  strengthen).

- **D2 — offline / bundle-unavailable under strict is a hard fail.**
  A post-epoch entry whose pinned bundle is unfetchable fails under `strict` (it
  does not settle into degraded-warn). The **escape hatches** are exactly three:
  (1) a prior successful cache hit (the content-addressed entry-bundle store is
  immutable — a once-fetched bundle is permanent, not a "freshness state"); (2)
  retry via a plain `milpa fetch` (there is no negative cache — `HttpEntryBundleStore`
  is hit-or-fetch-or-hard-fail); (3) the explicit manifest `warn`/`off` opt-outs.
  Note the escape hatches do **not** include a Layer-2 analog of Layer-1's
  four-state freshness cache: per-entry bundles have no TTL, no staleness concept,
  and no degraded-serve state by design (`rfc-per-entry-attestation.md §6`) — an
  earlier draft mis-cited that Layer-1 mechanism here, which would mislead a
  clean-room implementer into building a stale-serve path Layer 2 deliberately
  omits. The draft justified D2
  by pointing at observed `BUNDLE-MISSING` friction on a backfilled registry; that
  friction was the C3 wiring bug (§1), now a prerequisite fix (§6 S-Acq), not
  evidence about acquisition robustness. D2 stands on its own merits; the
  remediation UX is specified (D6).

- **D3 — the verification steps are normatively pinned** (§3.6 / S-Steps), naming
  the `rekor_adapter` step-5 offline-inclusion stand-in as a non-normative *impl
  note*, and **carrying forward the leaf-cert caveat**: sigstore-rs verifies the
  chain at the leaf's own `not_before` and bounds-checks only the leaf window
  against `integratedTime` (`rfc-attestation-verifier.md §4` gap-3). The normative
  prose states the guarantee milpa actually delivers, not a stronger one. Two
  further residuals are carried into the normative §3.6 surface (not left in
  design-history RFCs a Nim implementer never reads): (i) **no revocation** — an
  offline keyless verification of a once-valid bundle for a later-compromised OIDC
  identity verifies forever; intrinsic to the keyless model
  (`rfc-per-entry-attestation.md §6`), stated as a NOTE; (ii) **subject
  cardinality** — the in-toto `subject` list MUST be exactly length 1; any other
  length (0 or >1) is treated identically to absent (binding fails), closing the
  `subject[0]`-underspecification the Layer-1 §3.4.4 language also left implicit.

- **D4 (round 1) — `index-trust` default flips `warn` → `strict` in v1.**
  "Full strict attestation" means both axes. This is not cosmetic scope creep: the
  per-entry epoch classification reads `attestation-epoch` *from the index
  document*, whose authenticity is exactly what Layer 1 guarantees. Under
  `index-trust "warn"`, a forged/MITM index that simply omits `attestation-epoch`
  makes every entry classify as pre-epoch → warn, silently defeating the
  `entry-trust` mandate. entry-trust=strict is only as strong as index-trust; v1
  makes them consistent. Layer-1 crypto is already built in both impls, so this is
  a default + corpus-migration change, not a build. `index-history` stays `warn`
  (§3 non-goal; §8c residual).

- **D5 (round 1; round 2 sharpened; classification mechanism SUPERSEDED by
  D-Watermark, §8c).** Epoch classification is a first-class build, not "wiring."
  **Under D-Watermark the boundary oracle is a Rekor-anchored pre-epoch set commitment,
  not the `published_at ≥ E` comparison this decision originally specified.** The
  originally-drafted five `published_at` branches collapse to D-Watermark's four
  `epoch_basis` values (`in-pre-epoch-set` / `not-in-set` / `no-commitment-armed` /
  `commitment-verification-failed`); `published_at` is informational only and is no
  longer parsed for the gate. What survives from D5: classification is still a
  first-class, separately-tested build with an `epoch_basis` discriminator carried via
  the composed `EntryGateOutcome` (D9), and it still lands **before** the D1 flip.

  What D5 contributes, under the D-Watermark mechanism (full mechanism in §8c;
  build in S-Epoch):
  - **Classification is a first-class, separately-tested build, not "wiring."** It is
    a dedicated slice (S-Epoch) that parses + Rekor-verifies the epoch commitment `(C, E)`
    and evaluates set membership — not a field threaded into an existing predicate. The
    typed epoch-commitment field is **unified with** `index_ratchet_seam`'s existing
    `attestation-epoch` extractor (single-source; two parallel epoch parsers is the
    duplication CLAUDE.md forbids).
  - **Round-3 correction (D14): the discriminator splits into an index-scoped status and an
    entry-scoped membership.** Round 3 (all four lenses) found that folding
    `commitment-verification-failed` into a per-entry `epoch_basis` is a category error: a
    `C' != C` mismatch or bad Rekor proof is a fact about the *whole index*, identical for
    every entry, and its natural home is an **index-integrity abort before any candidate is
    selected** — not a value returned per-candidate from the entry gate (whose
    `EntryVerificationResult` type has no index-family variant, and whose late timing would
    let it co-occur with `TNG-ENTRY-*` outcomes, violating R4's cross-axis precedence). So the
    classification factors into **two** shapes (D14):
    - `EpochCommitmentStatus` (index-scoped, computed **once** per resolve, at the new
      index-gate epoch phase, R3-b): `Unarmed` / `Armed(C, E)` / `ArmingInvalid(reason)`.
      `ArmingInvalid` short-circuits the whole resolve via the new index-family slug
      **`TNG-INDEX-EPOCH-COMMITMENT-INVALID`** (distinct from both the whole-index-bundle slug
      and the `index-history` ratchet slugs — §8c decouples the epoch anchor from
      index-history, so re-using a ratchet slug would silently re-couple them).
    - `EpochMembership` (entry-scoped, per candidate, meaningful **only** when status is
      `Armed`): `PreEpoch` ⇒ warn / `PostEpoch` ⇒ mandate. `no-commitment-armed` is not a
      per-entry value at all — it is the `Unarmed` resolve-wide mode (warn-equivalent, D11).
    The fail-closed branch is still load-bearing (an invalid commitment must NOT downgrade to
    warn); it just fires once, at the index layer, with an index-family slug. See §8c and
    S-EpochCommitment/S-EpochGate for the full build.
  - **`epoch_basis` is a composed diagnostic, not a bare threaded string.** Round 2
    (design lens) flagged that "thread it exactly as `cause` is" would produce a *third*
    ad-hoc optional discriminator glued on by kwarg-passing (result-enum + `cause` +
    `epoch_basis`), independently in both impls. Instead the gate return is a single
    composed shape (`EntryGateOutcome`, D9) the spec hands over as a *type*.
  - **Explainability obligation.** Each `epoch_basis` value that can *cause a failure*
    carries pinned remediation prose (D6-style), not a raw enum token — in particular
    `not-in-set` ("this entry is not in the registry's committed pre-epoch set, so it
    must carry an attestation") and `commitment-verification-failed`, pinned in S-Epoch
    alongside its test matrix.

- **D6 (round 1) — the strict-failure remediation UX is specified, not improvised.**
  The `TNG-ENTRY-BUNDLE-MISSING` hint is split by `cause`: `unfetchable` →
  *"the attestation mirror was unreachable; this is usually transient — re-run
  `milpa fetch`"* (**not** `--refresh-index`, which only bypasses the *index*
  cache TTL and is a no-op for the content-addressed bundle store); `no-pin` →
  *"the registry has not published a bundle for this entry; set `entry-trust
  \"warn\"` or wait for backfill."* The draft's escape-hatch text recommended a
  flag that does nothing for this failure class (`entry_trust.py:520`); under a
  strict default that is the day-one failure surface, so the correct hint is a
  spec-level obligation (S-Acq). **Round 2 additions:** (i) the `unfetchable` hint
  is further scoped by store backend — for `FileEntryBundleStore`
  (`MILPA_ENTRY_BUNDLE_DIR`, air-gapped) a genuinely-absent file is *not* transient,
  so retrying deterministically re-fails; the hint for the file backend names the
  operator-populated mirror, not "re-run `fetch`." (ii) D6 widens to an audit of the
  *whole* `_HINT_MAP` before the flip: the pre-existing `Unattested` hint recommends
  `entry-trust "off"` (a permanent axis kill-switch), while `no-pin` correctly
  recommends the narrower `warn` — both failure classes share the same day-one root
  cause (registry hasn't finished attesting), so every "escape" hint defaults to
  `warn` (preserves the audit trail strict exists to produce); `"off"` language is
  reserved for genuinely permanent, deliberate opt-outs.

- **D7 (round 1; round 2 corrected) — Rust Layer-2 real crypto is completed
  in-scope (S-RustCrypto).** The real blocker (feasibility-verified) is that
  sigstore-rs's only public verify entry point, `Verifier::verify_digest(input:
  Sha256, …)`, takes a *live `Sha256` hasher* it `.finalize()`s, not a raw digest —
  and Layer 2 only ever holds `content_hash` (no source-tree preimage, by design),
  so it cannot seed that hasher. **The fix is not "the #183 patch shape."** #183 is
  *subtractive* (~15 lines, deletes the `envelopeHash` re-check in one file, no new
  API). The Layer-2 patch is *additive and two-file*: extract the ~90-line
  `verify_digest` body parameterized over the digest *source* (`&[u8]` vs `Sha256`)
  and expose it as a new method on **both** the async `Verifier` and its
  `blocking::Verifier` wrapper (milpa uses the blocking path). This is *safe* to
  write because, for the DSSE branch, `verify_bundle_content`'s digest check is
  redundant with the pre-crypto digest-equality check `SigstoreEntryVerifier`
  already performs — the patch bypasses an API-shape mismatch, it does not weaken a
  cryptographic check. **Real reuse confirmed:** stage-7 Rekor inclusion uses
  `crate::rekor_adapter::verify_entry_inclusion`, an already-built function Layer 1
  exercises today — not a new build. Wire `SigstoreEntryVerifier::verify` stages 5–7
  for real, delete the unconditional `SignatureInvalid`, and file the upstream
  tracking issue with the same forcing-function tripwire as sigstore-rs#285. Lands
  before the D1 flip and before the real-crypto FAIL fixtures can be green in both
  impls.

- **D8 (round 1; round 3: largely SUBSUMED by D-Watermark).** **Round-3 finding (depth H2,
  design F4, feasibility):** D8 was written for the retired `published_at ≥ E` classification,
  where a freshly-published entry could lie about `published_at` to sneak into the pre-epoch
  window. Under D-Watermark that dodge is *already closed for free* by the same fail-closed
  mechanism that closes the omission dodge — an attacker adding a post-arming identity to the
  committed set makes `C' != C` ⇒ `ArmingInvalid` ⇒ abort (the exact "backdater IS the
  registry" argument §8c uses to justify the whole design). So the epoch-boundary purpose of
  `TNG-ENTRY-BACKDATED` is subsumed. §8c's supersession list is corrected to include D8/S-Backdate.
  **S-Backdate survives only if it has a distinct, non-epoch-boundary purpose** (general
  chronological-consistency auditing of `published_at` as informational metadata); if it does
  not, the slice and slug are retired and S1 retires the dangling
  `registry-protocol.md:1675` forward-reference by deletion rather than by building the check.
  S-Backdate's slice description now states this explicitly. The remainder of D8 is retained
  below for the historical rationale.

  The omission dodge
  (post-epoch entry lacking `published_at`) is closed by D5's fail-closed
  classification. The *backdate* dodge (a real pre-epoch `published_at` on a
  freshly-published entry) is caught only by the publication-watermark check
  (`registry-protocol.md §3.5.4`), whose `TNG-ENTRY-BACKDATED`-class slug is today
  a **dangling forward-reference** (`registry-protocol.md:1675`, "lands with Part
  2's P3 slice" — that slice is now). S-Backdate builds the check and retires the
  dangling reference. Honest caveat carried to §8c: the watermark is
  index-history-gated (default `warn`), so full backdate protection interacts with
  the index-history default this RFC does not flip. **Round 2 sharpened §8c further:**
  the watermark is *per-consumer* (`T(baseline) := max(published_at)` over a *prior*
  fetch, `registry-protocol.md:1649`), so a TOFU/first-contact consumer — a fresh
  clone, or (very common) an ephemeral CI runner with no persisted `~/.cache/milpa`
  between jobs — has no baseline and gets **no** backdate check at all, silently,
  independent of the index-history policy. That is a second, distinct residual, not
  closed by any index-history default flip; recorded in §8c.

D9–D12 are round-2 additions.

- **D9 (round 2) — one composed gate diagnostic, not three parallel discriminators.**
  The entry-trust gate return is a single typed shape the spec hands over —
  `EntryGateOutcome { result: EntryVerificationResult, epoch_basis: EpochBasis?,
  cause: BundleMissingCause? }` — not a result-enum with `cause` and `epoch_basis`
  bolted on as independent optional strings threaded by kwarg in each impl. The spec
  (§3.6) specifies *the type*; "thread it like `cause`" described a Python/Rust impl
  detail, not a portable contract. Defining it once now (nothing is built yet) avoids
  both impls independently accreting a fourth ad-hoc field later, and gives the Nim
  implementer a shape to implement rather than a threading recipe to reverse-engineer.

- **D10 (round 2) — one shared verification-gate pipeline model in the spec; the two
  axes instantiate it.** §3.6 must not be a prose restatement of §3.4 (the two would
  drift on security-critical detail — the exact risk `rfc-per-entry-attestation.md §6`
  already flags for the *code*). Instead, factor a generic "§3.x verification-gate
  model" (parallel to how §3.4.0 factors the generic *policy* axis) stating **once**:
  parse-before-crypto ordering, the TOCTOU single-read invariant, delegate-not-
  hand-roll, first-failing-stage-wins precedence, and subject-binding-precedes-crypto
  — parametrized by (subject shape, expected-signer derivation, stage list, freshness
  applicability). §3.4 (index) and §3.6 (entry) each reduce to a short instantiation
  (own stage table + slug mapping + axis-specific rule: freshness for index, epoch
  classification for entry). This is the single-source-of-truth discipline applied to
  the spec prose, not the code.

- **D11 (round 2) — the index-trust/entry-trust degradation asymmetry is correct by
  design, and is documented, not "fixed."** entry-trust has a graceful
  no-epoch-armed ⇒ warn-equivalent path; index-trust (D4) is an unconditional
  hard-fail for a registry that carries no whole-index bundle, with only the explicit
  `index-trust "off"` opt-out. This asymmetry is *load-bearing*, not an oversight: a
  coarse "index never carries a bundle ⇒ warn-equivalent" grace would reintroduce
  exactly the MITM strip-the-bundle bypass D4 exists to close (an attacker deletes the
  bundle to trigger grace), and entry-trust's own grace is only *safe* because
  index-trust unconditionally authenticates the `attestation-epoch` field that drives
  it. So index-trust MUST be unconditional. The residual is an **adoption**, not a
  security, gap: a self-hosted / air-gapped operator using a never-attested index must
  set `index-trust "off"` on day one. §3.4 states this and S9 adds a one-line
  self-hosted-registry migration note; no grace mechanism is added.

- **D12 (round 2) — "verified-at-resolve" is a same-invocation-only rendering; cold
  reads stay "claims."** R8/S5 upgrade `milpa show` wording, but the lockfile schema
  is unchanged (correct — `lockfile-schema.md §3.9`: record the *claim*, never a
  verification outcome). Therefore "verified" wording is emitted **only** immediately
  after a strict `fetch`/`lock` where crypto actually ran in *this* process (and by
  `milpa verify`, which genuinely re-runs offline crypto). A `show` reading a
  pre-existing lockfile cannot know a check occurred — inferring "verified" from
  current policy shape would reintroduce the exact claim/outcome conflation §3.9
  forbids, and breaks under set-once-epoch time travel (an entry locked pre-arming,
  correctly warn at lock time, would misrender "verified" after the epoch is later
  armed). Cold `show` keeps "claims" wording.

- **D13 (round 2) — the trust root is a verification *input*; the differential
  guarantee is stated relative to a fixed root.** A verdict is always "valid relative
  to this trust root," so the cross-impl "both verify identically" claim is only
  meaningful when both impls consume the *same* root. The differential corpus supplies
  **one committed trust-root fixture to both impls** → the guarantee is unconditional
  and any divergence is a real logic bug (no allow-list for "accepted" trust-root
  divergence — that would be treating a differing input as output noise). Production is
  a separate path: each impl uses its native live root (Python's runtime TUF root keeps
  auto-propagating revocations; correct posture and unaffected by the test design).
  This resolves round-1 §8b without the false byte-identical-vs-revocation trade-off.

D14–D16 are round-3 additions — the **mechanism-agnostic** hardening of D-Watermark (they
hold under any resolution of the two escalated forks F1/F2 in §8c). Round 3 was the first
adversarial review of D-Watermark itself.

- **D14 (round 3) — the epoch classification is TWO types, not one four-value discriminator
  (see D5's round-3 correction).** `EpochCommitmentStatus` (index-scoped, once-per-resolve,
  `Unarmed`/`Armed(C,E)`/`ArmingInvalid`) is produced by a **new index-gate epoch phase** that
  runs after the index is parsed and before candidate selection; `EpochMembership` (per-entry,
  `PreEpoch`/`PostEpoch`) is read by the entry gate only when status is `Armed`. `ArmingInvalid`
  aborts the resolve via the new **`TNG-INDEX-EPOCH-COMMITMENT-INVALID`** slug (index family;
  R5). This preserves D10's "each axis instantiates the shared gate model" claim — commitment
  verification is index-scoped work that stays in the index instantiation, not smuggled into the
  entry gate — and it satisfies R4's cross-axis precedence (an epoch-commitment failure is an
  index-integrity abort, never co-occurring with `TNG-ENTRY-*`). The commitment is verified
  **once**, not per-candidate.

- **D15 (round 3, feasibility-verified) — the arming commitment is authenticated by COMPOSED
  crypto and delivered as a SIDECAR artifact.** Two feasibility findings correct the S-Epoch
  draft:
  - *Composed verification, not inclusion-proof-only.* `rekor_adapter::verify_entry_inclusion`
    proves only that a body was included in a Rekor-signed tree — its own docstring states it
    does **not** bind that body to a DSSE envelope/cert. Rekor is publicly writable by any OIDC
    identity, so inclusion-alone would let anyone forge a "committed" `C`. The commitment MUST be
    verified by the same **composed** pipeline index-trust uses (`index_trust::verify_crypto`:
    Fulcio cert-chain + DSSE signature over the commitment statement + Rekor inclusion), against
    a dedicated **re-arm signer identity** — not "reuse the inclusion path." `E` is the
    `integratedTime` of that fully-verified entry.
  - *Sidecar delivery, not a scalar field.* A real Rekor inclusion proof (`root_hash`,
    `hashes[]`, signed checkpoint) is not scalar KDL text; the commitment needs the same
    content-addressed **sidecar-bundle** fetch+cache class as `index.kdl.bundle`, not an inline
    document-root string. So S-EpochCommitment is two builds — a typed pointer on `Index` **and**
    a sidecar acquisition path (sized like S-Acq's bundle store, not a one-line field).

- **D16 (round 3) — identity includes `namespace`; re-arm is a NEW field, not a mutation.**
  - *Namespace in identity.* The pre-epoch identity is
    **`(namespace, name, version, content_hash)`**, matching the registry's own documented
    identity key `(namespace, name)` (`registry.py`). Dropping `namespace` (as the draft did)
    lets an attacker publish `mallory/leftpad@1.0.0` copying `alice/leftpad`'s exact bytes → an
    identical `(name, version, content_hash)` tuple → the post-epoch package misclassifies
    pre-epoch and dodges the mandate. It is also a cross-impl determinism hazard (one impl
    silently re-adds `namespace`, the other doesn't → divergent `C'`). Normative in S2/S3, with
    the namespace-collision case recorded as a rejected-attack example (as D3 does for subject
    cardinality).
  - *Re-arm as a new field.* `attestation-epoch` is `OrderKind.SET_ONCE` today, pinned by
    fixtures 389/409; **mutating its shape** (timestamp → `(C, Rekor-anchor)`) *is* the
    `TNG-INDEX-ROOT-MUTATED` violation those fixtures exist to catch, and would fire for every
    consumer with an established baseline the moment tianguis re-arms. So the commitment is a
    **new sibling field** with its **own** `OrderKind` (append-once), and the legacy
    `attestation-epoch` timestamp stays as informational metadata — not a re-typing of the
    existing field. S2 adds the `§3.5.1` OrderKind row and audits fixtures 389/409.
  - *Hash hygiene.* `C`'s construction carries a domain-separation prefix
    (`milpa-preepoch-v1:`), an explicit set-dedup rule (no duplicate identities), and reuses
    `version.py`'s ordering for the sort key (never an ad-hoc string sort) — all required for
    byte-exact cross-impl determinism. `content_hash` is assumed immutable-once-published (the
    identity model); a registry hash-*correction* is out of scope and MUST be handled as a new
    version, not an in-place edit (which would silently drop the entry from the pre-epoch set).

- **D17 (round 3, resolved) — the pre-epoch set is an ENUMERATED frozen set `S`, not a
  per-entry flag or an append-order cutover (F1=b; full argument in §8c "Round-3 escalations").**
  Because pre-epoch entries have no transparency-log footprint, the grandfathered population must
  be explicitly enumerated and committed at arming; committing the whole small frozen `S`
  (`C = hash(S)`, shipped as the D15 sidecar) yields authenticated membership **and**
  non-membership with zero Merkle/proof/flag machinery. Classification is
  "verify `S` (`hash(S)==C`, composed-verified, Rekor-anchored), then `identity ∈ S`." The
  drafted "recompute `C'` over pre-epoch-flagged local entries" is retired.

- **D18 (round 3, resolved) — arming an epoch commitment REQUIRES `index-history=strict`
  (F2=a).** Rekor gives immutability, not exclusivity; the only thing enforcing "the **first**
  commitment wins" is the `index-history` ratchet's `SET_ONCE`. So the malicious-registry-safety
  guarantee **is** `index-history=strict`. When an epoch commitment is armed **and**
  `entry-trust=strict`, `index-history=strict` is a **hard co-requirement** (else a config
  error) — a coupling invariant, **not** a change to the `index-history` default (§3 non-goal
  preserved: registries that arm no commitment are unaffected). The epoch commitment and the
  append-only ratchet are one security mechanism; splitting them across independently-defaulted
  knobs would ship the D1 claim as a footgun.

**Resolved-with-recommendation (not reopened; flagged for veto).** Three round-1
design findings carry confident recommendations, so they are resolved here rather
than escalated; recorded so they are not relitigated:
- **8 `TNG-ENTRY-*` slugs stay 8** (not collapsed to a `SUBJECT-BINDING-MISMATCH`
  + discriminator). DIGEST-MISMATCH and SUBJECT-MISMATCH do share a consumer
  remediation, but the slugs are already shipped (`errors.md`, 10-slug bijection
  green) across 22 fixtures and serve cross-impl differential precision (the S5.5
  precedent); collapsing pre-v1 churns all of that for a marginal ergonomic gain.
  The shared-remediation fact is documented honestly instead.
- **No time-bounded break-glass weaken lever in v1.** The manifest-only,
  env-can-only-strengthen model is the correct durable authority. A transient-outage
  emergency valve (`MILPA_ENTRY_TRUST_BREAK_GLASS` + an explicit
  `--i-know-this-is-insecure`) is a real ergonomic idea but not v1-blocking under
  D2's retry escape; **filed as a follow-up issue** (defer=file-now) rather than
  built or silently dropped.
- **The `trust { index …; entry …; index-history … }` grouping block stays a
  deferred cosmetic.** With strict/strict/warn defaults the three-knob surface is
  still legible; the block is sugar, not a semantic merge. One sentence of §3.4.0
  prose explains the remaining `index-history = warn` asymmetry so a reader of the
  SSOT table sees it as a decision, not an accident.

## 5. Reconciliation deltas (the spec edits, itemized)

| # | File / anchor | Current (stale) | Target (normative) |
|---|---|---|---|
| R1 | `registry-protocol.md` §3.2 (~361, ~383) + the §3.4 "SEPARATE document" framing (~722-731) | "no gate exists at this spec layer … nothing implies that gate exists yet"; gate's normative home is `rfc-per-entry-attestation.md §4-§5` | the gate is specified **in this document** at the new §3.6 and enforced; §3.4 prose rewritten to point at §3.6 |
| R2 | `registry-protocol.md` every dangling forward-ref: open-Q2 sites (~80, ~283, ~1191), "not yet part of any spec surface" (~388-390), "claim-only window … precedes … bundle-delivery slice" (~434), "target for … P2 slice … amendment preceding the implementation" (~397) | RFC-slice forward-references | resolved epoch-based criteria stated normatively; delivery/gate framed as *shipped*, not *forthcoming* |
| R3 | `registry-protocol.md` §3.4.0 SSOT table (~793-797): `entry-trust` **and** `index-trust` default `warn`; `entry-trust` Normative-home = `rfc-per-entry-attestation.md §4` | — | both defaults `strict` (D1, D4); `entry-trust` Normative-home → `registry-protocol.md §3.6`; one prose sentence on the retained `index-history = warn` asymmetry; **add a 4–6-row worked-example table** (manifest × env → effective) under the effective-policy formula (the "env can only strengthen" rule is a surprise-prone asymmetry a user should not have to infer) |
| R3.5 | `registry-protocol.md` **new generic §3.x gate-pipeline model** (D10) | (gate structure stated only inside §3.4, index-specific) | factor the axis-generic pipeline invariants once — parse-before-crypto, TOCTOU single-read, delegate-not-hand-roll, first-failing-stage-wins, subject-binding-precedes-crypto — parametrized; §3.4 and §3.6 each become a short instantiation, not a restatement |
| R4 | `registry-protocol.md` **new §3.6** (entry gate) **+ a §3.4-side epoch-commitment phase** (round-3 D14) | (gate specified only in the RFC; no epoch column anywhere) | "Per-entry attestation gate (Layer 2)" **instantiating the §3.x model** (R3.5): when-it-fires, selection-step pipeline, 8-slug outcomes, subject-binding (**cardinality = 1**, D3), verification steps with the D3 cert caveat + **no-revocation NOTE**, the **`EntryGateOutcome` diagnostic type** carrying `EpochMembership` (D9/D14). **Epoch classification splits (D14–D16):** an *index-scoped* `EpochCommitmentStatus` phase (composed-verified sidecar commitment, `(namespace,name,version,content_hash)` identities, own set-once field/`OrderKind`, `TNG-INDEX-EPOCH-COMMITMENT-INVALID` on failure — §8c; membership = `identity ∈ S`, the enumerated committed set, D17; arming requires `index-history=strict`, D18) producing a once-per-resolve status the entry gate *reads* as `PreEpoch`/`PostEpoch`/`Unarmed`; `published_at` informational only. NORMATIVE **cross-axis precedence**: index-trust (incl. the epoch-commitment phase) strictly precedes entry-trust; `TNG-INDEX-*` and `TNG-ENTRY-*` never co-occur. Plus the entry-trust-only-on-registry-source sentence (br11) |
| R5 | `errors.md` | 8 `TNG-ENTRY-*` + `WS-ENTRY-TRUST-ON-MEMBER` present (bijection green); `TNG-ENTRY-BACKDATED` referenced but undefined | bijection stays green; strict-fail slugs documented as errors-not-warnings under default; **add `TNG-INDEX-EPOCH-COMMITMENT-INVALID`** (index family, D14 — the epoch-commitment abort, distinct from the ratchet slugs) with its raise site (S-EpochCommitment); **`TNG-ENTRY-BACKDATED`** added *only if* S-Backdate retains a distinct non-epoch purpose (round-3 D8) — else its dangling ref is retired by deletion (S1) |
| R6 | `cli-contract.md` | `MILPA_ENTRY_TRUST` **entirely absent** (siblings §8.6/§8.7 exist) | new §8.8 "Per-entry attestation trust" mirroring §8.6; Appendix env-var row; explicit note that this axis (and index-trust) default `strict`, unlike `index-history` |
| R7 | `manifest-grammar.md` | `entry-trust`/`index-trust`/`index-history` missing from the **standalone-package** top-level node list (~121-124); `entry-trust`/`index-history` missing from the **workspace** list (~1226-1229) | all three axes added to both node lists, cross-referenced to §3.4.0/§3.6/§3.5.2 (fixes a live self-contradiction: the grammar would `MAN-UNKNOWN-TOP-LEVEL` a standalone `index-trust`) |
| R8 | `lockfile-schema.md` §3.9 NOTE (~752-759) + `cli.py`/Rust `milpa show` wording | "unverified claim … until a later slice adds the gate" (the gate exists) | schema unchanged (correct); NOTE + `show` wording upgraded per-policy but **scoped to same-invocation** (D12): "verified-at-resolve" only immediately after a strict `fetch`/`lock`/`verify` where crypto ran *this* process; a cold `show` of a pre-existing lockfile keeps "claims" wording (inferring verified from policy shape reintroduces the §3.9 claim/outcome conflation and breaks under set-once-epoch time travel) |
| R9 | `comparison-vs-nimble-atlas.md` | attestation = "research direction" | attestation = shipped, strict-default, v1 (both axes) |
| R10 | `cli-contract.md` §5.4 (`verify`) | "Recheck every dep … using content hashes. **Does not fetch.**" — silent on both attestation gates, contradicting `registry-protocol.md §3.4.1` ("`verify` invokes the gate in crypto-only mode, offline") | §5.4 amended: `verify` re-verifies cached bundles on **both** axes in crypto-only/offline mode (never *fetches*, only re-checks resident bytes), naming the `TNG-INDEX-*`/`TNG-ENTRY-BUNDLE-MISSING` outcomes; carries the D12/D6 `verify`-specific remediation ("no cached bundle → run `milpa fetch` to acquire, then re-verify" — `verify` cannot self-heal, unlike `fetch`) |
| R11 | `conformance-fixtures.md` | catalogs prior RFC-scale fixture additions but has no entry for the 8 `TNG-ENTRY-*`/`TNG-INDEX-*` families nor the new S6/S7 real-crypto fixtures | add a catalog block for the real-crypto fixture IDs and document the **new per-impl real-crypto tier** as a fixture *category* the format doc does not yet describe; **audit fixtures 389/409** for the re-arm transition (round-3 R12), don't only add new ones |
| R12 (round 3) | `registry-protocol.md` §3.5.1 (set-once order-kinds) + fixtures 389/409 | `attestation-epoch` is `OrderKind.SET_ONCE`; no field carries a `(C, Rekor)` commitment | add an `OrderKind` row for the **new** epoch-commitment field (append-once), keeping the legacy `attestation-epoch` timestamp informational; audit/amend 389/409 so the "commitment attached to an already-set epoch" transition is legal (D16 — mutating the timestamp shape would trip `TNG-INDEX-ROOT-MUTATED`) |
| R13 (round 3) | `registry-protocol.md` **new §3.4.x** commitment-artifact acquisition (parallel to `index.kdl.bundle`, ~829-848) | the commitment's on-index shape + Rekor-proof delivery is undefined | specify the commitment as a content-addressed **sidecar bundle** with its own fetch/derive path, composed-verified against the re-arm signer (D15); this is where `(C, E)` physically lives, not an inline field |

## 6. Slices (`/tdd`-sized, independently testable)

Sequenced so spec lands first, the **three builds** land before the flip they
enable, real-crypto fixtures exist before the flip they justify, and the flip is
proven by those fixtures. **This ordering is normative, not a handoff-doc
convenience** — the numbered order below *is* the execution order.

**Spec (S1–S3, spec-only):**

- **S1 — reconcile §3.2 + retire every dangling forward-ref (R1, R2).**
  Remove the "enforcement lands later" framing and every forward-reference hedge
  (not only "open question 2" — also "not yet part of any spec surface",
  "claim-only window … precedes", "amendment preceding the implementation"); state
  the epoch-based strict criteria and the set-once epoch commitment as normative
  (the D-Watermark set-membership boundary, §8c/S2 — **not** `published_at ≥ E`;
  `published_at` is informational). *Test:* `harness/corpus_lint`
  + cross-ref integrity — zero dangling forward-references below the shipped line;
  a grep allow-list of the retired phrases returns empty.

- **S2 — the Layer-2 gate normative section, epoch-aware (R3.5, R4; D9, D10).**
  First factor the axis-generic **§3.x verification-gate model** (R3.5/D10) —
  parse-before-crypto, TOCTOU single-read, delegate-not-hand-roll,
  first-failing-stage-wins, subject-binding-precedes-crypto, parametrized — so §3.6
  *instantiates* it rather than restating §3.4 (drift on security-critical prose is
  the exact risk this avoids). Then add `registry-protocol.md §3.6`: selection-step
  firing (post-solve), the 8-stage pipeline, subject-binding to `content_hash` +
  package coordinate **with cardinality = 1** (D3), **and the D-Watermark epoch
  classification** (§8c) — new normative content. **Round-3 shape (D14–D16):**
  - **Index-scoped commitment (a §3.4-side phase, not §3.6).** The arming commitment is over
    the frozen pre-epoch identity set, identity =
    **`(namespace, name, version, content_hash)`** (D16 — includes namespace; record the
    cross-namespace byte-copy attack as a rejected example); `C = hash(domain-sep ‖ deduped,
    version.py-ordered, canonically-encoded identities)` (D16 hygiene). `C` is delivered as a
    content-addressed **sidecar bundle** and **composed-verified** (Fulcio + DSSE + Rekor
    inclusion against the re-arm signer), **not** inclusion-proof-only, which is forgeable
    (D15). `E` := that verified entry's `integratedTime`. This produces `EpochCommitmentStatus`
    once per resolve; an invalid commitment ⇒ **`TNG-INDEX-EPOCH-COMMITMENT-INVALID`** (index
    family) aborting before selection. The commitment lives in a **new set-once field** with
    its own `OrderKind` (D16) — add the `§3.5.1` OrderKind row (R12) and audit fixtures
    389/409, since re-typing the existing `attestation-epoch` timestamp would trip
    `TNG-INDEX-ROOT-MUTATED`. **Membership is `identity ∈ S`, the enumerated committed set**
    (D17, resolved): `S` ships as the sidecar, is composed-verified as `hash(S)==C`, and both
    membership and non-membership are decided by local set lookup — no recompute, no per-entry
    flag. Spec the D18 co-requirement: arming under `entry-trust=strict` requires
    `index-history=strict`.
  - **Entry-scoped membership.** §3.6 reads `EpochCommitmentStatus` and yields `EpochMembership`
    (`PreEpoch` ⇒ warn / `PostEpoch` ⇒ mandate; `Unarmed` ⇒ warn-equivalent). `published_at`
    is **informational only**, never the boundary.
  Specify the **`EntryGateOutcome`** diagnostic type (D9, carrying `EpochMembership`) as the
  gate's return shape; subject-binding to `content_hash` + package coordinate **with
  cardinality = 1** (D3). Frozen-path resolves do NOT fire either gate (mirroring §3.4.1).
  Add the NORMATIVE **cross-axis precedence** sentence (R4: index-trust — including the
  epoch-commitment phase — strictly precedes entry-trust; the two slug families never
  co-occur), and a sentence that entry-trust fires **only** on candidates bound to the registry
  source, so a `git=`/`tarball=`/`oci=`-sourced dep (even one whose name shadows a registry
  entry — cf. `RES-REGISTRY-SHADOW`) is never subject to epoch classification (br11). Also
  update §3.4's cross-reference and the SSOT Normative-home column (R1, R3). *Test:* spec-lint
  + fixtures reference the §3.6/§3.4 epoch anchors.

- **S3 — verification-steps normative pin, clean-room precision (R4 cont., D3).**
  The exact algorithm: (1) Fulcio cert-chain to the trust root **at the leaf's
  `not_before`, leaf-window bounds-checked against `integratedTime`** — the caveat
  carried forward, not the stronger claim; (2) DSSE envelope signature over the
  in-toto statement; (3) Rekor inclusion proof, offline, over the served bundle;
  (4) subject-binding — statement subject digest MUST equal the entry's
  `content_hash` (scheme-agnostic hex extraction) AND `subject[0].name` MUST equal
  `pkg:tianguis/<ns>/<name>@<version>` — with **`subject` cardinality exactly 1**
  (any other length treated as absent), both **before** crypto. **Round-3 correction (D14):
  epoch classification is NOT a post-crypto "step 5" of the per-bundle pipeline** — it is the
  index-scoped `EpochCommitmentStatus` phase (S-EpochCommitment) that runs *before* candidate
  selection and *decides whether a bundle is required at all*; the per-entry `EpochMembership`
  read is a stage-0 gate on "is an attestation mandated," not a step after the bundle's own
  crypto. Number/place it accordingly so it does not collide with `errors.md`'s pipeline
  "stage 5" (`SIGNATURE-INVALID`). Name the `rekor_adapter` step-3 offline-inclusion stand-in a
  non-normative impl note. Carry the **no-revocation** residual as a NORMATIVE NOTE
  (a once-valid bundle for a later-compromised identity verifies forever offline —
  intrinsic to keyless; today only in the design-history RFC, invisible to a
  spec-only Nim implementer). *Test:* a Nim-implementer review question —
  "implementable from the prose alone?" — plus cross-ref to the verifier fixtures.

**Builds (land before the flip):**

- **S-Acq — fix the `MILPA_INDEX_URL` acquisition wiring, both impls (C3).**
  Replace the absent/empty collapse in `_build_entry_trust` (`cli.py:1131`) and
  `build_entry_trust_gate` (`main.rs:3492`) with the three-way semantics the
  sibling dep-decl store already documents. Add the D6 cause-split hint text —
  including the **store-backend split** (transient "re-run `fetch`" for the HTTP
  store vs the operator-mirror message for `FileEntryBundleStore`) and the
  **full `_HINT_MAP` audit** (every "escape" hint defaults to `warn`, not `off`; D6).
  *Test:* per-impl unit tests for absent → default-URL store, empty → None,
  non-empty → that URL; a test that a plain `fetch` against a served bundle now
  *attempts* acquisition; hint-text assertions per `cause` × backend. This unblocks
  any real end-to-end acquisition test — prerequisite to S-Epoch/S6/S7.

> **Round-3 split (D14/D15/F5) + forks resolved (D17/D18).** The old single `S-Epoch` conflated
> index-scoped commitment verification with the entry-scoped membership predicate. It is split
> into **S-EpochCommitment** (index-gate; the slice with the real tianguis dependency) and
> **S-EpochGate** (entry-gate; testable against synthetic `EpochCommitmentStatus` fixtures with
> no cross-repo blocker, so it proceeds in parallel with tianguis coordination). Forks F1/F2 are
> **resolved**: membership is `identity ∈ verified enumerated set S` (D17), and arming requires
> `index-history=strict` (D18). S-EpochCommitment is **not** blocked on S-RustCrypto (D7): it
> holds the `S`/`C` preimage locally, so the unpatched `Verifier::verify_digest` seeded with those
> bytes suffices (mirrors `index_trust.rs:547`), R3-g.

- **S-EpochCommitment — the index-gate epoch phase, both impls (D14, D15, D16, D17, D18).**
  A new verification phase in the **index gate** (after parse, before candidate selection),
  producing `Index.epoch_commitment_status: EpochCommitmentStatus`
  (`Unarmed`/`Armed(S, E)`/`ArmingInvalid`). Builds:
  1. **A typed pointer on `Index`** for the new set-once commitment field (D16 — a *new*
     sibling field with its own `OrderKind`, NOT a re-typing of the legacy `attestation-epoch`
     timestamp; unified with `index_ratchet_seam`'s extractor so there is one parse site, not two).
  2. **A sidecar acquisition path** for the commitment's Rekor-anchored bundle **and the
     enumerated set `S`** — the same content-addressed fetch+cache class as `index.kdl.bundle`
     (D15/D17; sized like S-Acq's bundle store). **Composed** verification (Fulcio cert-chain +
     DSSE + Rekor inclusion, against the re-arm signer identity) of the commitment over `S`,
     checking `hash(S)==C` with the D16 canonical construction — **not** inclusion-proof-only,
     which is forgeable (D15). `E` := that verified entry's `integratedTime`. A failed
     verification (`hash(S)!=C`, bad inclusion, or wrong signer) ⇒ `ArmingInvalid` ⇒ abort via
     **`TNG-INDEX-EPOCH-COMMITMENT-INVALID`** (index family), **once** per resolve, before any
     candidate is selected (R4 precedence). `Unarmed` (no field) is the natural default.
  3. **The D18 co-requirement check:** if the index is `Armed` and `entry-trust=strict`, assert
     `index-history=strict`; otherwise a config error (the commitment's `SET_ONCE` uniqueness is
     unenforced under `index-history=warn`). Add the config-error slug/diagnostic.
  *Test:* index-level unit matrix — {Unarmed, Armed(valid), ArmingInvalid(bad-inclusion),
  ArmingInvalid(bad-cert/DSSE), ArmingInvalid(`hash(S)!=C`)} — mirroring the Layer-1
  `test_index_trust` composition; a bad Rekor proof or wrong signer must NOT verify; plus the
  Armed+strict+`index-history=warn` ⇒ config-error row (D18).
  **Cross-repo prerequisite (the one slice with a hard tianguis dependency):** tianguis must
  build commitment emission over the enumerated `S` (with a **dry-run/diff of `S`** as an
  acceptance criterion — the existing timestamp-only tool cannot do this) and re-arm the
  production epoch from timestamp to the new `(C-over-S, Rekor-anchor)` sidecar field (§8c cost)
  — coordinate before this slice.

- **S-EpochGate — the per-entry membership predicate, both impls (D14, D17).**
  `EpochMembership` per candidate, read from `Index.epoch_commitment_status`: when `Armed`,
  pre-epoch (**`identity ∈ S`**, the verified enumerated set — D17) ⇒ warn, else `PostEpoch`
  (`∉ S`) ⇒ mandate; when `Unarmed` ⇒ warn-equivalent (D11). Membership is a set lookup against
  the already-verified `S` (both membership and non-membership are decided locally — no proof,
  no recompute-drift). Composed into the gate return via `EntryGateOutcome` (D9), with pinned
  per-outcome remediation prose (`PostEpoch`-mandate: "not in the registry's committed pre-epoch
  set, so it must carry an attestation"). No `published_at`-onto-`_Candidate` plumbing (the prior
  draft's 9 sites are **dropped**). Identity = `(namespace, name, version, content_hash)`
  byte-exact per S2 (D16 hygiene) for cross-impl determinism.
  *Test:* impl-level unit matrix — {PreEpoch, PostEpoch, Unarmed} × {warn, strict} ×
  {attested, unattested}, both impls, against **synthetic** `EpochCommitmentStatus` fixtures (no
  tianguis needed); **plus** a fresh-clone/ephemeral-CI case (no `~/.cache/milpa`) proving
  classification succeeds with zero dependency on `index_ratchet_seam`'s baseline sidecar (br7 —
  the "unify the parsers" instruction must not leak a baseline-file dependency into the gate), and
  a workspace-resolve case exercising classification on a member-pulled registry dep (br9). The
  `PreEpoch`-under-strict ⇒ warn row is the one S7 later needs as a real-crypto fixture.

- **S-RustCrypto — complete Rust Layer-2 real crypto (D7).**
  Extend `.vendor-sigstore` per D7's corrected shape: **extract the ~90-line
  `verify_digest` body parameterized over digest source (`&[u8]` vs `Sha256`),
  exposed on both the async and `blocking::Verifier`** (additive, two-file — *not*
  the subtractive #183 shape). Wire `SigstoreEntryVerifier::verify` stages 5–7 (cert
  chain + DSSE signature + Rekor inclusion via the already-built
  `rekor_adapter::verify_entry_inclusion`) for real; delete the unconditional
  `SignatureInvalid`. File the upstream tracking issue + forcing-function tripwire.
  *Test:* the Rust real verifier verifies a real bundle Trusted and rejects the
  round-1/round-2 negative vectors (mirroring the Layer-1 `test_index_trust`
  suite); no real per-entry bundle path returns a false `SignatureInvalid`.

**Conformance (fixtures exist before the flip proves them):**

- **S6 — real-crypto strict-PASS fixtures, both axes.**
  Mint fresh per-entry bundles via a `generate-attestation-fixture`-style workflow
  over *synthetic* known subjects (`{name: pkg:tianguis/<ns>/<name>@<v>, digest:
  <hex of a test content_hash>}`) — **not** promoted-from-backfill (a live backfill
  bundle is bound to a real package's real bytes and cannot drop into a synthetic
  fixture; and cross-impl byte-identical sharing of *real crypto* is infeasible, so
  these live in the **per-impl real-crypto tier**, not the shared mock corpus —
  matching the Layer-1 `_oracle/attestation/` precedent). A post-epoch entry with a
  valid author-signed bundle verifies and resolves under strict; the lockfile
  records the claim; an index with a valid whole-index bundle passes index-trust
  strict.
  **Two round-2 prerequisites, both blocking S6 build-start:**
  (i) **Signer-toolchain parity.** The existing precedent workflow signs with
  `cosign attest-blob` (Go); production per-entry bundles come through tianguis via
  **sigstore-python `sign_dsse`**. Go-cosign and a Python DSSE signer can emit
  byte-different envelope serializations (field order, `keyid`) — the exact #183
  class of bug, and milpa's documented differential blind spot
  ([[testing_differential_blind_spot]]). **Read tianguis's `sign_statement.py`
  first** and mint S6/S7 fixtures with the *same* signer production uses; state which
  in the slice. If they can't be reconciled in-repo, S6 needs a tianguis-side minting
  workflow (a cross-repo dependency, out of milpa's `/tdd` loop). **Round-3 addition:**
  signer parity extends to the **arming-commitment** bundle (D15) — a *third* artifact type
  with the same cosign-vs-`sign_dsse` byte-serialization risk and no tianguis minting path
  today; include it in the "read `sign_statement.py` first" prerequisite.
  (ii) **Subject-NAME binding is verified against production, not just self-minted.**
  Synthetic per-impl fixtures mint *and* verify with milpa's own naive purl format
  string — a construction mismatch against tianguis's real minting is structurally
  invisible to them. Add one real fetch+verify against the live tianguis registry
  (2898 backfilled entries) exercising the NAME half of subject binding, before S4
  flips (this also discharges §8a). The mint step itself is a manual,
  live-infra (OIDC/Fulcio/Rekor), **Corey-gated** `dispatch → download → commit`
  prerequisite — not part of the automated RED-GREEN loop (matching how the Layer-1
  `index.kdl.bundle` fixtures were produced); committed bundles then replay fully
  offline (verified against their own `integratedTime`, not wall-clock).
  *Test:* green in both impls (per-impl, not byte-identical-shared).

- **S7 — real-crypto strict-FAIL matrix.**
  Post-epoch unattested ⇒ fail; wrong-signer ⇒ fail; bundle-pin-mismatch ⇒ fail;
  bundle-unfetchable-under-strict ⇒ fail (D2); **pre-epoch legacy unattested ⇒
  warn, not fail** (needs S-Epoch); index-trust strict with a missing/forged
  whole-index bundle ⇒ fail. State per fixture whether it reuses a minted PASS
  bundle unmodified, is derived by byte/parameter tampering, or is cross-wired from
  two minted bundles — most FAIL vectors derive from one minted bundle
  (the Layer-1 `test_s5_real_bundle_wrong_signer` precedent), only genuinely
  different-signer vectors may need a second minted identity. If the live index has
  **no** genuine pre-epoch-unattested entry to source the warn row from, use a
  frozen synthetic pre-epoch snapshot (do not silently downgrade the row to
  mock-only). **Round-3 addition (D14/D15):** under D-Watermark the `pre-epoch ⇒ warn` row
  requires a valid **arming-commitment sidecar** over the frozen synthetic set (so the
  `EpochCommitmentStatus` is `Armed` and membership actually resolves `PreEpoch`) — a
  `published_at` field alone can no longer produce it; that commitment bundle is minted via the
  same Corey-gated live-infra step as S6 (and via the same signer toolchain — signer parity
  extends to this third artifact type). Add an **interregnum** fixture pinning F-op's chosen
  semantics (an entry published after 2026-07-12 but before re-arm classifies per the decided
  rule). *Test:* each fixture's `expected/error` (or warn) matches per impl.

- **S-Backdate — RE-SCOPED by round 3 (D8/H2); the epoch-boundary purpose is subsumed.**
  D-Watermark's own `ArmingInvalid` fail-closed already closes the epoch-boundary backdate
  dodge (a post-arming identity added to the committed set makes the commitment check fail).
  So this slice's original justification is gone. **Before building anything, decide** whether
  the `§3.5.4` publication-watermark check has a *distinct, non-epoch-boundary* purpose (general
  `published_at` chronological-consistency auditing as informational metadata). If **yes**:
  build it narrowly framed as audit hygiene (not "the epoch defense"), add `TNG-ENTRY-BACKDATED`
  (bijection stays green), and record the axis binding. If **no**: retire the slug and let S1
  retire the `registry-protocol.md:1675` dangling forward-reference by *deletion* — do not build
  a weaker, already-subsumed check. Do **not** silently flip a third default. *Test:* per the
  chosen disposition.

**Flip + close:**

- **S4 — flip both defaults + corpus migration (R3, D1, D4).**
  Update the §3.4.0 SSOT table + effective-policy prose; flip both impls' default
  constants (`manifest.py:743/824/1281`, Rust equivalents).
  **CRITICAL — the "corpus green" test is a false positive as currently designed
  (feasibility-verified).** The conformance harness
  (`test_conformance.py:_fixture_entry_trust_config`, Rust
  `runner.rs:fixture_entry_trust_config`) returns `None` — gate never constructed —
  when a fixture declares *neither* a manifest field *nor* the env var, keyed on
  `entry_trust_policy_explicit`, **not** on `effective_trust_policy`. So flipping the
  default constant leaves every non-explicit fixture with the gate still disabled;
  "full corpus green" would pass **without ever exercising the new default**, hiding a
  real default-plumbing/S-Epoch bug. **S4 must change this carve-out's trigger to
  exercise `effective_trust_policy`'s real output for non-explicit fixtures (both
  impls), or add a companion prove-the-default test — before "corpus green" counts as
  proof of the flip.**
  **The migration is ~228 fixtures, not "~70+", and it is index-trust-shaped, not
  entry-trust-shaped** (feasibility-measured: 267 fixtures carry an `index.kdl`; 228
  have no `.bundle` sidecar and no policy pin). Two different-shaped jobs:
  (a) **entry-trust — mostly free.** Fixtures whose `index.kdl` declares no
  `attestation-epoch` classify no-epoch-armed ⇒ warn-equivalent under strict (D1),
  needing zero per-fixture edits once S-Epoch lands — verify, don't hand-edit.
  (b) **index-trust — a near-mechanical bulk pin.** D4 has no epoch exemption, so all
  ~228 hard-fail under strict unless each gets `index-trust "warn"`, a real bundle,
  or is under-test-otherwise; scriptable as a single codemod pass, not 228 hand-edits.
  *Test:* the effective-policy unit tests assert `strict` defaults; the harness
  actually invokes the strict default for non-explicit fixtures; the full corpus is
  green post-migration.

- **S5 — impl reconcile: `milpa verify` + `milpa show` under strict defaults
  (R8, R10; D12).**
  Wire the D6 remediation hints; upgrade `milpa show` per-policy wording **scoped
  same-invocation (D12)** — "verified-at-resolve" only right after strict
  `fetch`/`lock`/`verify`; cold `show` of a pre-existing lockfile keeps "claims".
  Ensure `milpa verify` offline re-verification honors the new defaults (R10 §5.4)
  and carries its **own** remediation, since `verify` cannot self-heal (does not
  fetch): a lockfile minted under the old `warn` default has no cached bundle, so the
  first post-flip `verify` fails `BUNDLE-MISSING` with no way to recover in-command —
  the hint MUST name "run `milpa fetch` to acquire, then re-verify" (distinct from the
  fetch-path `unfetchable`/`no-pin` split; this is the concrete migration break for
  real users' existing lockfiles). Add a **`no-epoch-armed` observability notice**
  (Dsgn-H2): a one-time informational line when effective policy is `strict` but the
  loaded index carries no `attestation-epoch` — otherwise strict silently degrades to
  warn with zero signal (false confidence). Surface epoch-arming + entry-trust state
  in `show`'s existing `--index-trust`-style observability block (a minimal
  `show --entry-trust` parity, or record the deferral explicitly — not silent
  absence). **Round-3 additions:** (i) state whether `verify` **re-derives**
  `EpochMembership` against the pinned local index snapshot (idempotent, safe) or trusts the
  lock-time claim — and if re-deriving, test the case where the cached index was replaced by a
  newer fetch between lock and verify (M1). (ii) the no-epoch-armed notice must distinguish its
  two real audiences (br10): a flagship-registry consumer mid-transition ("attestation is
  rolling out") vs. a self-hosted operator who never adopts it ("you have not enabled
  attestation") — both are `Unarmed` but warrant different guidance. *Test:* per-impl tests for
  each policy × epoch-class × command outcome, including the pre-flip-lockfile `verify`
  regression, the verify re-derivation case, and both no-epoch-armed notices.

- **S8 — differential: attestation surface in the harness.**
  Confirm the mock-seam entry-trust + index-trust fixtures flow through
  `harness/` divergence detection (likely already generic — `discover_fixtures`
  has no allow-list; verify, don't rebuild); add real-crypto-mode differential
  once S-RustCrypto lands so both real verifiers report identical slugs on the
  shared multi-fault vector (the S5.5 precedent). **Both impls are fed the same
  committed trust-root fixture** (D13: the root is a verification *input*, not part of
  the impl), so "identical verdicts" is unconditional and any divergence is a genuine
  logic bug — no trust-root allow-list. (Confirm sigstore-python's `Verifier` accepts
  an offline `TrustedRoot` fixture, else inject the fixture root at the verifier seam.)
  *Test:* `harness/test_divergence_detection` covers the attestation surface; zero
  divergence against the fixed root.

- **S9 — cleanup + doc reconciliation (R9).**
  `comparison-vs-nimble-atlas.md`; check off `rfc-per-entry-attestation.md` /
  `rfc-attestation-verifier.md` status boxes (P3b/P4 done); annotate/close #182,
  #184/#185; note #183 (→ sigstore-rs#608) and sigstore-rs#285 and the new Rust
  Layer-2 upstream issue as delete-when-upstream, **each distinct**; file the
  break-glass follow-up issue; **add a superseded-pointer to
  `rfc-registry-trust-federation.md` §6.1** (its old `"warn"` default + old
  "flip once all packages covered" criteria are superseded by this RFC's D4/S4 and
  the epoch mechanism); **add the one-line self-hosted-registry `index-trust "off"`
  migration note** (D11); cross-link **D-Watermark to residual #187** (witnesses/gossip
  are the split-view ceiling D-Watermark degrades to, already deferred) and file the
  D-Watermark commitment format + **production epoch re-arm** (timestamp → new `(C, Rekor)`
  set-once sidecar field, D16) as a tianguis-side tracking issue coordinated with
  S-EpochCommitment — **with explicit acceptance criteria (round-3): (1)** a dry-run/diff of the
  committed pre-epoch set before Rekor-logging it (the existing timestamp-only tool cannot do
  this, br6); **(2)** the interregnum set-membership rule (F-op); **(3)** the commitment signer
  toolchain matches S6's (signer parity). Also: **do not advertise entry-trust strict as
  protecting the flagship registry until the re-arm is confirmed live** — until then the live
  registry is `Unarmed` ⇒ warn-equivalent, so R9/`comparison-vs-nimble-atlas.md` must state
  day-one entry-trust strict is a policy-shape change, not yet a live-registry protection change
  (br3). Add the `TNG-INDEX-EPOCH-COMMITMENT-INVALID` slug to `errors.md` (bijection stays
  green). Cross-link **D-Watermark to residual #187**. Update [[v1_critical_path]] memory with
  the corrected cost (three builds + the split epoch slices + D-Watermark re-arm, not
  reconciliation).

## 7. Contract to exit Stage 1

S1–S3 are spec-only. S-Acq/S-EpochCommitment/S-EpochGate/S-RustCrypto are the builds, each
single-surface and independently testable, landing before the flip. S6/S7/S-Backdate
are coverage. S4/S5 flip the specified defaults over a migrated corpus. S8 is
differential; S9 is doc + issue hygiene. No slice spans more than one conceptual
change. The premise is honest (§1), the scope is both-axes-strict + the builds,
and the round-1 forks (v1 scope shape; index-trust flip) are resolved. Rounds 1–2 are
applied (§8 ledgers). **Architect round 3 — the first adversarial review of D-Watermark
itself** (it entered via dialogue after the round-2 team ran) — applied the
mechanism-agnostic hardening: D14 (split `EpochCommitmentStatus`/`EpochMembership` + new
index-family slug), D15 (composed-crypto + sidecar commitment; inclusion-proof-only is
forgeable), D16 (namespace in identity; re-arm as a new set-once field, not a timestamp
mutation; hash hygiene), the S-Epoch split into S-EpochCommitment/S-EpochGate, the
S-Backdate re-scope, and R12/R13. Its two forks — F1 (pre-epoch membership
representation) and F2 (whether malicious-registry-safety requires flipping `index-history` to
strict) — were escalated per the standing order and **resolved by Corey (2026-08-04)**: F1 →
enumerated committed set `S` (D17); F2 → arming requires `index-history=strict` as a scoped
co-requirement, not a default flip (D18); F-op → grandfather-all-at-re-arm. Both were *forced by
structure* (the search for a "something else" found only the deferred #187 ceiling), and they
compose into one mechanism (§8c "Round-3 escalations — RESOLVED").

**`/tdd` gating:** all slices are unblocked. **S-EpochCommitment** additionally needs the
tianguis re-arm coordination (commitment over `S` + `index-history=strict` production posture)
before it can go green; every other slice, including S-EpochGate (synthetic-status fixtures), can
proceed. Note: throughout the *spec prose*, "watermark" is reserved for §3.5.4's publication
watermark; the mechanism is written as "the (pre-epoch) epoch commitment" (the decision-record
label "D-Watermark" is retained only as an internal reference).

## 8. Open items

**Round-2 items all closed; round 3's reopening of the D-Watermark mechanism is now resolved.**
The round-2 open items (a/b/c) are resolved (below). Round 3 — the first adversarial review of
D-Watermark — applied the mechanism-agnostic hardening (D14–D16) and escalated two mechanism
forks + one operational choice, all now **RESOLVED** (Corey, 2026-08-04): **F1 → enumerated
committed set `S` (D17); F2 → arming requires `index-history=strict` (D18); F-op →
grandfather-all-at-re-arm** (§8c "Round-3 escalations — RESOLVED"). No open items remain; `/tdd`
is unblocked (S-EpochCommitment still needs tianguis re-arm coordination before it can go green).

**Discharged in round 2 (folded into slices/decisions):**
- **(a) — subsumed and *sharpened*.** The real risk was never only network plumbing:
  it is a semantic contract mismatch on the one new Layer-2 field (subject **name**),
  invisible to synthetic self-minted fixtures because milpa mints and verifies with
  the *same* format function. Now a hard prerequisite in S6 (signer-toolchain parity +
  one real fetch+verify against live tianguis exercising the NAME half) that must
  clear before S4.

**Resolved in round 2 (was mis-posed as a fork):**
- **(b) Cross-impl trust-root parity — resolved by parameterizing over the root, not
  by pinning or allow-listing.** The earlier framing (byte-identical differential *vs*
  live revocation) was a false trade-off born of treating the trust root as part of the
  *implementation*. A trust root is an **input** to verification (a verdict is always
  "valid *relative to* this root"); you never claim identical outputs while feeding two
  impls different inputs. **Resolution (D13):** the differential corpus supplies **one
  committed trust-root fixture to both impls**, so the "identical verdicts" guarantee is
  unconditional and any divergence is a genuine logic bug — no allow-list. Production is
  a separate code path: each impl uses its native live root (Python's runtime TUF root
  keeps auto-propagating revocations — correct security posture — and Rust's committed
  root is a Rust-side hardening item, out of scope here). This gives *both* the
  byte-identical guarantee and live revocation; the S6/S8 "identical" claim is honest
  without qualification. (Impl detail for S8: confirm sigstore-python's `Verifier` can
  be constructed against an offline `TrustedRoot` fixture — expected, is how offline
  verification works — else the fixture root is injected at the verifier seam.)

**(c) RESOLVED — D-Watermark adopted (Corey, 2026-08-04): Rekor-anchored pre-epoch
set commitment supersedes `published_at` classification.**

Round 1 reserved this; round 2 escalated it (it reopens the settled `published_at ≥ E`
classification from the prior `rfc-per-entry-attestation`, open-Q2 resolved 2026-07-09 —
a baked-in assumption); Corey chose to reopen it. `published_at`-based classification is
retired as the trust boundary and demoted to informational metadata.

**Why the choice was binary (no clever third design).** The backdate adversary *is* the
registry (or whoever compromised it). No registry-signed-only artifact defeats it — a
set-once field only protects a consumer already holding the prior value (TOFU-broken),
and a self-signed in-index watermark is signed by the very party doing the backdating.
Defeating a malicious registry **TOFU-safely** mathematically requires an *external*
anchor, and there are exactly three: a transparency log (**Rekor** — milpa already
embeds its inclusion proofs), witnesses/gossip (**#187** — already deferred as a
residual), or the consumer's own history (TOFU-broken). Rekor is the one in hand. So the
only real options were *anchor to Rekor* or *accept the residual*; using the **per-consumer
`published_at` watermark** (§3.5.4) is **dominated** (a TOFU/ephemeral-CI consumer has no
baseline, so it gives no check regardless of policy) and is off the table. (Distinct from D18's
later use of `index-history`: D18 does not resurrect the per-consumer watermark — it uses the
ratchet's `SET_ONCE` order-kind to enforce the *commitment field's* uniqueness, which needs no
per-consumer baseline. The Rekor anchor gives temporal ordering; the ratchet gives set-once-ness;
they are complementary, not alternatives.)

**Mechanism** (round-3 hardened; the pre-epoch set representation is the **enumerated committed
set `S`**, D17/F1 resolved below).
- **At arming:** the registry commits over the frozen set of pre-epoch entry *identities*,
  identity = the stable **`(namespace, name, version, content_hash)`** tuple (D16 — the
  registry's own identity key; **not** the mutable record, so a later legal provenance/mirror
  addition does not disturb the commitment, and **not** the bare `(name, …)` tuple, which would
  admit cross-namespace byte-copy impersonation). `C = hash(domain-sep ‖ canonically-encoded,
  version-ordered, deduped identities)` (D16 hygiene). The commitment is **logged in Rekor and
  authenticated by the full composed pipeline** — Fulcio cert-chain + DSSE signature over the
  commitment statement + Rekor inclusion, against a dedicated re-arm signer identity (D15 — an
  inclusion proof *alone* is forgeable, since Rekor is publicly writable). **`E` is that
  fully-verified entry's Rekor `integratedTime`** — not a free-form operator date. The
  commitment is delivered as a content-addressed **sidecar bundle**, not an inline field (D15),
  and lives in a **new** set-once index field, not a re-typing of the legacy timestamp (D16).
- **At resolve** (the consumer already holds the whole `index.kdl` locally): the **index-gate
  epoch phase** (D14, once per resolve, after parse, before candidate selection) fetches +
  composed-verifies the commitment, yielding an authenticated `(C, E)` and an
  `EpochCommitmentStatus`. Membership is then tested per candidate: entry X is pre-epoch
  (grandfathered → warn) iff its identity is in the verified pre-epoch set; otherwise the
  attestation mandate applies. Attacker adds X to the set ⇒ the commitment check fails ⇒
  `ArmingInvalid` ⇒ abort via `TNG-INDEX-EPOCH-COMMITMENT-INVALID`; adds X outside the set,
  flagged post-epoch ⇒ X is mandated ⇒ cannot dodge.

**Why this shape (it got *simpler* under stress-test, not more complex).**
- **No Merkle inclusion/exclusion library.** The consumer holds the whole index locally, so
  membership is tested directly against the verified pre-epoch set (D17: an `∈ S` lookup against
  the shipped enumerated set) — no sparse-Merkle tree, no per-entry proofs.
  (An earlier "per-entry first-appearance snapshot" framing was discarded: verifying
  "first appeared before E" needs snapshot *history*, reintroducing TOFU. Set membership
  over the locally-present index needs neither history nor proofs.)
- **Round-3 correction — the anchor is Rekor, but set-once-ness needs the ratchet.** An
  earlier draft claimed "no coupling to `index-history` — this *removes* the c1/c2 residual."
  Round 3 (depth C2) falsified that: Rekor gives *immutability of a logged statement*, not
  *exclusivity* — nothing stops a compromised registry logging a **second** valid commitment and
  re-arming, and Layer-1 index-trust passes trivially (it authenticates *current* content, not
  temporal uniqueness). "Only the **first** commitment counts" is a set-once property, and the
  only thing enforcing it in either impl is the `index-history` ratchet's `SET_ONCE` order-kind.
  So the guarantee **is** `index-history=strict`; F2 (resolved, below) makes that a scoped
  co-requirement of arming. The Rekor anchor still supplies TOFU-free temporal ordering; the
  ratchet supplies uniqueness. Together they are TOFU-safe and malicious-registry-safe up to
  **log/registry equivocation** (witnesses/gossip, #187 — the deferred ceiling).

**Classification shape (round-3 corrected — D14 splits the discriminator).** The five
`published_at` branches are replaced not by one four-value `epoch_basis` but by two types: an
index-scoped `EpochCommitmentStatus` computed once (`Unarmed` ⇒ warn-equivalent, D11 /
`Armed(C, E)` / `ArmingInvalid` ⇒ fail-closed via `TNG-INDEX-EPOCH-COMMITMENT-INVALID`, since a
tampered commitment is an index-integrity fact, not a per-entry one), and a per-entry
`EpochMembership` read only when `Armed` (`PreEpoch` ⇒ warn / `PostEpoch` ⇒ mandate). See D14.

**Residual corners — all bounded or pre-existing:**
- **Rekor dependency at the resolution layer.** Scoped to registries/consumers *already*
  all-in on Sigstore: epoch classification touches Rekor only when `entry-trust=strict`
  **and** a commitment is armed; everyone else is `no-commitment-armed ⇒ warn-equivalent`
  (D11) and never consults Rekor. Offline-embedded (no runtime call). Reversible — `C` is
  log-agnostic and could later be re-anchored to sigsum/witnesses.
- **Arming mistake — narrow, per-entry (resolved by F1=b).** An arming-time omission of a
  legit entry from `S` fails-closed for that **one** entry (mandated) — inherent to any
  epoch/cutover; the timestamp epoch had the identical property; mitigated by tianguis's
  dry-run/diff of `S` before logging (S9 acceptance criterion). Under the resolved enumerated-set
  design there is **no** registry-wide blast radius from benign resolve-time drift: `S` is a
  frozen, explicitly-committed set verified as a unit (`hash(S)==C`), and membership is a lookup
  `identity ∈ S` derived from *nothing mutable* — a later legitimate attestation-backfill on an
  old package does not change `S` and cannot trigger a global abort. (This was the crux of fork
  F1; the earlier "recompute over pre-epoch-flagged local entries" framing, which *did* have the
  global-drift failure mode, is retired.)
- **#187 split-view/equivocation.** Shared by every tier including "do nothing," already
  deferred; strictly better here than `published_at`'s zero protection.

**Cost accepted:** re-arm the already-live production epoch
(`attestation-epoch "2026-07-12T00:00:00Z"` is a timestamp; D-Watermark wants a new
`(C, Rekor-anchor)` sidecar in a new set-once field — D16) and a tianguis-side obligation to
emit the pre-epoch set commitment at arming (with a **dry-run/diff of the committed set** as an
acceptance criterion — the existing tianguis tool only writes a timestamp, so this mitigation
does not exist yet, R3-j). Sequencing, not design risk — **must be settled before
S-EpochCommitment, not before S1.**

### Round-3 escalations — RESOLVED (Corey, 2026-08-04): F1→enumerated set (b), F2→scoped co-requirement (a)

Round 3 was the first adversarial review of D-Watermark itself. It applied the
mechanism-agnostic hardening (D14–D16) and escalated two findings that reopened the mechanism.
Corey asked whether there was a *clear best-in-class* design or "something else"; the search for
a "something else" (Merkle set-commitments with inclusion/exclusion proofs; per-entry Rekor
log-position; TOFU pinning; "earliest-matching-entry-in-the-log"; witness cosigning) showed
every candidate either collapses into a listed option or is the deferred #187 ceiling. Both
forks are **forced by structure, not preference**, and compose into one mechanism.

- **F1 — pre-epoch membership representation → RESOLVED: (b) enumerated committed set (D17).**
  The load-bearing fact: **pre-epoch entries have no independent transparency-log footprint**
  (they predate the mandate, so no per-entry Rekor entry / `integratedTime` / signature exists
  for them). This kills every temporal-anchor design: you cannot classify a legacy entry by "its
  own log position < E" (never logged), and a Merkle root with per-entry inclusion proofs is
  worse — legacy entries carry no proof, and you would *also* need **non-membership** proofs to
  stop a post-epoch entry claiming grandfathered status, forcing the sparse/sorted-Merkle
  machinery D-Watermark rejects. So the grandfathered population **must be explicitly enumerated
  and committed at arming** — unavoidable. Given that, the elegant move is to commit the whole
  small **frozen set `S` directly** (`C = hash(S)`, `S` shipped as the content-addressed sidecar
  of D15): the consumer already holds the entire index, `S` (~2898 identities, frozen, never
  grows) is strictly smaller than data it already downloads, and holding all of `S` locally gives
  **both** membership (`∈ S ⇒` warn) **and** non-membership (`∉ S ⇒` mandate) for free, with zero
  proof machinery, no per-entry schema, no circularity, TOFU-safe. **(a)** (per-entry frozen
  flag) has the identical trust model but scatters the enumeration across mutable schema and
  reintroduces recompute-drift — strictly dominated. **(c)** (append-order cutover) is only
  simpler if an *authenticated* monotonic ordering exists — which is itself an
  `index-history=strict` property, not available in the default config — and even then is a
  *special case* of a set commitment (the set "first N") that is more fragile. `(b)` is the floor
  of honest design. The drafted "recompute `C'` over pre-epoch-flagged local entries" is replaced
  by "**verify the shipped set `S` (`hash(S)==C`, composed-verified, Rekor-anchored), then test
  `identity ∈ S`**."

- **F2 — set-once enforcement → RESOLVED: (a) scoped co-requirement (D18).** The reframe that
  dissolves the "is this scope creep?" tension: **the epoch commitment and the append-only
  ratchet are one security mechanism artificially split across two knobs.** Defeating a re-arm
  equivocation *offline* and *TOFU-free* is achievable only via an append-only-with-consistency
  guarantee: "earliest matching entry in Rekor" is not offline-verifiable (Rekor proves inclusion
  + consistency, not "earliest-with-this-predicate," and the registry mediates which proofs the
  consumer sees); witness cosigning defeats it but *is* #187, deferred. milpa already has exactly
  one append-only-consistency mechanism — the `index-history` ratchet's `SET_ONCE` — and it is
  the only thing enforcing "first commitment wins." So the guarantee **is** `index-history=strict`
  — it is not strengthened by it. Therefore **arming an epoch commitment with `entry-trust=strict`
  REQUIRES `index-history=strict`** (else a config error), because a `SET_ONCE` field whose
  set-once-ness nobody checks is a nonsensical configuration. This is a **coupling invariant, not
  a blanket flip**: it does **not** change the `index-history` *default* (§3 non-goal preserved) —
  a registry that arms no commitment stays warn-equivalent, index-history untouched. Option (c)
  (leave it warn, downgrade the claim) is the only choice that ships D1's headline
  "malicious-registry-safe" as a documented footgun; rejected.

- **F-op — interregnum set membership → RESOLVED: grandfather everything present at re-arm.**
  The re-arm commits `S` over every entry present at re-arm time (the 2898 + the ~3-week
  interregnum), so the flip is non-breaking for good-faith un-attested publishers; the mandate
  applies only to entries published *after* re-arm. S7 fixture pins this.

**The composed decision (D17+D18).** The pre-epoch epoch commitment is a frozen enumerated set
`S`, committed as a Rekor-anchored, composed-verified, content-addressed **sidecar** in a **new
set-once field**; classification is `identity ∈ verified S`; and **arming it requires
`index-history=strict`** so the set-once field's uniqueness is actually enforced. The strictly
stronger design (witness/gossip cosigning surviving even a colluding log) is #187, correctly
deferred as the ceiling. These resolutions are reflected in D1 (claim corrected), the Mechanism
above, S2/S-EpochCommitment, and the §3 non-goal note.

**Supersession.** Wherever this RFC still describes classification via `published_at ≥ E`
(D1, D5, **D8**, S2, S3-step-5, S-Epoch/S-EpochCommitment/S-EpochGate, **S-Backdate**, S7,
R2/R4), **D-Watermark governs**; `published_at` remains informational metadata only, and the
epoch-boundary backdate defense is subsumed by D-Watermark's own `ArmingInvalid` fail-closed
(so S-Backdate survives only for a distinct non-epoch audit purpose — D8). D1/D5/D8/S-Epoch
carry inline supersession pointers; S2/S3/S7/deltas inherit this statement. All three round-2
open items (a discharged, b resolved D13, c resolved D-Watermark) are closed; **round 3 adds
D14–D18 — D14–D16 mechanism-agnostic, and D17 (F1 → enumerated set `S`) + D18 (F2 →
`index-history=strict` co-requirement) resolving the two escalated forks (above).**
