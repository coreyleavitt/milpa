# RFC: per-entry attestation & author-attribution (registry trust, Part 2)

**Status**: Draft — design decided at sketch level; **amended 2026-07-09**
resolving open question 1 (delivery: content-addressed pinned sidecar, §7) and
open question 2 (`strict` criteria: epoch-based, underwritten by
`rfc-registry-append-only.md`). The amendment deltas pend one architect review
round, scoped jointly with the append-only RFC. P1–P3a are unblocked committed
scope; the real-crypto tail (P3b, P4) is blocked only on the tianguis delivery
*implementation* (cross-repo prerequisite issue). Tracking issue: #184.
**Author**: Corey Leavitt
**Part 1 (landed)**: `docs/rfc-registry-trust-federation.md` — whole-index attestation
gate, #103 (committed `66f00ff` review-fixes + `25bc246` root-scoped redesign).
**Completion arc (landed)**: `docs/rfc-attestation-verifier.md` — real Sigstore
verifiers in BOTH impls (see "What already exists" below).
**Adjacent**: #91 (publisher-side self-mirror declarations — the availability surface).

## Why this RFC exists

Part 1 gives milpa a verified trust channel to the tianguis index: before any claim
in `index.kdl` is trusted, the whole file is cryptographically verified (keyless
Sigstore/cosign, DSSE + Rekor, offline) against the tianguis vendor-bot workflow
identity. That closes the *integrity* question — "was the index tampered?".

It does **not** answer the *attribution* question — "who signed **this specific
version** of this specific package?". Part 1 proves the vendor-bot assembled the
index; it says nothing about whether `foo@1.4.2` was published by foo's actual
author versus vendored-in-absentia by the bot. Layer 2 surfaces and (optionally)
gates that per-entry author identity.

**The load-bearing distinction: attribution ≠ integrity.** Layer 1 already
cryptographically covers every byte, so Layer 2 adds *no additional tamper
resistance to the index document*. Its value is accountability — a human-auditable,
machine-checkable answer to "who vouched for this artifact", and a policy knob to
refuse unattested or wrong-signer entries. That is why it was deferred out of
#103: it is genuinely additive, not a safety hole in Layer 1.

## Threat model — what the gate does and does not stop

Stated up front because the two attestation kinds have **asymmetric value**, and
pretending otherwise would oversell the gate:

- **`author-signed` entries are where Layer 2 earns its complexity.** Fulcio
  binds the per-entry cert to a real OIDC identity the vendor-bot does not
  control. A compromised or buggy bot **cannot fabricate** a valid
  `author-signed` bundle for a package whose author never signed it — the gate
  detects mis-attribution structurally, not by trusting the bot. (This claim
  holds only because the subject binds *package identity*, not just content —
  §1. A digest-only subject would be defeated by **replaying** another
  package's genuine bundle: `content_hash` is name-independent, so a
  byte-identical republish under a different namespace would inherit the
  original author's valid signature.)
- **`milpa-vendored` entries add no compromise resistance.** The expected signer
  is the same vendor-bot identity Layer 1 already trusts; a compromised bot is
  the legitimate signer and passes both layers. The per-entry check on vendored
  entries is a *bug ratchet*, not a security boundary: it detects non-malicious
  index-assembly skew (an entry whose `content_hash`/provenance drifted from
  what was attested at publish time, while the stale bundle is still served).
- **Stripping is the trivial warn-mode bypass.** An adversary who controls what
  the bot writes can simply omit the attestation record → the entry is
  *unattested* → under the default `warn` policy resolution proceeds with a
  warning. Layer 2 under `warn` is therefore an **observability feature**, not a
  gate; it becomes a gate only under `strict`, whose adoption criteria are open
  question 2.
- **No rollback/continuity protection in Part 2.** Nothing detects "this package
  used to be author-signed and is now vendored/unattested" across index updates
  (a targeted downgrade or republish). A monotonicity ratchet, like the
  independent owner registry, is Part-3 territory (open question 3).

Compromised-vendor-bot recovery remains a tianguis ops concern (Part 1 §3.4);
Part 2 narrows the blast radius for author-signed packages only.

## What already exists (the substrate this builds on)

Deliberately reusable — Layer 2 should not re-invent any of it:

- **Real offline verifiers in BOTH impls — shipped.** The attestation-verifier
  completion RFC landed real `SigstoreVerifier`s end-to-end: sigstore-python in
  the Python impl; in Rust, vendored sigstore-rs 0.14.0 with the DSSE
  envelopeHash fix (`.vendor-sigstore` + `[patch.crates-io]`; upstreaming
  tracked in #183). Both verify a real cosign bundle Trusted offline —
  cert-at-`integratedTime`, DSSE, Rekor inclusion proof + checkpoint. Nothing
  rides `MockVerifier` in production; `TNG-INDEX-VERIFY-UNSUPPORTED` is deleted.
- **The verify/enforce split + injected-verifier conformance seam.** The *split*
  extends directly to per-entry bundles; the concrete `IndexBundleVerifier`
  Protocol does **not** — it is one bundle, one pinned expected signer, one
  freshness window, called at index load. Per-entry verification needs N calls,
  per-kind expected-signer derivation, and a selection-time call site; §"Verifier
  seam" below specs the revised seam rather than pretending the signature reuses.
- **`TrustPolicy` + `effective_trust_policy` SSOT** (`warn`/`strict`/`off`,
  env/flag layering). Layer 2 reuses the *mechanism* on its own axis (decided
  below — not the `index-trust` axis).
- **Offline re-verification pattern.** `reverify_cached_index(url, cache_dir,
  config, verifier)` (Sv slice) re-verifies the cached index bundle from
  `milpa verify`, crypto-only, never fetching. Per-entry re-verification reuses
  this exact shape over cached per-entry bundles.
- **Chained trust.** Because Layer 1 has verified the whole index, the
  `signed_by` identity carried in each version node is trustworthy *input* —
  Layer 2 uses it as the **expected signer** for real per-entry bundle
  verification, without a separate owner registry. What chained trust does NOT
  give: independence from the bot's attribution claims (threat model above;
  owner registry is Part 3).

## Design

### 1. Attestation subject: package identity + `content_hash` (normative)

The per-entry DSSE statement's in-toto subject **MUST** bind BOTH coordinates
of what is being vouched for:

- `subject[0].digest.sha256` = the hex of the entry's `content_hash`
  (`IndexVersion.content_hash` — spec `identity.md` source-tree hash; note
  the canonical identity scheme is `dag-sha256:<64-hex>`, so the hex MUST be
  extracted scheme-agnostically the way `identity.parse_identity` does,
  never via a hardcoded `sha256:` prefix strip), and
- `subject[0].name` = the package identity,
  `pkg:tianguis/<namespace>/<name>@<version>`.

Verification **MUST** compare both against the *selected entry* — digest
mismatch is `TNG-ENTRY-DIGEST-MISMATCH`, package-identity mismatch is
`TNG-ENTRY-SUBJECT-MISMATCH` — **before** any cryptographic verification,
mirroring the subject-digest-binding precedence clause of
`registry-protocol.md §3.4.4`.

Each half closes a distinct hole:

- **Digest binding** is what makes the attestation mean something at all:
  without it, a *valid, stale* bundle (right signer, right signature) would
  still verify after the entry's `content_hash`/provenance was swapped
  underneath it — reopening per-entry exactly the hole Part 1's digest check
  closes for the whole index.
- **Name binding** closes cross-package replay: `content_hash` is
  name-independent by design, so with a digest-only subject, a byte-identical
  republish of `alice/widget@1.0.0` as `mallory/widget-pro@1.0.0` (same tree ⇒
  same hash, no collision needed) could point at alice's *genuine, public*
  bundle (Rekor is a transparency log) and pass digest, crypto, AND signer
  checks — earning "author-signed by alice" for a package alice never vouched
  for. The name check makes a bundle vouch for one `(namespace, name, version)`
  coordinate, which is the actual attribution claim this RFC exists to deliver.

Binding to `content_hash` + package coordinate (rather than tarball bytes or
index-entry bytes) keeps the design delivery-agnostic, lockfile-recordable, and
stable across index re-serialization.

Legacy entries with an empty `content_hash` cannot reach the gate: selection
already hard-fails them as `TNG-NO-IDENTITY`. And the subject digest is
well-defined per entry regardless of which mirror serves the bytes, because of
an existing invariant worth stating since this design leans on it: every
provenance of one entry yields the same `content_hash` — the identity gate
makes a mirror serving different bytes a hard error
(`registry-protocol.md §3.3`).

### 2. Data model: one optional tagged record, closed kind set

Spec-level, `IndexVersion` gains **one** optional field — not three
independently-nullable ones — so the correlation invariants are structural:

```
EntryAttestation = {
  rekor: RekorRef | None,                  # kind-independent, factored out
  bundle_pin: Sha256Hex | None,            # sha256 of the bundle BYTES — the
                                           # delivery-integrity pin (§7). None
                                           # during the P2 claim-only window →
                                           # the gate reports BUNDLE-MISSING
  kind: AuthorSigned { signer: str }       # signer REQUIRED
      | MilpaVendored,
}
attestation: EntryAttestation | None
```

The **wire format keeps the existing three sibling KDL child nodes**
(`attestation`, `signed_by`, `rekor` — tianguis already emits them; the Nim
`RekorRef` object exists there) **and adds a fourth, `bundle sha256="<64-hex>"`**
— the delivery pin (§7), emitted once per-entry delivery ships (P4). The parser normalizes at the boundary
(parse-to-typed, same pattern as `IndexProvenance`), in `_parse_version_node`
(`registry.py:605`) / `parse_version_node` (`registry.rs:453`).

**Normative forward-compat / conservative-collapse rule:** the kind set is
CLOSED (`author-signed`, `milpa-vendored`). Any other `attestation` value, and
any structurally invalid record (e.g. `author-signed` with no `signed_by`),
**MUST** normalize to *unattested* — an unrecognized or malformed attestation
claim must never verify as attested in an older client. The collapse is
observable (a warning naming the entry), so a vendor-bot bug surfaces instead
of silently degrading. Mechanically that is a small, explicit cross-impl API
change P2 makes at the parse boundary: both impls' version-node parsers are
pure functions today, so the parse step returns *(typed index, collapse
diagnostics)* and the caller threads diagnostics to the warning channel.
Persisted state does NOT distinguish collapsed-from-never-attested — the
Layer-1-verified index snapshot in the cache is the forensic record for "what
did the bot actually emit".

This inverts the four `spec/registry-protocol.md §3.2` tolerate-and-ignore
clauses and retires `test_rekor_block_is_tolerated_and_ignored`
(`test_registry.py:152`; note Rust currently has no equivalent tolerance test —
the inversion adds parse tests to both impls).

### 3. Gate placement: the selection step, after solving (decided)

The gate fires **post-solve, per selected registry-resolved dep** — at the same
lifecycle point as the existing identity check (`TNG-NO-IDENTITY` fires at
selection, not enumeration; `resolve_named`'s docstring already names the
enumeration/selection split). It does **not** run inside candidate enumeration:
`resolve_named_all` (`registry.py:264` / `registry.rs:285`) is the Phase-A
enumerate-ALL-candidates step — `_enumerate_named_stubs` deliberately passes
`constraint=None` so PubGrub sees the full version space.

Filter-at-enumeration was considered and **rejected**:

- Under `strict` it silently steers the solver to older, attested-but-passing
  versions — a silent downgrade with no visible signal that a newer version was
  excluded. A trust policy must fail loudly, not invisibly shape resolution.
- It multiplies cost: one bundle verification per *published version of every
  candidate*, versus one per *selected* dep (N, not N×versions).
- It would have to slot `TNG-ENTRY-*` into the §5.5 candidate-exclusion
  precedence chain (`TNG-NOT-FOUND → … → TNG-NO-SATISFYING-VERSION`), polluting
  solver-space semantics with policy semantics.

Consequence, stated honestly: under `strict`, a failing selected version is a
**hard, late resolve failure** with no automatic fallback — the remedy is an
explicit constraint/pin or a policy change. That is the intended behavior of a
strict trust gate.

### 4. Policy axis: separate `entry-trust`, root-scoped (decided)

Layer 2 gets its **own** configuration axis, `entry-trust` (`warn`/`strict`/`off`,
default `warn`), sharing only the `TrustPolicy` type and `effective_trust_policy`
layering mechanism. Reusing the `index-trust` axis was rejected: it would
silently change the meaning of `index-trust "strict"` for existing users (a
document-integrity opt-in would start hard-failing every unattested entry), and
it would contradict Part 1's own precedent — `attestation-policy` vs
`index-trust` stayed separate axes precisely because "they govern different
things… only the mechanism is unified" (Part 1 §6.6).

This makes **three** trust axes, and the proliferation is deliberate, not
accidental — each governs a different object: `attestation-policy` gates
*dep-metadata* (DepDecl) attestation, `index-trust` gates *index-document*
integrity, `entry-trust` gates *per-entry author attribution*. They fail
independently and are remediated independently, so collapsing any two conflates
unrelated postures. If the flat manifest surface gets noisy, a purely syntactic
`trust { index …; entry …; … }` grouping block is a cosmetic follow-up, not a
semantic merge — out of scope here.

Workspace authority mirrors the Part-1 redesign: `entry-trust` is
**root-scoped** — one shared graph, one trust posture; a member declaring it is
a hard error (`WS-ENTRY-TRUST-ON-MEMBER`, landing with the P3 error-catalog
change). One honest caveat: Part 1's root-scoping was *structurally* forced
(one index document per invocation), while per-entry outcomes are per-selected-
dep — a member owning a security-sensitive dep might legitimately want
strict-for-my-subtree. That granularity question was folded into open question
2 and is **subsumed by its epoch-based resolution** (2026-07-09): epoch scoping
makes universal `strict` adoptable directly, so per-member scoping is no longer
load-bearing for adoption — it survives only as a possible UX refinement. The
root-scoped placement of the knob is decided and unchanged.

**Amendment (`rfc-registry-append-only.md`, applied A1):** the
authority/effective-policy mechanics this section describes for
`entry-trust` — manifest `off` unconditional and manifest-only, otherwise
`max(manifest or "warn", env)`, root-only declaration, and the
member-declaration-error pattern — are no longer specific to this axis.
They are now the generic policy-axis model at `spec/registry-protocol.md
§3.4.0`, instantiated once per axis (`index-trust`, `entry-trust`,
`index-history`) rather than restated per RFC; `entry-trust`'s row in that
section's instantiation table records its manifest node (`entry-trust`),
env var (`MILPA_ENTRY_TRUST`), default (`warn`), and member-error slug
(`WS-ENTRY-TRUST-ON-MEMBER`). This section remains the normative home for
what `entry-trust` verification failure means and how it is remediated;
only the shared authority formula moved.

### 5. Error codes (8 × `TNG-ENTRY-*`) and the gate pipeline

The gate evaluates the selected entry through this pipeline; each stage maps to
exactly one slug, so every code is reachable, every outcome has a code, and a
multi-fault bundle slugs deterministically (first failing stage wins). The
ordering **mirrors Part 1's full effective §3.4.4 order** (malformed → digest →
cert chain/signature → signer → inclusion), not just its digest-before-crypto
boundary — Part 1 just paid (S5.5) to align exactly this class of cross-impl
precedence asymmetry; Part 2 inherits the alignment normatively instead of
rediscovering it:

| Stage | Condition | Slug | warn | strict |
|---|---|---|---|---|
| 0. attestation record | absent / unknown kind / structurally invalid (collapsed) | `TNG-ENTRY-UNATTESTED` | warning | error |
| 1. bundle acquisition | entry is attested but its bundle is unavailable (no pin recorded, or pinned bytes unfetchable) | `TNG-ENTRY-BUNDLE-MISSING` | warning | error |
| 1b. acquisition integrity | fetched bytes' sha256 ≠ the §2 `bundle` pin | `TNG-ENTRY-BUNDLE-PIN-MISMATCH` | **error (unconditional)** | error |
| 2. bundle parse | bundle bytes are not a well-formed Sigstore bundle (pre-crypto) | `TNG-ENTRY-BUNDLE-MALFORMED` | warning | error |
| 3. subject digest | `subject[0].digest.sha256` ≠ entry `content_hash` | `TNG-ENTRY-DIGEST-MISMATCH` | warning | error |
| 4. subject identity | `subject[0].name` ≠ selected `pkg:tianguis/<ns>/<name>@<version>` | `TNG-ENTRY-SUBJECT-MISMATCH` | warning | error |
| 5. cert + signature | cert chain / DSSE signature fails | `TNG-ENTRY-SIGNATURE-INVALID` | warning | error |
| 6. identity policy | cert SAN ≠ expected signer for the kind | `TNG-ENTRY-SIGNER-MISMATCH` | warning | error |
| 7. inclusion | Rekor inclusion proof / checkpoint fails | `TNG-ENTRY-SIGNATURE-INVALID` | warning | error |

NORMATIVE (failure→slug mapping): stages 5 and 7 deliberately share
`TNG-ENTRY-SIGNATURE-INVALID` — mirroring Part 1's cert/signature vs
inclusion collision — and the stage order fixes which fault a multi-fault
bundle reports. Under `warn`, each failing *selected* entry emits exactly one
warning line, deduplicated per `(namespace, name, version)` per invocation.

Expected signer by kind: `AuthorSigned` → the record's `signer` (chained
trust); `MilpaVendored` → **the same *effective* vendor-bot identity Layer 1
resolved** (default SAN + `MILPA_INDEX_TRUST_SIGNER`/manifest override
layering) — normatively NOT a second hardcoded copy of the default, or every
vendored entry on a self-hosted/forked index deployment would spuriously
mismatch. `UNATTESTED` and `BUNDLE-MISSING` are deliberately distinct slugs:
"never attested" and "attested but the proof is unavailable" are different
trust states with different remediations — as are `BUNDLE-MISSING` and
`BUNDLE-PIN-MISMATCH`: "proof unavailable" and "delivery path served wrong
bytes" differ in the same way (the latter is tamper evidence). Stage 1b is
enforced *inside* the artifact store at acquisition time (its one
hash-verify site, the `TNG-DEPDECL-HASH-MISMATCH` precedent — §7), never
re-checked at the gate; the pipeline row states where the outcome slots.
And it inherits that precedent's **full severity model, not just its raise
site**: `TNG-DEPDECL-HASH-MISMATCH` is a security invariant — always a hard
error, never policy-gated — and a bundle-pin mismatch is the same class of
fact (the Layer-1-verified index committed to exact bytes; the delivery path
served different ones — active tampering or serious infra corruption, never
a legacy/rollout state). `entry-trust` gates trust *interpretation*
(unattested / unverifiable / mismatched claims); it never gates transport
integrity. So stage 1b hard-fails under `warn` too — there is no coherent
"warn and proceed" (proceeding on the wrong bytes verifies nothing;
degrading to BUNDLE-MISSING would launder tamper evidence into a routine
availability warning). Stage 1b's payload also carries a `cause`
discriminator on `BUNDLE-MISSING` (`no-pin` — delivery not yet shipped /
legacy entry — vs `unfetchable` — pin present, transport failed), since
those two causes have the different-remediation property this section uses
to justify separate slugs elsewhere; the discriminator rides the payload,
not a new slug.

The eight slugs (plus `WS-ENTRY-TRUST-ON-MEMBER`, §4) land with their raise
sites at **P3**, `spec/errors.md` + `errors.py`/`error.rs` in the same change,
per the error-catalog discipline — NOT at the spec-only P1 slice, because both
impls' bijection lints reject spec slugs with no impl constants, and P3 is
where the raise sites exist. This section is the design SSOT for the list in
the meantime.

### 6. Verifier seam (revised, not reused)

```
EntryBundleVerifier.verify(
    expected_subject,    # {name: pkg:tianguis/<ns>/<name>@<version>, sha256: <hex of content_hash>}
    bundle_bytes,
    trust_bundle,
    expected_signer,     # derived per kind by the CALLER (gate), not the verifier
) -> VerificationResult
```

Differences from `IndexBundleVerifier` (`index_trust.py:221`), all deliberate:
the caller passes the expected *subject* (there are no "index bytes" to hash,
and the name half carries the package coordinate — §1); expected-signer
derivation (pinned vs `signed_by`) stays in the gate so the verifier stays
kind-agnostic; and there is **no freshness parameter**. The no-freshness
decision is derived, not asserted: Part 1's `max_age_seconds` exists because
the index is a *mutable rolling document* — a frozen-in-time index is itself an
attack (serve a stale-but-valid snapshot to hide newer versions). A per-entry
bundle binds an *immutable* subject; there is no newer state it could be hiding,
so a rolling window would only manufacture spurious failures. The residual this
leaves open, named plainly: a once-valid bundle for a later-compromised OIDC
identity verifies forever — offline Sigstore has no revocation, and neither
Part-3 item (owner registry, continuity ratchet) is a revocation mechanism.
That is intrinsic to the keyless model, not a milpa gap to close.

`VerificationResult` and the mock seam extend from Part 1 (`MockVerifier` grows
keyed per-subject outcome scripting — see Conformance); one reuse note: the
enum's stale variant is *structurally unreachable* for entries (no freshness
input exists), stated so the reuse doesn't imply otherwise. Implementation note for
P3, under the audit-for-duplication discipline: the real `EntryBundleVerifier`
shares ~90% of the just-shipped `SigstoreVerifier` internals (parse-once,
singleton assert, digest pre-check, cert+DSSE+SAN policy, rekor-adapter
inclusion) — P3 MUST either extract the shared core or record an explicit
decision not to, not duplicate security-critical code by drift.

### 7. Lockfile, caching, and the offline story

Without this section the gate would evaporate after the first resolve: the
frozen path (`frozen.py`) reconstructs purely from lockfile + CAS and never
loads the index, and today's `*Record` types carry no attestation fields.

- **Lockfile records the attestation CLAIM, never a verification outcome**
  (normative). Each registry-resolved dep's lockfile record gains an optional
  attestation block: kind, signer, rekor `{uuid, log_index, integrated_time}`.
  (The digest half of the subject is already there — the record's `sha256`
  identity IS the attested digest.) Verification results are always
  **re-derived** from the cached bundle at check time, never persisted — a
  stored "verified: true" would be an unverifiable assertion, exactly what this
  arc exists to eliminate. This also makes P2 honest and its schema
  P3-survivable: P2 populates the block with zero crypto ever run, so frozen
  resolves and `milpa show` render it as an **unverified claim** ("claims
  author-signed by X") until P3's gate exists; the wording upgrade, not the
  schema, is what P3 changes. Schema versioning: the block follows the
  `dep_decl` optional-field precedent — no `LOCKFILE_SCHEMA_VERSION` bump
  (both impls' parsers hard-fail on a version mismatch, so a bump would
  force-invalidate every existing lockfile for an additive optional field;
  stated explicitly because the parser behavior makes the choice load-bearing,
  not cosmetic).
- **Delivery & acquisition (open question 1 — RESOLVED 2026-07-09): bundles
  are content-addressed leaves pinned from the signed index** — the second
  instance of the registry's two-tier pattern (mutable signed map → immutable
  hash-pinned artifacts; DepDecl was the first). The §2 `bundle` pin commits
  the Layer-1-verified index to the exact bundle bytes; acquisition fetches
  `<index_base_url>/attestation/<sha256_hex>.bundle` (same §3.3 URL derivation
  as `dep-decl/`) through a **generalized content-addressed artifact store**
  extracted from `HttpDepDeclStore` (path segment, extension, size cap, and
  mismatch slug parametrized — an extraction owed under the §6
  extract-or-decline discipline; P3a's mockable acquisition surface IS this
  store's file-backed variant, whose parity knob is named now:
  `MILPA_ENTRY_BUNDLE_DIR`, the mirror of `MILPA_DEP_DECL_DIR`). The bundle
  size-cap default is fixed at P3 by the same measured-corpus reasoning that
  sized `_DEP_DECL_MAX_ARTIFACT_BYTES` — not inherited blindly: Sigstore
  bundles (cert chain + inclusion proof + SET) run larger than DepDecl KDL
  text. The store verifies the pin at its one
  hash-verify site before caching; a mismatch is
  `TNG-ENTRY-BUNDLE-PIN-MISMATCH` (§5 stage 1b) — delivery-path tampering
  caught before any cryptography, extending Part 1's trust boundary to the
  bundle bytes for free. Rationale for pinned leaves over the alternatives:
  a coordinate-addressed tree (`bundles/<ns>/<name>/<version>.bundle`) is
  semantically mutable — no transport integrity, and it reintroduces the
  freshness problem the §6 no-freshness derivation just eliminated, with a
  worse federation story (mirrors must replicate layout; pinned leaves are
  location-independent). Inlining bundles in `index.kdl` multiplies index
  size by orders of magnitude, makes acquisition eager where §3 made the
  gate lazy, and re-churns the Layer-1 bundle + cache on every backfill.
  Addressing by the *subject's* `content_hash` is a near-miss trap: §1's
  name binding means one `content_hash` legitimately maps to multiple
  bundles (byte-identical trees under different coordinates), and an
  unpinned path has no transport integrity at all. Prior-art convergence:
  TUF targets, cargo sparse-index checksums, OCI blobs, and Go's sumdb all
  land on this same shape.
- **Per-entry bundles are cached** alongside the index cache, keyed by the §2
  bundle pin (the store's native key), at first acquisition — the cache is
  *storage only*; subject/name
  binding is enforced at every verification, never by cache location. Repeat
  resolves and offline operation verify from cache; no per-resolve network
  amplification. `BUNDLE-MISSING` is not negatively cached **during the
  bootstrap window** — a missing bundle is re-attempted on the next online
  resolve, so P4's backfill of bundles for existing entries reaches consumers
  without cache surgery. This is a bootstrap policy, not a permanent
  commitment: once delivery exists, a permanently-gone bundle would otherwise
  be re-fetched on every online resolve — P4 revisits with a bounded-TTL
  negative marker, mirroring Part 1's `.no-bundle` degraded-marker precedent.
- **`milpa verify` re-verifies offline** — same shape as Sv's
  `reverify_cached_index`: for each locked dep with an attestation block,
  re-verify the cached bundle (crypto + subject binding, no freshness) against
  the lockfile's recorded kind/signer. Missing cached bundle →
  `TNG-ENTRY-BUNDLE-MISSING` (warn/strict per policy). Acknowledged
  consequence: lockfiles minted during the P2-only window have claims but no
  cached bundles, so the first post-P3 `verify` emits a `BUNDLE-MISSING` wave —
  acceptable pre-v1 (one-shot re-lock regenerates; no legacy tier).

Performance envelope, for the record: one offline Sigstore verification per
selected registry dep (same cost class as Part 1's whole-index check), only on
resolves that touch the index; frozen fast-path unchanged.

### 8. Command coverage

The Part-1 §6.7 exercise, run for the per-entry gate. Scope boundary first:
the gate covers **registry-named deps only** — git/tarball/local/member deps
have no index entry, so no per-entry gate; their trust story is `content_hash`
identity plus their own provenance record, unchanged by this RFC.

| Command | Interaction |
|---|---|
| `fetch` / `lock` / `add` / `update` (online, index-loading) | gate runs at selection (§3); claims recorded to lockfile (§7) |
| `fetch` (frozen path) | no index, no gate; lockfile claim carried through, nothing re-checked |
| `verify` | offline re-verification of cached bundles against lockfile claims (§7) |
| `show` | renders the lockfile claim (unverified-claim wording until P3) |
| `remove` / `clean` | no interaction |

## Conformance strategy

Same depth as Part 1 §10, which this extends (Part 1 needed 19 scenarios to get
cross-impl convergence; per-entry has MORE states, not fewer):

- **Shared corpus, mock seam** (policy-only, no real crypto — §10.1 policy
  holds): `entry-*` fixtures scripting per-entry outcomes through the extended
  `MockVerifier`. Two seam extensions the fixtures need, named now: (i) the
  mock's outcome becomes a **keyed per-subject map** (today it is one fixed
  result — a mixed resolve needs different verdicts per entry); (ii) stage 1
  (`BUNDLE-MISSING`) is an *acquisition* failure, so the bundle-delivery/cache
  lookup needs its own mockable surface, distinct from the verifier. Matrix:
  each of the eight slugs × {warn, strict} × {author-signed, vendored}, the
  collapse cases (unknown kind, `author-signed` missing `signed_by`), one mixed
  resolve (attested + unattested + failing entries in one graph) to pin
  warning ordering/aggregation, plus four scenario fixtures guarding specific
  design decisions: **cross-entry replay** (two `(namespace, name)` entries
  sharing one `content_hash` and one bundle → `TNG-ENTRY-SUBJECT-MISMATCH` on
  the second, pinning §1 name binding), **enumeration-not-gated** (a failing
  entry that is a *candidate* but not *selected* produces no diagnostic,
  pinning §3), **lockfile round-trip** (claim block survives lock → frozen →
  show), and **workspace member-declares-entry-trust** (hard error, §4).
- **Per-impl real-crypto tier**: reuse the S5 pattern — the CI
  `generate-attestation-fixture.yaml` workflow mints real cosign bundles over
  known subjects; per-entry needs bundles whose subjects are known
  `content_hash`es + package coordinates. Two logistics facts recorded now:
  ALL needed subjects get batched into ONE `workflow_dispatch` (each dispatch
  is human-gated — N dispatches don't scale), and one signing identity
  suffices — `author-signed` fixtures simply set `signed_by` to the workflow's
  own SAN. Byte-mutation negatives derive from the committed fixtures, as in
  S4b/S5.5.
- Differential check: both impls produce identical slugs on the shared matrix
  (the S5.5 precedent — that differential caught the digest-precedence
  asymmetry Part 1 then specced).

## Prerequisites

1. **tianguis per-entry bundle delivery** — design SETTLED (open question 1;
   §7 content-addressed pinned sidecar). The cross-repo remainder is
   implementation only (bundle tree + pin emission + backfill + publish-time
   epoch gate; tianguis prerequisite issue coreyleavitt/tianguis#42). Gates
   P3b+P4 only;
   P1–P3a are delivery-agnostic by construction
   (subject binding is to `content_hash` + package coordinate, not to any
   delivery envelope, and P3a's bundle-acquisition surface is mocked).
   **Honest tail:** that claim is about the *code*, not about production
   usability — until P4's backfill ships, every real attested entry carries
   no `bundle` pin, so `entry-trust strict` against the live registry
   fail-closes with `TNG-ENTRY-BUNDLE-MISSING` on 100% of mandated entries,
   not a partial degradation. `strict` is code-complete at P3a and
   *functional* only after P4; the default (`warn`) is unaffected in the
   window.
2. **Layer 1 shipped** — ✅ DONE (#103).
3. **Real verifiers in both impls** — ✅ DONE (attestation-verifier RFC; Rust
   via vendored sigstore-rs patch, upstreaming tracked in #183).

## Open questions

1. **Per-entry bundle delivery — RESOLVED (2026-07-09): content-addressed
   pinned sidecar (§7).** The index's `bundle sha256=` pin commits to the
   exact bytes; tianguis serves `attestation/<sha256_hex>.bundle` under the
   index base URL. Inline-in-index and coordinate-addressed sidecar variants
   rejected on transport-integrity / caching / federation grounds (full
   rationale in §7); online-only Rekor lookup stays rejected (breaks the
   offline guarantee, Part 1 §5.2). The cross-repo remainder is
   implementation, not design — tianguis prerequisite issue filed
   (coreyleavitt/tianguis#42: bundle tree + pin emission + backfill dispatch
   + the publish-time epoch gate from open question 2).
2. **`strict` adoption criteria — RESOLVED (2026-07-09): epoch-based, not
   coverage-based**, underwritten by the append-only ratchet
   (`rfc-registry-append-only.md`). tianguis enforces a publish-time gate:
   every entry with `published_at >= E` (the attestation epoch) MUST carry
   an attestation, so post-epoch `UNATTESTED` is a *legacy-only* state and
   "strict for post-epoch entries" is sound without waiting for universal
   backfill. This dissolves both hazards the question named: (i) there is
   no coverage threshold to guess — the strict boundary is a fact about the
   registry, not a bet about adoption; (ii) the floating-constraint
   regression class collapses — a new `1.4.2` publish is post-epoch and
   therefore attested by construction, so `^1.4` strict consumers cannot be
   broken by upstream publishes; only pre-epoch legacy versions stay
   warn-territory, a fixed and shrinking set. Robustness: `published_at`
   is bot-asserted, but the ratchet freezes it once observed, and the
   ratchet's baseline watermark makes backdating *new* entries
   consumer-detectable (append-only RFC §4); that backdate check lands with
   P3. **`published_at` is mandatory post-epoch** (closing the omission
   dodge the append-only RFC §4 names): tianguis#42's publish-time gate
   makes `published_at` required at publish once the epoch is set, and the
   consumer side is fail-closed — when the index declares
   `attestation-epoch`, an entry *lacking* `published_at` is treated as
   post-epoch (the mandate applies); omission must never be cheaper than a
   detectable backdate. Detail (interaction with pre-epoch legacy entries
   that genuinely lack the field) finalized at P3. Epoch encoding —
   recommended: a root-level `attestation-epoch` field in `index.kdl`,
   signed with the document and **set-once under the append-only RFC's
   root-field class (its §1)** — set-once, not merely monotone-non-
   decreasing, because *raising* the epoch reclassifies every published
   entry as pre-epoch/legacy and nullifies the mandate while staying
   technically non-decreasing; a root-field violation is
   `TNG-INDEX-ROOT-MUTATED` there. Finalized at P3. The §4 granularity caveat (per-member scoped
   strict) is subsumed: epoch scoping makes universal `strict` adoptable
   directly, so per-member scoping is no longer load-bearing for adoption —
   it survives only as a possible UX refinement.
3. **Stronger identity model → Part 3.** Two distinct gaps, one mechanism-shaped
   answer: (i) chained trust takes `signed_by` on the bot's word — an
   independent, itself-attested owner registry (`(namespace, name)` → allowed
   signer set) would detect a compromised bot mis-attributing an author;
   (ii) no monotonicity across republishes — a continuity ratchet ("was
   author-signed, must stay author-signed by the same identity") covers the
   downgrade/rollback hole. **(ii) AMENDED 2026-07-09:** the continuity
   ratchet is no longer Part-3 territory — it is exactly the monotone row of
   the append-only RFC's §1 lattice (`rfc-registry-append-only.md`, #185):
   stripping, re-attribution, and author→vendored downgrade are ratchet
   violations there. Ownership split: Part 2 owns the `EntryAttestation`
   *type*; the append-only RFC owns the *order* over its values. Only (i),
   the owner registry, remains Part-3 scope. Part 2's lockfile attestation
   block remains the local raw material for per-consumer continuity.

## Slices

Re-sequenced so the unblocked, cross-repo-independent work is the committed v1
scope, and everything bundle-shaped waits on the delivery decision:

- **P1** spec: invert the §3.2 clauses; `EntryAttestation` tagged data model +
  closed-set/conservative-collapse rule + subject-binding requirements (§1);
  lockfile attestation-block schema (claim, not outcome). Spec-only; both
  impls' parse behavior specced. **No error slugs here** — the nine slugs
  (§5's eight + the WS one) land at P3 with their raise sites, keeping the
  bijection lints green throughout the window before P3a lands.
- **P2** attribution surfacing WITHOUT gating (committed scope, not blocked):
  parse `EntryAttestation` into `IndexVersion` (both impls, parse-to-typed;
  the parse boundary grows the *(typed index, collapse diagnostics)* return —
  §2); record the claim in the lockfile; surface in `milpa show` as an
  unverified claim (§7 wording). Delivers the human-audit value on its own.
- **P3** the gate (P3a fully unblocked — open question 2 is resolved
  epoch-based; P3b lands with P4, which is implementation-blocked on the
  tianguis prerequisite issue):
  `entry-trust` axis (root-scoped), selection-step pipeline (§5 table),
  the nine-slug error-catalog change, `EntryBundleVerifier` + keyed
  `MockVerifier` + mockable bundle-acquisition surface, `milpa verify` offline
  re-verification, conformance `entry-*` matrix. Includes the
  extract-or-decline decision on sharing `SigstoreVerifier` internals (§6).
  Honest tail: P3's mock-seam matrix is self-contained, but its real-crypto
  strict-fail tests are **P4-gated** (no real bundles exist before delivery
  ships) — sequence as P3a (mock-gated, complete) / P3b (real-crypto, lands
  with P4) to avoid an S4b-style dangling slice.
- **P4** (cross-repo) tianguis per-entry bundle delivery + real-crypto
  fixtures (one batched CI dispatch over all subjects — see Conformance) +
  P3b.
- **P5** Part 3: owner registry + continuity ratchet (open question 3).

## Connections

- **Part 1** (`rfc-registry-trust-federation.md`) — the whole-index gate this
  chains off; reuses its trust root, policy mechanism, mock-seam pattern, and
  §3.4.4 digest-precedence convention.
- **Attestation-verifier RFC** (`rfc-attestation-verifier.md`) — the real
  verifiers and the CI fixture-minting workflow this reuses; #183 tracks
  upstreaming the vendored sigstore-rs patch.
- **tianguis publishing architecture** — `milpa-vendored` vs `author-signed`
  come from the adopted-author / vendor-en-absentia paths; per-entry attestation
  is where those two provenance stories become consumer-visible.
- **#91** — publisher-side self-mirror declarations; adjacent availability
  surface. **#184** — this RFC's tracking issue.
