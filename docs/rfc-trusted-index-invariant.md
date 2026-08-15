# RFC: The `GatedIndex` construction invariant

**Status:** READY FOR `/tdd` (Stage 2 — architect rounds 1 & 2 applied; no open forks)
**Issue:** #199 (index-trust eager-vs-lazy gating) — this RFC reframes #199 from
"align two diverging impls" to "make ungated index use unrepresentable."
**Related:** `rfc-attestation-v1-normative.md` (the S4 strict-default flip that
exposed the latent hole), `rfc-registry-append-only.md` (the `index-history`
sibling axis), `spec/registry-protocol.md` §3.4 (the whole-index trust gate).

> **Round-1 note.** The type was renamed `TrustedIndex` → **`GatedIndex`**
> (finding: the name lied under `warn`/`off`). Three lenses converged on the
> load-bearing correction: the mint point is the *production* gate inside
> `index_cache`, not a test-facing `acquire` (§2.1). A live security bug in
> Python `milpa verify` was found (§1.2). Epoch-commitment folding, a deep
> witness-carrying type, and a corrected slice plan were added.
>
> **Round-2 note.** Four lenses hardened the *revised* design (no forks). The
> boundary inventory was completed — a fourth Rust surface (`lib.rs` `pub trait
> Resolver`/`ResolveParams`, §2.1), a second Python entry point
> (`resolve_workspace`, §2.5), and a fourth in-process bypass
> (`_execute_verify`, §4). The witness type's `off`-case was made representable
> (`verification: Option<VerificationResult>` + a single trusted-accessor, §2.4).
> `Deref` was replaced by a grep-able `.index()` accessor (§2.5). The epoch fold
> was pinned to preserve `trust_active` conditionality and priced honestly (§2.2).
> The §2.4 `show`-unification claim was withdrawn as incoherent. The §1.1 C3
> corpus math was corrected (the strict default has *zero* resolve-tier coverage,
> not 62 dead fixtures). Python `for_test` containment (§2.6) and a strict-success
> corpus fixture (§4) were added. Slices re-cut (S1a → S1a-i/S1a-ii; explicit
> shared-corpus sequencing barrier).

---

## 1  Motivation

### 1.1  #199 is a shadow of a structural flaw

Issue #199 was filed as a suspected cross-impl divergence: under
`index-trust "strict"`, Python was believed to gate a present-but-unconsumed
`index.kdl` eagerly while Rust gated lazily. **Investigation falsified that
premise.** Both impls gate *eagerly and identically* — the gate lives at the
CLI acquisition layer (`cli.py::_load_index_for_verb` → `index_cache.py`;
`main.rs::maybe_index` → `index_cache.rs`), invoked before `resolve()`. Neither
resolver contains index-trust code. Spec §3.4.1 already normatively pins eager.

So there is nothing to "align" and no eager-vs-lazy decision to "pick." But the
*reason* #199's filer could plausibly reason a divergence exists is itself the
defect, and it has three faces:

- **(C1) cross-impl agreement is coincidental, not structural.** The pure
  resolver consumes a raw, trust-unaware `Index` (`resolver.rs:89`; Python via
  `MilpaEnv.index`, `context.py:80`). The gate is enforced by *convention* at
  each CLI, so nothing forces the two CLIs to agree — the exact reasoning that
  produced #199.
- **(C2) the in-process conformance adapters bypass the gate.** Python
  `_build_env` (`test_conformance.py:624`) and Rust `runner.rs:507`
  (`Cmd::Resolve`) / `:905` (`Cmd::Verify`) construct the index via
  `parse_index`/`Index::parse` directly — no policy, no verifier, no gate. This
  is the [[feedback_gate_active_impl_pytest]] failure mode institutionalized;
  the same "verification a caller can forget to invoke" shape the #103 review
  caught.
- **(C3) the S4 strict-default has *zero* resolve-tier gate coverage.**
  Post-S4 `index-trust` defaults to `strict` (`milpa-manifest/src/lib.rs:1346`,
  `manifest.py:726/809/1276`). 207 fixtures ship `index.kdl` + `milpa.kdl`;
  **none ship a bundle**; **74 declare no policy**. **Correction (round 2):** all
  74 are `man-*`/`ws-*` validation fixtures that expect a `MAN-*`/`WS-*` error
  (73 `MAN-*`, 1 `WS-MEMBER-IS-WORKSPACE`) and fail on manifest/workspace
  validation *before* the CLI ever loads the index (`cli.py:2109` before `:2210`;
  same in `main.rs`) — **none are success-shaped, so none reach the gate**, in
  production or in-process. Round 1's "62 reach the gate" figure described a
  population that does not exist. The true state is stronger, not weaker: the
  corpus has **no fixture whatsoever** exercising "absent/strict policy,
  resolution actually consults the index" — the S4 strict default fires on
  **zero** resolve-tier paths. The new S3 pin (§4) is the *first* fixture ever to
  reach the index-trust gate through resolution; there is no dead coverage to
  repair, there is missing coverage to create.

C1/C2/C3 are one bug: *index trust is enforced at the periphery by convention,
not at the boundary by construction.* C3 sharpens it — the boundary is not just
unforced, it is **wholly unexercised** by the shared corpus.

### 1.2  A live bug the same flaw already produced (found in round 1)

Python `_verify_dep_decl_pins` (`cli.py:3132`, the online dep_decl-pin check,
spec §3.7.2) calls `load_default_index()` **bare** (`cli.py:3188`) — per its own
docstring, `config=None` **disables the trust gate**. So under
`index-trust "strict"`, Python's `milpa verify` fetches and parses the index
over the network with **zero** cryptographic verification and uses its
`dep_decl` fields to decide `VERIFY-EDGE-MISMATCH`. Rust's equivalent
(`main.rs:1109`) routes through the gated `maybe_index` seam and fails closed.
This is a real shipped divergence, reachable in-process and via subprocess, with
no corpus fixture exercising it. `_load_index_for_verb`'s own docstring
(`cli.py:1313`) describes this exact bug already fixed once at a *sibling* call
site; `:3188` was missed. The `GatedIndex` refactor fixes it structurally (a
bare, ungated index becomes untypeable at the resolver/verify boundary), and
this RFC adds a dedicated reroute slice + pin fixture (§6 S-Verify).

---

## 2  Design — make illegal states unrepresentable at the trust boundary

Introduce **`GatedIndex`**: the type every resolution/verification path
consumes, mintable *only* by the gate. Possessing a `GatedIndex` proves the
index-level gates *ran and their outcome was applied under the effective
policy* — **not** that the content is cryptographically trusted (see §2.3).

### 2.1  The mint point is the production gate, not a leaf `acquire`

The gate composition (`verify → enforce_index_trust → parse`, **eager /
before-parse** per §3.4.1) is **not** one reusable function today — it is
inlined at ~4 production sites inside the 4-state freshness cache:

- Python: `index_cache.py:882` (State-1 fresh read), `:956` (State-3 offline
  fallback), and via `index_ratchet_seam.py:100` feeding the State-2/recovery
  `GateDecision.index`. Each preceded by its own inline `_verify_and_enforce`.
- Rust: `index_cache.rs:1184` (`try_serve_from_cache`, states 1+3), and
  `index_ratchet_seam.rs:63` feeding `GateDecision.index`.

> **Decision (round 1):** the privileged `GatedIndex` constructor is **private
> to the gate module** (`index_cache` + `index_ratchet_seam`). Every one of
> those ~4 mint points is refactored to produce a `GatedIndex`;
> `load_default_index` / `load_index_with_history` / `load_index_raw` change
> their return type from `Index` to `GatedIndex`. `parse_index` / `Index::parse`
> become effectively private to that module. There is **no** public path from
> bytes to a resolver-consumable index that skips the gate.

> **Constructor naming (round 2).** The privileged constructor is named
> **`GatedIndex::mint(...)`** (Rust, `pub(crate)` / module-private) /
> `GatedIndex._mint(...)` (Python), matching this RFC's own prose ("the mint")
> and the existing `SolverKey::new` precedent whose doc reads "Mint a `SolverKey`
> from …" (`milpa-types/src/lib.rs:212`). Both impls MUST use the same verb so a
> future Nim impl inherits one vocabulary — do not let the two impls
> independently invent `_construct`/`_new`/sentinel-`__init__`.

> **Boundary inventory completeness (round 2 — HIGH).** The naive list of "who
> takes `&Index`" is incomplete. `milpa-core/src/lib.rs:258-305` exposes a
> `pub trait Resolver { fn resolve(…, idx: Option<&Index>, …); fn
> resolve_workspace(…, params: ResolveParams<'_>, …) }` and a `pub struct
> ResolveParams<'a> { pub index: Option<&'a Index>, … }`. `ResolveParams.index`
> is a **public field on a public struct** — a downstream crate can build one
> from a raw `Index` today, so this is a *fourth* public gate-bypass surface, and
> `impl Resolver for Milpa` forwards straight into `resolver::resolve*` (the
> functions §2.5 retypes). It appears to have no live caller (only
> `Milpa::resolve_frozen` is used, `runner.rs:832`), but leaving it `&Index`
> either (a) breaks S1a's "whole crate stays compiling" once `resolver::resolve*`
> flips, or (b) survives as an unaudited hole that falsifies §2.1's "no public
> path skips the gate." **S1a MUST migrate `Resolver`/`ResolveParams` to
> `&GatedIndex` / `Option<&'a GatedIndex>` in the same pass — or delete the trait
> if confirmed dead.** Same-pass companions the round-1 map missed:
> `manifest_writer.rs:289` (`index: Option<&Index>`, a production consumer) and
> `edge_sources.py:745` (`edgeset_to_terms(…, index: Index)`, Python).

`GatedIndex::acquire(bytes, bundle, config, verifier, url, epoch_status)` is a
**thin cache-free convenience** built on the *same* private `mint` primitive —
for callers that hold bytes directly (the conformance runner; a future
`milpa verify --index-only`). It is not a second implementation. Building it is
~10–20 lines/impl of genuinely new code (the private `verify_and_enforce`
helpers — `index_cache.py:324`, `index_cache.rs:300` — exist but are neither
exported nor parse-and-wrap), named explicitly in the slice plan.

### 2.2  Fold the epoch-commitment phase into the mint

A **fourth** step runs after parse and before the resolver: the
epoch-commitment phase *mutates the parsed index in place*
(`apply_epoch_commitment_phase(index: &mut Index, …)`, `main.rs:3513`;
`index.epoch_commitment_status = …`, `cli.py:1436`). A `GatedIndex` with a
private, immutable field cannot host a caller-visible `&mut` write without a
`DerefMut` that would erode the guarantee.

> **Decision:** fold epoch-commitment application **into the mint**, before the
> final wrap, so a `GatedIndex` represents "passed *all* index-level gates
> (index-trust **and** epoch-commitment)". The cache-integrated mint runs the
> phase itself (it already owns sidecar I/O); the cache-free `acquire` takes the
> resolved `epoch_status` as an injected parameter (exactly as the runner
> already injects `fixture_epoch_commitment_status`, `runner.rs:507`). No
> caller-visible mutation of a gated index exists.

> **Preserve the `trust_active` conditionality (round 2 — HIGH; correctness).**
> Today the epoch phase runs **only when index-trust policy ≠ off**: it is
> guarded by `if let (Some(active), Some(index)) = (gate.as_ref(), …)`
> (`main.rs:3490`) and sources its `TrustBundle` from `active.cfg.trust_bundle`;
> under `off` there is no `IndexTrustConfig` at all (`config: None`,
> `index_cache.rs:824`), so there is *no trust root to build the epoch verifier
> from*. The fold MUST preserve this verbatim: an `off`-minted `GatedIndex`
> carries `epoch_commitment_status = Unarmed`/unset, **untouched** by the fold.
> A literal "the mint always applies epoch" reading is not just a behavior change
> (starting crypto under `off` that never happens today) — it is a structural
> impossibility given today's signatures. Pin it: no current fixture combines
> `index-trust "off"` with an epoch pointer; add one asserting `Unarmed`.

> **Threading cost (round 2 — feasibility).** Folding is *not* free scope. The
> epoch phase currently lives **above** the mint in both impls
> (`cli.py:1369 _apply_epoch_commitment_phase`; `main.rs` orchestration), and
> needs `entry_trust_policy` (`_effective_entry_trust_policy`, `cli.py:1097`),
> which `load_default_index` (`index_cache.py:1392`) does not take. Thread a
> **new `entry_trust_policy: str` parameter** to the mint (do **not** thread
> `env`/`project_dir` — `cli.py` already imports `index_cache.py`, so that risks
> a cycle). In Rust the epoch verifier is constructed in the `milpa-cli` crate
> (`build_epoch_commitment_verifier`, `main.rs`) while the mint is in
> `milpa-core` — a **crate boundary**; follow the existing injected-verifier
> pattern (`try_serve_from_cache` already takes `verifier: Option<&dyn
> IndexBundleVerifier>`) and widen the chain `maybe_index → load_index_with_history
> → try_serve_from_cache` with the ~3 new epoch params. This gets its own
> checklist item in S1a/S2a, not a silent "fold" line.

### 2.3  Honest per-policy invariant (the type is not a "trusted" claim)

`enforce_index_trust` does not raise under `warn` for *any* result —
`BundleMissing`, `SigInvalid`, `DigestMismatch` (tampering), `SignerMismatch`,
`BundleStale` all warn-and-continue (`index_trust.rs:750/797`,
`index_trust.py:951/990`). Under `off` the verifier is **never called**
(`index_cache.py:351`, `index_cache.rs:828`). So:

> **NORMATIVE naming invariant.** `GatedIndex` ⇒ acquisition completed under the
> effective `index-trust` policy:
> - `strict` ⇒ cryptographically verified (Trusted), else no `GatedIndex` exists;
> - `warn` ⇒ verified, or a non-Trusted result was recorded as a warning;
> - `off` ⇒ verification was explicitly disabled; no trust claim is asserted.

This is why the type must **carry its `VerificationResult`** (§2.4) — so a
consumer that needs "cryptographically asserted" can distinguish it from "gate
merely ran under an opt-out," rather than trusting a name.

### 2.4  A deep type, not a shallow tag

The round-1 sketch (`struct GatedIndex(Index)`, `Deref`-transparent) is a
textbook shallow tag — its only content is "a private constructor was called."
The `SolverKey` precedent this RFC invokes carries *two* fields
(identity + display) for exactly this reason.

> **Decision:** `GatedIndex { index: Index, verification: Option<VerificationResult>,
> bundle_info: Option<IndexBundleInfo> }`, populated once at the mint from the
> verify call already being made — zero extra I/O.
>
> **`verification` is `Option` (round 2 — correctness).** Under `off` the
> verifier is **never invoked** (`index_cache.rs:850`, `.py:351`), so there is no
> `VerificationResult` to store — `verification: None` ⇔ "policy was `off`,
> verification deliberately skipped." Do **not** add an 8th `NotChecked` enum
> variant: `VerificationResult` is a closed 7-variant type with a *total*
> `to_slug()` match (`index_trust.rs:113`), and a slug-less variant would both
> break that totality and conflate "not checked" with "checked and failed" (an
> SSOT violation). `None` keeps the two cleanly distinct.
>
> **One boolean-blind-proof accessor (round 2).** Every consumer branches through
> a single `is_cryptographically_trusted(&self) -> bool` — `true` **only** for
> `Some(VerificationResult::Trusted)`. No consumer may read trust off
> `bundle_info.is_some()`: under `warn`, a `DigestMismatch` (tampering) still
> warns-and-continues and still populates `bundle_info` from the mismatched
> sidecar (§2.3), so `bundle_info` presence is *not* an endorsement. The
> accessor is the only sanctioned "is this trusted?" question.
>
> The deep type is justified by giving a future lockfile index-provenance field
> something to record (the identity-vs-provenance non-negotiable) **and** giving
> strict-path consumers their `VerificationResult` without a second I/O
> round-trip. Resolves former Fork F1.
>
> **Struck (round 2):** the earlier claim that this "unifies the duplicate
> derivation in `cmd_show_index_trust`" is **withdrawn** — three lenses confirmed
> it is unreachable and semantically incoherent. `show --index-trust` is a
> standalone, offline, **non-cryptographic**, fail-*open* observability command
> that reads the bundle bytes straight off disk (`describe_index_bundle`,
> `cli.py:2825`/`main.rs:751`) precisely so it can display *why* strict
> verification would fail; a `GatedIndex` under `strict` exists **only if
> verification already succeeded**, so in the exact diagnostic scenario an
> operator runs `show` for (strict + bad/missing bundle) there is no `GatedIndex`
> to consume — the mint would have raised. §8 already exempts `show` by
> construction. `describe_index_bundle` and the mint serve genuinely different
> purposes (fail-open display vs. fail-closed gate) and are correctly *not*
> unified. No slice touches `cmd_show_index_trust`.

### 2.5  Enforcement strength (asymmetric by language)

- **Rust — compile-time, explicit accessor (not `Deref`).** `pub struct
  GatedIndex { … }` with private fields exposes `pub fn index(&self) -> &Index`.
  The `resolve*`/`resolve_workspace*` family takes `&GatedIndex` /
  `Option<&GatedIndex>` and unwraps once via `.index()` at each entry point; the
  private internals (`ResolveProvider.index` at `resolver.rs:1404`, the
  `binding.rs` leaf helpers) keep their plain `&Index` type unchanged. A caller
  cannot hand the resolver an ungated index.

  > **`.index()` over `Deref` (round 2 — design).** The round-1 `Deref<Target=Index>`
  > plan was justified as "keeps it transparent, no pubgrub breakage" — but
  > `ResolveProvider.index` stays a plain `&Index` field regardless (pubgrub
  > never sees `GatedIndex`), so `Deref` was doing real work at only the ~3–4
  > entry-point unwrap sites, where an explicit `.index()` is exactly as terse.
  > `Deref` costs auditability: a coercion `&GatedIndex → &Index` is **invisible
  > at the call site**, so any *future* `fn f(idx: &Index)` would silently accept
  > and downgrade a gated value with no signal. `.index()` is grep-able
  > (`grep -rn '\.index()'` enumerates every extraction point). rustls's cited
  > `ServerCertVerified` has no `Deref` for precisely this reason. Deref
  > coercion also does **not** apply through `Option<&Index>` / struct fields, so
  > it never saved the ~17 `resolve*` / `ResolveProvider` / default-anchor sites
  > (`resolver.rs`, 8 `Option<&Index>` signatures + 3 match-rebinds + anchors)
  > that must be retyped either way — those are hard-required S1a edits, not
  > "mostly free." Deref's only beneficiaries were the `binding.rs` leaf helpers,
  > which the `.index()` unwrap-at-entry approach keeps unchanged anyway.

- **Python — wrapper + `.index` property + runtime assertion, at *both* entry
  points and the internal reads.** `MilpaEnv` becomes a frozen dataclass with
  `index: GatedIndex | None` (frozen so a later `env.index = raw_index`
  reassignment raises at the point of misuse, not silently). `GatedIndex` exposes
  an `.index` **property** returning the wrapped `Index`. The retrofit surface is
  larger than "two lines":
  - **Two** resolve entry points assert `isinstance(env.index, GatedIndex)` —
    `resolve()` (`resolver.py:3338`, unwrap at `:3466`) **and**
    `resolve_workspace()` (`resolver.py:5643`, unwrap at `:5778`). Asserting only
    the first leaves the workspace path gated by convention — the very C1 defect,
    relocated one layer down.
  - **Five** internal `self._env.index` reads (`resolver.py:855, 4304, 4536,
    4638, 4724`) feed `edge_sources.py:745 edgeset_to_terms(…, index: Index)`.
    Retype that parameter to `GatedIndex` and unwrap via `.index` **once inside**
    `edgeset_to_terms`, collapsing "5 sites that must remember to unwrap" into 1.
  - A named **negative test per impl** — pass a bare `Index` (or a duck-typed
    non-`GatedIndex`) to each entry point, assert rejection — pins the invariant
    rather than assuming the mechanical retrofit exercises it.

  This closes the cross-impl conformance gap (Rust won't compile a bare `Index`;
  Python must actively reject one). Resolves former Fork F2. (`Index` is not a
  pervasive primitive like the `str`-subclassed `SolverKey`, so a wrapper — not a
  subclass — is correct.)

### 2.6  The empty/frozen anchor

The 4 `Index::default()` resolver anchors (`resolver.rs:265/881/1078/6412`) plus
the **5th** at `frozen.rs:560` (and Python `frozen.py:241`) become
`GatedIndex::empty()` — an empty index has no claims to trust; sound under all
policies (verified: the frozen path never loads an index, `frozen.py:434`, and
returns before `_load_index_for_verb`, `cli.py:2196`; spec §3.4.1 exempts
`--frozen`). Prior art for a trivially-constructible "verified by assertion"
witness: rustls's `ServerCertVerified::assertion()` (`rustls::client::danger`) —
zero-sized, its purpose is to force a verifier to *name* the claim, not to
cryptographically prevent it. Any non-empty escape hatch is **test-only**,
loudly named (`for_test`), and `#[cfg(test)]`-gated in Rust so the impl that can
enforce at compile time does. Resolves former Fork F4.

> **Python `for_test` containment (round 2 — CRITICAL).** Python has no
> `#[cfg(test)]`: anything importable from `milpa/` is callable by production
> code, so a `GatedIndex.for_test(any_index)` shipped in the package would make
> `isinstance(x, GatedIndex)` true for an object that never passed the gate —
> reducing §2.5's assert to a type check, not a provenance check. The ~90 Rust /
> equivalent Python existing tests construct **non-empty, name/version-bearing**
> `Index` fixtures, so `empty()` cannot serve them; a real test double is
> unavoidable. Contain it two ways: (1) physically place the helper **outside the
> `milpa` package** (e.g. `tests/_gated_index_helpers.py`, never imported by
> `milpa/*`); (2) reuse the codebase's existing production guard idiom — the
> `MILPA_INDEX_TRUST_MOCK_VERIFIER` / `…_EPOCH_MOCK_VERIFIER` seams are already
> `file://`-only and refuse to activate otherwise (`main.rs:3572`, `cli.py:1477`)
> — so the mint accepts an injected test verifier under that same guard rather
> than exposing a raw wrap. Add a CI grep lint (`for_test(` outside `tests/`) as
> the Python analogue of Rust's compiler enforcement, named explicitly in S2a.

### 2.7  What this is NOT

- **Not moving the gate into the resolver.** The resolver stays pure — it holds
  gated data, does no crypto/IO. The type changes *who guarantees* the gate
  fired, not *where* (acquisition) or *when* (eager, §3.4.1 verbatim).
- **Not a new axis or policy.** `index-trust` warn/strict/off unchanged.

---

## 3  Corpus hygiene — the 74 no-policy fixtures

**Correction (round 2, confirmed against the live corpus):** these 74 are not
resolution fixtures — all 74 are manifest/workspace-*validation* fixtures that
expect a `MAN-*`/`WS-*` error (73 `MAN-*`, 1 `WS-MEMBER-IS-WORKSPACE`) and ship a
boilerplate `index.kdl` while declaring no policy. They short-circuit on
manifest/workspace validation *before* the index is ever loaded, so they neither
reach the gate today nor under the reroute (which is manifest-first, S1b/S2b), and
migrating them adds **no** gate coverage (S3 does). Migrate all 74 to explicit
`index-trust "warn"` anyway (a pure-data, additive edit; a no-op under today's
bypass, so it can land **first** — see S0): it is harmless hygiene — every
`index.kdl`-bearing fixture then declares its policy explicitly — and
defense-in-depth against a future adapter that gates before manifest validation.
Verified harmless: no `expected/stderr` anywhere in the corpus,
so the warn line perturbs no byte-match; none of the 74 exercise
`add`/`update`/`remove`, so the manifest-writer canonical-order divergence
(`85a6add`) is not triggered. `warn` (not `off`) keeps the gate exercised;
resolves former Fork F3.

---

## 4  The regression pins (resolve-tier and verify-tier)

- **Resolve-tier (#199):** `fixture-<N>-index-trust-strict-present-unconsumed` —
  `index-trust "strict"`, `index.kdl` present, no bundle, `deps {}` with only
  `local=`/`git=` (index genuinely unconsumed), `expected/error:
  TNG-INDEX-BUNDLE-MISSING`. Fires the gate **in-process** under the reroute.
  Template: `fixture-367-entry-trust-strict-unattested`.
- **Verify-tier (§1.2):** `index-trust "strict"`, no bundle, a lockfile with a
  `dep_decl` pin, `cmd=verify`, `expected/error: TNG-INDEX-BUNDLE-MISSING` —
  pins the live-bug fix so it cannot regress.
- **Strict-*success* (round 2 — breadth):** the corpus proves the negative case
  exhaustively but has **no** fixture proving the positive path — `strict` + a
  *verified-trusted* bundle → `GatedIndex` minted with `Trusted` → a named dep
  actually resolved out of the index. That is the type's whole raison d'être
  (proof the gate *ran and passed*, not merely that ungated access is blocked).
  Add one resolve-tier fixture using the existing `MILPA_INDEX_TRUST_MOCK_VERIFIER=trusted`
  seam (no real bundle bytes needed; the seam is `file://`-guarded), a named dep
  resolvable only via the index, `index-trust "strict"`, expecting **success**.
  Lands in S3.

**The verify-tier in-process bypass (round 2 — CRITICAL).** #199's C2 named three
bypass sites; there is a **fourth**: `test_conformance.py:2682`, inside
`_execute_verify` (`:2481`), a *separate* in-process reimplementation of
`cmd_verify`'s dep_decl edge-check that does its own bare
`parse_index(...)` with no policy consultation — the pytest mirror of the live
`cli.py:3188` bug. As written it can **never** raise `TNG-INDEX-BUNDLE-MISSING`,
so the verify-tier pin's "in-process **and** harness" claim is unachievable until
it is fixed. Rust already handles the symmetric site (`runner.rs:905`, named in
S1b). **S-Verify MUST also reroute `_execute_verify`'s edge-check through the
gated seam** (Python's `runner.rs:905` analogue); only then is the verify pin
verifiable in-process rather than `is_cli_only`.

All pins verified in-process **and** through `harness/` (the black-box subprocess
runner, confirmed to strip host `MILPA_*`, set `MILPA_INDEX_URL` per fixture, and
force no global policy override). Resolves former Fork F6.

---

## 5  Spec delta (`spec/registry-protocol.md` §3.4)

- §3.4.1 stays verbatim (eager). **Do not** add the round-0 impl-shaped clause
  ("MUST enforce the gate as a construction precondition of the index value") —
  §3.4.1's "MUST fire on every index load … before parse … no index claim may
  be used before the gate passes" already binds a future Nim impl *behaviorally*,
  and a type-shaped clause is weaker (satisfiable by a no-op alias). `GatedIndex`
  is an impl-quality decision, not a spec mandate. Resolves former Fork F5.
- **Add** two clarifying sentences: (a) the honest per-policy meaning of a
  passed gate (§2.3), so a Nim impl doesn't over-read "strict-verified" into the
  warn/off cases; (b) the online `dep_decl` verify check (§3.7.2) loads-and-gates
  **conditional on there being pins to check** (Rust `if !pinned.is_empty()`,
  `main.rs:1080`), which is not an exception to "every index load" but a case
  where no load occurs — distinct from the offline reverify crypto-only carve-out.
- No new error slugs; bijection lint unaffected.

---

## 6  Slice plan (vertical, TDD) — corrected for a green corpus at every step

- **S0 — corpus hygiene, data-only, no code.** Migrate the 74 fixtures to
  `index-trust "warn"`. No-op under the current bypass → corpus stays green;
  eliminates the red window the reroute would otherwise open. (Note the corrected
  §1.1 C3 framing: all 74 short-circuit on `MAN-*`/`WS-*` before the gate, so S0
  is *harmless* but does not itself add gate coverage — S3 does.)
- **S1a-i — Rust type, additive, stays green.** Introduce `GatedIndex` (§2.4
  fields incl. `verification: Option<VerificationResult>`) + `index()` accessor +
  `empty()` + the module-private `mint` + `#[cfg(test)] for_test()`. No return
  type changes yet — purely additive, whole crate still compiles.
- **S1a-ii — Rust flip + retrofit, one atomic green commit.** Changing
  `load_*`/`maybe_index` return types `Index → GatedIndex` is a big-bang in Rust
  (every consumer breaks until fixed — this cannot be sub-incremental and stay
  compiling). In the same commit: refactor the ~4 `index_cache`/`index_ratchet_seam`
  mint points to `mint`; fold the epoch phase in (§2.2) with the **`entry_trust_policy`
  param threading + `trust_active` conditionality** as an explicit sub-checklist;
  retype the ~17 Deref-blind `resolve*`/`ResolveProvider`/anchor sites in
  `resolver.rs`; migrate **`lib.rs` `Resolver`/`ResolveParams`** (§2.1) and
  **`manifest_writer.rs:289`**; retrofit the remaining ~60 prod + ~96 test
  `&Index` sites (`.index()` at entry points; leaf helpers unchanged; tests via
  `for_test`). Bit-for-bit identical behavior; green at commit end.
- **S1b — Rust behavioral (real RED/GREEN).** Build the cache-free `acquire`;
  reroute the runner bypass onto it — `runner.rs:507` (`Cmd::Resolve`) is
  **parse-order-inverted** (index at :507 before manifest at :547) and must be
  flipped to manifest-first; `runner.rs:905` (`Cmd::Verify`) is **already
  manifest-first** (manifest :867 before index :905) — reroute it, no reorder.
  RED: the strict+no-bundle resolve fixture raises `TNG-INDEX-BUNDLE-MISSING`
  in-process (GREEN given S0).
- **S2a — Python type + enforcement (mechanical, stays green).** Frozen-dataclass
  `MilpaEnv` + `GatedIndex` wrapper with `.index` property + `_mint` +
  contained `for_test` (§2.6: outside `milpa/`, `file://`-guarded seam, CI grep
  lint) + `empty()`/`frozen.py:241` anchor + epoch fold (`entry_trust_policy`
  param, no `env`/`project_dir` threading). Add the `isinstance` assert at
  **both** `resolve()` **and** `resolve_workspace()`, retype `edgeset_to_terms`
  (`edge_sources.py:745`) unwrapping `.index` internally (§2.5), plus the named
  negative test per entry point.
- **S2b — Python reroute (behavioral).** Reroute `_build_env`
  (`test_conformance.py:624`), manifest-first. (Python's single unified bypass
  covers resolve+verify, unlike Rust's split — but see S-Verify for the *second*
  Python in-process verify path.)
- **S-Verify — the live bug (§1.2) + its in-process mirror.** Reroute
  `_verify_dep_decl_pins` (`cli.py:3188`, production) **and** `_execute_verify`'s
  edge-check `parse_index` (`test_conformance.py:2682`, the fourth bypass, §4)
  through the gated seam; add the verify-tier pin. Verify in-process **and**
  through `harness/`.
- **S3 — the resolve-tier pins (§4).** The #199 strict+present-unconsumed pin
  **and** the strict-*success* pin (`MILPA_INDEX_TRUST_MOCK_VERIFIER=trusted`).
  In-process + `harness/`.
- **S4 — spec (§5) + close #199** with the finding; note in
  `docs/comparison-vs-nimble-atlas.md` if it references the trust model.

Ordering rationale: S0 first removes the red-corpus hazard; S1a-i/S2a-additive
and S1a-ii/S2a carry the real design (mint-as-boundary) while staying green;
S1b/S2b/S-Verify are the behavioral REDs. S1 (Rust) and S2 (Python) are per-impl
independent — **except** the shared corpus: **S3 and S-Verify's pins must not
land in `conformance/` until *both* S1b and S2b are green**, or the impl that
hasn't yet rerouted its bypass will fail a shared fixture it used to pass.

---

## 7  Disposition of the forks (rounds 1 & 2)

All six original forks were **resolved** in round 1: F1 → §2.4 (carry the
witness); F2 → §2.5 (Python runtime assert); F3 → §3 (`warn`); F4 → §2.6
(rustls-framed, test-only escape); F5 → §5 (drop the type-clause, keep
behavioral + clarify); F6 → §4 (both pins first-class).

Round 2 pressure-tested the revised design and applied every finding as a
clear-best fix (each carried a goal-determined answer, so none reached Corey as a
fork): the completed boundary inventory (§2.1 `lib.rs`, §2.5 `resolve_workspace`,
§4 `_execute_verify`), the `Option<VerificationResult>` `off`-case (§2.4), the
`.index()`-over-`Deref` decision (§2.5), the epoch conditionality + threading
price (§2.2), the withdrawn `show`-unification claim (§2.4), the corrected C3
corpus math (§1.1), `for_test` containment (§2.6), the strict-success fixture
(§4), and the re-cut slices (§6). **No open forks remain.** The RFC is ready for
the `/tdd` grind.

---

## 8  Non-goals

- No change to eager/§3.4.1, the warn/strict/off axis, or the `index-history`
  (append-only) sibling axis (beyond the mint sharing its parse).
- No crypto in the resolver. No new provenance kind. No fetcher change.
- `milpa show` (plain), `show --index-trust`/`--entry-trust`, `index
  status`/`accept`, and `publish` never construct a resolver-consumed `Index`
  (they read the lockfile or operate on raw candidate text) — out of scope by
  construction.
