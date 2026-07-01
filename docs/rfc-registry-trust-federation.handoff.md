# rfc-registry-trust-federation — handoff

- **Stage:** 3 (tdd slice grind) — **S1–S7 DONE**. Functional grind COMPLETE. S4b mini-spike COMPLETE (NOT VIABLE — see below). Next: `/code-review docs/rfc-registry-trust-federation.md` (Stage 4).
- **Resume:** COMMITTED: `8b65abd` (S1–S7 functional) + `afa06ae` (S4b NOT-VIABLE record). S4b deferred (upstream sigstore-rs#285). **Next: observability command** (`milpa show --index-trust`), then `/code-review docs/rfc-registry-trust-federation.md` (Stage 4).
- **Observability IN FLIGHT** (agent `a7a7bd0`): disk-verified — `describe_index_bundle` in both impls (`index_trust.py` + `index_trust.rs`), `show --index-trust` wired in both CLIs, 3 conformance fixtures (356-fresh/357-stale/358-no-bundle), errors.md untouched. Mid dual-gate (pytest + `./dev-rust`). **VERIFY at completion:** spec stanza in `spec/cli-contract.md` (grep found 0 `--index-trust` mentions — may be unwritten; spec-first is non-negotiable, send agent back if missing) + both runners byte-identical + no verify-verdict printed. If a crash interrupts: re-run both gates before trusting.
- **Observability plan (parity-preserving scope):** describe the cached bundle's CLAIMS only — effective policy, signer SAN + OIDC issuer, `integratedTime` + human age/freshness, Rekor UUID, DSSE subject digest — pure JSON parse, byte-identical both impls. NO "verified ✓" badge (would diverge: Python verifies, Rust S4b-stubbed → violates cross-impl parity; verification is already enforced by the gate on fetch/lock). Unit = spec/cli-contract.md stanza + `describe_index_bundle` helper + CLI wiring both impls + conformance fixture(s). Not yet started.
- **RFC path:** `docs/rfc-registry-trust-federation.md`
- **Corey's decisions (resolved):** (1) S4b → RUN the low-level-primitives mini-spike → **agent `a46525fa` IN FLIGHT** (spike-then-implement-if-viable). (2) Commit → DONE `8b65abd` (136 files; excluded harness lock + pre-existing fetch-hardening/#177 handoffs). (3) "no, do them now" → skip GH-issue filing, implement small follow-ons inline: **observability command** sequenced AFTER S4b (it needs the verifier to surface signer/integratedTime/Rekor-UUID metadata, which S4b's real-verifier work defines); **tianguis `index.kdl.bundle` delivery** is cross-repo (`coreyleavitt/tianguis`) — not checked out here, pending; **Part-2 per-entry attribution** STAYS deferred (settled Layer-1-only scope, separate RFC).
- **⚠️ git-identity landmine (fixed):** `.git/config` had a LOCAL override `user.email=t@t`/`user.name=t` (leftover from #177 git experiments) shadowing the correct global `corey@leavitt.dev`. Removed via `git config --local --unset user.{email,name}`. VERIFY `git config user.email` == corey@leavitt.dev before any future commit this session.

## Progress
- **S7 DONE** (cross-impl conformance fixtures + `index-trust` cmd in both runners; Python **2543 passed, 31 skipped**; Rust **317 pass, 34 skip (cli-only), 0 regressions** — 351 total fixtures): 18 fixture directories (`fixture-338` through `fixture-355`) under `conformance/spec-v1/`; `_oracle/test_trust_bundle.json` placeholder committed; `Cmd::IndexTrust` + `from_dir("index-trust")` in Rust `fixture.rs`; `Produced::IndexTrustPass` + `run_index_trust_fixture` + `Cmd::IndexTrust` dispatch in Rust `runner.rs`; `_execute_index_trust_fixture` + dispatch + `_is_not_yet_wired` entry in Python `test_conformance.py`. Both runners consume identical env fields (`mock_verifier_result`, `MILPA_INDEX_TRUST_MANIFEST`, `MILPA_INDEX_TRUST`, `MILPA_REQUIRE_ATTESTED_INDEX`, `MILPA_INDEX_TRUST_WS_MEMBER_MAX`, `MILPA_INDEX_TRUST_WS_CONFLICT`) and produce byte-identical outcome strings (`trusted`, `warn:TNG-INDEX-*`, `error:TNG-INDEX-*`, `error:WS-INDEX-CONFLICTING-SIGNERS`). Functional grind complete.

- **S6 DONE** (Rust mirror of S5; `./dev-rust test --workspace` 549+182+33+17+24+… passed, 0 failed): `milpa-manifest` 3 new fields (`index_trust_policy`, `index_trust_signer`, `index_trust_bundle`) + parse cases + 5 Manifest construction sites updated; `milpa-core/src/index_trust.rs` `enforce_index_trust` (6-way dispatch, thread_local warn dedup); `milpa-core/src/index_cache.rs` full rewrite — `HttpGet` now bytes, `BundleHttpGet`, `derive_bundle_url`, `get_bundle_url`, new `load_index` with 4 optional trust-gate params (crypto-verify-every-read, freshness-only-on-network, crash-recovery `try_serve_from_cache`, `.no-bundle` degraded marker, `--refresh-index` bypass); 24 new index_cache tests green; `workspace.rs` `merge_workspace_index_trust_policy` + `check_conflicting_signers` (→ `WS-INDEX-CONFLICTING-SIGNERS`) called in `load_workspace_from_manifest`; `error.rs` 7 new codes; `corpus.rs` DEFERRED emptied (all 7 TNG-INDEX-* + WS-INDEX-CONFLICTING-SIGNERS → `implemented_error_codes()` via `all_codes()`); CLI wired: `--require-attested-index`, `--refresh-index` flags + 5 env reads (`MILPA_INDEX_TRUST`, `MILPA_INDEX_TRUST_SIGNER`, `MILPA_INDEX_TRUST_BUNDLE`, `MILPA_INDEX_MAX_AGE`, `MILPA_INDEX_BUNDLE_URL`); `http_get` updated to bytes; `IndexTrustConfig` built + passed to `load_index`; `SigstoreVerifier` placeholder still wired (S4b). Bijection test green.

- **S5 DONE** (Python functional slice; both gates green): manifest nodes `index-trust`/`index-trust-signer`/`index-trust-bundle`; `trust.py` `effective_trust_policy` extended to full §6.6 (matches Rust); `IndexTrustConfig` on context; cli flags `--require-attested-index`/`--refresh-index` + 5 env reads; `load_index(url, config, verifier, http_get, bundle_http_get)` rewrite — verify-every-read, freshness-only-on-network (`max_age_seconds=None` on cache reads), bundle-URL derivation (query/fragment preserved), bounded crash-recovery (1 refetch then hard-fail), warn degraded-marker `.kdl.no-bundle` / strict no-partial-cache, `--refresh-index` TTL bypass; `enforce_index_trust` 6-way dispatch (warn=1 dedup'd warning/URL+exit0, strict=raise, off=silent); workspace `merge_workspace_index_trust_policy` (strict>warn>off) + `_check_conflicting_signers` → `WS-INDEX-CONFLICTING-SIGNERS`. **7 new codes** (6 `TNG-INDEX-*` + `WS-INDEX-CONFLICTING-SIGNERS`) in `errors.py`+`spec/errors.md`+Rust `corpus.rs` DEFERRED — disk-verified consistent, bijection green. Real-`SigstoreVerifier` oracle integration test = `@pytest.mark.skip` (hermetic Sigstore signing deferred). Python **2525 passed, 31 skipped**; Rust conformance+bijection **2 passed**.

## S4b COMPLETE — mini-spike verdict: NOT VIABLE (sigstore-rs 0.11.0 has two blocking gaps)

**S4 original finding:** `CheckedBundle::try_from` returns `BundleErrorKind::DsseUnsupported` for
any `Content::DsseEnvelope` bundle; only `MessageSignature` (hashedrekord) is handled.

**S4b mini-spike finding (low-level primitives path):** The spike sourced the vendored sigstore 0.11.0
source and found **TWO blocking gaps** that make the approach NOT VIABLE:

1. **`CertificatePool` is `pub(crate)` only** (`crypto/mod.rs` line 177). `CertificatePool::verify_cert_with_time`
   is the primitive that validates the Fulcio leaf cert chain against the embedded Fulcio root AT cert
   issuance time. It is inaccessible from outside the crate. Without it, RFC §4 step 2 (cert chain at
   `integratedTime`) cannot be implemented without hand-rolling webpki at-time validation — which violates
   the no-hand-rolled-crypto rule.

2. **Rekor SET / inclusion proof verification is a TODO in sigstore-rs 0.11.0** (`bundle/verify/verifier.rs`
   lines 155–162: `// TODO(tnytown): Merkle inclusion; sigstore-rs#285` and `// TODO(tnytown) SET verification;
   sigstore-rs#285`). This is NOT implemented even for the MessageSignature path. RFC §4 step 5 requires
   SET verification. Hand-rolling it (ECDSA verify over tlog entry JSON using Rekor public key) violates
   the no-hand-rolled-crypto rule.

**What sigstore-rs 0.11.0 DOES provide:** cert-at-SET-time window check ✓ (verifier.rs step 7),
`ManualTrustRoot` ✓, `CosignVerificationKey` (ECDSA P-256 verify given a public key) ✓, identity
policy ✓ — but none of the blocking-gap items.

**Outcome:** S4b is DEFERRED as a tracked known-limitation. Placeholder and comments updated in
`impls/rust/crates/milpa-core/src/index_trust.rs` and `Cargo.toml` to record the full finding.
No code changes beyond comment updates; no new tests. Conformance stays green via MockVerifier.

**Path forward:** Retry S4b when sigstore-rs ships both (a) DSSE/in-toto attestation support AND
(b) Rekor SET/inclusion proof verification (sigstore-rs#285). Consider upstream contribution.

## Progress
- **S4 DONE** (Rust verifier, S4b activated): `impls/rust/crates/milpa-core/src/index_trust.rs` at structural parity with S3 (7-variant `VerificationResult` with string reprs byte-identical to Python `.value`; `IndexBundleVerifier` trait; pure `verify_index_bundle` steps 1–3; `MockVerifier`; `IndexTrustConfig` no-verifier-field; `TrustBundle` prod via `include_bytes!` placeholder / test via `_oracle/`). `SigstoreVerifier` = honest `unimplemented!` placeholder (S4b). `sigstore = "0.11"` in `milpa-core/Cargo.toml` w/ deps-rationale documenting the DSSE gap. `./dev-rust test --workspace` 849 passed 0 failed; conformance 299 pass 0 regressions; bijection test green (no `TNG-INDEX-*` added).

## S3 INCIDENT (resolved — for the record)
First two S3 agents (`general-purpose`) spawned NESTED sub-agents that ran in git worktrees on a STALE base (`c057c49`) and stalled waiting on each other; one produced a 29/29-green module in worktree `a80a792989…` that was lost when I removed the stray worktrees. No real loss (stale base, uncommitted, design fully in RFC). **Main verified healthy** at `53a3d04` (#177 committed; reflog `reset` is the old documented #177 recovery, not new). Redo `a4ad6d7` ran clean IN THE MAIN TREE with explicit no-nested-agent/no-worktree/no-git constraints. **Lesson baked into all future slice briefs: forbid nested Agent/Task spawns + worktrees; work direct-in-tree.**

## Progress
- **S3 DONE** (Python verifier): `impls/python/milpa/index_trust.py` (22KB) — `VerificationResult` 7-variant enum (`.value` strings match `mock_verifier_result` fixture field), `IndexBundleVerifier` Protocol, pure `verify_index_bundle` (JSON→`BundleMalformed`; `integratedTime` extract; freshness only when `max_age_seconds is not None`; cert-at-SET-time via sigstore-python `Verifier.production(offline=True)`), `SigstoreVerifier`, `MockVerifier`, `IndexTrustConfig` frozen dataclass (NO `verifier` field, default `max_age_seconds=604800`), `TrustBundle` (`.production()` loads `milpa/_trust/trust_bundle.json` PLACEHOLDER via importlib.resources; real bundle gated at S5), `.test()` loads `_oracle/`. `sigstore>=3.0.0` dep (resolved 4.3.0). 35 new tests. Full suite 2442 passed. `errors.py`/`spec/errors.md` untouched; `enforce_index_trust`+`TNG-INDEX` in docstrings only.
- **S2 DONE** (spec-only): `spec/registry-protocol.md` new §3.4 "Whole-index attestation gate (Layer 1)" (§3.4.1–3.4.7; §3.2 untouched, regression note intact; Appendix A has a FORWARD-REF table of the 6 codes, none added to `spec/errors.md`). `spec/cli-contract.md` §2.8/§2.9 flags + §8.6 five env vars + Appendix B rows. Verified: `spec/errors.md` unmodified, 0 `TNG-INDEX` refs → Rust bijection intact.
- **S1 DONE** (both impls green): Python 2407 passed (`trust.py` new; `TrustPolicy` is the single type name — `AttestationPolicy` alias removed; `effective_strict_policy`→`effective_trust_policy`; `permissive`→`warn` clean cutover). Rust 825 passed, 0 failed (4-crate hard rename `AttestationPolicy`→`TrustPolicy`; `trust.rs` new; corpus bijection ok; no `permissive` in corpus).
  - **NOTE for S5:** the Rust S1 agent already implemented the FULL §6.6 authority formula in `effective_trust_policy` (off-is-manifest-only / env-no-op-floor / flag-escalation) — an S6 head-start. Python still ports the OLD semantics (`env_override` reserved, unused). No observable divergence today (all Rust call sites pass `env_override=None`; attestation axis uses no `off`; no shared fixture exercises the 3-source formula until S7). **S5 must make Python's `effective_trust_policy` match Rust's §6.6 exactly.**

---

## Round 2 fixes applied

**Freshness-at-fetch-time (Groups A, N):** Freshness assertion (`now -
integratedTime < MILPA_INDEX_MAX_AGE`) fires ONLY on network-fetch paths (State 2
and recovery refetch). Pure cache reads (States 1, 3) still re-verify the full
cryptographic chain but NOT the wall-clock bound — preserving offline/air-gap use
without weakening rollback protection. `milpa verify` re-verifies crypto offline
but not freshness. Committed `_oracle/` test bundles use a "skip freshness"
sentinel. §3.3, §3.4, §4 step 6, §5.2, §6.7, §7.2, §10.1, §12.2 updated.

**`off` is a project-only auditable opt-out (Group C):** Replaced the
effective-policy formula. `manifest=off` returns `off` unconditionally.
`MILPA_INDEX_TRUST=off` in env is a no-op floor (cannot weaken manifest
`warn`/`strict`). Env/flag may only STRENGTHEN. `env=strict`/`env=warn` cannot
override `manifest=off`. Resolved the round-1 parked question. §6.2, §6.3, §6.6
updated. `MILPA_REQUIRE_ATTESTED_METADATA` named as the DISTINCT existing
attestation env var (confirmed in `cli.py:3037–3043`).

**Signer-identity / trust-root split (Group D):** `MILPA_INDEX_TRUST_SIGNER` is
identity-only (OIDC URL / SAN). New `MILPA_INDEX_TRUST_BUNDLE` for `file://` CA
trust-root override. New `index-trust-bundle` manifest node. Both seams are
orthogonal in the `IndexBundleVerifier` protocol (`trust_bundle` + `expected_signer`
are independent parameters). §3.2, §6.3, §6.4, §8.3, §10.1 updated.

**Per-URL workspace signer resolution (Group E):** Signer identity and trust-bundle
are resolved PER index URL (per cache key). Conflicting signers for the same index
URL across workspace members → hard validation error before any fetch. New S7
fixture `workspace-conflicting-signers`. §6.4a, S2, S7 updated.

**Bundle-URL derivation normative + overridable (Group F):** Derivation is: strip
query/fragment from `MILPA_INDEX_URL`, append `.bundle` to PATH, reattach
query/fragment. New `MILPA_INDEX_BUNDLE_URL` env override for non-derivable URLs.
§7.3, §9.2, §8.1, §6.3, §8.3 updated.

**Bounded crash-recovery (Group G):** At most ONE crash-recovery refetch per
`load_index` call. Second consecutive mismatch → hard-fail regardless of policy
(active-adversary signal, not interrupted-write). §7.2 updated.

**Partial-cache under warn (Group H):** Bundle-404 under `warn` MAY write a
`.kdl.no-bundle` degraded-marker sidecar so TTL governs refetch cadence. Under
`strict`, no partial-cache state. §7.2, §7.4 updated.

**VerificationResult 7-variant / 6-way dispatch (Group Q):** All seven variants
enumerated: `Trusted | SigInvalid | DigestMismatch | SignerMismatch | BundleStale |
BundleMissing | BundleMalformed`. `enforce_index_trust` is a 6-way dispatch (six
non-Trusted failure variants → six `TNG-INDEX-*` slugs). `BundleMissing` is
constructed by `load_index` (not the verifier); the type is still unified. S3 code
updated.

**Verifier as explicit param (Group R):** `verifier: IndexBundleVerifier` removed
from `IndexTrustConfig`. Made an explicit parameter of `load_index(url, config,
verifier, http_get, bundle_http_get)`. Prevents tests silently running against real
Sigstore. `IndexTrustConfig` remains one-param to `load_index` for policy/signer
config. §7.2, S3 updated.

**Sidecar rename (Group S):** Cache sidecar renamed `<key>.index.bundle` →
`<key>.index.kdl.bundle` (consistent stem; `rm <key>.index.kdl*` cleans all).
Degraded marker is `<key>.index.kdl.no-bundle`. §7.2 updated.

**S5→S6 Rust DEFERRED bucket (Group W):** S5 now also touches
`impls/rust/crates/milpa-conformance/tests/corpus.rs` to add all six `TNG-INDEX-*`
codes to the `DEFERRED` bucket, so the spec/Rust bijection test passes during the
S5→S6 window. S6 moves them from `DEFERRED` to `implemented_error_codes()`.

**S3 integration test → S5 (Group X):** S3's gate is `MockVerifier` unit tests
only. The real `SigstoreVerifier` integration test against `_oracle/` is gated at
S5 (when full policy stack is wired). §12.2, S3, S5 updated.

**Separate `bundle_http_get` (Group Y):** `load_index` takes two separate
injectable transports: `http_get` (index) and `bundle_http_get` (bundle). Matches
`fetchers/tarball.py` pattern. URL/transport fakes for bundle-404, bundle-malformed,
all cache states named in S5/S6.

**S1 four-crate Rust scope (Group Z):** S1 files-touched now names all four crates:
`milpa-manifest/src/trust.rs`, `milpa-manifest/src/lib.rs+format.rs`,
`milpa-core/src/resolver.rs` (rename), `milpa-core/src/lib.rs` (BREAKING pub-API
rename: `AttestationPolicy` → `TrustPolicy`), `milpa-core/src/discovery.rs`,
`milpa-cli/src/main.rs`, `milpa-conformance/src/runner.rs`, `*_tests.rs`. Fixture
clean confirmed (no `permissive` in conformance corpus).

**Conditional S4b (Group AA):** Named conditional slice S4b
"Rust SigstoreVerifier retrofit (CONDITIONAL)" — only if the S4 spike finds
`sigstore-rs` API insufficient. Slot stays empty if spike succeeds; naming prevents
a stub silently persisting into a release. §12.1, S4 updated.

**New off/authority fixtures → 18 total (Group V):** Six new fixtures added:
`off-sig-invalid`, `off-digest-mismatch`, `off-bundle-missing`,
`manifest-off-env-strict`, `manifest-warn-env-off`, `workspace-conflicting-signers`.
Total: 18 (was 12). All "twelve" replaced by "eighteen"/"18". §10.3, S7 updated.

**Additional fixes:** Group I (decode failure → index-parse error path); Group J
(cross-process concurrency: no lock, crash-recovery is conformance guarantee);
Group K (TNG-INDEX-* slug is machine-readable under warn; exit 0 stays); Group L
(`remove`/`clean` don't load index; `show` fires gate only when loading index);
Group M (dedup key = MILPA_INDEX_URL, at most one warn per unique URL); Group N
(rollback-in-window documented in §3.4); Group O (Fulcio-rotation operational
story: emergency bypass, slug doesn't distinguish rotation from tamper, maintainer
advisory commitment); Group P (§7.5 post-incident remediation subsection); Group T
(`context_msg` → `index_url` in `enforce_index_trust`); Group U (MILPA_REQUIRE_ATTESTED_METADATA
named as distinct existing env var); Group AB (S1 fixture-clean confirmed; S5
implementation-order note: data-model plumbing first, cache rewrite second).

---

## Key decisions (this session — do not reopen)

### Scope decision 1: Defer Layer 2 to Part 2

Layer 1 (whole-index gate) alone fully closes #103. Layer 2 (per-entry
verification) adds only author-ATTRIBUTION, not additional integrity (Layer 1
already cryptographically covers every byte in the index). Deferral cost
justification: per-entry Layer 2 requires the tianguis per-entry bundle-delivery
design to be settled (three competing options, none chosen) plus `sigstore-rs`
offline API stability at version-selection frequency.

Removed from active RFC body (moved to new "Part 2" section at end of RFC):
- §4.2 Layer 2 per-entry verification gate.
- 3 per-entry error codes: `TNG-ENTRY-UNATTESTED`, `TNG-ENTRY-SIGNATURE-INVALID`,
  `TNG-ENTRY-SIGNER-MISMATCH`.
- IndexVersion field surfacing (`attestation`, `signed_by`, `rekor` fields).
- `spec/registry-protocol.md §3.2` normative inversions: the "parsed and ignored"
  clauses STAY as-is; `test_rekor_block_is_tolerated_and_ignored` is NOT inverted.
- Original S8 per-entry verification slice.
- §9.3 per-entry bundle delivery.
- §12.4 author-identity crux, §12.6 per-entry bundle availability.
- Entry-* conformance fixtures.

Layer 1 adds NEW normative text to `spec/registry-protocol.md` (a new subsection
after §3.2) rather than inverting the existing per-entry clauses.

### Scope decision 2: Full SSOT unify + rename permissive→warn

`index-trust` (warn/strict/off) + `effective_index_trust_policy` would duplicate
the existing `attestation-policy` (permissive/strict) + `effective_strict_policy`
in `attestation.py:52–75`. milpa forbids duplicate mechanism. Resolution:

- S1 introduces `TrustPolicy = Literal["warn", "strict", "off"]` in a new
  `trust.py` module (Python) / corresponding module in `milpa-manifest` (Rust).
- Renames existing `permissive`→`warn` in `attestation-policy` (pre-v1 breaking
  change; clean cutover, no legacy alias).
- Replaces `effective_strict_policy(...)` with one shared
  `effective_trust_policy(manifest_value, flag, env_override) -> TrustPolicy`.
- Both axes (attestation-policy + index-trust) parse to `TrustPolicy` via a
  shared `_parse_trust_policy` helper.
- The two CONFIG AXES remain separate (different concerns); only the mechanism
  is unified.

### Key clear-best fixes applied

**Crypto correctness:**
- **Cert-at-SET-time** (§4 step 2): certificate validity MUST be checked at
  Rekor SET `integratedTime`, NOT wall-clock `now`. Fulcio certs are ~10 min
  lived; wall-clock check is always wrong. Normative in §4; required to confirm
  in sigstore-rs spike (§12.1).
- **DSSE description** (§4 step 4): signature covers the DSSE envelope payload
  (an in-toto statement), NOT raw index bytes. Verification extracts
  `statement.subject[0].digest.sha256` and asserts it equals `sha256(index_bytes)`.
- **Rollback/freshness** (§3.3, §4 step 6, §6.5): new `TNG-INDEX-BUNDLE-STALE`
  error; `MILPA_INDEX_MAX_AGE` env (default 7 days); asserted offline from
  `integratedTime` in the bundle. Moved from "not provided" to "provided" in §3.3.
- **Cache crash recovery** (§7.2): disk-read mismatch / missing bundle sidecar
  on a CACHE READ → silently delete both sidecars + re-fetch (interrupted write
  is not an attack). Network-fetch mismatch → hard-fail regardless of policy
  (active adversary signal).
- **Single-read TOCTOU** (§4, §7.2): `index_bytes` read once; same in-memory
  object passed to verify and parse; no second disk read between them.

**Coverage:**
- **`TNG-INDEX-BUNDLE-MALFORMED`** (§6.5): new code for pre-crypto failure
  (bundle JSON won't parse), distinct from `TNG-INDEX-SIGNATURE-INVALID`
  (crypto failure).
- **Rename `TNG-INDEX-IDENTITY-MISMATCH` → `TNG-INDEX-DIGEST-MISMATCH`** (§6.5):
  "identity" is a load-bearing milpa term (content_hash of source tree); using
  it for a bundle-subject mismatch creates a false collision.
- **Non-tianguis signer override** (§3.2, §6.3): `MILPA_INDEX_TRUST_SIGNER` env
  + `index-trust-signer` manifest node. Makes index-trust a protocol feature,
  not tianguis-only.
- **Workspace policy merge** (§6.4a): effective index-trust = MAX over root +
  all members, computed before index load. Fixture: root=warn + member=strict
  → strict.
- **Command coverage** (§6.7): `fetch`/`lock`/`show`/`add`/`update` + `verify`
  fire the gate; frozen path does NOT (lockfile is trust anchor); `--no-index`
  suppresses entirely.
- **`off` vs flag escalation** (§6.2/§6.6): `--require-attested-index` escalates
  `warn`→`strict` but MUST NOT escalate `off` (positive opt-out).
- **OR semantics all three sources** (§6.6): formula is
  `base = max(manifest, env)` then `if flag and base != "off": return "strict"`.
  `env=off` cannot weaken `manifest=strict`.
- **`HttpGet → bytes`** (§7.2/§7.3): transport returns `bytes`; index decoded for
  parse, bundle kept as bytes. Byte/text boundary explicit at transport seam.
- **Upgrade migration** (§7.4): pre-RFC cache triggers `TNG-INDEX-BUNDLE-MISSING`
  warn with remediation hint; `--refresh-index` forces re-fetch.
- **`MILPA_INDEX_MAX_AGE`** documented in `spec/cli-contract.md §8`.

**Design/ergonomics:**
- **`enforce_index_trust` companion** (§11 S3): `verify_index_bundle` is PURE;
  `enforce_index_trust(result, policy, context_msg)` holds the 4-way
  result→slug dispatch. Neither is smeared into `load_index`.
- **`IndexTrustConfig` dataclass** (§11 S3/S5): bundles policy + trust_bundle +
  signer + max_age + verifier into one frozen dataclass passed to `load_index`.
  Prevents `index_cache.py` from importing `context.py`.
- **Warning cardinality** (§6.1): at most ONE index-trust warning per invocation,
  deduped by cache key.

**Feasibility:**
- **Mock verifier seam** (§10, §11 S7): injected `IndexBundleVerifier` protocol /
  trait; `MockVerifier` driven by `mock_verifier_result` in fixture `env`. Shared
  corpus tests POLICY STATE MACHINE only. Per-impl integration tests (excluded from
  corpus) exercise real `SigstoreVerifier` against committed test bundle.
- **`sigstore-rs` spike gate** (§11 S4, §12.1): dedicated spike before S4 confirms
  offline API + cert-at-SET-time availability.
- **Trust-bundle embedding** (§3.1): Python via `importlib.resources` over
  `milpa/_trust/`; Rust via `include_bytes!`. Test bundle in
  `conformance/spec-v1/_oracle/test_trust_bundle.json`, test-only in both impls.
- **S5 + S7 merged** (§11 S5): original S5 (policy wiring) and S7 (cache
  verify-on-every-read) both rewrite `load_index` — merged into one Python slice
  and one Rust slice. `load_index` is touched exactly once.
- **Error codes land with raise sites** (§11 S5/S6): bijection invariant enforced;
  codes added to `spec/errors.md` + `errors.py` in the SAME commit as raise sites.
  Spec-only S2 adds NO error codes.

---

## Slice checklist (all unchecked — no code yet)

- [ ] S1 — SSOT policy unification (both impls): `trust.py` (new) + `TrustPolicy`;
  rename `permissive`→`warn` in `attestation-policy`; replace `effective_strict_policy`
  with `effective_trust_policy`; shared `_parse_trust_policy`. Rust: 4-crate scope
  (`milpa-manifest/src/trust.rs` new; `milpa-manifest/src/lib.rs+format.rs`;
  `milpa-core/src/resolver.rs` rename; `milpa-core/src/lib.rs` BREAKING pub-API
  rename `AttestationPolicy`→`TrustPolicy`; `milpa-core/src/discovery.rs`;
  `milpa-cli/src/main.rs`; `milpa-conformance/src/runner.rs`; `*_tests.rs`).
  No fixture edits needed (no `permissive` in conformance corpus).
  Gate: both impls' existing suites green with the rename.
- [ ] S2 — Spec: whole-index gate: new "Whole-index attestation gate" subsection in
  `spec/registry-protocol.md` (does NOT touch §3.2; regression test stays valid);
  includes per-URL signer resolution and workspace conflicting-signers validation error.
  `MILPA_INDEX_TRUST` / `MILPA_INDEX_TRUST_SIGNER` / `MILPA_INDEX_TRUST_BUNDLE` /
  `MILPA_INDEX_MAX_AGE` / `MILPA_INDEX_BUNDLE_URL` / `--require-attested-index` /
  `--refresh-index` in `spec/cli-contract.md §8`. No impl files. No error codes.
- [ ] S3 — Whole-index verifier module (Python): new `index_trust.py`;
  `IndexBundleVerifier` protocol (7-variant `VerificationResult`, 6-way dispatch in
  `enforce_index_trust(result, policy, index_url)`); `SigstoreVerifier` (sigstore-python);
  `MockVerifier`; pure `verify_index_bundle`; `IndexTrustConfig` frozen dataclass
  (NO `verifier` field — verifier is explicit param of `load_index`); `TrustBundle`
  (PRODUCTION / TEST); cert-at-SET-time; `max_age_seconds` in protocol.
  `sigstore` dep in pyproject.toml with rationale comment.
  Gate: `uv run pytest tests/test_index_trust.py` — MockVerifier unit tests ONLY.
  Integration test against real `_oracle/` bundle is gated at S5.
- [ ] S4 — Whole-index verifier module (Rust): parity with S3; `sigstore-rs` dep.
  **Spike gate first**: confirm offline API + cert-at-SET-time before coding.
  `MockVerifier` keeps conformance green if real API lags. If API insufficient,
  activate S4b.
- [ ] S4b (CONDITIONAL) — Rust SigstoreVerifier retrofit: ONLY if S4 spike finds
  `sigstore-rs` insufficient. Slot stays empty if spike succeeds.
- [ ] S5 — Policy surface + load_index hook + cache (Python) [merged S5+S7]:
  `index-trust` / `index-trust-signer` / `index-trust-bundle` manifest nodes;
  `IndexTrustConfig` on `ResolveParams`/`MilpaEnv`; authority model formula in
  `effective_trust_policy`; `--require-attested-index` + `--refresh-index` + all 5
  env reads in `cli.py`; `load_index(url, config, verifier, http_get,
  bundle_http_get)` signature; normative bundle-URL derivation; crypto verify every
  read (freshness only on network); bounded crash-recovery (one retry, hard-fail on
  second); workspace max-merge + per-URL signer resolution + conflicting-signers
  validation error; warn degraded-marker (`.kdl.no-bundle`); strict no-partial-cache;
  `milpa verify` gate (crypto only, no freshness); `remove`/`clean` no-op; `show`
  conditional gate; 6 `TNG-INDEX-*` codes in `errors.py` + `spec/errors.md` (bijection
  same commit); `impls/rust/crates/milpa-conformance/tests/corpus.rs` DEFERRED bucket;
  `sigstore` dep in pyproject.toml; integration test with freshness DISABLED.
  Implementation order: data-model plumbing first (manifest/context/cli/errors),
  THEN cache rewrite (atomicity is subtle).
- [ ] S6 — Policy surface + load_index hook + cache (Rust) [mirror S5]:
  milpa-manifest manifest fields (incl. `index-trust-bundle`); milpa-core
  `index_cache.rs` seam rewrite with `bundle_http_get`; 6 `TNG-INDEX-*` slugs;
  MOVE codes from DEFERRED to `implemented_error_codes()` in `corpus.rs`;
  `sigstore` crate dep in Cargo.toml.
- [ ] S7 — Conformance fixtures (whole-index, policy state machine via mock seam):
  `cmd: index-trust` in both runners; `mock_verifier_result` env field; **18** fixture
  scenarios (§10.3 — 12 original + 6 new: `off-*`, `manifest-off-env-strict`,
  `manifest-warn-env-off`, `workspace-conflicting-signers`);
  `conformance/spec-v1/_oracle/test_trust_bundle.json`. Both runners byte-identical
  on policy outcomes.

---

## Follow-on issues to file (before or alongside implementation)

1. **tianguis whole-index `index.kdl.bundle` delivery** (tianguis cross-repo):
   update `reindex.yaml` / `vendor.yaml` to commit `index.kdl.bundle` alongside
   `index.kdl`; fetchable at `<MILPA_INDEX_URL>.bundle`. Must be filed before S5/S6
   production wiring. S3/S4 can proceed without it.

2. **Part-2 per-entry author-attribution** (milpa repo): follow-on to this RFC,
   adjacent to #91. Covers: `spec/registry-protocol.md §3.2` inversions;
   `IndexVersion` field surface (`attestation`, `signed_by`, `rekor`); per-entry
   gate at version selection; 3 `TNG-ENTRY-*` codes; tianguis per-entry bundle
   delivery design.

3. **Observability** (milpa repo): a `milpa verify --verbose` / `milpa show
   --index-trust` command to display the cached index's signer identity,
   `integratedTime`, Rekor UUID, and freshness status for human audit. Not a
   slice in this RFC; file separately.

---

## Open forks (round 2 resolved; one CONFIRM + one implementation risk)

1. **CONFIRM: Authority model — `off` is project-only auditable opt-out.**
   Round 2 resolved this: `off` can ONLY be declared in `milpa.kdl`; env/flag may
   only STRENGTHEN, never set or clear `off`; `env=strict`/`env=warn` cannot
   override `manifest=off`. Confirm you accept this (vs operator-env-overrides-all).

2. **sigstore-rs offline API viability (S4 spike gate — top IMPLEMENTATION risk):**
   Confirm `sigstore-rs` supports (a) offline bundle verification and (b)
   cert-at-SET-time (`cert.valid_at(integrated_time)` or equivalent). If
   insufficient, S4b activates. This is the highest-risk unknown going into
   implementation.

(Remaining round-2 questions resolved: test trust root generation is gated at S5;
default-to-strict migration criteria are operational not spec decisions; TUF
rotation confirmed deferred with emergency bypass documented in §12.3.)

---

## Settled decisions (do not reopen)

1. **Trust model:** Keyless cosign / Sigstore. Trust root = embedded trust bundle
   (Fulcio CA + Rekor public key). NOT TOFU, NOT long-lived pinned keys.

2. **Layer 1 only in active RFC.** Layer 2 = Part 2 follow-on. Active RFC fully
   closes #103.

3. **SSOT:** One `TrustPolicy` type; `permissive`→`warn` rename; one
   `effective_trust_policy` function for both axes.

4. **Offline-capable.** Verification works without live Rekor access.

5. **Verify on every cache read.** Covers the poison-then-block hole (State 3).

6. **Library choice.** `sigstore-python` + `sigstore-rs`. Do NOT hand-roll
   crypto. Do NOT shell out to `cosign` at resolve time.

7. **Mock verifier seam.** Shared conformance corpus tests policy state machine
   via `MockVerifier`; per-impl integration tests exercise `SigstoreVerifier`.

8. **Error codes land with raise sites.** `spec/errors.md` + `errors.py` updated
   in the same commit as raise sites (S5 / S6). S2 is spec-only, no error codes.

9. **Active TNG-INDEX-* codes (6):** `BUNDLE-MISSING`, `BUNDLE-MALFORMED`,
   `SIGNATURE-INVALID`, `DIGEST-MISMATCH`, `SIGNER-MISMATCH`, `BUNDLE-STALE`.
