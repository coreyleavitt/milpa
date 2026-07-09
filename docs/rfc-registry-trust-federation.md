# RFC: Consumer-side registry trust — whole-index Sigstore verification

**Status:** ACTIVE — designed, Stage 2 architect review rounds 1 and 2 complete, ready for Stage 3.
**Issues:** #103 (integrity, this RFC); #91 (availability / publisher mirrors, separate follow-on).
**Umbrella:** #107 (registry trust & federation). Adjacent: #38 (Sigstore / SLSA).
**Milestone:** registry trust & federation (Tier 3 structural differentiation).

---

## 1. Scope

This RFC designs **#103 — consumer-side verification of the tianguis index's Sigstore
attestation at resolve time** (the integrity half of the registry trust story). This
revision covers **Layer 1 only**: whole-index attestation gate.

**Explicitly out of scope here:**

- **#91 — publisher-declared self-mirror availability** (the availability half). #91's
  mirror delivery rides the trusted-index channel that #103 establishes; it is
  a Part-2 follow-on designed separately once the trust channel is in place.
- **Layer 2 — per-entry author-attribution.** Layer 1 verifies every byte in the index
  cryptographically before any claim is trusted; per-entry verification adds only
  author-ATTRIBUTION (who signed a specific version), not additional integrity. Layer 2
  is deferred to a Part-2 follow-on (see end of this document).
- The *producer* side: that is settled and built (Sigstore keyless attestation
  as the publishing gatekeeper in tianguis; `docs/rfc-distribution-and-publishing.md`
  and the tianguis `rfc-registry.md`).

---

## 2. Problem

### 2.1 Trust-on-transport-alone

Today `load_index` in `impls/python/milpa/index_cache.py` (L151–251) fetches
`index.kdl` over HTTPS and passes the raw bytes directly to `parse_index` without
any signature or attestation check. The bytes-to-trusted seam is the assignment
at L207 (`fetched_text = http_get(url)`) followed immediately by `return
parse_index(fetched_text)` at L251. An adversary who controls the CDN delivery
path (GitHub raw CDN, a corporate MITM, a split-horizon DNS entry, or a
compromised network hop) can substitute arbitrary index bytes. The consumer's
`milpa lock` or `milpa fetch` will then resolve, fetch, and pin whatever the
adversary's index says. TLS protects against passive eavesdropping and random
interference; it does not protect against an active CDN-level substitute by an
authorized CDN operator.

The tianguis vendor-en-absentia workflow already emits a Rekor-anchored Sigstore
cosign attestation over `index.kdl` at every publish. The consumer never checks
it. The producer's security guarantee is unenforceable at the consumer end.

### 2.2 The poison-then-block pattern

The four-state cache in `index_cache.py` (docstring L9–15) has a specific
failure mode at State 3 (offline fallback, L211–222):

```python
if fetch_error is not None:
    if cache_file.is_file():
        text = cache_file.read_text()
        return parse_index(text)
```

An adversary who can (a) substitute a malicious `index.kdl` at the GitHub raw
URL long enough for one successful consumer fetch and (b) then restore the
legitimate file has already poisoned every consumer's local cache. On every
subsequent invocation, even if the live index is now correct, the consumer
re-reads the poisoned bytes from disk without any freshness or integrity check.
The adversary does not need persistent CDN control; a single successful inject
during the TTL window suffices.

This is not a theoretical scenario. The stale-fallback path exists precisely to
tolerate transient network failures — which are the same window an adversary
needs. The same bug exists in the Rust impl at
`impls/rust/crates/milpa-core/src/index_cache.rs` L83–86.

### 2.3 Spec currently says "ignored"

`spec/registry-protocol.md §3.2` (L211–246) currently contains four normative
clauses explicitly marking attestation data as inert to the resolver:

- L218: `"milpa's reader treats attestation as forward-compat metadata: it is
  parsed and then ignored."`
- L222: `"Informational; not enforced by milpa."`
- L238–241: The `rekor` block "MUST NOT cause a parse error. milpa does not
  validate or enforce Rekor entries during resolution; the block is forward-compat
  metadata for the tianguis.dev site and auditing tooling."
- L243–246: "`IndexVersion` carries no `rekor` field; Rekor data is inert to the
  resolver." (Enforced by the regression test `test_rekor_block_is_tolerated_and_ignored`.)

These four clauses cover per-entry attestation data in `IndexVersion` nodes.
Layer 1 does NOT invert them; per-entry field surfacing is deferred to Part 2.
Instead, Layer 1 **adds new normative text** to `spec/registry-protocol.md`
describing the whole-index gate that fires before any index bytes reach the
parser. The existing regression test remains valid.

---

## 3. Trust model

### 3.1 Trust root composition

milpa uses **keyless cosign / Sigstore** verification. The trust root is a
**pinned Sigstore trust bundle** embedded in the milpa distribution containing:

- The Fulcio certificate authority root certificate (or chain) for the Sigstore
  public instance.
- The Rekor public key for the Sigstore public instance.

This is the same trust model used by `cosign verify` without a `--key` flag.
The trust bundle is NOT fetched at runtime; it is embedded at build time and
rotated only via explicit milpa version update. TUF-based root rotation is a
future extension (§12.3).

Two trust bundle constants exist in both impls:

- `PRODUCTION_TRUST_BUNDLE` — embedded via `importlib.resources` over a
  `milpa/_trust/` package-data directory (Python, wheel-included) or
  `include_bytes!` (Rust). Production code uses only this constant.
- `TEST_TRUST_BUNDLE` — loaded from `conformance/spec-v1/_oracle/
  test_trust_bundle.json`. Used only in test code (`#[cfg(test)]` in Rust;
  test-only import in Python). Production code MUST NEVER reference the test
  bundle.

### 3.2 Signer identity and override

The pinned default signer identity for the whole-index attestation is the GitHub
Actions OIDC identity of the tianguis reindex workflow:

```
SubjectAltName issuer: https://token.actions.githubusercontent.com
SubjectAltName value:  https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml@refs/heads/main
```

This identity is pinned because its source is the authoritative public repository;
changing it requires a milpa release.

**Non-default registry override:** A user running a custom `MILPA_INDEX_URL`
(e.g., a private registry) needs a way to configure the expected signer identity
and/or an alternate trust root. Four mechanisms exist — two env vars and two
manifest nodes — covering orthogonal concerns:

- `MILPA_INDEX_TRUST_SIGNER "<identity>"` env var — overrides the expected signer
  IDENTITY only: a GitHub Actions OIDC workflow URL / expected SubjectAltName.
  Default: the pinned tianguis vendor-bot identity above. Does NOT accept a
  `file://` path; use `MILPA_INDEX_TRUST_BUNDLE` for trust-root overrides.
- `MILPA_INDEX_TRUST_BUNDLE "<file://path>"` env var — a `file://` path to an
  alternate Fulcio CA root + Rekor public key bundle for PRIVATE Sigstore
  instances. Overrides the `trust_bundle: TrustBundle` parameter in the verifier
  seam. Orthogonal to `MILPA_INDEX_TRUST_SIGNER`.
- `index-trust-signer "<identity>"` — a new top-level node in `milpa.kdl` that
  persists the signer IDENTITY override; parsed alongside `index-trust`.
- `index-trust-bundle "<file://path>"` — a new top-level node in `milpa.kdl`
  that persists the trust-ROOT override; orthogonal to `index-trust-signer`.

When `MILPA_INDEX_URL` is non-default and no signer override is configured,
resolves under `warn` policy proceed with a `TNG-INDEX-SIGNER-MISMATCH` warning;
under `strict` they fail. Setting `index-trust "off"` in `milpa.kdl` is the
intentional escape for unsigned private registries; `off` can ONLY be declared
in the manifest (auditable in version control) — see §6.6 for the authority
model.

### 3.3 What keyless Sigstore provides

- **No long-lived keys.** The signing key is ephemeral, created by the GitHub
  Actions runner and certified by Fulcio against a short-lived OIDC token.
- **Transparency-log anchoring.** Every signing event is logged in Rekor with an
  inclusion proof. The bundle contains the signed entry timestamp (SET) — a
  counter-signed Rekor log entry that proves the signature existed at a specific
  time.
- **Offline verifiability.** The bundle contains all material needed to verify the
  signature against the embedded Fulcio root and the inclusion proof against the
  embedded Rekor public key. No live Rekor query is needed at resolve time.
- **Freshness-window protection.** By asserting
  `now - SET.integratedTime < MILPA_INDEX_MAX_AGE` at network-fetch time, milpa
  closes the rollback attack vector: a network adversary serving an old but
  validly-signed (index, bundle) pair is caught because `integratedTime` is
  embedded in the bundle and checkable offline (§7). An air-gapped deployment
  performs ONE network `milpa fetch`; subsequent offline cache reads never fail
  on staleness (freshness is only re-evaluated when the network is next reached).

### 3.4 What this model does NOT provide

- Per-package author reputation (milpa does not operate a web-of-trust).
- Real-time revocation. Compromised-author recovery requires a new vendor-bot
  reindex pass (this is a tianguis ops concern, not a milpa protocol concern).
- TUF metadata freshness / root rotation (follow-on, §12.3).
- Per-entry author attribution (Layer 2, deferred to Part 2).
- **Rollback protection within the freshness window.** Within `MILPA_INDEX_MAX_AGE`
  (default 7 days) a validly-signed OLDER index can still be served; milpa will
  accept it as fresh. Lowering `MILPA_INDEX_MAX_AGE` tightens the window at the
  cost of requiring network access that often; the 7-day default is a
  deployment-smoothness tradeoff.

---

## 4. Whole-index attestation gate

**What:** Verify the vendor-bot's cosign attestation bundle over the full
`index.kdl` document before trusting ANY claim in the index.

**When:** Immediately after fetching (or reading from cache) the index bytes and
BEFORE passing them to `parse_index`. This is the seam at:

- Python: `index_cache.py` between L207 (`fetched_text = http_get(url)`) and
  L251 (`return parse_index(fetched_text)`). The bundle is fetched/cached in
  parallel with the index; verification fires on all four cache states.
- Rust: `index_cache.rs` between L80 (`let text = match http_get(url)`) and
  L107 (`Index::parse(&text)`); and the cached-read path at L74–76.

**Why at this seam:** Verifying before parsing means a tampered index never
reaches the parser. A tampered-but-parses-clean index cannot be used to inject
packages, provenances, or attested metadata.

**Input:** The raw bytes of `index.kdl` and the corresponding Sigstore bundle
(a JSON file containing the certificate, the DSSE envelope, and the Rekor
inclusion proof / signed entry timestamp).

**Verification steps (normative):**

1. Parse the bundle JSON. If the bundle is not valid JSON or does not conform
   to the Sigstore bundle schema, raise `TNG-INDEX-BUNDLE-MALFORMED` (this is a
   pre-crypto failure distinct from a cryptographic failure).
2. Extract `integratedTime` from `verificationMaterial.tlogEntries[0].integratedTime`.
   If the field is absent or non-integer, raise `TNG-INDEX-BUNDLE-MALFORMED`.
   This timestamp anchors both the freshness check (step 3) and cert-at-SET-time
   validation (step 4).
3. **Network-fetch path only:** Assert `now - SET.integratedTime < MILPA_INDEX_MAX_AGE`
   (default 7 days; offline-checkable because `integratedTime` is in the bundle). On
   exceed: raise `TNG-INDEX-BUNDLE-STALE`. This freshness assertion fires ONLY when
   the bundle was obtained via a network fetch (cache State 2, or any path that reaches
   the network). Freshness is placed here — after integratedTime extraction (step 2)
   and before cryptographic verification (steps 4–7) — because it needs only the parsed
   timestamp; failing fast on staleness is fail-closed. On a PURE CACHE READ (States 1
   and 3) step 3 MUST NOT be asserted; steps 1–2 and 4–7 MUST still be executed.
   Rationale: the rollback attack is a network-delivery attack; defending at the fetch
   boundary fully closes it. Re-asserting wall-clock freshness on offline cache reads
   breaks air-gapped use without adding security.
4. Decode and validate the bundle's certificate against the embedded Fulcio root.
   Certificate validity MUST be checked at the Rekor SET `integratedTime`, NOT
   current wall-clock time. Checking `cert.NotAfter >= now` is INCORRECT and
   MUST NOT be implemented: Fulcio issues ~10-minute certificates, so every real
   bundle's cert will be expired by wall-clock but was valid at signing time.
   `TNG-INDEX-SIGNATURE-INVALID` is raised only when the certificate was expired
   at its own `integratedTime`; a cert now-expired but valid at SET time MUST
   verify successfully. The `sigstore-rs` spike (§12.1) MUST confirm that the
   cert-at-SET-time property is available in the library API before S4 begins.
5. Confirm the certificate's SubjectAltName matches the expected signer identity
   (default: pinned vendor-bot OIDC identity; overridable via §3.2). Mismatch
   raises `TNG-INDEX-SIGNER-MISMATCH`. Implementations MUST detect this via the
   verification policy call-site, not by matching exception message text.
6. Verify the DSSE envelope signature using the cert's public key. After successful
   signature verification, extract the in-toto statement from the verified DSSE
   payload and assert `statement.subject[0].digest.sha256 == sha256(index_bytes)`.
   The signature covers the DSSE envelope payload (an in-toto statement), NOT raw
   index bytes. A digest mismatch raises `TNG-INDEX-DIGEST-MISMATCH`. Implementations
   MUST detect digest mismatch from the verified payload, NOT from exception message
   text. Fixture-generation tooling MUST produce DSSE bundles (`cosign attest-blob`
   shape), not raw signatures.
7. Verify the Rekor inclusion proof / signed entry timestamp against the embedded
   Rekor public key. Failure raises `TNG-INDEX-SIGNATURE-INVALID`.

If all seven verification steps pass: `index_bytes` is decoded to `str` for
parsing. A `UnicodeDecodeError` (non-UTF-8 index bytes — e.g., a tianguis
encoding bug over a validly-signed blob) MUST surface via the existing
index-parse error path, NOT as a bare exception. The exact error slug is chosen
in S5 (reusing the existing index-parse/KDL-parse error code if one exists; no
new TNG code is introduced unless none exists). This is a normative requirement,
not an implementation detail.

Steps 1–7 are executed by the `sigstore-python` library (Python) or the
`sigstore-rs` crate (Rust). milpa does not implement signature or
transparency-log verification internally.

**Single-read invariant:** `index_bytes` is read ONCE and the same in-memory
bytes object is passed to both `verify_index_bundle` and `parse_index`. There
is NO second disk read between verification and parsing (TOCTOU prevention).

---

## 5. Verification mechanics

### 5.1 Bundle format

A **Sigstore bundle** (`.bundle` or `*.sigstore.json`) is the standard cosign
output format from `cosign attest-blob`. It is a JSON document carrying:

- `mediaType` identifying the bundle format version.
- `verificationMaterial.x509CertificateChain` — the signing cert chain.
- `verificationMaterial.tlogEntries[]` — one or more Rekor transparency-log
  entries (each carrying an inclusion proof + signed entry timestamp).
- `dsseEnvelope` — the DSSE envelope (payload + signatures).

The DSSE payload for an `attest-blob` bundle is a JSON `in-toto` attestation
statement whose subject is the sha256 digest of the signed file. Verification
step 6 (§4) extracts `statement.subject[0].digest.sha256` from the verified DSSE
payload and asserts it matches `sha256(index_bytes)`. The signature covers the
DSSE envelope, which in turn attests to the bytes' digest; it does NOT cover the
raw `index.kdl` bytes directly.

### 5.2 Offline verification

Verification MUST work without live Rekor network access. The bundle carries an
inclusion proof (a Rekor signed entry timestamp) that can be verified offline
against the embedded Rekor public key. Online Rekor query is at most an optional
freshness cross-check; it is never a hard dependency at resolve time.

This is critical for CI environments with restricted egress, air-gapped
deployments, and offline laptop development. An air-gapped deployment performs
ONE network `milpa fetch` to prime the cache; subsequent offline cache reads
re-verify the cryptographic chain (steps 1–2 and 4–7: cert-at-SET-time, DSSE
digest, inclusion proof, signer identity) but do NOT re-assert the wall-clock
freshness bound (step 3) — so they never fail on staleness. The freshness bound
is only re-evaluated when the network is next reached (§7.2).

The `sigstore-python` and `sigstore-rs` libraries both support offline bundle
verification when the bundle carries an inclusion proof. The Rust library's
offline API stability must be confirmed before S4 begins (§12.1 spike gate).

### 5.3 Library choice and dependency justification

**Python:** `sigstore-python` (`sigstore` package on PyPI). Maintained by the
Sigstore project; supports offline bundle verification against a custom trust
root. Added to `impls/python/pyproject.toml` as a direct dependency.

**Rust:** `sigstore` crate (`sigstore-rs`). The Sigstore project's Rust library.
Added to `impls/rust/crates/milpa-core/Cargo.toml`.

Both are deliberate, justified exceptions to milpa's dep-light posture:
signature and transparency-log verification MUST NOT be hand-rolled, and
shelling out to the `cosign` binary at resolve time is unacceptable (adds an
external binary dep on every user's machine, creates shell-injection surface,
and makes conformance testing harder). The libraries are the correct abstraction.

The library additions MUST be recorded in a `deps-rationale` comment in both
`pyproject.toml` and `Cargo.toml` explaining the exception.

---

## 6. Failure policy and configuration surface

### 6.1 Policy values

The `index-trust` field in `milpa.kdl` controls the failure policy for
whole-index verification.

| Policy value | Behavior on verification failure |
|---|---|
| `"warn"` (default) | Verify; resolve proceeds; emit one loud stderr warning per invocation. |
| `"strict"` | Hard fail; raises the appropriate `TNG-INDEX-*` error. |
| `"off"` | Skip verification entirely. |

**Detection vs prevention:** Under `warn`, the gate provides tamper DETECTION
(a visible warning appears) but NOT PREVENTION — the resolve still proceeds using
the (potentially tampered) index. The CDN-substitution threat (§2.1) is closed
only under `strict`. Users with supply-chain integrity requirements MUST set
`strict`. The default of `warn` exists for deployment smoothness during the
transition period before all tianguis packages have attestation coverage; it is
not a security default.

**Machine-readable warn signal:** Under `warn`, the `TNG-INDEX-*` slug embedded
in the stderr warning IS the machine-readable signal — CI systems can match the
`TNG-INDEX-` prefix to detect index-trust failures non-intrusively. Exit code
stays 0 under `warn` (nonzero would contradict "warn proceeds"). Under `strict`,
the slug is the raised error code.

**Warning dedup key:** The dedup key is the `MILPA_INDEX_URL` value — at most
one warning is emitted per UNIQUE index URL per invocation. A workspace with N
distinct index URLs emits at most N warnings. (Non-normative note: impls MAY
further suppress repeated identical warnings within a session; this is not a
tested conformance guarantee, to avoid time-dependence in fixtures.)

**Flipping the default to `strict`:** Once all tianguis-published packages have
attestation coverage AND the bundle-delivery contract (§9) is stable, a milpa
minor version bump changes the default from `warn` to `strict`.

### 6.2 CLI flags

`--require-attested-index` — a CI hard-fail toggle. When set, the effective
policy is escalated from `warn` to `strict`. The flag can ONLY STRENGTHEN the
policy (warn→strict); it CANNOT set or clear `off`. When the manifest declares
`index-trust "off"`, the flag has no effect — `off` is a positive, auditable
opt-out that only the committed manifest can declare. See §6.6 for the authority
model. Mirrors `--require-attested-metadata` at `cli.py:230–236`.

`--refresh-index` — forces a fresh index + bundle fetch, bypassing the cache
TTL. Use when upgrading from a pre-RFC cache (which has no bundle sidecar) to
force immediate re-fetch and sidecar creation.

### 6.3 Environment knobs

- `MILPA_INDEX_TRUST` — accepts `"warn"`, `"strict"`, or `"off"`. `"off"` in
  the env is a no-op floor (cannot disable a project's `warn`/`strict`); env
  may only strengthen. See §6.6 for the authority model.
- `MILPA_INDEX_TRUST_SIGNER` — overrides the expected signer IDENTITY (a GitHub
  Actions OIDC workflow URL / expected SubjectAltName). Does NOT accept a
  `file://` trust-bundle path; use `MILPA_INDEX_TRUST_BUNDLE` for that.
- `MILPA_INDEX_TRUST_BUNDLE` — a `file://` path to an alternate Fulcio CA root
  + Rekor public key bundle for PRIVATE Sigstore instances. Overrides the
  embedded `PRODUCTION_TRUST_BUNDLE`. Orthogonal to `MILPA_INDEX_TRUST_SIGNER`.
- `MILPA_INDEX_MAX_AGE` — freshness window in seconds (default: 604800 = 7 days).
- `MILPA_INDEX_BUNDLE_URL` — explicit URL for the Sigstore bundle, overriding the
  derived `<index-url>.bundle` (§7.3). Use when suffix-derivation is not viable
  (e.g., a separate artifact host).

All five are declared alongside `MILPA_INDEX_URL` in `spec/cli-contract.md §8`.

### 6.4 Manifest fields

`index-trust "<policy>"` is a new top-level node in `milpa.kdl`, parsed alongside
`attestation-policy`. `index-trust-signer "<identity>"` overrides the expected
signer IDENTITY (§3.2). `index-trust-bundle "<file://path>"` overrides the trust
ROOT (§3.2) — orthogonal to `index-trust-signer`. All three share the unified
`TrustPolicy` type (for the policy field) and the `TrustBundle` / signer seams
introduced in S1 (§6.6). Parser seam: `manifest.py` alongside `attestation-policy`
at L1001–1019.

In the Rust impl, mirrors `attestation_policy` in `milpa-manifest/src/lib.rs`.

### 6.4a Workspace root authority (SUPERSEDES the original max-merge design)

> **Redesign note:** the original S1–S7 build of this RFC shipped a
> "workspace policy merge" (MAX over root + all member policies, plus a
> conflicting-signers validation error across members). That design was a
> scope error: the registry index is a process-global, workspace-shared
> resource (one index URL per invocation, no per-member index URL), so
> index-trust is a property of the **resolution root**, not of each member.
> The text below describes the corrected, current design. The historical
> slice narration further down this document (S5/S6/S7) describes what was
> originally built and is kept for the historical record; where it conflicts
> with this section, this section is authoritative.

The index is loaded ONCE per workspace invocation. `index-trust`,
`index-trust-signer`, and `index-trust-bundle` are declared ONLY on the
**resolution root**:

- Standalone package: the package manifest itself (unchanged).
- Workspace: the workspace ROOT manifest (the one carrying
  `workspace { member … }`). The workspace-root grammar permits these three
  nodes as top-level nodes alongside `workspace { }` — they are neither
  `deps` nor `kind`, so the deps/kind rejection is unaffected.

The effective policy for a workspace invocation is simply the root's own
`index-trust` value (default `warn`) — there is no merge. A workspace root
declaring `index-trust "off"` disables the gate for the whole workspace; this
was structurally unreachable under the old max-merge design (see the old S7
`workspace-conflicting-signers` scenario note above) and is now the whole
point of the redesign.

A workspace MEMBER manifest declaring ANY of the three index-trust nodes is a
HARD validation error — `WS-INDEX-TRUST-ON-MEMBER` — raised at workspace-load
time, BEFORE any index fetch, even when the declared value matches the
default (e.g. an explicit `index-trust "warn"` on a member still errors: the
rule is about WHERE the field is declared). This supersedes the old
per-URL conflicting-signers check; per-URL signer/bundle grouping across
members is now moot because members cannot declare signer/bundle at all.

### 6.5 Error codes

The following six slugs are added to `spec/errors.md` and `errors.py`. All carry
the `TNG-` prefix (tianguis index client domain):

| Slug | Condition |
|---|---|
| `TNG-INDEX-BUNDLE-MISSING` | No bundle sidecar is available alongside the index. Strict: hard fail. Warn: proceed with warning and remediation hint. |
| `TNG-INDEX-BUNDLE-MALFORMED` | Bundle JSON fails to parse or is not a valid Sigstore bundle (pre-crypto failure, before any signature check). |
| `TNG-INDEX-SIGNATURE-INVALID` | Cryptographic verification failed — bad cert chain, wrong Fulcio CA root, or certificate expired AT `integratedTime`. A cert now-expired but valid at `integratedTime` MUST NOT trigger this error. |
| `TNG-INDEX-DIGEST-MISMATCH` | The bundle's attested subject digest (`statement.subject[0].digest.sha256`) does not match `sha256(index_bytes)`. Indicates tampering after attestation or a mismatched bundle/index file pair. |
| `TNG-INDEX-SIGNER-MISMATCH` | The bundle's certificate SubjectAltName does not match the expected signer identity (pinned vendor-bot or configured override via §3.2). |
| `TNG-INDEX-BUNDLE-STALE` | `now - SET.integratedTime >= MILPA_INDEX_MAX_AGE`. Bundle is cryptographically valid but was signed beyond the maximum allowed age; indicates a rollback attack or a frozen CDN. |

All six slugs follow the `TNG-*` error catalog conventions in `errors.py`
(L261–282) and the bijection discipline enforced by `tests/test_errors.py`.
Error codes land in `spec/errors.md` AND `errors.py` in the SAME slice as their
raise sites (S5 for Python, S6 for Rust). The spec-only slice S2 does NOT add
error codes to `errors.py`.

**Note on terminology:** The slug uses `DIGEST-MISMATCH` (not `IDENTITY-MISMATCH`)
because "identity" is a load-bearing term in milpa meaning `content_hash` of a
source tree. Using it for a bundle-subject mismatch would create a false collision
with milpa's identity model.

### 6.6 Effective-policy computation and SSOT

The existing `AttestationPolicy = Literal["permissive", "strict"]` in `manifest.py`
and `effective_strict_policy(...)` in `attestation.py` (L52–75) are a parallel
mechanism to the new `index-trust` policy. milpa forbids duplicate mechanism. S1
unifies them:

- One shared `TrustPolicy = Literal["warn", "strict", "off"]` type in a new
  `trust.py` module (Python) / corresponding module in `milpa-manifest` (Rust).
- The existing user-facing `permissive` value in `attestation-policy` is renamed
  to `warn` (pre-v1 breaking change; clean cutover, no legacy alias). `off` is
  added as a new value.
- `effective_strict_policy(...)` is replaced by ONE
  `effective_trust_policy(manifest_value, flag, env_override) -> TrustPolicy`
  function shared by BOTH axes (attestation-policy and index-trust). Both
  manifest fields parse to `TrustPolicy` via a shared `_parse_trust_policy` helper.

The two CONFIGURATION AXES remain separate — they govern different things (dep-
metadata attestation vs index integrity). Only the mechanism is unified.

**Effective-policy formula (both axes):**

```python
# off is a positive, auditable opt-out: ONLY the committed manifest can disable
# verification. Env and the flag can only STRENGTHEN; neither can set or clear off.
if manifest_policy == "off":
    return "off"
base = max(manifest_policy or "warn", env_override_if_strengthening)  # over {warn, strict}
# MILPA_INDEX_TRUST=off in the ENV is a no-op floor: it cannot weaken a manifest warn/strict.
if flag:
    return "strict"
return base
```

Authority model: `off` can ONLY be declared in `milpa.kdl` (auditable in version
control). `MILPA_INDEX_TRUST=off` in the environment is a no-op floor — it cannot
disable a project's `warn` or `strict`. Env and `--require-attested-index` may
only STRENGTHEN the policy (never set or clear `off`). `env=strict`/`env=warn`
cannot override `manifest=off`. This resolves the round-1 parked question: the
`manifest=off + env=warn → warn` case is intentionally NOT allowed; project
opt-outs are not overridable by CI env.

**Distinct env vars:** The existing attestation-policy strict env var is
`MILPA_REQUIRE_ATTESTED_METADATA` (governs dep-metadata attestation per `cli.py`
L3037–3043). The new index-trust env var is `MILPA_INDEX_TRUST` (governs
whole-index verification). These are DISTINCT names governing DISTINCT axes; no
collision exists. This formula replaces `attestation.py:52–75` for both axes.

### 6.7 Command coverage

The whole-index gate fires during: `fetch`, `lock`, `show`, `add`, `update`.

`milpa verify` also fires the gate: it re-verifies the cached bundle's
cryptographic chain OFFLINE but does NOT assert wall-clock freshness (so offline
audit works; freshness is a fetch-boundary concern). This is the `verify`
subcommand's index-trust contribution.

`milpa remove` and `milpa clean` do NOT load the index: `remove` operates on
manifest dep-node identity; `clean` operates only on `_deps/`. Neither fires
the index-trust gate.

`milpa show` fires the gate ONLY when it actually loads the index. A
lockfile-only `show` (no index fetch required) does NOT fire the gate — the
same treatment as the frozen path. Combined with Group-A fetch-time-only
freshness, a cached-index `show` works fully offline.

The frozen path (`fetch --frozen`, `frozen.py`) does NOT load the index; the
lockfile is the trust anchor. Index-trust has no effect on frozen invocations.

When `--no-index` is active (`MilpaEnv.no_index`, `context.py:86`), no index
is loaded and no index-trust verification fires. `MILPA_INDEX_TRUST` and
`--require-attested-index` are silently no-ops under `--no-index`.

---

## 7. Cache / staleness redesign

### 7.1 The bug: verify-on-fetch-only does not close the poison-then-block hole

A naive approach (verify on fetch, store verified bytes to cache, trust the
cache) still leaves the poison window:

1. A stale cache written before this RFC's implementation contains no bundle and
   no verified state; the upgrade path would need a migration or forced re-fetch.
2. A future cache implementation bug or a system-level file replacement can
   silently replace the cached bytes between writes. Verifying on fetch provides
   no ongoing integrity guarantee.

### 7.2 Bundle-bound cache: verify crypto on every read, freshness only on network

The correct fix is: **verify the cryptographic chain on every cache read** (not
just on fetch), but assert the **wall-clock freshness bound only at network-fetch
time** (States 2 and any path that reaches the network). The cryptographic
verification is cheap (pure crypto, no network); the freshness restriction avoids
breaking air-gapped/offline use (§5.2).

The cache acquires sidecar files. Consistent stem: `rm <key>.index.kdl*` cleans all.

```
<cache_key>.index.kdl          ← index content (existing)
<cache_key>.index.kdl.at       ← fetch-time stamp (existing)
<cache_key>.index.kdl.bundle   ← Sigstore bundle (NEW)
<cache_key>.index.kdl.no-bundle ← degraded marker (warn only, see below)
```

**Atomic write:** The bundle is fetched and written before the index file is
renamed into place. Two sidecar files cannot be written truly atomically at the
filesystem level; a crash between bundle-write and index-rename leaves a
mismatched pair.

**Crash recovery (bounded):** On a CACHE READ (States 1 or 3), a digest-mismatch or
missing bundle sidecar due to an interrupted write → silently DELETE both
sidecars and fall through to a fresh network fetch (ONE recovery refetch). If
the network-refetched (index, bundle) pair ALSO fails verification, HARD-FAIL
regardless of policy: a second consecutive mismatch is not an interrupted-write
scenario but an active-adversary signal. Do NOT loop. This is a normative
invariant (both impls behave this way). Reserve hard-fail for a NETWORK-FETCHED
mismatch (State 2 or the recovery refetch): the live index bytes do not match
the live bundle indicates an active adversary.

**Single-read invariant:** `index_bytes` is read ONCE. The same in-memory bytes
object is passed to both `verify_index_bundle` and `parse_index`. There is no
second disk read between verification and parsing.

**Transport boundary:** `HttpGet` is now `bundle_http_get: Callable[[str], bytes]`
for bundle fetches and `http_get: Callable[[str], bytes]` for index fetches —
two SEPARATE injectable transports. This matches the `fetchers/tarball.py`
pattern and keeps per-URL mock state simple in tests (each can be faked
independently). `load_index` decodes `index_bytes` to `str` for parsing but
keeps `bundle_bytes` as `bytes` for verification.

Revised `load_index` signature and logic:

```
load_index(url, config, verifier, http_get, bundle_http_get) → Index
  fetch_or_load() → (index_bytes: bytes, bundle_bytes: bytes)
  verifier.verify(index_bytes, bundle_bytes, trust_bundle, expected_signer,
                  max_age_seconds=config.max_age_seconds if network else SKIP_FRESHNESS)
  parse_index(index_bytes.decode("utf-8"))  # decode failure → index-parse error path
```

Note: `verifier` is an EXPLICIT parameter of `load_index`, NOT a field on
`IndexTrustConfig`. A verifier is a behavioral dependency; embedding a production
default in config makes tests silently run against real Sigstore if they forget
to override. Production passes `SigstoreVerifier()`; tests pass `MockVerifier(...)`.

All four cache states (plus the bundle-404 case):

| State | index source | bundle source | crypto verified | freshness asserted |
|---|---|---|---|---|
| 1 — fresh | disk | disk | YES (before parse) | NO (pure cache read) |
| 2 — stale-refetch | network | network | YES (before parse) | YES (network fetch) |
| 3 — offline-fallback | disk | disk | YES (before parse) | NO (pure cache read) |
| 4 — no cache | raise `MILPA-INDEX-UNREACHABLE` | — | — | — |
| bundle 404, strict | any | missing | — | — |
| bundle 404, warn | any | missing | — | — |

Under `strict`, a bundle 404 raises `TNG-INDEX-BUNDLE-MISSING`; do NOT cache the
index without its bundle sidecar. Under `warn`, a bundle 404 MAY cache the index
with a `.kdl.no-bundle` degraded-marker sidecar so the normal TTL governs
refetch cadence (without this, every invocation worldwide re-fetches from the CDN
during the pre-bundle transition window). The bundle is retried on the next TTL
expiry. The degraded-marker path only applies under `warn` and only when the
bundle endpoint 404s (not for other bundle errors).

Under `strict`, any verification failure rejects the resolve. Under `warn`, the
resolve proceeds with a loud stderr warning including the `TNG-INDEX-*` slug.

**Cross-process concurrency:** NO advisory file lock is required across processes.
A racing reader that observes a half-written (index, bundle) pair triggers
crash-recovery (digest mismatch → single bounded refetch per above), which is
safe and self-correcting. This is a CONFORMANCE guarantee — both impls behave
this way — not one impl's incidental behavior.

### 7.3 Bundle acquisition

The bundle for the whole-index attestation is fetched from a **normatively
derived** URL. Bundle-URL derivation is: strip any query string and fragment from
`MILPA_INDEX_URL`; append `.bundle` to the URL PATH; then reattach the original
query string and fragment. (Naive string suffixing breaks `?ref=main` and
trailing-slash URLs.) For the default index URL:
`https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl.bundle`

`MILPA_INDEX_BUNDLE_URL` env override (§6.3) bypasses derivation entirely for
URLs where suffix-derivation is not viable (e.g., a separate artifact host).

The bundle fetch uses a SEPARATE injectable `bundle_http_get: Callable[[str], bytes]`
transport distinct from the index `http_get`. Both return `bytes`. This keeps
per-URL mock state simple in tests; see §9 for the tianguis production contract.

### 7.4 Upgrade migration

A warm pre-RFC cache (no bundle sidecar) triggers `TNG-INDEX-BUNDLE-MISSING`
under default `warn` policy. The warning text MUST include a remediation hint:

```
milpa: index-trust warning (TNG-INDEX-BUNDLE-MISSING): no attestation bundle
for the cached index. Run 'milpa fetch --refresh-index' to re-fetch with
attestation, or set 'index-trust "off"' in milpa.kdl to suppress.
```

Under `warn`, if the bundle endpoint 404s, a `.kdl.no-bundle` degraded-marker
sidecar is written alongside the cached index so the normal TTL governs refetch
cadence (see §7.2). Under `strict`, the resolve is rejected; no partial-cache
state is written.

`--refresh-index` forces a fresh index + bundle fetch (bypasses the cache TTL)
to restore the bundle sidecar. The default fires every resolve until the bundle
is present; the default `warn`→`strict` flip waits until tianguis bundle-delivery
is stable and attestation coverage is complete.

### 7.5 Post-incident remediation

If a user ran `milpa lock` during a poison window (§2.2), `milpa verify` reports
GREEN — the lockfile hashes match the malicious `_deps/` contents. Remediation:

1. Delete `milpa.lock`.
2. `milpa fetch --refresh-index` to force a clean index + bundle re-fetch,
   bypassing any poisoned cache state.
3. `milpa lock` to re-resolve from the clean index.
4. Diff the new vs. old lockfile to spot changed dep versions or hashes.

Content-addressing (`rfc-content-addressed-identity.md`) is defense-in-depth: a
changed `content_hash` in the re-resolved lockfile is a detectable attack signal.
The diff surface is thus minimal and auditable even without prior lockfile backups.

---

## 8. Spec changes

### 8.1 `spec/registry-protocol.md` — new whole-index gate subsection

Layer 1 does NOT modify `spec/registry-protocol.md §3.2`. The per-entry
attestation clauses ("parsed and ignored") remain as-is for now; they are
inverted in Part 2 when per-entry author-attribution is implemented. The
regression test `test_rekor_block_is_tolerated_and_ignored` is NOT inverted;
it remains a correct characterization of behavior under Layer 1 alone.

Instead, S2 (the spec slice) adds a NEW subsection to
`spec/registry-protocol.md` after §3.2, titled **"Whole-index attestation gate"**.
This subsection is normative and specifies:

- The index bytes MUST be verified against a valid Sigstore bundle before any
  claim in the index is trusted.
- The verification steps from §4 of this RFC (bundle parsing, cert-at-SET-time,
  DSSE subject-digest binding, signer identity match, freshness window) are
  normative requirements.
- The failure policy (`index-trust`: warn/strict/off) governs behavior on
  verification failure.
- The bundle is delivered at the normatively derived URL (§7.3): strip query
  and fragment from `MILPA_INDEX_URL`, append `.bundle` to the path, reattach
  query/fragment. Overridable via `MILPA_INDEX_BUNDLE_URL` env var.
- Crypto verification fires on every cache read (fresh, stale-refetch, and
  offline-fallback); freshness assertion fires ONLY on network-fetch paths.
- The single-read invariant (same in-memory bytes to verify and parse).
- Under `warn`, a bundle-404 MAY use a `.kdl.no-bundle` degraded-marker sidecar
  (§7.4); under `strict`, no partial-cache state is written.

### 8.2 `spec/errors.md` additions

The six new `TNG-INDEX-*` codes from §6.5 are added as `### \`slug\`` catalog
entries in `spec/errors.md` under the `## TNG` section (alongside
`TNG-DEPDECL-HASH-MISMATCH` at L268). Each entry follows the existing format:
slug header, condition description, `**Triggered:**` field citing the raise site.

The bijection invariant (`spec/errors.md slugs == errors.py ALL_SLUGS`) requires
both files to be updated in the same commit (S5, the Python policy + error
plumbing slice).

### 8.3 `spec/cli-contract.md §8` additions

Document alongside `MILPA_INDEX_URL`:

- `MILPA_INDEX_TRUST` — policy override (`warn`/`strict`/`off`); env `off` is a
  no-op floor (cannot weaken manifest warn/strict; see §6.6 authority model).
- `MILPA_INDEX_TRUST_SIGNER` — expected signer IDENTITY override (GitHub Actions
  OIDC workflow URL / SubjectAltName). Does NOT accept `file://` trust-bundle paths.
- `MILPA_INDEX_TRUST_BUNDLE` — `file://` path to an alternate Fulcio CA root +
  Rekor public key bundle for PRIVATE Sigstore instances. Orthogonal to
  `MILPA_INDEX_TRUST_SIGNER`.
- `MILPA_INDEX_MAX_AGE` — freshness window in seconds (default: 604800).
- `MILPA_INDEX_BUNDLE_URL` — explicit bundle URL, overriding the normatively
  derived `<index-url path>.bundle` (use when suffix-derivation is not viable).

Document alongside `--require-attested-metadata`:

- `--require-attested-index` — escalates index-trust `warn`→`strict`; cannot
  set or clear `off` (only the manifest can declare `off`).
- `--refresh-index` — forces fresh index + bundle fetch, bypassing cache TTL.

---

## 9. tianguis prerequisite

### 9.1 The bundle-delivery gap

The tianguis `vendor.yaml` and `reindex.yaml` CI workflows currently emit
Rekor-anchored cosign bundles:

- `vendor.yaml` produces `vendor-attest.bundle` as a CI workflow artifact.
- `reindex.yaml` produces `reindex-attest.bundle` as a CI workflow artifact.

These bundles are **not committed to the tianguis repo** alongside `index.kdl`.
A consumer fetching `index.kdl` from `raw.githubusercontent.com` has no way to
retrieve the corresponding bundle.

### 9.2 Required tianguis change

The tianguis-side change is a **dependency of this RFC's implementation** and
must be done before S5/S6 (when the live production trust path is wired). The
exact contract:

- The whole-index bundle MUST be committed to the tianguis repo as
  `index.kdl.bundle` alongside `index.kdl` in the same commit.
- The bundle MUST be fetchable at the normatively derived URL (§7.3): strip
  query and fragment from `MILPA_INDEX_URL`, append `.bundle` to the URL path,
  reattach query/fragment. For the default URL:
  `https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl.bundle`

The tianguis workflows (`vendor.yaml`, `reindex.yaml`) must be updated to commit
the bundle file rather than (or in addition to) uploading it as a CI artifact.

**File this as a tianguis cross-repo issue** before beginning S5/S6. S3/S4
(the verifier modules) can proceed using test trust roots and pre-generated test
bundles; they do not require the tianguis production bundle.

---

## 10. Cross-implementation conformance

### 10.1 Injected verifier seam (mock-based policy testing)

Deterministic offline-verifiable Sigstore bundles cannot be generated without
live Fulcio/Rekor infrastructure (`sigstore-python` has no test-CA API that
produces bundles verifiable by `sigstore-rs` byte-identically). Requiring both
impls to verify the same committed bundle byte-identically is not buildable.

Following milpa's existing no-real-network-in-shared-conformance discipline, the
shared conformance corpus tests the **policy state machine** only, not the
cryptographic implementation. The seam is an injected `IndexBundleVerifier`
protocol (Python) / trait (Rust):

```python
class IndexBundleVerifier(Protocol):
    def verify(
        self,
        index_bytes: bytes,
        bundle_bytes: bytes,
        trust_bundle: TrustBundle,   # trust ROOT seam (orthogonal to signer identity)
        expected_signer: str,        # signer IDENTITY seam (orthogonal to trust root)
        max_age_seconds: int,        # SKIP_FRESHNESS sentinel for pure cache reads
    ) -> VerificationResult: ...
```

`trust_bundle` and `expected_signer` are the two ORTHOGONAL seams: `trust_bundle`
is the Fulcio CA + Rekor key bundle (overridable via `MILPA_INDEX_TRUST_BUNDLE` /
`index-trust-bundle`); `expected_signer` is the SubjectAltName identity
(overridable via `MILPA_INDEX_TRUST_SIGNER` / `index-trust-signer`). Changing
one does not imply the other. `max_age_seconds` is passed as
`config.max_age_seconds` on a network-fetch path and as a "skip freshness"
sentinel on pure cache reads (so committed test bundles do not go stale 7 days
after commit). The `MockVerifier` ignores `max_age_seconds`; its result is
externally driven by `mock_verifier_result`.

In production code, `SigstoreVerifier` implements this using `sigstore-python` /
`sigstore-rs`. In conformance fixtures, a `MockVerifier` is injected; its result
is driven by the fixture's `env` field.

The shared conformance fixtures assert POLICY OUTCOMES given the mock verifier
result. The cross-impl proof is convergence on the policy state machine (warn /
strict / off dispatches correctly), which is milpa's actual responsibility.
Cryptographic correctness is each library's own test suite's job.

**Per-impl integration tests:** Each impl carries a per-impl-only integration
test (Python: `tests/test_index_trust_integration.py`; Rust:
`tests/index_trust_integration.rs`) that exercises `SigstoreVerifier` against a
committed real test bundle (signed with a test trust root, stored in
`conformance/spec-v1/_oracle/`). These tests are EXCLUDED from the shared corpus;
they mirror the "real git, local bare repo" pattern from `test_conformance.py`.
These integration tests are gated at **S5** (when the full policy stack is wired
and the test-bundle generation tooling can be validated end-to-end) — NOT at S3.
The committed `_oracle/` test bundle is verified with freshness DISABLED (the
`max_age_seconds` sentinel or an injected clock), so it does not go stale 7 days
after commit.

### 10.2 Conformance fixture shape

```
conformance/spec-v1/fixture-NNN-index-trust-<scenario>/
  index.kdl                   ← test index
  index.kdl.bundle            ← placeholder bytes (MockVerifier ignores content)
  env                         ← index_trust_policy + mock_verifier_result
  expected/
    outcome                   ← "trusted" | "warn:<slug>" | "error:<slug>"
```

The `env` field `mock_verifier_result` is one of:
`trusted | sig-invalid | digest-mismatch | signer-mismatch | bundle-missing | bundle-malformed | bundle-stale`

Both runners dispatch `cmd: index-trust` fixtures (analogous to
`cmd: git-protocol` added in H-infra).

### 10.3 Fixture scenarios (S7)

All eighteen pre-generated fixtures in `conformance/spec-v1/` (12 original + 6 new):

| Fixture scenario | mock_verifier_result | policy | Expected outcome |
|---|---|---|---|
| valid-trusted | trusted | warn | trusted |
| warn-on-tamper | digest-mismatch | warn | warn:TNG-INDEX-DIGEST-MISMATCH |
| strict-sig-invalid | sig-invalid | strict | error:TNG-INDEX-SIGNATURE-INVALID |
| strict-digest-mismatch | digest-mismatch | strict | error:TNG-INDEX-DIGEST-MISMATCH |
| strict-signer-mismatch | signer-mismatch | strict | error:TNG-INDEX-SIGNER-MISMATCH |
| strict-bundle-missing | bundle-missing | strict | error:TNG-INDEX-BUNDLE-MISSING |
| strict-bundle-malformed | bundle-malformed | strict | error:TNG-INDEX-BUNDLE-MALFORMED |
| strict-bundle-stale | bundle-stale | strict | error:TNG-INDEX-BUNDLE-STALE |
| cert-expired-wall-clock-ok | trusted | strict | trusted (cert valid at SET time; not a failure) |
| flag-escalates-warn | trusted | warn + flag | trusted (strict effective; no warning emitted) |
| upgrade-no-bundle-warn | bundle-missing | warn | warn:TNG-INDEX-BUNDLE-MISSING (with hint) |
| workspace-member-strict *(fixture-349, REPURPOSED — see 6.4a redesign)* | trusted | workspace ROOT declares strict, member declares nothing | strict effective (root authority); trusted result |
| off-sig-invalid | sig-invalid | off | trusted/proceed (verifier NOT consulted; no warning) |
| off-digest-mismatch | digest-mismatch | off | proceed silently |
| off-bundle-missing | bundle-missing | off | proceed silently |
| manifest-off-env-strict | trusted | manifest=off + env=strict | off (env cannot override manifest off) |
| manifest-warn-env-off | trusted | manifest=warn + env=off | warn (env=off cannot weaken manifest warn) |
| workspace-conflicting-signers *(fixture-355, REPURPOSED — see 6.4a redesign)* | trusted | workspace MEMBER illegally declares `index-trust "strict"` | error:WS-INDEX-TRUST-ON-MEMBER (before fetch) |
| workspace-root-off *(fixture-366, NEW — 6.4a redesign)* | sig-invalid | workspace ROOT declares off | trusted/proceed (gate disabled; proves root can reach off) |

Both runners produce byte-identical policy outcomes for all nineteen scenarios
(fixture-349 and fixture-355 were repurposed in place, fixture-366 is new —
see §6.4a for the root-authority redesign that motivated the change).

---

## 11. Slices

Slice order: each slice is independently testable and builds on the previous.

### S1 — SSOT policy unification (both impls)

**Behavior:** Pure refactor. Introduce `TrustPolicy = Literal["warn", "strict",
"off"]` in a new `trust.py` module (Python) / corresponding module in
`milpa-manifest` (Rust). Rename the existing `AttestationPolicy` user-facing
value `permissive`→`warn` and add `off`. Replace `effective_strict_policy(...)`
with `effective_trust_policy(manifest_value, flag, env_override) -> TrustPolicy`
shared by both axes. Both manifest fields parse to `TrustPolicy` via a shared
`_parse_trust_policy` helper.

No new behavior, no new error codes. Existing attestation-policy tests updated
`permissive`→`warn`.

**Files touched (Python):** `trust.py` (new), `attestation.py`, `manifest.py`,
`context.py`, call sites in `resolver.py` / `cli.py`.

**Files touched (Rust):** `milpa-manifest/src/trust.rs` (new),
`milpa-manifest/src/lib.rs` + `milpa-manifest/src/format.rs` (attestation-policy
parse sites), `milpa-core/src/resolver.rs` (public `effective_strict_policy` →
`effective_trust_policy` rename), `milpa-core/src/lib.rs` (public re-exports of
`TrustPolicy` and `effective_trust_policy` — BREAKING pub-API rename from
`AttestationPolicy`/`effective_strict_policy`), `milpa-core/src/discovery.rs`,
`milpa-cli/src/main.rs` (call sites), `milpa-conformance/src/runner.rs` (call
sites), plus `*_tests.rs` updating `AttestationPolicy::Permissive` →
`TrustPolicy::Warn`.

**Note:** No `conformance/spec-v1/` fixtures use the `permissive` value (only
`strict` appears, which maps cleanly to `TrustPolicy::Strict`), so S1's
"existing suites green" gate is achievable without fixture edits.

**Gate:** Both impls' existing test suites green with `permissive`→`warn` rename.
Independently testable with no cross-slice dependencies.

---

### S2 — Spec: whole-index gate

**Behavior:** Normative spec text for Layer 1. Does NOT touch
`spec/registry-protocol.md §3.2`; does NOT add error codes to `errors.py`.

**Scope:**
- `spec/registry-protocol.md` — new subsection "Whole-index attestation gate"
  (§8.1): normative verification requirements (cert-at-SET-time, DSSE subject-
  digest binding, freshness-at-network-fetch-only, bundle-index binding, single-read
  invariant, per-URL signer resolution, workspace conflicting-signers validation error).
- `spec/cli-contract.md §8` — `MILPA_INDEX_TRUST`, `MILPA_INDEX_TRUST_SIGNER`,
  `MILPA_INDEX_TRUST_BUNDLE`, `MILPA_INDEX_MAX_AGE`, `MILPA_INDEX_BUNDLE_URL`,
  `--require-attested-index`, `--refresh-index` documented.

No impl files touched.

**Gate:** Downstream slices validate their implementations against this spec.

---

### S3 — Whole-index verifier module (Python)

**Behavior:** New `impls/python/milpa/index_trust.py`. Exports:

```python
# Sealed result type — ALL SEVEN variants
class VerificationResult: ...   # variants: Trusted | SigInvalid | DigestMismatch
                                #           | SignerMismatch | BundleStale
                                #           | BundleMissing | BundleMalformed
# Note: BundleMissing is constructed by load_index when the bundle fetch 404s
# (the verifier is not called with absent bundle bytes); BundleMalformed and the
# cryptographic variants are returned by the verifier itself. All share one type
# so enforce_index_trust dispatch is total.

# Injected verifier protocol (production: SigstoreVerifier; test: MockVerifier)
class IndexBundleVerifier(Protocol):
    def verify(self, index_bytes, bundle_bytes, trust_bundle, expected_signer,
               max_age_seconds) -> VerificationResult: ...
    # trust_bundle and expected_signer are ORTHOGONAL seams (§3.2, §10.1)
    # max_age_seconds: pass SKIP_FRESHNESS sentinel on pure cache reads

class SigstoreVerifier:   # production; uses sigstore-python
    ...

# Pure verification (no policy decision)
def verify_index_bundle(
    index_bytes: bytes,
    bundle_bytes: bytes,
    trust_bundle: TrustBundle,
    expected_signer: str,
    max_age_seconds: int = 604800,
) -> VerificationResult: ...

# Policy enforcer (6-way result→slug dispatch — six non-Trusted failure variants)
def enforce_index_trust(
    result: VerificationResult,
    policy: TrustPolicy,
    index_url: str,            # the index URL that triggered this (not a generic context msg)
) -> None:
    # strict: raises MilpaError with slug
    # warn: emits one deduped stderr warning with slug (dedup key = index_url)
    # off/Trusted: silent
    ...

# Config bundle passed as one param to load_index (avoids param-explosion)
# NOTE: verifier is NOT a field here — it is an EXPLICIT param of load_index
@dataclass(frozen=True)
class IndexTrustConfig:
    policy: TrustPolicy
    trust_bundle: TrustBundle
    expected_signer: str
    max_age_seconds: int = 604800
```

`verify_index_bundle` is PURE (no policy decision). `enforce_index_trust`
holds all 6-way result→slug dispatch (six non-Trusted failure variants → six
`TNG-INDEX-*` slugs); neither function is smeared into `load_index`.
`IndexTrustConfig` is passed as ONE parameter to `load_index`; `verifier` is a
SEPARATE explicit parameter of `load_index(url, config, verifier, http_get,
bundle_http_get)`. This keeps `index_cache.py` from importing `context.py`, and
prevents tests from silently running against real Sigstore if they forget to
override the verifier. Production passes `SigstoreVerifier()`; tests pass
`MockVerifier(...)`.

Does NOT require the tianguis prerequisite (uses test bundles).

**Gate:** `uv run pytest tests/test_index_trust.py` — all seven `VerificationResult`
variants via `MockVerifier` (unit tests only). The real `SigstoreVerifier`
integration test (`tests/test_index_trust_integration.py`) against the committed
`_oracle/` test bundle is gated at **S5**, not here — by S5 the full policy stack
is wired and the test-bundle generation tooling can be validated end-to-end.

---

### S4 — Whole-index verifier module (Rust)

**Behavior:** New `impls/rust/crates/milpa-core/src/index_trust.rs`. Parity
with S3: `VerificationResult`, `IndexBundleVerifier` trait, `SigstoreVerifier`
struct, `IndexTrustConfig`, `verify_index_bundle`, `enforce_index_trust`.

**Spike gate (BEFORE coding):** Run a dedicated spike to confirm:
1. `sigstore-rs` supports offline bundle verification (no live Rekor call).
2. The cert-at-SET-time property (`cert.valid_at(integrated_time)` or
   equivalent) is available in the library API.
3. The API is stable enough to pin, or the maintenance risk is documented.

If the API is sufficient: complete `SigstoreVerifier` in S4.
If the API is insufficient: implement with `MockVerifier` keeping conformance
green, then address in **S4b** (see below). Document the spike finding in the
commit that opens S4.

**Gate:** `./dev-rust test -p milpa-core -- index_trust` + conformance fixtures
(mock verifier) passing on the Rust runner.

---

### S4b — Rust SigstoreVerifier retrofit (CONDITIONAL)

**When:** Only if the S4 spike finds the `sigstore-rs` API insufficient for
offline bundle verification or cert-at-SET-time. If the spike succeeds, S4b
remains empty (a named placeholder, not a committed slice).

**Behavior:** Retrofit a real `SigstoreVerifier` for the Rust impl once the API
question resolves — either via an alternate crate, a patched version, or a
`cosign verify-blob` subprocess fallback (process isolation; undesirable but
acceptable as a fallback). The `MockVerifier` keeps all conformance and policy
tests green in the interim.

**Gate:** Rust integration test against `_oracle/` test bundle green.

---

### S5 — Policy surface + load_index hook + cache (Python)

**[Merged: original S5 policy-wiring + original S7 cache-verify]**

**Behavior:** Wire `index-trust` and `index-trust-signer` manifest fields,
`--require-attested-index` / `--refresh-index` CLI flags, and env knobs
end-to-end. `load_index` in `index_cache.py` takes an `IndexTrustConfig`,
fetches/caches the bundle sidecar, and calls `verify_index_bundle` before every
parse. Six `TNG-INDEX-*` codes raised at runtime.

**Files touched:**
- `impls/python/milpa/manifest.py` — `index_trust_policy: TrustPolicy`,
  `index_trust_signer: str | None`, and `index_trust_bundle: str | None` on
  `Manifest` and `MemberManifest`; parse `index-trust`, `index-trust-signer`,
  and `index-trust-bundle` nodes.
- `impls/python/milpa/context.py` — `IndexTrustConfig` on `ResolveParams` or
  `MilpaEnv` (whichever carries the loaded-index context cleanly).
- `impls/python/milpa/workspace.py` — index-trust root-authority validation
  (§6.4a): a member manifest declaring `index-trust` / `index-trust-signer` /
  `index-trust-bundle` raises `WS-INDEX-TRUST-ON-MEMBER` before index load.
  *(Originally shipped as a workspace max-merge + per-URL conflicting-signers
  check; superseded by the §6.4a root-authority redesign — see that section.)*
- `impls/python/milpa/cli.py` — `--require-attested-index`, `--refresh-index`
  flags; `MILPA_INDEX_TRUST` / `MILPA_INDEX_TRUST_SIGNER` / `MILPA_INDEX_TRUST_BUNDLE` /
  `MILPA_INDEX_MAX_AGE` / `MILPA_INDEX_BUNDLE_URL` env reads.
- `impls/python/milpa/index_cache.py` — `load_index(url, config, verifier,
  http_get, bundle_http_get)` signature; separate `bundle_http_get` transport;
  normative bundle-URL derivation; atomic write (bundle before index rename);
  crypto verify on every read (freshness only on network fetch); crash-recovery
  (disk mismatch → single bounded re-fetch); `--refresh-index` TTL bypass;
  `TNG-INDEX-BUNDLE-MISSING` on bundle 404 (strict: no partial-cache; warn: write
  `.kdl.no-bundle` degraded marker); `milpa verify` gate; decode failure via
  index-parse error path.
- `impls/python/milpa/errors.py` — six new `TNG-INDEX-*` constants.
- `spec/errors.md` — six new `TNG-INDEX-*` entries (bijection: same commit as
  `errors.py`).
- `impls/rust/crates/milpa-conformance/tests/corpus.rs` — add all six
  `TNG-INDEX-*` codes to the `DEFERRED` bucket so the spec/Rust bijection test
  (`rust_error_catalog_is_a_bijection_with_the_spec`) passes during the S5→S6
  window when Python has the codes but Rust does not yet.
- `impls/python/pyproject.toml` — `sigstore` dependency with rationale comment.
- `tests/test_index_trust_integration.py` — per-impl integration test exercising
  `SigstoreVerifier` against the committed `_oracle/` test bundle with freshness
  DISABLED (the `max_age_seconds` sentinel). Gated HERE (S5), not at S3.

**Implementation order:** RED-GREEN the data-model plumbing layer (manifest /
context / cli / errors) FIRST. THEN the `index_cache.py` rewrite layer
(crash-recovery, atomic write, verify-on-every-read, bundle-404, `--refresh-index`,
`bundle_http_get`), since the latter's atomicity properties are subtle and a red
test there should not block the former.

**Gate:** `uv run pytest` (all existing tests + new policy-seam + new cache-
bundle tests + integration test). Requires S1 and S3. Does NOT require tianguis
prerequisite (uses `MockVerifier` and test bundles from conformance corpus).

---

### S6 — Policy surface + load_index hook + cache (Rust)

**[Mirror of S5]**

**Behavior:** Mirror S5 in the Rust impl. `IndexTrustConfig` struct, `load_index`
seam rewrite, six `TNG-INDEX-*` error slugs, workspace max-merge, `--refresh-index`.

**Files touched:**
- `impls/rust/crates/milpa-manifest/src/lib.rs` — `TrustPolicy` (from S1),
  `index_trust_policy`, `index_trust_signer`, `index_trust_bundle` on manifest structs.
- `impls/rust/crates/milpa-core/src/index_cache.rs` — `load_index(url, config,
  verifier, http_get, bundle_http_get)` seam rewrite (parity with S5 Python);
  separate `bundle_http_get`; normative bundle-URL derivation; atomic write;
  crypto verify every read (freshness on network only); crash-recovery; all four
  cache states; bundle-404 handling (strict/warn).
- `impls/rust/crates/milpa-core/src/errors.rs` — six new `TNG-INDEX-*` slugs.
- `impls/rust/crates/milpa-conformance/tests/corpus.rs` — MOVE the six
  `TNG-INDEX-*` codes from the `DEFERRED` bucket (added by S5) to
  `implemented_error_codes()`, restoring full bijection.
- `Cargo.toml` — `sigstore` crate dependency with rationale comment.

**Gate:** `./dev-rust test --workspace`. Requires S4.

---

### S7 — Conformance fixtures (whole-index, policy state machine)

**Behavior:** Eighteen pre-generated fixtures committed to `conformance/spec-v1/`
(§10.3 — 12 original + 6 new covering `off` policy, authority model, and
workspace-conflicting-signers). The fixture corpus uses `mock_verifier_result` in
the `env` field; no live Sigstore infrastructure required. Both Python and Rust
conformance runners extended to dispatch `cmd: index-trust` fixtures.

The test trust root public material is committed to
`conformance/spec-v1/_oracle/test_trust_bundle.json` (used by per-impl
integration tests in S5 and S6).

**Gate:** Both runners pass all eighteen fixture scenarios byte-identically on
policy outcomes. This is the cross-impl convergence proof for the policy state
machine.

---

## 12. Open questions / architecture-review seeds

### 12.1 Rust sigstore-rs offline API viability

The `sigstore-rs` crate has changed its public API significantly between
versions. Before beginning S4, the spike MUST confirm:

1. Does the crate support offline bundle verification (no Rekor network call) in
   its current release?
2. Is the cert-at-SET-time property (`cert.valid_at(integrated_time)` or
   equivalent) available? This is a correctness requirement (§4 step 4 / spec
   §3.4.4 step 4), not an optimization.
3. Is the API stable enough to pin, or does it track a pre-1.0 semver?
4. Is offline bundle verification exercised by the crate's own test suite, or
   only by integration tests requiring a live Sigstore instance?

If the API is insufficient: activate **S4b** (§11 S4b) — the conditional retrofit
slot. Options: (a) alternative crate; (b) patched version; (c) shell out to
`cosign verify-blob` (process isolation, adds an external binary dep — acceptable
fallback). Resolve during the S4 spike; document the finding before any Rust impl
code is written. If the spike succeeds, S4b remains empty. This is the highest-
risk unknown in the plan.

### 12.2 Test trust root strategy

The per-impl integration tests (Python: S5, Rust: S6) exercise `SigstoreVerifier`
against a committed test bundle in `conformance/spec-v1/_oracle/`. These tests are
gated at S5/S6 — NOT at S3 — because the test-bundle generation tooling is
validated end-to-end only when the full policy stack is wired. The generation
script must use a local Fulcio/Rekor mock or `sigstore-python` test utilities and
be re-runnable when the Sigstore bundle format version changes.

The committed `_oracle/` test bundle MUST be verified with freshness DISABLED (a
sentinel `max_age_seconds` meaning "skip freshness check", or an injected clock),
so the test does not go stale 7 days after commit. This is a normative requirement
for all per-impl integration tests against committed bundles.

The shared conformance corpus (S7) uses `MockVerifier` and does not depend on
these bundles being cryptographically verifiable by both impls. This resolves
the original determinism challenge: no cross-impl bundle byte-identity requirement
exists; only per-impl integration tests touch the real verifier.

### 12.3 TUF-based root rotation (follow-on) and emergency bypass

The embedded trust bundle is static across milpa binary versions. If the
Sigstore public instance rotates its Fulcio CA or Rekor key, all pinned binaries
will fail verification until updated. TUF is the long-term fix; the
embedded-bundle approach is acceptable for v1.

**Emergency bypass during unplanned rotation:** `index-trust "off"` in `milpa.kdl`
is the documented emergency bypass during an unplanned Sigstore public-good CA or
key rotation where the embedded bundle becomes stale before a milpa release ships
with the updated bundle.

**Note:** `TNG-INDEX-SIGNATURE-INVALID` does NOT distinguish a legitimate CA
rotation from active tamper — both produce a cert-chain validation failure against
the embedded trust root. The remedy is identical in both cases: upgrade milpa to a
build with the rotated embedded bundle.

**Tianguis maintainer commitment:** On a best-effort basis, after any Sigstore
public instance CA or key rotation, the tianguis maintainer will (a) post a GitHub
advisory on the milpa repo noting the rotation, (b) ship a milpa release with the
updated embedded trust bundle, and (c) document the `index-trust "off"` interim
bypass in the advisory.

---

## Part 2 — Per-entry author-attribution (DEFERRED follow-on)

**Status:** DEFERRED. Layer 1 (whole-index gate) fully closes #103: every byte of
the index is cryptographically verified before any claim is trusted. Layer 2
adds per-entry AUTHOR ATTRIBUTION only — answering "who signed this specific
version?" rather than "was the index tampered?". Deferral rationale:

- Requires per-entry tianguis bundle delivery: a significant tianguis repo
  change with open design questions (§ Per-entry bundle delivery below).
- Introduces the `sigstore-rs` offline API risk at version-selection frequency
  (exercised once per selected dep, not once per resolve).
- Attribution is not integrity: Layer 1 already proves the index was authored by
  the tianguis vendor-bot workflow; per-entry attribution adds author identity
  for human-signed versions, which is valuable but not a safety gate.

The full Part-2 design (field surface, per-entry gate, the 3 `TNG-ENTRY-*`
codes, chained-trust rationale, and the open per-entry-bundle-delivery question)
now lives in its own stub — **`docs/rfc-per-entry-attestation.md`** — so this RFC
stays the single source of truth for Layer 1 and Part 2 has one home. A tracking
GitHub issue (adjacent to #91) should be filed against that stub.

---

## Appendix: Current state summary

| Component | Python seam | Rust seam | Current state |
|---|---|---|---|
| Whole-index gate (Layer 1) | `index_cache.py:207/251` | `index_cache.rs:80/107` | Absent (trust-on-transport) |
| Per-entry gate (Layer 2) | `registry.py:264–360` | `registry.rs:290–` | Deferred to Part 2 |
| `IndexVersion` attestation fields | `registry.py:181–206` | `registry.rs:141–154` | Deferred to Part 2 |
| `TrustPolicy` / `effective_trust_policy` | `attestation.py:52–75` (old form) | `milpa-manifest` (old form) | S1 unifies |
| Policy config (`index-trust`) | `manifest.py`, `cli.py`, `context.py` | milpa-manifest, milpa-core | S5 / S6 |
| Cache bundle sidecar | `index_cache.py:112–121` | `index_cache.rs:49–53` | S5 / S6 (merged with policy wire) |
| Error codes (6 TNG-INDEX-*) | `errors.py` | `errors.rs` | S5 / S6 (with raise sites) |
| Conformance fixtures | `conformance/spec-v1/` | same corpus | S7 |
