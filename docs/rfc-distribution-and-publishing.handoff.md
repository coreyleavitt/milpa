# milpa publish revival (rfc-distribution-and-publishing Phase 3) — handoff

- **Stage:** 1 (RFC/design DONE + approved by Corey 2026-07-12) → next 3 (TDD).
- **Resume:** `/loop implement the next unimplemented RFC slice with /tdd, following the
  standing rules; after each slice report one progress line; stop when every slice is implemented`
  (milpa impl; gate each slice on `cd impls/python && uv run pytest`).
- **Why now:** closes the ONE remaining item of tianguis#42 — real author-signed E2E needs a
  real author package published via the Model-3 composite action. **nim-z3** (`~/projects/nimlibs/nim-z3`,
  a real coreyleavitt Nim lib, milpa-managed, name `z3` v2.0.0) is that package. Publishing it
  exercises the full author→dispatch→commit-entry path that has never run E2E.

## The design (approved — best-in-class, first-principles; NOT a restore of the deleted monolith)

`milpa publish` was deleted in the clean-room swap (`5ae87ad`) because it's external-service-coupled
→ not conformance-fixture-testable (spec/cli-contract.md §10 marks it impl-specific + out-of-v1.0-
conformance, "reserved for a later amendment"). A blueprint survives at `git show 5ae87ad^:impls/python/milpa/publish.py`
(+ `tests/test_publish.py`). Do NOT restore it verbatim — the Model-3 composite action (new, from S8)
changes where the seams belong.

### Two structural decisions

**1. SSOT tree enumeration (the correctness crown jewel).** The old `pack_source` had its own
`.git`-excluding walk, SEPARATE from `identity.py::compute_content_hash`. Under Model-3 that is a
latent gate-breaker: the subject-binding chain is
`content_hash_A = milpa hash(local tree)` (composite action signs it into the §1 statement) →
`milpa publish packs local tree → OCI` → tianguis `content_hash_B = milpa hash(fetched tree)` must
`== statement subject`. If pack and hash enumerate the tree differently, `A ≠ B` → EVERY author
publish rejected (`TNG-ENTRY-DIGEST-MISMATCH`). **Fix:** lift ONE `enumerate_package_tree(root)` into
`identity.py` as the single source of truth; `compute_content_hash`, the packer, and `milpa hash`
all consume it → "the artifact you push IS the thing whose hash is your identity" holds by
construction. (This is also why pack MUST live in milpa — it shares milpa's identity enumeration,
uninlinable in a bash action.)

**2. Shed the tianguis coupling.** The old monolith did pack→push→cosign→**dispatch**. Dispatch
payload+endpoint are 100% tianguis-specific, and the composite action already owns tianguis-specific
knowledge (it builds tianguis's in-toto statement). So split along that seam:
- **`milpa publish` = generic, registry-agnostic:** `pack → push OCI → cosign (provenance) → emit
  oci_ref+digest`. Knows NOTHING about tianguis. NO `--dispatch-url`/`--provider`.
- **tianguis composite action = submission:** `milpa hash → sign §1 attestation (author SAN) →
  milpa publish (artifact) → POST dispatch {oci_ref, entry_bundle_b64, …}`. All tianguis knowledge
  (attestation format + dispatch) in the tianguis-owned tool, in the author's OIDC job.

### Internal shape (milpa disciplines)
- **Pure plan / impure execute:** `build_publish_plan(...) -> PublishPlan` (value: artifact spec from
  the enumeration, oci_ref, cosign target) is pure + exhaustively unit-testable; `execute(plan, oci,
  signer)` runs it via injected seams. `--dry-run` = build plan + print, skip execute (not a special path).
- **Push as the symmetric sibling of pull:** OCI push lands in `fetchers/oci.py` next to
  `make_oras_pull`, sharing the oras machinery (first concrete step of rfc-pluggable-fetchers transport).
- **Injected seams, fakes not mocks:** the two external boundaries (oras push, cosign) are injected
  `Runner`s, tested like the old `test_publish.py` (no network). publish stays OUTSIDE the conformance
  corpus (per §10) — fake-tested, not fixture-tested.

### Spec
Refine `spec/cli-contract.md §10` to the GENERIC signature (drop `--dispatch-url`/`--provider`), keep
it explicitly impl-specific + out-of-v1.0-conformance. Not reversing §10 — it's the layering §10
should have now the composite action exists (feedback_spec_vs_impl; done in place, pre-1.0).

## Slice plan (vertical, TDD; gate each on `cd impls/python && uv run pytest`)
- [ ] **S1 — SSOT `enumerate_package_tree` in identity.py.** Extract the canonical tree walk
      (paths + canonical bytes + `.git`/exclusion rules) as one function; refactor
      `compute_content_hash` to consume it. **INVARIANT: content_hash output byte-identical before/after
      — the whole conformance corpus + identity property tests MUST stay green (no fixture churn).**
      This is the delicate one — pure refactor, zero behavior change.
- [ ] **S2 — deterministic packer** consuming S1's enumeration → reproducible tar.gz (zeroed
      mtime/uid/gid, sorted). Round-trip test: pack → extract → `compute_content_hash` == original.
- [ ] **S3 — `PublishPlan` + `build_publish_plan` (PURE).** Value object; unit-test plan contents
      (artifact entries, oci_ref, cosign target) with zero I/O. `--dry-run` renders this.
- [ ] **S4 — OCI push in fetchers/oci.py** (`make_oras_push` sibling of pull) + `cosign_sign`, both
      injected `Runner`s. `execute(plan, ...)` orchestrates. Fake-Runner tests (assert oras/cosign
      argv), no network.
- [ ] **S5 — `publish` subparser in cli.py** + wire plan→execute + `--dry-run`. Generic flags only
      (`--name --version --registry --repo-url --signed-by [--dry-run]`; NO dispatch). Fake-injected
      CLI test.
- [ ] **S6 — spec §10 refine** to the generic signature + doc. (No conformance-corpus entry.)

## Cross-repo (after milpa publish lands)
- [ ] **T1 (tianguis):** extend `.github/actions/publish/action.yaml` to orchestrate:
      milpa hash → attest-statement + sign_statement.py (bundle) → `milpa publish` (artifact→oci_ref)
      → POST dispatch {oci_ref, entry_bundle_b64, name, version, signed_by, …}. Retire the
      `milpa publish`-does-dispatch assumption in `publish.yaml`/`docs/adoption/github.md`.
- [ ] **N1 (nim-z3):** add `release.yaml` (tag-triggered, `id-token: write`) invoking the composite
      action; target `ghcr.io/coreyleavitt/z3`. Artifact-scope decision: first run publishes the clean
      git tree as-is (defer `_audit_headers/` exclusion).
- [ ] **E2E:** fire (dry-run first, then real `v2.0.0`) → dispatch → commit-entry verify+admit →
      L3 ratchet TOFU-pins coreyleavitt as `authorizedSigner` for `github.com/coreyleavitt` `z3`
      (distinct from existing vendored zevv/zielmicha `z3`) → confirm milpa verifies. Closes tianguis#42.

## Key facts (verified 2026-07-12)
- `milpa publish` absent from cli.py (subparsers: fetch/lock/show/verify/clean/add/remove/update/
  workspace/hash/store/index). `milpa hash` EXISTS (composite action already calls it).
- Old publish.py at `5ae87ad^`: pack_source/push_oci/cosign_sign/post_dispatch/fetch_sigstore_oidc_token/
  publish. Injectable Runner + urllib http_post. Payload lacked `entry_bundle_b64` (added post-deletion).
- Spec: cli-contract.md §10 (frozen signature, impl-specific, out-of-conformance); RFC
  rfc-distribution-and-publishing.md Phase 3 (design); issue #95 (closed, orphaned), #96 (open, auto-discover).
- tianguis index: `z3` name already used by `github.com/zevv` + `github.com/zielmicha` (vendored,
  backfilled). coreyleavitt `z3` = NEW tuple → clean first-use ratchet. No collision.
- nim-z3: zero publish automation today (only test ci.yaml); clean 239-file/2.7MB tracked tree;
  content_hash on clean checkout auto-excludes nimcache_*/_deps/scratchpad. Big uncommitted
  fixedpoint-callbacks diff is ORTHOGONAL (feature/test surface, no publish files).

## Open sub-decisions (non-blocking; recommend + proceed unless flagged)
- Artifact scope (`_audit_headers/` ~40% of nim-z3 bytes): first E2E = whole clean tree; optimize later.
- Dry-run first vs straight to real v2.0.0 publish: recommend dry-run first (composite-action dry_run path).
