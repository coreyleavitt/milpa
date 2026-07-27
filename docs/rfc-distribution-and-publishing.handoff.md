# milpa publish revival (rfc-distribution-and-publishing Phase 3) — handoff

- **Stage:** 3 (TDD grind) ✅ **COMPLETE** — round 1+2 architect DONE; Corey ran the `/loop` grind (no veto
  on the 3 notable calls → they stand: drop S0a, version↔tag fail-closed, workspace-publish → #190).
  **ALL 11 SLICES LANDED + GREEN (2026-07-17):** S0b, S2, S3a, S1a, S1b, S1c, S3b, S3c, S3d, S4, S5.
  Final full suite: **3025 passed, 31 skipped, exit 0** (independently re-verified by the control loop).
  **NOTHING COMMITTED — awaiting Corey.** Working tree carries all publish-revival changes uncommitted.
- **Stage 4 (code review) ✅ COMPLETE — floor reached 2026-07-18.** 3 fix rounds (see code-review ledger):
  R1 found 2 High + 10 Med + 5 Low → all High+Med fixed (M1 was a fork → Corey chose "verify via manifest
  fetch"); R2 re-review found 2 Med + Lows → both Med fixed; R3 fixed them + folded Lows; control-loop
  re-verify = floor (0 C/H/M). 2 Lows left per mandate (L3 mem-buffer, R2-L4 utf8-decode). Suite **3083
  passed, exit 0** (+58 tests). Security re-review clean (path-containment + digest-verify hand-traced).
- **Resume / next stage:** cross-repo **T1** (tianguis composite action → `milpa publish --output`; delete
  empty `milpa hash local=`; rewrite `publish.yaml`/adoption off the deleted monolith; dispatch needs
  name/version/oci_ref/provider/repo_url/signed_by) → **N1** (nim-z3 `release.yaml` → GHCR
  `ghcr.io/coreyleavitt/z3`, package PUBLIC on first publish) → **E2E** (dry-run→real v2.0.0→dispatch→
  ratchet TOFU-pins coreyleavitt) → **closes tianguis#42**. **NOTHING COMMITTED — awaiting Corey.**
- **Files touched this grind (all uncommitted):** `milpa/publishing.py` (NEW), `milpa/cli.py`,
  `milpa/source_spec.py`, `milpa/errors.py`, `milpa/fetchers/safe_extract.py` (S0b),
  `tests/test_publishing.py` (NEW), `tests/test_publish_subcommand.py` (NEW),
  `tests/test_identity.py` (S0b parity test), `spec/cli-contract.md`, `spec/errors.md`.
- **Why now:** closes the ONE remaining item of tianguis#42 — real author-signed E2E needs a
  real author package published via the Model-3 composite action. **nim-z3** (`~/projects/nimlibs/nim-z3`,
  a real coreyleavitt Nim lib, milpa-managed, name `z3` v2.0.0, **standalone — no submodules, no
  workspace**) is that package. Publishing it exercises the full author→dispatch→commit-entry path
  that has never run E2E.

## The design (approved — best-in-class, first-principles; NOT a restore of the deleted monolith)

`milpa publish` was deleted in the clean-room swap (`5ae87ad`) because it's external-service-coupled
→ not conformance-fixture-testable (spec/cli-contract.md §10 marks it impl-specific + out-of-v1.0-
conformance, "reserved for a later amendment"). A blueprint survives at `git show 5ae87ad^:impls/python/milpa/publish.py`
(+ `tests/test_publish.py`). Do NOT restore it verbatim — the Model-3 composite action (new, from S8)
changes where the seams belong, AND the blueprint predates several disciplines now mandatory
(coded error slugs, the epoch-2 DAG identity, typed fetcher closures).

### Three structural decisions

**1. Publish source = the git tree at HEAD, read via `enumerate_git_entries` (the object-store seam).**
(Resolves architect-R1 fork F1; **supersedes R1's `git archive HEAD` choice — see R2/D-git below.**)
`compute_content_hash`/`enumerate_local_entries` walk the *working directory* and exclude only `.git`
(`spec/identity.md §1.4`). Run against a real dev checkout that pollutes into a signed public artifact,
nim-z3's working dir is 1272 entries (`_deps/` machine-local CAS symlinks, `nimcache_*/`, `scratchpad/`,
`.claude/` — all untracked). The publish source must be the **committed tracked tree**, not the working
dir. milpa **already has the right seam for that**: `fetchers/git.py::enumerate_git_entries(repo, commit,
*, submodule_fetch) -> (list[MaterializedEntry], dict[str,str])` (git.py:153) reads a commit's tree
straight from the object store (`git ls-tree -r -z` + `git cat-file --batch`) — **raw blob bytes, no
working tree, no index, no `.gitattributes` processing.** So publish resolves its source as
`enumerate_git_entries(repo=<project>, commit="HEAD", submodule_fetch=None)`, run **against the author's
real repo** (git reads `.git`'s object DB regardless of working-tree/untracked cruft). Consequences:
- (a) **A==B holds by construction.** `content_hash_A` (publish, over these entries) is computed from
  the *exact same enumeration function* a downstream `git=` consumer uses for the same commit — no
  divergence is possible (this is why we do NOT use `git archive`, see D-git).
- (b) `_deps/`/`nimcache_*`/`.claude/` and every untracked/working-tree artifact are excluded for free
  (they're not in the tree object); reproducible hash, no home-path/username leak.
- (c) `identity.py` AND `enumerate_local_entries` are both UNTOUCHED — publish reuses the *git* seam,
  the correct SSOT for "the tree at a commit," so the whole conformance corpus stays byte-identical.
- (d) **No temp dir, no `git archive` subprocess, no re-extraction, no third walk.** The plan/hash/pack
  payload all derive from ONE `enumerate_git_entries` call.
- (e) Symlink-escape containment + non-UTF8-relpath refusal come for free (git.py's existing R1-15
  guards) — valuable precisely because this tree becomes a permanent signed public artifact.

Publish REQUIRES a git repo whose HEAD resolves; refuses otherwise (`PUBLISH-NOT-GIT-REPO`).
`_audit_headers/` IS tracked → published as-is (nim-z3 repo hygiene, not a milpa special-case; see
Open sub-decisions).

**D-git — why NOT `git archive HEAD` (R1's choice, reversed in R2).** R2 depth+design converged: `git
archive` is a *different* git code path than object-store reads. It applies `.gitattributes`
`export-ignore` (silently drops tracked paths), `export-subst` (rewrites `$Format:$` bytes), and
`text`/`eol`/`filter=` clean/smudge — so `content_hash_A` from an archive can **silently diverge** from
what a `git=` clone of the *same commit* hashes (`enumerate_git_entries`, which does none of that),
breaking the identity invariant (`identity.py:196`). `git archive` also has no submodule support
(gitlinks vanish → incomplete artifact). Both holes evaporate by reading the object store directly.
(nim-z3 `.gitattributes`/submodule state is moot under this design, but confirm absence before E2E anyway.)

**Submodules (gitlinks, mode 160000):** `enumerate_git_entries(..., submodule_fetch=None)` records
NOTHING for gitlinks (no recursion) → would ship *incomplete* source. Since a `git=` consumer WOULD
recurse them, publishing a submodule package via OCI would be a silent completeness gap. **Refuse**:
if `git ls-tree` surfaces any mode-160000 entry, raise `PUBLISH-SUBMODULE-UNSUPPORTED` (S3a). nim-z3 has
none; full recursion is a deferred follow-up (needs the fetch seam), not v1 of publish.

**2. The SSOT is already `enumerate_git_entries` — reuse it, don't re-invent (and don't pack a parallel
walk).** The old `pack_source` had its own `path.rglob("*")` walk SEPARATE from identity — the latent
gate-breaker. The packer instead builds tar members directly from the `(relpath, mode_byte, content)`
triples that `enumerate_git_entries` returns. Subject-binding chain: `content_hash_A =
compute_dag_identity(entries)` (emitted in publish's receipt, signed by the composite action into the
§1 statement) → publish packs the SAME `entries` → OCI → tianguis `content_hash_B =
compute_content_hash(fetched+extracted tree)` must `== A`. Because pack and hash consume one
enumeration of one tree, "the artifact you push IS the thing whose hash is your identity" holds by
construction — no parallel invariant test needed.

**3. Shed the tianguis coupling.** The old monolith did pack→push→cosign→**dispatch**. Dispatch
payload+endpoint are 100% tianguis-specific, and the composite action already owns tianguis-specific
knowledge (it builds tianguis's in-toto statement). Split along that seam:
- **`milpa publish` = generic, registry-agnostic:** `resolve git tree (enumerate_git_entries) → hash →
  pack → push OCI → cosign (provenance) → emit a PublishReceipt {content_hash, oci_ref, digest,
  artifact_type}`. Knows NOTHING about tianguis. NO `--dispatch-url`/`--provider`.
- **tianguis composite action = submission:** `milpa publish → read receipt → sign receipt.content_hash
  into §1 attestation (author SAN) → POST dispatch`. All tianguis knowledge (attestation format +
  dispatch, incl. the `provider`/`repo_url`/`signed_by` fields the dispatch handler requires) lives in
  the tianguis-owned tool, in the author's OIDC job. See **Cross-repo T1** for exactly which fields the
  action supplies from GH context vs. from the receipt.

### Internal shape (milpa disciplines)
- **Pure plan / impure execute, with a structured receipt.**
  `build_publish_plan(source: PublishSource, target: PublishTarget) -> PublishPlan` is pure: it resolves
  `entries` via `enumerate_git_entries` ONCE to compute `content_hash = compute_dag_identity(entries)`,
  then carries the **source handle + content_hash + target metadata — NOT the entries and NOT the
  digest.** (R2/design: a "plan" holding raw bytes for hundreds of files is a `--dry-run --output` JSON-
  serialization footgun; keep bytes out by construction. Re-deriving entries in `execute` is cheap now
  that materialization is `ls-tree`/`cat-file`, not an `os.walk`.) The DIGEST is a product of the push,
  never in the plan. `execute(plan, push, sign) -> PublishReceipt {content_hash, oci_ref, digest,
  artifact_type}` re-derives entries, packs, and runs the injected seams. `--dry-run` = build plan +
  render it (incl. enumeration stats: entry count / top dirs / total bytes — a cheap guardrail, and it
  touches NO network by construction since the digest is never computed) and STOP; it never special-
  cases a branch inside `execute` (the old monolith's mistake).
- **Small typed param objects, not loose args.** `PublishTarget` groups `registry`/`repository`/`tag`/
  `artifact_type`/`layer_media_type` (mirrors the `ResolveParams`/`MilpaEnv` cut in `context.py`).
  `PublishSource` carries the repo path + resolved commit. Keeps `build_publish_plan` a 2-arg signature.
- **Push/cosign live in their OWN module, not `fetchers/oci.py`.** `fetchers/oci.py` is the consumer-side
  `Fetcher` contract (claim/materialize/receipt) raising only `FETCH-OCI-*`; a push failure is not a
  fetch outcome. New module `milpa/publishing.py` owns the author-side transport + plan/receipt types +
  the `enumerate_git_entries`-backed source resolution, with its own `PUBLISH-*` error domain. This is
  ONE deep module (mirrors how `fetchers/oci.py` bundles descriptor + receipt + fetcher + closure-
  factory), not a grab-bag — do NOT split the types out.
- **Typed semantic closures, fakes not mocks.** `OrasPush = Callable[[Path, str, str, str], str]`
  ((artifact, registry_ref, artifact_type, layer_media_type) → digest), the producer dual of
  `make_oras_pull`. Get the digest from `oras push --format json` (or a follow-up `oras resolve`),
  never by parsing human log lines. Factor `parse_oras_digest_json(stdout) -> str` as a standalone pure
  function (pull side can reuse it later). Same discipline for `cosign_sign`. Both injected; `execute`
  is tested against injected fakes. **Accepted test gap (R2/feasibility):** the *production*
  `make_oras_push`/`cosign_sign` argv cannot be unit-proven under milpa's no-mock house style (same as
  `make_oras_pull`, which has no argv test today) — real coverage of the real binaries is the N1/T1
  E2E, not a unit test. State this; don't imply "argv-assertion tests" cover the production closures.
  Every user-supplied token reaching `oras`/`cosign` argv runs through `validate_oci_field` first.
- **`PublishReceipt.oci_ref` is DERIVED, not stored twice.** Build it via `OciProvenance(registry,
  repository, digest).reference` (oci.py:134 — `registry/repository@digest`), NOT a hand-rolled f-string
  (duplication discipline). `oci_ref` + `digest` co-present is a deliberate ergonomic denormalization
  for the action's dispatch payload. Align the digest field name with the pull side (`OciReceipt.layer_digest`).
- **publish stays OUTSIDE the conformance corpus** (per §10) — fake-tested, not fixture-tested.

### CLI surface (S4)
`milpa publish --version <semver> --target <registry>/<repository> [--name <n>] [--tag <t>]
[--output <path>] [--dry-run] [--allow-untagged]`.
- **`--target <registry>/<repository>` is ONE combined token** (e.g. `ghcr.io/coreyleavitt/z3`), split
  on the first `/` — mirroring milpa's already-shipped `oci=<registry>/<repository>@<digest>` consumer
  grammar (`source_spec.py:141-150`). R2/design: two separate `--registry`/`--repository` flags would be
  an ergonomic regression against milpa's own surface. Extract the split into a shared helper
  (`split_oci_target`) reused by (a) `source_spec.py`'s `oci=` parse, (b) this CLI, (c) receipt
  `oci_ref` composition.
- `--name` **auto-derives from the manifest** (`Manifest.name`); explicit override accepted. (No
  manifest field exists to auto-derive `--target`/`--version` from — verified; staying explicit is not
  an oversight.)
- `--version` stays explicit + required — milpa's data model has NO self-version field.
- `--allow-untagged` is the escape hatch for the version↔HEAD binding guard (see S3a).
- **Dropped from the old §10 signature:** `--repo-url`, `--signed-by` (identity-theater — cosign keyless
  derives the REAL signer from ambient OIDC; and tianguis re-derives trust from the VERIFIED bundle SAN,
  never a flag), `--dispatch-url`, `--provider`, `--oidc-token-env`. (Note: the tianguis *dispatch
  handler* still requires `provider`/`repo_url`/`signed_by` as present fields — the composite action
  supplies them from GH context, NOT milpa; see Cross-repo T1.)
- `--output <path>` writes the `PublishReceipt` as JSON (precedent: `--certificate <path>` on
  `fetch`/`lock`, cli-contract §2.5) — the machine-readable milpa→composite-action handoff, not stdout
  scraping. `--dry-run`'s plan render also honors `--output`.
- **Registry auth is the CALLER's responsibility** (ambient `oras`/`docker` config): publish is
  registry-agnostic and runs no login flow; T1/N1 own the login step. Stated so nobody scope-creeps a
  registry-auth abstraction.
- **Republish/overwrite is NOT guarded by milpa** — tianguis's append-only ledger + L3 signer ratchet
  reject an altered/duplicate version tuple downstream (verify this holds in tianguis merge before
  E2E). The version↔tag binding (S3a) is milpa's honest-case guard; the ledger is the adversarial one.
- **Partial-push (push OK, cosign fails):** artifact sits live+unsigned, no receipt emitted; retry is
  safe (deterministic pack → same digest) and tianguis's cosign-verify gate rejects an unsigned
  artifact anyway. Non-issue by construction — stated, not engineered.

### Spec (S5 — land the flag-list edit WITH S4, prose can trail)
Refine `spec/cli-contract.md §10` to the GENERIC signature above (drop `--dispatch-url`/`--provider`/
`--repo-url`/`--signed-by`/`--oidc-token-env`; combined `--target`; add `--allow-untagged`), keep it
impl-specific + out-of-v1.0-conformance. Media type is `application/vnd.milpa.source.v1(.tar+gzip)`
(milpa-owned). **Add a normative PublishReceipt schema note** (R2/breadth-M1: the receipt is a cross-
*repo* contract — undocumented dict shape is a silent-break risk; spec it like `--certificate`'s
§2.5.1 field list). Note the Rust reference impl stays intentionally in the not-implemented branch
(§10's NORMATIVE "MUST exit non-zero + diagnostic" still applies — asymmetric-but-conformant).
**Fix the false NOTE at cli-contract.md:493** (R2/feasibility): it currently asserts `cmd_publish`'s
dry-run print exists (it doesn't, post-`5ae87ad`). S4 must make the real `cmd_publish` satisfy it —
the SOLE unguarded `print()` is the dry-run confirmation line; everything else routes to stderr.
Do NOT add any `publish` entry to `harness/coverage.py::CLAUSE_INVENTORY` (would demand a fixture that
by-design never exists).

## Slice plan (vertical, TDD; gate each on `cd impls/python && uv run pytest`)

**Dependency graph:** `{S0b, S2, S3a}` → `S1a` → `S1b`(needs S0b) → `S1c` → `{S3b, S3c}` → `S3d`
(needs S1 + S2 + S3b/S3c) → `S4` → `S5`. Front-load the fake-free pure/git-only slices (S2, S3a)
before the network-touching ones.

**Precursor bug-fix (proven live, root-cause; blocks the E2E):**
- [x] **S0b — `extract_tar` preserves the executable bit (regular AND hardlink writes).** DONE 2026-07-17:
      shared `_regular_file_mode(member)` helper chmods both pass-1 (regular) and pass-2 (hardlink) write
      branches; parity test `test_tar_extracted_ondisk_equals_object_store_invariant` (test_identity.py:588)
      pins the tarball/OCI on-disk↔object-store invariant. Full suite green (exit 0).
      `fetchers/safe_extract.py::extract_tar` (shared by `OciFetcher` AND `TarballFetcher`) never
      `chmod`s extracted files → drops the exec bit → `content_hash_B` (fetched, MODE_REGULAR) ≠
      `content_hash_A` (git tree, MODE_EXECUTABLE) → deterministic `TNG-ENTRY-DIGEST-MISMATCH` for any
      package with an executable file. The dag-oracle test uses in-memory tar bytes and never calls
      `extract_tar` — a differential blind spot. Fix: `os.chmod(0o755 if member.mode & 0o111 else 0o644)`
      on regular files (pass-1, `isfile()` branch, mirroring `git.py:501`) **AND on the hardlink pass-2
      write branch** (R2/depth: `enumerate_tarball_entries` applies MODE_EXECUTABLE to `islnk()` members
      too, so an exec hardlink in an external tarball still mismatches after a regular-only fix). Do NOT
      chmod symlinks (POSIX ignores symlink mode) or dirs. Add the missing STEP-1 "on-disk-after-
      materialize == object-store-enumeration" invariant test for tarball/OCI (parity with the existing
      git one, `test_identity.py:520`). Root-cause fix repairing both fetchers for every consumer.

**Publish slices:**
- [x] **S2 — `PublishPlan` + `PublishTarget` + `PublishSource` + `build_publish_plan` (PURE) +
      `PublishReceipt`. DONE 2026-07-17.** New `milpa/publishing.py`: 4 frozen dataclasses + pure
      `build_publish_plan` (folds `enumerate_git_entries(...)` through `compute_dag_identity`; plan carries
      source + content_hash + target ONLY — no entries, no digest). `PublishReceipt` field named
      `layer_digest` (matches `OciReceipt.layer_digest`, per handoff's explicit alignment note over the
      shorthand `digest`). 4 tests in new `tests/test_publishing.py`: tracer content_hash≡compute_content_hash
      (no divergence — holds by construction, shared `compute_dag_identity`), untracked-cruft-excluded,
      plan-carries-no-bytes/digest, receipt oci_ref≡`OciProvenance.reference`. Full suite green (2977 passed).
- [x] **S3a — git-tree source resolution + preflight guards. DONE 2026-07-17.**
      `resolve_publish_source(repo, version, *, allow_untagged=False) -> PublishSource` in
      `milpa/publishing.py`: resolves HEAD via `git rev-parse --verify --quiet HEAD`
      (`PUBLISH-NOT-GIT-REPO` if unresolvable — covers both non-git-repo and zero-commit repo);
      enforces the version↔HEAD tag binding — a tag `<version>` or `v<version>` must resolve to
      HEAD, unless `allow_untagged=True` (`PUBLISH-VERSION-TAG-MISMATCH`); refuses gitlinks via a
      direct `git ls-tree -r -z HEAD` mode-160000 scan (`PUBLISH-SUBMODULE-UNSUPPORTED`). Three new
      slugs minted in `milpa/errors.py` + `spec/errors.md` (new `## PUBLISH` section) in-commit —
      bijection lint green. 12 tests in `tests/test_publishing.py` (thin-reused
      `_make_local_git_repo` fixture, adapted from `test_hash_subcommand.py:53`): happy path,
      v-prefixed tag, not-a-git-repo, empty-repo-no-commits, tag-missing, tag-points-elsewhere,
      allow_untagged escape hatch, submodule-gitlink refusal. Each guard's load-bearing-ness was
      spot-checked by temporarily disabling it and confirming the corresponding test fails.
      Full suite green (2985 passed, 31 skipped).
- [x] **S1a — canonical packer skeleton. DONE 2026-07-17.** `pack_source(entries) -> bytes` in
      `milpa/publishing.py`: canonical sort by relpath → uncompressed GNU-format tar in memory
      (per-member mtime/uid/gid=0, uname/gname="") → separate `gzip.GzipFile(mtime=0)` compress (no
      `filename=`). Mode dispatch via `_add_entry` (MODE_REGULAR only; other modes raise
      `NotImplementedError` naming S1b/S1c as the single extension point). GNU longname ext-header
      mtime/uid/gid confirmed 0 by construction (CPython `_create_gnu_long_header` reads fresh info dict).
      5 tests: round-trip pack→real `extract_tar`→`compute_content_hash`==`compute_dag_identity(entries)`,
      byte-determinism, input-order independence, gzip-mtime-bytes==0, >100-char longname round-trip.
      Load-bearing-ness of the sort spot-checked (reverted sort → order test fails). Full suite green
      (2990 passed, 31 skipped).
- [x] **S1b — executable-bit round-trip. DONE 2026-07-17.** `_add_entry` packs `MODE_EXECUTABLE` as a
      regular-file member with tar mode `0o755` (via `_REGULAR_FILE_TAR_MODE` map: REGULAR→0o644,
      EXECUTABLE→0o755); shared `_normalized_tarinfo` zeroes mtime/uid/gid/uname/gname for both. Fallthrough
      `NotImplementedError` now only covers MODE_SYMLINK (S1c). 3 tests: exec round-trip pack→real
      `extract_tar`→hash==`compute_dag_identity`, on-disk `0o111` set on exec + NOT on sibling regular
      (guards uniform-chmod false-green), byte-determinism with an exec entry. RED confirmed via
      NotImplementedError. Full suite green (2993 passed, 31 skipped).
- [x] **S1c — symlink round-trip. DONE 2026-07-17.** `_add_entry` MODE_SYMLINK branch: reuses
      `_normalized_tarinfo`, sets `type=tarfile.SYMTYPE`, `linkname=entry.content.decode("utf-8")`,
      `size=0`, `tf.addfile(info)` (no data stream). UTF-8 is symmetric with the read side
      (`enumerate_local_entries` stores `os.readlink(...).encode("utf-8")`; `extract_tar` does
      `symlink_to(member.linkname)`) so `os.readlink(extracted)==content.decode` closes the loop. No mode
      chmod (POSIX ignores symlink bits). `else` fallthrough now only guards truly-unsupported modes —
      packer handles all 3 git-materializable modes cleanly. 3 tests: symlink round-trip
      pack→real `extract_tar`→hash==`compute_dag_identity`, on-disk `is_symlink()`+`readlink=="real.txt"`
      (guards regular-file-with-target-text false-green), byte-determinism. Relative in-tree target stays
      inside extract_tar's symlink-escape guard. RED via NotImplementedError. Full suite green (2996 passed).
- [x] **S3b — `make_oras_push` + digest parsing. DONE 2026-07-17.** `parse_oras_digest_json(stdout)->str`
      (pure): reads top-level `"digest"` field, falls back to `@`-suffix of `"reference"`; reuses
      `_RE_SHA256_DIGEST` from `milpa.registry` (same regex `validate_oci_digest` uses — no second parser
      invented). Empty/non-JSON/non-object/digestless → `PUBLISH-NO-DIGEST-IN-OUTPUT`. `OrasPush =
      Callable[[Path,str,str,str],str]`; `make_oras_push()->OrasPush` mirrors `make_oras_pull` (hard-coded
      `subprocess.run`, no injected runner — matched, not diverged). Closure runs `validate_oci_field` on
      all 3 user tokens BEFORE argv/subprocess (validation-precedes-side-effect seam → bad field raises
      `TNG-UNSAFE-OCI-FIELD` deterministically, no `oras` needed); non-zero exit → `PUBLISH-OCI-PUSH-FAILED`.
      Production subprocess path is the accepted no-mock gap (= `make_oras_pull`; real coverage is N1/T1
      E2E). 9 tests (digest happy×2, malformed×5 parametrized, bad-field-rejection×3). 2 slugs in
      errors.py + spec/errors.md, bijection lint green. Full suite green (3006 passed).
- [x] **S3c — `cosign_sign`. DONE 2026-07-17.** `CosignSign = Callable[[str], None]`;
      `make_cosign_sign()->CosignSign` mirrors `make_oras_push`: validates `oci_ref` via
      `validate_oci_field` before argv, runs `cosign sign --yes <oci_ref>` (keyless/ambient OIDC),
      non-zero → `PUBLISH-COSIGN-FAILED`. Return `None` (signature lives in registry/Rekor, not the
      receipt — PublishReceipt has no cosign field). 1 test (bad-oci_ref rejected pre-subprocess via
      `TNG-UNSAFE-OCI-FIELD`); production `cosign` invocation is the accepted no-mock E2E gap. Slug in
      errors.py + spec/errors.md, bijection lint green. Full suite green (3007 passed).
- [x] **S3d — `execute(plan, push, sign) -> PublishReceipt`. DONE 2026-07-17.**
      `def execute(plan, *, push: OrasPush, sign: CosignSign) -> PublishReceipt`. Re-derives entries via
      `enumerate_git_entries(plan.source.repo, plan.source.commit, submodule_fetch=None)` → `pack_source`
      → `tempfile.TemporaryDirectory` (context-managed, cleaned up unconditionally BEFORE sign, exception-
      safe) → `push(artifact, registry/repository:tag, artifact_type, layer_media_type)` returns digest →
      `oci_ref = OciProvenance(registry, repository, digest).reference` (never hand-rolled) → `sign(oci_ref)`
      (signs the immutable digest-pinned ref, NOT the tag) → receipt with `content_hash` straight from the
      plan (never recomputed). Push-target tag-form ref hand-rolled (research-confirmed no existing helper
      composes the `:tag` form — first instance, not duplication). 5 fake-injected tests: happy-path receipt
      shape, sign-gets-digest-ref-not-tag, push-gets-canonical-`pack_source`-bytes, push-before-sign
      ordering, temp-artifact-cleaned-up. No new slugs (execute propagates push/sign MilpaErrors). Full
      suite green (3012 passed).
- [x] **S4 — `publish` subparser in cli.py. DONE 2026-07-17.** `milpa publish --version <semver>
      --target <reg>/<repo> [--name] [--tag] [--output] [--dry-run] [--allow-untagged]`; `--version`+
      `--target` required (subparser `--version` does NOT collide with the global version action).
      `cmd_publish`: `load_or_discover_manifest` → `name or manifest.name`, `tag or version` →
      `split_oci_target(target)` → `PublishTarget` → `resolve_publish_source` → `build_publish_plan` →
      dry-run (re-enumerate + cheap stats `entry_count`/`total_bytes`/`top_dirs`, ONE unguarded stdout
      `print`, honor `--output`, no network) OR real path (`execute` with production
      `make_oras_push`/`make_cosign_sign`, receipt JSON to `--output` else stderr confirm). `MilpaError` →
      `main()`'s existing `_emit_slug`+exit-1 path. **Injectability seam 7a:** `cmd_publish(..., push=None,
      sign=None)` fills production factories when None (mirrors `cmd_fetch`'s injected env) — real receipt-
      write path fully fake-tested, no binaries. `split_oci_target` extracted to `source_spec.py` (SSOT:
      `parse_source_spec`'s `oci=` branch now calls it, old inline split removed) + reused by cli.py.
      Media types fixed (not flags): `application/vnd.milpa.source.v1` + `.v1.tar+gzip`. §10 signature edit
      landed (old `--dispatch-url`/`--provider`/`--repo-url`/`--signed-by`/`--oidc-token-env` all removed;
      grep-confirmed 0). 12 tests (`tests/test_publish_subcommand.py`): dry-run render+stats, dry-run
      `--output` JSON, `--name` auto-derive+override, `--target` first-`/` split, missing-`--version`
      exit 2, untagged→exit1+`PUBLISH-VERSION-TAG-MISMATCH` stderr + `--allow-untagged` reaches plan,
      real-path injected-fake receipt (signs digest-ref not tag), tag defaults to version+override,
      black-box subprocess dry-run smoke. Full suite green (3024 passed). No new slugs, no CLAUSE_INVENTORY
      entry, no conformance fixture.
- [x] **S5 — spec §10 prose refine. DONE 2026-07-17.** Restructured `spec/cli-contract.md §10` into
      subsections (both original NORMATIVE paragraphs preserved, section stays out-of-v1.0-conformance):
      §10.1 Behavior (generic pipeline, 3 preflight guards, dry-run/allow-untagged/name-autoderive/required
      flags), **§10.2 PublishReceipt JSON schema** (normative field list mirroring §2.5.1 `--certificate`
      style: `content_hash`/`oci_ref`/`layer_digest`/`artifact_type` — cross-tool contract; dry-run `--output`
      gets the plan render instead; note: the CLI `--output` record wraps these 4 receipt fields with the
      caller-supplied `name`+`version` for the T1 dispatch handler — no drift, spec documents both),
      §10.3 media types (`application/vnd.milpa.source.v1` + `.v1.tar+gzip`), §10.4 registry-auth-is-caller's,
      §10.5 Rust-intentionally-not-implemented (§10's normative "unimplemented verb MUST fail non-zero +
      diagnostic" still binds). §493 NOTE prose rewritten to match real `cmd_publish` stream routing (sole
      unguarded stdout print = dry-run render; real-run confirm → stderr). Guardrail test
      `test_publish_receipt_field_set_matches_spec_schema` pins the dataclass field set to EXACTLY the 4
      documented fields (load-bearing: exact-set equality). No CLAUSE_INVENTORY entry, no conformance
      fixture, no Rust edits, no new slugs. Full suite green (3025 passed, independently re-verified).

**Dropped from R1:** ~~S0a (`milpa hash local=` fix)~~ — R2 depth+feasibility: it reverses a
deliberate, spec-grounded (`lockfile §4.3 NORMATIVE`), currently-GREEN pinned test
(`test_hash_local_prov_no_identity_empty_stdout`, `test_hash_subcommand.py:144`) documenting that local
trees intentionally have no stable identity; and round-1's own receipt design deleted its only live
caller (`action.yaml:191` → `receipt.content_hash`). Forcing an emit reintroduces the mutable-snapshot
anti-pattern `cas_admissible=False` exists to prevent. The action gets `content_hash` from the receipt;
`milpa hash git=<path> ref=HEAD` already works for standalone hashing via the cas-admissible git path.
(Corey may veto the drop — see report.)

## Cross-repo E2E — BUILT 2026-07-25 (uncommitted in tianguis + softlink; milpa pushed)
- milpa publish pushed to origin/main `27435c5`. E2E target = **softlink v0.11.0** (dry-run validated: 162 files, `--name softlink` explicit since no milpa.kdl at that commit).
- **T1 (tianguis, ~/projects/tianguis — UNCOMMITTED):** `.github/actions/publish/action.yaml` rewritten to unified pack→push→sign→verify→attest→**dispatch** (replaces dead `milpa hash local=` with `milpa publish --output receipt.json` → read content_hash/oci_ref; dispatch POST via `jq -n`, `audience=sigstore` bearer confirmed vs function.go/oidc.go). **Control-loop caught+fixed a real bug:** the step overrode `ACTIONS_ID_TOKEN_REQUEST_TOKEN` with `github.token` (inherited latent from publish.yaml) → would break cosign keyless OIDC; removed. `commit-entry.yaml` milpa pin bumped `130ecd1`(stale, pre-restructure — path didn't exist)→`27435c5` (lockstep). `publish.yaml` retired to an erroring stub (was the SAN-collapse reusable-workflow path + called the deleted monolith). `docs/adoption/github.md` → composite-action pattern.
- **N1 (softlink, ~/projects/softlink — UNCOMMITTED):** NEW `.github/workflows/tianguis-publish.yaml` (did NOT clobber existing release.yaml). Rewritten by control loop to add `workflow_dispatch` (ref+dry-run inputs, checks out the tagged tree) since release.yaml creates tags via GITHUB_TOKEN → loop-prevention means no auto-chain. Calls the composite action in softlink's own job (SAN fix).
- All YAML syntax-valid. Q2 (oras login hardcoded ghcr.io) = fine for softlink/GHCR, noted.
- **FIRING runbook (Corey-gated):** (1) add `MILPA_GIT_READ_PAT` secret to softlink (read-only PAT on milpa, private); (2) commit+push tianguis + softlink; (3) trigger tianguis-publish.yaml via workflow_dispatch ref=v0.11.0 dry-run=true (smoke); (4) set GHCR pkg `ghcr.io/coreyleavitt/softlink` PUBLIC after first publish; (5) real run dry-run=false → dispatch commits entry → ratchet TOFU-pins coreyleavitt as authorizedSigner → **closes tianguis#42**.

## Cross-repo (original R2 plan — superseded by the BUILT section above)
- [ ] **T1 (tianguis) — bigger than a footnote (R2/breadth C1+C2).** Two surfaces, not one:
      - **`.github/actions/publish/action.yaml`:** call `milpa publish --output receipt.json` (resolves
        git tree, hashes, packs, pushes, cosigns) → read `receipt.content_hash`/`oci_ref`/`digest` →
        `attest-statement` + `sign_statement.py` (bundle) over `receipt.content_hash` → POST dispatch.
        **Delete the `milpa hash local=…` step** (~line 191, emits empty). Bump `milpa-ref` off the
        retired pre-`5ae87ad` pin.
      - **Dispatch payload:** the handler (`dispatch/handler.go:274`) hard-400s unless `name, version,
        oci_ref, provider, repo_url, signed_by` are ALL present. The receipt carries `oci_ref` (+ derive
        `name`/`version` from action inputs). The action supplies `provider`/`repo_url`/`signed_by` from
        **GH context** (`github.repository_owner`, `github.repository`, OIDC-derived signer — as
        `publish.yaml:100-149` already does), NOT from milpa. Note: `signed_by` is an **untrusted hint** —
        tianguis re-derives the real SAN from the VERIFIED author bundle (per Model-3), so its dispatch
        value is presence-only, not trust-bearing.
      - **`.github/workflows/publish.yaml` + `docs/adoption/github.md`:** the SOLE documented author-
        onboarding path, and it calls the DELETED monolith (`milpa publish --provider … --dispatch-url …`)
        and never invoked `action.yaml` → produces no entry bundle → **post-epoch (armed 2026-07-12) any
        publish through it is hard-rejected at commit-entry admission** (`mokMissingAttestation`). Rewrite
        it to route through `action.yaml`, or retire it. This is a scoped rewrite, not the R1 footnote.
      - **Media-type agreement:** confirm tianguis's OCI *fetch/verify* side accepts
        `vnd.milpa.source.v1` (today `OciFetcher` picks the artifact by `*.tar.gz` suffix only,
        `oci.py:288` — media type unenforced on pull; a push/pull type mismatch would not be caught).
- [ ] **N1 (nim-z3):** add `release.yaml` (tag-triggered, `id-token: write`) invoking the composite
      action; target `ghcr.io/coreyleavitt/z3`. **GHCR first-publish footgun (R2/breadth M2):**
      `GITHUB_TOKEN` + `packages: write` can PUSH a new package, but newly created GHCR packages default
      to **private** → milpa's unauthenticated `oras pull` (`oci.py:173`) can't fetch it and surfaces no
      diagnostic. Ensure the login step AND set package visibility public on first publish. Source scope
      = whole git tree at HEAD (`enumerate_git_entries`); `_deps/`/`nimcache_*`/`.claude/` excluded for
      free. Optional hygiene: untrack `_audit_headers/` (14 tracked files) if it shouldn't ship.
- [ ] **E2E:** fire (dry-run first, then real `v2.0.0`) → dispatch → commit-entry verify+admit →
      L3 ratchet TOFU-pins coreyleavitt as `authorizedSigner` for `github.com/coreyleavitt` `z3`
      (distinct from existing vendored zevv/zielmicha `z3`) → confirm milpa verifies. **R2/breadth M3
      (a win to confirm):** with N1 calling the action in nim-z3's own job, milpa's `cosign_sign` and
      the action's `sign_dsse` both land under nim-z3's REAL per-repo SAN — the genuine fix of the
      SAN-collapse "BOMBSHELL" (`commit-entry.yaml`), conditional on retiring the shared `publish.yaml`
      path (T1). Closes tianguis#42.

## Key facts (verified 2026-07-12)
- `milpa publish` absent from cli.py. `milpa hash` EXISTS; `local=` intentionally emits nothing
  (spec-grounded, NOT a bug — S0a dropped).
- **`enumerate_git_entries` (git.py:153) is the publish source SSOT** — reads the tree at a commit from
  the object store (`ls-tree -r -z` + `cat-file --batch`), no working tree / index / `.gitattributes`;
  returns `(list[MaterializedEntry], submodule_shas)`; `submodule_fetch=None` records nothing for
  gitlinks. `compute_content_hash` for the *working dir* uses `enumerate_local_entries` (identity.py:216)
  — a DIFFERENT seam; publish must use the git one. `MaterializedEntry = (relpath, mode_byte, content)`;
  symlink content = target; empty dirs are hash-invisible; **no inode/hardlink concept.**
- **`OciProvenance.reference` (oci.py:134)** = `registry/repository@digest` — the receipt `oci_ref` shape.
- **`safe_extract.extract_tar` drops the exec bit** on BOTH the regular-file and hardlink-write branches
  (S0b) — pre-existing; sinks the crown-jewel invariant for any executable-containing package.
- **`cli-contract.md:493` NOTE is false today** — references `cmd_publish`'s dry-run print that doesn't
  exist post-`5ae87ad` (S4/S5 fix).
- **Bijection lint** (`test_errors.py:57` `test_bijection_with_spec_errors_md`) is unconditional; add a
  `# PUBLISH` block. `harness/coverage.py::CLAUSE_INVENTORY` has no `publish` entry (§10 exempt by
  omission) — keep it that way.
- **Fixtures/precedents:** git repos (`test_conformance.py:613`, `test_hash_subcommand.py:53`), STEP-1
  parity (`test_identity.py:520`), fake-closure injection (`test_oci_fetcher.py`), subprocess smoke
  (`test_hash_subcommand.py`). Production `make_oras_pull` has NO argv test — the push/sign production
  closures inherit that no-mock gap (accepted).
- **nim-z3 real tree:** git-tracked = 251; working = 1272 (untracked `_deps/`/`nimcache_*`/`scratchpad/`/
  `.claude/`). `_audit_headers/` = 14 TRACKED files. No tracked symlinks, no submodules.
- Old publish.py at `5ae87ad^`: pack_source(rglob)/push_oci(regex digest scrape)/cosign_sign/
  post_dispatch/dry_run branch INSIDE the impure path. Bare `RuntimeError`s. No symlink test.
- Manifest `oci=`/`digest=` grammar + lockfile encoding + `OciProvenance` validators ALREADY SHIPPED.
- tianguis index: coreyleavitt `z3` = NEW tuple → clean first-use ratchet. No collision.
- tianguis S5 strict gate ARMED 2026-07-12 (`attestation-epoch`) — post-epoch publishes MUST carry a
  bundle or get rejected (why the `publish.yaml` retirement is urgent, not cosmetic).

## Code-review ledger (stage 4)

Round 1 (2026-07-17; 5 lenses: correctness/security/design/quality/coverage). Severities are the
control-loop's consolidated call after dedup + adversarial verification.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| H1 | High | `pack_source` has NO path-containment guard (relpath + symlink linkname used verbatim) → a crafted/malicious git tree ships a `../` zip-slip or absolute-symlink-escape payload into the cosign-**signed** public artifact. | **fixed** (A) | `_check_entries_safe`/`_check_relpath_safe`/`_check_symlink_target_safe` reuse `_normalize_lexical` (SSOT from safe_extract); validated at `build_publish_plan` (dry-run catches) + `pack_source`. Slug `PUBLISH-UNSAFE-PATH`. Tests: `test_{pack_source,build_publish_plan}_rejects_*` |
| H2 | High | `pack_source` pins no `encoding="utf-8"` on `tarfile.open` → real publish crashes with a bare `UnicodeEncodeError` on any non-ASCII path under an ascii-locale CI; `--dry-run` passes first. | **fixed** (A) | `encoding="utf-8"` pinned (publishing.py:534); `test_pack_source_non_ascii_relpath_*` + control assertion. I reproduced the bug pre-fix (LC_ALL=C) |
| M1 | Med | `execute` trusts the registry-reported push digest and cosign-signs it without local verification. | **fixed** (B) | Corey chose "verify via manifest fetch". `make_oras_manifest_fetch()` + `OrasManifestFetch` closure; `execute` fetches manifest post-push, asserts `layers[0].digest == sha256(artifact_bytes)` BEFORE sign, else `PUBLISH-DIGEST-MISMATCH`. Slugs `PUBLISH-DIGEST-MISMATCH`/`PUBLISH-MANIFEST-FETCH-FAILED`. 10 execute tests updated + mismatch/malformed tests |
| M2 | Med | SSOT violation: `_refuse_submodules` re-implements gitlink (160000) detection `enumerate_git_entries` already does. | **fixed** (A) | Extracted `parse_ls_tree_z(raw)` SSOT in git.py; both sites call it. Kept two subprocess calls (early guard = listing-only, mustn't pay for cat-file) — one parser, zero blast radius. Tests pin it. |
| M3 | Med | Double git-tree enumeration per publish, contradicting the RFC's "ONE enumerate call" claim. | **fixed** (A infra + B cli) | `execute(entries=None)` seam (A); `cmd_publish` enumerates once, reuses for stats + `execute` (B). Spy tests assert exactly-once. **Note:** B inlined plan composition → SSOT smell CR-B1, fixed in C. |
| M4 | Med | `--name` auto-derives from the working-tree `milpa.kdl`, not the git HEAD tree that's actually published. | **fixed** (B) | `_load_head_manifest_name` = `git show HEAD:milpa.kdl` + `parse_manifest`; `MAN-NO-MANIFEST` if absent. Test: working-tree edit ignored, HEAD name wins |
| M5 | Med | `_add_entry` symlink `content.decode("utf-8")` leaks a bare `UnicodeDecodeError` on a non-UTF-8 symlink target. | **fixed** (A) | Combined with H1: validated at plan time. Slug `PUBLISH-NON-UTF8-SYMLINK-TARGET`. Test `test_*_non_utf8_symlink_target` |
| M6 | Med | After an irreversible push+sign, if the `--output` write fails the digest is surfaced nowhere. | **fixed** (B) | `published …→oci_ref` confirmation prints to stderr unconditionally + BEFORE the `--output` write. Test: `_atomic_write` raises → oci_ref still on stderr |
| M7 | Med | The `--output` JSON (real cross-repo wire contract) is an ad-hoc dict built in two places; only the `PublishReceipt` dataclass is pinned by a test, not the wire shape. | **code fixed (B) / spec doc → C** | Frozen `PublishOutputRecord` (6 fields) + `PublishDryRunRecord`, one builder each, exact-field-set guardrail tests on the ACTUAL serialized keys. Spec §10.2 doc → C. |
| M8 | Med | `split_oci_target` accepts empty registry/repository (`ghcr.io/`, `/pkg`) → garbled ref. | **fixed** (B) | raises `CLI-SOURCE-SPEC-INVALID` on empty side; hardens `oci=` too. Tests at split + `cmd_publish` + `main()` levels |
| M9 | Med | `PUBLISH-NOT-GIT-REPO` raised at two semantically-different sites but spec documents only one. | open (C) | quality review |
| CR-B1 | Med | (introduced by B's M3 fix) `cmd_publish` inlines `build_publish_plan`'s composition → plan-building logic duplicated. | open (C) | control-loop design lens; fix = optional `entries` param on `build_publish_plan` |
| M10 | Med | Zero test coverage: S0b hardlink exec-bit chmod branch; `execute`'s failure paths. | **fixed** (A) | `test_hardlink_executable_bit_is_preserved_and_sibling_is_not` + `test_execute_{push,sign}_failure_*` (propagation, no-sign-on-push-fail, temp cleanup) |
| L1 | Low | `push`/`sign` typed `object` + `entries: "list"` — drops the closure/entry types. | **fixed** (B) | `cmd_publish` now `push: "OrasPush\|None"`, `sign`, `manifest_fetch` typed; `entries: "list[MaterializedEntry]"`; dropped the `# type: ignore` |
| L2 | Low | `_add_entry` unsupported-mode raised bare `NotImplementedError`. | **fixed** (A) | now `MilpaError(MILPA_INTERNAL, ...)` (house pattern for unreachable); test added |
| L3 | Low | `pack_source`/enumeration buffer all blob bytes in memory, no size cap — self-DoS on a hostile huge tree. | open | security (minor) |
| L4 | Low | Missing tests: malformed-present-digest fallback; mixed-mode/empty-file/non-ASCII round-trips; `test_safe_extract` own exec-bit assertion. | open | coverage review |
| L5 | Low | `--dry-run` never runs `validate_oci_field`, so a flag-injection-shaped `--target` passes dry-run and only fails at real push. | **fixed** (B) | `cmd_publish` calls `validate_oci_field` on registry/repository right after `split_oci_target`, unconditionally. Test: dry-run rejects `-evil/x` |

### Round 2 (2026-07-18; re-review over the fixed scope: security/correctness/design)
Security: clean — all round-1 fixes hold, nothing new above Low (path-containment + digest-verify hand-traced, fail-closed, every entry checked). Correctness: all 6 fixes verified correct. Design: 2 new Mediums.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R2-M1 | Med | `execute`'s `manifest_fetch` defaults to `make_oras_manifest_fetch()` when omitted — inconsistent + untested None-fallback branch. | **fixed** (R3) | `execute(plan, *, push, sign, manifest_fetch, entries=None)` — manifest_fetch now required (no default/internal fallback); `test_execute_requires_manifest_fetch_kwarg` pins the TypeError |
| R2-M2 | Med | `_load_head_manifest_name` lives in cli.py, runs its own `git show` — belongs in publishing.py with the other HEAD-tree reads. | **fixed** (R3) | moved to `publishing.py::resolve_publish_name(source: PublishSource)` alongside `_resolve_head_commit`/etc; cli.py has 0 refs to the old name; 2 direct unit tests + CLI pins kept |
| R2-L1 | Low | `parse_source_spec`'s `oci=` branch re-wraps `split_oci_target`'s error with a stale "must contain '/'" message. | **fixed** (R3) | branches on `"/" not in ref_part` first; other failures propagate `split_oci_target`'s accurate error; message-text test added |
| R2-L2 | Low | "if entries is None: enumerate" duplicated in `build_publish_plan` + `execute`. | **fixed** (R3) | `_entries_or_derive(source, entries)` helper, called from both |
| R2-L3 | Low | dry-run hand-rebuilds the `target` dict instead of `dataclasses.asdict(pub_target)`. | **fixed** (R3) | now `asdict(pub_target)` |

### FLOOR REACHED (2026-07-18)
Round 3 fixed both round-2 Mediums + 3 Lows cleanly; control-loop re-verification (proportionate to the mechanical delta; Security surface untouched) found nothing new above Low. **0 Critical / 0 High / 0 Medium open.** Only Lows deliberately LEFT per the through-Medium mandate: **L3** (unbounded in-memory blob buffering — self-DoS, size-cap belongs in a broader effort) and **R2-L4** (non-UTF-8 `milpa.kdl` → `MILPA-INTERNAL` instead of a coded slug; caught by the safety net). Full suite **3083 passed, 31 skipped, exit 0** (+58 tests over the review). NOTHING COMMITTED — awaiting Corey.
| R2-L4 | Low | `_load_head_manifest_name` decodes the `git show` manifest blob without `errors="replace"` → a non-UTF-8 `milpa.kdl` raises bare `UnicodeDecodeError` (caught by `MILPA-INTERNAL` net; less-specific diagnostic, not a crash). | **left (Low, per mandate)** | correctness re-review; natural fold-in when R2-M2 relocates the fn |

## Architect review ledger

### Round 1 (2026-07-12; depth/breadth/design/feasibility)
| id | sev | finding | status |
|----|-----|---------|--------|
| F1 | fork | publish source tree scope (working-dir pollution → leak) | RESOLVED → git-tracked tree (Corey); **materialization method superseded by R2** |
| C1 | crit | `milpa hash local=` emits nothing | **REVERSED by R2** → S0a dropped (fixing dead code / green pin) |
| C2 | crit | `extract_tar` drops exec bit → digest mismatch | fixed-in-plan → S0b (widened in R2) |
| D1/H2/D2/D6/D4/D5/E1/D3/E2 | high/med | reuse enumerate_*; symlink round-trip; drop identity-theater flags; digest→receipt; own module; typed closure; PUBLISH-* slugs; auto-name; §10 with S4 | applied (further refined in R2) |

### Round 2 (2026-07-12; depth/breadth/design/feasibility) — clear-best fixes APPLIED
| id | sev | finding | resolution |
|----|-----|---------|-----------|
| R2-1 | crit | `git archive HEAD` byte-diverges from `git=` consumers via `.gitattributes` → breaks A==B | **use `enumerate_git_entries` object-store seam** (Decision 1 / D-git) |
| R2-2 | high | submodules vanish from `git archive` → incomplete artifact | refuse gitlinks → `PUBLISH-SUBMODULE-UNSUPPORTED` (S3a) |
| R2-3 | high | version↔HEAD binding unverified (`--version` is a bare arg) | `PUBLISH-VERSION-TAG-MISMATCH` tag-binding guard + `--allow-untagged` (S3a) |
| R2-4 | high | S0a reverses a spec-grounded GREEN pin + fixes dead code | **drop S0a** (Corey veto invited) |
| R2-5 | high | S1 hardlink round-trip test structurally unreachable | dropped from S1c |
| R2-6 | high | dispatch handler needs provider/repo_url/signed_by; T1 dropped them | T1 supplies from GH context (untrusted hints); server re-derives SAN |
| R2-7 | high | `publish.yaml`/docs = sole onboarding path, calls deleted monolith, post-epoch broken | T1 scoped rewrite/retire (not a footnote) |
| R2-8 | med | S1/S3 too coarse for TDD | split S1→a/b/c, S3→a/b/c/d; pull S2/S3a forward |
| R2-9 | med | plan carrying raw `entries` = `--output` JSON footgun | plan holds source+hash+target; execute re-derives |
| R2-10 | med | two-flag `--registry`/`--repository` vs shipped `oci=` grammar | combined `--target`; shared split helper |
| R2-11 | med | `oci_ref` hand-rolled; receipt has no normative schema | derive from `OciProvenance.reference`; spec the schema (S5) |
| R2-12 | med | S0b misses hardlink pass-2 chmod | widened S0b |
| R2-13 | med | `cli-contract.md:493` NOTE false about nonexistent `cmd_publish` | S4/S5 fix |
| R2-14 | med | GHCR first-publish private-by-default footgun | N1 set visibility public |
| — | low | prod oras/cosign argv unprovable (no-mock); media-type unenforced on pull; `--name`/`--target` mismatch; detached HEAD/size/retry out-of-scope; dry-run no-network; digest field naming | stated in doc |

## Open forks / notable calls (awaiting Corey — invited to veto, else proceed to TDD)
- **Drop S0a** (R2-4): recommend drop — it reverses a spec-grounded green pin and fixes dead code. Say
  the word to keep it (as an explicitly-labeled point-in-time diagnostic, NOT a stable identity).
- **Version↔tag binding** (R2-3): recommend requiring a `<version>`/`v<version>` tag at HEAD, fail-
  closed, with `--allow-untagged`. Alternative: warn-only. Recommend fail-closed (release safety).
- **Workspace-member publish OUT OF SCOPE** (R2/breadth H1): publish operates on the whole git repo
  tree at HEAD; a workspace member can't be published in isolation (would need `git archive`-style
  pathspec scoping). nim-z3 is standalone so not blocking. **Follow-up GH issue to be filed** (per
  file-defer-now discipline). Confirm this scope boundary is acceptable.

## Open sub-decisions (non-blocking; recommend + proceed)
- Dry-run first vs straight to real v2.0.0: recommend dry-run first (composite-action dry_run path).
- `_audit_headers/` (14 tracked files): publishes as-is under "tracked = published." Publish reads the
  tree at HEAD, so a plain `git rm -r _audit_headers` commit drops it from all FUTURE artifacts — no
  history rewrite needed (a `filter-repo` expunge is orthogonal, only for the repo's past). nim-z3 repo
  hygiene, not milpa's concern.
