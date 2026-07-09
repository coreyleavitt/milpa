# #177 — conformance golden-hash gap — handoff

- **Mode:** direct `/tdd` (no RFC ceremony — user approved; 3 fixtures, not a design problem)
- **Scope:** extend the git-protocol fixture tier with 3 cross-impl golden fixtures (Python + Rust runners both assert).
- **Status:** ALL 3 SLICES DONE + independently gated green (Python full suite exit 0 / 2391 passed; Rust conformance 0 failed, corpus 333 fixtures 299 pass). Awaiting user decision on commit (`closes #177`).
- **NEXT (active work moved on):** session pivoted to **#103** (consumer-side registry trust). That work is RFC-first — see `docs/rfc-registry-trust-federation.handoff.md` (Stage 1 draft in progress). #177 itself is terminal: nothing left but the commit decision. #103 fixtures will stack on top of #177's uncommitted tree — commit #177 first to keep changesets clean.

## Slices
- [x] **Slice 1** — realistic-size fixture (60 ASCII files, 152.4 KiB) exercising `cat-file --batch` past the 64 KiB pipe buffer. `fixture-334-git-protocol-realistic-size`. Golden `dag-sha256:9f97c0781233a93befb74e75b43ae84659f057d19ad2a219f0a62e76c27b09cc`. Python 316 pass / Rust 296 pass, byte-match. Incidental fix: `_REGEN_MODE`-aware early-return in `test_conformance.py` (~L687) so new git-protocol fixtures can bless.
- [x] **Slice 2** — hostile-tree zip-slip fixtures: `fixture-335-...-parent-escape` (`../../escape`) + `fixture-336-...-absolute-path` (`/escape`), both assert `EXTRACT-ZIP-SLIP`. Added `hostile_tree` directive to BOTH generators (raw tree via `git hash-object -t tree --literally`). Key discovery: `git clone file://` runs pack-fsck which rejects hostile trees pre-materialization → fixtures use a BARE local path (loose-object local transport, no fsck) so hostile objects reach milpa's OWN guard. Faithful: milpa clones without `transfer.fsckObjects` (verified `git.py:812`), so production https (fsck off by default) also delivers hostile objects to the materializer guard. fixture-336 (absolute) NO divergence — both impls raise EXTRACT-ZIP-SLIP via PathBuf-join-replaces-root semantics.
- [x] **Slice 3** — submodule superproject `fixture-337-git-protocol-submodule-superproject`: 2 submodules (`libs/zeta`, `libs/alpha`, declared unsorted) via `submodules` descriptor directive → `.gitmodules` with RELATIVE `./<repo>` sibling urls (NOT `../` — git strips the superproject basename before resolving, so `./repo` = sibling; milpa supports it → deterministic content_hash) + gitlinks via `git update-index --cacheinfo 160000`. Golden `content_hash` `dag-sha256:7e4235e042a8dc9a9e0c00bc32f260e978c4eab1a8e5d3103ad158991e4e68da` + golden `submodule_shas` (path-sorted: `libs/alpha 03b4039a…`, `libs/zeta 42025d90…`). Determinism: generator pins `GIT_AUTHOR/COMMITTER_DATE=1577836800` AND `-c commit.gpgSign=false` (host commit-signing was the root cause of an initial Rust/Python SHA divergence — signature changes the commit object). New runner assertion `expected/submodule_shas` (both impls) + Python REGEN writes it. Cross-impl byte-match confirmed.

## Files touched (uncommitted, do NOT commit without asking)
- `conformance/spec-v1/fixture-334/335/336/337-*` (new)
- `impls/python/tests/test_conformance.py` (REGEN early-return, hostile_tree gen + bare-path exec, [slice3: date-pin + submodules gen + submodule_shas assert/regen])
- `impls/rust/crates/milpa-conformance/src/runner.rs` (hostile_tree gen + bare-path exec, [slice3: date-pin + submodules gen + submodule_shas assert])
- Pre-existing WIP (NOT mine): `docs/rfc-fetch-extraction-hardening.handoff.md`, amoxtli's re-locked milpa.lock (separate repo).

## Incident (resolved)
A botched empirical experiment (`mktemp -d "$TMPDIR/..."` with TMPDIR unset → `/`, perm denied → `cd` silently failed → git plumbing ran against the MAIN repo) clobbered `refs/heads/main` to a hostile commit. Fixed with `git reset --soft 3e6226d` (real main); removed stray `.tree_sha`; no file escaped to disk; dangling hostile objects auto-GC. LESSON: all git experiments go in the scratchpad dir with an explicit verified absolute path.

## Issue cleanup done this session
Closed 6 stale-open issues already shipped in `cd41dce` (rfc-resolver-correctness #172, commit lacked `closes` trailers): #178 #168 #131 #115 #108 #179. (#142 was already closed.) Open count 79→73.

## After #177
- File the minor lzma tech-debt note from #177 (Rust `decompress_capped_lzma`/`_xz` HRTB un-unifiable) — already documented in-code; decide if it needs its own issue or just stays a code comment.
- #103 (the user's stated follow-on): verify tianguis index Rekor/signature attestation at resolve time (consumer-side trust, #107 umbrella).
- Consider committing #177 when green (ask first; user may bundle).
