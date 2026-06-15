# pluggable-fetchers (Tier 3, F1–F3) — handoff

- **Stage:** 4 (/code-review) — **COMPLETE: FLOOR REACHED (0 Crit/High/Med open) after 4 fix rounds + 3 re-review rounds.**   •   Mandate was: fix through Medium, leave Lows.
- **Resume:** stage 4 done. Remaining = Lows (left per mandate) + deferred issues #146/#148/#149. **Still outstanding: commit the uncommitted tree (content-addressed-identity Phase B–D + ALL pluggable-fetchers stage 3+4 work + spec edits) — ONLY when Corey asks.** Recommend committing Phase B–D separately for a clean boundary.
- **Round 3 (R19+R21+R5-1+doc) → re-review clean (0 Crit/High/Med) EXCEPT R5-1 self-inflicted digest slug divergence → Round 4 reverted (Rust digest now format-validated like Python). #147 closed-invalid.**
- **Round-1 fixes (all at baseline, both suites green):** R1+R1b+R7 (G1 Python `_fetch_any` SSOT+None-guard+_clear_dest symlink), R2+R6 (G2 Rust `decompress_capped`+`DECOMP_CAP_OVERHEAD`+USTAR checksum), R10 (G5 spec §4.1 SSOT, Opus-corrected member two-axis), R4+R5 (G3 download-cap + git `--end-of-options`), R9+R16 (G4 stale-sweep regression + bz2/xz bomb tests). R3/R8→#146, R18→#147.
- **R3/R8 DEFERRED → issue #146** (bz2 + mixed-case-sha corpus fixtures infeasible under option-B text-only corpus + no pure-Rust bz2 encoder; mitigated by mirrored per-impl tests; R16 keeps them mirrored).

## FORK RESOLVED (2026-06-15) — corpus tarball decompression
Corey chose **B (build archives at test time, corpus stays text-only)**. Implemented in slice 5: build-mode trigger = `format` file (`gz`/`xz`) in mock dir; runner builds real archive from `content/`, runs production decoder (SSOT); encoder-dependent TOFU pin redacted as `<TARBALL-SHA256>` in both runners. bz2 EXCLUDED from corpus (no pure-Rust bz2 encoder) — bz2 decoder covered by per-impl unit tests (Rust `tarball_extracts_bzip2`, Python `test_bzip2_archive_extracted`).

## Stage 3 slice plan (8 slices) + progress
1. [x] **Local no-identity — Python + spec.** SSOT seam: `FetcherRegistry.fetch()` dispatches on `cas_admissible` → `identity=None` for local; propagates to writer (gated on `is not None`). Spec: lockfile-schema §6.2 kind-dispatch (local=liveness-only), cli-contract §5.5 clean-no-follow-symlinks. 10 tests. pytest green (only fixture-144).
2. [x] **Local symlink + no-identity — Rust.** `Provenance::cas_admissible()` (already existed) mirrors Python; `fetch_local` copy→symlink; `resolver::process_local` skips hash (identity=""=sentinel→None); verify `is_local_dep`→liveness-only. 8 tests. `./dev-rust test --workspace` green at baseline (fixture-099+144), 0 divergence.
3. [x] **Shared local-fetch fixture (181) + root-cause harness fix.** Local deps run REAL (not mocked) in conformance — filesystem-native, hermetic (source in-fixture). Both runners: resolve local against fixture_dir, real LocalFetcher, portable symlink snapshot (`name -> (symlink)`). ALSO fixed latent bug both impls: `rebuild_deps_view` was sweeping local symlinks during stale cleanup. fixture-181 (cmd=resolve) passes both, 0 divergence.
4. [x] **Rust bz2/xz tarball formats.** Pure-Rust `bzip2-rs`+`lzma-rs` (verified no C deps); unified decompress-by-magic seam; same `EXTRACT-SIZE-LIMIT` bomb-guard cap all formats; matches spec §TarballDep. 3 tests incl cross-format identity. 0 divergence.
5. [x] **Tarball multi-format byte-identity fixtures.** Build-mode harness (both runners, SSOT into production decoder); TOFU pin redacted `<TARBALL-SHA256>`. fixture-182 (gz) + fixture-183 (xz), byte-identical `identity`. Python bz2 unit test added. 0 divergence.
6. [x] **Cross-transport byte-identity fixture (RFC invariant #2).** fixture-184: same content via git + tarball(gz) ⇒ identical `identity` (sha256:9b0826d0…); also exercised Phase D dedup (aliases). 0 divergence.
7. [x] **sha256 case-normalization** (both impls). SSOT at 4 compare sites (real+mocked × 2 impls); lowercase+strip `sha256:` on `want`. 8 tests. Both suites green. NOTE: consider a normative note in spec (sha256 compare is case-insensitive) — minor, deferred.

DEFERRED (filed, do NOT implement): #144 hardlink extraction; #145 Rust commit_present.
NOTE: re-counted to 7 implementation slices (item count differs from earlier "8" — fixtures 5+6 are distinct; CLI add --local/--tarball = file issue, not this pass).

## Fork RESOLVED (2026-06-15) — local-dep identity
Corey: "what's the best-in-class phd-level design — pre-v1 spec freeze, this is the time to fix things" (= resolve under the bar, don't poll). **Decision: option (a) — local deps carry NO identity; `verify` checks liveness only.** Rationale: identity=hash-of-immutable-bytes is a category error for a live tree; drift on an edited tree is noise not signal; frozen path already rejects local deps so identity isn't load-bearing; right pressure (want a snapshot ⇒ use git=/tarball=). Folded into RFC item 1 with the verify/lockfile slices.

## Deferred issues FILED
- #144 — hardlink extraction bug (both impls; reject-with-EXTRACT-HARDLINK-UNSUPPORTED when implemented).
- #145 — Rust commit_present single-step vs Python 4-step (shallow-clone divergence).

## Round-2 outcome (2026-06-15)
4 lenses. Confirmed F1/F2 DONE; produced full spec-cascade list + sequenced slice plan (A spec → B Rust bz2/xz → C Rust copy→symlink → D cross-transport fixture → E sha256 case-norm; F hardlink + G commit_present = file issues, defer impl). Crate blocker CLEARED: `bzip2-rs` + `lzma-rs` are pure-Rust (verify-first). Design lens raised the deep one ↓.

### Round-2 fork (awaiting Corey)
- **Local-dep verify-drift semantics.** A symlinked live local tree has a drift-prone content_hash; current verify HARD-FAILS after first edit (defeats live-dev = the point of `local=`). Options: (a) record NO identity, verify checks liveness only [purist]; (b) record snapshot identity, verify reports drift INFORMATIONAL exit 0 [matches my earlier "drift caught by verify" framing]; (c) hard-fail [current, wrong]. **My rec: (b).** Frozen path already rejects local deps (FROZEN-LOCAL-DEP) so local identity isn't load-bearing for reproducibility.

### Overreach caught + handled
breadth agent (a6b01f9d) exceeded review scope — edited 6 spec files + errors.py + Rust all_codes(), adding a dangling `EXTRACT-HARDLINK-UNSUPPORTED` code (NO raise site; hardlink is a DEFERRED item). **Reverted** that code from errors.md/plugin-contract.md/errors.py/fetch.rs; bijection restored; Python suite back to baseline (only fixture-144). KEPT its symlink + bz2/xz + identity-taxonomy spec-doc edits (match resolved decisions = legit stage-2 design output, but re-validate in stage 3 slice A). NOTE: spec now says local=symlink while Rust still copies — that's the punch-list gap, documented.

### To file (defer-now)
- GH issue: hardlink extraction bug (both impls, reject-with-EXTRACT-HARDLINK-UNSUPPORTED if implemented; strip_components-to-linkname).
- GH issue: Rust commit_present single-step vs Python 4-step (shallow-clone divergence).

## Round-1 outcome (2026-06-15)
All 4 lenses agree: **F1 + F2 = DONE both impls; SafeExtractor DONE; F3 structurally done but DIVERGENT.** RFC was ~3mo stale; landed code beat the RFC on every open design Q. Applied a status-banner + corrections table + "Remaining work" punch list to the RFC (one surgical insertion). Verified the concrete code claims myself (not just agent say-so).

### Verified findings
- **Fork 1 (spec decision):** LocalFetcher Python symlink (`local.py:146`) vs Rust copy (`fetchers.rs:120`); spec §LocalDep says MUST copy → Python violates. Un-fixtured. **My rec: amend spec to symlink** (local= exists for live dev; drift caught by verify) — but genuinely Corey's product call.
- **Fork 2 (spec decision):** tarball Python `r:*` (gz/bz2/xz) vs Rust gzip+raw-tar (`fetchers.rs:285`). Spec silent. **My rec: restrict normatively to gzip+raw-tar, align Python to reject others w/ coded error, file issue to extend** (minimal + SSOT) — reduces a working Python capability, so surfacing.
- **Bug (shared, file issue):** hardlink→symlink + parent-relative escape + no strip on linkname, BOTH impls (`safe_extract.py:194`/`safe_extract.rs:108`). Not a divergence. Niche.
- **Divergence (file issue):** Rust `commit_present` single `cat-file -e` vs Python 4-step fallback (`git.py`). Shallow-clone edge. Un-fixtured.
- **Test gap:** no cross-transport byte-identity fixture (RFC invariant #2). Add in stage 3.
- **Hygiene:** sha256 compare not case-normalized; CasAdmitting.fetch_any SSOT dup (deliberate, low).
- **Scope this pass:** F1 (git→Fetcher-protocol refactor), F2 (TarballFetcher), F3 (LocalFetcher). F4–F8 (hg/fossil/OCI/IPFS/entry-points) OUT of scope this pass.

## Context
Second pass of the Tier-3 `/rfc-flow` (`/rfc-flow remaining tier 3`). First pass (content-addressed-identity Phase B–D) is Stage-4 COMPLETE but **still uncommitted** — see `docs/rfc-content-addressed-identity.handoff.md`. One RFC at a time through the full flow; this is the second.

**KEY RISK — RFC is STALE (dated 2026-05-22).** Substantial work landed since. milpa ALREADY has `impls/python/milpa/fetchers/` (`types.py` protocol+registry, `git.py`, `tarball.py`, `local.py`, `oci.py`, `mocked.py`, `cas_admitting.py`, `safe_extract.py`) + Rust `fetchers.rs`/`safe_extract.rs`. Strong prior: **F1 + SafeExtractor already DONE; F2/F3 likely PARTIAL or DONE.** The architect round must reconcile RFC against current code — likely outcome is a gap analysis ("what's left"), not a fresh slice plan. Feasibility agent tasked to render DONE/PARTIAL/NOT-STARTED verdicts with evidence.

## Architect round 1 — agents launched (2026-06-15)
- depth (id ac4972…), breadth (a2159d…), design (a399fe…), feasibility (a071e1…) — all sonnet, background.

## Open forks (awaiting Corey)
- _none yet — pending consolidation_

## Key decisions (this session)
- Sequenced content-addressed-identity FIRST (done), pluggable-fetchers SECOND (now).

## Review ledger (stage 4) — ROUND 2 (2026-06-15)
4 lenses re-reviewed changed scope (security, cross-impl+correctness, design, spec-consistency). Spec §4.1 + lockfile-schema member edits verified FULLY CONSISTENT with impls + fixtures. #147 (from round 1) CLOSED-INVALID — Rust transport `Provenance` enum has no Member variant (first verifier conflated it with `ProvenanceRecord::Member`); cas_admissible() never called for member.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R19 | Med | xz path bypasses shared `decompress_capped` (inline LimitedWriter cap + dup EXTRACT-SIZE-LIMIT) — R2 SSOT incomplete. | round-3 fix | design lens; in round-3 Rust agent. |
| R21 | Low(div) | Rust safe_extract skips file_count cap in Symlink/HardLink arm; Python enforces → >100k symlinks: Python errors, Rust accepts (cross-impl divergence). | round-3 fix | cross-impl lens; trivial; in round-3 Rust agent. |
| R5-1 | Low→— | Rust fetch_oci doesn't leading-`-` validate `digest`. | resolved-by-revert (R4) | NOT a real gap — Python doesn't either (digest is format-validated → TNG-BAD-OCI-DIGEST). Round-3 "fix" ADDED digest to Rust's loop → created a slug divergence (Rust TNG-UNSAFE-OCI-FIELD vs Python TNG-BAD-OCI-DIGEST on `-`-prefixed digest). Round 4 reverted; Rust digest now format-validated at registry layer like Python. Baseline green. |
| R19,R21,RustDoc | Med/Low | (round-3 fixes) | FIXED | Round-3 re-review (security+design + cross-impl) confirmed clean: xz SSOT via `size_limit_error()`+`decompress_capped_xz()` (sole EXTRACT-SIZE-LIMIT literal); R21 symlink cap EXACT parity w/ Python (>, max_file_count, EXTRACT-SIZE-LIMIT). |
| RustDoc | Low | `cas_admissible()` doc comment (milpa-types/lib.rs:160-161) conflates Local w/ member. | round-3 fix | spec+cross-impl lens; in round-3 agent. |
| SpecR2 | — | §6.3 wording said member verify "not to _deps/<name>/" but impl routes VIA the _deps/<name> symlink; manifest-grammar §4.3 lacked identity-bearing cross-ref; plugin-contract §4 NOTE implied a Member transport Provenance subclass. | FIXED (Opus) | Self-introduced/accuracy; corrected §6.3 + added cross-refs/NOTEs. |
| R22/R23 | High-class(latent) | USTAR corrupt-mid-archive header: Rust rejects, Python tarfile silently truncates at offset>0 (success+diff identity); + Rust can't parse GNU base-256 checksum. No corpus reach. | deferred → #148 | Fix = harden Python to match Rust strictness + cross-impl fixture (blocked w/ #146). Flagged to Corey. |
| R20 | Low | Download cap enforced post-buffer; curl --max-filesize bypassed by chunked/no-Content-Length → narrow OOM DoS. | deferred → #149 | Both security+cross-impl reviewers non-actionable; proper fix = bounded streaming read. |
| R7-1 | Low | `_clear_dest` rmtree(ignore_errors=True) swallows cleanup failures (pre-existing). | wontfix(loop) | Leave per mandate (Low). |
| design Lows | Low | `fetch_one` Callable Protocol; compressed_cap ctor leak; oras-validation no shared helper. | wontfix(loop) | Leave per mandate (Low). |

## Review ledger (stage 4) — round 1 (2026-06-15)
5 reviewers (security, cross-impl fidelity, correctness, design, test-coverage), all sonnet. 4 High/Critical verified adversarially.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R1 | High | `fetch_any` fully duplicated in `FetcherRegistry` (types.py:351-429) + `CasAdmittingFetcher` (cas_admitting.py:128-201), ~78 lines; SSOT (Critical by project rule). Bundles latent `result.identity[:23]` None-crash. | fixed | VERIFIED holds; liftable to shared `fetch_one` callable, no behavior change. Crash latent (no prod fetch_any call sites). |
| R2 | High | Rust bomb-cap formula `max_total_size+512` + `.take(cap)` guard duplicated across `fetch_tarball` (fetchers.rs:355,366-375) + `fetch_oci` (497,499-503); `decompress_with_cap` nested-local, no named const. | fixed | VERIFIED holds (all 4 sub-claims, exact lines). |
| R3 | High | No bz2 corpus fixture (182=gz,183=xz only) — cross-impl byte-identity for bz2 has NO shared guard (per-impl tests only). | fixed | Confirmed from fixture listing. RFC round-2 item #10 left unassigned. |
| R4 | Med | No compressed-download-size cap before decompression → OOM DoS via large incompressible archive. Both impls symmetric (tarball.py:177, fetchers.rs:309). | fixed | security agent; not separately re-verified (clear from code). |
| R5 | Med | git `ref` (and `commit_sha`, oras registry/repo) option-injection: leading-`-` reaches subprocess unchecked. | fixed | VERIFIED downgraded: url REFUTED (scheme whitelist); ref holds but no code-exec checkout flag exists. Fix = `--` separator + commit_sha hex guard. Defense-in-depth. |
| R6 | Med | Rust hand-rolled USTAR reader skips tar header checksum (safe_extract.rs); corrupt-but-structurally-valid archive writes garbage on first TOFU fetch. Python tarfile validates → divergence. | fixed | correctness agent. |
| R7 | Med | `_clear_dest` (types.py:457-463) `shutil.rmtree` without `is_symlink()` guard → would delete user's source tree if a local-dep symlink is the dest. Latent (only via fetch_any local fallback). | fixed | correctness agent; tied to R1 area. |
| R8 | Med | No mixed-case sha256 corpus fixture (case-norm covered per-impl only). | fixed | test-coverage agent. |
| R9 | Med | rebuild_deps_view local-symlink stale-sweep (the slice-3 bug fix) has NO regression test in either impl (test_deps_view.py has zero local cases; Rust frozen_tests none). | fixed | test-coverage agent. |
| R10 | Med | "local ⟹ no identity" re-derived in 3 independent layers — no single spec predicate. | FIXED | G5 added `spec/identity.md §4.1` SSOT. **Opus-corrected**: G5 conflated `identity-bearing` with `cas_admissible`; they're ORTHOGONAL axes that diverge on `member` (member = identity-bearing YES, cas_admissible NO — verified vs fixtures 081/086/117 which emit member identity + impls' `is_local_dep`=local-only). Rewrote §4.1 as two-axis table + per-axis consequences (a/b on identity-bearing, c/d on cas_admissible); fixed lockfile-schema §2.4/§3.1/§6.2/§6.2.1/§6.2.2/§6.3 member-classification. Cross-refs to manifest-grammar §4.3 + plugin-contract §4 (both confirm member cas_admissible=False). |
| R18 | — | (NEW, found during R10 verify) Rust `cas_admissible()` returns true for Member, violating spec (manifest-grammar §4.3 / plugin-contract §4 say False); Python agrees with spec. Latent (sweep keys on ProvenanceRecord::Member directly). | deferred → #147 | Pre-existing; workspace (#25) territory, out of F1–F3 fix scope; needs workspace-aware test. |
| R11 | Low | Rust `io_zip` maps ALL I/O errors (incl. create_dir/write failures) to `EXTRACT-ZIP-SLIP` (safe_extract.rs:180). | fixed | design agent. |
| R12 | Low | Dead `LocalProvenance` branch in `_build_graph` (resolver.py:1935-37) would emit ABSOLUTE path to lockfile if reached. | fixed | correctness agent. |
| R13 | Low | Rust `fetch_local` uses `FETCH-LOCAL-PATH-NOT-DIR` for symlink/clear-dest creation failure (wrong slug). | fixed | correctness agent. |
| R14 | Low | verify local-liveness four-state machine expressed as implicit two-bool if-else (both impls). | fixed | design agent. |
| R15 | Low | edge-source dispatch (`if has_milpa_kdl … else Nimble…`) repeated 3× in resolver.py (1391/1568/1639) instead of using the `resolve_edges` coordinator. | fixed | design agent. |
| R16 | Low | bz2/xz decompression-bomb guard not explicitly unit-tested (gzip is). | fixed | test-coverage agent. |
| R17 | Low | mocked fetcher disk-side `archive_sha256` not lowercased before compare (both impls; harmless — no fixture uses uppercase on disk). | fixed | cross-impl agent. |
| — | refuted | Decompress-bomb error-code divergence (Rust EXTRACT-SIZE-LIMIT vs Python FETCH-EXTRACT-FAILED) | refuted | Both collapse to FETCH-ALL-FAILED at observable boundary (conformance-fixtures.md unreachable table). Latent internal-only. |
| — | refuted | git `url` `--upload-pack` injection (High claim) | refuted | manifest-parse scheme whitelist (MAN-GIT-URL-NO-SCHEME) blocks leading-`-` URLs; clone path also dest-controlled. |
| — | refuted | Correctness BUG5/6/8 (os.sep Windows, empty-provenance crash, symlink milpa.kdl) | refuted | self-refuted by correctness agent on closer read. |
| — | deferred | #144 hardlink→symlink extraction; #145 Rust commit_present shallow-clone divergence | deferred | filed pre-review; out of this pass. |
