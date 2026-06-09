# Rust-port design RFC — handoff

- **Stage:** 3 (slice grind) — **P1–P4 (main). S0 (main 94c524f). S1 (rust 6de9646). S2 harness+CI (rust a05697b). S3 manifest grammar (rust 2bf4fe5). S4 identity+CAS (rust 09323f7). S5a lockfile parse DONE+GREEN+COMMITTED (rust 2d95579). On `rust` branch. Next = S5b lockfile emit (needs S4 identities; depends on S6 for Version→semver formatting — see S5b note).**   •   **Round:** 2/2
- **LOOP MODE:** Corey switched to autonomous grind — DON'T pause per slice; do a slice, commit, report one line, ScheduleWakeup ~15 min, continue. He compacts occasionally. Still pause only on a genuine fork or wrong-spec escalation.
- **COMMIT CADENCE: standing approval granted** — commit each slice on `rust` as it greens, no re-ask; still pause on forks/wrong-spec.
- **S3 result (DONE, rust 2bf4fe5):** full milpa.kdl package+workspace grammar in milpa-manifest, mirroring milpa/manifest.py. Five dep forms + predicates (inline/child-OR/when-AND) + flags/overrides/mirrors/cas/spec-version/dev-deps + every structural MAN-* code. **kdl-rs = KDL 1.0 via `parse_v1`** (v2's `parse` decodes bare true/false as strings — confirmed against fixtures 027/038/040/045; enabled the `v1` cargo feature → pulls kdl 4.7.1 backend, in Cargo.lock). `ManifestError` is now one struct `{code:&'static str, message}` (mirrors Python's coded exception); `all_codes()` lists the 62 structural slugs. **Deliberate spec-correct divergence:** `url_arg` rejects non-`(url)` annotations on URL positions (MAN-URL-ARG-TYPE) per grammar §2 — Python ignores annotations; no fixture exercises it. milpa-core re-exports `parse_document`/`ManifestDoc`. MilpaTarget::Resolve parses → surfaces MAN-* / falls through to NOT_WIRED. Corpus 62 pass / 55 xfail / 0 regressions.
- **S4 result (DONE, rust 09323f7):** `identity.rs` = `compute_content_hash` (canonical byte stream §1.2 — relpath/mode/content with 0x00 seps, raw-byte relpath sort §1.3, .git-exclude §1.4, exec-bit §1.7, symlink-by-target §1.5, no CRLF norm §1.6) + `parse_identity` (4 ID-* codes; **ID-NOT-A-STRING unreachable** — input is `&str`) + ID-NON-UTF8-SYMLINK-TARGET. `store.rs` = CaStore admit (**move-via-rename** per spec §3.3 — the S4-line "copy-then-admit" paraphrase was wrong; spec+Python use rename; copy-then-admit is the S10 TempCaStore/cas-seed concern), CAS-IDENTITY-MISMATCH, duplicate=no-op, link (relative symlink §3.5, CAS-NOT-IN-STORE §3.6, idempotent clear_dest mirroring fsutil.py), default_store tiers 1/3/4. **Deliberate non-catalog choice:** mid-hash filesystem I/O failures are uncoded in spec §5 (Python propagates raw OSError) → rendered as `MILPA-INTERNAL-IO` sentinel, kept OUT of all_codes(). all_codes() now declares 5 ID-* + 2 CAS-* (subset; bijection at S12). **Byte-parity vector pinned against the Python oracle** (mixed regular/exec/symlink/.git tree → efa2…60b9). 26 core tests green; conformance corpus UNCHANGED (no fixture greens at S4 — unblocks first success fixture at S9). `compute_content_hash`/`parse_identity`/`default_store`/`SUPPORTED_ALGORITHMS` re-exported from milpa-core.
- **S5a result (DONE, rust 2d95579):** `lockfile.rs` = `parse_lockfile(text)->Lockfile` (KdlDocument::parse_v1, KDL-1.0 same as S3) + `load_lockfile(path)` disk wrapper. **New milpa-types data model** (the S1 scaffold wrongly reused `Vec<ResolvedDep>` for `Lockfile.deps`): `LockedDep` (identity is `Option<String>` — Phase A partial; + active_flags/self_mirrors) and `ProvenanceRecord` — a **6-kind** enum (Git/Tarball/Local/Member/Oci/Registry) deliberately SEPARATE from the **4-kind** transport `Provenance` (Member=workspace-internal, Registry=read-compat #97; neither is a transport). `Lockfile` gains `version:u32` + hand-written `Default` (v1, not derived 0); `LOCKFILE_SCHEMA_VERSION` const. **`Milpa` impl type** added to lib.rs carrying `LockfileParser`; Resolver(S7)/FrozenResolver(S10) land on the SAME type. identity validation reuses `parse_identity`, remapping any ID-* → LOCK-DEP-IDENTITY-INVALID. **Deliberate spec-correct strictness:** `version` requires a true KDL `Integer` → a numeric *string* is LOCK-FIELD-TYPE (Python's `int("1")` would coerce; spec §2.1 says non-integer→type-error, Rust is more conformant). CoreError grew 14 LOCK-* slugs + a `message()` accessor; all_codes() includes LOCK-FILE-NOT-FOUND/UNREADABLE (unit-tested, not fixture-expressible). 12 LOCK-* fixtures (066-077) greened+removed → corpus **74 pass / 43 xfail / 0 xpass / 0 regressions**. 33 milpa-core unit tests green; clippy+fmt clean.
- **S5b resume — lockfile EMIT** (RFC §6 S5b; canonical byte-exact serialization): in milpa-core `lockfile.rs`, add `format_lockfile(&Lockfile)->String` + `write_lockfile` mirroring `lockfile.py:format_lockfile`/`_format_provenance_fields`/`_kdl_str`. Byte-exact per lockfile-schema §2.4 (header line, `version`/`strategy`, deps **sorted lexicographically by name**, `requires` args sorted, per-kind provenance field order git=kind/url/ref/commit_sha · tarball=kind/url/sha256 · local=kind/path · member=kind/name · oci=kind/registry/repository/digest · registry=kind/name/tag/commit_sha; optional fields omitted when None; `self_mirrors` `(url)`-annotated; final byte `\n`). **R11 escaping** (`"`/`\`/control via the single `_kdl_str` helper). Need a `from_graph(ResolvedGraph)->Lockfile` bridge (`_locked_from_resolved`: placeholder version "0.0.1" for non-named kinds, named carry resolved version → **needs S6 Version→semver `_format_version_str`**, so S5b depends on S4+S6). NO fixture greens on S5b alone (first success = S4+S5b+S6+S7b+S7c+S9, §9). fixture-118-lock-string-escaping is the escaping check (greens once the resolve/emit path is complete). Spec refs: lockfile-schema §2.4/§3/§4, errors.md, `milpa/lockfile.py`. TDD: port format_lockfile unit tests (round-trip parse↔format on hand-built Lockfiles).
- **Resume (stage 3):** `/loop implement the next unimplemented RFC slice with /tdd …` — next = **S3 KDL reader + manifest grammar** (RFC §6 S3 + §4.5 S0(a) decision). In `milpa-manifest`: use `kdl` 6.7.1 as a parse-only impl detail (annotation via `KdlEntry::ty()`, value via `.value().as_string()`, line/col via `KdlError::diagnostics[].span`) to parse `milpa.kdl` package + workspace (`(url)` annotation, `when`/predicate blocks, feature flags, `dev-deps`, `spec-version`) into the milpa-owned `Manifest`/`Workspace` (NEVER re-export the kdl AST; no emission depends on kdl). **Plus the `.nimble` line-form compat parser** (4 `requires` forms, `srcDir`, `when`-block warning, drop `nim` req). Replace `parse_manifest`/`parse_workspace` `unimplemented!()`. Fan `ManifestError` into the granular `MAN-*` codes (S1 skeleton currently maps the generic parse variant→`MAN-KDL-SYNTAX`); update `ManifestError::all_codes()` to list every real MAN-* it can now emit. **Wire `MilpaTarget`**: the `Cmd::Resolve` arm starts parsing (manifest parse alone greens the 62 MAN-* *error* fixtures, which fail before fetch/solve); the `Cmd::ParseLockfile` arm stays unwired (S5a). As MAN-* fixtures green, REMOVE their ids from `rust/crates/milpa-conformance/known_failing.txt`. NIMBLE-* are **exempt** (not fixture-expressible; unit-test only). TDD: port the Python manifest grammar unit tests + drive the MAN-* conformance fixtures green.
- **S3 spec refs:** `docs/spec/manifest-grammar.md` (full grammar), `docs/spec/errors.md` (MAN-* slugs), `tests/test_man_code_triggers.py` (trigger table → fixture mapping), `milpa/manifest.py` + `milpa/nimble_parse.py` (Python oracle). RFC §4.5 (kdl-rs decision/seam) + §6 S3.
- **S2 result (DONE, rust a05697b):** harness in `milpa-conformance` = `urlkey` (§2.3.1 + @-edge) / `fixture` (discover + cmd + expected I/O, NO milpa parsing) / `fake_fetcher` (`FakeFetcher` impl of `milpa_core::Fetcher`) / `runner` (`Target` seam + `Scratch` + `run_fixture` byte-diff/`<CAS_ROOT>`-canonicalize + `MilpaTarget` incremental-wire). **Design note:** the §4.4 sketch's `FixtureContext{manifest:Option<Manifest>}` was realized as the **`Target` trait** (impl-under-test parses raw inputs itself) — the truest black box (§5), keeps the oracle from baking in the parser it validates; the harness layer does pure fixture I/O. Per-fixture `cargo test <slug>` filtering (rstest/datatest-stable) was **deferred** — fixtures are dirs with non-uniform contents (datatest matches files), so a single aggregating corpus `#[test]` with a grep-able xfail/xpass summary is the better fit; RED→green observability preserved via the summary counts. `TempCaStore`/`cas-seed` copy-then-admit deferred to **S10/frozen** (synthetic fixtures don't need it; `admit` is S4). Error-parity is **subset (⊆)** now, flips to **bijection** at S12. 117 real fixtures all parked in `known_failing.txt`.
- **P1–P4 (committed, main):** 6569b32 P1 fixture-117 + per-member nim.cfg; 8c489eb P2 `.nimble` SSOT unify; b37e3e0 P3 `_kdl_str` lockfile escaping; 00aa968 P4 dispatch-exemption + §5.1. Suite 906/6.
- **S0 spikes (DONE, decisions recorded in RFC §6 S0):** (a) **kdl-rs `kdl` 6.7.1 — USE CRATE** (annotation via `KdlEntry::ty()`, value via `.value().as_string()`, errors carry line/col via `KdlError::diagnostics[].span`). (b) **pubgrub-rs `pubgrub` 0.4.0 — USE CRATE** (canonical solve on fixture-063 = X@2.0.0/Y@1.0.0/Z@1.0.0; BFS order P = `prioritize` returns `Reverse(name)`; maxver = `choose_version` highest-in-range). No fallbacks → **S7a stays the ~3-day "wire the crate" branch**. Pinned: kdl 6.7.1, pubgrub 0.4.0, miette 7.6.0. Throwaway spike crate deleted.
- **S1 scaffold (DONE+GREEN, uncommitted, on `main` working tree as untracked `rust/` + `dev-rust`):** six-crate workspace (milpa-types/solver/manifest/core/cli/conformance), `Cargo.toml` workspace + pinned `[workspace.dependencies]`, **committed-ready `Cargo.lock`**, `rust-toolchain.toml` (1.96.0), `rust/.gitignore` (target/, .cargo/), `./dev-rust` wrapper (podman/docker, tty-guard, cargo-registry volume). milpa-types = data skeletons (Version/Provenance+cas_admissible/ResolvedDep/ResolvedGraph/Lockfile); solver = Strategy/VersionSet/parse_version stubs + SolverError; manifest = Manifest/Workspace/Profile/ManifestError; core = 3 resolver traits + Fetcher/FetcherRegistry/Receipt + MilpaError+From impls + identity/store/registry stubs; cli = bin stub; conformance = links core + CORPUS_REL. **`cargo build --workspace` + `cargo clippy -D warnings` clean; 8 unit tests pass; `uv run pytest` 906/6 green.**
- **COMMIT PLAN (awaiting Corey go):** (1) S0 RFC decisions → `main` (design/spec lives on main, §4.3). (2) cut `rust` from `main`. (3) S1 scaffold (`rust/` + `dev-rust`) → `rust`. (4) standing per-slice commits on `rust` for S2+.
- **RFC:** `docs/rfc-rust-port-design.md` (rounds 1+2; committed main `8375f84`; S0 decisions added, uncommitted).
- **§8 GATE: RESOLVED + COMMITTED** — R1–R11 spec reconciliations committed main `b49e21b`.
- **Branch:** still on `main`. `rust` cut at commit-plan step 2.
- **Dev image (untracked):** `rust/Containerfile` built = `ghcr.io/coreyleavitt/milpa-rust:1.96` (Tumbleweed + rustup-pinned Rust 1.96.0 + rustfmt/clippy). NOTE deviation from RFC §4.3's "FROM rust:slim" wording — Tumbleweed+rustup bakes the toolchain at build time so the runtime build needs no network (the RFC's actual goal); immaterial base-image choice, not a spec violation. Committed at S1 with the workspace, on `rust`.

## P1 RESOLVED — workspace nim.cfg is per-member, not single (approved, landed)
P1 (workspace success fixture) hit a latent gap: the conformance harness's
`_outputs` emits ONE root nim.cfg via the single-package `format_nimcfg`, treating
members as `_deps/<name>` external deps. But milpa actually emits **per-member**
nim.cfg via `write_workspace_nimcfgs` — each member dir gets its own nim.cfg with
relative sibling paths, and there is NO root nim.cfg. Verified output for the
fixture-117 two-member case:
- `member-a/nim.cfg` = header only (no deps)
- `member-b/nim.cfg` = header + `--path:"../member-a/src"`
The spec (conformance-fixtures.md §2 layout / §2.1.1 / §2.5) assumes a single
`expected/nim.cfg`. No workspace success fixture ever existed, so the gap was never
exercised. milpa.lock + _deps_structure.txt ARE correct as shared root outputs
(members are exempt from CAS materialization, so _deps_structure is empty here).

**Recommended resolution (clear-best, but amends frozen spec v1.0 → needs go/no-go):**
1. Workspace success fixtures express nim.cfg per-member: `expected/<member-path>/nim.cfg`,
   one per member (mirrors the member-subdir input layout). No root `expected/nim.cfg`.
2. Harness `_outputs`/runner: when parsed type is WorkspaceManifest, write per-member
   nim.cfg via `write_workspace_nimcfgs` into a scratch copy and byte-diff each against
   `expected/<member>/nim.cfg`. milpa.lock + _deps_structure.txt stay single shared root files.
3. Amend conformance-fixtures.md §2/§2.1.1/§2.5 to define per-member nim.cfg for workspace fixtures.
4. Update RFC P1 text ("expected/{milpa.lock,nim.cfg,_deps_structure.txt}") + S11 + §9 coverage to match.
Fixture-117 inputs already authored (root + member-a/liba + member-b/libb→member liba).
Once approved: finish harness change, generate expected/, green Python suite, then resume P2.

## P2 RESOLVED — NIMBLE-* not fixture-expressible + SSOT dup fixed inline (Corey: fix inline; DONE)
P2 said "author 2 NIMBLE-* error fixtures (coverage-floor bijection gap)". Investigation:
- **No bijection gap.** `NIMBLE-FILE-NOT-FOUND` has a direct unit test (test_error_catalog.py:923);
  `NIMBLE-FILE-UNREADABLE` is already in that file's KNOWN_UNTESTED (line 941). Lint is clean now.
- **Not fixture-reachable.** `load_nimble` (sole raiser of NIMBLE-*) has NO production caller —
  only tests call it. The conformance harness never runs `.nimble` discovery (reads milpa.kdl text
  directly; cmds = resolve/parse-lockfile/frozen). And you can't commit a missing/unreadable file to
  git, so -NOT-FOUND/-UNREADABLE are intrinsically not fixture-expressible.
- **SSOT duplication found.** `_load_manifest_from_nimble` (the real discovery path) re-reads the file
  and raises `MAN-FILE-UNREADABLE`; `load_nimble`(→NIMBLE-*) is dead outside tests. Two codes, one condition.

**Recommended resolution:**
1. **P2 = exemption, not fixtures** (mirror P4): document NIMBLE-FILE-* as CLI-discovery file-IO errors
   exempt from the conformance corpus — covered by unit tests + KNOWN_UNTESTED. Add to both impls'
   bijection-lint exemption lists (Python already effectively exempts via KNOWN_UNTESTED; document for Rust).
   Update RFC P2 text + §9 (NIMBLE-* row already says "none exist (corpus gap)" → change to "exempt").
2. **File a separate cleanup issue** for the load_nimble vs MAN-FILE-UNREADABLE duplication (catalog-design
   call: delegate `_load_manifest_from_nimble`→`load_nimble` and pick one code, OR retire load_nimble+NIMBLE-*).
   Touches errors.md (frozen v1.0) + both catalogs → not inline corpus-prep work. Per [[feedback_defer_file_now]] file now.

## Round-2 changes applied (clear-best)
- **CRITICAL** fixed: VersionSet/Strategy+algebra moved to milpa-solver (orphan-rule); milpa-types = raw Version + data only. Added type-placement table.
- **CRITICAL** fixed: pubgrub seam = `DependencyProvider::prioritize` (order P), NOT VersionSet trait; S0(b) criterion = solution-match on fixture-063, not emission order.
- Resolver trait gains `prior_lockfile` param (pin reuse). Provenance → closed enum (not dyn Any). Traits+MilpaError+From-impls live in milpa-core. build.rs→`#[test]` for bijection lint. BTreeMap/IndexMap determinism non-negotiable. FixtureContext builder seam + canonicalize-not-readlink trap. known_failing xpass detection. Containerfile base-image-with-toolchain + MSRV≥1.74.
- Slices: S5→S5a(parse,no-S4)/S5b(emit); S7b depends on S6; "unblocks vs greens" labels fixed; S13 now all 8 verbs incl add/remove/update + format_manifest; S14 strip-before-hash test; per-slice unreachable-code unit tests. §9 coverage map corrected (first success = S4+S5b+S6+S7b+S7c+S9).
- New §10 **pre-grind P-slices** (Corey's call: make them the FIRST slices, not side-channel issues): P1 workspace-success fixture, P2 NIMBLE-* fixtures, P3 escaping fixture+Python fix, P4 exclusive-dispatch exemption decision. (strip_components folded into S14, not a corpus slice.) Fixed factual error: MAN-*=62 not ~65; NIMBLE-* fixtures=0.
- Spec doc: lockfile §7.4 cross-ref to always-on header (R5 follow-up).

## Stage-3 order (when grind begins)
P1–P4 (on `main`) → S0 spikes (kdl-rs, pubgrub-rs) → S1 scaffold → S2 harness+self-test+CI → S3… per §6. First success fixture greens at S9.

## Open items for Corey
1. ~~Commit gate~~ — DONE: RFC+handoff (`8375f84`) + 3 spec docs (`b49e21b`) committed to main.
2. Containerfile push to ghcr-public deferred (needs `podman login ghcr.io` + push + flip package visibility). Not blocking.

## Constraints from Corey (verbatim intent)
- Rust impl developed on a **separate branch** (`rust`); merge to main when green.
- **Same-repo coexistence for now** — design how Python + Rust live side by side in this repo.
- Do **NOT** design a multi-repo conformance harness yet (may split repos later; not worth it now). One shared fixture corpus, read from disk by both impls.

## Key decisions in the draft (to be stressed in architect rounds)
- Pure Rust (no PyO3) — the reference must be an independent oracle.
- Layout: `/rust/` cargo workspace, crates `milpa-core` (lib) / `milpa-cli` (bin) / `milpa-conformance` (harness). Hatchling only packages `milpa/`, so Python build is unaffected. Fixtures referenced by relative path (one copy).
- The **fixtures** are the single source of truth; two runners (Python pytest + Rust `milpa-conformance`) consume one corpus.
- Library forks-with-fallback: `kdl` (kdl-rs) for parse only / hand-roll fallback; `pubgrub` (pubgrub-rs) or port the teaching solver; `sha2`; real fetchers behind a trait (fake-injected in fixtures, not fixture-gated).
- Spec-conformance is the bar, not Python-parity (Rust may be *more* conformant, e.g. #117).

## Slices (15; see RFC §6)
S1 scaffold+coexistence · S2 conformance harness (RED backbone) · S3 KDL+manifest · S4 identity+CAS · S5 lockfile · S6 version/VersionSet/Strategy · S7 solver+resolver · S8 fetcher trait+fake+index/TNG · S9 nim.cfg · S10 frozen · S11 workspace · S12 error-catalog parity · S13 CLI · S14 real fetchers · S15 (stretch) differential harness.
Done = S1–S13 + full spec-v1 suite green under milpa-conformance.

## Open questions — ALL RESOLVED in round 1 (RFC §7)
- kdl-rs → S0(a) spike (annotation+value accessible; error carries line/col); hand-roll fallback.
- pubgrub-rs → S0(b) spike vs fixture-063; milpa VersionSet impls pubgrub trait; port fallback.
- harness → #[test]/rstest parametrization (not standalone bin).
- error parity → independent Rust catalog + build.rs lint vs errors.md.

## Round-1 changes applied to RFC (clear-best)
- Crate split 3→6 (milpa-types vocabulary crate enforces SSOT at compile time).
- 3 narrow traits (LockfileParser/Resolver/FrozenResolver) replace god `trait Milpa`.
- Fetcher returns receipt-not-identity; cas_admissible on Provenance. Per-domain error enums + MilpaError.code().
- Slices: added S0 spikes; split S7→S7a/b/c; S2 done = synthetic pass+fail self-test (not "all RED"); S14 gets local no-network tests; known_failing.txt drives progress; CI minimal by S2; toolchain pinned + containerized.
- Added missing-coverage acceptance criteria: verify verb (S13), index cache 4-state (S8), mirror fallback + pin reuse + provenance precedence + dev-deps (S7b), .nimble parse + TOFU (S3/S14), per-member nim.cfg closure (S11), env→Profile/_deps literal/member subdirs (S2).
- New §8 (11 spec reconciliations R1–R11 + workspace-success-fixture corpus gap) and §9 (fixture coverage map).

## GATE awaiting Corey (the one escalation)
§8: the review found 11 internal spec contradictions (R1/R2 text-verified: nim.cfg order conflict; _deps_structure relative-vs-absolute). All fixtures-win, v1-permitted reconciliations. Need go/no-go to land them on main (per §4.3 reflow) before the dependent slices.

## Context note
This RFC opened in the same session that froze spec v1.0 (prior RFC: rfc-reaching-rust-rewrite, committed: a2957b6/ad55aa0/20e2de6). Context is large — safe to `/compact` after architect round 1, or `/clear` before a fresh session (re-read this handoff first).

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (stage 4 not started) | — | — |
