# Identity Conformance Authority RFC — handoff

- **Stage:** 3 tdd (grind via /loop)   •   N1/N2/N3 stand; **"no legacy support" correction applied to RFC** (Corey: strip the read-only `sha256:` legacy apparatus — two-tier parse_identity, no `ID-LEGACY-SCHEME`, `sha256:`→`ID-UNSUPPORTED-ALGORITHM`)
- **Resume:** loop PAUSED — Phase-A code slices (A0/A1/A2) all DONE+green, uncommitted. Remaining slices need Corey: **A3 blocked on commit+push to milpa main (parity.yaml clones HEAD) + cross-repo tianguis**; **Phase B (B1+) is the epoch-2 Merkle-DAG effort that re-changes all hashes via B-cutover (amoxtli unblock = Corey's call)**. Decision needed: (a) commit Phase A now to unblock A3, and/or (b) green-light grinding Phase B's B1 spec slice.
- **Suite:** Python full suite green @ 2357; Rust `./dev-rust test --workspace` green (conformance 290 pass). A0 (parse+cmd+fixture) + A1 (two-tier parse_identity, `dag-sha256:` cutover) + A2 (EOL git-vs-archive fixtures) done both impls.

## Slices (round-1 revised — Merkle folded in, dual-emit dropped, B2 split, B4 split out)
Phase A — authority & epoch rails (pre-v1 simplified: no flat-sha256; delete tianguis hasher outright):
- [~] A0 — `milpa hash <source>` oracle subcommand (both impls) — SSOT delegation surface; prereq for A3
  - [x] A0-parse (py): `parse_source_spec` in `milpa/source_spec.py`; new slug `CLI-SOURCE-SPEC-INVALID`
  - [x] A0-cmd (py): `milpa hash` cmd via `env.fetcher.inner.fetch`→`FetchResult.identity` (pin holds); spec cli-contract §5.11
  - [x] A0 (rust): parse_source_spec (`crates/milpa-core/src/source_spec.rs`) + `milpa hash` cmd; added `identity:Option<String>` to Rust `Receipt`, `DefaultRegistry::fetch` is the single hash site, `CasAdmittingFetcher::inner()`. 800 tests green, clippy clean.
  - [x] A0-fixture: `fixture-326-hash-git-probe` pins `milpa hash git=<url> ref=main` → `sha256:813c34f…` via real GitFetcher over a generated bare repo (no network). NOTE: `local=` form prints EMPTY stdout by design (local deps have no stable identity, lockfile §4.3) — so the fixture uses the git-protocol form. Both runners wired (py `_execute_hash_fixture`, rust `Cmd::Hash`/`run_hash_fixture`).
- [x] A1 — DONE both impls. Two-tier parse_identity: `dag-sha256` sole supported algo, bare `sha256:`/unknown→`ID-UNSUPPORTED-ALGORITHM` (no new error, no legacy tier). Emit prefix cutover `sha256:`→`dag-sha256:` over the SAME flat digest (interim epoch; real Merkle DAG digest = B1) — spec §2.1 interim NOTE records the tension. cas.py/store.rs algo-enum generalized. Struck identity.md §1.7 stale "no external consumers" clause + §1.7.6 + §2.3 dual-emit; errors.md ID-UNSUPPORTED-ALGORITHM covers stale sha256 (re-lock); dep-decl.md §3 dep_decl_hash stays sha256: (distinct domain). Regenerated ~222 identity + 63 content_hash + 73 _deps_structure fixtures to dag-sha256. Py 2351→2355, Rust all ok.
- [x] A2 — DONE. AUDIT verdict: fixture-296/297 do NOT exercise git-vs-archive EOL divergence (both git-only; their hash diff is `.gitattributes` presence, not LF/CRLF; runner passes `core.autocrlf=false`, object-store bytes). Added `fixture-327-eol-lf-git-identity` (git LF → `dag-sha256:985b34e3…`) + `fixture-328-eol-crlf-tarball-identity` (tarball CRLF → `dag-sha256:f1baf39c…`) — two DIFFERENT hashes prove no EOL normalization (§1.6). fixture-327 LF hash == fixture-302 tarball-LF hash ⇒ transport-independence also pinned. Py 2355→2357, Rust conformance 288→290 pass.
- [ ] A3 — **BLOCKED on Corey**: cross-repo (tianguis), and `parity.yaml` clones milpa HEAD so it REQUIRES A0–A2 committed+pushed to milpa main first. tianguis cross-repo ATOMIC: route BOTH driver.nim + realdriver.nim through `milpa hash`; DELETE identity.nim + test_identity.nim + frozen JSON (after namespace.nim audit). tianguis stops being a hashing impl entirely.

Phase B — canonical Merkle-DAG identity (epoch 2):
- [ ] B1 — spec the canonical content Merkle DAG (byte-level tree-node table, DAG-construction algo, neutral blob hash, 3-valued mode-byte incl exec, submodule splice, empty-tree recursion, dag-sha256/64-hex); epoch-2 cross-transport fixtures = blocking gates
- [ ] B2-git / B2-tarball / B2-local / B2-oci(stub) — per-transport materializers behind iterator seam; MockedFetcher uses DAG-over-staged-bytes
- [ ] B-cutover — corpus-regen tool (~126 locks+6 hashes, cross-impl verified) + index.kdl/json regen + Rekor policy + consumer re-lock + UNBLOCK amoxtli; retire flat-sha256 emission
- [ ] B-split (separate issue) — CAS subtree dedup (layout change; refs rfc-store-gc)

Ordering: A0→A1→A2→(A3+A4) ; B1→B2-git→{tarball,local,oci}→B-cutover.
Interim amoxtli unblock = one-off epoch-1 regen (ops, reversible, superseded by B-cutover) — Corey's call.

## Forks & decisions (after rounds 1+2)
RESOLVED r1: F-A→neutral blob hash; F-B→explicit non-CID `dag-sha256:`; dual-emit→dropped; subtree-dedup→split.
ROUND 2: §3.4 encoding declared SOUND after **C1 fix** (4-valued mode-byte incl `0x40`=tree → blob/subtree domain separation; was structurally unable to represent subdirs). Folded: per-level leaf-name sort (top cross-impl risk) + hand-computed pinned nested fixture; empty-root digest; `milpa hash` pinned to FetcherRegistry.fetch + `local=` form + ref-must-be-SHA; three-tier parse_identity; `--frozen` pre-flight; per-command lock semantics; spec-edit ledger; A0-parse + B2-git-split + cross-repo ordering. Error RENAMED ID-EPOCH-MISMATCH→**ID-LEGACY-SCHEME**.
NOTABLE DECISIONS (applied, Corey may veto): N1 SSOT=delegate via `milpa hash`; N2 exec bit in epoch-2 identity; **N3 strike spec §2.3 dual-emit "algorithm agility"** (override of a prior spec decision — the one to veto if you want dual-emit kept).
OPEN: none blocking. §3.4 byte table (B1) is the last cheap-to-change artifact; reviewed-sound. /tdd can begin once N1/N2/N3 stand.

## Key decisions (this session)
- Diagnosis: not a milpa bug, not just an old binary — an **SSOT violation**. Identity is an algorithm with 4 impls; tianguis's `identity.nim` is an **ungated second producer** (`vendor/driver.nim:84 computeContentHash(tmp)`, working-tree), its parity test is a **stale git-free snapshot**, and the spec's "no external consumers → mutate in place" premise is **falsified** (tianguis + every lock are compat-bound).
- Evidence: bearssl@22c6a76 hashes 3 ways — `7bdfea3c` (index+locks) / `6ddd9062` (Jun-22 binary) / `7caf0450` (HEAD object-store). Reproduced live with the rebuilt HEAD binary.
- cargo/uv use artifact-bytes identity (zero drift, but transport-bound) → **rejected** for milpa (multi-transport thesis needs transport-independent tree identity). git/OCI/IPFS Merkle-DAG/multihash → **Phase B horizon**.
- milpa **leads**: identity is spec-owned, corpus is the authority; tianguis becomes a bound peer. Fixing tianguis-in-isolation = symptom.
- milpa HEAD binary rebuilt + installed (symlink `~/.local/bin/milpa` → `impls/rust/target/release/milpa`, now HEAD via `./dev-rust build --release`).

## Environment / unblock state
- amoxtli is still broken (no change made to its trees). The unblock is slice A5; until then, amoxtli coasts on nothing (its stale `_deps/` were deleted by Corey).
- Repro projects live under `/tmp` only (`milpa-skew-repro*`, `amox-test`, `amox-iso`) — none touch the real project trees.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (none yet — not in review) | — | — |
