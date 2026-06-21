# rfc-conformance-parity — handoff

- **Stage:** 3 (tdd / implement slices)   •   **Round:** —
- **Resume:** `/loop implement the next unimplemented RFC slice from docs/rfc-conformance-parity.md with /tdd …` (PAUSED on a scope escalation — see Open forks)

Corpus state after Slice C "205": **BLACK-BOX HARNESS GREEN** (`HARNESS_EXIT=0`).
`python PASS=275 FAIL=0 (3 cert SKIP)`, `rust PASS=278 FAIL=0 SKIP=0`,
CROSS-IMPL DIVERGENCES = NONE (`/tmp/harness_after_205.txt`). The only remaining
parked items are 3 cert fixtures (127/128/150 = Python --certificate
unimplemented). Phase 1's primary exit criterion (harness green for both impls)
is MET; remaining = in-process adapter alignment (Slices 2/3) + the cert scope call.

## Slices
- [x] Slice 0 — baseline protocol (`f0fc3e7`).
- [x] Slice A — divergence detector flags pass/fail asymmetry (`e3f2c44`).
- [x] Slice B — runner honors `MILPA_CLI_FEATURES` family (`7c8ede6`); exposed Slice F.
- [x] Slice C c1/c2 — `<TARBALL-SHA256>` + local-dep symlink (`6e14648`); greened 181/182/183.
- [x] Slice C c3 — impl-neutral CAS seed for frozen (`81a1609`); greened 177/208/251.
- [x] Slice C c4 — partial-profile 255/256 deferred to KNOWN_LIMITATIONS (`94268da`);
      spec fork flagged (see Open forks).
- [x] Slice E — python ws flag-union -d: defines into member nim.cfg (`3854f8b`); greened 213/214/282.
- [ ] **Slice C "205"** — local-override transitive (py✗ rust✗, both-fail).
      Passes IN-PROCESS, fails black-box: `MockedLocalFetcher` (mocked.py:320)
      raises FETCH-MOCK-MISSING because it requires a `mocked-fetches/<url_key>/`
      entry, but the fixture supplies the override target as a REAL dir
      (`mylib-fork/`) in the fixture root. In-process resolves it directly (TBD how
      — trace local-override materialization in resolver vs CLI fetcher routing).
      Likely fix: MockedLocalFetcher falls back to reading the real path when
      `Path(p.path).is_dir()` and no mock entry exists. Verify the in-process path
      first to converge both. Needs care (don't rush). *(Python/impl.)*
- [x] Slice 1 — fixture-099 rust RES-PROVENANCE-CONFLICT (`f766d78`); closes #154.
- [x] Slice D — fixture-252 + 212 frozen active-flags-check ordering (`e59e6a1`).
- [x] Slice F — single-package fetch honors --features (`d238a5d`); greened
      209/210/211/216/228/230/244. **Divergences → NONE.**
- [x] Slice C "205" — local deps use real LocalFetcher in mock mode, both impls
      (`2578076`); removed dead MockedLocalFetcher (py) + its tests. **Black-box GREEN.**
- [ ] Slice 2 — fixture-144 in-process adapters (rust + python). Black-box already
      passes it; align the two in-process adapters to the CLI's
      MILPA_INDEX_URL→HttpDepDeclStore logic (RFC §4 Slice 2). *(Not a black-box failure.)*
- [ ] Slice 3 — `project-dir` control file (#167) — spec it + teach both in-process adapters.
- [ ] cert fixtures 127/128/150 — Python `--certificate` not implemented (parked in
      descriptors.py python_known_failing). Separate Python feature; decide if in-scope.
- [ ] Phase 2: S4a/S4/S5/S6/S7 (gated on differential-harness RFC).

NOTE: fixture-114's KNOWN_LIMITATIONS reason ("stdlib harness cannot compute the
identity hash") is now STALE — Slice C c3 proved impl-neutral seeding via the lock
identity works. Re-evaluate fixture-114 for un-quarantining (it tests
FROZEN-LEGACY-REGISTRY-PROVENANCE / #115; may need its own handling).

Rust batch (1/D/F) all need `./dev-rust` (container image
`ghcr.io/coreyleavitt/milpa-rust`); gate each via `./dev-rust test -p milpa-conformance`.

## Open forks (awaiting Corey)
- RESOLVED 2026-06-21: "fold everything here" — all findings are in-scope Phase-1
  parity work in THIS RFC (not routed to #172).

## Key decisions (this session)
- Committed round-2 RFC (`c0cb5df`); Slice 0 (`f0fc3e7`); Slice A (`e3f2c44`); Slice B.
- "Fold everything here": expanded Phase-1 slice list (A–F) recorded in RFC §4.
- Slice B revealed the Rust CLI `--features` gap (Slice F) — runner gap was masking it.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (stage 4 not started) | — | — |
