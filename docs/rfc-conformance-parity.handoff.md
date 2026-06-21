# rfc-conformance-parity — handoff

- **Stage:** 3 (tdd / implement slices)   •   **Round:** —
- **Resume:** `/loop implement the next unimplemented RFC slice from docs/rfc-conformance-parity.md with /tdd …` (PAUSED on a scope escalation — see Open forks)

Corpus state after Slice C c1/c2/c3: `python PASS=271 FAIL=6 (3 cert SKIP)`,
`rust PASS=267 FAIL=13`, 13 divergences (`/tmp/harness_after_C3fix.txt`).
Python real failures (6): 205, 213, 214, 255, 256, 282.

## Slices
- [x] Slice 0 — baseline protocol (`f0fc3e7`).
- [x] Slice A — divergence detector flags pass/fail asymmetry (`e3f2c44`).
- [x] Slice B — runner honors `MILPA_CLI_FEATURES` family (`7c8ede6`); exposed Slice F.
- [x] Slice C c1/c2 — `<TARBALL-SHA256>` + local-dep symlink (`6e14648`); greened 181/182/183.
- [x] Slice C c3 — impl-neutral CAS seed for frozen (`81a1609`); greened 177/208/251.
- [~] Slice C c4 — partial-profile absent-axis (255/256). **BLOCKED on a spec fork
      (#159/#160/#110)**: CLI `Profile.from_environment()` host-defaults absent axes
      (correct per cli-contract §8), but the fixtures need partial semantics
      (absent axis → None). Not a harness fix. See Open forks.
- [ ] Slice C "205" — local-override transitive: mocked-fetches keyed by the
      non-reproducible runtime temp path (`/tmp/.../mylib-fork`); fixture/mock
      path-keying issue. Needs investigation (harness vs fixture).
- [ ] Slice E — python ws flag-union into member nim.cfg (213/214/282; py✗ rust✓). *(Python resolver; clean, do next.)*
- [ ] Slice 1 — fixture-099 rust (root-caused in RFC §4). *(Rust; needs container.)*
- [ ] Slice D — fixture-252 rust frozen-slug order. *(Rust.)*
- [ ] Slice F — Rust CLI honors `--features` (209/210/211/212/216/228/230/244; py✓ rust✗). *(Rust.)*
- [ ] Slice 2 — fixture-144 in-process adapters (rust + python).
- [ ] Slice 3 — `project-dir` control file (#167).
- [ ] Phase 2: S4a/S4/S5/S6/S7 (gated on differential-harness RFC).

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
