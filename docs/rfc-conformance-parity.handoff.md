# rfc-conformance-parity — handoff

- **Stage:** 3 (tdd / implement slices)   •   **Round:** —
- **Resume:** `/loop implement the next unimplemented RFC slice from docs/rfc-conformance-parity.md with /tdd …` (PAUSED on a scope escalation — see Open forks)

Corpus state after Slice B: `python PASS=263 FAIL=14`, `rust PASS=261 FAIL=19`,
11 divergences (`/tmp/harness_after_B.txt`).

## Slices
- [x] Slice 0 — baseline protocol (`f0fc3e7`): `[tool.milpa]` + metadata test + baseline doc.
- [x] Slice A — divergence detector flags pass/fail asymmetry (`e3f2c44`).
- [x] Slice B — black-box runner honors `MILPA_CLI_FEATURES` family (this commit).
      Greened 7 python feature fixtures; exposed Slice F.
- [ ] Slice C — runner normalization/seeding: c1 `<TARBALL-SHA256>` (182/183),
      c2 symlink-normalize (181), c3 CAS seed for frozen (177/208/205),
      c4 profile-axis parity (255/256). *(Python/harness; do next.)*
- [ ] Slice E — python ws flag-union into member nim.cfg (213/214/282; py✗ rust✓). *(Python resolver.)*
- [ ] Slice 1 — fixture-099 rust (root-caused in RFC §4). *(Rust; needs container.)*
- [ ] Slice D — fixture-252 rust frozen-slug order. *(Rust.)*
- [ ] Slice F — Rust CLI honors `--features` (209/210/211/212/216/228; py✓ rust✗). *(Rust; NEW from Slice B.)*
- [ ] Slice 2 — fixture-144 in-process adapters (rust + python).
- [ ] Slice 3 — `project-dir` control file (#167).
- [ ] Phase 2: S4a/S4/S5/S6/S7 (gated on differential-harness RFC).

Remaining both-fail fixtures needing Slice C/other: 230/244 (when + features),
251 (ws-frozen-flag-filter + seed).

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
