# rfc-conformance-parity — handoff

- **Stage:** 3 (tdd / implement slices)   •   **Round:** —
- **Resume:** `/loop implement the next unimplemented RFC slice from docs/rfc-conformance-parity.md with /tdd …` (PAUSED on a scope escalation — see Open forks)

## Slices
- [x] Slice 0 — formal baseline protocol (commit `f0fc3e7`): `[tool.milpa]` +
      `tests/test_conformance_metadata.py` + `docs/rfc-conformance-parity.baseline.md`.
      Rust release binary present; black-box harness run + classified.
- [ ] Slice 1 — fixture-099 (rust), root-caused in RFC §4
- [ ] Slice 2 — fixture-144 in-process adapters (rust + python)
- [ ] Slice 3 — `project-dir` control file (#167)
- [ ] Phase 2: S4a/S4/S5/S6/S7 (gated on differential-harness RFC)
- [ ] **NEW (Slice 0 findings, not yet in RFC):** harness divergence-detector
      fix; `MILPA_CLI_FEATURES` runner wiring; runner normalization/seeding gaps;
      252 rust slug; 213/214/282 python ws flag-union.

## Open forks (awaiting Corey)
Slice 0 proved the RFC's Phase-1 premise ("only fixture-099 red") is wrong. See
`docs/rfc-conformance-parity.baseline.md`. Decision needed: how to fold the
expanded baseline into the RFC, and where the two impl-bug clusters belong
(here vs rfc-resolver-correctness). **Recommended:** fold harness/runner fixes
(Findings 1/3/4) into this RFC as Phase-1 slices; route resolver bugs
(213/214/282 python, 252 rust) to rfc-resolver-correctness (#172).

## Key decisions (this session)
- Committed round-2 RFC (`c0cb5df`).
- Slice 0 done; baseline recorded; loop paused for the scope escalation above.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (stage 4 not started) | — | — |
