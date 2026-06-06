# RFC: Resolution diagnostics & observability (STUB)

Status: **stub** — triage grouping from the 2026-06-06 issue audit. Not yet designed.
Umbrella: (umbrella issue links here). Milestone: *v0.x — ergonomic CLI + manifest editing*.

## Problem

milpa's explicit errors are good, but resolution is otherwise a black box: a
`milpa fetch` prints only a final `resolved N deps` line, identity-gate
fall-throughs are silent, and first-time manifest mistakes surface as confusing
`nim` errors a layer downstream. These are all "make resolution legible" — group
them so the output story is consistent (cargo/npm-style per-dep feedback).

## Issues unified

- **#101 — per-dep resolution/fetch observability.** Emit one stderr line per
  resolved named dep (`fetching chronos 0.28.0 (git abc1234)`), including which
  version + provenance was chosen and whether S2.5's exact-commit fetch fell back
  to a full history fetch (the invisible 3s-vs-90s difference).
- **#102 — `fetch_any` identity-gate mismatch warning.** When a candidate's bytes
  fail the identity gate and `fetch_any` falls through to a mirror, emit a
  `warning:` naming the candidate + expected/actual hash — a mismatched *primary*
  is a possible supply-chain signal, not a silent success. (Surfaced in the #97
  review; now routine since #97 exercises multi-provenance `fetch_any`.)
- **#94 — manifest-setup UX.** Silent gaps that surface as downstream `nim`
  errors; "couldn't tell what state I was in." Make missing/half-configured state
  legible at the milpa layer (the `name`-missing error is the gold standard to
  replicate).

## Adjacent (already in v0.x — coordinate, don't duplicate)

- **#19 `milpa why <name>`**, **#20 `milpa outdated`**, **#21 `milpa doctor`** —
  the CLI diagnostic command trio. This RFC's output conventions should feed them
  (e.g. `doctor` reuses the #94 state checks; `why` reuses the resolution trace).

## Why one RFC

One output/diagnostics vocabulary: per-dep progress lines, warning conventions,
and state legibility checks that the standalone diagnostic commands (#19/#20/#21)
then consume. Defining them piecemeal yields inconsistent phrasing and duplicated
state-inspection logic.

## Open questions

- Default verbosity (always per-dep lines, or `-v`)? (the #101 deferred
  sub-question.)
- Is #94 a set of checks (shared with `doctor` #21) or inline fetch-time hints?

## Slices

TBD. #102 (the safety warning) is small and high-value; likely first.
