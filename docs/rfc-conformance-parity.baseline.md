# Conformance-parity baseline (Slice 0 record)

Status: **baseline artifact** for `rfc-conformance-parity.md` Phase 1, Slice 0.
Captured 2026-06-21. This file records *reality* (it is not a green run); later
slices cite it to legitimately claim "fixed a red."

## How this was produced

1. Rust release binary present: `impls/rust/target/release/milpa` (the black-box
   harness skips Rust without it).
2. Black-box differential runner: `python3 -m harness` → exit 1
   (`/tmp/harness_baseline.txt`). Summary line:
   - `python: PASS=256 FAIL=21 SKIP(known-failing)=3`
   - `rust:   PASS=260 FAIL=20 SKIP=0`
   - `Skipped (known limitations, all impls): 5`
   - `Cross-impl divergences: NONE` — **see Finding 1; this line is misleading.**
3. In-process Python suite: `cd impls/python && uv run pytest
   tests/test_conformance.py -q` → **green** (only `fixture-144` xfailed).
4. Python conformance declaration added (`[tool.milpa]` in `pyproject.toml`),
   satisfying spec §1.4 / RFC §3.5; covered by `tests/test_conformance_metadata.py`.

## Finding 1 — the harness divergence detector has a structural blind spot

`harness/corpus.py::_detect_divergences` only diffs impls that **both passed**
their individual check (`passed_results`, `len < 2 → []`). For any fixture that
carries an `expected/`, "passed" means "output == expected", so two passing impls
are both equal to `expected/` and **can never diverge** — and if one impl fails,
only one remains in `passed_results`, so the diff is skipped entirely.

Consequence: for the static corpus, **`Cross-impl divergences: NONE` is
structurally guaranteed** regardless of actual parity. The real cross-impl signal
is the *pass/fail asymmetry* per fixture, which `overall_passed()` folds into
per-impl FAIL counts. The textbook divergence — impl A matches the spec-blessed
`expected/`, impl B does not — is exactly what the detector cannot see.

This is a Phase-1 / D1 defect in the **enforcement mechanism for the invariant**,
not a per-fixture bug. It must be fixed for the parity invariant to be enforceable
at all (the RFC §1 invariant is currently un-checked for asymmetric fixtures).

## Finding 2 — genuine cross-impl divergences (parity violations)

Fixtures where one impl matches `expected/` and the other does not. These ARE
parity violations under §1; the harness reports them only as per-impl FAILs.

| fixture | python | rust | nature |
|---|---|---|---|
| `fixture-099-res-provenance-conflict` | PASS | FAIL | rust emits `FETCH-ALL-FAILED`, expects `RES-PROVENANCE-CONFLICT` (RFC **Slice 1**, root-caused) |
| `fixture-252-ws-frozen-flags-mismatch` | PASS | FAIL | rust emits `FROZEN-IDENTITY-NOT-IN-STORE`, expects `FROZEN-ACTIVE-FLAGS-MISMATCH` |
| `fixture-213-s11-workspace-wide-union` | FAIL | PASS | python member `nim.cfg` short by flag-union lines |
| `fixture-214-s11-workspace-root-flags` | FAIL | PASS | python member `nim.cfg` short by root-flag lines |
| `fixture-282-ws-cross-pkg-enable-fixpoint` | FAIL | PASS | python member `nim.cfg` short by cross-pkg-enable lines |

Only `fixture-099` is named in the RFC. `252` and `213/214/282` are **unanticipated
parity violations** — and `213/214/282` are a *Python* resolver gap (workspace
flag union into per-member `nim.cfg`) the RFC did not surface.

## Finding 3 — black-box harness ignores `MILPA_CLI_FEATURES` (both impls fail)

The in-process adapter (`test_conformance.py::_fixture_cli_features` /
`_fixture_no_default_features` / all-features) translates the fixture `env` keys
`MILPA_CLI_FEATURES` / `MILPA_NO_DEFAULT_FEATURES` / `MILPA_ALL_FEATURES` into the
`--features` / `--no-default-features` / `--all-features` resolver inputs. The
black-box runner (`harness/runner.py`) has **no such translation** — it sets them
as env vars the CLI never reads. So these fixtures pass in-process and fail
black-box *identically in both impls* (not a divergence; a runner-driver gap):

`209, 210, 211, 212, 216, 228, 230, 244, 249, 251` (10 fixtures).

This is the **same shape as RFC Slice 3 (`project-dir`)** — a declared fixture
control input the black-box runner does not honor — but a larger, unanticipated
class. The fix is unambiguous (teach `runner.py` to map these env keys to CLI
flags, mirroring the adapter), and is a new Phase-1 slice the RFC must enumerate.

## Finding 4 — other both-impls-fail fixtures (harness fixture-input gaps)

Both impls fail identically vs `expected/`; each is a harness normalization /
seeding gap, not a divergence:

| fixtures | gap |
|---|---|
| `182, 183` | `expected/milpa.lock` uses a `<TARBALL-SHA256>` placeholder the runner does not substitute before diffing |
| `181` | `_deps_structure.txt` expects `mylib -> (symlink)`; runner does not normalize a local-dep symlink target to `(symlink)` |
| `177, 208` | frozen fixtures expect a pre-seeded CAS (`FROZEN-IDENTITY-NOT-IN-STORE`); the black-box runner does not seed `cas-seed/` content the in-process path provides |
| `205` | local-override transitive: mocked-fetch has no entry for the override's temp path (path-keyed mock vs absolute temp dir) |
| `255, 256` | s4 partial-profile absent-axis: profile axis the black-box path sets differs from the adapter, so `archlib` is not filtered and a real fetch is attempted (#159/#160 territory) |

## Classification summary (Slice 0 step 4)

- **passes black-box, fails in-process:** none (in-process is green).
- **fails black-box, passes in-process — runner-driver gap:** Findings 3 + 4
  (the black-box runner does not reproduce a fixture control input the adapter
  honors: features env, `<TARBALL-SHA256>`, symlink normalization, CAS seeding,
  profile axes). The CLI itself is correct; the gap is in `harness/runner.py`.
- **genuine cross-impl divergence (impl bug at the resolver/CLI layer):**
  Finding 2 — `099` (rust), `252` (rust), `213/214/282` (python).
- **harness mechanism defect:** Finding 1 — the divergence detector cannot see
  asymmetric fixtures.

## Impact on the RFC

Phase 1's premise ("only `fixture-099` is red; everything else green") is
materially incomplete. The corrected Phase-1 work-list:

1. **Finding 1** — fix the divergence detector to flag pass/fail asymmetry (the
   invariant is otherwise unenforceable). *New, highest priority.*
2. **Slice 1** — `fixture-099` (rust), already root-caused.
3. **Finding 2 residual** — `252` (rust slug), `213/214/282` (python ws flag
   union). *New parity violations.*
4. **Finding 3** — teach the black-box runner to honor `MILPA_CLI_FEATURES`
   family (10 fixtures). *New runner slice, same shape as Slice 3.*
5. **Finding 4** — runner normalization/seeding gaps (`<TARBALL-SHA256>`,
   symlink, CAS seed, profile axes). *New runner slices.*
6. **Slice 2** — `fixture-144` adapters (in-process; unchanged).
7. **Slice 3** — `project-dir` (`fixture-288`; unchanged).
