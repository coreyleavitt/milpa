# RFC: Cross-impl conformance parity & corpus widening

Status: **design draft** — architect round 1 applied (2026-06-21). Was a triage
stub; round 1 gave it a spine (the parity invariant), corrected three misdiagnosed
issues, removed two that don't belong, and split finite cleanup from standing
discipline. One scope fork remains open (see §8).
Umbrella: #169. Milestone: *v1.5 — spec extraction + cross-impl hardening*.

## 1  The invariant

This RFC exists to establish and maintain one invariant:

> **Parity.** For every input in `conformance/spec-v<N>/`, every implementation
> that claims conformance to spec version `N` produces identical output on all
> **normative surfaces**, as determined by the differential corpus runner.

"Normative surfaces" is a precise, closed set (§2). Everything else — human-readable
diagnostic prose, log phrasing, progress lines — is explicitly **non-normative** and
MAY differ per impl by design (`spec/cli-contract.md §3.1`). A parity RFC that does
not pin down this normative/non-normative boundary will chase cosmetic differences
(this is exactly what sank the original #156 framing — see §6).

The RFC has three jobs, in order:
1. **Make the boundary normative and durable** — hoist the surface list into `spec/`
   (§2, deliverable D1).
2. **Restore the baseline** — close the finite set of current parity violations
   (Phase 1, §4).
3. **Widen coverage as a standing discipline** — every discovered divergence becomes
   a pinned fixture (Phase 2, §5).

## 2  Normative surfaces (deliverable D1)

The single most valuable artifact this RFC produces is a normative section — proposed
as a new **`spec/conformance-fixtures.md §5 — Normative surfaces`** (it sits naturally
above the existing §4 coverage floor) — stating, once and authoritatively:

**Parity-normative (byte-exact or canonical-equal across impls):**
- `expected/milpa.lock` — byte-exact (`spec/lockfile-schema.md`)
- `expected/nim.cfg` (or per-member `expected/<path>/nim.cfg`) — byte-exact, POSIX
  separators
- `expected/_deps_structure.txt` — byte-exact after `<CAS_ROOT>` substitution (§2.6)
- the error slug on the `milpa-error: <SLUG>` line (`spec/cli-contract.md §3.1`,
  R1–R4) — the sole normative error-identity surface
- `expected/certificate.json` — canonical JSON comparison (§2.7.3)

**Explicitly NON-normative (MAY differ per impl):**
- the human-readable diagnostic line(s) on stderr, including any prefix
  (Python `milpa:` vs Rust `<CODE>:`) — `cli-contract.md §3.1` says this "differs
  per impl by design"
- stdout prose for liveness commands (`show`, `--version`) — only exit-0 +
  non-empty is asserted (§2.7.2)
- ordering/timing of progress output

D1 also restates the **arbitration rule**: the spec is the arbiter. Impls agreeing is
*evidence*, not proof; impls disagreeing is a bug in one impl **or** a hole in the
spec — never resolved by "whatever the impls happen to do."

Once D1 lands, a third impl (the planned Nim dogfood) inherits an unambiguous
statement of what it must match and what it is free to vary.

## 3  Machinery (current state — verified 2026-06-21)

- **Static corpus differential runner — EXISTS.** `harness/` (`corpus.py`,
  `runner.py`, `assertions.py`, `descriptors.py`, `pin.py`, `spec.py`) runs all
  fixtures × all registered impls as black-box subprocesses and diffs normative
  outputs. Entry point: `python3 -m harness` from the repo root. `descriptors.py`
  registers `[python, rust]`; each carries a `known_failing` list. This is the
  enforcement gate for the invariant.
- **Generative layer (tier-1/tier-2 input generators) — DELETED, owned elsewhere.**
  The Hypothesis generator (`impls/python/tests/differential/strategies.py`,
  symbol `unsatisfiable_graph_st`) was removed in commit `5ae87ad` (clean-room
  swap); only `__pycache__` remains. `harness/spec.py` carries the `FixtureSpec`
  *serializer* but its generator is a documented TODO ("slice 3b: will generate
  FixtureSpec values"). **Generative coverage is owned by
  `docs/rfc-differential-conformance-harness.md`** (draft, round 2 applied — its
  §2c defines the tier-1/tier-2 generators and the saturation bar). This RFC depends
  on that runner; it does not re-implement generation.
- **In-process adapters — a divergence seam, not a normative gate.** `test_conformance.py`
  (pytest) and the Rust in-process runner are developer conveniences that call
  resolver APIs directly, bypassing CLI routing. Per `cli-contract.md §3.1 NOTE` the
  **black-box CLI path is the normative gate**. A fixture reachable only via an
  in-process adapter is a per-impl unit test, NOT a cross-impl conformance fixture
  (relevant to #167 and to `lock-roundtrip`/`workspace-manifest-roundtrip`, which
  today have no CLI surface and are never cross-impl compared).

## 4  Phase 1 — baseline restoration (finite)

Exit criterion: `python3 -m harness` is green for both impls with empty
`known_failing` lists for the fixtures below, and each fix is pinned as a fixture.

### Slice 0 — formal baseline protocol (blocks everything)

Not an informal re-run. Produce a checked-in baseline record by:
1. Running the black-box harness against both impls (`python3 -m harness`).
2. Running the Rust in-process suite (`./dev-rust test -p milpa-conformance`, inside
   the pinned container — requires podman/docker + the
   `ghcr.io/coreyleavitt/milpa-rust` image; verify pullable first).
3. Diffing in-process vs black-box per impl: any fixture that passes in-process but
   fails black-box (or vice versa) is an **adapter/runner gap**, not an impl bug —
   classify it as such, do not "fix" it as a parity violation.
4. Recording the result as a versioned text artifact in the repo so later slices can
   legitimately claim to "fix a red."

### Slice 1 — fixture-099 (#154), Rust-only red

Python passes; Rust emits `FETCH-ALL-FAILED` where the corpus expects
`RES-PROVENANCE-CONFLICT`. The Rust provenance gate **is** implemented and unit-tested
— so "not wired" is the wrong diagnosis. **Candidate root cause (round-1 trace, to
confirm at fix time):** `edgeset_to_extracted` deduplicates URL requires by *derived
dep name* before enqueueing, so two requires with different URLs that strip to the
same name collapse to one `Item::Url`; the gate never sees both provenances and cannot
raise the conflict. Fix direction: enqueue both URL items and let the gate handle
same-name suppression/conflict — not "add a missing code path."

### Slice 2 — fixture-144 (#153), a fixture authoring error (BOTH impls)

Both impls emit `RES-UNATTESTED-METADATA`; the corpus expects
`TNG-DEPDECL-FETCH-FAILED`. This is **not** an impl bug and **not** "Python pending a
resolver slice." **Verified 2026-06-21:** the fixture directory has *no* `dep-decl/`
subdirectory, so the harness never sets `MILPA_DEP_DECL_DIR` (§2.11), `FileDepDeclStore`
never activates, resolution falls through to the nimble path, and the attestation
policy raises `RES-UNATTESTED-METADATA`. The code path that raises
`TNG-DEPDECL-FETCH-FAILED` requires `MILPA_DEP_DECL_DIR` set to a dir lacking the
artifact. **Fix the fixture** (add the `dep-decl/` directory per `§2.11` / the §4
coverage-floor note), not the impls. Then remove `fixture-144` from Python's
`_NOT_YET_WIRED_FIXTURE_NAMES` and Rust's `known_failing.txt` together (a strict
xfail→pass transition).

### Slice 3 — `project-dir` control file: spec-first (#167)

`project-dir` is used by `fixture-288` but appears **nowhere in `spec/`** (verified).
It is an unspecced control file the CLI harness honors and the in-process adapters
ignore — a two-tier corpus. Fix order: (1) add `project-dir` to
`spec/conformance-fixtures.md` as a normative control input (semantics: the project
root is `<fixture-root>/<value>`, i.e. the dir passed as `-C` to the impl); (2) teach
both in-process adapters to honor it. Per §3, fixtures that remain reachable only via
an adapter are not cross-impl fixtures.

## 5  Phase 2 — corpus coverage discipline (ongoing)

Governed by the saturation bar in `rfc-differential-conformance-harness.md`
(every normative MUST-clause maps to ≥1 fixture; a tier-2 generator run produces no
new divergence). This RFC contributes the **promotion workflow** and the specific
hand-authored fixtures below.

**Promotion workflow (the violation→fixture loop).** When Python≠Rust (found by the
harness, the generator, or by hand):
1. Read the spec to determine the correct behavior (spec is arbiter). If the spec is
   silent, file a spec-sharpening issue and **defer** the fixture until resolved.
2. Shrink the input to minimal form.
3. Emit a candidate via `harness/pin.py` (writes a fixture dir *without* `expected/`
   plus `divergence.json`).
4. **Human-bless `expected/`** from the spec-correct impl's output (lockfile: against
   the canonical sort; nim.cfg: against `lockfile-schema.md`; slug: against
   `errors.md`).
5. Merge into `conformance/spec-v1/`; remove any `known_failing` parking.

**Policy (recommended, see §8):** every fix in this RFC MUST land as a pinned corpus
fixture, not merely a `known_failing` edit or an in-process unit test. A fix without a
pinned fixture leaves every future impl (Nim) unguarded against the same regression.

**Hand-authored fixtures:**
- **#148 — adversarial corrupt tar archives** (mid-archive bad checksum; GNU base-256
  checksum). Ship a *pre-built* corrupt archive in `mocked-fetches/` (no `format`
  file ⇒ pre-built mode); both impls must surface the same terminal slug. Note: the
  inner extract/fetch codes are fetch-wrapped to `FETCH-ALL-FAILED` at the black-box
  boundary (§7), so the fixture asserts the wrapper slug, not the inner code.
- **#146 — tarball bz2-identity + mixed-case sha256.** Reframed: this is a
  **success-path byte-equality** gap (does each impl extract+hash a bz2 archive to
  the same `content_hash`?), not an error-code-floor gap. The "encoder determinism"
  blocker only applies to *build-mode* fixtures; authoring a **pre-built** bz2 archive
  with a fixed `archive_sha256` sidesteps it entirely. Prefer pre-built mode unless
  the suite must also prove the impls can *build* bz2 (a separate concern).
- **#166 — workspace + dev-deps resolve fixture.** Pure addition; the workspace
  resolver already seeds member dev-deps. Confirm `fixture-064-dev-deps` (single-pkg)
  and the workspace baseline are green first.
- **#135 — `milpa show` surfacing cond_requires.** `show` output is non-frozen in
  spec v1.0 (§2.7.2), so this is a **liveness** fixture (exit-0 + non-empty stdout),
  not a byte-compare. Byte-comparing `show` output would require first freezing its
  format — out of scope here; file separately if wanted.

## 6  Removed from scope (round 1)

- **#156 — human stderr prefix differs.** *Not a conformance issue.*
  `cli-contract.md §3.1` makes the human diagnostic line non-normative by design and
  the normative `milpa-error: <SLUG>` line is already byte-identical across impls (all
  error fixtures pass). Standardizing the human prefix would *amend a deliberate
  design decision* for zero conformance value. If UX consistency is still wanted, it
  is a cosmetic concern for the diagnostics RFC (#106), not parity. Recommend closing
  #156 as "non-normative by design."
- **#124 — widen tier-2 unsatisfiable generator diversity.** Belongs to
  `rfc-differential-conformance-harness.md` (it owns tier-1/tier-2 generators), and
  as written it references deleted code (`unsatisfiable_graph_st`, removed in
  `5ae87ad`). Move the issue under the differential-harness umbrella; it is blocked on
  re-landing the generator there.

## 7  Known blind spot — wrapping boundaries

`conformance-fixtures.md §4` lists ~30 codes as "structurally unreachable" because
they are wrapped at a boundary (fetcher inner codes → `FETCH-ALL-FAILED`; identity
codes → `LOCK-DEP-IDENTITY-INVALID`). Two impls can wrap **differently** and still
agree on the observable wrapper slug — a divergence the corpus cannot catch by
construction. Mitigations this RFC adopts:
- The inner-code→wrapper *mapping* MUST be unit-tested within each impl (not only at
  the black-box boundary).
- Changing a wrapping boundary is a **spec-level event** (it can make a
  previously-unreachable code observable); whoever changes it must add the
  now-reachable fixture.

## 8  Open fork (awaiting Corey)

**Scope boundary vs `rfc-differential-conformance-harness.md`.** With #124 moved out,
the remaining work cleanly bifurcates. Three framings:
- **(a) one RFC, two phases (recommended):** Phase 1 baseline restoration + Phase 2
  coverage discipline live here; generation is a declared dependency on the
  differential-harness RFC. Keeps the parity *discipline* in one place.
- **(b) narrow this RFC to baseline + D1 only:** keep #154, #153, #167 and the
  normative-surfaces spec section here; move all corpus-widening (#146, #148, #166,
  #135) to the differential-harness RFC, which already owns generative coverage.
  Cleaner ownership; more cross-RFC coordination.
- **(c) three-way split** by kind (bug-fix / widening / spec-amendment). Maximal
  separation; likely over-fragmented.

Recommendation: **(a)**. The bug fixes are the motivating examples of the discipline
the RFC defines, and keeping them together preserves a single coherent done-state.
