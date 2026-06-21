# RFC: Cross-impl conformance parity & corpus widening

Status: **design draft** — architect round 2 applied (2026-06-21). Round 1 gave the
stub a spine (the parity invariant), corrected three misdiagnosed issues, removed two
that don't belong, and split finite cleanup from standing discipline. Round 2
**reversed the round-1 fixture-144 diagnosis** (it passes the normative black-box gate
— the divergence is an in-process adapter bug, verified empirically), closed the
normative-surface set (exit code, empty-stdout, `expected/absent`), corrected the D1
landing point (the proposed `§5` already exists), named the CI enforcement gap, added
the new-impl onboarding + multi-epoch protocol, and re-sliced Phase 2. Scope is
option (a) — one RFC, two phases (§8).
Umbrella: #169. Milestone: *v1.5 — spec extraction + cross-impl hardening*.

## 1  The invariant

This RFC exists to establish and maintain one invariant:

> **Parity.** For every input in `conformance/spec-v<N>/`, every implementation
> that **claims conformance to spec version `N`** produces identical output on all
> **normative surfaces**, as determined by the differential corpus runner.

Two qualifiers carry weight:

- **"Normative surfaces"** is a precise, closed set (§2). Everything else —
  human-readable diagnostic prose, log phrasing, progress lines — is explicitly
  **non-normative** and MAY differ per impl by design (`spec/cli-contract.md §3.1`). A
  parity RFC that does not pin down this boundary will chase cosmetic differences
  (this is exactly what sank the original #156 framing — see §6).
- **"that claims conformance to spec version `N`"** is the *epoch filter* (§3.4). The
  corpus is versioned (`spec-v1/`, future `spec-v2/`); an impl is only held to the
  epochs it declares. The runner MUST run an impl against exactly its declared epochs,
  never all discovered ones — otherwise a v2 impl that intentionally breaks a v1
  behavior is falsely flagged. This is currently unimplemented (§3.4).

The RFC has three jobs, in order:
1. **Make the boundary normative and durable** — declare the surface set as a single
   machine-readable source of truth and hoist its prose into `spec/` (§2, deliverable D1).
2. **Restore the baseline** — close the finite set of current parity violations
   (Phase 1, §4).
3. **Widen coverage as a standing discipline** — every discovered divergence becomes
   a pinned fixture (Phase 2, §5).

## 2  Normative surfaces (deliverable D1)

The single most valuable artifact this RFC produces is an authoritative, **closed**
statement of what impls must match — expressed once, in *two coupled forms* that
cannot drift:

**(D1-a) Machine-readable source of truth — `harness/surfaces.py`.** A small module
the runner imports, declaring the comparison set per command class:

```python
NORMATIVE_FILES = {            # byte-exact (or canonical-equal) per command class
    "success": ["milpa.lock", "nim.cfg", "_deps_structure.txt"],  # + per-member nim.cfg
    "check-certificate": ["certificate.json"],   # canonical-JSON comparison (see below)
    "error": [],                                  # slug only; no file diff
}
LIVENESS_CMDS = {"show", "--version"}  # assert exit-0 + non-empty stdout only
EMPTY_STDOUT_VERBS = {"fetch", "lock", "verify", "clean", "add", "remove", "update"}
NORMATIVE_EXIT_CODES = {0, 1, 2}       # cli-contract §3; the *code* is compared, not just 0/≠0
ABSENT_PATHS_SURFACE = "expected/absent"  # listed paths MUST NOT exist post-run
```

`assertions.py` derives its comparison logic from this module; nothing in the runner
re-states the set inline. (Today `assertions.py` hard-codes it — collapsing the two is
the first task of D1.)

**(D1-b) Spec prose.** Strengthen the existing **"Normative surface" summary block**
near the top of `spec/conformance-fixtures.md` (it already names the MUST outputs) so
it formally enumerates the normative/non-normative split and cites
`cli-contract.md §3.1`. **Do NOT create a new `§5`** — `conformance-fixtures.md §5`
already exists ("Black-box diff semantics", the *protocol* for running the check);
D1 declares *what* is compared, which belongs in the top-of-doc normative block, not
buried after §4's coverage-floor appendix. At stabilization, a lint test asserts the
prose enumeration and `harness/surfaces.py` agree.

### The closed surface set

**Parity-normative (byte-exact or canonical-equal across impls):**
- `expected/milpa.lock` — byte-exact (`spec/lockfile-schema.md`)
- `expected/nim.cfg` (or per-member `expected/<path>/nim.cfg`) — byte-exact, POSIX
  separators
- `expected/_deps_structure.txt` — byte-exact after `<CAS_ROOT>` substitution
- the error slug on the `milpa-error: <SLUG>` line (`spec/cli-contract.md §3.1`,
  R1–R4) — the sole normative error-identity surface
- `expected/certificate.json` — **canonical JSON comparison.** *The canonicalization
  is not yet defined anywhere* (round-2 gap). D1 MUST specify it (proposed: RFC 8785
  JCS — sorted keys, no insignificant whitespace, fixed number formatting) or the
  "canonical-equal" claim is hand-waved.
- **process exit code** — the exact code (0/1/2 per `cli-contract.md §3`), not merely
  zero-vs-nonzero. An impl exiting 2 where another exits 1 is a divergence today
  invisible to the corpus.
- **empty stdout on success** for the non-liveness verbs (`cli-contract.md §4`
  NORMATIVE). The harness does not assert this today; D1 makes it normative and the
  runner enforces `stdout == ""` for `EMPTY_STDOUT_VERBS`.
- **`expected/absent`** — paths that MUST NOT exist after the run (harness-enforced
  today, e.g. S11e member-local `milpa.lock`; spec-invisible). D1 documents it.

**Explicitly NON-normative (MAY differ per impl):**
- the human-readable diagnostic line(s) on stderr, including any prefix
  (Python `milpa:` vs Rust `<CODE>:`) — `cli-contract.md §3.1` says this "differs
  per impl by design"
- stdout prose for liveness commands (`show`, `--version`) — only exit-0 +
  non-empty is asserted
- ordering/timing of progress output

D1 also restates the **arbitration rule**: the spec is the arbiter. Impls agreeing is
*evidence*, not proof; impls disagreeing is a bug in one impl **or** a hole in the
spec — never resolved by "whatever the impls happen to do."

**Platform scope (round-2 addition).** The corpus is **Linux/POSIX for spec v1** —
state this explicitly. Windows support would require additional normalization rules
the corpus does not yet carry: path-separator normalization inside
`_deps_structure.txt`, case-collision handling for `mocked-fetches/<url-key>/` and
`cas-seed/` on case-insensitive filesystems, and CRLF/LF normalization (git
`autocrlf`) for the single-line control files (`error`, `cmd`, `env`, `sha`). Enumerate
these as the v2-platform checklist; do not silently assume cross-platform parity.

Once D1 lands, a third impl (the planned Nim dogfood) inherits an unambiguous,
machine-checkable statement of what it must match and what it is free to vary.

## 3  Machinery (current state — verified 2026-06-21)

- **Static corpus differential runner — EXISTS.** `harness/` (`corpus.py`,
  `runner.py`, `assertions.py`, `descriptors.py`, `pin.py`, `spec.py`) runs all
  fixtures × all registered impls as black-box subprocesses and diffs normative
  outputs. Entry point: `python3 -m harness` from the repo root. `descriptors.py`
  registers `[python, rust]`; each carries a `known_failing` set. The Rust descriptor
  needs `impls/rust/target/release/milpa` (a *release* binary). This runner is the
  enforcement gate for the invariant.
- **Generative layer (tier-1/tier-2 input generators) — DELETED, owned elsewhere.**
  The Hypothesis generator (`impls/python/tests/differential/strategies.py`,
  symbol `unsatisfiable_graph_st`) was removed in commit `5ae87ad` (clean-room
  swap); only `__pycache__` remains. `harness/spec.py` carries the `FixtureSpec`
  *serializer* but its generator is a documented TODO. **Generative coverage is owned
  by `docs/rfc-differential-conformance-harness.md`** (draft, round 2 applied — its
  §2c defines the tier-1/tier-2 generators and the saturation bar). This RFC depends
  on that runner; it does not re-implement generation.
- **In-process adapters — a divergence seam, not a normative gate.** `test_conformance.py`
  (pytest) and the Rust in-process runner (`milpa-conformance/src/runner.rs`) call
  resolver APIs directly, bypassing CLI routing. Per `cli-contract.md §3.1 NOTE` the
  **black-box CLI path is the normative gate**. A fixture reachable only via an
  in-process adapter is a per-impl unit test, NOT a cross-impl conformance fixture
  (relevant to #167 and to `lock-roundtrip`/`workspace-manifest-roundtrip`, which
  have no CLI surface and are never cross-impl compared).
  - **Long-term disposition (round-2 decision — Option A):** the two in-process
    adapters are **permanent fast inner-loop dev tools**, not phased out. They are
    never normative. This matches the repo's testing philosophy (fast unit feedback +
    a separate cross-impl gate). The corollary (newly enforced below): **an in-process
    adapter that produces a *different normative output* than its own CLI is itself a
    bug** — the adapter must mirror the CLI's env/configuration logic, not a simplified
    proxy of it. fixture-144 (§4 Slice 2) is exactly this bug.

### 3.4  Multi-epoch handling (round-2 gap — currently unimplemented)

The invariant is scoped to "the spec version an impl claims." The runner does not honor
this: `corpus.py::_discover_fixtures()` discovers **every** `spec-v<N>/` directory and
runs all of them against all impls; `known_failing` is a flat basename set with no
version dimension. When `spec-v2/` exists, a v2-only impl that intentionally changes a
v1 behavior will be flagged as a parity violation, and `_all_fixture_names()` would
wrongly enrol every v1 fixture as "known failing" (those are *intentional
non-conformance*, not regressions).

D1 specifies the mechanism (build now is deferred per
[[spec_versioning_deferred]] — there is no v2 yet — but the design is fixed so a future
bump cannot be dodged by an ad-hoc workaround):
- Each impl declares its conformed epoch set in its conformance metadata
  (`spec-version`, see §3.5).
- The runner filters discovered fixtures to the intersection of (declared epochs) ×
  (discovered corpus epochs) per impl. An impl is held to **exactly** its declared
  epochs.
- Parity is compared **only among impls that share a declared epoch**, on that epoch's
  corpus. Two impls on disjoint epochs are never diffed.

### 3.5  New-impl onboarding protocol (round-2 gap — the Nim dogfood gate)

D1's entire justification is the *third* impl, yet nothing today specifies how one
registers. Make this normative:
- **Conformance declaration (`spec/conformance-fixtures.md §1.4` NORMATIVE).** Each
  impl declares `spec-version`, `corpus`, and `known-failing` in its project metadata.
  Rust has it (`crates/milpa-conformance/Cargo.toml [package.metadata.milpa]`);
  **Python is missing `[tool.milpa]` in `pyproject.toml`** — add it (§4 Slice 0).
  The Nim impl declares the equivalent in its build manifest.
- **Harness registration.** A new impl adds an `ImplDescriptor` to
  `descriptors.py::build_descriptors()`. Required fields: binary path convention,
  `invoke_via` (`Subprocess` today; `Container` is a documented extension point that
  currently raises `NotImplementedError` — onboarding a containerized impl must
  implement it).
- **Partial-conformance onboarding.** A new impl starts with
  `known_failing = _all_fixture_names(corpus)` (the existing helper) and greens
  fixtures incrementally. "Registered but partial" (non-empty `known_failing`) is a
  legitimate merged state; "conformant" means empty `known_failing` for its declared
  epochs. The onboarding gate is therefore *registration*, not *full green*.

### 3.6  Enforcement status — the CI gap (round-2 finding; name it, don't hide it)

The invariant's enforcement gate (`python3 -m harness`) is **not run in CI today**.
`.github/workflows/ci.yaml` runs `uv run pytest` (Python in-process) and
`./dev-rust test --workspace` (Rust in-process) — both *in-process adapters*, never the
black-box differential runner. The Rust CI job builds debug, not the
`target/release/milpa` the harness needs; `harness/test_coverage.py` (the coverage-floor
enforcer) is outside `impls/python/tests/` and so is also never run in CI. **An
invariant nobody enforces automatically is aspirational.**

A full CI redesign (matrix + differential harness) is deliberately deferred (a large
rewrite is pending; see [[feedback_commit_cadence_ci_defer]]). Until then this RFC
adopts a **transitional enforcement protocol**:
1. A documented pre-merge step: contributors run `./dev-rust build --release` then
   `python3 -m harness` locally and confirm green before merging corpus/resolver
   changes.
2. A non-blocking CI job that runs the harness (best-effort; may skip if the release
   binary is unavailable) so divergence is at least *visible* on PRs.
3. The coverage-floor test (`harness/test_coverage.py`) is added to the same job.

This is a stopgap, explicitly named so the deferral is a decision, not an omission.

## 4  Phase 1 — baseline restoration (finite)

Exit criterion: `python3 -m harness` is green for both impls **and** every impl's
`known_failing` set is empty for the fixtures below, with each fix pinned as a fixture.
Note (round-2): `overall_passed()` checks only `failed == 0 and divergences == 0` — it
does **not** assert `known_failing` is empty. Either add that assertion (preferred:
a `--require-empty-known-failing` harness mode) or treat "zero SKIP(known-failing)
lines" as a manually-checked criterion. State which; do not leave it implicit.

### Slice 0 — formal baseline protocol (blocks Slices 1–2; see §4 note on Slice 3)

Not an informal re-run. Produce a checked-in baseline record by:
1. Building the Rust release binary (`./dev-rust build --release`) so the black-box
   harness can invoke it (the harness skips Rust otherwise).
2. Running the black-box harness against both impls (`python3 -m harness`). **This run
   will exit nonzero** (fixture-099 is Rust-red today; see Slice 1). The *failing
   output is the baseline artifact* — Slice 0 records reality, it does not produce a
   green run.
3. Running each in-process suite (`uv run pytest`; `./dev-rust test -p milpa-conformance`
   inside the pinned container — image `ghcr.io/coreyleavitt/milpa-rust`, verified
   locally pullable).
4. **Diffing in-process vs black-box per impl and classifying each mismatch:**
   - passes black-box, fails in-process → **in-process adapter gap** (the adapter
     diverges from the CLI). Fix the adapter. *fixture-144 is this case (Slice 2).*
   - fails black-box, passes in-process → **either** an adapter gap (the adapter
     bypasses a layer the CLI exercises) **or** a CLI-wiring bug (library correct, CLI
     misroutes). The latter **is** an impl bug at the CLI layer — do not auto-classify
     this direction as "adapter gap, don't fix." Decide by checking whether the CLI
     exercises a code path the adapter skips.
   - fails both → impl bug or fixture error (diagnose per case).
5. Adding `[tool.milpa]` to `impls/python/pyproject.toml` (§3.5) so Python satisfies
   the §1.4 NORMATIVE conformance declaration.
6. Recording the result as a versioned text artifact in the repo so later slices can
   legitimately claim to "fix a red."

### Slice 0 findings — folded Phase-1 work (2026-06-21, "fold everything here")

Slice 0's recorded baseline (`docs/rfc-conformance-parity.baseline.md`) proved the
"only fixture-099 is red" premise wrong. The findings are folded into Phase 1 as
the slices below (Corey decision 2026-06-21). Ordering is dependency-driven: the
divergence-detector fix (Slice A) comes first because the invariant is otherwise
unenforceable; the fast Python runner/harness slices precede the container-gated
Rust work.

- **Slice A — fix the harness divergence detector (Finding 1).**
  `harness/corpus.py::_detect_divergences` only diffs impls that **both passed**,
  so for any `expected/`-bearing fixture two passers are both equal to `expected/`
  (never divergent) and an asymmetric fixture (one passes, one fails) is skipped
  (`len < 2`). Result: `Cross-impl divergences: NONE` is structurally vacuous for
  the static corpus. Fix: a divergence is **any normative-surface disagreement
  across impls that both produced an output**, OR a pass/fail asymmetry vs
  `expected/`. RED = a harness unit test asserting that an asymmetric fixture is
  reported as a divergence; GREEN = detector flags 099/252/213/214/282.
- **Slice B — black-box runner honors the `MILPA_CLI_FEATURES` family
  (Finding 3).** Teach `harness/runner.py` to translate the fixture `env` keys
  `MILPA_CLI_FEATURES` / `MILPA_NO_DEFAULT_FEATURES` / `MILPA_ALL_FEATURES` into
  `--features` / `--no-default-features` / `--all-features` argv (mirroring the
  in-process adapter), so these are CLI inputs, not ignored env. Greens 10
  fixtures (209/210/211/212/216/228/230/244/249/251).
- **Slice C — black-box runner normalization/seeding (Finding 4).** Per-gap:
  (c1) substitute the `<TARBALL-SHA256>` placeholder before diffing (182/183);
  (c2) normalize a local-dep symlink target to `(symlink)` in
  `_deps_structure.txt` (181); (c3) seed `cas-seed/` content for frozen fixtures
  so `FROZEN-IDENTITY-NOT-IN-STORE` does not spuriously fire (177/208/205);
  (c4) profile-axis parity for partial-profile absent-axis fixtures (255/256;
  coordinates with #159/#160). Each c-gap is independently testable; split as
  needed during /tdd.
  - **c4 resolution (2026-06-21): DEFERRED to a known-limitation.** The CLI builds
    its Profile via `from_environment()`, host-defaulting every absent axis
    (`cli-contract §8`), so a partial profile (e.g. PLATFORM set, ARCH absent →
    None) is not expressible via the CLI on *either* impl — both produce a
    host-defaulted resolution, so 255/256 fail black-box symmetrically (not a
    divergence). The partial-profile resolver behavior is covered in-process.
    255/256 are marked `KNOWN_LIMITATIONS` pending an open spec decision:
    **should the CLI express an explicitly-absent axis** (#159/#160 Profile
    optional axes) — which interacts with **#110 universal cross-platform
    resolution**? **Open fork for Corey** (lean: change `cli-contract §8` so a
    *partially*-specified `MILPA_TARGET_*` leaves unset axes `None` instead of
    host-defaulting — host-defaulting a build-host arch while targeting another
    platform is arguably a bug — but this is a cross-impl spec change tied to #110
    governance, so it is escalated rather than made unilaterally).
- **Slice D — fixture-252 rust frozen-slug (Finding 2).** Rust emits
  `FROZEN-IDENTITY-NOT-IN-STORE` where the corpus expects
  `FROZEN-ACTIVE-FLAGS-MISMATCH`: the active-flags check must run before the
  in-store check on the frozen workspace path. Rust-only; gate via
  `./dev-rust test -p milpa-conformance`.
- **Slice E — python workspace flag-union into member `nim.cfg` (Finding 2).**
  213/214/282: Python emits member `nim.cfg` short by the workspace-wide /
  root-flag / cross-pkg-enable lines Rust includes. Python resolver gap; gate via
  `cd impls/python && uv run pytest`.

Note (Slices B/C): once the runner honors these inputs, the corresponding
fixtures may surface *new* cross-impl divergences (previously masked by both
impls failing identically). Re-run the harness after each and treat any residual
asymmetry per Slice A.

- **Slice F — Rust CLI honors `--features` family (exposed by Slice B).** After
  Slice B fed both impls `--features` on the black-box path, 209/210/211/212/216/228
  flipped from both-fail to **python✓ / rust✗** divergences: the Rust CLI does not
  apply the feature-selection flags the way Python does (the runner is
  impl-agnostic, so both receive identical argv). Rust-only resolver/CLI fix;
  gate via `./dev-rust test -p milpa-conformance`. This is a substantive new
  finding — the feature fixtures' black-box reds were a runner gap *masking* a
  Rust CLI gap, not a pure runner gap.

### Slice 1 — fixture-099 (#154), Rust-only red

Python passes; Rust emits `FETCH-ALL-FAILED` where the corpus expects
`RES-PROVENANCE-CONFLICT`. The Rust provenance gate **is** implemented and unit-tested
— "not wired" is the wrong diagnosis. **Root cause (verified in source, round 2):**
`edgeset_to_extracted` (`impls/rust/crates/milpa-core/src/resolver.rs`, ~L2717–2731)
deduplicates URL requires by *derived dep name* (`seen_dep_names`) **before** creating
`Item::Url`, so two requires with different URLs that strip to the same name
(`sharedlib` from both `…/example/sharedlib.git` and `…/other/sharedlib.git`) collapse
to one item; the gate never sees both provenances and cannot raise the conflict.
Python's BFS checks the provenance gate *before* its URL-key dedup, so it sees both.

**Fix direction (confirmed safe):** remove the `seen_dep_names` guard for
`RequireEntry::Url`; enqueue both items and let `gate()` handle it —
`prior_key == pkey` → `Gate::Suppress` (legitimate same-provenance duplicate),
different pkey → `Gate::Conflict`. The gate already distinguishes these, so dedup is
not lost.
- **Second bug site (round-2 finding):** `edgeset_to_terms`
  (`edge_sources.rs` ~L440–445) carries the *same* `seen_dep_names` dedup. It is only
  called from `edge_sources.rs` tests today (not the transitive path), so it does not
  cause the current violation — but it is a latent copy. Patch both sites, or add a
  `// INVARIANT: only safe when a gate is downstream` comment to `edgeset_to_terms`.
- **/tdd gate (round-2 finding):** this is a **Rust-only** fix. The standard
  `cd impls/python && uv run pytest` gate is always green here and would mask the red.
  Drive this slice with: RED = `./dev-rust test -p milpa-conformance` fails on
  fixture-099; GREEN = it passes **and** `fixture-099` is removed from
  `known_failing.txt` (which uses the `spec-v1/fixture-099-…` prefixed form).

### Slice 2 — fixture-144 (#153): an IN-PROCESS ADAPTER bug (round-2 reversal)

**The round-1 diagnosis ("fixture authoring error — add a `dep-decl/` dir") was wrong.
Do not add a `dep-decl/` directory.** Empirically verified 2026-06-21:

- **Black-box CLI — already correct.** With `index.kdl` present the harness sets
  `MILPA_INDEX_URL=file://…/index.kdl` and (no `dep-decl/`) leaves `MILPA_DEP_DECL_DIR`
  unset. The CLI's `_build_dep_decl_store` then takes case 3 → `HttpDepDeclStore` over
  the `file://` index base → looks up the missing
  `dep-decl/8345eab….kdl` → raises `TNG-DEPDECL-FETCH-FAILED`; strict mode
  (`MILPA_REQUIRE_ATTESTED_METADATA=1`) re-raises. Confirmed by running the Python CLI
  directly: `milpa-error: TNG-DEPDECL-FETCH-FAILED`, exit 1 — **matches
  `expected/error`.** fixture-144 **passes the normative gate.**
- **In-process adapters — diverge.** Both the Rust in-process runner
  (`runner.rs` ~L554–558: `if dep_decl_dir.is_dir() { … } else { None }`) and the
  Python `test_conformance.py` gate the `dep_decl_store` on the **physical presence of
  a `dep-decl/` directory** rather than on the `MILPA_INDEX_URL`→`HttpDepDeclStore`
  logic the CLI uses. With no dir, the store is `None`, resolution falls through to
  nimble, and the attestation policy raises `RES-UNATTESTED-METADATA` — a mismatch the
  adapters park in their `known_failing` lists.

**Fix:** make the in-process adapters mirror the CLI — when `dep-decl/` is absent but
an index is configured, build an `HttpDepDeclStore` from the index URL (as the CLI
does), instead of forcing `None`. This is the §3 corollary in action: an adapter must
not produce a different normative output than its own CLI. After the fix, remove
`fixture-144` from Python's `_NOT_YET_WIRED_FIXTURE_NAMES` and Rust's
`known_failing.txt`. (Black-box `descriptors.py` has **no** fixture-144 parking — by
design, since the CLI already passes it. The cleanup touches the **two in-process**
lists only.)

**Spec reconciliation:** `conformance-fixtures.md` (~L1009) says "fixture-144:
`dep-decl/` directory is present but empty." The fixture has *no* `dep-decl/` dir at
all, and the correct behavior (per the verified CLI trace) is the *absent*-dir +
`file://` index path. Correct the spec note to describe the actual mechanism (absent
dir → `HttpDepDeclStore` miss), not an empty dir.

### Slice 3 — `project-dir` control file: spec-first (#167) — independent of 0–2

`project-dir` is used by `fixture-288` but appears **nowhere in `spec/`** (verified).
It is an unspecced control file the CLI harness honors and the in-process adapters
ignore — a two-tier corpus. Note (round-2): fixture-288 **already passes both impls
black-box** with zero divergence, so this slice does **not** perturb the Slice-0
baseline and can be done in any order relative to 1–2. Fix order: (1) add `project-dir`
to `spec/conformance-fixtures.md` as a normative control input (semantics: the project
root is `<fixture-root>/<value>`, i.e. the dir passed as `-C` to the impl); (2) teach
both in-process adapters to honor it. Per §3, fixtures reachable only via an adapter
are not cross-impl fixtures.

## 5  Phase 2 — corpus coverage discipline (ongoing)

Governed by the saturation bar in `rfc-differential-conformance-harness.md`
(every normative MUST-clause maps to ≥1 fixture; a tier-2 generator run produces no
new divergence). This RFC contributes the **promotion workflow** and the specific
hand-authored fixtures below, now sliced (S4–S7).

**Promotion workflow.** The generate→disagree→shrink→bless→pin loop is defined in
`rfc-differential-conformance-harness.md §2c`; do not re-state it here. This RFC adds
two constraints on top of §2c:
1. **Field-level spec derivation when blessing `expected/` (anti-circularity).** §2c's
   "bless from the spec-correct impl" is circular when the spec is ambiguous — blessing
   from one impl's output can encode an impl artifact (e.g. dict iteration order) as
   normative. Rule: each field of a blessed `expected/` MUST be derivable from a
   specific normative clause (lockfile → canonical sort in `lockfile-schema.md`;
   nim.cfg → emission order in its spec; slug → `errors.md`). **Any field not derivable
   from the spec is a spec hole — file a spec-sharpening issue and defer the fixture**
   rather than blessing an impl-specific value.
2. **Every fix lands as a pinned corpus fixture** (policy, see §8): not merely a
   `known_failing` edit or an in-process unit test. A fix without a pinned fixture
   leaves every future impl (Nim) unguarded against the same regression.

**`harness/pin.py` interface (specify before Phase 2 is actionable).** Today the RFC
treats `pin.py` as a black box ("writes a fixture dir without `expected/` plus
`divergence.json`"). Target ergonomics — one command:
`python3 -m harness pin <fixture-or-input-dir>` that (a) runs both impls, (b) emits a
candidate fixture dir + `divergence.json`, (c) takes a single interactive gate — which
impl is spec-correct (subject to the field-level derivation rule above) — and (d)
re-runs the harness to confirm the pinned fixture passes for the winning impl. Document
`pin.py`'s actual current arguments so the gap to this target is explicit.

**Static corpus lint (round-2 addition — fixture-rot guard).** fixture-144 was wrong
for an unknown period because nothing checks fixtures statically. Add a lint
(runnable without executing any impl) that asserts, for every fixture: (a) `expected/error`
(when present) contains a slug that exists in `spec/errors.md`; (b) the slug in the
fixture **directory name** is semantically consistent with `expected/error`. Run it in
the §3.6 harness CI job.

### Phase 2 Layer A slices — infra (do FIRST; not gated)

Layer A makes the parity machinery itself trustworthy before any new fixtures land.
The three deliverables of §2/§5 above (D1 SSOT, the static lint, the `pin.py`
ergonomics) are sliced here. None depend on S4a; all are mechanical-to-moderate.

- **S-A1 — D1 normative-surfaces SSOT (`harness/surfaces.py`).** Extract the
  comparison set (`NORMATIVE_FILES` / `LIVENESS_CMDS` / `EMPTY_STDOUT_VERBS` /
  `NORMATIVE_EXIT_CODES` / `ABSENT_PATHS_SURFACE`) out of `assertions.py` into a new
  `harness/surfaces.py`; `assertions.py` derives its logic from it (nothing re-states
  the set inline). Strengthen the top-of-doc **Normative surface** block in
  `spec/conformance-fixtures.md` to formally enumerate the normative/non-normative
  split and cite `cli-contract.md §3.1` (do NOT create a new `§5`). RED = a harness
  unit test asserting `assertions.py`'s surface set is sourced from `surfaces.py`
  (e.g. monkder/patch the module and observe the comparison change), plus a lint test
  asserting the spec prose enumeration and `surfaces.py` agree. No behavior change to
  the corpus run. *(Python/harness.)*
- **S-A1b — D1 new enforcement (empty-stdout + exact exit code).** Wire the two
  surfaces D1 declares but the harness does NOT enforce today: `EMPTY_STDOUT_VERBS`
  (`fetch`/`lock`/`verify`/`clean`/`add`/`remove`/`update` MUST emit empty stdout on
  success, `cli-contract §4`) and the **exact** process exit code (0/1/2 per
  `cli-contract §3`, not merely zero-vs-nonzero, incl. surfacing an impl that exits 2
  where another exits 1). Both constants live in `surfaces.py` (from S-A1) and are
  wired here alongside their assertions — no dead constants. RED = a harness unit test
  that a success fixture emitting non-empty stdout on a non-liveness verb is flagged;
  GREEN = it is. **This slice CAN change corpus results** (by design — it catches
  divergences invisible today); re-run `python3 -m harness` after and treat any
  residual asymmetry per Slice A. *(Python/harness.)*
- **S-A2 — `certificate.json` canonicalization = RFC 8785 JCS.** Define the
  canonicalization normatively in `spec/conformance-fixtures.md` (sorted keys, no
  insignificant whitespace, fixed number formatting per JCS) so the "canonical-equal"
  claim is no longer hand-waved. First verify whether both impls already emit
  JCS-equal output (fixture-150 passes today); if so the slice is spec-+-assertion
  (`compare_certificate_json` canonicalizes per JCS before diffing) — if not, align
  both impls' cert serializers to emit JCS. RED = a test feeding two
  key-order-permuted-but-equal certs and asserting `compare_certificate_json` treats
  them equal, plus a per-impl test that emitted output is JCS-canonical. Gate Python
  via `uv run pytest`; Rust via `./dev-rust test -p milpa-conformance` if the Rust
  serializer changes. *(Cross-impl if serializers change; else Python/harness + spec.)*
- **S-A3 — static corpus lint (fixture-rot guard).** A lint runnable without
  executing any impl asserting, for every fixture: (a) `expected/error` (when present)
  contains a slug that exists in `spec/errors.md`; (b) the slug in the fixture
  **directory name** is semantically consistent with `expected/error`. RED = the lint
  fails on a deliberately-corrupted temp fixture (unknown slug / name mismatch);
  GREEN = it passes the real corpus. Wire it into the §3.6 harness CI job.
  *(Python/harness.)*
- **S-A4 — `pin.py` ergonomics (`python3 -m harness pin <dir>`).** One command that
  (a) runs both impls, (b) emits a candidate fixture dir + `divergence.json`, (c)
  takes a single interactive gate — which impl is spec-correct (subject to the
  field-level derivation rule, §5) — and (d) re-runs the harness to confirm the pinned
  fixture passes for the winning impl. Document `pin.py`'s current arguments so the gap
  is explicit. RED = a test driving the non-interactive core of the flow on a synthetic
  divergence and asserting the emitted fixture dir shape; GREEN = it produces a
  harness-passing fixture. *(Python/harness.)*

### Phase 2 Layer B / C slices — fixtures (after Layer A; C is gated)

- **S4 — adversarial corrupt tar archives (#148).** **Blocked on a mechanism gap
  (round-2 finding):** the RFC's "ship a pre-built corrupt archive (no `format` file ⇒
  pre-built mode)" is **mechanically impossible today** — pre-built/copy mode
  (`mocked.py` ~L265–295) copies `content/` verbatim and **never invokes the
  extractor**, so a corrupt blob is never read; build mode only ever builds *valid*
  archives. There is no path that pipes raw fixture bytes through the *real*
  `TarballFetcher`. **Prerequisite slice S4a:** design+spec a mocked-fetcher "raw
  bytes" mode (an `archive` file fed through the real extractor) in both impls, then
  S4 authors the fixture. Entry: S4a landed in both impls. Done: both impls surface
  the same terminal slug; per §7 the inner extract code is fetch-wrapped to
  `FETCH-ALL-FAILED` at the boundary, so the fixture asserts the wrapper slug.
- **S5 — tarball bz2 byte-equality (#146).** Reframed as a **success-path
  byte-equality** gap (do both impls extract+hash a bz2 archive to the same
  `content_hash`?). **Caveat (round-2):** bz2 is **not currently supported** in either
  impl (Python ~L112, Rust ~L1034) and pre-built copy mode doesn't extract — so this
  fixture needs the S4a raw-bytes mode *and* bz2 decompression support. Sequence S5
  after S4a; if bz2 support is out of scope, descope S5 to a filed issue rather than
  authoring a fixture that can't run. Entry: S4a + bz2 decode landed. Done:
  byte-identical `content_hash` in both impls' lockfiles.
- **S6 — workspace + dev-deps resolve fixture (#166).** Pure addition; the workspace
  resolver already seeds member dev-deps. Entry: `fixture-064-dev-deps` (single-pkg)
  and the workspace baseline are green. Done: cross-impl byte-identical resolve, pinned.
- **S7 — `milpa show` surfacing cond_requires (#135) — LIVENESS, not byte-compare.**
  `show` output is non-frozen in spec v1.0, so this is a **liveness** fixture (exit-0 +
  non-empty stdout), a different exit criterion from S4–S6. Byte-comparing `show`
  output would require first freezing its format — out of scope; file separately if
  wanted. Entry: a `show` invocation exercises `cond_requires`. Done: liveness fixture
  green for both impls.

## 6  Removed from scope (round 1)

- **#156 — human stderr prefix differs.** *Not a conformance issue.*
  `cli-contract.md §3.1` makes the human diagnostic line non-normative by design and
  the normative `milpa-error: <SLUG>` line is already byte-identical across impls (all
  error fixtures pass). Standardizing the human prefix would *amend a deliberate
  design decision* for zero conformance value. Recommend closing #156 as
  "non-normative by design"; UX consistency, if wanted, is the diagnostics RFC (#106).
- **#124 — widen tier-2 unsatisfiable generator diversity.** Belongs to
  `rfc-differential-conformance-harness.md` (it owns tier-1/tier-2 generators), and
  as written it references deleted code (`unsatisfiable_graph_st`, removed in
  `5ae87ad`). Move the issue under the differential-harness umbrella; blocked on
  re-landing the generator there.

## 7  Known blind spot — wrapping boundaries

`conformance-fixtures.md §4` lists ~30 codes as "structurally unreachable" because
they are wrapped at a boundary (fetcher inner codes → `FETCH-ALL-FAILED`; identity
codes → `LOCK-DEP-IDENTITY-INVALID`). Two impls can wrap **differently** and still
agree on the observable wrapper slug — a divergence the corpus cannot catch by
construction. Mitigations this RFC adopts:
- The inner-code→wrapper *mapping* MUST be unit-tested within each impl. **But this is
  insufficient alone (round-2):** per-impl unit tests catch *within-impl* regression,
  not *cross-impl* divergence — Python and Nim can each pass their own mapping tests
  while mapping the same inner condition to different wrappers, both emitting the same
  boundary slug. Two additional mitigations:
  - **Every wrapped code MUST have ≥1 black-box fixture that exercises an inner code
    path through its wrapper** (e.g. S4 drives a real extract failure to
    `FETCH-ALL-FAILED`), so the boundary mapping is observed cross-impl for at least
    one path per wrapper.
  - **Cross-impl root-cause substring check:** when both impls emit the same wrapper
    slug for a fixture, their (non-normative) diagnostic messages MUST each contain a
    shared root-cause token (a digest, a URL) identifying the *same* underlying cause.
    This is a weaker-than-byte but stronger-than-slug cross-check that catches
    divergent wrapping without freezing the human line.
- Changing a wrapping boundary is a **spec-level event** (it can make a
  previously-unreachable code observable); whoever changes it must add the
  now-reachable fixture.

## 8  Scope decision (resolved 2026-06-21 → option a)

**Scope boundary vs `rfc-differential-conformance-harness.md`.** With #124 moved out,
the remaining work cleanly bifurcates. Three framings were weighed:
- **(a) one RFC, two phases (chosen):** Phase 1 baseline restoration + Phase 2
  coverage discipline live here; generation is a declared dependency on the
  differential-harness RFC. Keeps the parity *discipline* in one place.
- **(b) narrow to baseline + D1 only:** move all corpus-widening to the
  differential-harness RFC. Cleaner ownership; more cross-RFC coordination.
- **(c) three-way split** by kind. Maximal separation; over-fragmented.

**Decision: (a)** — one RFC, two phases. The bug fixes are the motivating examples of
the discipline the RFC defines, and keeping them together preserves a single coherent
done-state. Generation remains owned by the differential-harness RFC and is a declared
dependency of Phase 2 (S4a's raw-bytes mode and the generator are the real gates for
the bulk of Phase 2).
