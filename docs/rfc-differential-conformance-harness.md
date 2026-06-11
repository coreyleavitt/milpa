# RFC: differential conformance harness — one neutral runner for every impl

> Status: **draft, architect round 2 applied** (2026-06-09). Supersedes the
> deferred "S15 differential harness" stretch slice from `rfc-rust-port-design.md`.
> No code yet; this RFC is written *before* the Python rewrite and Nim dogfood so
> both are built to the contract rather than retrofitted into it.
>
> Round 1 (4-lens review) changes: Gap-1 error format moved from inline
> `error[<SLUG>]:` to a **terminal `milpa-error: <SLUG>` line** (R1–R4) — the
> inline anchor conflated human+machine channels and mis-parsed multi-line
> bodies; corrected the false "corpus regen" claim (no `expected/` changes; Gap 1
> is a code change in *both* CLIs); descriptor argv-prefix → struct + container
> wrapper; added determinism/normalization (per-run `MILPA_CACHE_DIR`, `LC_ALL=C`,
> CAS_ROOT normalize before diff, partial-output assertion); operationalized live
> mode (SHA substitution + frozen index + gating + retry); directory-shrink
> strategy + generator tiers; §2f scope-out of mutation verbs + `show`; harness =
> standalone python3-stdlib; #1-blocks-#2 sequencing.
>
> Round 2 (4-lens review) further changes: R2 made **position-independent**
> (unique full-line `^milpa-error: <SLUG>$` anywhere in stderr, not "last line" —
> immune to post-error stack traces / podman noise; fd-3 considered, rejected);
> two "modes" reframed as **one loop + pluggable fetch transport** (mocked/git);
> descriptor gains `invoke_via: Direct|Container` (harness owns `podman run`,
> distinguishes infra-failure from impl-failure) + `known_failing` (partial-impl
> skip list); added a **"Relationship to rfc-property-based-testing.md"**
> reconciliation (no duplicate counterexample pipeline — anti-duplication); spec-
> hole **dedup + single-arbitrator** governance; **saturation/done-ness** bar in
> acceptance; **#2-is-infra-only / #2+#3 = MVP** note; component vocabulary
> (fixture runner / corpus runner / generator / shrink-pin loop) + divergence
> **summary grouping**; `verify` failure-fixture assertion shape; Gap-1 framed as
> a self-contained prerequisite. Below: round-2 depth/feasibility second pass —
> Gap-1 scope clarified —
> three distinct sub-problems beyond "thread .code": (1) typed exceptions with
> `.code` in hand but discarded (`SolverError`, `NotFrozen` in Python;
> `Ok(1)` paths in Rust `cmd_verify`/`cmd_add`/`cmd_remove`); (2) arg-parse
> exits that must be exit 2 not exit 1 (harness crash-class, not R3 coded
> errors; Python argparse already does this, Rust `parse_args`-None path must
> change); (3) catch-all `MILPA-INTERNAL` sentinel for bare `except Exception`
> fallbacks. TDD entry point for issue #1 specified (subprocess assertion against
> existing conflict fixture, no runner needed). §2c tier-2 oracle sharpened:
> structural post-hoc validity check (locked version satisfies manifest
> constraint) added as the oracle for "both impls wrong"; pure cross-impl
> agreement alone is insufficient.
>
> Round 3 (issue-#4 implementation feedback) correction: §2a's container-vs-host
> "resolution" was **wrong** and is rewritten. The earlier text considered only
> two options — host harness + per-fixture `podman run`, vs harness inside the
> *toolchain* container — and chose the former, conflating *toolchain container*
> (rustc/cargo, can't reach Python) with *harness container* (runtime artifacts
> only). The right design is a third option: build each impl's **runtime artifact**
> once in its toolchain container (build-time), then run the harness once in a
> single environment holding *all* artifacts, invoking every impl `Direct`.
> Per-fixture `podman run` (measured ~0.54s/fixture, linear in corpus size) is
> eliminated; `invoke_via: Container` is demoted from the first-class Rust path to
> an optional escape hatch. See §2a.

## Why this RFC exists

milpa now has two passing implementations (Python reference, Rust reference)
against one shared fixture corpus (`tests/conformance/spec-v1/`, 117 fixtures).
A manual live-network run on fresco's real dep tree produced **byte-identical**
`milpa.lock` and `nim.cfg` from both impls. That hand-crank is the embryo of a
differential harness: generate inputs, run them through every impl, and treat
*disagreement* as the signal.

The strategic point — argued at length in the session that produced this RFC —
is that **no single implementation is the oracle**. The spec plus the shared
corpus is the authority (`rfc-multi-impl-strategy.md`; `docs/spec/README.md`).
Independent impls agreeing is evidence the spec is unambiguous; disagreeing is a
spec hole or a bug. The value of a differential harness is therefore *spec
hardening*, and that payoff is implementation-independent: a counterexample
found now becomes a corpus fixture that the future Nim impl must pass before it
is even written. Front-loading it is what lets a later flagship (Nim) *earn*
gold-standard status rather than be crowned it.

We are about to write two more impls (Python rewrite first, then Nim). This is
the cheapest, most-independent differential window we will ever have — and the
moment to fix the contract those impls are built against.

**Structure.** This RFC has two parts that ship in order: **Gap 1** is a small,
self-contained prerequisite *spec change* (the machine-readable error channel)
whose normative text lands directly in `cli-contract.md` as issue #1 — it stands
alone and is not specific to the harness. **Gap 2** is the harness design proper.
Gap 1 is presented first because everything downstream depends on it.

## The principle

> The harness is impl-neutral at exactly one boundary: **a process that takes
> fixture-shaped inputs on disk and produces fixture-shaped outputs on disk,
> plus a machine-readable error slug on failure.** Everything above that
> boundary (generation, comparison, arbitration) is written once, in one place,
> and never linked against any impl.

Corollary: adding a new implementation to the harness MUST require only one
**descriptor entry** (an `ImplDescriptor` struct — name, argv, cwd, static env;
its prebuilt artifact already present in the harness env per the §2a build/run
split). No harness code changes, and no per-impl wrapper script — the optional
`Container` escape hatch is driven by the harness from `image`/`mounts` alone.

## What already exists (do not rebuild)

`docs/spec/conformance-fixtures.md` already specifies the neutral boundary for
the **static corpus**, and we reuse it verbatim:

- §2 — the fixture input contract (`milpa.kdl`, `index.kdl`, `mocked-fetches/`,
  `cmd`, `env`, `cas-seed/`). `mocked-fetches/` is the language-neutral
  deterministic transport — a directory convention, not shared fake-fetcher
  code. This is the thing that makes offline determinism portable across
  languages.
- §2.6 — the `<CAS_ROOT>` normalization that makes `_deps_structure.txt`
  machine-independent (canonicalize, strip trailing separator, substitute).
- §5 — the black-box byte-diff protocol: copy inputs to scratch, invoke the
  impl, diff `milpa.lock` / `nim.cfg` / `_deps_structure.txt`, or assert the
  error slug.

This RFC adds **nothing** to the fixture format. It adds the two things §5
gestures at but does not nail down: a machine-readable failure channel, and the
differential/generative layer on top.

## Gap 1 — machine-readable error-slug emission (load-bearing)

`cli-contract.md` §3 requires only that failure "produce at least one
diagnostic line on stderr" and that the slug appear "e.g., `SOLVE-CONFLICT`"
*somewhere* in that text. There is no anchored, parseable format. A
language-neutral runner trying to extract the slug would have to substring-grep
for known slugs in free-form, explicitly-non-normative message text — fragile
and wrong (a message may mention multiple slug-like tokens; phrasing differs per
impl by design).

This is why neither current runner is black-box: both read the in-process
exception's `.code`. That coupling is acceptable for two impls; it does not
scale to "any binary, including Nim" and it cannot drive a differential run that
shells out.

**Decision: change the default failure output to carry a dedicated, terminal
machine line.** (Review round 1 revised this away from an inline rustc-style
`error[<SLUG>]:` anchor — that overloaded one line as both the human message and
the machine channel, and a wildcard anchor mis-parses when a multi-line message
body, a nested cause, or a progress line happens to match the prefix. A separate
terminal line is unambiguous and does not constrain the human text.)

On any failure, stderr MUST contain exactly one line of the form:

```
milpa-error: <SLUG>
```

Normative rules (to be written into `cli-contract.md` §3):

- **R1 — slug grammar.** `<SLUG>` is a conformance-stable code from `errors.md`,
  matching `^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$` (at least one hyphen segment — the
  loose `[A-Z][A-Z0-9-]+` would admit dashless or trailing-dash non-slugs). The
  harness additionally checks membership in the `errors.md` catalog.
- **R2 — exactly one, position-independent.** On a failure exit there MUST be
  exactly one full-line match of `^milpa-error: <SLUG>$`, and no other emitted
  line may begin with `milpa-error:`. The harness scans *all* stderr lines for
  the unique match and validates it against the catalog — it does **not** rely on
  line position, so a stack trace, a `__del__` finalizer, or `podman` startup
  noise emitted *after* the slug line cannot corrupt extraction (round-2 finding).
  Zero matches → crash verdict (R4); two or more → protocol-violation verdict
  (reported as a harness-level failure, not a slug). Impls SHOULD still emit the
  slug line last for human readability, but the contract does not depend on it.
  (A dedicated fd-3 channel was considered and rejected: it is a POSIX-ism that
  complicates Windows support and container fd-passing, for a robustness the
  full-line anchor already delivers.)
- **R3 — iff exit 1.** The `milpa-error:` line appears **if and only if** the
  process exits 1. An exit-0 run (including one emitting `verify` drift
  *warnings* to stderr, cli-contract §5.4) MUST NOT emit a `milpa-error:` line.
- **R4 — crash is observable.** Any exit with **no** terminal `milpa-error:`
  line is the harness's **crash/panic verdict** — distinct from a clean error.
  This covers: exit 1 without the terminal line (impl forgot to emit it), exit >
  1 (e.g., Rust panic → 101, OOM kill → 137), and signal termination. The fuzz
  invariant of §2d is therefore: *for non-OOM, non-signal inputs, the impl MUST
  NOT produce a crash verdict — it MUST always exit 1 with a slug*. Rust impls
  MUST install a top-level panic handler that emits `milpa-error: INTERNAL-PANIC`
  (or another catalog code) before exiting 1; an unhandled `panic!()` that exits
  101 is a crash verdict by R4 and a fuzz failure.

A human still gets a readable message; impls MAY keep or improve their
human-facing error rendering above the terminal line (rustc-style spans are
welcome there). No flag: the machine line is present by default. A structured
JSON format with context fields (which dep, which constraint) remains a trivial
later addition — emitted as lines *before* the terminal slug line, so it never
conflicts with R2. We take the default-output change rather than an opt-in
`--error-format=json` flag because there is **one consumer** (the author)
pre-stabilization, so the "don't break the default output" constraint that
normally favors a flag does not apply.

> NORMATIVE constraint to add to `cli-contract.md` §3 alongside R1–R4: no
> non-error diagnostic line a conformant impl emits may begin with `milpa-error:`.

**This is real code in both impls, not just a spec edit** (review finding). Today
neither emits this line: Python `cli.py` prints bare prose (e.g. `error reading
manifest: …`) and never accesses `e.code`; Rust `main.rs` prints `<CODE>:
<message>`. Both CLIs must be changed to emit the terminal `milpa-error:` line.

**Scope of the change is larger than "thread .code through catch sites"** (round
2 finding). Three distinct sub-problems exist, all of which must be resolved in
issue #1 before the corpus passes under the black-box runner:

1. **Typed exceptions with a `.code` in hand but unused.** Python `SolverError`
   has `code = "SOLVE-CONFLICT"` as a class attribute but `_resolve_or_error`
   ignores it and renders bare prose. `NotFrozen` has `.code` (e.g.
   `FROZEN-IDENTITY-NOT-IN-STORE`) but `_try_frozen` discards it via
   `return str(e)` — both frozen exit-1 paths (`cmd_fetch` and
   `_cmd_fetch_workspace`) print a bare reason string with no slug. Rust's
   `cmd_verify`, `cmd_add`, and `cmd_remove` return `Ok(1)` with prose-only
   `eprintln!` calls, bypassing the `Err(MilpaError)` path where `e.code()`
   fires. All these exit 1 today with no `milpa-error:` line.

2. **Argument-parse failures exit code 2, not 1.** Python argparse calls
   `sys.exit(2)` on invalid `--strategy` values, missing required positionals
   (e.g. `milpa remove` with no dep name), and unrecognized flags — code 2,
   not 1. Rust's `parse_args`-returns-None path currently exits 1 with bare
   `USAGE` text. The conformant design: **argument-parse errors exit 2**, and
   the harness treats exit-2 as the "usage/crash" verdict (no `milpa-error:`
   line expected, distinct from R3 coded errors and from R4 panics). A
   `MILPA-USAGE-ERROR` slug is NOT added for this class; exit 2 is the signal.
   Rust must change its parse-failure paths from `Ok(1)` to
   `std::process::exit(2)` to match. Add to R4's note: "exit 2 (arg parse
   failure) is also a crash-class verdict; the harness treats any exit ≠ 0,
   ≠ 1 as crash."

3. **`except Exception` fallback paths need a catch-all slug.** Python `cli.py`
   has 18 bare `except Exception as e` handlers that print prose and return 1.
   These need a `MILPA-INTERNAL` sentinel in the catalog, emitted by the
   outermost `main()` entry-point wrapper for any exception that escapes typed
   handlers. The sentinel makes the R3 invariant mechanically enforceable: the
   entry point catches `BaseException`, emits the slug, and exits 1.

Issue #1's TDD entry point is a single subprocess assertion against an existing
conflict fixture — no black-box runner of issue #2 needed: run
`subprocess.run([...,"fetch","-C","<conflict-fixture>"], capture_output=True)`,
assert `returncode == 1`, assert `stderr.splitlines()[-1] == "milpa-error:
SOLVE-CONFLICT"`. That is the first RED test.

## Spec versioning (deferred until stabilization)

milpa is pre-stabilization with a single consumer. The spec-version machinery in
`conformance-fixtures.md` §1.3 (normative-change → version bump, immutable
`spec-v<N>/` partitions) is the right discipline *once we declare stability* —
at which point `v1` gets stamped on whatever surface is then stable. Until then
we **amend the spec docs in place** rather than minting `spec-v2/` for every
in-flight change.

**The Gap-1 change touches no corpus fixtures** (review correction). Error
fixtures store the bare slug in `expected/error`, and both current runners assert
it against the in-process exception `.code` — neither parses stderr. So Gap 1 is:
(a) `cli-contract.md` §3 — the R1–R4 contract; (b) `conformance-fixtures.md` §5
item 4 — reword "emitted an error whose `.code` matches" to "emitted a terminal
`milpa-error: <slug>` line matching"; (c) the two CLI impls. **No `expected/`
file changes.** Not a version event.

## Gap 2 — the differential + generative layer

### 2a. The impl descriptor (the only per-impl coupling)

A registry of descriptors, one per impl. Review round 1 corrected the original
"one-line argv prefix" to an honest small struct — argv alone cannot express the
working directory `uv run` needs, the env the harness injects, or a
container-wrapped impl's mounts:

```
ImplDescriptor {
    name:          str               # "python" | "rust" | "nim"
    invoke_via:    Direct | Container # how the harness launches it (below)
    argv:          list[str]         # invocation prefix (the milpa entry point)
    cwd:           str | None        # e.g. the milpa source tree for `uv run`
    env:           dict              # static extras; harness ALSO injects per-run isolation env
    known_failing: list[int] | None  # fixture numbers this impl is not yet expected to pass
}
Direct                                   # exec argv as a local subprocess in the harness env
Container { image: str, mounts: list }   # OPTIONAL escape hatch — harness synthesizes the `podman run`
```

- **python:** `Direct`, `argv=["uv","run","python","-m","milpa"]`, `cwd=<repo>`.
- **nim:** `Direct`, `argv=["/path/to/milpa"]`.
- **rust:** `Direct`, `argv=["/path/to/milpa"]` — the **prebuilt binary**, not the
  toolchain. (Round 3 correction; see below.)

#### Build-time / run-time split — every impl is `Direct` in the harness env

The harness needs each impl's **runtime artifact** (the Python package + interpreter,
the compiled Rust binary, the future Nim binary), never its *toolchain* (rustc, cargo,
the Nim compiler). So the two are separated cleanly:

- **Build-time** — each impl produces its runtime artifact in whatever container its
  toolchain lives in (Rust in `dev-rust`'s toolchain image, Nim later in its own).
  Python has nothing to build. This stage runs once per impl change.
- **Run-time** — the harness runs **once** in a single environment that holds *all*
  the artifacts, invoking every impl as a local `Direct` subprocess. For CI that
  environment is one **multi-stage harness image** whose final stage = python3 (for
  the stdlib harness + the Python impl) with the Rust/Nim binaries `COPY`'d in from
  their build stages; for local dev it is simply the host with the binary copied out
  of the build container. Either way, **container startup is paid once per harness
  run, not once per fixture.**

This is the option round 2 missed. It had reduced the choice to (1) host harness +
per-fixture `podman run` for Rust, or (2) harness inside the *Rust toolchain*
container — and rejected (2) correctly (that image has only Rust, so it cannot also
drive the Python impl), leaving (1). But (1)'s per-fixture `podman run` is the cost
that kills the generator loop: measured **~0.54s/fixture** on WSL2 (container startup;
milpa itself is ~0.02s of that) → ~63s over the current 117-fixture corpus, **linear
in fixture count**, so issue #3's generated inputs (thousands) would spend minutes in
pure container startup. Option (3) — one harness env, all `Direct` — eliminates it
entirely: the same Rust binary, run directly, is **~0.0006s/invocation** (~900× faster;
the binary is a portable ELF, so the per-fixture *wrapper* was the whole cost, not the
binary). (3) drives all impls from one process (so it is a true single differential
pass, unlike (2)) at no per-fixture container cost (unlike (1)).

`invoke_via: Container` therefore survives only as an **optional escape hatch** — for
ad-hoc differential runs against an impl not baked into the harness image — not as the
canonical Rust path. When used, the harness still owns the `podman run` synthesis from
`Container{image, mounts}` (mount recipe, env-forwarding of `MILPA_CACHE_DIR` /
`MILPA_INDEX_URL` / `LC_ALL`, and distinguishing a `podman`-infrastructure failure —
image pull / mount error, before any impl output — from an impl failure), written and
tested once rather than reimplemented per impl in bash. It is not on the CI hot path.

`known_failing` mirrors the partial-conformance declaration in
`conformance-fixtures.md` §1.4: a mid-development impl (the Nim dogfood, or any
new port) is registered with the fixtures it is not yet expected to pass, and the
differential runner *skips* those for that impl (logging `skipped: known-failing
for <impl>`) instead of flooding the divergence report. Without it, a half-built
impl can only be registered once 100% conformant — which defeats the
catch-bugs-early argument. The list shrinks to empty as the impl matures.

All impls already honor the shared CLI contract (`-C <dir>`, `MILPA_CACHE_DIR`,
`MILPA_INDEX_URL`, the `cmd`/`env` fixture inputs). For each `(fixture, impl)`
run the harness creates an **isolated scratch dir** (inputs deep-copied
recursively — including `cas-seed/` — so each run has a full independent copy
regardless of whether any prior run consumed the tree) and an **isolated
`MILPA_CACHE_DIR`** (so impl A's fetch can't warm impl B's CAS and
mask a divergence), invokes `<argv> -C <scratch> <cmd> …` under `LC_ALL=C`, then
reads outputs off disk and the terminal `milpa-error:` line off stderr. Scratch
+ cache are torn down after the diff. **No impl code is linked.**

> Decision: the canonical multi-impl runner drives via **CLI subprocess**,
> enabled by Gap 1, and **is the normative conformance gate**. The existing
> in-process adapters (pytest / `cargo test`) are a per-impl *developer
> convenience* (fast inner loop) testing an implementation detail — the
> in-process API — not the observable CLI surface; they MAY differ in
> human-message rendering as long as the slug contract holds. The Python rewrite
> and Nim impl need a descriptor, not an adapter.

### 2b. One run loop, two fetch transports

There is **one** run loop (generate/copy input → invoke each impl → normalize →
diff), not two modes (round-2 finding: after round 1 added SHA-pinning + a frozen
index, "live mode" had collapsed into "offline mode with a real git fetch"). The
only axis that varies is the **fetch transport**, a slot with two
implementations:

- **`mocked` (default).** Inputs use `mocked-fetches/` / `cas-seed/`; zero
  network. The bar is **byte-identical** outputs across every registered impl
  (and against checked-in `expected/` when the fixture is in the corpus). This is
  the PBT/fuzz vehicle. Note: `conformance-fixtures.md` §2.10 documents the
  Python adapter's `cas-seed` `admit()` as *move-not-copy* (frozen fixtures
  non-idempotent on rerun); the harness sidesteps it via the per-run deep copy
  (§2a), but the underlying adapter fix is still owed.
- **`git` (gated behind `MILPA_INTEGRATION_TESTS=1`).** Real git fetch of pinned
  SHAs; generalizes the manual fresco run. "Pin a commit" is operationalized: the
  harness resolves each mutable `ref` to a commit SHA once and **substitutes the
  SHA** on subsequent runs (a `ref="main"` that advances would otherwise break
  idempotency). SHA pins live in a **committed sidecar** (e.g.
  `tests/live/ref-pins.json`), not computed per-session, so reproducibility is
  auditable via git history; a force-push invalidates a pin, and refreshing means
  explicitly deleting the entry and re-running. `MILPA_INDEX_URL` still points at
  a **frozen local index snapshot**, so the only live hit is the git fetch.
  Asserts each impl *succeeds*, is *idempotent* (rerun → identical lockfile), and
  that `verify` passes; cross-impl byte-equality holds because both fetch the same
  pinned SHAs + frozen index. A pre-output network failure (non-zero exit, no
  outputs, no slug) is retried once before being reported.

Everything above the transport — copy/serialize, normalization, cross-impl diff,
shrink/pin — is shared by both transports, so there is no duplicated code path to
maintain.

#### Normalization before comparison (offline)

Differential mode compares two **live** outputs with no checked-in `expected/`
to anchor them, so the harness MUST apply `conformance-fixtures.md` §2.6
normalization to *each* impl's output before diffing — most importantly
substituting each run's isolated `MILPA_CACHE_DIR` prefix with `<CAS_ROOT>` in
`_deps_structure.txt` (otherwise per-impl cache dirs guarantee a spurious diff).
`milpa.lock` / `nim.cfg` dep ordering is already deterministic (lockfile-schema
canonical sort — confirmed byte-identical + idempotent in the manual fresco run),
so `-j` concurrency does not perturb output; the harness relies on this rather
than re-sorting. `_deps_structure.txt` is sorted lexicographically by dep name
per conformance-fixtures.md §2.6 — no re-sort needed there either. Content hashes
are order-independent (computed over a canonical sorted tree walk per
`docs/spec/identity.md`); naive `os.walk` order does not affect them. `LC_ALL=C`
and `\n` line endings are pinned for every invocation. For error fixtures the harness additionally asserts **no**
`milpa.lock` / `nim.cfg` was left in the scratch dir (verifies the §5.1 atomic
write-then-rename — a failed run leaves no partial output to pollute a later
diff).

### 2c. Generation → arbitration → pin (the loop)

Generators are **pluggable and need not be neutral** — they live wherever the
best PBT lib is (Hypothesis today; nkdl's grammar-derived generators for the KDL
*syntax* layer later, noting those target KDL parsing, which milpa delegates,
not milpa's semantic layer). A generator's *output* is neutral: a fixture-shaped
input directory.

The loop:

1. Generate an input. Run it through all registered impls (offline mode).
2. **Agreement** → discard (or sample-retain) — no signal.
3. **Disagreement** → the spec is the arbiter:
   - If the spec determines a winner, the losing impl has a bug; minimize
     (shrink), then pin the minimized input as a corpus fixture with the
     spec-correct `expected/`. Computing `expected/` for a pinned differential
     fixture **requires human verification**: a reviewer reads the spec prose,
     inspects the winning impl's output, and manually blesses the bytes. The
     harness automates generation, disagreement detection, and shrinking;
     arbitration and pinning are gated on human review. This is the
     `rfc-property-based-testing.md` shrink → fix → pin → promote pipeline,
     extended cross-impl. Note also: for error fixtures, "spec determines a
     winner" requires the spec to uniquely determine which slug fires first for
     the input; when two slug-paths are both valid for the same input (e.g., a
     syntax error masking a semantic error), the spec must be sharpened to
     define a priority ordering before the fixture can be pinned.
   - If the spec is *silent* (neither impl is "wrong" per the text), it is a
     **spec hole**: file an issue, sharpen the spec, then pin the fixture once
     the spec resolves it. (Per `feedback_no_workarounds` / "spec outlives
     impl": sharpen the spec, do not special-case an impl.) To avoid a flood of
     low-value issues, the harness emits **at most one issue per distinct
     behavioral class** — minimized fixtures producing the same divergence
     pattern `(cmd, output_file, disagreement_shape)` are deduped before filing.
     Pre-stabilization the project author is the sole arbitrator, and spec
     sharpening follows the in-place amendment policy above (not a version event).

**Shrinking a fixture is shrinking a directory, not a string** (review finding —
flagged as the hard part of issue #3, designed there, not hand-waved here). A
fixture input is a tree (`milpa.kdl` + optional `index.kdl` + `mocked-fetches/`)
whose parts must stay mutually consistent (every dep named in the manifest needs
a matching `mocked-fetches/` entry). The feasible approach: the **generator emits
a single structured value** (manifest + index rows + the dep→fetch map) that
Hypothesis can shrink natively; a serializer projects that value to the fixture
directory. Shrinking happens on the structured value (drop a dep → drop its fetch
entry together, drop an index row, narrow a constraint), and each candidate is
re-serialized and re-run. The directory is never shrunk directly. The pinned
counterexample is the serialized minimal value.

**Generator tiers** (the floor, so we don't ship a parser-only harness):
syntactic generators (malformed KDL / lockfiles — surfaces parse + error-slug
divergence) are tier 1; **semantic graph generators** (satisfiable and
unsatisfiable PubGrub instances, diamonds, workspace topologies — surfaces the
*resolution* divergence that is the highest-value signal) are tier 2 and the
operational bar. `rfc-property-based-testing.md` defers solver-soundness
generation to its research tier; this RFC sets tier 2 as required for the
differential harness to be considered done, and `log()`s coverage (which
normative MUST-clauses a run exercised) rather than implying full coverage.

**Tier-2 oracle is structural post-hoc verification, not cross-impl agreement**
(round 2 finding). Pure cross-impl agreement for satisfiable instances cannot
catch "both impls wrong in the same way." The generator knows the input manifest's
constraints; the harness can check the *output* lockfile structurally: for every
dep in the lockfile, assert the locked version satisfies every constraint declared
in the manifest for that dep. This is a local, solver-free check on each impl's
output independently. For unsatisfiable instances, the check is weaker: both exit
1 with some slug. The generator should additionally record the *reason for
unsatisfiability* (which constraint pair creates the conflict) so a human reviewer
can verify the slug is `SOLVE-CONFLICT` (not a parse error or a network error
masking the actual conflict). The oracle for "both wrong" is this structural
validity check; it does not require a reference solver.

The durable output of the whole harness is therefore **corpus fixtures** — the
same artifact every impl's own runner already consumes, including the
not-yet-written Nim impl.

**Relationship to `rfc-property-based-testing.md` (no duplicate pipeline).** That
RFC already defines a counterexample lifecycle (shrink → triage → fix → pin →
promote). This RFC does **not** introduce a second one — it *is* the cross-impl
realization of the same lifecycle, with three reconciliations stated explicitly
so the two docs cannot drift (per the anti-duplication discipline):
1. **Pinning target.** Cross-impl findings skip the PBT RFC's intermediate JSON
   `property-counterexamples/` form and pin **directly as fixture directories**
   in `tests/conformance/spec-v1/` (naming `fixture-NNN-generated-<slug>`). The
   JSON form remains only for single-impl algebraic counterexamples that have no
   fixture-directory representation.
2. **Triage = spec arbitration.** The PBT RFC's "is it a property bug or an impl
   bug?" triage step maps onto this RFC's §2c arbitration (spec winner / spec
   hole). Same gate, cross-impl framing.
3. **Promote is immediate here.** The PBT RFC defers "promote to conformance
   fixture" to the v1.5 spec-extraction; for cross-impl findings promotion is the
   point and happens at pin time (the spec is already extracted — `docs/spec/`).

> **Limitation — shared-spec-misreading is invisible to differential testing.**
> If two impls misread the same ambiguous prose identically, they *agree* and no
> signal fires (see [[testing_differential_blind_spot]]). Differential agreement
> is necessary, not sufficient. Mitigation: the corpus `expected/` for normative
> MUST-clauses must be **human-verified against the spec prose**, not merely
> generated by running one impl; and impl independence (Python-original + Rust,
> the cleanest pair) must be protected. This is *why* the spec — not impl
> agreement — is the arbiter.

### 2d. Fuzzing

Parser fuzzing (manifest, lockfile, index) is the cheapest high-ROI target: the
invariant is *the impl never panics/crashes — it emits a slug and exits 1*. A
crash is a bug by construction. Fuzz harnesses are per-impl (cargo-fuzz for
Rust, `atheris`/Hypothesis for Python) but feed the same minimize → pin loop, so
their output is again neutral corpus fixtures.

### 2e. Components, where they live, and what they emit

Four named layers (round-2 finding: the doc had ~4 loose terms for these — fixing
the vocabulary so code, issues, and acceptance criteria agree):

- **fixture runner** — given one fixture dir + one `ImplDescriptor`, invokes the
  impl (Direct/Container), captures outputs + the `milpa-error:` slug. The neutral
  CLI primitive; the normative conformance gate.
- **corpus runner** — iterates fixtures × impls over the fixture runner, applies
  normalization, computes cross-impl divergences. "The harness" elsewhere.
- **generator** — produces fixture-shaped inputs; lives wherever the PBT lib fits.
- **shrink/pin loop** — drives the generator's shrink on a divergence, emits a
  corpus fixture (human-gated, §2c).

The corpus + shrink layers are a **standalone `python3`-stdlib program** — a
*separate* program from the uv-managed milpa package, depending on nothing but the
CLI contract and the stdlib. Note (round 3): under the §2a build/run split the
harness env is a single image that *does* contain the Python impl's runtime artifact
(it is the base layer the Rust/Nim binaries are `COPY`'d onto), so the python impl is
physically `import`-able there. The "drive every impl as a black-box subprocess, never
`import` its internals" rule is therefore a **design discipline enforced by code review
and by the harness being a distinct program** — not by the impl's physical absence from
the environment. (The earlier "CI runner has none of the impls pre-installed" framing
no longer holds and is the cost of eliminating per-fixture containers; it is the right
trade.) What the harness still must NOT require is any impl's *toolchain* (rustc, cargo,
the Nim compiler) — only prebuilt artifacts. Rationale over bash: it grows a structured
divergence record, the normalization pass, and the shrink/generator integration —
stdlib Python stays readable where bash would not, at the same zero-install cost.

On divergence it emits one JSON record per finding for human triage + ingestion:
`{ fixture, cmd, output_file, impls: { <name>: <normalized-bytes-or-slug> } }`.
**Before** the per-finding records, the corpus runner emits a **summary grouped by
`(cmd, output_file, disagreement_shape)` with a count per class**, so a human
triages "3 classes, 47 instances of class-1" rather than reading 50 raw records
(round-2 finding). The record points at a fixture directory, not a Hypothesis
value: for **generated** inputs Hypothesis shrinks the structured value *before*
serializing, and the record is the post-shrink artifact handed to a reviewer for
pinning; for **corpus** fixtures it names which fixture regressed and who
disagrees.

### 2f. Scope and coverage gaps (inherited from the fixture format)

This RFC "adds nothing to the fixture format" — so it also **inherits that
format's gaps**, which review surfaced as real holes (stated here rather than
silently skipped):

- **Mutation verbs `add` / `remove` / `update` (3 of 8 verbs) are not
  fixture-expressible.** They rewrite `milpa.kdl` *and* `milpa.lock`, and `add
  --git` does a live `git ls-remote`. The corpus has no `cmd` for them, no
  `expected/milpa.kdl` output slot, and no mocked-ref convention. → Fixture-format
  extension (a `cmd=manifest-mutate` + an `op` input + diffing `expected/
  milpa.kdl`); **filed as its own issue**, not built here. Until then the
  differential harness cannot cover these verbs and says so.
- **`show` stdout is not byte-diffable.** cli-contract §5.3 leaves `show`'s format
  explicitly *non-frozen* for v1, and there is no `expected/stdout` slot. → The
  harness tests `show` for **liveness only** (exit 0, non-empty stdout), not byte
  equality, until/unless the format is frozen (separate issue). `--version`:
  same — liveness only.
- **`verify` failure fixtures need a slug assertion, not the no-partial-output
  rule.** `verify` reads a lockfile and writes none, so §2b's "no `milpa.lock`
  left in scratch on error" check is vacuous for it; and a single `verify` run can
  emit a drift *warning* (exit 0 path, §5.4) *and* a hard mismatch. The assertion
  shape for a `verify` failure fixture is therefore: exit 1 + the unique
  `milpa-error: <slug>` line (R2), independent of any warning text on stderr.

## What this constrains in the Python rewrite (first consumer)

The Python rewrite is the first new impl built against this RFC. It MUST:

1. Emit the terminal `milpa-error: <SLUG>` failure line per Gap-1 R1–R4 (a real
   change — today's Python CLI prints bare prose and never reads `e.code`).
2. Be drivable by the neutral CLI runner via a descriptor (Gap 2a) — i.e. the
   black-box subprocess path must pass the full corpus, not only the in-process
   pytest adapter.
3. Keep emitting the same conformance-stable slugs (no behavior change; the
   corpus is the arbiter).

Building the rewrite to this contract is the point: it proves the contract is
real on a second impl *before* Nim, at near-zero marginal cost.

## Acceptance: testable invariants

- A new impl is added to the differential harness by adding exactly one
  descriptor entry (struct), its prebuilt artifact present in the harness env
  (§2a build/run split) — and changing no harness code.
- Every corpus fixture passes via the **black-box CLI** path (not only the
  in-process adapter) for every registered impl (excepting the §2f scope gaps,
  which are tracked, not silently skipped).
- The offline differential run over the full corpus is byte-identical across all
  registered impls.
- A seeded divergence (deliberately broken impl) is detected and reported with
  the diverging fixture and the per-impl outputs.
- A generated counterexample flows shrink → pin → corpus and is thereafter
  enforced by every impl's own runner.
- **Saturation / done-ness** (round-2 finding — "spec hardening" needs a finite
  bar). The generate loop is *complete for a tier* when (a) every normative
  MUST-clause in `cli-contract.md` and `resolver-semantics.md` maps to ≥1 corpus
  fixture (static or pinned), and (b) a tier-2 run of 1000 examples produces no
  new divergence and no new spec hole (the same saturation rule
  `rfc-property-based-testing.md` uses for nightly CI). The coverage map of (a) is
  `log()`ged each run so the gap is always visible.

## What this RFC does NOT commit milpa to

- A *compiled* harness or a harness that links any impl. §2e fixes the comparison
  layer as a standalone `python3`-stdlib program, but only its *inputs and
  outputs* (the CLI contract + fixture format) are normative — a third party may
  reimplement the runner in any language against the same contract.
- Runtime shipping of any PBT/fuzz dependency (dev-only, as in
  `rfc-property-based-testing.md`).
- A structured JSON error format — deferred until a real second consumer needs
  machine-readable fields beyond the slug; the terminal `milpa-error:` line
  covers the harness's need (and structured lines can precede it later).
- Spec versioning ceremony before stabilization — Gap 1 amends
  `cli-contract.md` §3 in place; `v1` is stamped at stabilization.
- Cross-time byte-equality on live-network runs (only against pinned refs).

## Issues this RFC will spawn (when it lands)

Sequencing matters: **#1 blocks #2** — the black-box runner can only pass error
fixtures once both CLIs actually emit the terminal slug line (review finding). And
**#2 is infrastructure only**: re-running the existing 117-fixture corpus through
the black-box runner produces *no novel signal* (both impls already pass it). The
harness is not operational as a spec-hardening tool until **#3** lands a
generator; **#2 + #3 together are the minimum viable differential harness**
(round-2 finding — don't close #2 thinking the harness is "done").

1. **Gap-1 terminal error line.** (a) `cli-contract.md` §3 = R1–R4 contract +
   the no-`milpa-error:`-prefix prohibition; (b) `conformance-fixtures.md` §5
   item 4 reword ("`.code` matches") + §3.1 NORMATIVE reword (same stale
   in-process language — both need updating to "emitted a terminal
   `milpa-error: <slug>` line"); (c) **Python `cli.py`** emit `milpa-error:
   <slug>` (thread `.code` through every coded exception); (d) **Rust `main.rs`**
   change `<code>: <msg>` → terminal slug line + install top-level panic handler
   emitting `milpa-error: INTERNAL-PANIC` before exit 1; (e) audit every
   documented exit-1 path in cli-contract §§5.1–5.8 for missing catalog slugs
   (e.g., `add --git` ref-discovery failure, unrecognized `--strategy` value,
   `verify` with missing `_deps/`) and add any missing slugs; (f) smoke-check
   both CLIs via subprocess. **No corpus `expected/` files change.**
2. Neutral CLI black-box runner + impl-descriptor struct (all impls `Direct` per the
   §2a build/run split — Rust via its prebuilt binary, no per-fixture container) + §2b
   normalization + divergence record (Gap 2a/2b/2e); re-run the existing corpus
   through it for Python + Rust. *Depends on #1.*
3. Differential generator harness + directory-shrink + tier-1/2 generators +
   shrink→pin→corpus loop (Gap 2c). *Depends on #2.*
4. Parser fuzz targets feeding the same loop (Gap 2d). *Depends on #1; parallel
   with #2.*
5. **Fixture-format extension** for the §2f gaps: `cmd=manifest-mutate` +
   `expected/milpa.kdl` for add/remove/update, and a `show`-format decision
   (freeze + `expected/stdout`, or keep liveness-only). *Independent.*
6. Python rewrite tracking item: build to this contract (the three MUSTs above).
   *Folds in #1c.*

## Cross-references

- `docs/spec/conformance-fixtures.md` — fixture format + black-box diff (reused
  wholesale; nothing added here).
- `docs/spec/cli-contract.md` §3 — the error-channel gap this RFC closes.
- `docs/spec/errors.md` — the slug catalog the `code` field carries.
- `docs/rfc-property-based-testing.md` — the shrink → pin → promote pipeline,
  here extended cross-impl.
- `docs/rfc-multi-impl-strategy.md` — why the spec, not any impl, is the oracle.
- `docs/rfc-rust-port-design.md` — the S15 stretch slice this RFC supersedes.
