# milpa CLI contract (S15)

Normative spec of the milpa command-line interface. Every implementation
that claims milpa conformance MUST implement the behaviour marked
`> NORMATIVE:`. Items marked `> NOTE:` describe the reference Python
implementation; conformant alternatives MAY differ in those details.

This document covers **conformance-tested verbs, global flags, exit codes,
stdout/stderr routing, and environment variables**. Related specs:

- `spec/resolver-semantics.md` (S6) — `--frozen` no-network and
  solver-bypass guarantees; prior-lockfile pin reuse
- `spec/identity.md` (S12) — CAS layout; `MILPA_CACHE_DIR` layout
- `spec/manifest-grammar.md` (S4) — predicate keys and
  platform/arch vocabulary that `MILPA_TARGET_*` override
- `spec/errors.md` — error codes emitted to stderr

---

## Normative surface

A conformant implementation of this spec MUST:

1. Expose the eight conformance-tested verbs: `fetch`, `lock`, `show`,
   `verify`, `clean`, `add`, `remove`, `update`.
2. Accept `-C <dir>` (or `--directory <dir>`) as a global flag that
   resolves the working directory before any verb executes.
3. Accept `--frozen` as a global flag; apply its exit-1 semantics only
   to `fetch` (the only verb with a frozen fast-path).
4. Accept `-s`/`--strategy` with the three values `maxver`, `minver`,
   `semver`; default to `maxver` when absent.
5. Accept `-j`/`--parallel` as a global concurrency limit; default to 8.
6. Route all human-readable diagnostic output to **stderr**; route all
   machine-readable output (currently only `milpa show`'s dep tree) to
   **stdout**.
7. Exit 0 on success; exit 1 on any diagnosed failure; exit 2 on an
   argument-parse / usage error (§3). On any exit-1 failure, emit exactly
   one terminal `milpa-error: <SLUG>` line to stderr (§3, R1–R4).
8. Honour `MILPA_TARGET_PLATFORM`, `MILPA_TARGET_ARCH`, `MILPA_TARGET_NIM`,
   and `MILPA_TARGET_MILPA` as overrides for conditional-dep predicate
   evaluation; these affect the resolved graph and are normative.
9. Honour `MILPA_CACHE_DIR` as the CAS root override; the default
   search order is `MILPA_CACHE_DIR` → `$XDG_CACHE_HOME/milpa/cas` →
   `~/.cache/milpa/cas`.
10. Mark `publish` as outside spec v1.0 conformance (see §10).
11. Implement the workspace detection algorithm described in §7.1 (parent
    traversal; package manifests transparent; unparseable manifests absent;
    membership check; orphan warning).
12. Honour `MILPA_INDEX_URL` as an override for the tianguis index URL
    (§8.1); required for air-gapped and mirror deployments.
13. Honour `MILPA_MOCKED_FETCHES` as the deterministic conformance fetch
    transport (§8.4); required for black-box corpus conformance.
14. Accept `--certificate <path>` as a global flag; when given, write the
    result certificate as JSON to `<path>` for every solver-running verb
    (`fetch`, `lock`) — on both success and failure outcomes (§2.5).
15. Accept `--require-attested-metadata` as a global flag (S5 attestation
    policy, §8.5); also honour `MILPA_REQUIRE_ATTESTED_METADATA` as an
    environment variable with the same effect. Effective strict policy =
    logical OR of the manifest `attestation-policy "strict"` field, the
    CLI flag, and the environment variable. The flag/env CANNOT weaken a
    manifest-declared strict policy.
16. Accept `--features <list>`, `--no-default-features`, and `--all-features`
    on `fetch`, `lock`, and `update` (S9, §2.7); also honour
    `MILPA_CLI_FEATURES`, `MILPA_NO_DEFAULT_FEATURES`, and `MILPA_ALL_FEATURES`
    as the corresponding environment-variable forms used by the conformance
    harness.
17. Accept `--require-attested-index` as a global flag; escalates the effective
    `index-trust` policy from `warn` to `strict`; MUST NOT set or clear `off`
    (§2.8, `spec/registry-protocol.md §3.4.5`). Also honour `MILPA_INDEX_TRUST`
    as the environment-variable form of the index-trust policy (§8.6).
18. Accept `--refresh-index` as a global flag; forces a fresh index and bundle
    fetch, bypassing the cache TTL (§2.9, §8.6).
19. Honour `MILPA_INDEX_HISTORY` as the environment-variable form of the
    `index-history` policy axis (§8.7, `spec/registry-protocol.md §3.5.2`);
    expose the `milpa index status` / `milpa index accept` verb family
    (§5.12) for inspecting and accepting append-only-ratchet state.

---

## 1  Invocation form

```
milpa [--version] [-C <dir>] [-j <N>] [-s <mode>] [--frozen] [--certificate <path>] [--require-attested-metadata] [--require-attested-index] [--refresh-index] <verb> [<verb-args>]
```

> NORMATIVE: The implementation MUST support the short flag `-C` (and
> equivalently the long flag `--directory`) to specify a project directory.
> All path resolution within a verb MUST be relative to the resolved
> `<dir>`, not the process working directory at invocation.

> NORMATIVE: When invoked with no verb, the implementation MUST print
> help text to stdout and exit 0.

> NOTE: The reference Python implementation resolves `<dir>` with
> `Path(args.directory).resolve()` before dispatching, so the verb
> functions receive an absolute path (`project_dir`).

---

## 2  Global flags

All global flags are parsed before the verb and apply to any verb that
uses them. Verbs that have no use for a flag silently ignore it.

### 2.1  `-C <dir>` / `--directory <dir>`

> NORMATIVE: Changes the effective project directory for the duration of
> the invocation. MUST be resolved to an absolute path before any
> filesystem operation. Default: `.` (the process working directory).

### 2.2  `-j <N>` / `--parallel <N>`

> NORMATIVE: Maximum number of concurrent fetch operations. MUST be a
> positive integer. Default: `8`. A value of `1` enforces serial fetching.

> NOTE: Parallelism is implemented via `concurrent.futures.ThreadPoolExecutor`
> in `resolver.py`. The flag is forwarded as `max_parallel` to `resolve()`.

### 2.3  `-s <mode>` / `--strategy <mode>`

> NORMATIVE: Resolution strategy. Accepted values:
>
> - `maxver` (default) — select the highest version satisfying constraints
> - `minver` — select the lowest version satisfying constraints (useful for
>   library authors verifying minimum-version compatibility)
> - `semver` — select the highest version within the same major as the
>   constraint's lower bound
>
> The strategy is recorded in `milpa.lock` and MUST match when
> `--frozen` is used (mismatch raises `FROZEN-STRATEGY-MISMATCH` and,
> with `--frozen`, exits 1). Cross-reference S6 for selection semantics.

> NORMATIVE: An implementation MUST reject any `--strategy` value not in
> the set `{maxver, minver, semver}`.

### 2.4  `--frozen`

> NORMATIVE: When `--frozen` is given and the frozen fast-path
> **preconditions fail** (no lockfile, CAS miss, manifest drift, strategy
> mismatch, or any other `NotFrozen` reason), the implementation MUST
> print the failure reason to stderr and exit 1. It MUST NOT fall through
> to network-based resolution.

> NORMATIVE: When `--frozen` is given and the frozen fast-path
> **succeeds**, the implementation MUST exit 0 after writing `nim.cfg`
> and MUST NOT contact any network resource.

> NORMATIVE: When `--frozen` is **absent** and the frozen fast-path
> succeeds, the implementation MUST take the fast-path (no network). When
> the fast-path fails, it MUST silently fall through to the full
> network-based resolve.

> NOTE: `--frozen` is currently effective only for `fetch`. Other verbs
> receive the flag but do not inspect it. The no-network and
> solver-bypass guarantees for the frozen path are specified in S6
> (`spec/resolver-semantics.md`); this document specifies only the
> flag-level exit semantics.

> NOTE: The reference implementation performs the frozen fast-path
> attempt unconditionally in `_try_frozen` / `_try_workspace_frozen`; the
> `frozen` boolean only gates whether a `NotFrozen` result is an error or
> a silent fallthrough.

### 2.5  `--certificate <path>`

This flag provides an exit-code–orthogonal channel for the result certificate
defined in `spec/resolver-semantics.md` §5. It applies to the solver-running
verbs (`fetch` and `lock`) — the only verbs that invoke the resolver and produce
a solve result. All other verbs silently ignore it.

> NORMATIVE: When `--certificate <path>` is given and the verb runs the resolver,
> the implementation MUST write the solve result as a JSON document to `<path>`,
> regardless of whether the resolve succeeded or failed. The write is
> **orthogonal** to the normal exit-code and slug discipline (R1–R4):
>
> - **SATISFIABLE resolve:** write the success certificate (§2.5.1), exit 0,
>   emit NO `milpa-error:` line — as usual.
> - **UNSATISFIABLE resolve (`SOLVE-CONFLICT`):** write the failure certificate
>   (§2.5.2), AND exit 1 with the normal `milpa-error: SOLVE-CONFLICT` slug —
>   as if `--certificate` were absent. The certificate never suppresses a slug.
>
> The write MUST be **atomic**: the implementation MUST write to a sibling
> temporary file and rename it into place. On any failure before the rename
> (disk error, serialisation error) the file at `<path>` MUST be left
> absent or unchanged (consistent with the §5.6 atomic-write discipline used
> for `milpa.lock` and `milpa.kdl`).

> NORMATIVE: `--certificate` MUST NOT add or suppress any `milpa-error:` slug
> line. R1–R4 are unaffected. The certificate is a side-output; it carries no
> new error codes. A tooling consumer that wants the resolve outcome reads the
> certificate JSON `kind` field; it MUST NOT rely on the presence or absence of
> `--certificate` to change the exit-code semantics.

#### 2.5.1  Success certificate JSON schema

> NORMATIVE: On a SATISFIABLE resolve the certificate MUST be a JSON object of
> the following schema (derived from `resolver-semantics.md` §5.1):
>
> ```json
> {
>   "kind": "success",
>   "resolved": [
>     {"package": "<name>", "version": "<semver>"},
>     ...
>   ],
>   "witness": [
>     {
>       "package":      "<name>",
>       "version":      "<semver>",
>       "constraint":   "<constraint-string>",
>       "satisfied_by": "<consuming-package-name>"
>     },
>     ...
>   ]
> }
> ```
>
> Field semantics (cross-reference `resolver-semantics.md` §5.1):
>
> - `kind` — the string literal `"success"`. The discriminant field; always
>   present.
> - `resolved` — an array of `{package, version}` objects, one per package in
>   the solved graph. `package` is the dep name (string); `version` is the
>   selected version as a semver string `X.Y.Z`. The validity predicate
>   requires every named package to be in the candidate set.
> - `witness` — an array of `{package, version, constraint, satisfied_by}`
>   objects, one per declared dep constraint across all resolved packages.
>   `package` is the dep name; `version` is the selected version for that dep;
>   `constraint` is the constraint string as declared by the consuming package;
>   `satisfied_by` is the name of the package that declared the constraint.
>   The validity predicate is:
>   `VersionSet.from_constraint(constraint).contains(parse_version(version))`.
>   Every declared constraint across all resolved packages MUST appear as
>   exactly one entry.
>
> Array ordering:
>
> - `resolved` entries MUST be ordered lexicographically by `package` name
>   (consistent with the canonical emission order defined in
>   `resolver-semantics.md` §4.4).
> - `witness` entries MUST be ordered in the same lexicographic-by-dep-name
>   order as `resolved`; within entries for the same `package`, ordering is
>   by `satisfied_by` (lexicographic). This order is deterministic and
>   implementation-independent.

> NOTE: The reference serialiser is `certificate_to_json` in `solver.py` (the
> new `impls/python-ng` impl) and its Rust equivalent. It produces the JSON
> with `indent=2` (two-space indentation). The indentation style is NOT
> byte-normative for the conformance check: the `check-certificate` fixture
> type (`conformance-fixtures.md` §2.7.3) compares parsed JSON objects, not
> raw bytes.

> NORMATIVE (S8, workspace-completion RFC §3.E): `--certificate` MUST be
> honored by workspace `fetch` and workspace `lock` in **both** implementations.
> A workspace resolves as one shared graph; the certificate schema (§2.5.1 /
> §2.5.2) is defined over that graph and does not change for the workspace case.
> Workspace members appear in `resolved` and `witness` under their `name` field
> (exactly like any other dep). The workspace `__root__` package appears as the
> top-level satisfier for direct member deps.
>
> Conformance check: the `check-certificate` fixture type compares parsed JSON
> objects (NOT bytes). Python emits `json.dumps(indent=2)`; Rust hand-rolls a
> compact layout — the bytes legitimately differ while the objects are equal.
> The harness normalises via `_canonical_certificate` before comparing, so both
> implementations produce a conformance-passing result from the same fixture.
> Workspace certificate fixtures are `CliOnly` in the in-process Rust corpus
> (same as single-package certificate fixtures); the binding gate is the
> black-box harness (`python -m harness --fixture …`), NOT
> `./dev-rust test --workspace` (which skips `CliOnly` fixtures).

#### 2.5.2  Failure certificate JSON schema

> NORMATIVE: On an UNSATISFIABLE resolve the certificate MUST be a JSON object
> of the following schema (derived from `resolver-semantics.md` §5.2):
>
> ```json
> {
>   "kind": "failure",
>   "message": "<human-readable conflict prose>",
>   "refutation": [
>     {"package": "<name>", "constraint": "<constraint-string>"},
>     ...
>   ]
> }
> ```
>
> Field semantics (cross-reference `resolver-semantics.md` §5.2):
>
> - `kind` — the string literal `"failure"`. The discriminant field; always
>   present.
> - `message` — a human-readable description of the conflict. This field is
>   present but is **NOT byte-normative**: two conformant implementations MAY
>   render the conflict prose differently; neither is wrong. Conformance
>   checking MUST NOT byte-compare `message`.
> - `refutation` — an array of `{package, constraint}` objects forming the
>   weak UNSAT core (`resolver-semantics.md` §5.2). Each entry names a package
>   and a constraint that contributed to the unsatisfiability. The named set
>   MUST be genuinely unsatisfiable — no version assignment satisfies all
>   constraints simultaneously. The conformance check (`check-certificate`
>   fixture type, §2.7.3) asserts the set is genuinely unsatisfiable; it does
>   NOT require byte-identical `refutation` arrays.

> NORMATIVE: On an UNSATISFIABLE resolve the implementation MUST ALSO exit 1
> with `milpa-error: SOLVE-CONFLICT` on stderr (the normal R1–R4 failure
> protocol). Writing the failure certificate does NOT replace that line and does
> NOT count as the `milpa-error:` line. R2 still requires exactly one
> `milpa-error:` line on stderr.

### 2.6  `--no-index`

> NORMATIVE: `--no-index` resolves with **no tianguis index** (offline /
> air-gapped). URL and local deps resolve normally; any named dep that would
> require the index MUST raise `RES-NO-INDEX` (a named dep in a workspace
> member raises `RES-WS-NO-INDEX`). It is the explicit, discoverable spelling
> of an empty `MILPA_INDEX_URL` (§8.1, the "present but empty" state) and MUST
> behave identically to it.

> NORMATIVE: `--no-index` **overrides any configured index** — it takes
> precedence over a non-empty `MILPA_INDEX_URL` and over the default index URL.
> The flag can only ADD the no-index condition; a configured index MUST NOT
> silently re-enable index resolution when `--no-index` is given. Equivalently,
> the effective "no index" condition is `--no-index` **OR** empty
> `MILPA_INDEX_URL`.

> NOTE: `--no-index` is parsed as a global flag and applies to any verb that
> performs resolution (`fetch`, `lock`, `add`, `remove`, `update`, `verify`).
> Verbs that never consult the index are unaffected.

### 2.7  `--features <list>` / `--no-default-features` / `--all-features` (S9)

These three verb-level flags select which root-manifest feature flags are active
during resolution (RFC #23 §3.4). They apply to `fetch`, `lock`, and `update`.

> NORMATIVE: `--features <list>` accepts a comma-separated list of flag names
> declared in the root manifest's `flags {}` block. Each named flag is activated
> on the root manifest for the duration of the resolve. Names MUST be declared;
> an undeclared name MUST raise `FROZEN-ACTIVE-FLAGS-MISMATCH`.

> NORMATIVE: `--no-default-features` suppresses all flags whose `default=#true`
> in the root manifest. Only flags named in `--features` are then active.

> NORMATIVE: `--all-features` activates every flag declared in the root manifest's
> `flags {}` block, regardless of their `default` value. When both
> `--all-features` and `--features` are given, `--all-features` takes precedence
> and all flags are activated.

> NORMATIVE: Under `--frozen`, the implementation MUST recompute the root
> active-flag closure from the manifest + CLI inputs, then verify it matches
> the lockfile (i.e., every flag-gated root dep admitted by the closure appears
> in the lock, and no flag-gated root dep absent from the closure appears in
> the lock). A mismatch MUST raise `FROZEN-ACTIVE-FLAGS-MISMATCH`.

> NORMATIVE: The feature-selection flags are root-manifest-only; they do not
> propagate to transitive deps. Cross-package flag propagation uses the
> edge-request mechanism (RFC #23 §3.1 S3, `flag "x"` child on a dep
> declaration).

> NOTE: `MILPA_CLI_FEATURES` (comma-separated), `MILPA_NO_DEFAULT_FEATURES`
> (non-empty non-false value), and `MILPA_ALL_FEATURES` (non-empty non-false
> value) are the corresponding environment-variable forms, used by the
> conformance harness to drive these flags via the fixture `env` file.

### 2.8  `--require-attested-index`

> NORMATIVE: When `--require-attested-index` is given, the effective
> `index-trust` policy (see `spec/registry-protocol.md §3.4.5`) is escalated
> from `warn` to `strict` for the duration of the invocation. This flag MAY
> ONLY strengthen the policy (warn→strict). It MUST NOT set or clear `off`.
> When the manifest declares `index-trust "off"`, the flag has no effect —
> `off` is a positive, auditable opt-out that only the committed manifest can
> declare (§3.4.5 effective-policy rule 1).

> NORMATIVE: `--require-attested-index` MUST NOT interfere with or imply
> `--require-attested-metadata` (§15, §8.5). These are DISTINCT flags governing
> DISTINCT policy axes: `--require-attested-index` governs whole-index Sigstore
> verification; `--require-attested-metadata` governs per-dep DepDecl attestation.
> Setting one has no effect on the other.

> NOTE: This flag is the CLI companion to `MILPA_INDEX_TRUST=strict` (§8.6).
> The difference: the env var persists across all invocations in a shell session;
> the flag applies only to one invocation. Both respect the authority model —
> neither can override a manifest `off`.

### 2.9  `--refresh-index`

> NORMATIVE: When `--refresh-index` is given, the implementation MUST bypass
> the index cache TTL and perform a fresh network fetch of both the index and
> its bundle sidecar, regardless of the cached file's age. The fresh
> (index, bundle) pair MUST be verified (per `spec/registry-protocol.md §3.4.4`)
> and, on success, cached as normal. The flag is idempotent — applying it when
> the cache is already fresh has no observable effect beyond the network fetch.

> NORMATIVE: `--refresh-index` is the documented remediation step after a
> pre-RFC cache warm (no bundle sidecar exists). A warm cache lacking a bundle
> sidecar triggers `TNG-INDEX-BUNDLE-MISSING` under `warn` policy; running
> `milpa fetch --refresh-index` forces re-fetch with bundle acquisition and
> produces the `.index.kdl.bundle` sidecar for future cache reads.

> NOTE: `--refresh-index` does NOT change the trust policy; it only bypasses the
> cache TTL. Under `strict` policy, if the freshly fetched bundle fails
> verification, the resolve still fails as normal.

---

## 3  Exit-code taxonomy

> NORMATIVE: An implementation MUST exit with code `0` on success and
> code `1` on any **diagnosed failure** (a condition with an `errors.md`
> slug). Code `2` is reserved for **argument-parse / usage errors** (an
> invalid flag value, a missing required positional, an unrecognized
> flag). No other exit codes are defined for spec v1.0.

> NORMATIVE: Failure MUST produce at least one diagnostic line on stderr
> before exiting. An implementation MUST NOT exit non-zero silently.

There is no distinction between *diagnosed-error categories* at the
exit-code level (e.g., solver conflict vs network failure both exit 1).
Error **identity** is carried by a slug printed to stderr (e.g.,
`SOLVE-CONFLICT`, `FROZEN-IDENTITY-NOT-IN-STORE`) as specified in
`spec/errors.md`. Tooling that needs to distinguish failure kinds MUST
parse the slug, not the exit code.

### 3.1  The machine-readable error channel (`milpa-error:` line)

The slug above is carried by a dedicated, machine-parseable line so that
a language-neutral conformance runner can extract it without substring-
grepping free-form human prose (which may mention multiple slug-like
tokens and differs per impl by design).

> NORMATIVE (R1 — slug grammar): On a diagnosed failure (exit 1) stderr
> MUST contain a line of the exact form `milpa-error: <SLUG>`, where
> `<SLUG>` matches `^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$` (at least one hyphen
> segment) and is a code defined in `spec/errors.md`.

> NORMATIVE (R2 — exactly one, position-independent): On an exit-1
> failure there MUST be exactly one full-line match of
> `^milpa-error: <SLUG>$` anywhere in stderr, and **no other emitted line
> may begin with `milpa-error:`**. A conformance runner scans all stderr
> lines for the unique match and validates it against the catalog; it
> MUST NOT rely on line position (a stack trace, a finalizer, or
> container startup noise emitted after the slug line does not corrupt
> extraction). Zero matches is a crash verdict (R4); two or more is a
> protocol-violation reported as a harness-level failure. Impls SHOULD
> emit the slug line last for human readability, but the contract does
> not depend on it.

> NORMATIVE (R3 — iff exit 1): The `milpa-error:` line appears **if and
> only if** the process exits 1. An exit-0 run — including a `verify` run
> that emits drift *warnings* to stderr (§5.4) — MUST NOT emit a
> `milpa-error:` line. No non-error diagnostic line a conformant impl
> emits may begin with `milpa-error:`.

> NORMATIVE (R4 — crash is observable): Any exit with **no** terminal
> `milpa-error:` line is a **crash/panic verdict**, distinct from a clean
> diagnosed error. This covers exit 1 without the line (impl forgot to
> emit it), exit 2 (argument-parse failure — a usage/crash-class verdict,
> not an R1–R3 coded error; **no** `milpa-error:` line is expected), and
> any exit ≠ 0, ≠ 1 (e.g., a Rust panic exiting 101, an OOM kill exiting
> 137, signal termination). A conformance runner treats every exit ≠ 0,
> ≠ 1 as a crash-class verdict. Rust impls MUST install a top-level panic
> handler that emits `milpa-error: INTERNAL-PANIC` (or another catalog
> code) before exiting 1; an unhandled `panic!()` exiting 101 is a crash
> verdict.

A human still gets a readable message; impls MAY keep or improve their
human-facing rendering above the terminal line. A structured JSON error
format remains a trivial later addition — emitted as lines *before* the
terminal slug line, so it never conflicts with R2. The machine line is
present by default; there is no flag to enable it.

> NOTE: The reference Python implementation's outermost `main()` wrapper
> catches any exception escaping the typed handlers, emits the
> `MILPA-INTERNAL` sentinel, and exits 1 — making the R3 invariant
> mechanically enforceable. Argument-parse failures (Python `argparse`)
> exit 2 by default; the Rust CLI exits 2 from its parse-failure paths.

---

## 4  Stdout vs stderr routing

> NORMATIVE: All human-readable diagnostic output (progress, warnings,
> error messages) MUST be written to **stderr**.

> NORMATIVE: Machine-readable output — the dep tree printed by `milpa show`,
> the observability block printed by `show --index-trust` (§5.3a), and the
> status/diff block printed by `milpa index status` / `milpa index accept`
> (§5.12) — MUST be written to **stdout**.

> NORMATIVE: Verbs that produce no machine-readable output (`fetch`,
> `lock`, `verify`, `clean`, `add`, `remove`, `update`) MUST produce
> **no output on stdout** on a successful run.

> NOTE: The reference implementation follows this routing strictly for the
> verbs the NORMATIVE rules above govern. Within `cmd_publish` (§10,
> out-of-scope for conformance but described here for accuracy): the sole
> unguarded `print(…)` (no `file=` argument) is the `--dry-run` plan render,
> which is JSON meant for inspection or `--output` piping — by design, not
> incidentally. Every other `cmd_publish` path is diagnostic and goes to
> stderr: the real-run one-line confirmation
> (`published <name>@<version> -> <oci_ref>`, printed only when `--output`
> is absent) uses `file=sys.stderr`, and a real (non-dry-run) publish with
> `--output` given prints nothing to stdout at all.
> `cmd_show` writes its dep-tree lines to stdout (the implicit default).

---

## 5  Conformance-tested verbs

### 5.1  `fetch`

**Purpose:** Resolve the manifest, clone all deps into `_deps/`, emit
`nim.cfg`, and write `milpa.lock`. Workspace-aware.

**Arguments:** none beyond global flags.

**Global flags used:** `-C`, `-j`, `-s`, `--frozen`.

**Frozen fast-path:** If a lockfile is present and the global CAS holds
every pinned identity, resolution skips fetching and only symlinks
`_deps/` from the CAS. With `--frozen`, any precondition failure exits 1.
Without `--frozen`, precondition failure falls through to full resolution.
See S6 for the no-network + solver-bypass guarantees.

> NORMATIVE: On success, `fetch` MUST:
>
> - Write or overwrite `<dir>/milpa.lock`.
> - Write or overwrite `<dir>/nim.cfg`.
> - Populate `<dir>/_deps/` with the fetched or CAS-linked source trees.
> - Print a summary line to stderr (`resolved N deps` or
>   `resolved N deps (frozen)`).
> - Exit 0.

> NORMATIVE: On any failure (manifest error, network failure, solver
> conflict, `--frozen` precondition miss), `fetch` MUST print a
> diagnostic to stderr and exit 1. Neither `milpa.lock` nor `nim.cfg`
> MUST be partially written: writes are atomic (write-then-rename) or
> the command exits 1 before reaching them.

> NOTE: Workspace mode is triggered when `workspace_containing(project_dir)`
> returns a non-None `Workspace`. In workspace mode a shared lockfile is
> written at `<ws_root>/milpa.lock` and per-member `nim.cfg` files are
> written at `<ws_root>/<member>/nim.cfg`. The stderr summary includes a
> member count.

**Exit codes:** 0 success, 1 failure.

**stdout:** none.

**stderr:** progress summary on success; diagnostic on failure.

### 5.2  `lock`

**Purpose:** Resolve the manifest and write `milpa.lock`; do NOT emit
`nim.cfg` or populate `_deps/`.

**Arguments:** none beyond global flags.

**Global flags used:** `-C`, `-j`, `-s`. (`--frozen` is accepted but has
no effect; `lock` always runs the full resolver.)

> NORMATIVE: On success, `lock` MUST:
>
> - Write or overwrite `<dir>/milpa.lock`.
> - Print a summary line to stderr (`locked N deps`).
> - Exit 0.
> - Leave `nim.cfg` and `_deps/` untouched.

> NORMATIVE: On any failure, `lock` MUST print a diagnostic to stderr
> and exit 1.

**Exit codes:** 0 success, 1 failure.

**stdout:** none.

**stderr:** `locked N deps` on success; diagnostic on failure.

### 5.3  `show`

**Purpose:** Read `milpa.lock` and print the resolved dep tree to
stdout. Does not resolve or fetch.

**Arguments:** none beyond `-C`.

**Global flags used:** `-C`.

> NORMATIVE: `show` MUST read `milpa.lock` from the project directory
> and print each dep as a block to stdout with at least: name, version,
> truncated identity (if present), provenance summary, and direct
> requires (if non-empty).

> NORMATIVE: If `milpa.lock` does not exist, `show` MUST print a
> diagnostic to stderr and exit 1.

> NOTE: The reference output format is:
>
> ```
> <name padded to 20 chars>  <version>
>   identity    <algo>:<first-8-hex-chars>
>   provenance  <transport> <url> @ <ref> (sha <first-8-sha-chars>)
>   requires    <dep1>, <dep2>
> ```
>
> The identity digest is truncated to 8 characters for readability.
> This format is incidental; a conformant implementation MAY use a
> different layout provided identity, provenance, and requires are
> distinguishable. Machine-readable `show` output format is NOT frozen
> for spec v1.0.

**Exit codes:** 0 success, 1 failure (no lockfile, parse error).

**stdout:** dep tree (one block per dep).

**stderr:** diagnostic on failure only.

> NOTE (workspace behavior — current, pending #165): `show` does **not**
> perform workspace detection. At a **workspace root**, `show` reads the
> shared `milpa.lock` from that directory and prints a flat shared-graph
> dump with no member attribution (the lockfile contains the entire
> resolved graph as a flat dep list). From a **workspace member directory**
> that has no member-local lockfile (the shared lock lives at the workspace
> root, not inside the member), `show` raises `LOCK-FILE-NOT-FOUND` because
> no `milpa.lock` exists at the `-C` directory. To show the shared graph
> from a member dir, use `milpa -C <workspace-root> show`. Member-scoped
> output (attributing each dep to its originating member) is tracked as a
> future enhancement in issue #165.

### 5.3a  `show --index-trust`

**Purpose:** Print the effective index-trust policy and the observable claims
from the locally-cached Sigstore bundle — no cryptographic verification, no
network access. A pure observability/debugging tool.

**Arguments:** `--index-trust` flag on the `show` subcommand.

**Global flags used:** `-C` (ignored; the command reads the XDG/env-derived
index cache, not a project directory).

> NORMATIVE: `show --index-trust` MUST:
> - Print the effective index-trust policy string (`warn`, `strict`, or `off`)
>   as `policy:` in the output block.
> - Report whether the index file and the Sigstore bundle sidecar are present
>   in the local cache (`index-cached:` and `bundle-cached:` fields, `yes`/`no`).
> - If and only if a bundle is cached and parseable as a JSON object with a
>   valid `verificationMaterial.tlogEntries[0].integratedTime`, print the
>   following additional fields: `signer:`, `issuer:`, `integrated:`,
>   `subject-sha256:`, `rekor-entry:`, `freshness:`.
> - MUST NOT print a cryptographic verification verdict (`verified ✓/✗`).
>   Claims are printed as-is from JSON fields; verification is enforced at
>   `fetch`/`lock` time, not by this command.
> - Produce output that is byte-identical between all conformant implementations.

> NORMATIVE: The output format uses a **fixed 16-character label+colon column**
> so values align in a single column. Every label (including the trailing colon)
> occupies exactly 16 characters. Trailing whitespace MUST NOT appear on any line.

> NORMATIVE: The canonical field set and format:
>
> ```
> index-url:      <url>
> policy:         <warn|strict|off>
> index-cached:   <yes|no>
> bundle-cached:  <yes|no>
> ```
>
> When a bundle is cached and parseable, the following additional fields are
> appended in this order:
>
> ```
> signer:         <SAN or (not available)>
> issuer:         <OIDC issuer or (not available)>
> integrated:     <unix epoch seconds>
> subject-sha256: <hex digest or (not available)>
> rekor-entry:    <log index integer or (not available)>
> freshness:      <fresh|stale>
> ```
>
> Freshness: `fresh` if `now - integrated_time < max_age_seconds`, else `stale`.
> Default `max_age_seconds` is 604800 (7 days). Overridable via
> `MILPA_INDEX_MAX_AGE` env var (integer seconds).

> NORMATIVE (workspace root authority): index-trust is declared ONLY on the
> resolution root (`spec/registry-protocol.md §3.4.7`) — for a workspace, the
> workspace ROOT manifest. `show --index-trust` MUST resolve the effective
> policy from that single root value (no merge across members): if the
> current directory is a workspace member or root, find the workspace root
> and read its `index-trust` value (default `warn` if absent); otherwise read
> the standalone package manifest's value.

> NOTE: `signer:`, `issuer:`, and `subject-sha256:` are extracted from the
> `_milpa_claims` JSON section that the tianguis publishing workflow writes into
> every conformance-fixture mock bundle. Real Sigstore bundles do NOT contain
> this section (SAN and OIDC issuer are encoded in the DER certificate chain);
> those fields show `(not available)` until a dedicated X.509 extraction path is
> added (tracked as a future slice). The `integrated:` and `rekor-entry:` fields
> are extracted from `verificationMaterial.tlogEntries[0]` and are available in
> all real Sigstore bundles.

**Conformance fixtures:** `fixture-356` (fresh bundle), `fixture-357` (stale
bundle), `fixture-358` (index cached, no bundle).

**Environment variables consumed:**
- `MILPA_INDEX_URL` — index URL to report (defaults to the global default).
- `MILPA_INDEX_TRUST_MANIFEST` — manifest-declared policy (used as the `policy:`
  display value in fixtures; the live CLI derives the effective policy via the
  full `effective_trust_policy` logic from §8.6).
- `MILPA_INDEX_MAX_AGE` — freshness window in seconds (default 604800).
- `MILPA_SHOW_NOW` — injected unix timestamp for deterministic freshness in
  conformance fixtures (conformance runners MUST use this value when set;
  production CLI uses `SystemTime::now()`).

**Exit codes:** 0 always (even when bundle is absent or claims are unavailable).

**stdout:** the fixed-format observability block (above).

**stderr:** empty.

### 5.4  `verify`

**Purpose:** Recheck every dep in `_deps/` against `milpa.lock` using
content hashes. Does not fetch.

**Arguments:** none beyond `-C`.

**Global flags used:** `-C`.

> NORMATIVE: `verify` MUST:
>
> - Compute the content hash of each directory under `_deps/`.
> - Compare against the `identity` field in `milpa.lock`.
> - Detect extra (unlocked) entries in `_deps/` (excluding dotfiles).
> - If all hashes match and there are no extra entries, print a summary
>   to stderr and exit 0.
> - If any divergence is found, print every divergence to stderr and
>   exit 1.

> NORMATIVE: If `milpa.lock` does not exist, `verify` MUST print a
> diagnostic to stderr and exit 1. If `_deps/` does not exist, `verify`
> MUST print a diagnostic to stderr and exit 1.

> NORMATIVE: For deps with a `local` provenance, `verify` MUST emit a
> **warning** (not an error) to stderr when the source directory's
> current content hash differs from the lockfile pin, then continue and
> exit 0 if no other divergence exists. Local source drift is advisory
> because local sources are mutable by design; the user is instructed to
> re-run `milpa fetch` to refresh the pin.

> NOTE: Workspace mode is triggered when `workspace_containing(project_dir)`
> returns a non-None `Workspace`. In workspace mode `verify` checks
> `<ws_root>/_deps/` against the shared lockfile and reports across all
> members.

> NORMATIVE (S11b / Breadth-P2c): `verify` MUST run the
> `FROZEN-ACTIVE-FLAGS-MISMATCH` check for **both** single-package and
> workspace manifests. The workspace frozen-flags check reuses the same
> SSOT helper as the `fetch --frozen` path (S2); it runs with manifest
> defaults (no CLI feature overrides at verify time) BEFORE the disk-state
> check, so the correct slug fires when the lockfile was produced under a
> different feature selection.

**Exit codes:** 0 success (all hashes match), 1 failure (any divergence,
missing lockfile, or missing `_deps/`).

**stdout:** none.

**stderr:** `verified N deps` on success; divergence list on failure;
local-source drift warnings are printed regardless of exit code.

### 5.5  `clean`

**Purpose:** Remove `_deps/` and `nim.cfg`; keep `milpa.lock`.

**Arguments:** none beyond `-C`.

**Global flags used:** `-C`.

> NORMATIVE: `clean` MUST remove `<dir>/_deps/` (recursively) and
> `<dir>/nim.cfg` if they exist. It MUST leave `milpa.lock` untouched.
> It MUST exit 0 even if `_deps/` or `nim.cfg` do not exist (idempotent).

> NORMATIVE: When removing `_deps/` recursively, implementations MUST NOT
> follow symlinks into their targets.  Only the symlink entries themselves
> (and any non-symlink content directly under `_deps/`) are removed.  This
> rule protects both local-dep source trees (which are live, user-owned
> directories outside the project) and CAS store entries (which are shared
> across projects).  A correct implementation uses `rm -rf _deps/` or an
> equivalent that removes the symlinks themselves, not their targets.

> NORMATIVE: In workspace mode, `clean` MUST remove `<ws_root>/_deps/`
> and each member's `nim.cfg`.

> NOTE: `clean` produces no stdout or stderr output on success in the
> reference implementation. An implementation MAY emit a confirmation
> line to stderr.

**Exit codes:** 0 always.

**stdout:** none.

**stderr:** none (reference implementation); MAY emit a confirmation.

### 5.6  `add`

**Purpose:** Add a new dep to `milpa.kdl` (with `--git`), or record a
declared mirror URL on an existing dep (with `--mirror`). `--git`
validates by running a full resolve before writing. `--mirror` is a pure
manifest mutation — no network fetch, no lockfile write.

**Arguments:**

```
milpa add <dep> --git <url> [--ref <ref>]
milpa add <dep> --mirror <url>
```

> NORMATIVE: `add` with `--git` MUST:
>
> - Reject if `<dep>` is already declared in `milpa.kdl`
>   (`dep <name> already declared`; exit 1).
> - If `--ref` is omitted, discover the remote's default branch via
>   `git ls-remote --symref HEAD` (or the mocked-fetches tree under
>   `MILPA_MOCKED_FETCHES`); if discovery fails, fail with
>   `FETCH-REF-DISCOVERY-FAILED` (exit 1).
> - Run a full resolve over the proposed manifest (manifest + new dep).
> - On successful resolve, atomically write the updated `milpa.kdl` and
>   `milpa.lock`.
> - Print `added <name> (git=<url> ref=<ref>)` to stderr and exit 0.
> - On any failure, leave `milpa.kdl` and `milpa.lock` unmodified.

> NORMATIVE: `add` with `--mirror` MUST:
>
> - Reject if `<dep>` is not declared in `milpa.kdl`; exit 1.
> - Reject if `<dep>` is not a URL dep (git-backed `UrlDep`) — local,
>   member, named, or tarball deps cannot carry mirrors; emit
>   `MAN-MIRROR-EDITABLE-PROVENANCE` and exit 1.
> - Exit 0 without rewriting `milpa.kdl` if `<url>` is already a mirror
>   for `<dep>` (idempotent).
> - Otherwise atomically append `<url>` to the dep's `mirrors` block in
>   `milpa.kdl` ONLY. MUST NOT fetch `<url>`, MUST NOT verify bytes, and
>   MUST NOT write `milpa.lock`.
> - Print `added mirror <url> for <dep>` to stderr and exit 0.
> - On any failure, leave `milpa.kdl` unmodified.
>
> NOTE: The declared mirror is an author CLAIM. It is written into the
> lockfile as a `declared` provenance block on the next `milpa lock`
> (see D-lifecycle slice) and is verified against the locked identity at
> USE time (D-fallback). This two-phase design preserves the
> observed/declared provenance model: an unverified record is never
> written directly into `milpa.lock`.

> NORMATIVE: `add` without `--git` or `--mirror` MUST print a usage
> error to stderr and exit 2 (a usage/crash-class verdict per §3.1 R4;
> no `milpa-error:` slug line, like any argument-parse failure).

> NORMATIVE (S11a): `add` invoked at a **workspace root** MUST emit
> `MAN-MUTATE-WORKSPACE-REFUSED` (exit 1) with a directive message:
> *"to add a dep, `cd` to a member; to add a member, use
> `milpa workspace add-member`"*. It MUST NOT attempt to parse the
> manifest as a package manifest.

> NORMATIVE (S11e): `add` invoked from a **workspace member directory**
> (a directory that is a declared member of a parent workspace) MUST
> detect the parent workspace, mutate the **member's** `milpa.kdl` to
> add the new dep, then re-resolve the **entire workspace** (all
> members), writing the shared `<ws_root>/milpa.lock` and shared
> `<ws_root>/_deps/`. A member-local `milpa.lock` MUST NOT be written.
> The success message is the same as for single-package `add`.

**Exit codes:** 0 success, 1 failure.

**stdout:** none.

**stderr:** summary on success; diagnostic on failure.

### 5.7  `remove`

**Purpose:** Remove a dep from `milpa.kdl` and regenerate the lockfile.

**Arguments:**

```
milpa remove <dep>
```

> NORMATIVE: `remove` MUST:
>
> - If `<dep>` matches a `dep.aliases` entry in the prior lockfile (not a
>   top-level lockfile dep name), resolve it to the canonical dep name before
>   any manifest check (alias→canonical resolution).
> - Reject if the canonical dep name is not declared in `milpa.kdl` (exit 1).
> - If the prior lockfile recorded `aliases` for the removed canonical dep,
>   emit a warning to stderr per alias (whether or not the alias is still
>   required transitively). Removal still proceeds (warning, not error).
> - Run a full resolve over the proposed manifest (manifest minus `<dep>`).
> - On successful resolve, atomically write the updated `milpa.kdl` and
>   `milpa.lock`.
> - Print `removed <canonical-name>` to stderr and exit 0.
> - On any failure, leave `milpa.kdl` and `milpa.lock` unmodified.

> NOTE: Orphaned transitives that were only required by `<dep>` disappear
> naturally from the new lockfile via the full re-resolve. If `<dep>` is
> still required transitively by another dep, it remains in the resolved
> graph; removal from the manifest does not force removal from the graph.
> The manifest MUST NOT be modified in this case — if the dep is still
> in the graph it was never a top-level dep requiring removal from
> `milpa.kdl`.

> NORMATIVE (S11a): `remove` invoked at a **workspace root** MUST emit
> `MAN-MUTATE-WORKSPACE-REFUSED` (exit 1) with a directive message:
> *"to remove a dep, `cd` to a member; to remove a member, use
> `milpa workspace remove-member`"*. It MUST NOT attempt to parse the
> manifest as a package manifest.

> NORMATIVE (S11e): `remove` invoked from a **workspace member directory**
> MUST detect the parent workspace, resolve any alias against the
> **shared** `<ws_root>/milpa.lock`, mutate the **member's** `milpa.kdl`
> to remove the dep, then re-resolve the **entire workspace**, writing
> the shared `<ws_root>/milpa.lock` and shared `<ws_root>/_deps/`. A
> member-local `milpa.lock` MUST NOT be written. The success message is
> the same as for single-package `remove`.

**Exit codes:** 0 success, 1 failure.

**stdout:** none.

**stderr:** `removed <name>` on success; per-alias warning(s) before the
success line when the removed dep had prior lockfile aliases; diagnostic on
failure.

### 5.8  `update`

**Purpose:** Re-resolve and refresh the lockfile, optionally scoped to a
single dep. Does not mutate `milpa.kdl`.

**Arguments:**

```
milpa update [<dep>]
```

> NORMATIVE: `update` with no `<dep>` argument MUST drop all pins and
> re-resolve the entire graph from scratch; the resulting `milpa.lock`
> may select different versions for any dep.

> NORMATIVE: `update <dep>` MUST:
>
> - If `<dep>` matches a `dep.aliases` entry in the lockfile (not a top-level
>   dep name), resolve it to the canonical dep name before the guard (alias→
>   canonical resolution). The check "is `<dep>` in the lockfile" MUST match
>   both canonical names and aliases.
> - Reject if neither `<dep>` nor any dep's alias matches (exit 1).
> - Carry forward the updated dep's prior **declared** mirror provenances
>   (those with `origin="declared"` in the prior lockfile entry), filtered to
>   URLs still declared in `milpa.kdl`; drop any declared URL whose mirror
>   entry was removed from the manifest. Concretely: the dep's filtered-prior
>   entry has `identity=None` (forces fresh re-resolve) and retains only its
>   declared provenances (no observed/commit pin).
> - All other deps' pins are retained as a prior lockfile.
> - Re-resolve; all other deps are stable unless their provenance changes.
> - Write the new `milpa.lock`.
> - Print `updated <name>` to stderr and exit 0.

> NORMATIVE: `update` MUST NOT mutate `milpa.kdl`; only `milpa.lock`
> and `_deps/` change. `update` MUST NOT emit `nim.cfg` in either
> single-package or workspace mode.

> NORMATIVE: If `<dep>` is provided but `milpa.lock` does not exist,
> `update` MUST print a diagnostic to stderr and exit 1 (no lockfile
> means no prior pins to drop selectively; a full `milpa fetch` is the
> correct action).

> NORMATIVE (S11b): `update` invoked at a **workspace root** MUST perform
> the full workspace re-resolve: drop the specified dep's pin (or ALL pins
> when no dep is named) → re-resolve the shared graph across all members →
> refresh the shared `<ws_root>/milpa.lock`. The behavior mirrors the
> single-package path; no verb emits a confusing internal error at a
> workspace root.

> NORMATIVE (S11e): `update` invoked from a **workspace member directory**
> MUST detect the parent workspace and delegate entirely to the workspace
> re-resolve path (identical behavior to S11b above). The shared
> `<ws_root>/milpa.lock` is written; a member-local `milpa.lock` MUST NOT
> be written.

**Exit codes:** 0 success, 1 failure.

**stdout:** none.

**stderr:** `updated <name>` or `updated all deps` on success; diagnostic
on failure.

---

### 5.9  Workspace per-member `nim.cfg` — `self_src_dir` ordering (normative)

**Context:** `fetch` and `lock` in workspace mode write a `nim.cfg` for each
member (§5.1 NOTE, §5.2). The emission ordering rule below applies to every
workspace nim.cfg written by these commands.

**Normative ordering:** For each workspace member, the implementation MUST
emit `--path:` lines in the following order:

1. **Self-src-dir (self-first, mandatory):** If the member's manifest declares
   a `src_dir`, the implementation MUST emit `--path:"<src_dir>"` as the
   **first** `--path:` line in that member's `nim.cfg`. This gives the
   member's own source tree shadowing priority over all dep import paths —
   the same rule as single-package emission (`format_nimcfg` self-first rule).
   If the member has no `src_dir`, no self-path line is emitted.
2. **Dep paths, lex-sorted:** All dep paths (member-to-member references and
   external deps) are emitted after the self-src-dir line, sorted
   lexicographically by dep name — the same single canonical ordering rule
   as single-package emission (resolver-semantics §4.4).

The trailing `nim.cfg` header logic is unchanged: a member with only a
self-src-dir and no deps still receives the full `nim.cfg` header + the
self-src-dir `--path:` line (not header-only).

> NOTE: This ordering is byte-normative across implementations.
> `conformance/spec-v1/fixture-262-s7-ws-member-self-src-dir` is the
> canonical 3-member fixture (A→B, B→C; A has `src_dir "src"`) that pins
> A's self-first + lex-sort ordering.

---

### 5.10  `workspace add-member` / `workspace remove-member` (D4)

Two grouped verbs under the `workspace` subcommand that mutate the workspace
manifest's `member` list. Both follow the same validate→resolve-in-memory→
write-manifest→write-lock atomicity contract as `add` and `remove` (§5.6/§5.7):
the workspace manifest and lockfile are only written on a successful in-memory
resolution of the modified workspace. On any failure both files are left
unmodified.

#### `milpa workspace add-member <path>`

Adds a workspace member at `<path>` (relative to the workspace root supplied
by `-C`).

**Validation rules (in order; checked before any mutation):**

1. `<path>` must be an existing directory → `WS-MEMBER-DIR-MISSING`
2. `<path>/milpa.kdl` must exist → `WS-MEMBER-NO-MANIFEST`
3. `<path>/milpa.kdl` must be a **package** manifest (not a workspace manifest)
   → `WS-MEMBER-IS-WORKSPACE`
4. The package manifest must declare a `name` → `MAN-NAME-MISSING`
5. No existing workspace member may share that name → `WS-MEMBER-DUPLICATE-NAME`

On success: the member's relative path is appended to the `workspace { member …
}` block; the workspace is re-resolved in memory; `milpa.kdl` (updated member
list) and `milpa.lock` are written atomically. Exit 0. Diagnostic: `added
member "<name>"` to stderr.

#### `milpa workspace remove-member <name|path>`

Removes a workspace member identified by its declared package name, relative
path, or absolute path.

**Validation rules (in order; checked before any mutation):**

1. `<name|path>` must match a declared member → `WS-REMOVE-MEMBER-NOT-FOUND`
2. The workspace root's `overrides {}` block must contain no `pkg { member
   "<name>" }` rule targeting the member being removed →
   `WS-REMOVE-MEMBER-TARGET-EXISTS`
3. No remaining workspace member's `deps` or `dev_deps` may carry a `member
   "<name>"` edge pointing at the member being removed →
   `WS-REMOVE-MEMBER-REFERENCED`

On success: the member's entry is removed from the `workspace { member … }`
block; the workspace is re-resolved in memory; `milpa.kdl` (updated member
list) and `milpa.lock` are written atomically. Exit 0. Diagnostic: `removed
member "<name>"` to stderr.

> NORMATIVE (D4): Both verbs MUST be grouped under the `workspace`
> subcommand — i.e. invoked as `milpa workspace add-member` / `milpa workspace
> remove-member`, not as top-level verbs. A conformant implementation MUST
> route the verb `workspace` to the subcommand dispatcher; an unrecognised
> sub-verb under `workspace` exits 2.

> NOTE: These verbs are `cmd=workspace` fixtures in the conformance corpus
> (`fixture-265` through `fixture-272`). They are `CliOnly` from the
> in-process conformance runner's perspective (no library entry point), driven
> exclusively by the black-box harness.

### 5.11  `hash` (A0-cmd)

**Purpose:** Probe the content identity of a source without producing any
persistent output. Intended for build-pipeline use — a caller can pin the
identity returned here and later use it as the `expected_identity` when
fetching from the same source.

**Arguments:**

```
milpa hash <token> [<token>...]
```

Source spec tokens (same grammar as `parse_source_spec`):

| Form | Tokens |
|---|---|
| git | `git=<url> ref=<commit-sha-or-ref>` |
| local | `local=<path>` |
| oci | `oci=<registry>/<repository>@sha256:<64hex>` |

> NORMATIVE: `milpa hash` MUST:
>
> - Parse the source spec tokens via `parse_source_spec`; on any parse error
>   emit `CLI-SOURCE-SPEC-INVALID` and exit 1.
> - Fetch the source into a **scratch/throwaway** destination using the SAME
>   fetcher machinery that `milpa fetch` uses (the bare `FetcherRegistry`,
>   NOT the CAS-admitting wrapper). This produces the content identity via the
>   same code path as a real `milpa fetch`.
> - Print the content identity to **stdout** as exactly one line
>   (`sha256:<64hex>`) for CAS-admissible sources (git, tarball, OCI).
> - Print **nothing** to stdout for non-admissible (local/editable) sources
>   — local trees have no stable identity in milpa's model
>   (lockfile §4.3 NORMATIVE).
> - Discard the scratch directory; MUST NOT write `milpa.lock`, populate
>   `_deps/`, or admit any entry to the CAS.
> - Exit 0 on success.

> NORMATIVE: `milpa hash` MUST NOT call `compute_content_hash` or any hash
> function directly. The identity MUST come from the fetch result's
> `.identity` field — the same field the resolver and CAS-admission path
> rely on. A direct hash call would reintroduce a dual-derivation path that
> this command exists to eliminate.

> NOTE: git auth inherits the same environment (SSH agent, credential helper)
> that `milpa fetch` uses — no additional auth configuration is required or
> accepted.

**Exit-code / slug table:**

| Condition | Exit code | Slug |
|---|---|---|
| Success | 0 | — |
| Bad source spec | 1 | `CLI-SOURCE-SPEC-INVALID` |
| git/fetch errors | 1 | `FETCH-GIT-FAILED`, `FETCH-GIT-COMMIT-ABSENT`, etc. (same as `fetch`) |

**stdout:** `sha256:<64hex>` (one line) for CAS-admissible sources; empty for
local sources.

**stderr:** diagnostic on failure only.

### 5.12  `milpa index status` / `milpa index accept`

Two grouped verbs under an `index` subcommand — the inspection and
explicit reset surface for the append-only consumer ratchet
(`spec/registry-protocol.md §3.5`). This is the third instance of the
nested-subparser pattern `workspace add-member`/`remove-member` (§5.10)
established: sub-verbs routed through one `index` dispatcher, an
unrecognised sub-verb exits 2.

**Purpose:** `status` is a read-only inspection tool — it reports the
locally-cached append-only-ratchet state (and, with `--refresh`, previews
what a forced refresh would find) without ever writing to disk. `accept`
performs the same forced-refresh diff and then, and only then, atomically
swaps the local trust baseline — it is the sole sanctioned way to absorb a
detected history change (`spec/registry-protocol.md §3.5.1`'s "no in-band
correction path" clause).

**Arguments:**

```
milpa index status [--refresh]
milpa index accept
```

Neither verb takes a URL argument in v1: both operate on the effective
index URL for the current invocation, resolved exactly as `fetch` resolves
it (§8.1).

**Global flags used:** `-C` (workspace/member resolution).

> NORMATIVE: `milpa index status` MUST:
>
> - Resolve the effective index URL and, when invoked from a workspace
>   member directory, delegate to the workspace root (S11e symmetry — the
>   same delegation `add`/`update` already perform, §5.6/§5.8): root-only
>   axis, one baseline per effective URL, no member-level state.
> - Without `--refresh`: read ONLY the local baseline sidecar pair for
>   that URL (`<cache-key>.index.kdl.baseline` / `.baseline.meta`,
>   `spec/registry-protocol.md §3.5.2`/`§6`) and print the fixed-format
>   status block below to stdout. MUST NOT perform a network fetch.
> - Never write to disk, under any invocation of this verb — including
>   `--refresh`.
> - Report `baseline: corrupt` in the status block (rather than raising
>   `TNG-INDEX-BASELINE-CORRUPT`) when the baseline sidecar exists but
>   fails to parse. `status` is a read-only inspection tool and MUST NOT
>   hard-fail on a broken local trust state — it exists in part to let an
>   operator discover that state safely.

> NORMATIVE (status block, fixed format): the canonical field set, in this
> order, using the same fixed-width label-column convention as
> `show --index-trust` (§5.3a; a 19-character label+colon column, no
> trailing whitespace on any line):
>
> ```
> index-url:         <url>
> policy:            <off|warn|strict>
> baseline:          <present|absent|corrupt>
> established-at:    <ISO-8601 timestamp, or (none)>
> pending:           <yes|no>
> last-reported:     <ISO-8601 timestamp, or (none)>
> ```
>
> `pending` and `last-reported` are read from `.baseline.meta`'s
> `reported_digest` / `reported_at` (an empty or absent `reported_digest`
> means `pending: no`, `last-reported: (none)`). When `baseline` is
> `absent` or `corrupt`, `established-at`, `pending`, and `last-reported`
> are printed as `(none)`, `no`, and `(none)` respectively — there is no
> observed history to report on.

> NORMATIVE (`--refresh`): with `--refresh`, `status` additionally performs
> the SAME fetch-and-verify sequence `accept` performs (below) — a network
> fetch of the candidate index, verified under the effective `index-trust`
> policy (`spec/registry-protocol.md §3.4`) — and then prints the would-be
> diff, using the three-branch shape and violation-line format specified
> under `accept` below, WITHOUT writing the bundle sidecar, the index
> file, the freshness stamp, or the baseline pair (the dry-run of `accept`;
> `terraform plan` shape). If the forced fetch itself fails (network
> error, or a Layer-1 rejection under `index-trust "strict"`), `status
> --refresh` fails with that error and touches no cache state — the
> `--refresh-index` precedent (§2.9).

> NORMATIVE (exit code): `milpa index status` exits 0 when there is no
> attention-worthy state — baseline absent (nothing established yet); or,
> without `--refresh`, `.meta` reports no pending violation set; or, with
> `--refresh`, the dry-run diff is clean — and exits 1 otherwise (baseline
> corrupt; or a nonempty violation set, either `.meta`'s recorded pending
> set without `--refresh`, or the dry-run diff with `--refresh`). This
> makes the exit code a scriptable CI gate ("am I sitting on an unresolved
> history violation, and since when").

> NORMATIVE: `milpa index accept` MUST:
>
> - Resolve the effective index URL and workspace root exactly as `status`
>   does (member-dir delegates to root, S11e).
> - Perform a network fetch of the candidate index, verified under the
>   effective `index-trust` policy (§3.4). If this fetch fails, `accept`
>   fails with that error and MUST NOT touch the baseline pair or any
>   other cache state (the `--refresh-index` precedent, §2.9).
> - Compute the diff against the local baseline exactly as the ratchet
>   check does (`spec/registry-protocol.md §3.5.2`), across all three
>   baseline states, and print exactly one of:
>   - **present and parseable** — the full composite-ordered violation
>     diff (the violation-line format below): what is about to be
>     accepted. An empty violation set prints `nothing to accept` instead
>     and performs no baseline write (the idempotent no-op case, below).
>   - **absent** (TOFU) — `no prior baseline — this fetch establishes the
>     trust anchor` (there is no diff to show).
>   - **corrupt** (`TNG-INDEX-BASELINE-CORRUPT` state) — `baseline
>     unreadable — cannot show what changed; re-establishing the trust
>     anchor` (same anchor-establishment semantics as TOFU, explicit about
>     the blindness).
> - On a nonempty violation set that includes an `attestation-epoch`
>   root-field change (`spec/registry-protocol.md §3.5.1`), print an
>   additional line, visually distinct from the per-violation lines,
>   naming the blast radius before the ordinary diff output: accepting
>   this change reclassifies every entry between the epochs as
>   pre-epoch/legacy, nullifying the attestation mandate for all of them —
>   an index-wide consequence, not a one-row one.
> - **Atomically** swap the baseline: write
>   `<cache-key>.index.kdl.baseline` (temp + rename) from the fetched
>   candidate, then rewrite `.baseline.meta` (`reported_digest` cleared,
>   `established_at` restamped to the current time). A baseline-write
>   failure MUST be a loud, distinct error — never a
>   printed-diff-then-silent-no-op — and MUST leave the previous baseline
>   pair intact.
> - Exit 0 on success, including the empty-violation-set no-op case.

> NORMATIVE (violation-line format, shared by `status --refresh` and
> `accept`): each violation is printed to stdout as one tab-joined line,
> in composite-key order (`spec/registry-protocol.md §3.5.3`), with the
> label `violation:` followed by the 8-tuple `class`, `namespace`, `name`,
> `version`, `field`, `kind`, `baseline_value`, `candidate_value` — absent
> components rendered as empty strings, values exactly as they appear in
> the document (never re-formatted). This is the same tuple the canonical
> violation digest (`spec/registry-protocol.md §3.5.3`) is computed over,
> with `baseline_value` additionally included for human/script
> consumption. A trailing `digest: <sha256-hex>` line reports the
> canonical digest of the printed violation set, for correlation with
> `.baseline.meta`'s `reported_digest`.
>
> Yank-state transitions observed while computing the diff are reported
> the same way the ordinary ratchet check reports them
> (`spec/registry-protocol.md §3.5.3`'s `[milpa] warning:` stderr line) —
> on stderr, not folded into the stdout diff — and do not affect either
> verb's exit code or `accept`'s no-op decision (yank transitions are
> legal and do not block a clean-diff no-op).

> NORMATIVE (contract points):
>
> - Both verbs are **non-interactive** by design: no confirmation prompt,
>   no `--yes` flag. `accept` is already an explicit, deliberate verb, and
>   its printed diff is the record of what was accepted.
> - `accept` is **idempotent**: running it again immediately after a
>   successful accept sees a clean diff against the just-written baseline
>   and prints `nothing to accept`, exit 0.
> - Diff output goes to **stdout**, in the fixed format above, and MUST be
>   byte-identical across conformant implementations (the
>   `show --index-trust` precedent, §5.3a).
> - Both verbs are **per-URL**: they operate on the effective index URL
>   for the current invocation; there is no cross-URL batch mode in v1.
> - Invoked from a **workspace member directory**, both verbs delegate to
>   the root (S11e symmetry): root-only axis, one baseline per effective
>   URL, no member-level state.
> - Under **`--no-index`**, both verbs error: there is no index to load
>   or compare against.
> - Under **`index-history "off"`**, `status` still reports (including
>   that the axis is off, in the `policy:` field) and `accept` still
>   works, but `accept` additionally warns that the baseline it writes
>   will not be consulted again until the axis is re-enabled.
> - Under **`index-trust "off"`**, the fetched candidate has NO
>   cryptographic basis — the diff an operator confirms via `accept`
>   attests to continuity of whatever content the transport delivered,
>   nothing more. Both verbs MUST print this caveat (or an equivalent
>   sentence) whenever the effective `index-trust` policy is `off`; it
>   MUST NOT be read as "out-of-band confirmation that the rewrite is
>   legitimate" — that guarantee does not exist in this configuration.

> NOTE: These verbs are `cmd=index` fixtures in the conformance corpus,
> landing with `rfc-registry-append-only.md`'s A4b slice; the fixture
> matrix is enumerated in that RFC's Conformance strategy section. Like
> `workspace add-member`/`remove-member` (§5.10), they are expected to be
> `CliOnly` from the in-process conformance runner's perspective.

**Conformance fixtures:** land with `rfc-registry-append-only.md`'s A4b
slice.

**Environment variables consumed:** `MILPA_INDEX_URL`, `MILPA_INDEX_TRUST`
and its siblings (§8.6), `MILPA_INDEX_HISTORY` (§8.7).

**Exit codes:** `status` — 0 (no attention-worthy state) / 1 (corrupt
baseline, or a nonempty pending/diff violation set). `accept` — 0 on
success (including the no-op case) / 1 on fetch failure or baseline-write
failure.

**stdout:** the fixed-format status/diff block described above; empty on
failure before any block is printed.

**stderr:** progress/diagnostic messages, yank-transition notices, and (on
failure) the error diagnostic.

---

## 6  `--frozen` flag/exit semantics (normative)

This section specifies the CLI-level semantics of `--frozen`. The
resolver-level guarantees (no network access; solver bypass; lockfile is
used as-is without re-running PubGrub) are specified in
`spec/resolver-semantics.md` §7.1 (S6), which is the **authoritative
source** for the complete list of frozen-fast-path disqualifying conditions.

> NORMATIVE: The frozen fast-path is disqualified by any of the conditions
> enumerated in `spec/resolver-semantics.md` §7.1. For convenience the
> full list of disqualifying error codes is reproduced here; the resolver-
> semantics document is authoritative in case of any discrepancy:
>
> - `FROZEN-STRATEGY-MISMATCH` — requested strategy differs from the
>   lockfile's recorded strategy
> - `FROZEN-MANIFEST-DEP-NOT-IN-LOCK` — a manifest dep has no lockfile entry
> - `FROZEN-LOCKED-VERSION-UNPARSEABLE` — a locked version string cannot be
>   parsed as X.Y.Z
> - `FROZEN-CONSTRAINT-UNSATISFIED` — a named dep's locked version no longer
>   satisfies the manifest constraint
> - `FROZEN-IDENTITY-NOT-IN-STORE` — a dep's pinned identity is absent from
>   the CAS
> - `FROZEN-LOCAL-DEP` — a dep has a local provenance (editable trees always
>   re-resolve)
> - `FROZEN-MEMBER-DEP` — a dep is a workspace member (members always
>   re-resolve in single-package mode)
> - `FROZEN-MEMBER-NOT-IN-WORKSPACE` — the lockfile references a workspace
>   member that is absent from the current workspace definition
> - `FROZEN-MEMBER-IDENTITY-DRIFT` — a workspace member's on-disk content
>   hash differs from the lockfile pin

> NORMATIVE: When `--frozen` is absent and the frozen fast-path fails
> for any reason, the implementation MUST silently fall through to the
> full resolution path. The failure reason MUST NOT be printed.

> NORMATIVE: When `--frozen` is present and the frozen fast-path fails
> for any reason, the implementation MUST print the `NotFrozen` reason to
> stderr in the form `frozen: <reason>` and exit 1. The full resolution
> path MUST NOT be attempted.

> NORMATIVE: When `--frozen` is present and the frozen fast-path
> succeeds, the implementation MUST exit 0 after writing `nim.cfg`. No
> network request MUST occur.

---

## 7  `-C <dir>` working-directory semantics

> NORMATIVE: The `-C <dir>` flag MUST be resolved to an absolute path at
> parse time. All subsequent path lookups — `milpa.kdl`, `milpa.lock`,
> `_deps/`, `nim.cfg` — MUST be joined against this resolved path, not
> against the process working directory.

> NORMATIVE: A relative `<dir>` MUST be resolved relative to the process
> working directory at invocation time.

> NORMATIVE: `-C` applies before workspace detection. The resolved
> `<dir>` is the starting point for `workspace_containing()`.

> NOTE: The reference implementation calls `Path(args.directory).resolve()`
> immediately after argument parsing. The resulting absolute `project_dir`
> is passed to every `cmd_*` function.

### 7.1  Workspace detection algorithm

> NORMATIVE: An implementation MUST detect whether the resolved `-C <dir>` is
> inside a workspace using the following parent-traversal algorithm
> (`workspace_containing` in `milpa/workspace.py`):
>
> 1. Start from `<dir>` (resolved to an absolute path per §7).
> 2. Walk up the directory tree one level at a time.
> 3. At each directory, check whether a `milpa.kdl` file exists. If it does:
>    - Attempt to parse it. If the parse fails (e.g., syntax error), treat
>      the file as **absent** and continue walking upward.
>    - If the parse succeeds and the document is a **package manifest** (no
>      top-level `workspace {}` block), the file is **transparent** — continue
>      walking upward. Package manifests along the walk do NOT terminate
>      discovery; workspace members carry their own package manifest.
>    - If the parse succeeds and the document is a **workspace manifest**
>      (contains a top-level `workspace {}` block), this directory is
>      the **workspace root** — stop walking.
> 4. If the filesystem root is reached without finding a workspace manifest,
>    workspace mode is NOT active; return `None`.
>
> After finding a workspace root, the implementation MUST:
>
> 5. Load the workspace manifest and resolve all declared member directories.
> 6. Verify that `<dir>` is either the workspace root itself **or** exactly
>    the resolved directory of one of the declared members. If neither, return
>    `None` (the workspace found does not legitimately contain `<dir>`).
> 7. Return the loaded `Workspace` value.

> NORMATIVE: When walking past package manifests in step 3, the implementation
> MUST NOT emit any diagnostic. The transparent-package behavior is by design
> (it lets `milpa -C <member-dir>` discover the workspace above the member).

> NORMATIVE: When `load_workspace` scans the workspace root for depth-1
> subdirectories that contain a `milpa.kdl` but are NOT declared as members,
> the implementation MUST emit a warning to stderr per orphaned directory:
>
> ```
> warning: <rel>/milpa.kdl exists but is not declared as a workspace member
>          (add `member "<rel>"` to the workspace block to include it)
> ```
>
> This warning MUST NOT cause the workspace load to fail.

> NOTE: The membership check in step 6 guards against the "accidental ancestor"
> scenario — a workspace manifest higher up the tree that happens to be an
> ancestor of `<dir>` but does not declare it as a member. Only declared
> members are activated; an undeclared subdirectory is not silently enrolled.

---

## 8  Environment variables

### 8.1  Resolution-affecting (normative)

These variables affect the resolved dep graph and MUST be honoured by
any conformant implementation.

#### `MILPA_TARGET_PLATFORM`

> NORMATIVE: When set, this value MUST be used as the `platform` key in
> the resolution `Profile` instead of the auto-detected host platform.
> Accepted values are Nim `hostOS` names: `linux`, `macosx`, `windows`,
> `freebsd`, `openbsd`, `netbsd`. Unknown values are passed through
> without rejection; a `when platform="X"` predicate that names an
> unknown platform simply will not match.

> NORMATIVE: Setting `MILPA_TARGET_PLATFORM` enables cross-resolution:
> deps gated on `when platform="windows"` will be included (or excluded)
> correctly for the named target even when resolving on a different host.

#### `MILPA_TARGET_ARCH`

> NORMATIVE: When set, this value MUST be used as the `arch` key in the
> resolution `Profile` instead of the auto-detected host architecture.
> Accepted values are Nim `hostCPU` names: `amd64`, `arm64`, `i386`.
> Unknown values are passed through without rejection.

#### `MILPA_TARGET_NIM`

> NORMATIVE: When set, this value MUST be used as the Nim version in the
> resolution `Profile` instead of the version queried from `nim --version`.
> The value MUST be a semver string `X.Y.Z`. If `nim` is not installed and
> `MILPA_TARGET_NIM` is not set, the Nim version defaults to `"0.0.0"` and
> `when nim="X"` predicates will not match.

#### `MILPA_TARGET_MILPA`

> NORMATIVE: When set, this value MUST be used as the milpa version in the
> resolution `Profile` instead of the implementation's own version
> (`milpa.__version__`). The value MUST be a semver string `X.Y.Z`. This
> override is evaluated by `when milpa="..."` predicates (§6.4 of S4) and
> enables testing version-gated conditional deps without changing the
> installed binary.

> NOTE: The four `MILPA_TARGET_*` env vars are read in
> `Profile.from_environment()` (`milpa/profile.py`). `profile.py` maps
> Python's `platform.system()` and `platform.machine()` strings to Nim's
> `hostOS`/`hostCPU` vocabulary; the env var override bypasses that
> mapping entirely. The canonical vocabulary tables are in
> `spec/manifest-grammar.md` §6.

#### `MILPA_INDEX_URL`

> NORMATIVE: Three-way semantics based on **presence vs value**, not just
> truthiness:
>
> | State | Behavior |
> |---|---|
> | **Absent** from env | Load from `DEFAULT_INDEX_URL` (live tianguis; see below). Network failure → soft `index=None`; resolver raises `RES-NO-INDEX` only when a named dep actually needs the index. |
> | **Present but empty** (`""`) | Explicitly NO index. `index=None` without any network attempt. Used by the conformance harness for air-gapped fixtures that contain no `index.kdl`. |
> | **Present and non-empty** | Load from that URL. Any HTTP(S) or `file://` URL pointing to a valid `index.kdl` is accepted. |
>
> The default index URL is:
>
> ```
> https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl
> ```
>
> This three-way design is required so that `milpa fetch` works out of the
> box in production (no env var needed for named deps), while the conformance
> harness can opt out of the network entirely by setting `MILPA_INDEX_URL=""`
> for air-gapped fixtures.

> NORMATIVE: A `file://` URL MUST be accepted as a non-empty value.
> This is what lets a black-box conformance harness point each impl
> at a fixture's local `index.kdl` (`MILPA_INDEX_URL=file:///abs/path/index.kdl`)
> without standing up an HTTP server — the index analog of the
> `MILPA_MOCKED_FETCHES` local fetch transport (§8.4). Both reference impls
> handle the `file://` scheme natively (Python `urllib.request.urlopen`;
> Rust `curl`).

> NOTE: See `spec/conformance-fixtures.md §2.2` for the harness-side contract:
> the harness ALWAYS sets `MILPA_INDEX_URL`, either to a `file://` path (when
> `index.kdl` is present in the fixture) or to the empty string (when no index
> file is present, keeping the fixture air-gapped).

### 8.2  CAS root (normative)

#### `MILPA_CACHE_DIR`

> NORMATIVE: When set, this value MUST be used as the root of the
> content-addressed store instead of the XDG-derived default. The value
> MUST be an absolute path to a directory (which will be created if
> absent).

> NORMATIVE: `MILPA_CACHE_DIR` takes precedence over a manifest-level
> `cas { dir "..." }` override. Precedence order (highest first):
>
> 1. `MILPA_CACHE_DIR` env var
> 2. Manifest `cas { dir "..." }` (relative paths resolved against
>    the project root)
> 3. `$XDG_CACHE_HOME/milpa/cas`
> 4. `~/.cache/milpa/cas`

> NOTE: `default_store()` in `milpa/cas.py` implements this precedence.
> The CAS layout (`<root>/<algorithm>/<hex>/`) is specified in
> `spec/identity.md` (S12).

### 8.3  Convenience / infrastructure (non-normative)

These variables affect operational behaviour but do NOT affect the
resolved dep graph. An implementation MAY ignore them.

#### `XDG_CACHE_HOME`

Used as the base for both the CAS default path (`$XDG_CACHE_HOME/milpa/cas`)
and the tianguis index cache (`$XDG_CACHE_HOME/milpa/index`). Standard
XDG Base Directory specification. Not milpa-specific.

#### `ACTIONS_ID_TOKEN_REQUEST_TOKEN` / `ACTIONS_ID_TOKEN_REQUEST_URL`

GitHub Actions OIDC token environment variables consumed by `publish`
(out-of-scope for conformance; see §10). Not relevant to resolution.

### 8.4  Conformance fetch transport (normative)

#### `MILPA_DEP_DECL_DIR`

This is the env var that makes DepDecl artifact resolution **black-box
testable**: it lets a language-neutral conformance harness point any impl
at a directory of pre-authored DepDecl artifact files instead of the
production `HttpDepDeclStore`'s network fetch. It is the DepDecl analog of
`MILPA_MOCKED_FETCHES` for git/tarball fetches and `MILPA_INDEX_URL` for
the tianguis index.

> NORMATIVE: When `MILPA_DEP_DECL_DIR` is set to a non-empty value, it
> MUST be the path to a `dep-decl/` directory as specified in
> `spec/conformance-fixtures.md` §2.11. The implementation MUST swap the
> production `HttpDepDeclStore` for a `FileDepDeclStore` that satisfies
> every DepDecl artifact lookup exclusively from that directory — no
> network access and no HTTP client consulted. For each lookup the
> `FileDepDeclStore` MUST:
>
> 1. Derive the filename from the pointer's sha256 digest:
>    `$MILPA_DEP_DECL_DIR/<sha256_hex>.kdl` (where `<sha256_hex>` is the
>    64-character lowercase hex from the `dep_decl` field in the index
>    version-node, with the `sha256:` prefix stripped).
> 2. If the file does not exist, raise `TNG-DEPDECL-FETCH-FAILED`.
> 3. Read the file bytes, verify `sha256(bytes) == sha256_hex`; on
>    mismatch raise `TNG-DEPDECL-HASH-MISMATCH`.
> 4. Parse the bytes as a DepDecl artifact (`spec/dep-decl.md` §2); on
>    parse failure raise `TNG-DEPDECL-PARSE-ERROR`.
> 5. Return the resulting `EdgeSet`.

> NORMATIVE: When `MILPA_DEP_DECL_DIR` is unset or empty, the
> production `HttpDepDeclStore` is used; transport selection is
> unaffected.

> NORMATIVE: `MILPA_DEP_DECL_DIR` is a **conformance-only** env var —
> like `MILPA_MOCKED_FETCHES` and `MILPA_INDEX_URL`. It MUST be honoured
> by **all** conformant implementations. It MUST NOT affect the resolved
> dep graph other than by substituting the DepDecl artifact source; the
> `EdgeSet` content (requires, src_dir) is the same whether it came from
> the network or from the local file.

> NOTE: In the reference implementations the store swap is performed at
> the CLI entry point: when `MILPA_DEP_DECL_DIR` is set, the
> `HttpDepDeclStore` instance is replaced by `FileDepDeclStore(dir)` and
> passed to the resolver. This is the single source of truth; the per-impl
> in-process conformance adapters delegate to the same store, so there is
> one code path for the directory convention. This is a testing/conformance
> store: it is inert unless the env var is explicitly set.

> NOTE: S3a (this section) specifies the env var contract and the
> `FileDepDeclStore` behaviour. The actual store-swap implementation is
> S3b. Until S3b lands, setting `MILPA_DEP_DECL_DIR` has no observable
> effect on either impl; the harness runner injects the var but the impls
> silently ignore it.

#### `MILPA_MOCKED_FETCHES`

This is the env var that makes the fixture corpus **black-box runnable**: it
lets a language-neutral harness drive any impl's CLI as a subprocess and have
its fetches satisfied deterministically from a directory, with no network and
no in-process fake-fetcher injection. It is the CLI-level counterpart of the
in-process fetcher that a per-impl test adapter would otherwise inject.

> NORMATIVE: When `MILPA_MOCKED_FETCHES` is set to a non-empty value, it MUST
> be the path to a `mocked-fetches/` directory as specified in
> `spec/conformance-fixtures.md` §2.3, and the implementation MUST satisfy
> **every** dependency fetch exclusively from that directory — the **mocked
> transport** — performing no network access and consulting no real transport
> (git/tarball/OCI/local). For each fetch the implementation MUST:
>
> 1. encode the candidate's `(url, ref)` to a subdirectory key per
>    conformance-fixtures.md §2.3.1;
> 2. if `<dir>/<key>/` does not exist, fail that candidate with
>    `FETCH-MOCK-MISSING`;
> 3. otherwise read `<key>/sha` (the returned commit SHA), copy the
>    `<key>/content/` tree into the fetch destination, copy `<key>/<name>.nimble`
>    into the destination root if present, and compute the content hash over the
>    destination per `spec/identity.md`.
>
> When `MILPA_MOCKED_FETCHES` is unset or empty, transport selection is
> unaffected.

> NORMATIVE: When `MILPA_MOCKED_FETCHES` is set, **ref-resolution** is also
> answered from the mocked transport with no network. Specifically, the
> default-branch discovery `add --git` performs when `--ref` is omitted (§5.6,
> `git ls-remote --symref HEAD`) MUST instead locate the unique
> `mocked-fetches/<key>/` entry whose decoded URL equals the requested URL and
> return that entry's ref (the ref component of the §2.3.1 URL-key). The fetch
> then proceeds against that same entry, so the entry's `sha` (read at fetch
> time) is the single source of truth for both ref-resolution and the returned
> commit SHA — no parallel ref→SHA mapping exists. If the entry is absent, ref
> discovery fails exactly as a network discovery failure would (§5.6: exit 1).

> NORMATIVE: The mocked transport participates in the §8a mirror-fallback
> candidate loop like any other transport: a `FETCH-MOCK-MISSING` candidate
> failure is folded into the candidate list, and an exhausted candidate list
> still terminates in `FETCH-ALL-FAILED` (the `FETCH-MOCK-MISSING` cause appears
> in the human message, not as the terminal `milpa-error:` slug). This keeps the
> observable error contract identical to the real transports.

> NORMATIVE: `MILPA_MOCKED_FETCHES` takes precedence over all real-transport
> selection and over a manifest-level `cas { dir }` transport choice; it does
> NOT override `MILPA_CACHE_DIR` (the mocked transport still admits fetched
> content into the CAS root resolved per §8.2).

> NOTE: In the reference implementations this is a single `MockedFetcher`
> (`milpa/fetchers/mocked.py`; `milpa-core` `fetchers.rs`) selected by the CLI
> when the env var is set; the per-impl in-process conformance adapters delegate
> to the **same** implementation, so there is one source of truth for the
> directory convention. This is a testing/conformance transport: it is inert
> unless the env var is explicitly set.

### 8.5  Attestation policy

#### `MILPA_REQUIRE_ATTESTED_METADATA`

> NORMATIVE: When `MILPA_REQUIRE_ATTESTED_METADATA` is set to a non-empty value
> that is not `"0"` or `"false"`, it activates **strict attestation policy** for
> the invocation. The effective strict policy is the logical OR of:
>
> 1. the manifest `attestation-policy "strict"` field (see
>    `spec/manifest-grammar.md` §attestation-policy);
> 2. the `--require-attested-metadata` CLI flag (§15 of the normative
>    requirements above); and
> 3. this environment variable.
>
> Setting this variable CANNOT weaken a strict policy already declared by the
> manifest. Under strict policy, any resolved named dep whose index entry carries
> no `dep_decl` pointer (i.e. whose `EdgeSet.source` is `NimbleFallback`) MUST
> cause the implementation to raise `RES-UNATTESTED-METADATA` (see
> `spec/errors.md`) and exit non-zero without writing any output files.
>
> Under permissive (default) policy — when none of the three sources above are
> active — the implementation MUST emit a single human-readable summary warning
> to stderr listing all deps resolved from un-attested `.nimble` metadata, and
> MUST NOT fail. The warning is informational and its exact format is
> non-normative.
>
> When no resolved named deps have `source == NimbleFallback`, both policies are
> silent (no warning, no error).

> NOTE: In the reference implementations the effective policy is computed as the
> logical OR of `Manifest.attestation_policy`, `Cli.require_attested_metadata`
> (set by either the flag or the env var), inside `enforce_attestation_policy()`
> (Rust: `milpa-core/src/resolver.rs`; Python-ng:
> `milpa/resolver.py::enforce_attestation_policy()`). The per-impl in-process
> conformance adapters read `MILPA_REQUIRE_ATTESTED_METADATA` from the fixture
> `env` file via `fixture_require_attested_metadata()` and pass it to `resolve()`
> directly, so there is one code path for both the CLI and the conformance runner.

### 8.6  Index attestation trust (normative)

These five variables control whole-index Sigstore verification (see
`spec/registry-protocol.md §3.4`). All five are normative — conformant
implementations MUST honour them. They are distinct from the dep-metadata
attestation axis governed by §8.5 (`MILPA_REQUIRE_ATTESTED_METADATA`); these
two axes govern different concerns and MUST NOT be conflated.

#### `MILPA_INDEX_TRUST`

> NORMATIVE: Sets the `index-trust` policy for the invocation. Accepted values:
> `warn` (default), `strict`, `off`.
>
> When unset, the effective policy is derived from the manifest `index-trust`
> field and the `--require-attested-index` flag per
> `spec/registry-protocol.md §3.4.5`.
>
> `MILPA_INDEX_TRUST=off` is a **no-op floor**: it CANNOT weaken a manifest
> `warn` or `strict` policy. Only a manifest `index-trust "off"` declaration
> (committed to version control) can disable the gate. Setting `off` in the
> environment has no effect when the manifest declares `warn` or `strict`.
>
> `MILPA_INDEX_TRUST=strict` or `=warn` MAY strengthen the effective policy
> (env `strict` beats manifest `warn`); they CANNOT override a manifest `off`.

> NOTE: This is the distinct env-var sibling of `MILPA_REQUIRE_ATTESTED_METADATA`
> (§8.5). The naming confirms they are separate axes: `MILPA_INDEX_TRUST` governs
> whole-index Sigstore verification; `MILPA_REQUIRE_ATTESTED_METADATA` governs
> per-dep DepDecl attestation. No collision exists.

#### `MILPA_INDEX_TRUST_SIGNER`

> NORMATIVE: When set to a non-empty value, overrides the expected signer
> IDENTITY for whole-index attestation. The value MUST be a GitHub Actions OIDC
> workflow URL or other SubjectAltName string expected in the signing certificate
> (e.g. `https://github.com/myorg/myregistry/.github/workflows/attest-index.yaml@refs/heads/main`).
>
> This variable overrides the signer IDENTITY only. It MUST NOT be used for
> trust-bundle (CA root) overrides — use `MILPA_INDEX_TRUST_BUNDLE` for that.
> `MILPA_INDEX_TRUST_SIGNER` MUST NOT accept a `file://` path.
>
> Use this variable (or the `index-trust-signer` manifest node) to configure
> the expected signer when running a private registry at a custom
> `MILPA_INDEX_URL`. When `MILPA_INDEX_URL` is non-default and no signer
> override is configured, `warn` policy emits a `TNG-INDEX-SIGNER-MISMATCH`
> warning; `strict` fails.

#### `MILPA_INDEX_TRUST_BUNDLE`

> NORMATIVE: When set to a `file://` path, overrides the embedded Fulcio CA
> root and Rekor public key bundle used for whole-index verification. The value
> MUST be a `file://` URL pointing to a valid Sigstore trust bundle JSON file.
> Values that are not `file://` paths MUST be rejected.
>
> This variable overrides the trust ROOT (Fulcio CA + Rekor public key). It is
> ORTHOGONAL to `MILPA_INDEX_TRUST_SIGNER` — changing one does not imply the
> other. Required for private Sigstore instances (e.g. a self-hosted Fulcio +
> Rekor deployment serving a private registry).

#### `MILPA_INDEX_MAX_AGE`

> NORMATIVE: Sets the freshness window for the whole-index bundle verification,
> in seconds. Default: `604800` (7 days).
>
> This bound is asserted as `now - SET.integratedTime < MILPA_INDEX_MAX_AGE` at
> network-fetch time ONLY (State 2 and recovery re-fetches, per §6 of
> `spec/registry-protocol.md`). It is NOT asserted on pure cache reads (States 1
> and 3), preserving offline / air-gapped use.
>
> `integratedTime` is embedded in the bundle; no live Rekor network query is
> needed for this check. Lowering the value tightens rollback-attack protection
> at the cost of more frequent network access. The 7-day default is a
> deployment-smoothness tradeoff.

#### `MILPA_INDEX_BUNDLE_URL`

> NORMATIVE: When set to a non-empty URL, overrides the normatively derived
> bundle URL (`spec/registry-protocol.md §3.4.2`) for the current index URL.
> Use this when the bundle is served from a separate host or when the path-suffix
> derivation is not viable (e.g. when the index URL has an unusual path structure
> incompatible with `.bundle` appending).
>
> Supports the same URL schemes as `MILPA_INDEX_URL`: HTTPS, HTTP, and
> `file://`. When set, the derivation algorithm in §3.4.2 is bypassed entirely.

#### `MILPA_INDEX_TRUST_MOCK_VERIFIER` (CONFORMANCE-INTERNAL)

> CONFORMANCE-INTERNAL: This variable is **not for production use**. It drives
> the `MockVerifier` seam in the shared S7 index-trust conformance corpus so the
> corpus can exercise the trust-gate policy state machine in both implementations
> without real Sigstore infrastructure.
>
> When set to one of the 7 wire strings (`trusted`, `sig-invalid`,
> `digest-mismatch`, `signer-mismatch`, `bundle-stale`, `bundle-missing`,
> `bundle-malformed`), the CLI injects a `MockVerifier` that returns that
> `VerificationResult` and ignores all other inputs. The gate (`enforce_index_trust`
> + effective policy computation) still runs normally against the injected result.
>
> **`file://` index URL restriction:** This variable is ONLY honored when the
> resolved index URL has a `file://` scheme. All conformance fixtures and
> hermetic tests use `file://` index URLs; production indexes are `https://`.
> If this variable is set (non-empty after trimming) and the resolved index URL
> does NOT have a `file://` scheme, the implementation MUST raise
> `MILPA-INTERNAL` and exit 1 immediately — fail closed and visible, never
> silently ignore or silently bypass verification. This rule prevents the mock
> seam from being accidentally activated against a real index URL in a
> misconfigured environment. Both reference implementations enforce this rule.
>
> An **invalid** value (not in the set of 7 wire strings) MUST cause the
> implementation to fail immediately with a `MILPA-INTERNAL` diagnostic and exit 1.
> The seam MUST NOT fail-open silently (silently treating an invalid value as
> `trusted` would mask misconfigured test environments and hide regressions).
>
> When absent or empty, the production verifier (`SigstoreVerifier`) is used — this
> variable has no effect on production invocations.
>
> **Cross-impl alignment:** Both reference implementations use the SAME variable
> name with the SAME value semantics (wire string as value, not a boolean flag +
> a second variable). The S7 conformance fixtures inject this variable via the
> fixture `env` file under the key `mock_verifier_result`, which the conformance
> runner maps to `MILPA_INDEX_TRUST_MOCK_VERIFIER` when driving the CLI path.

### 8.7  Index-history (append-only ratchet) axis (normative)

This variable controls the append-only consumer ratchet
(`spec/registry-protocol.md §3.5`) — a policy axis distinct from both
`MILPA_INDEX_TRUST` (§8.6, whole-index Sigstore verification) and
`MILPA_REQUIRE_ATTESTED_METADATA` (§8.5, per-dep DepDecl attestation). All
three fail independently and are remediated independently
(`spec/registry-protocol.md §3.4.0`) and MUST NOT be conflated.

#### `MILPA_INDEX_HISTORY`

> NORMATIVE: Sets the `index-history` policy for the invocation. Accepted
> values: `warn` (default), `strict`, `off`. This is an instantiation of
> the generic policy-axis model (`spec/registry-protocol.md §3.4.0`, whose
> instantiation table this axis is a row of): when unset, the effective
> policy is derived from the manifest `index-history` field using the same
> authority formula `MILPA_INDEX_TRUST` uses (§8.6) — manifest `off` is
> unconditional and manifest-only; otherwise
> `max(manifest_policy or "warn", env_policy)`.
>
> `index-history` is declared ONLY on the resolution root (root-only axis,
> `spec/registry-protocol.md §3.4.0`); a workspace member manifest
> declaring `index-history` MUST raise `WS-INDEX-HISTORY-ON-MEMBER` (lands
> with implementation slice) — the sibling of `WS-INDEX-TRUST-ON-MEMBER`
> for this axis.

> NOTE: This is the distinct sibling of `MILPA_INDEX_TRUST` (§8.6) and
> `MILPA_REQUIRE_ATTESTED_METADATA` (§8.5): `MILPA_INDEX_TRUST` governs
> whole-index document integrity; `MILPA_REQUIRE_ATTESTED_METADATA` governs
> per-dep DepDecl attestation; `MILPA_INDEX_HISTORY` governs whether a
> newly-fetched, already-trusted index is a legal successor of the last one
> this consumer observed (`spec/registry-protocol.md §3.5`). All three MAY
> be set independently; none implies or overrides another.

---

## 9  `--version`

> NORMATIVE: The implementation MUST support `milpa --version` and print
> a version string to stdout, then exit 0.

> NOTE: The reference implementation prints `milpa <version>` where
> `<version>` comes from `milpa/__init__.py:__version__` (a PEP 440
> version string). The exact format is incidental.

---

## 10  `publish` — out of scope for spec v1.0

> NORMATIVE: `publish` is NOT part of milpa spec v1.0 conformance. A
> conformant implementation is not required to implement it. It is
> reserved for a later spec amendment.

`publish` exists in the reference Python implementation as the
author-side packaging and registry-submission pipeline:

```
milpa publish --version <semver> --target <registry>/<repository> \
              [--name <pkg>] [--tag <tag>] [--output <path>] \
              [--dry-run] [--allow-untagged]
```

It depends on external services (OCI registry, cosign/Sigstore, tianguis
dispatch endpoint) and is not amenable to dir-tree-fixture conformance
testing. Its exit semantics and env var usage (`ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
`ACTIONS_ID_TOKEN_REQUEST_URL`, and any per-CI OIDC token vars) are
implementation-specific and not frozen by this spec.

### 10.1  Behavior

The reference implementation's `publish` is **registry-agnostic**: it knows
nothing about tianguis, any specific registry's submission conventions, or
any package index. It performs exactly four steps, each described here for
context only (none of this is conformance-tested):

1. **Resolve the source.** The publish source is the git repository's HEAD
   commit tree (read via the git object store, *not* the working directory —
   untracked/uncommitted files are excluded for free). Three guards run
   before anything else:
   - HEAD must resolve to a commit (otherwise `PUBLISH-NOT-GIT-REPO`).
   - Unless `--allow-untagged` is given, a git tag named exactly `<version>`
     or `v<version>` must point at HEAD (otherwise
     `PUBLISH-VERSION-TAG-MISMATCH`) — `--allow-untagged` is the escape
     hatch for publishing before the release tag exists.
   - HEAD's tree must contain no submodule (gitlink) entries (otherwise
     `PUBLISH-SUBMODULE-UNSUPPORTED` — milpa does not vendor submodule
     contents into a published artifact).
2. **Compute identity.** The resolved tree is folded into its content-hash
   identity (the same `dag-sha256:<hex>` algorithm used elsewhere in this
   spec's identity model) — computed once, before any network I/O. Every
   enumerated entry's path (and, for a symlink entry, its decoded target) is
   validated for containment and UTF-8 before the identity is computed:
   an absolute path or a `..`-escaping path component (source or symlink
   target) raises `PUBLISH-UNSAFE-PATH`, and a symlink target that is not
   valid UTF-8 raises `PUBLISH-NON-UTF8-SYMLINK-TARGET`. Both checks run at
   plan-build time, so `--dry-run` catches an unsafe/corrupted tree too, not
   only a real push.
3. **`--dry-run`:** builds the plan above and renders it as a JSON object
   (package name, version, content hash, target descriptor, and cheap
   enumeration stats — entry count, total byte size, top-level directory
   names) to stdout, unconditionally. When `--output <path>` is also given,
   the identical JSON is additionally written to `<path>`. No network
   connection, no `oras`/`cosign` subprocess, and no `execute()` call happens
   on this path by construction — `--dry-run` short-circuits before the
   impure step, it is not a branch inside it.
4. **Real run (no `--dry-run`):** packs the resolved tree into a
   byte-deterministic `tar.gz` (normalized mtimes/uid/gid/mode), pushes it to
   `<registry>/<repository>:<tag>` via `oras`, derives the immutable
   digest-pinned reference (`<registry>/<repository>@sha256:<digest>`).
   Before signing anything, it fetches the just-pushed manifest back and
   verifies that its (single) layer digest equals a fresh local `sha256` of
   the packed artifact bytes — a mismatch raises `PUBLISH-DIGEST-MISMATCH`
   and `cosign` is never invoked; if the manifest cannot be fetched or is not
   shaped as expected, `PUBLISH-MANIFEST-FETCH-FAILED` is raised instead.
   Only once verified does it sign that digest-pinned reference keylessly via
   `cosign` (ambient CI OIDC — Fulcio-issued certificate, Rekor transparency
   log), and assemble a `PublishReceipt`-shaped result (§10.2). When
   `--output <path>` is given, the result is written there as JSON and
   nothing is printed to stdout; otherwise a single one-line confirmation
   (`published <name>@<version> -> <oci_ref>`) is printed to **stderr**,
   matching every other verb's summary-line convention.

`--name` auto-derives from the manifest's `name` node when omitted; when
given explicitly it overrides the manifest. `--version` and `--target` are
always required (argparse-enforced — omitting either is an argument-parse
error, not a `publish`-specific diagnostic). `--tag` defaults to `--version`
when omitted.

### 10.2  `--output` JSON schemas

> NOTE (informative, not conformance-tested — mirrors the §2.5.1 field-list
> style for a schema that IS a real cross-tool contract): `--output <path>`
> writes one of two distinct JSON shapes depending on `--dry-run`, both of
> which are genuine **cross-tool contracts** parsed by external submission
> tooling (the tianguis composite action) — field names and meanings are
> stable and MUST NOT be silently renamed or removed by the reference
> implementation.

**Real-run shape** (no `--dry-run`) — the reference implementation's
`PublishOutputRecord`, six fields:

- `name`, `version` — the caller-supplied (or manifest/tag-derived) package
  identity.
- `content_hash` — the `dag-sha256:<hex>` content identity of the published
  source tree, computed in step 2 of §10.1. This is the value that
  downstream attestation tooling (e.g. the tianguis composite action) binds
  as the attestation subject.
- `oci_ref` — the full, immutable OCI reference the artifact was pushed to:
  `<registry>/<repository>@sha256:<digest>`. Always digest-pinned, never the
  mutable `:<tag>` form used for the push itself.
- `layer_digest` — the OCI content digest of the pushed manifest/layer,
  `sha256:<64-hex>` — the same digest embedded in `oci_ref`.
- `artifact_type` — the OCI artifact-type media type the artifact was pushed
  as (§10.3).

**Dry-run shape** (`--dry-run --output`) — the reference implementation's
`PublishDryRunRecord`, deliberately a SEPARATE shape (no `oci_ref`/
`layer_digest`, since nothing has been pushed yet — modeling them as absent/
null would misleadingly read as "pushed to nothing" rather than "hasn't
pushed"):

- `name`, `version`, `content_hash` — same meaning as the real-run shape
  (`content_hash` is still the plan's precomputed identity; no push has
  happened).
- `target` — the resolved push destination as an object: `registry`,
  `repository`, `tag`, `artifact_type`, `layer_media_type`.
- `entry_count`, `total_bytes`, `top_dirs` — the cheap enumeration-stats
  guardrail described in step 3 of §10.1 (`top_dirs` is the sorted set of
  each entry's first path component).

The two shapes are distinguished by the presence/absence of `--dry-run`, not
by a discriminant field in the JSON itself.

### 10.3  Media types

The reference implementation publishes every artifact under two
milpa-owned, fixed OCI media types (there are no `--artifact-type` /
`--layer-media-type` flags to override them in this slice):

- **Artifact type:** `application/vnd.milpa.source.v1`
- **Layer media type:** `application/vnd.milpa.source.v1.tar+gzip`

### 10.4  Registry authentication

`publish` runs no login flow of its own and is registry-agnostic: OCI
registry authentication is the **caller's** responsibility, via whatever
ambient credential configuration the `oras`/`docker` CLI toolchain already
honors (e.g. `docker login`, an `oras`-compatible credential helper, or a CI
job's registry-login step run before `milpa publish`). Signing similarly
relies on ambient CI OIDC for `cosign`'s keyless flow — `publish` does not
manage or accept key material.

### 10.5  Rust reference impl

The Rust reference implementation intentionally leaves `publish` in its
not-implemented branch. This is conformant: §10's opening NORMATIVE
paragraph does not require any implementation to implement `publish`.
The NORMATIVE requirement immediately below — that an unimplemented verb
MUST fail loudly rather than silently no-op — still applies to Rust's
`publish` branch exactly as it would to any other unimplemented verb. An
implementation earns "spec-conformant" by either implementing `publish`
compatibly with this section, or by refusing it cleanly; a silent no-op is
the one outcome this section forbids either way.

> NORMATIVE: An implementation that does NOT implement `publish` MUST
> NOT silently succeed when `milpa publish` is invoked — it MUST exit
> with a non-zero code and a clear "not implemented" diagnostic.

---

## Appendix A — Summary table

| Verb      | Args                     | `--frozen` | `-j` | `-s` | `--certificate` | Stdout     | Stderr           | Exit |
|-----------|--------------------------|-----------|------|------|-----------------|------------|------------------|------|
| `fetch`   | —                        | yes       | yes  | yes  | yes (§2.5)      | none       | progress/error   | 0/1  |
| `lock`    | —                        | ignored   | yes  | yes  | yes (§2.5)      | none       | progress/error   | 0/1  |
| `show`    | —                        | ignored   | —    | —    | ignored         | dep tree   | error only       | 0/1  |
| `verify`  | —                        | ignored   | —    | —    | ignored         | none       | progress/error   | 0/1  |
| `clean`   | —                        | ignored   | —    | —    | ignored         | none       | none/confirm     | 0    |
| `add`     | `<dep> --git/--mirror`   | ignored   | —    | yes  | ignored         | none       | summary/error    | 0/1  |
| `remove`  | `<dep>`                  | ignored   | —    | yes  | ignored         | none       | summary/error    | 0/1  |
| `update`  | `[<dep>]`                | ignored   | yes  | yes  | ignored         | none       | summary/error    | 0/1  |
| `publish` | *(out-of-scope)*         | —         | —    | —    | —               | —          | —                | —    |

---

## Appendix B — Environment variable reference

| Variable                          | Normative? | Affects                       | Default                                          |
|-----------------------------------|-----------|-------------------------------|--------------------------------------------------|
| `MILPA_TARGET_PLATFORM`           | YES       | resolved dep graph            | auto-detected host OS                            |
| `MILPA_TARGET_ARCH`               | YES       | resolved dep graph            | auto-detected host CPU                           |
| `MILPA_TARGET_NIM`                | YES       | resolved dep graph            | queried from `nim --version`                     |
| `MILPA_TARGET_MILPA`              | YES       | resolved dep graph            | `milpa.__version__`                              |
| `MILPA_INDEX_URL`                 | YES       | tianguis index URL            | `https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl` |
| `MILPA_CACHE_DIR`                 | YES       | CAS root                      | `$XDG_CACHE_HOME/milpa/cas`                     |
| `MILPA_MOCKED_FETCHES`            | YES       | fetch transport (conformance) | (none; real transport used)                      |
| `MILPA_DEP_DECL_DIR`              | YES       | DepDecl store (conformance)   | (none; `HttpDepDeclStore` used)                  |
| `MILPA_INDEX_TRUST`               | YES       | index attestation policy      | `warn`                                           |
| `MILPA_INDEX_TRUST_SIGNER`        | YES       | expected signer identity      | (pinned tianguis vendor-bot OIDC SAN; §8.6)      |
| `MILPA_INDEX_TRUST_BUNDLE`        | YES       | Fulcio CA + Rekor key bundle  | (embedded production trust bundle; §8.6)         |
| `MILPA_INDEX_MAX_AGE`             | YES       | bundle freshness window (sec) | `604800` (7 days; §8.6)                          |
| `MILPA_INDEX_BUNDLE_URL`          | YES       | Sigstore bundle URL override  | (derived from `MILPA_INDEX_URL`; §8.6)           |
| `MILPA_INDEX_HISTORY`             | YES       | append-only ratchet policy    | `warn` (§8.7)                                    |
| `XDG_CACHE_HOME`                  | NO        | CAS + index cache base        | `~/.cache`                                       |
| `ACTIONS_ID_TOKEN_REQUEST_TOKEN`  | NO        | `publish` OIDC (out-of-scope) | —                                                |
| `ACTIONS_ID_TOKEN_REQUEST_URL`    | NO        | `publish` OIDC (out-of-scope) | —                                                |
