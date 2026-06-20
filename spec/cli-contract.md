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

---

## 1  Invocation form

```
milpa [--version] [-C <dir>] [-j <N>] [-s <mode>] [--frozen] [--certificate <path>] [--require-attested-metadata] <verb> [<verb-args>]
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

> NORMATIVE: Machine-readable output — currently only the dep tree
> printed by `milpa show` — MUST be written to **stdout**.

> NORMATIVE: Verbs that produce no machine-readable output (`fetch`,
> `lock`, `verify`, `clean`, `add`, `remove`, `update`) MUST produce
> **no output on stdout** on a successful run.

> NOTE: The reference implementation follows this routing strictly. All
> `print(…, file=sys.stderr)` calls are diagnostics; the sole `print(…)`
> without a `file=` argument is in `cmd_publish`'s dry-run confirmation
> line, which is incidental to the out-of-scope `publish` verb.
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
> and `_deps/` change.

> NORMATIVE: If `<dep>` is provided but `milpa.lock` does not exist,
> `update` MUST print a diagnostic to stderr and exit 1 (no lockfile
> means no prior pins to drop selectively; a full `milpa fetch` is the
> correct action).

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
> - `FROZEN-LEGACY-REGISTRY-PROVENANCE` — a lockfile entry uses the legacy
>   `kind "registry"` provenance (pre-#97); must re-resolve via tianguis
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
milpa publish --name <pkg> --version <semver> --registry <oci-ref> \
              --provider <ci> --repo-url <url> --signed-by <identity> \
              [--dispatch-url <url>] [--oidc-token-env <var>] [--dry-run]
```

It depends on external services (OCI registry, cosign/Sigstore, tianguis
dispatch endpoint) and is not amenable to dir-tree-fixture conformance
testing. Its exit semantics and env var usage (`ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
`ACTIONS_ID_TOKEN_REQUEST_URL`, and any per-CI OIDC token vars) are
implementation-specific and not frozen by this spec.

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
| `XDG_CACHE_HOME`                  | NO        | CAS + index cache base        | `~/.cache`                                       |
| `ACTIONS_ID_TOKEN_REQUEST_TOKEN`  | NO        | `publish` OIDC (out-of-scope) | —                                                |
| `ACTIONS_ID_TOKEN_REQUEST_URL`    | NO        | `publish` OIDC (out-of-scope) | —                                                |
