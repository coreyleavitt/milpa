# milpa conformance fixture format (S8a)

Normative spec of the **directory-tree fixture format** shared by all milpa
conformance suites — Python, Rust, and any future implementation. Every
implementation that claims conformance to a spec version MUST pass the
corresponding fixture set without modification.

Every rule marked `> NORMATIVE:` is a conformance requirement. Items marked
`> NOTE:` describe the reference Python implementation or rationale; conformant
alternatives MAY differ in those details.

Related specs:

- `docs/spec/lockfile-schema.md` (S5) — normative `milpa.lock` and `nim.cfg`
  output formats cross-referenced from §2.4 and §2.5
- `docs/spec/identity.md` (S12) — `_deps/` symlink convention cross-referenced
  from §2.6
- `docs/spec/registry-protocol.md` (S14) — `index.kdl` input format
  cross-referenced from §2.2
- `docs/spec/errors.md` — error slug catalog cross-referenced from §3
- `docs/rfc-reaching-rust-rewrite.md` — G4/S8a gate deliverable this doc
  fulfills
- `docs/rfc-multi-impl-strategy.md` — original conformance-suite design;
  `index.kdl` replaces the earlier `registry.json` placeholder (post-#97)

---

## Normative surface

A conformant implementation of this spec MUST:

1. Store all fixtures under `tests/conformance/spec-v<N>/` where `N` is the
   integer spec version the fixtures target.
2. Include in each `fixture-NNN-<slug>/` directory at minimum `milpa.kdl` and
   `expected/`; `index.kdl` and `mocked-fetches/` are required for `resolve`
   fixtures that use named deps or fetched URL deps respectively (see §2.2).
3. Express success fixtures via output files under `expected/` (`milpa.lock`,
   `nim.cfg`, `_deps_structure.txt`).
4. Express error fixtures via `expected/error` containing a single bare error
   slug on one line and no `milpa.lock` or `nim.cfg`.
5. Produce `expected/` outputs that are byte-exact when diffed against a
   conformant implementation's output.
6. Retain all fixture directories under their original `spec-v<N>/` version
   directory when a new spec version is introduced; MUST NOT mutate existing
   fixtures in place.
7. Include at least one normative fixture per MUST-clause across the spec docs.

---

## 1  Location and versioning

### 1.1  Fixture tree root

> NORMATIVE: All fixtures live under `tests/conformance/` in the milpa
> repository. They are version-partitioned by spec version:
>
> ```
> tests/conformance/
>   spec-v1/
>     fixture-003-single-url-dep/
>     fixture-061-named-dep/
>     ...
>   spec-v2/            ← added when spec v2 exists; spec-v1/ unchanged
>     fixture-NNN-...
> ```

> NORMATIVE: The version subdirectory name is `spec-v<N>` where `N` is a
> positive integer matching the spec-version the fixture targets. An
> implementation declaring conformance to spec version `N` MUST pass every
> fixture under `spec-v<N>/`.

### 1.2  Fixture directory naming

> NORMATIVE: Each fixture directory MUST be named `fixture-NNN-<slug>` where:
>
> - `NNN` is a zero-padded three-digit (or more) integer that uniquely
>   identifies the fixture within its spec-version directory and determines
>   the order in which a runner processes them.
> - `<slug>` is a short, lowercase, hyphen-separated label that names the
>   behavior under test (e.g., `single-url-dep`, `named-dep-diamond`,
>   `man-kdl-syntax-error`).

### 1.3  Fixture lifecycle and spec-version bumps

> NORMATIVE: A **normative behavior change** — any change to a MUST-clause in
> a spec doc — MUST produce a new spec version (`N` → `N+1`). New fixtures
> targeting the new behavior MUST be added under `spec-v<N+1>/`. Existing
> fixtures under `spec-v<N>/` MUST be retained unchanged.

> NORMATIVE: A **behavioral extension** (adding a MAY behavior, adding a new
> optional field, or documenting previously unspecified behavior without
> changing existing MUST-clauses) does NOT require a new spec version. Such
> extensions are additive within an epoch.

> NORMATIVE: The mapping rule: a **format break** (grammar or byte-layout
> change to an existing construct) is a normative behavior change → major bump.
> A **feature addition** that leaves existing syntax valid and existing outputs
> intact is a behavioral extension → no bump.

> NOTE: This rule mirrors Cargo `edition` / Kubernetes `apiVersion` semantics.
> The Python impl carries `LOCKFILE_SCHEMA_VERSION` (an internal integer) and
> `TIANGUIS_INDEX_SCHEMA_VERSION` (the index protocol version). Both are
> **distinct namespaces** from the conformance spec version: a lockfile schema
> version bump does not automatically bump the spec version (the spec version
> covers all conformance behaviors; a lockfile schema bump is one component of
> that). When a lockfile schema bump constitutes a normative change, the spec
> version bumps too; the cross-reference in `lockfile-schema.md` documents the
> exact mapping.

### 1.4  Implementation conformance declaration

> NORMATIVE: An implementation MUST declare, in its project metadata or a
> companion doc, the spec version it claims conformance to and the fixture
> set it passes. A partial-conformance claim MUST enumerate which fixture
> numbers it is known to fail.

> NOTE: The Python implementation declares its conformance level in
> `pyproject.toml` under `[tool.milpa]`. The Rust implementation will carry
> a comparable declaration. The spec version frozen at Python gate-close is
> spec v1.0; subsequent spec versions require an RFC amendment.

---

## 2  Fixture directory layout

Each `fixture-NNN-<slug>/` directory has this exact layout:

```
fixture-NNN-<slug>/
  milpa.kdl                    # input: project manifest (workspace root for workspace fixtures)
  <member>/                    # input (optional): workspace member subdir (see §2.1.1)
    milpa.kdl                  #   the member's own manifest
  index.kdl                    # input (optional): frozen tianguis index snapshot
  cmd                          # input (optional): entry-point selector (see §2.7)
  env                          # input (optional): MILPA_TARGET_* overrides (see §2.8)
  milpa.lock                   # input (optional): lockfile for parse-lockfile / frozen cmds
  cas-seed/                    # input (optional): source trees to pre-populate CAS (frozen cmd)
    <name>/                    # one subdirectory per dep to seed
      <file> ...               # source tree bytes (identity computed from these bytes)
  mocked-fetches/              # input: per-URL fake-fetcher returns
    <url-encoded-key>/
      sha                      # git commit SHA (40 hex chars)
      content/                 # unpacked source tree bytes
        <file> ...
      <name>.nimble            # nimble file for the package (may be absent)
  expected/                    # success: outputs to byte-diff
    milpa.lock                 # or: error fixture has none of these
    nim.cfg                    # single-package fixtures only (see §2.5)
    <member>/                  # workspace fixtures only: one dir per member
      nim.cfg                  #   the member's own nim.cfg (see §2.5)
    _deps_structure.txt
  # — OR for an error fixture (see §3) —
  expected/
    error                      # contains the bare error slug
```

> NOTE: A single-package fixture has exactly one `expected/nim.cfg`. A
> workspace fixture instead has one `expected/<member-path>/nim.cfg` per
> declared member and **no** root `expected/nim.cfg` (§2.5). `milpa.lock` and
> `_deps_structure.txt` remain single shared root outputs in both cases.

### 2.1  `milpa.kdl` — project manifest

> NORMATIVE: `milpa.kdl` MUST be a valid milpa manifest as defined in
> `docs/spec/manifest-grammar.md`. It is the sole manifest input to the
> resolver under test.

> NOTE: For fixtures testing error conditions that originate in the manifest
> (e.g., `MAN-KDL-SYNTAX`), `milpa.kdl` deliberately contains the malformed
> content that triggers the error. The fixture is still valid from the
> conformance-suite perspective; only the fixture inputs are malformed.

### 2.1.1  Workspace member subdirectories (optional)

> NORMATIVE: When the fixture's `milpa.kdl` declares a `workspace { }` block,
> each member path named by a `member "<path>"` node MUST exist as a
> subdirectory of the fixture root, and each such subdirectory MUST contain at
> minimum its own `milpa.kdl`. The runner treats the fixture root as the
> workspace root and loads members from these subdirectories (the reference
> adapter calls `load_workspace(fixture_root)`); member manifests are NOT
> inlined into the root `milpa.kdl`. Member subdirectories are the only nested
> manifest inputs a fixture may contain.

> NORMATIVE: A workspace success fixture expresses its `nim.cfg` outputs
> **per-member**, mirroring the input layout: for each member declared as
> `member "<path>"`, the expected output is `expected/<path>/nim.cfg`. A
> workspace fixture MUST NOT contain a root `expected/nim.cfg`. This reflects
> milpa's workspace emission model: members do not share a single root
> `nim.cfg`; each member gets its own with `--path:` lines relative to that
> member's directory (sibling member dirs and the shared `_deps/`). The
> reference adapter renders these via the same emitter milpa's CLI uses and
> byte-diffs each against its `expected/<path>/nim.cfg`.

### 2.2  `index.kdl` — frozen index snapshot (optional)

> NORMATIVE: When present, `index.kdl` MUST be a valid tianguis index document
> as defined in `docs/spec/registry-protocol.md`. It contains the frozen set of
> named packages visible to this fixture's resolver run. A fixture that
> exercises no named deps MAY include `index.kdl` as an empty index (a document
> with only a `schema_version` node and no `package` nodes), or MAY omit
> `index.kdl` entirely. When `index.kdl` is absent the runner passes
> `index=None` to the resolver, which raises `RES-NO-INDEX` or
> `RES-WS-NO-INDEX` if the manifest contains named deps without an override.

> NORMATIVE: The frozen index is `index.kdl`, consumed via the `parse_index`
> path. The earlier `registry.json` placeholder in `rfc-multi-impl-strategy.md`
> is superseded by this format (post-#97, `registry.py` retired).

> NOTE: The `index.kdl` file is the exact bytes that `parse_index(text)` in
> `tianguis_client.py` would consume. Any index entry declared here is visible
> to the fixture's resolver; any package absent from this file is invisible.
> This is the frozen-world guarantee that makes fixtures reproducible.

### 2.3  `mocked-fetches/` — fake-fetcher returns

`mocked-fetches/` contains one subdirectory per URL+ref combination that the
fixture's resolver will attempt to fetch. Each subdirectory represents one
mocked network round-trip.

#### 2.3.1  Subdirectory key encoding

> NORMATIVE: Each subdirectory under `mocked-fetches/` MUST be named using the
> **URL-key encoding**: the URL and ref joined by a `@` separator, with every
> character outside `[A-Za-z0-9._-]` replaced by `_`. For example:
>
> ```
> https://github.com/example/foo.git @ main
> →  https___github.com_example_foo.git@main
> ```
>
> The encoding rule: apply `re.sub(r'[^A-Za-z0-9._-]', '_', url)` to the URL
> portion, then append the literal `@` separator, then apply the same
> substitution to the ref. The `@` separator is literal and is NOT substituted.
> A `@` *within the ref* is not special-cased: it is replaced by `_` like any
> other character outside `[A-Za-z0-9._-]` (so a ref `v1@beta` encodes to
> `v1_beta`). Only the single separator `@` between url and ref is preserved.

> NOTE: The Python conformance adapter (S8b) derives the subdirectory name
> from a `GitProvenance(url, ref)` pair using this rule. The derivation is the
> single source of truth so the adapter and the fixture generator agree without
> a separate lookup table.

#### 2.3.2  Per-URL subdirectory contents

Each subdirectory under `mocked-fetches/<key>/` MUST contain:

**`sha`** (required)

> NORMATIVE: A plain text file containing exactly one line: the 40-character
> lowercase hexadecimal git commit SHA that the mocked fetcher returns as
> `GitReceipt.commit_sha`. No trailing whitespace other than a single newline.

**`content/`** (required)

> NORMATIVE: A subdirectory tree whose contents are the source tree that the
> mocked fetcher writes to `dest` before returning. The conformance adapter
> copies these files into `dest` verbatim, byte-for-byte. The identity
> algorithm (`docs/spec/identity.md`) is then applied to `dest` to compute
> `content_hash`; the result is the identity recorded in the lockfile.
>
> The `content/` tree MAY be empty (zero files) to represent a package that
> contributes no source files (unusual but valid). It MUST NOT contain a `.git/`
> directory (that would be excluded by the identity algorithm and is confusing).

> NOTE: The `content/` tree is the **ground truth** for the fixture's expected
> `content_hash`. When promoting a Python regression test, the content tree is
> the actual bytes the test was using. When writing a new fixture by hand, the
> expected `milpa.lock` is generated from the hash of this tree.

**`<name>.nimble`** (optional)

> NORMATIVE: If present, a file named `<name>.nimble` (where `<name>` is the
> dep's name as declared in the manifest) contains the `.nimble` file text for
> that package. The conformance adapter writes this file into `dest` at the
> tree root, alongside the files copied from `content/`. The resolver then
> parses it for the dep's transitive requires. If absent, no `.nimble` file is
> written; the resolver treats the dep as having no transitive requires.

> NORMATIVE: The `<name>.nimble`, once written into `dest`, **is part of the
> materialized tree and therefore IS included in the `content_hash`.** The
> identity algorithm (`docs/spec/identity.md`) runs over all of `dest` and
> excludes only `.git/` — it does **not** exclude `.nimble`. This mirrors a real
> fetch, where a package's own `.nimble` lives in its source tree and is hashed
> like any other file. A fixture author MUST therefore compute the expected
> `content_hash` over the full `dest` tree **including** the `<name>.nimble`
> (equivalently: generate `expected/milpa.lock` by running the reference
> implementation through the conformance adapter, which materializes the
> `.nimble` into `dest` before hashing).

> NOTE: The `<name>.nimble` is authored as a *sibling* of `content/` in the
> fixture directory (not inside it) purely as an authoring convenience — it
> separates "the package's declared requires" from "the rest of the source
> tree" for a human reader. At materialization time the adapter flattens both
> into `dest`, so the distinction has no effect on the hash: the `.nimble` is
> hashed exactly as if it had been placed inside `content/` at the tree root.

### 2.4  `expected/milpa.lock` — expected lockfile

> NORMATIVE: For a success fixture, `expected/milpa.lock` MUST be a valid
> lockfile as defined in `docs/spec/lockfile-schema.md`. A conformant
> implementation's output MUST be byte-identical to this file. Diff of any
> single byte is a conformance failure.

> NOTE: The byte-exact requirement means that the expected file is generated
> by the reference implementation and checked in. If the lockfile format
> changes in a normative way, the spec version bumps and new fixtures are
> written. Existing `spec-v1/` fixtures are not regenerated.

### 2.5  `expected/nim.cfg` — expected compiler path config

> NORMATIVE: For a **single-package** success fixture, `expected/nim.cfg` MUST
> contain the nim.cfg output as defined in `docs/spec/lockfile-schema.md`
> §nim.cfg emission. A conformant implementation's output MUST be
> byte-identical.

> NORMATIVE: For a **workspace** success fixture, there is no root
> `expected/nim.cfg`. Instead, each declared member `member "<path>"` has an
> `expected/<path>/nim.cfg` containing that member's nim.cfg output (the
> per-member emission defined in `docs/spec/resolver-semantics.md` §11.4).
> Each member's `--path:` lines are relative to the member's own
> directory: sibling member references resolve to `../<other-member>/<src_dir>`
> and external deps to the shared `../_deps/<dep>/<src_dir>`. A conformant
> implementation's output for each member MUST be byte-identical to its
> `expected/<path>/nim.cfg`.

> NOTE: `nim.cfg` uses POSIX path separators regardless of the host OS
> (`docs/spec/lockfile-schema.md` NORMATIVE item 8). Fixtures MUST use POSIX
> separators; a Windows implementation that produces `\` paths fails the
> byte-diff and is non-conformant.

### 2.6  `expected/_deps_structure.txt` — expected `_deps/` layout

`_deps_structure.txt` captures the expected filesystem structure of the `_deps/`
directory after `milpa fetch` completes. It serves as the conformance check for
the CAS-admission and symlink-creation steps defined in `docs/spec/identity.md`
§3.

> NORMATIVE: `_deps_structure.txt` MUST be a plain text file whose lines are
> `<name> -> <CAS_ROOT>/sha256/<hex>/` pairs, one per dep, sorted
> lexicographically by name, terminated by a trailing newline. Each line is
> produced by **resolving** the `_deps/<name>` symlink to an absolute CAS entry
> path and then substituting the runner's CAS root prefix with the
> fixture-stable placeholder `<CAS_ROOT>` (next clause). Example stable form:
>
> ```
> chronos -> <CAS_ROOT>/sha256/a3f9.../
> intonaco -> <CAS_ROOT>/sha256/7c21.../
> ```
>
> The on-disk symlink itself MAY be created with a relative target (per
> `docs/spec/identity.md` §3.4); `_deps_structure.txt` records the *resolved*
> CAS entry, not the raw link target.

> NORMATIVE: The runner MUST normalize the CAS root before substitution:
> 1. Resolve the CAS root path to its canonical form (no symlink components — on
>    hosts where the temp dir is itself a symlink, an unresolved prefix would
>    fail to match the resolved symlink target).
> 2. Form the substitution prefix as that canonical string with **no trailing
>    path separator**.
> 3. Replace that prefix with `<CAS_ROOT>` in each resolved target before the
>    byte-diff.
>
> This makes `_deps_structure.txt` machine-independent even though the CAS root
> location varies (`~/.cache/milpa/cas` vs `$MILPA_CACHE_DIR`). Every
> implementation's runner (Python, Rust) applies the identical algorithm.

### 2.7  `cmd` — entry-point selector (optional)

> NORMATIVE: If `cmd` is present, it MUST contain exactly one of the following
> strings (no leading/trailing whitespace, no newline required):
>
> - `resolve` — parse `milpa.kdl` (and optionally `index.kdl`) and resolve the
>   dep graph against mocked-fetches. This is the default when `cmd` is absent.
> - `parse-lockfile` — parse the fixture's `milpa.lock` input only. No
>   `milpa.kdl`, `index.kdl`, or `mocked-fetches/` are read. Used exclusively for
>   `LOCK-*` error fixtures. This entry point has no success variant (no output
>   files); every `parse-lockfile` fixture is an error fixture.
> - `frozen` — exercise the no-network frozen fast path: parse `milpa.kdl` and
>   `milpa.lock`, optionally seed the CAS from `cas-seed/`, then resolve without
>   fetching. Used for `FROZEN-*` fixtures; MAY be a success or error fixture.

> NORMATIVE: When `cmd` is absent or contains `resolve`, `index.kdl` MAY be
> omitted; its absence causes the runner to pass `index=None`, which triggers
> `RES-NO-INDEX` / `RES-WS-NO-INDEX` when the manifest has named deps (see
> §2.2). When `cmd` is `parse-lockfile`, `index.kdl` and `mocked-fetches/`
> MAY be omitted. When `cmd` is `frozen`, `milpa.lock` MUST be present;
> `index.kdl` and `mocked-fetches/` MAY be omitted if the fixture does not
> exercise the resolve path.

### 2.8  `env` — target-profile overrides (optional)

> NORMATIVE: If present, `env` MUST be a plain text file where each non-empty,
> non-comment line has the form `KEY=VALUE`. Lines beginning with `#` and blank
> lines are ignored. Recognized keys are `MILPA_TARGET_PLATFORM`,
> `MILPA_TARGET_ARCH`, `MILPA_TARGET_NIM`, and `MILPA_TARGET_MILPA`; all other
> keys are accepted and silently ignored by the runner.

> NORMATIVE: When `env` is present, the runner MUST construct a `Profile` from
> those key–value pairs and pass it to `resolve` / `resolve_workspace` as the
> `profile=` argument. Conditional deps whose predicates do not match the
> constructed `Profile` MUST be excluded from the resolved graph exactly as if
> the user had run `milpa fetch` with those environment variables set. When
> `env` is absent the runner passes `profile=None`, which disables predicate
> filtering (all deps are included regardless of predicates).

> NOTE: The runner temporarily sets the listed environment variables in the
> Python process, calls `Profile.from_environment(nim_version_query=lambda:
> "2.0.0")` to build the Profile, then restores the original environment.
> The `nim_version_query` lambda is injected so no `nim` subprocess runs during
> conformance. The `MILPA_TARGET_NIM` env var, if set in `env`, overrides this
> injected value via the normal `from_environment` priority order.

> NOTE: Use `env` to write a conditional-dep exclusion success fixture: set
> `MILPA_TARGET_PLATFORM=linux` while the manifest declares a dep gated on
> `platform="windows"`. The dep is absent from `expected/milpa.lock` and
> `expected/nim.cfg`, proving the predicate filter is applied before the fetch
> phase (the dep is never fetched and no `mocked-fetches/` entry is required
> for it). See fixture-115-conditional-dep-excluded for the canonical example.

### 2.9  `milpa.lock` — lockfile input (required for `parse-lockfile` and `frozen`)

> NORMATIVE: When `cmd` is `parse-lockfile`, `milpa.lock` MUST be present and
> is the sole input. The runner parses it and asserts the resulting error code
> (for error fixtures). This is the canonical way to test `LOCK-*` codes that
> arise during lockfile parsing; `LOCK-VERSION-UNSUPPORTED` is testable via this
> path (a fixture with `version 99` in `milpa.lock` triggers it reliably).

> NORMATIVE: When `cmd` is `frozen`, `milpa.lock` MUST be present. The runner
> parses both `milpa.kdl` and `milpa.lock` and runs the no-network frozen path.

### 2.10  `cas-seed/` — CAS pre-population trees (optional, `frozen` only)

> NORMATIVE: When `cmd` is `frozen` and `cas-seed/` is present, the runner
> MUST compute the content hash of each immediate subdirectory of `cas-seed/`
> and admit those trees into the per-test CAS instance before running the frozen
> path. This lets a frozen success fixture prove that a dep whose identity IS in
> the CAS resolves correctly without a network fetch. The fixture's `milpa.lock`
> MUST pin the matching `sha256:...` identity for each seeded dep.

> NOTE: The reference Python adapter seeds the CAS by calling
> `store.admit(tree, identity)` which currently moves (not copies) the seed
> tree. This means `cas-seed/` trees are consumed on the first run and absent on
> subsequent runs. Fixture authors relying on `cas-seed/` for success fixtures
> should be aware of this behavior; it is a known limitation of the Python
> adapter and will be corrected (by using `shutil.copytree` + `admit`) in a
> later revision.

---

## 3  Error fixtures

An error fixture asserts that the resolver, manifest parser, or lockfile
verifier produces a specific error code for the given inputs, rather than
emitting `milpa.lock` and `nim.cfg`.

### 3.1  `expected/error` — expected error slug

> NORMATIVE: An error fixture MUST contain `expected/error`, a plain text file
> with exactly one line: the bare error slug from `docs/spec/errors.md` (e.g.,
> `MAN-KDL-SYNTAX`, `SOLVE-CONFLICT`, `LOCK-VERSION-UNSUPPORTED`). The file
> MUST end with a single newline and MUST NOT contain whitespace before or
> after the slug.

> NOTE: `LOCK-*` codes (e.g., `LOCK-VERSION-UNSUPPORTED`) are triggered via
> `cmd=parse-lockfile` fixtures (§2.7), not via the default `resolve` path.
> A fixture with `cmd=parse-lockfile` and `milpa.lock` containing `version 99`
> reliably triggers `LOCK-VERSION-UNSUPPORTED`. See §2.8.

> NORMATIVE: An error fixture MUST NOT contain `expected/milpa.lock`,
> `expected/nim.cfg`, or `expected/_deps_structure.txt`. The presence of
> `expected/error` unambiguously marks the fixture as an error fixture; the
> runner does not inspect output files for error fixtures.

> NORMATIVE: A conformant implementation passes an error fixture if and only
> if the raised exception carries `.code == <slug>` as defined in
> `docs/spec/errors.md`. The human-readable error message is **not** checked
> and is NOT byte-normative.

### 3.2  Error fixture inputs

> NORMATIVE: Error fixtures MUST include `milpa.kdl`. `index.kdl` and
> `mocked-fetches/` are optional; omit `index.kdl` to exercise `RES-NO-INDEX`
> / `RES-WS-NO-INDEX`; include an empty `index.kdl` and/or an empty
> `mocked-fetches/` for errors that originate before fetch lookup.

> NOTE: Omitting `index.kdl` entirely is the canonical trigger for
> `RES-NO-INDEX` and `RES-WS-NO-INDEX` (the runner passes `index=None` when
> the file is absent). For all other error codes, including `index.kdl` as an
> empty snapshot keeps the fixture minimal and the runner's behavior
> deterministic.

### 3.3  Promoted trigger-table fixtures

> NOTE: The `tests/test_man_code_triggers.py` trigger table (and equivalent
> tables for other error categories) is the primary source of error fixtures
> to promote into `tests/conformance/spec-v1/`. Each row in a trigger table
> maps directly to one error fixture: the Python lambda's input KDL becomes
> `milpa.kdl`, the empty index becomes `index.kdl`, and the slug becomes
> `expected/error`. The S8b (code) slice executes this promotion.

---

## 4  Coverage floor

> NORMATIVE: The conformance suite MUST include at least one fixture per
> normative error code across the spec's error catalog. The suite is the
> **cross-implementation arbiter**: when the Python and Rust implementations
> disagree, the fixture determines which is correct. A suite that skips error
> codes is not a conformance suite — it is a partial regression suite.

> NOTE: The `rfc-multi-impl-strategy.md` acceptance criterion states ≥100
> fixtures total as the acceptance bar for the full multi-impl strategy. Gate
> G4 (this document's scope) does not gate-close at 100 fixtures; it gates at
> ≥1 per normative error code and includes the diamond-conflict fixture (S9).
> The 100-fixture bar is a strategic milestone for when the Rust port reaches
> Python parity.

> NOTE: The ≥1-per-code floor is now met for all codes that are reachable
> through the conformance runner's fixture mechanism. The following codes are
> documented as **structurally unreachable** via the current runner and are
> therefore exempt from the coverage floor:
>
> - `MAN-WORKSPACE-IN-PACKAGE` — raised only by `parse_manifest()` (not
>   `parse_workspace_or_manifest()`); the runner always uses the latter, which
>   routes workspace blocks to the workspace parser before this error can fire.
> - `LOCK-FILE-NOT-FOUND`, `LOCK-FILE-UNREADABLE` — raised only by
>   `load_lockfile()` (disk-read path); the `parse-lockfile` cmd uses
>   `parse_lockfile()` which receives text directly, bypassing disk I/O errors.
> - `LOCK-GRAPH-MISMATCH` — raised only by `verify_against_graph()`; the
>   runner does not call the verifier.
> - `WS-NO-MANIFEST`, `WS-NOT-A-WORKSPACE` — the runner dispatches on
>   `parse_workspace_or_manifest()` output type and always passes a directory
>   that has a workspace-typed `milpa.kdl` to `load_workspace()`; the two
>   pre-conditions checked by those codes are therefore never false.
> - `TNG-BAD-VERSION` — explicitly reserved for a future strict-parse pass;
>   currently unparseable version strings are silently skipped.
>
> The following codes were previously listed as unreachable but are now covered
> by fixtures added in this revision:
>
> - `RES-NO-INDEX` — fixture-112: package manifest with a named dep and no
>   `index.kdl` (runner now passes `index=None` when `index.kdl` is absent).
> - `RES-WS-NO-INDEX` — fixture-113: workspace member with a named dep and no
>   `index.kdl`.
> - `WS-MEMBER-DOT` — fixture-108: workspace declares `member "."`.
> - `WS-MEMBER-DIR-MISSING` — fixture-107: declared member directory absent from
>   disk (runner now routes workspace fixtures through the real
>   `load_workspace()` which checks the filesystem).
> - `WS-MEMBER-NO-MANIFEST` — fixture-109: member directory exists but contains
>   no `milpa.kdl`.
> - `WS-MEMBER-HAS-OVERRIDES` — fixture-110: member manifest carries an
>   `overrides` block.
> - `WS-MEMBER-DUPLICATE-NAME` — fixture-111: two member directories both declare
>   the same package name.
> - `FROZEN-LEGACY-REGISTRY-PROVENANCE` — fixture-114: `cas-seed/` pre-populates
>   the CAS (runner now copies before admitting, so the seed tree is not
>   destroyed on the first run), then the lockfile's `kind "registry"` provenance
>   triggers the raise.
> - Conditional-dep exclusion via profile predicates — fixture-115: `env` file
>   sets `MILPA_TARGET_PLATFORM=linux`; a dep gated on `platform="windows"` is
>   absent from the resolved graph.
> - `--path:"src"` self-path line — fixture-116: root manifest declares
>   `src_dir "src"`; the runner now passes `self_src_dir` to `format_nimcfg()`,
>   producing a leading self-path line before the dep paths.

---

## 5  Black-box diff semantics

> NORMATIVE: The conformance format is a **black-box byte-diff format**. A
> conformance runner executes the implementation under test against each
> fixture's inputs, then diffs the outputs against `expected/`. No bespoke
> JSON `{input, expected}` encoding is used; no implementation-internal data
> structures are inspected.

> NORMATIVE: A runner written in any language MUST be able to implement this
> check without importing milpa's Python code:
>
> 1. Copy the fixture's inputs into a scratch directory.
> 2. Invoke the implementation under test (as a CLI subprocess or via its
>    public API) with that directory as the project root.
> 3. For a success fixture: diff `milpa.lock`, `nim.cfg`, and
>    `_deps_structure.txt` (after `<CAS_ROOT>` substitution) against
>    `expected/`. Any diff is a failure.
> 4. For an error fixture: assert that the implementation exited with a
>    non-zero status and emitted an error whose `.code` matches `expected/error`.

> NORMATIVE: When the runner invokes `nim.cfg` emission, it MUST supply the deps
> directory as the literal relative path `_deps` (not an absolute scratch path).
> The checked-in `expected/nim.cfg` files encode `_deps/` as the `--path:`
> prefix; passing any other path fails the byte-diff. (This is the
> `deps_dir=_deps` argument to `format_nimcfg` in the reference adapter.)

> NOTE: The Python conformance adapter (S8b) wraps this protocol as a `pytest`
> parametrized test that discovers all `tests/conformance/spec-v<N>/` fixture
> directories at collection time. The Rust conformance runner drives the library
> API via `cargo test` (`#[test]` parametrization, one test per fixture), not a
> standalone binary. Both diff against the same checked-in `expected/` files;
> neither generates expected files at test time.

---

## 6  Example fixture

Below is a minimal annotated example of a success fixture and an error fixture.
These are illustrative, not normative.

### 6.1  Success fixture: `fixture-003-single-url-dep`

```
tests/conformance/spec-v1/fixture-003-single-url-dep/
  milpa.kdl
    name "myapp"
    kind "application"
    deps {
        foo git=(url)"https://github.com/example/foo.git" ref="main"
    }

  index.kdl
    schema_version 1
    // no named deps; empty index

  mocked-fetches/
    https___github.com_example_foo.git@main/
      sha
        abcdef1234567890abcdef1234567890abcdef12
      content/
        foo.nim
          # minimal Nim source
      foo.nimble
        # Package
        version = "1.0.0"
        author = "example"
        description = "foo"
        license = "MIT"

  expected/
    milpa.lock          ← generated by reference impl; byte-frozen
    nim.cfg             ← generated by reference impl; byte-frozen
    _deps_structure.txt
      foo -> <CAS_ROOT>/sha256/3a7f.../
```

### 6.2  Error fixture: `fixture-001-man-kdl-syntax`

```
tests/conformance/spec-v1/fixture-001-man-kdl-syntax/
  milpa.kdl
    this is not valid { kdl

  index.kdl
    schema_version 1

  mocked-fetches/
    (empty directory)

  expected/
    error
      MAN-KDL-SYNTAX
```

### 6.3  Lockfile parse error fixture: `fixture-068-lock-version-unsupported`

```
tests/conformance/spec-v1/fixture-068-lock-version-unsupported/
  cmd
    parse-lockfile

  milpa.lock
    // generated by milpa; reproducible build snapshot
    version 99
    strategy "maxver"

  expected/
    error
      LOCK-VERSION-UNSUPPORTED
```

### 6.4  Frozen error fixture: `fixture-083-frozen-identity-not-in-store`

```
tests/conformance/spec-v1/fixture-083-frozen-identity-not-in-store/
  cmd
    frozen

  milpa.kdl
    name "myapp"
    kind "application"
    deps {
        foo git=(url)"https://github.com/example/foo.git" ref="main"
    }

  milpa.lock
    // generated by milpa; reproducible build snapshot
    version 1
    strategy "maxver"

    dep "foo" {
        identity "sha256:a1e5adf..."
        version "0.0.1"
        src_dir "src"
        requires
        provenance {
            kind "git"
            url "https://github.com/example/foo.git"
            ref "main"
            commit_sha "abcdef12..."
        }
    }

  expected/
    error
      FROZEN-IDENTITY-NOT-IN-STORE
```
