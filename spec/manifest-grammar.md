# milpa manifest grammar (S4)

Normative spec of `milpa.kdl` — the package/workspace manifest format.
Every parser that claims milpa conformance MUST implement the rules marked
`> NORMATIVE:`. Items marked `> NOTE:` describe the reference Python
implementation; conformant alternatives MAY differ in those details.

This document covers the **manifest grammar** and **provenance-descriptor
model** only. Related specs:

- `spec/errors.md` — every error code this grammar can produce
- `spec/lockfile-schema.md` (S5) — lockfile representation of provenance
- `spec/resolver-semantics.md` (S6) — pre-solver predicate evaluation
- `spec/plugin-contract.md` (S10) — Layer 2 backend-binding contract

---

## Normative surface

A conformant implementation of this spec MUST:

1. Parse `milpa.kdl` files as valid KDL 2.0, rejecting all other input.
2. Distinguish the two disjoint document roles — **package** and **workspace** —
   by detecting a top-level `workspace { }` node.
3. Accept the top-level nodes of a package manifest (`name`, `kind`, `deps`,
   `dev-deps`, `overrides`, `src_dir`, `flags`, `mirrors`, `cas`,
   `spec-version`); reject unknown nodes with `MAN-UNKNOWN-TOP-LEVEL`.
4. Accept URLs in both bare-string and `(url)`-annotated form; normalize to a
   URL string internally; reject other types with `MAN-URL-ARG-TYPE`.
5. Parse all five dep forms (URL, named, local, tarball, member) using the
   disambiguating properties described in §3.
6. Enforce that dep names are unique **within** each of `deps` and `dev-deps`
   independently (`MAN-DEP-DUPLICATE`); the same name in both blocks is valid
   (§3.3).
7. Parse the P3 provenance-descriptor model (§4): closed meta-grammar, the four
   declared kinds (`git`, `local`, `tarball`, `oci`), and the three behavioral
   properties (parse-always, verify-always, fetch-fails-precisely).
8. Reject an unknown provenance kind **only on a cache-miss fetch**; parse and
   verify-if-materialized MUST succeed.
9. Parse `.nimble` transitive-dep files using the heuristic described in §5;
   emit `UserWarning` on `when` blocks; include all `requires` unconditionally.
10. Parse the `when`-block / inline-predicate conditional syntax (§6): four keys,
    OR semantics, negation annotation, mixed-negation rejection
    (`MAN-PREDICATE-MIXED-NEGATION`).
11. Evaluate predicates **before** passing deps to the solver (pre-solver
    filtering); cross-reference S6 for evaluation semantics.
12. Enforce that `strip_components` stripping happens **before** `content_hash`
    computation (so the hash reflects the stripped tree).
13. Parse the `spec-version` epoch field (§4.4): treat absent as epoch 1, reject
    epochs greater than the implementation's `MANIFEST_SPEC_VERSION` with
    `MAN-SPEC-VERSION-UNSUPPORTED`.
14. Parse the `dev-deps` block (§3.3) with the same dep grammar as `deps`;
    populate `Manifest.dev_deps` (empty when absent). Apply the resolution-
    context rule: root's dev-deps ARE resolved; a transitive dep's dev-deps
    MUST NOT enter the graph. Cross-reference resolver-semantics.md §9.
15. Honor `MILPA_TARGET_MILPA` as an override for the `milpa` predicate field
    (§6.6); default to the implementation's own version (`milpa.__version__`).
16. When serializing the manifest (§8): emit valid KDL 2.0; warn to stderr
    when comments are dropped; preserve dep-entry insertion order; emit
    `(url)` annotations on all URL fields.

---

## 1  Document format and file name

> NORMATIVE: A milpa manifest MUST be a valid [KDL 2.0](https://kdl.dev)
> document. A parser MUST reject documents that do not conform to KDL 2.0
> syntax and raise `MAN-KDL-SYNTAX`. Boolean values are written `#true`/`#false`;
> bare `true`/`false` are reserved identifiers and are rejected as syntax errors.

> NORMATIVE: The canonical manifest file name is `milpa.kdl`. Discovery order
> when no explicit path is given: (1) `<project_dir>/milpa.kdl`; (2)
> `<project_dir>/<basename>.nimble`; (3) any single `*.nimble` in the
> directory. Multiple `.nimble` files with no project-name match MUST raise
> `MAN-NIMBLE-AMBIGUOUS`. No manifest found MUST raise `MAN-NO-MANIFEST`.

> NORMATIVE: A milpa.kdl document takes exactly one of two disjoint roles:
> **package manifest** (has `deps`/`kind`) or **workspace manifest** (has
> `workspace { }` block). Mixing them is forbidden: a document with a
> `workspace` node MUST NOT also declare `deps` or `kind`
> (`MAN-WORKSPACE-HAS-DEPS-OR-KIND`). A document without a `workspace` node
> is always treated as a package manifest.

> NOTE: The reference implementation detects the role by scanning top-level
> node names for `workspace` before dispatching to `_parse_workspace_doc` or
> `_parse_manifest_doc` (`manifest.py:parse_workspace_or_manifest`).

---

## 2  The `(url)` type-annotation convention

KDL 2.0 supports optional type annotations on values: `(tag)"value"`. milpa
uses the `(url)` annotation to mark URL strings.

> NORMATIVE: A parser MUST accept both forms for any URL-typed field:
>
> - Plain string: `git="https://github.com/foo/bar.git"`
> - `(url)`-annotated: `git=(url)"https://github.com/foo/bar.git"`
>
> Both MUST be treated identically after normalization to a plain URL string.
> Any other type annotation on a URL position MUST raise `MAN-URL-ARG-TYPE`.

> NORMATIVE: A serializer (formatter) MUST emit the `(url)` annotation on all
> URL-valued fields in generated output. This is a documentation convention,
> not a parse requirement, but machine-written files MUST follow it for
> interoperability.

> NOTE: The reference Python serializer (`format_manifest`) emits `(url)` on
> every `git=`, `tarball=`, and `mirror` URL. The parser accepts both forms via
> `_url_arg` which coerces a kdl-py `ParseResult` (the product of `(url)` parsing)
> back to a plain string.

---

## 3  Package manifest structure

### 3.1  Top-level nodes

> NORMATIVE: A package manifest MUST contain exactly one `name` node and at
> most one each of: `kind`, `deps`, `dev-deps`, `overrides`, `src_dir`, `flags`,
> `mirrors`, `cas`, `spec-version`. Any other top-level node name MUST raise
> `MAN-UNKNOWN-TOP-LEVEL`. Two `name` nodes MUST raise `MAN-NAME-DUPLICATE`.

> NORMATIVE: The `name` node MUST carry exactly one positional string argument
> (the package name). Missing `name` raises `MAN-NAME-MISSING`; wrong arity or
> non-string arg raises `MAN-NAME-TYPE`.

> NORMATIVE: The `kind` node MUST carry exactly one positional string argument
> whose value is one of `"library"` or `"application"`. Wrong arity raises
> `MAN-KIND-ARITY`; any other value raises `MAN-KIND-INVALID`. When `kind` is
> absent, the package defaults to `"library"`.

> NORMATIVE: The `src_dir` node MUST carry exactly one positional string
> argument (a relative or absolute path). Wrong arity or non-string arg raises
> `MAN-SRC-DIR-TYPE`. When absent, `src_dir` defaults to the empty string.

#### `cas` block

> NORMATIVE: The `cas` block MUST contain exactly one child node named `dir`
> carrying exactly one positional string argument. A missing `dir` child raises
> `MAN-CAS-DIR-MISSING`; wrong arity or non-string raises `MAN-CAS-DIR-TYPE`.
> When absent, the project-level CAS directory falls back to the environment
> variable `MILPA_CACHE_DIR` and then to the XDG default.

#### `mirrors` block

> NORMATIVE: The `mirrors` block declares alternative URLs where **this
> package** is hosted. Each child node MUST be named `mirror` and carry exactly
> one URL argument (plain string or `(url)`-annotated). Unknown child names raise
> `MAN-MIRRORS-UNKNOWN-CHILD`; wrong arity raises `MAN-MIRRORS-ARITY`.

### 3.2  The `deps` block

> NORMATIVE: The `deps` block contains zero or more dep declarations.
> Dep names MUST be unique within the manifest; duplicates raise
> `MAN-DEP-DUPLICATE`.

> NORMATIVE: Dep disambiguation uses the following ordered rules on the dep's
> child KDL node:
>
> 1. If the node name is `member` → **MemberDep**
> 2. Else if the node has a `git=` property → **UrlDep**
> 3. Else if the node has a `local=` property → **LocalDep**
> 4. Else if the node has a `tarball=` property → **TarballDep**
> 5. Otherwise → **NamedDep**
>
> The disambiguation is property-presence-based; unknown properties on a
> recognized form raise `MAN-DEP-UNKNOWN-PROPS`.

#### UrlDep

Grammar: `<name> git=(url)"<URL>" ref="<git-ref>" [<predicate-props>] [{ … }]`

> NORMATIVE: A UrlDep MUST carry both `git=` and `ref=` properties. Missing
> `ref=` raises `MAN-DEP-REF-MISSING`. The `git=` URL MUST have a scheme;
> the supported schemes are `https`, `http`, `ssh`, `git`. No-scheme raises
> `MAN-GIT-URL-NO-SCHEME`; unsupported scheme raises `MAN-GIT-URL-BAD-SCHEME`.

> NORMATIVE: A UrlDep block MAY contain child nodes. Permitted children:
>
> - `mirror (url)"<URL>"` — a fallback URL tried in order after the primary
>   (`git=`) fails. Exactly one URL argument required (`MAN-DEP-MIRROR-ARITY`).
> - `flag "<name>" [<bool>]` — a consumer feature-flag request (§3.5).
> - Any predicate name from `{platform, arch, nim, milpa, flag}` as a
>   multi-value child node (§6.2).
>
> Any other child name raises `MAN-DEP-UNKNOWN-CHILD`.

#### NamedDep

Grammar: `<name> ["<version-constraint>"]`

> NORMATIVE: A NamedDep MUST have zero or one positional string argument (the
> version constraint). More than one positional arg raises `MAN-DEP-NAMED-ARITY`;
> a non-string arg raises `MAN-DEP-NAMED-CONSTRAINT`. Any property (other than
> `git=`, which routes to UrlDep) raises `MAN-DEP-NAMED-PROPS`.

> NOTE: NamedDeps are resolved against the tianguis index. The constraint
> syntax is an opaque string passed to `VersionSet.from_constraint`; the
> constraint grammar is defined in `spec/resolver-semantics.md` (S6).

#### LocalDep

Grammar: `<name> local="<path>"`

> NORMATIVE: A LocalDep MUST carry exactly one `local=` property whose value is
> a non-empty string (a relative-to-project or absolute filesystem path).
> Empty or non-string value raises `MAN-DEP-LOCAL-PATH`. No other properties
> are permitted (`MAN-DEP-UNKNOWN-PROPS`).

> NORMATIVE: LocalDep is NOT CAS-admissible. The fetcher MUST copy the source
> tree into `_deps/<name>/` as a snapshot; the copy is not stored in the
> content-addressed store. See §4.3 and `spec/plugin-contract.md` (S10).

#### TarballDep

Grammar: `<name> tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]`

> NORMATIVE: A TarballDep MUST carry a `tarball=` URL (plain string or
> `(url)`-annotated, non-empty). Empty or non-string raises `MAN-DEP-TARBALL-URL`.
> Other permitted properties: `sha256` (optional string; raises
> `MAN-DEP-TARBALL-SHA` if non-string when present) and `strip_components`
> (optional non-negative integer; raises `MAN-DEP-TARBALL-STRIP` if negative,
> non-numeric, or boolean). Default `strip_components` is `0`.

> NORMATIVE: `strip_components` MUST be applied **before** `content_hash`
> computation. The identity of a tarball dep is the sha256 of the
> **post-strip** extracted source tree, not of the raw archive bytes. The
> archive's sha256 is recorded as provenance receipt metadata (not identity).

> NOTE: When `sha256` is absent, the fetcher uses TOFU (trust-on-first-use):
> the archive is downloaded, its sha256 is computed and written to the lockfile
> receipt. Subsequent fetches that have the lockfile pin treat the recorded
> sha256 as the pre-declared `expected_sha256`. The TOFU policy is specified
> normatively in `spec/lockfile-schema.md` (S5).

#### MemberDep

Grammar: `member "<name>"`

> NORMATIVE: A MemberDep node MUST be named `member` (a reserved keyword, not
> a package name) and carry exactly one positional string argument (the
> workspace-member's intrinsic name). Wrong arity raises `MAN-DEP-MEMBER-ARITY`;
> any properties raise `MAN-DEP-MEMBER-PROPS`.

> NORMATIVE: MemberDep is NOT CAS-admissible. It resolves through the
> workspace member table, not through any fetcher. See §4.3.

### 3.3  The `dev-deps` block

> NORMATIVE: The `dev-deps` block declares dependencies needed to build or test
> **this package itself**. Its grammar is identical to the `deps` block (§3.2):
> the same five dep forms (UrlDep, NamedDep, LocalDep, TarballDep, MemberDep),
> the same `when`-conditional syntax (§6), and the same error codes (`MAN-DEP-*`)
> for malformed entries. Dep names MUST be unique within `dev-deps`;
> duplicates raise `MAN-DEP-DUPLICATE`.

> NORMATIVE: **Resolution context** — this is the core normative rule:
>
> - When a package is the **root** of a resolution (i.e., the package being
>   directly built/tested), its `dev-deps` entries ARE resolved alongside its
>   regular `deps`. They appear in the resolved graph, in `milpa.lock`, and on
>   the `nim.cfg` path.
> - When a package is a **transitive dependency**, its `dev-deps` MUST be
>   silently ignored. They MUST NOT enter the resolved graph. This mirrors
>   Cargo's `[dev-dependencies]` model.
> - A **workspace member** is treated as a root for its own resolution closure:
>   its `dev-deps` are enrolled alongside its `deps` in the workspace graph.
>
> See `spec/resolver-semantics.md` §9 for the normative resolver rule.

> NORMATIVE: `deps` and `dev-deps` are **independent namespaces**. A dep name
> MAY appear in both `deps` and `dev-deps` within the same manifest; this is
> NOT a duplicate. Uniqueness is enforced within each block independently —
> two entries with the same name inside `deps` raise `MAN-DEP-DUPLICATE`, and
> two entries with the same name inside `dev-deps` raise `MAN-DEP-DUPLICATE`,
> but the same name appearing once in each block is valid.

> NOTE: `dev-deps` is an additive extension to spec v1.0. Its presence does
> NOT require bumping `MANIFEST_SPEC_VERSION`; parsers that pre-date this
> extension will reject `dev-deps` as `MAN-UNKNOWN-TOP-LEVEL`. No existing
> serialized lockfile format changes are needed — resolved dev-deps appear as
> regular `dep` entries (they are requirements from the root's perspective).

### 3.4  The `overrides` block

> NORMATIVE: The `overrides` block contains zero or more override rules.
> Each child MUST be named `pkg`. In `pkg "<name>" git=(url)"<URL>" ref="<ref>"`:
> the positional arg is the match name; `git=` and `ref=` are both required.
> Unknown override kind raises `MAN-OVERRIDE-KIND`; wrong arity raises
> `MAN-OVERRIDE-ARITY`; missing `git=` raises `MAN-OVERRIDE-GIT-MISSING`;
> missing `ref=` raises `MAN-OVERRIDE-REF-MISSING`; duplicates raise
> `MAN-OVERRIDE-DUPLICATE`; unknown properties raise `MAN-OVERRIDE-UNKNOWN-PROPS`.

> NORMATIVE: An override applies project-wide (manifest-direct deps, transitive
> URL deps, and named deps with the matching name). It does NOT propagate to
> downstream consumers of this project. Overrides change provenance; identity
> follows the override's actual content hash.

### 3.5  The `flags` block

> NORMATIVE: The `flags` block declares named feature flags. Each child node's
> KDL identifier is the flag name. Permitted properties: `default` (boolean,
> default `false`; raises `MAN-FLAG-DEFAULT-TYPE` if non-bool) and `description`
> (string; raises `MAN-FLAG-DESCRIPTION-TYPE` if non-string). No positional
> arguments are allowed (`MAN-FLAG-POS-ARGS`). Unknown properties raise
> `MAN-FLAG-UNKNOWN-PROPS`; duplicate flag names raise `MAN-FLAG-DUPLICATE`.

> NORMATIVE: A flag MAY carry a single child node named `defines` with one or
> more positional string arguments (the `-d:` Nim compiler flags to pass when
> the flag is active). Unknown child names raise `MAN-FLAG-UNKNOWN-CHILD`; non-
> string `defines` args raise `MAN-FLAG-DEFINES-ARG-TYPE`.

> NORMATIVE: Any `when flag="<name>"` predicate (§6) that references a flag name
> not present in the `flags { }` block MUST raise `MAN-FLAG-UNDECLARED-REFERENCE`.

### 3.6  Consumer flag requests on a UrlDep

> NORMATIVE: A UrlDep block MAY contain `flag` child nodes to request a specific
> flag state from the dep. Grammar:
>
> ```
> flag "<name>"           // enable (implicit true)
> flag "<name>" true      // enable (explicit)
> flag "<name>" false     // opt out (override a default-true flag)
> ```
>
> Missing name raises `MAN-DEP-FLAG-NAME-MISSING`; more than two args raise
> `MAN-DEP-FLAG-TOO-MANY-ARGS`; a non-boolean second arg raises
> `MAN-DEP-FLAG-BOOL`.

---

## 4  P3 provenance-descriptor model

The milpa manifest grammar encodes deps as **provenance descriptors**: pure-data
declarations of where to obtain a source tree. This section specifies the
structural model these descriptors follow.

### 4.1  Layer 1 — Declaration surface

> NORMATIVE: A provenance descriptor has the **closed meta-grammar**:
>
> ```
> <kind> { <typed field>... }
> ```
>
> A descriptor is a **kind discriminant** (a string identifier) paired with
> **typed children** (the kind-specific fields). The meta-grammar is
> spec-frozen; adding a new kind requires a spec amendment but does NOT change
> the meta-grammar itself.

> NORMATIVE: The **kind-set** is owned by the spec-version. Spec v1.0 defines
> four kinds: `git`, `local`, `tarball`, `oci`. Future kinds require an
> amendment to the spec.

> NORMATIVE: Implementations MUST enforce the following three behavioral
> properties when encountering a provenance descriptor:
>
> 1. **Parse-always** — a parser MUST parse any descriptor regardless of whether
>    it recognizes the `kind`. Structural parsing (node shape, children as
>    key-value pairs) MUST succeed for unknown kinds; the parser MUST NOT raise
>    an error at parse time for an unknown `kind`.
>
> 2. **Verify-always (of a materialized tree)** — if a source tree has already
>    been materialized on disk (CAS hit or existing `_deps/<name>/`), the
>    implementation MUST be able to verify it by recomputing
>    `content_hash(tree)` and comparing to the locked identity — regardless of
>    whether it knows the `kind`. Transport knowledge is not required for
>    identity verification.
>
> 3. **Fetch-fails-precisely** — if and only if a dep with an unknown `kind`
>    has a **cache miss** (not materialized), the fetch MUST fail with a clear
>    diagnostic naming the unknown kind and the dep. This is a capability gap
>    (the impl cannot re-fetch), not a comprehension gap. Implementations MUST
>    NOT silently drop or skip the dep.

> NORMATIVE: The three properties together guarantee: an old implementation
> reading a newer lockfile/manifest MUST verify every already-fetched dep AND
> report precisely which deps it cannot re-fetch. Silent drops are forbidden.

### 4.2  Kind-specific shapes (spec v1.0)

#### `git`

Fields: `url` (string, required), `ref` (string, required), `commit_sha`
(string, optional — exact commit pin; takes precedence over `ref` when present).

> NORMATIVE: `url` MUST be a non-empty string with scheme in
> `{https, http, ssh, git}`. `ref` MUST be a non-empty string. `commit_sha`,
> when present, MUST be a valid git commit SHA; the fetcher MUST check out this
> exact commit rather than the tip of `ref`.

> NOTE: In the manifest, `git` provenance is expressed as a UrlDep's properties
> (`git=` + `ref=`), not as an explicit `git { }` node. The `git { }` block form
> appears in the lockfile and tianguis index. The meta-grammar is the same;
> the surface syntax differs by layer.

#### `local`

Fields: `path` (string, required — absolute path after resolver normalization).

> NORMATIVE: `path` MUST be an absolute path at the time the fetcher is
> invoked. Relative-to-project resolution from the manifest's `local="..."` value
> is the resolver's responsibility, performed before constructing the provenance
> descriptor.

> NORMATIVE: `local` is **NOT CAS-admissible** (`cas_admissible = False`).
> Implementations MUST NOT admit a local source tree into the content-addressed
> store. The motivation: admitting a local tree would silently freeze user edits.

#### `tarball`

Fields: `url` (string, required), `expected_sha256` (string, optional),
`strip_components` (non-negative integer, default `0`).

> NORMATIVE: `strip_components` stripping MUST be applied before
> `content_hash` computation. The locked identity is the sha256 of the
> **post-strip** extracted tree, not of the archive bytes.

> NORMATIVE: `expected_sha256`, when present, MUST be verified against the
> downloaded archive **before any extraction begins**. A mismatch MUST raise
> `FETCH-SHA256-MISMATCH` and MUST NOT create any files at the destination.

> NORMATIVE: `tarball` is CAS-admissible (`cas_admissible = True`). Extracted
> source trees MAY be admitted to the content-addressed store.

#### `oci`

Fields: `registry` (string, required), `repository` (string, required),
`digest` (string, required — an OCI digest in `<algorithm>:<hex>` form).

> NORMATIVE: The canonical reference form is
> `<registry>/<repository>@<digest>` (the `oci_ref` property). Implementations
> MUST use this form when invoking the pull tool (`oras` in the reference
> implementation).

> NORMATIVE: `oci` is CAS-admissible (`cas_admissible = True`).

### 4.3  `cas_admissible` per kind

> NORMATIVE: Each provenance kind declares whether fetched bytes are admissible
> to the content-addressed store. This is a contract, not an implementation
> detail:
>
> | Kind      | `cas_admissible` | Rationale                                      |
> |-----------|-----------------|------------------------------------------------|
> | `git`     | `True`          | Immutable once ref is pinned to commit SHA     |
> | `tarball` | `True`          | Immutable; pinned by archive sha256            |
> | `oci`     | `True`          | Immutable; pinned by digest                    |
> | `local`   | `False`         | Editable source — admitting would freeze edits |
> | `member`  | `False`         | Workspace-internal; resolved by path, not fetch|
>
> The `FetcherRegistry` MUST check `cas_admissible` before calling `admit()`.
> See `spec/plugin-contract.md` (S10) for the full backend contract.

### 4.4  Spec-version epoch field

> NORMATIVE: A package or workspace manifest MAY carry a top-level
> `spec-version <int>` node. When absent, the epoch defaults to `1`. When
> present, the argument MUST be a single positive integer (>= 1); wrong arity,
> non-integer arg, or value < 1 raises `MAN-SPEC-VERSION-TYPE`.
>
> ```kdl
> spec-version 1
> ```

> NORMATIVE: An implementation MUST reject (`MAN-SPEC-VERSION-UNSUPPORTED`) any
> manifest that declares an epoch greater than the highest epoch the
> implementation supports. The error message MUST name both the declared epoch
> and the highest supported epoch. This rule applies to both package and
> workspace manifests.

> NORMATIVE: The `spec-version` epoch is bumped **only** for breaking semantic
> changes to the manifest grammar — a change whose meaning cannot be inferred by
> an older implementation reading the syntax. Additive grammar changes (new node
> kinds, new provenance kinds, new optional fields) stay within the current epoch
> and are handled by the P3 forward-unknown properties in §4.1 (parse-always,
> verify-always, fetch-fails-precisely). No additive change bumps this epoch.

> NORMATIVE: A serializer MUST preserve the `spec-version` node exactly when
> it was present in the source (present-stays-present). A serializer MUST NOT
> emit `spec-version` into a manifest that did not originally declare it
> (absent-stays-absent). Both forms decode to the same logical epoch; the
> difference is source-level round-trip fidelity.

> NOTE: This epoch field is the same major-vs-minor bump discipline that the
> RFC's G4 uses for conformance fixtures — epoch bumps mean "an old impl cannot
> safely process this". It is a **distinct namespace** from
> `LOCKFILE_SCHEMA_VERSION` (owned by `lockfile.py` / S5) and from
> `TIANGUIS_INDEX_SCHEMA_VERSION` (owned by `tianguis_client.py`). The full
> lockfile↔spec-version mapping is owned by S5 (`spec/lockfile-schema.md`)
> — cross-reference there, not here.

---

## 5  `.nimble` compatibility parsing

When no `milpa.kdl` is present, milpa auto-promotes a `.nimble` file.
`.nimble` files are NimScript (a Turing-complete Nim superset); milpa does not
execute them. Instead it applies the heuristic described here to extract
dependency information.

> NORMATIVE: A `.nimble` parser MUST extract `requires` and `srcDir` values
> using a line-by-line scan. It MUST NOT execute NimScript.

### 5.1  The four `requires` forms

> NORMATIVE: A conformant `.nimble` parser MUST recognize all four of these
> forms:
>
> 1. **Single-line**: `requires "foo >= 1.0.0"`
> 2. **Comma-separated**: `requires "foo >= 1.0.0", "bar"`
> 3. **Multi-line continuation** (trailing comma): the parser MUST join
>    continuation lines until no trailing comma remains.
> 4. **Multiple `requires` statements**: each is processed independently.
>
> The parser extracts all quoted strings from each recognized `requires` line.

> NORMATIVE: Each extracted spec string is classified as follows:
>
> - If it starts with one of `http://`, `https://`, `ssh://`, `git://`,
>   `file://` → **URL requirement**. A `#ref` suffix (if present) is split off
>   as the ref; the remainder is the URL.
> - Otherwise → **named requirement**. The first whitespace-separated token is
>   the package name; any remainder is the version constraint string.
>
> This classification is the single authoritative rule for URL-vs-named
> disambiguation in `.nimble` files.

### 5.2  `srcDir`

> NORMATIVE: The `.nimble` parser MUST extract `srcDir = "<path>"` (with or
> without quotes around the path value). The extracted value is stored as
> `NimbleManifest.src_dir`.

### 5.3  `when`-block policy

> NORMATIVE: If any line matches the pattern `^\s*when\b`, the parser MUST:
>
> 1. Set an internal `has_when` flag.
> 2. Continue processing all `requires` and `srcDir` lines unconditionally
>    (do NOT attempt to evaluate the condition).
> 3. After completing the scan, emit a `UserWarning` with the exact text:
>
>    ```
>    .nimble contains `when` block(s); milpa does not evaluate nimscript, so
>    all `requires` are included unconditionally. If this over-includes,
>    consider expressing the conditionality in milpa.kdl with platform=/nim=
>    predicates (#26).
>    ```
>
> Conformant implementations MUST include all `requires` unconditionally when
> `when` blocks are present — over-inclusion is safe; under-inclusion would
> silently break builds.

> NOTE: The rationale for unconditional inclusion is that `when` blocks in
> `.nimble` files are NimScript expressions that milpa cannot safely evaluate.
> Skipping requires inside a `when` block could silently drop a dep.

### 5.4  `nim` requirement filtering

> NORMATIVE: When converting a `.nimble` file to a milpa `Manifest`, any
> `NamedRequirement` whose name is `"nim"` MUST be silently dropped. The Nim
> compiler version is the v2 toolchain RFC's territory, not source-dep
> resolution.

### 5.5  Error codes

> NORMATIVE: `NimbleParseError` is raised with `NIMBLE-FILE-NOT-FOUND` when
> the `.nimble` path does not exist; with `NIMBLE-FILE-UNREADABLE` when the
> OS denies access. On promotion to `ManifestError` at the milpa boundary:
> `MAN-NIMBLE-PARSE` wraps any `NimbleParseError`; `MAN-NIMBLE-AMBIGUOUS`
> is raised when multiple `.nimble` candidates exist.

---

## 6  Conditional deps and `when`-block syntax

milpa.kdl supports conditional dep declarations via predicates that are
evaluated against a runtime profile before deps are passed to the solver.

> NORMATIVE: Predicate evaluation MUST be performed **before** the dep set is
> given to the solver. Deps whose predicates do not match the current profile
> MUST be excluded entirely from the solver's input. See
> `spec/resolver-semantics.md` (S6) for the full evaluation semantics.

### 6.1  Inline predicate form (single-value)

Grammar: `<name> git=... ref=... platform="linux" nim=">= 2.0"`

> NORMATIVE: An inline predicate appears as a property on a dep node, whose
> key is one of the four recognized predicate names (`platform`, `arch`, `nim`,
> `milpa`) and whose value is a string. The value is the single match token for
> the predicate. Inline predicates carry exactly one value.

> NORMATIVE: Negation in inline form: the `(not)` type annotation on the value
> negates the predicate.
> Example: `platform=(not)"windows"` — satisfied when the platform is NOT
> `windows`.

### 6.2  Child-node predicate form (multi-value, OR semantics)

Grammar:
```kdl
intonaco git=(url)"..." ref="main" {
    platform "linux" "macosx"
}
```

> NORMATIVE: A predicate child node's KDL identifier is the predicate name;
> its positional arguments are the OR-combined match tokens. The predicate is
> satisfied if **any** value matches (OR semantics).

> NORMATIVE: All positional arguments on a predicate child node MUST agree on
> negation: either all are bare strings, or all are `(not)`-annotated. Mixing
> bare and `(not)` args on the same predicate node MUST raise
> `MAN-PREDICATE-MIXED-NEGATION`.

### 6.3  `when` block

Grammar:
```kdl
when platform="linux" {
    intonaco git=(url)"..." ref="main"
}
```

> NORMATIVE: A `when` node inside a `deps { }` block is a grouping construct.
> Its properties are predicates (same syntax as inline predicates on a dep).
> Each dep declared inside the `when` block inherits those predicates, combined
> with AND semantics with any predicates already on the dep itself.

> NOTE: `when` blocks and inline predicates compose with AND: a dep must
> satisfy ALL predicates from outer `when` blocks AND its own inline/child
> predicates to be included.

### 6.4  The four predicate keys

> NORMATIVE: The recognized predicate keys are:
>
> | Key        | Profile field | Value semantics                                       |
> |------------|--------------|-------------------------------------------------------|
> | `platform` | `platform`   | Exact string match against platform vocabulary (§6.5) |
> | `arch`     | `arch`       | Exact string match against arch vocabulary (§6.5)     |
> | `nim`      | `nim`        | Exact match OR semver constraint if value starts with `>=`, `<=`, `>`, `<`, `==`, `!=`, `~`, `^` |
> | `milpa`    | `milpa`      | Same as `nim` — exact match or semver constraint       |
> | `flag`     | flags set    | Satisfied if any value is in the active-flags set      |
>
> Any other key in a predicate position MUST raise `MAN-PREDICATE-UNKNOWN`.

> NORMATIVE: A non-string predicate value MUST raise
> `MAN-PREDICATE-VALUE-TYPE`. An unsupported type annotation (anything other
> than `(not)`) MUST raise `MAN-PREDICATE-UNSUPPORTED-ANNOTATION`.

> NORMATIVE: The same predicate name MUST NOT appear in both inline form
> (as a property) and child-node form on the same dep. Doing so raises
> `MAN-PREDICATE-FORM-CONFLICT`.

### 6.5  Platform and architecture vocabulary

The profile fields are normalized to Nim's `hostOS` / `hostCPU` vocabulary.

> NORMATIVE: Conformant implementations MUST use the following canonical token
> sets. Predicates MUST be compared against these normalized values.

**Platform tokens** (Nim `hostOS` names):

| Token      | Corresponding OS         |
|------------|--------------------------|
| `linux`    | Linux                    |
| `macosx`   | macOS / Darwin           |
| `windows`  | Windows                  |
| `freebsd`  | FreeBSD                  |
| `openbsd`  | OpenBSD                  |
| `netbsd`   | NetBSD                   |

> NOTE: The reference Python implementation maps Python's `platform.system()`
> to these tokens: `"darwin"` → `"macosx"`, `"windows"` → `"windows"`,
> `"linux"` → `"linux"`, `"freebsd"` → `"freebsd"`, `"openbsd"` → `"openbsd"`,
> `"netbsd"` → `"netbsd"`. Other values pass through unchanged (best-effort).

**Architecture tokens** (Nim `hostCPU` names):

| Token   | Corresponding CPU         |
|---------|--------------------------|
| `amd64` | x86-64 (also `x86_64`)   |
| `arm64` | ARM 64-bit (also `aarch64`) |
| `i386`  | x86 32-bit               |

> NOTE: The reference Python implementation maps `platform.machine()` to these
> tokens: `"x86_64"` → `"amd64"`, `"amd64"` → `"amd64"`, `"aarch64"` →
> `"arm64"`, `"arm64"` → `"arm64"`, `"i386"` → `"i386"`, `"i686"` → `"i386"`.
> Other values pass through unchanged.

### 6.6  Profile environment overrides

> NORMATIVE: The following environment variables MUST override the detected
> profile fields when set and non-empty:
>
> | Variable                  | Overrides field |
> |---------------------------|-----------------|
> | `MILPA_TARGET_PLATFORM`   | `platform`      |
> | `MILPA_TARGET_ARCH`       | `arch`          |
> | `MILPA_TARGET_NIM`        | `nim`           |
> | `MILPA_TARGET_MILPA`      | `milpa`         |
>
> These variables enable cross-platform resolution (e.g., resolving deps for a
> different target OS from the host).

> NOTE: `MILPA_TARGET_NIM` sets the `nim` field directly as a version string.
> When not set, the reference implementation queries `nim --version` and parses
> the `Version X.Y.Z` line. On failure it defaults to `"0.0.0"` (ensuring that
> `nim`-keyed conditional deps do not match).

> NOTE: `MILPA_TARGET_MILPA` sets the `milpa` field directly as a version
> string, overriding the implementation's own version (`milpa.__version__`).
> This allows testing how `when milpa="..."` predicates resolve across milpa
> version boundaries without changing the installed binary.

---

## 7  Workspace manifest structure

> NORMATIVE: A workspace manifest contains a `workspace { }` block and
> optionally `name` and `overrides` top-level nodes. It MUST NOT contain `deps`
> or `kind` (`MAN-WORKSPACE-HAS-DEPS-OR-KIND`). Any other top-level node raises
> `MAN-WORKSPACE-UNKNOWN-TOP-LEVEL`.

> NORMATIVE: The `name` node, when present, MUST carry exactly one positional
> string argument. It is **informational only**: implementations MAY store or
> discard it without any behavioral effect. No other node depends on the
> workspace name, and it does not appear in the lockfile or nim.cfg output.

> NORMATIVE: The `workspace { }` block contains zero or more `member "<path>"`
> children, each carrying exactly one positional string argument (the member
> directory path). Wrong arity raises `MAN-WORKSPACE-MEMBER-ARITY`; duplicate
> paths raise `MAN-WORKSPACE-MEMBER-DUPLICATE`; unknown child names raise
> `MAN-WORKSPACE-UNKNOWN-NODE`.

> NOTE: A workspace manifest is a pure container. To make the workspace root
> itself a package, place the package at a subdirectory and declare it as a
> member. The "`.`" path is not currently supported as a workspace member
> (`WS-MEMBER-DOT`).

---

## 8  Manifest serialization

When milpa rewrites `milpa.kdl` (via `add`, `remove`, `update`, or any other
verb that mutates the manifest), it produces a serialized KDL 2.0 document.
This section specifies the normative constraints on that output.

> NORMATIVE: A serializer MUST produce a valid KDL 2.0 document. The output
> MUST parse back to the same logical `Manifest` value as the input (semantic
> round-trip), but it is NOT required to be byte-identical to the original
> source (this output is **not byte-normative**, unlike the lockfile).

> NORMATIVE: Comments from the original `milpa.kdl` are NOT preserved by the
> serializer. When any comment is dropped, the implementation MUST emit a
> warning to stderr of the form:
>
> ```
> warning: milpa.kdl comments are not preserved when the manifest is rewritten
> ```
>
> The warning MUST be emitted to stderr before writing the new file. It MUST
> NOT be suppressed even when the write is otherwise successful.

> NORMATIVE: Dep-entry order within `deps` and `dev-deps` blocks MUST be
> **insertion-stable**: entries appear in the same order they were declared
> in the source, with newly-added entries appended at the end of the block.

> NORMATIVE: All URL-valued fields in the serialized output MUST carry the
> `(url)` type annotation (see §2).

> NOTE: The reference Python serializer (`format_manifest` in `manifest.py`)
> does not currently detect and warn about dropped comments — that is tracked
> as a future deliverable (#15). The normative warning requirement is binding
> on the spec; implementations that cannot yet detect comments SHOULD document
> the limitation clearly.

---

## Appendix A  Complete dep-form grammar summary

```kdl
deps {
    // URL dep
    <name> git=(url)"<https|http|ssh|git URL>" ref="<git-ref>"
           [platform="<token>" | platform=(not)"<token>"]
           [arch="<token>"     | arch=(not)"<token>"]
           [nim="<semver-or-constraint>"]
           [milpa="<semver-or-constraint>"] {
        [mirror (url)"<fallback-URL>"]
        [flag "<flag-name>" [<bool>]]
        [platform "<t1>" "<t2>" ...]     // OR-form, all bare or all (not)
        [arch "<t1>" "<t2>" ...]
    }

    // Named dep (registry-resolved)
    <name>                           // any version
    <name> "<version-constraint>"    // e.g. ">= 0.5.0"

    // Local dep
    <name> local="<path>"

    // Tarball dep
    <name> tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]

    // Workspace-internal member dep
    member "<member-name>"

    // Conditional group
    when platform="<token>" [arch="<token>"] ... {
        // any dep forms above
    }
}
```

---

## Appendix B  Predicate evaluation quick-reference

Predicate evaluation is defined normatively in
`spec/resolver-semantics.md` (S6). The syntax rules that govern what the
parser accepts (and what errors it raises) are normative here. A quick
summary for reference:

- **AND across predicates**: a dep must satisfy ALL its predicates.
- **OR within a predicate**: satisfied if ANY value matches (negated: satisfied
  if NO value matches).
- **`nim` / `milpa` constraint values**: if the declared value starts with
  `>=`, `<=`, `>`, `<`, `==`, `!=`, `~`, or `^`, it is interpreted as a semver
  constraint against the profile's version string. Otherwise exact string
  match.
- **`flag` predicate**: satisfied if any declared value names an active feature
  flag (flags whose `default=true` plus any explicitly enabled by the consumer).
- **Evaluation order**: filter happens entirely before the solver receives the
  dep set.
