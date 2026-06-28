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
4. Require the `(url)` annotation on all URL fields (`git=`, `tarball=`, `mirror`); normalize to a
   URL string internally; reject other types with `MAN-URL-ARG-TYPE`.
5. Parse all five dep forms (URL, named, local, tarball, member) using the
   disambiguating properties described in §3.
6. Enforce that dep names are unique **within** each of `deps` and `dev-deps`
   independently (`MAN-DEP-DUPLICATE`); the same name in both blocks is valid
   (§3.3). For NamedDeps, uniqueness is by `(namespace, name)` pair (the
   solver variable) — two deps with the same bare name but different namespaces
   are distinct (S5b: `ns1/bar` and `ns2/bar` are not duplicates).
7. Parse the P3 provenance-descriptor model (§4): closed meta-grammar, the four
   declared kinds (`git`, `local`, `tarball`, `oci`), and the three behavioral
   properties (parse-always, verify-always, fetch-fails-precisely).
8. Reject an unknown provenance kind **only on a cache-miss fetch**; parse and
   verify-if-materialized MUST succeed.
9. Parse `.nimble` transitive-dep files using the heuristic defined normatively
   in `spec/dep-decl.md §7`; translate recognized `when` conditions to
   `Predicate` tuples (§7.5.1); emit `UserWarning` only on UNRECOGNIZED
   conditions (§7.5.3); always include all `requires` unconditionally.
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
    (§6.7); default to the implementation's own version (`milpa.__version__`).
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

> NORMATIVE: A parser MUST require the `(url)` annotation on all URL-typed
> fields (`git=`, `tarball=`, and `mirror`). The canonical form is:
>
> - `git=(url)"https://github.com/foo/bar.git"`
>
> A plain (unannotated) string at a URL position MUST raise `MAN-URL-ARG-TYPE`.
> Any type annotation other than `(url)` on a URL position MUST also raise
> `MAN-URL-ARG-TYPE`.

> NORMATIVE: A serializer (formatter) MUST emit the `(url)` annotation on all
> URL-valued fields in generated output. This matches the strict parse requirement.

> NOTE: The reference Python serializer (`format_manifest`) emits `(url)` on
> every `git=`, `tarball=`, and `mirror` URL. The parser requires the `(url)`
> annotation via `_kdl_entry_as_url` in `kdl_io.py`.

---

## 3  Package manifest structure

### 3.1  Top-level nodes

> NORMATIVE: A package manifest MUST contain exactly one `name` node and at
> most one each of: `kind`, `deps`, `dev-deps`, `overrides`, `src_dir`, `flags`,
> `mirrors`, `cas`, `spec-version`, `attestation-policy`. Any other top-level
> node name MUST raise `MAN-UNKNOWN-TOP-LEVEL`. Two `name` nodes MUST raise
> `MAN-NAME-DUPLICATE`.

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
>
> NORMATIVE (R2-C2 + R2-Unicode security): **src_dir value safety.** The
> `src_dir` string MUST NOT contain ASCII control characters (codepoints
> 0x00–0x1F or 0x7F) or Unicode line separators (U+2028 or U+2029). These
> characters would inject extra lines into nim.cfg `--path:` directives when
> the value is incorporated verbatim. A parser MUST validate the value at parse
> time and raise `MAN-SRC-DIR-UNSAFE` if any forbidden character is present.

#### `attestation-policy` field

> NORMATIVE: The `attestation-policy` node MUST carry exactly one positional
> string argument whose value is one of `"permissive"` (default) or `"strict"`.
> Wrong arity or a value outside the two-element set MUST raise
> `MAN-UNKNOWN-TOP-LEVEL`. When absent, the policy defaults to `"permissive"`.
>
> Under `"strict"`, any resolved named dep whose index entry carries no
> `dep_decl` pointer (and therefore falls back to un-attested `.nimble`
> metadata) causes `resolve()` to raise `RES-UNATTESTED-METADATA`. The
> `--require-attested-metadata` CLI flag and the `MILPA_REQUIRE_ATTESTED_METADATA`
> environment variable also activate strict mode; effective strict = logical OR of
> all three sources. The flag / env-var CANNOT weaken a manifest-declared strict
> policy (OR semantics, not override semantics).
>
> Non-strict (`"permissive"` or flag absent): if any named dep resolved from
> un-attested `.nimble` metadata, a single summary warning is emitted to stderr.

#### `cas` block

> NORMATIVE: The `cas` block MUST contain exactly one child node named `dir`
> carrying exactly one positional string argument. A missing `dir` child raises
> `MAN-CAS-DIR-MISSING`; wrong arity or non-string raises `MAN-CAS-DIR-TYPE`.
> When absent, the project-level CAS directory falls back to the environment
> variable `MILPA_CACHE_DIR` and then to the XDG default.

#### `mirrors` block

> NORMATIVE: The `mirrors` block declares alternative URLs where **this
> package** is hosted. Each child node MUST be named `mirror` and carry exactly
> one `(url)`-annotated URL argument. Unknown child names raise
> `MAN-MIRRORS-UNKNOWN-CHILD`; wrong arity raises `MAN-MIRRORS-ARITY`; a plain
> (unannotated) string raises `MAN-URL-ARG-TYPE`.

### 3.2  The `deps` block

> NORMATIVE: The `deps` block contains zero or more dep declarations.
> Dep names MUST be unique within the manifest; duplicates raise
> `MAN-DEP-DUPLICATE`.
>
> NORMATIVE (R2-C1 security): **Dep name charset.** Every dep node name (the
> KDL node identifier, which becomes the dep's canonical name) MUST match
> `[A-Za-z0-9_-]+`. The `member` node is exempt (it is a keyword, not a dep
> name). KDL 2.0 quoted identifiers can contain characters outside this set;
> a parser MUST validate every dep name at parse time and raise
> `MAN-DEP-NAME-INVALID` if the name contains any disallowed character. Dep
> names flow to nim.cfg `--path:` lines and feature-flag defines
> (`-d:<pkg>_<flag>`); an injection character in the name would produce
> extra nim.cfg lines. Alias names (derived from dep names by the optional
> desugar pass) inherit this protection automatically.

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

Grammar:

```kdl
// Canonical form — namespace= attribute
<name> [namespace="<ns>"] ["<version-constraint>"]

// Slash-shorthand sugar — desugars at parse time to the canonical form
"<ns>/<name>" ["<version-constraint>"]
```

> NORMATIVE: A NamedDep MUST have zero or one positional string argument (the
> version constraint). More than one positional arg raises `MAN-DEP-NAMED-ARITY`;
> a non-string arg raises `MAN-DEP-NAMED-CONSTRAINT`. Any property other than
> `git=` (which routes to UrlDep), `optional=`, and `namespace=` raises
> `MAN-DEP-NAMED-PROPS`.

> NORMATIVE (S5b — namespace-qualified named deps): A NamedDep MAY carry a
> `namespace=` attribute whose value is a non-empty string matching the dep-name
> charset `[A-Za-z0-9_-]+`. An empty or non-string `namespace=` value raises
> `MAN-DEP-NAMED-PROPS`; a non-empty value that violates the charset raises
> `MAN-DEP-NAME-INVALID`.
>
> Alternatively, the node name MAY use the **slash shorthand** syntax
> `"<ns>/<name>"` where both `<ns>` and `<name>` are non-empty and contain
> no further slashes. The parser MUST desugar this form at parse time into
> separate `namespace` + `name` fields. A name with more than one slash
> (e.g. `"a/b/c"`) or with an empty segment MUST raise `MAN-DEP-NAME-INVALID`.
>
> **M2 — disagreement rule (NORMATIVE):** If BOTH the slash shorthand AND
> a `namespace=` attribute are present on the same dep, the parser MUST check
> that the two namespace values agree. If they agree, the result is identical
> to either form alone (no error). If they DISAGREE, the parser MUST raise
> `MAN-DEP-NAME-INVALID`. Using both forms with the same namespace is
> redundant but not an error. Example (raises `MAN-DEP-NAME-INVALID`):
> `"ns1/bar" namespace="ns2"` (slash says ns1, attribute says ns2).
>
> Two NamedDeps with the same bare `<name>` but different `<namespace>` values
> are **distinct deps** (`DepKey = (namespace, name)`) and MUST NOT be flagged
> as `MAN-DEP-DUPLICATE`.
>
> The **canonical serialization** of a qualified NamedDep is the `namespace=`
> attribute form; the slash-shorthand MUST NOT appear in generated manifests.

> NORMATIVE: The solver variable for a NamedDep is:
> - Bare dep (no namespace): `<name>`
> - Qualified dep (has namespace): `<namespace>::<name>`
>
> The solver variable is SOLVER-INTERNAL ONLY — it MUST NOT appear in the
> lockfile, `_deps/` layout, `nim.cfg` paths, or the `requires` list.
> See `spec/resolver-semantics.md §6b` and `§6c` for the correct serialized
> forms of qualified dep names on each surface.

> NOTE: NamedDeps are resolved against the tianguis index. The constraint
> syntax is an opaque string passed to `VersionSet.from_constraint`; the
> constraint grammar is defined in `spec/resolver-semantics.md` (S6).
> Qualified NamedDeps use `lookup_qualified(ns, name)` which bypasses
> `TNG-AMBIGUOUS-NAME`; bare NamedDeps use the standard `resolve_named`
> path which may still raise `TNG-AMBIGUOUS-NAME` on collision.

#### LocalDep

Grammar: `<name> local="<path>"`

> NORMATIVE: A LocalDep MUST carry exactly one `local=` property whose value is
> a non-empty string (a relative-to-project or absolute filesystem path).
> Empty or non-string value raises `MAN-DEP-LOCAL-PATH`. No other properties
> are permitted (`MAN-DEP-UNKNOWN-PROPS`).

> NORMATIVE: LocalDep is NOT CAS-admissible. The fetcher MUST expose the
> source tree at `_deps/<name>` via a **symlink** to the source path; it MUST
> NOT copy or move the tree. Symlink semantics give the user edit-in-place
> behaviour: changes to the source tree are immediately visible through
> `_deps/<name>` without a re-fetch. The tree is not stored in the
> content-addressed store. See §4.3 and `spec/plugin-contract.md` (S10).

#### TarballDep

Grammar: `<name> tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]`

> NORMATIVE: A TarballDep MUST carry a `tarball=` URL (`(url)`-annotated,
> non-empty). A plain (unannotated) string or non-string raises `MAN-URL-ARG-TYPE`;
> an empty string raises `MAN-DEP-TARBALL-URL`.
> Other permitted properties: `sha256` (optional string; raises
> `MAN-DEP-TARBALL-SHA` if non-string when present) and `strip_components`
> (optional non-negative integer; raises `MAN-DEP-TARBALL-STRIP` if negative,
> non-numeric, or boolean). Default `strip_components` is `0`.

> NORMATIVE: A conformant tarball fetcher MUST support the following compression
> formats, detected by magic bytes on the downloaded archive before extraction:
>
> | Format | Magic bytes (hex) | Extension(s) |
> |--------|------------------|--------------|
> | gzip   | `1f 8b`          | `.tar.gz`, `.tgz` |
> | bzip2  | `42 5a 68`       | `.tar.bz2`, `.tbz2` |
> | xz     | `fd 37 7a 58 5a 00` | `.tar.xz` |
> | uncompressed tar | (no magic match) | `.tar` |
>
> Compression format detection MUST be based on magic bytes, not file-name
> extension. An archive in any of these formats MUST produce the same
> `content_hash` for the same extracted source tree (independent of compression
> format). Each decompressor MUST be wrapped in the same decompression-bomb size
> cap as the gzip path (`max_total_size` per `spec/plugin-contract.md` §2.1).

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

> NORMATIVE (S8 — RFC #23 §3.3): The `overrides` block contains zero or more
> override rules. Each child MUST be named `pkg`. The positional argument is the
> match name. Each `pkg` rule MUST carry **exactly one** provenance target form
> from the following three:
>
> - **Git form:** `pkg "<name>" git=(url)"<URL>" ref="<ref>"` — redirect to a git
>   fork. `git=` (URL-annotated string) and `ref=` (string) are both required.
>   Missing `ref=` raises `MAN-OVERRIDE-REF-MISSING`.
> - **Local form:** `pkg "<name>" local="<relative-path>"` — redirect to a local
>   filesystem path (non-reproducible; see §3.3 carve-out in RFC #23).
> - **Member form:** `pkg "<name>" { member "<member-name>" }` — redirect to a
>   workspace member. The `member` child takes exactly one positional string
>   argument (the member name).
>
> Zero target forms, or more than one form simultaneously (e.g. both `local=` and
> `git=`), raise `MAN-OVERRIDE-TARGET-AMBIGUOUS`.
>
> Other error codes: unknown override kind → `MAN-OVERRIDE-KIND`; wrong arity →
> `MAN-OVERRIDE-ARITY`; duplicate name → `MAN-OVERRIDE-DUPLICATE`; unknown property
> → `MAN-OVERRIDE-UNKNOWN-PROPS` (known properties: `git`, `ref`, `local`).
>
> ```kdl
> overrides {
>     pkg "chronos" git=(url)"https://github.com/example/chronos.git" ref="patched"
>     pkg "results" local="../results-fork"
>     pkg "stew" {
>         member "stew"
>     }
> }
> ```

> NORMATIVE: An override applies project-wide (manifest-direct deps, transitive
> URL deps, and named deps with the matching name). It does NOT propagate to
> downstream consumers of this project. Overrides change provenance; identity
> follows the target kind's rules (git: identity-bearing + CAS-admissible; local:
> liveness-only; member: identity-bearing, not CAS-admissible).

### 3.5  The `flags` block

> NORMATIVE: The `flags` block declares named feature flags. Each child node's
> KDL identifier is the flag name. Permitted properties: `default` (boolean,
> default `false`; raises `MAN-FLAG-DEFAULT-TYPE` if non-bool) and `description`
> (string; raises `MAN-FLAG-DESCRIPTION-TYPE` if non-string). No positional
> arguments are allowed (`MAN-FLAG-POS-ARGS`). Unknown properties raise
> `MAN-FLAG-UNKNOWN-PROPS`; duplicate flag names raise `MAN-FLAG-DUPLICATE`.

> NORMATIVE (H1 security): **Flag name charset.** Every flag name declared in
> the `flags {}` block MUST match `[A-Za-z0-9_-]+`. KDL 2.0 quoted node names
> can contain characters outside that set (spaces, `!`, control characters, etc.).
> A parser MUST validate every declared flag name against this charset and raise
> `MAN-FLAG-NAME-INVALID` for any name that fails. This is a parse-boundary check;
> the data model MUST NOT admit a flag with an illegal name.

> NORMATIVE: A flag MAY carry a single child node named `defines` with one or
> more positional string arguments (the `-d:` Nim compiler flags to pass when
> the flag is active). Unknown child names raise `MAN-FLAG-UNKNOWN-CHILD`; non-
> string `defines` args raise `MAN-FLAG-DEFINES-ARG-TYPE`.

> NORMATIVE (H1 + R2-Unicode security): **Defines value safety.** Every string
> argument to a `defines` node MUST NOT contain any ASCII control character
> (codepoints 0x00–0x1F and 0x7F), in particular `\n` (0x0A) and `\r` (0x0D),
> NOR the Unicode line separators U+2028 (LINE SEPARATOR) or U+2029 (PARAGRAPH
> SEPARATOR). KDL 2.0 string escapes allow `\n` and `\u{2028}` inside
> double-quoted strings; a manifest from a malicious transitive dep can exploit
> this to inject arbitrary `nim.cfg` lines (e.g. `--passC:…`, `--passL:…`)
> leading to code execution at the next `nim c` invocation. A parser MUST reject
> any `defines` string containing any of these characters with
> `MAN-FLAG-DEFINES-UNSAFE`. This is a parse-boundary check; the emission layer
> (nimcfg.py / nimcfg.rs) MUST NOT receive defines values that contain these
> characters.

> NORMATIVE (S1 — RFC #23 §3.1.1): **Name charset (cross-reference).** Flag names and dep names
> that participate in `enables`, optional-dep desugaring, or `when flag=`
> predicates MUST match `[A-Za-z0-9_-]+` (the KDL bare-identifier charset already
> used for dep names). The `MAN-FLAG-NAME-INVALID` check (above) supersedes the
> narrower S1 requirement for the `flags {}` block.

> NORMATIVE (S1 — RFC #23 §3.1.1): A flag MAY carry one or more `enables` child
> nodes. Each `enables` node may carry:
>
> - **Bare string positional arguments** — same-package flag names activated when
>   this flag is active.
> - **Child nodes** — cross-package activation: each child's KDL node-name is a
>   dep name; that dep's children are `flag "<name>" [#false]` requests,
>   structurally identical to the §3.6 consumer flag request form.
>
> A single `enables` node may carry both args and children. Multiple `enables`
> nodes union together. The canonical serialization form is a single `enables`
> node with all same-package names as positional args and all cross-package deps
> as children.
>
> ```kdl
> flags {
>     tls  default=#false
>     http default=#false
>     full default=#false {
>         enables "tls" "http" {          // same-package flags = bare string args
>             chronos { flag "tls" }      // cross-package = child node
>         }
>     }
> }
> ```
>
> **Validation (post-parse, normative).** After the full `flags` table is built,
> each bare same-package name in any `enables` MUST match a declared flag in the
> same manifest. Forward references (flag declared later in the block) are **legal**
> because validation is post-parse. An unmatched bare name raises
> `MAN-FLAG-ENABLES-UNDECLARED`. When the unmatched name is also a non-optional dep
> name in the same manifest, the diagnostic MUST add:
> `"<name>" is a dependency, not a flag — add optional=#true to make it a feature.`
>
> Cross-package `enables` children (dep-name node-names) are **not** validated at
> parse time — the dep may be conditionally absent; validation is resolve-time.

> NORMATIVE: **Flag activation fixpoint.** The `enables` relation defines a
> monotone propagation: activating a flag may activate additional flags (via
> same-package `enables` args) or request flags on deps (via cross-package
> `enables` children). Conformant implementations MUST compute the **least
> fixpoint** of this propagation — the unique smallest set of active flags
> consistent with all `enables` rules and the initial active set. Because the
> propagation only adds flags (never removes them) and the flag set is finite,
> the least fixpoint always exists and is unique. The normative output is the
> converged `active_flags` set; any internal iteration strategy (repeated
> forward pass, worklist, etc.) is an implementation detail. Implementations
> MUST NOT expose or document an iteration count as a convergence criterion;
> any internal safety cap MUST be set high enough that it can never truncate
> a real convergence on a valid manifest (a cap below the number of declared
> flags in the manifest would be incorrect). Two conforming implementations
> with different internal caps MUST produce byte-identical `active_flags`
> output for the same manifest and initial flag set.

> NORMATIVE (S1 — RFC #23 §3.1.4): A flag MAY carry a `conflicts` child node
> with one or more positional string args naming same-package flags that MUST NOT
> be co-active with this flag. The bare names in `conflicts` follow the same
> post-parse validation rule as `enables` same-pkg names — unmatched names raise
> `MAN-FLAG-CONFLICTS-UNDECLARED` (deferred to slice S4c; parsing and data-model
> round-trip of `conflicts` is S1). Symmetric: `openssl conflicts bearssl` implies
> `bearssl conflicts openssl`; declare once.

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
> store. The fetcher MUST expose the source tree via a **symlink** at
> `_deps/<name>` pointing directly to the source directory (no copy, no snapshot).
> This gives the user edit-in-place semantics: changes to the source directory
> are immediately visible through `_deps/<name>` without a re-fetch. See
> `spec/identity.md` §3.5 and `spec/plugin-contract.md` (S10) §1.2.

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
> | `local`   | `False`         | Editable source — symlinked in-place; admitting would freeze edits |
> | `member`  | `False`         | Workspace-internal; resolved by path, not fetch|
>
> The `FetcherRegistry` MUST check `cas_admissible` before calling `admit()`.
> See `spec/plugin-contract.md` (S10) for the full backend contract.

> NOTE: `cas_admissible` is **not** the same axis as *identity-bearing* (whether a
> dep carries a recorded content `identity` that is hash-compared on verify). The
> two coincide for `git` / `tarball` / `oci` and for `local`, but **diverge for
> `member`**: a `member` is `cas_admissible = False` (symlinked to the editable
> member directory, never admitted to the CAS) yet **identity-bearing** (its
> content is hashed and drift-detected). The single normative definition of both
> axes — and the per-axis consequences — is `spec/identity.md §4.1`.

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

> **RELOCATED:** The normative `.nimble`→`EdgeSet` heuristic — including the
> complete line-matching predicate, multi-line continuation rules,
> comment-line behavior, `when`-block policy, and authored-order preservation
> — is now specified in **`spec/dep-decl.md §7`** (the joint milpa↔tianguis
> contract). This is the single authoritative algorithm shared across all
> implementations (Python/Rust resolvers and tianguis ingest). The summary
> below is a cross-reference; `spec/dep-decl.md §7` is the normative source.

When no `milpa.kdl` is present, milpa auto-promotes a `.nimble` file.
`.nimble` files are NimScript (a Turing-complete Nim superset); milpa does not
execute them. Instead it applies the heuristic defined normatively in
`spec/dep-decl.md §7` to extract dependency information as an `EdgeSet`.

> NORMATIVE: A `.nimble` parser MUST extract `requires` and `srcDir` values
> using a line-by-line scan. It MUST NOT execute NimScript. See
> `spec/dep-decl.md §7` for the complete normative algorithm.

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
>   as the ref; the remainder is the URL. If no `#ref` fragment is present,
>   `ref` defaults to `"HEAD"` (the remote's default branch), matching
>   nimble's behavior. The empty string `""` MUST NOT be used as the default;
>   `"HEAD"` is the sole conformant default. (Normative definition:
>   `spec/dep-decl.md §7.2`.)
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

> **NORMATIVE DEFINITION IS IN `spec/dep-decl.md §7.5`** — the joint
> milpa↔tianguis contract. This section is a cross-reference summary only;
> `dep-decl.md §7.5` is the normative source and MUST be consulted for
> implementation.

> NORMATIVE: Implementations MUST recognize the bounded subset of NimScript
> `when` conditions defined in `spec/dep-decl.md §7.5.1` and translate them
> to `Predicate` tuples. Every `requires` from every branch is STILL included
> unconditionally — the dep set is unchanged. Predicates are recorded as
> metadata on `RequireEntry.predicates` and flow to the lockfile as additive
> `cond-require` annotations (`spec/lockfile-schema.md §3.5`). See
> `spec/dep-decl.md §7.5` for the complete normative algorithm including:
>
> - §7.5.1 — the translation table (recognized conditions → Predicate tuples)
> - §7.5.2 — branch algebra (`elif`/`else` negation, chain poisoning, nesting)
> - §7.5.3 — warning policy (fires ONLY on UNRECOGNIZED conditions; a fully
>   recognized file emits NO warning)
> - §7.5.4 — lockfile annotation and activation boundary (#110)
> - §7.5.5 — semantic asymmetry between root `milpa.kdl` `when` (filtered at
>   resolve time) and transitive `.nimble` `when` (recorded, activated by #110)
>
> The `spec/manifest-grammar.md §6` predicate vocabulary and `(not)` negation
> syntax (§6.1) are reused verbatim by the `.nimble` `when` translation — there
> is one predicate model in milpa. **`manifest-grammar.md §6` is UNCHANGED** by
> #26; the §7.5.1 table maps into the existing §6 vocabulary.

> NOTE: Unconditional inclusion is the safety invariant for the dep *set*:
> #26 never under-includes relative to pre-#26 behavior. The observable change
> is the addition of `cond-require` annotation nodes in the lockfile for
> recognized conditions; the `requires` line is byte-identical to today for any
> given dep's transitive set.

> IMPLEMENTATION NOTE (non-normative): Conforming implementations MAY bound the
> recursive traversal depth of nested `when` blocks for DoS resistance.  The
> reference value is **8** levels.  Beyond this bound the implementation MUST
> treat all branches as UNRECOGNIZED — that is, include every `requires` found in
> the sub-tree unconditionally with no predicate annotation.  This is the same
> over-include policy already applied to unrecognized conditions (§7.5.2), so the
> observable dep set is UNCHANGED: the bound does not alter which `requires`
> entries are resolved, only whether they carry predicate metadata.  Real
> `.nimble` files rarely exceed 2–3 levels of nesting; the bound is conservative
> enough to never fire in practice.  An attacker-crafted `.nimble` with thousands
> of nested `when` levels would otherwise cause unbounded stack growth (stack
> overflow) in a naive recursive implementation.  This note applies equally to
> the `spec/dep-decl.md §7.5` normative algorithm: implementations of that
> algorithm SHOULD apply the same bound.

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

> NORMATIVE: A `member` dep node MUST NOT appear inside a `when` block.
> Workspace members are unconditional topology — they are present in every
> resolution regardless of platform, arch, nim version, or flag predicates.
> A `member` inside a `when` block is a category error; the parser MUST raise
> `MAN-MEMBER-WHEN-GATED` rather than silently accepting or dropping the
> predicates. The four dep forms that DO support `when`-conditional syntax are:
> UrlDep, NamedDep, LocalDep, and TarballDep.

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

### 6.6  Predicate ordering (representational determinism)

> NORMATIVE: The predicate list attached to a parsed dep MUST preserve
> **source order**: outer `when`-block predicates first (outermost block
> first), followed by inline (node-property) predicates in source order,
> followed by child-node predicates in source order.  If a dep appears
> inside nested `when` blocks, the predicates from the outermost block
> are prepended before those of the next block, and so on.

> NORMATIVE: Predicate evaluation is **order-independent** (conjunction:
> all predicates must be satisfied).  Source order is preserved for
> representational determinism — so that equivalent manifests produce
> identical in-memory representations across implementations — not
> because order affects evaluation semantics.

> NORMATIVE: Implementations MUST NOT sort, deduplicate, or otherwise
> reorder predicates during parsing or merging.  Sorting is forbidden
> because it breaks cross-implementation byte-identity of any output
> that serializes predicate lists (e.g. lockfile `requires_predicates`
> entries, `CondRequire` blocks).

### 6.7  Profile environment overrides

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
> MUST parse back to the same logical `Manifest` (or `WorkspaceManifest`) value
> as the input (semantic round-trip). The canonical serializer's output IS
> **byte-stable**: `format(parse(format(m))) == format(m)` for all valid manifests
> and workspace manifests. This is distinct from "round-trips the original source"
> (which it does NOT — comments and trivia are dropped). The canonical serializer's
> byte-stability is pinned by conformance fixtures (fixture-264 for workspace
> manifests; `add`/`remove` output fixtures for package manifests) and MUST be
> preserved. `format_workspace_manifest` inherits this byte-stability guarantee.
>
> NOTE: Earlier drafts of this section said the output was "not byte-normative,
> unlike the lockfile." That framing was imprecise. The correct statement is:
> the output is NOT byte-normative with respect to the *original source* (it does
> not preserve comments, trivia, or original formatting), but the *canonical
> serializer* is byte-stable with respect to itself — repeated application
> produces the same bytes.

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
