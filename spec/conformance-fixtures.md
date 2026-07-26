# milpa conformance fixture format (S8a)

Normative spec of the **directory-tree fixture format** shared by all milpa
conformance suites — Python, Rust, and any future implementation. Every
implementation that claims conformance to a spec version MUST pass the
corresponding fixture set without modification.

Every rule marked `> NORMATIVE:` is a conformance requirement. Items marked
`> NOTE:` describe the reference Python implementation or rationale; conformant
alternatives MAY differ in those details.

Related specs:

- `spec/lockfile-schema.md` (S5) — normative `milpa.lock` and `nim.cfg`
  output formats cross-referenced from §2.4 and §2.5
- `spec/identity.md` (S12) — `_deps/` symlink convention cross-referenced
  from §2.6
- `spec/registry-protocol.md` (S14) — `index.kdl` input format
  cross-referenced from §2.2
- `spec/errors.md` — error slug catalog cross-referenced from §3
- `docs/rfc-reaching-rust-rewrite.md` — G4/S8a gate deliverable this doc
  fulfills
- `docs/rfc-multi-impl-strategy.md` — original conformance-suite design;
  `index.kdl` replaces the earlier `registry.json` placeholder (post-#97)

---

## Normative surface

A conformant implementation of this spec MUST:

1. Store all fixtures under `conformance/spec-v<N>/` where `N` is the
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

### Normative vs non-normative surface enumeration

The conformance gate compares implementations on a **closed, enumerated set
of normative surfaces** per command class. All other output is explicitly
**non-normative** and MAY differ per implementation by design
(`cli-contract.md §3.1`). The machine-readable source of truth is
`harness/surfaces.py` (S-A1); this prose enumerates the same set.

**Parity-normative — impls MUST agree on these (byte-exact or canonical-equal):**

| Surface | Scope | Comparison |
|---|---|---|
| `expected/milpa.lock` | success fixtures | byte-exact |
| `expected/nim.cfg` (root) | success fixtures, single-package | byte-exact, POSIX separators |
| `expected/<member>/nim.cfg` | success fixtures, workspace members | byte-exact, POSIX separators |
| `expected/_deps_structure.txt` | success fixtures with `_deps/` | byte-exact after `<CAS_ROOT>` substitution |
| `expected/certificate.json` | `check-certificate` fixtures | canonical JSON comparison (see §2.7.3) |
| `expected/error` (the slug on the `milpa-error: <SLUG>` line) | error fixtures | exact slug string (`spec/errors.md` catalog) |
| `expected/absent` (paths listed MUST NOT exist post-run) | success fixtures | existence check per listed path |
| Process exit code | all fixtures | exact integer; valid range `{0, 1, 2}` per `cli-contract.md §3` — `0` success/liveness/clean, `1` error, `2` usage error. Any code outside the range is a conformance violation. |
| `expected/milpa.kdl` | mutation fixtures (`add`/`remove`); per-member as `expected/<member>/milpa.kdl` | byte-exact |
| Empty stdout on success | `fetch`/`lock`/`verify`/`clean`/`add`/`remove`/`update` (non-liveness verbs) | stdout MUST be empty (`cli-contract.md §4`) |

**Explicitly non-normative — MAY differ per impl:**

- The human-readable diagnostic line(s) on stderr, including any prefix
  (Python `milpa:` vs Rust `<CODE>:`) — `cli-contract.md §3.1` makes this
  non-normative by design.
- Stdout prose for liveness commands (`show`, `--version`) — only exit-0 +
  non-empty stdout is asserted (see §2.7.2). (Non-liveness verbs, by contrast,
  MUST emit *empty* stdout on success — that is parity-normative, above.)
- Ordering and timing of progress output.

**Arbitration rule:** the spec is the arbiter. Impls agreeing is evidence, not
proof; impls disagreeing is a bug in one impl **or** a hole in the spec — never
resolved by "whatever the impls happen to do."

**Platform scope (spec v1):** this corpus is Linux/POSIX. Windows support
requires additional normalization (`_deps_structure.txt` path separators,
case-collision handling for `mocked-fetches/`, CRLF/LF for control files) and
is deferred to a future spec version.

---

## 1  Location and versioning

### 1.1  Fixture tree root

> NORMATIVE: All fixtures live under `conformance/` in the milpa
> repository. They are version-partitioned by spec version:
>
> ```
> conformance/
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
  project-dir                  # input (optional): project-root subpath (see §2.8.1)
  milpa.lock                   # input (optional): lockfile for parse-lockfile / frozen cmds
  cas-seed/                    # input (optional): source trees to pre-populate CAS (frozen cmd)
    <name>/                    # one subdirectory per dep to seed
      <file> ...               # source tree bytes (identity computed from these bytes)
  dep-decl/                    # input (optional): DepDecl artifact dir (see §2.11)
    <sha256_hex>.kdl           # one DepDecl artifact per named-dep version-node pointer
  mocked-fetches/              # input: per-URL fake-fetcher returns
    <url-encoded-key>/
      sha                      # git commit SHA (40 hex chars)
      content/                 # unpacked source tree bytes
        <file> ...
      <name>.nimble            # nimble file for the package (may be absent)
  expected/                    # success: outputs to byte-diff
    milpa.kdl                  # mutation fixtures only: post-mutation manifest (see §2.4.1)
    milpa.lock                 # or: error fixture has none of these
    nim.cfg                    # single-package fixtures only (see §2.5)
    <member>/                  # workspace fixtures only: one dir per member
      nim.cfg                  #   the member's own nim.cfg (see §2.5)
    _deps_structure.txt
    certificate.json           # check-certificate fixtures only (see §2.7.3)
  # — OR for an error fixture (see §3) —
  expected/
    error                      # contains the bare error slug
    certificate.json           # check-certificate error fixtures only (see §2.7.3)
```

> NOTE: A single-package fixture has exactly one `expected/nim.cfg`. A
> workspace fixture instead has one `expected/<member-path>/nim.cfg` per
> declared member and **no** root `expected/nim.cfg` (§2.5). `milpa.lock` and
> `_deps_structure.txt` remain single shared root outputs in both cases.

### 2.1  `milpa.kdl` — project manifest

> NORMATIVE: `milpa.kdl` MUST be a valid milpa manifest as defined in
> `spec/manifest-grammar.md`. It is the sole manifest input to the
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
> as defined in `spec/registry-protocol.md`. It contains the frozen set of
> named packages visible to this fixture's resolver run. A fixture that
> exercises no named deps MAY include `index.kdl` as an empty index (a document
> with only a `schema_version` node and no `package` nodes), or MAY omit
> `index.kdl` entirely.

> NORMATIVE: `MILPA_INDEX_URL` env-var semantics in the harness (three-way;
> `spec/cli-contract.md §8.1` NORMATIVE):
>
> | Fixture state | Harness sets `MILPA_INDEX_URL` to | Impl behavior |
> |---|---|---|
> | `index.kdl` **present** | `file://<abs-path>` | Load from that file (no network). |
> | `index.kdl` **absent** | `""` (empty string) | Explicitly no index; `index=None` without any network attempt. |
>
> The harness ALWAYS sets `MILPA_INDEX_URL` (never leaves it absent), so the
> impl's "absent → DEFAULT_INDEX_URL" production path is never triggered inside
> the conformance corpus. This keeps the corpus hermetic: no fixture ever touches
> the live tianguis network.

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

> NORMATIVE: `mocked-fetches/` is a **language-neutral CLI transport**, not a
> per-impl in-process detail. A conformant implementation MUST consume it
> through the `MILPA_MOCKED_FETCHES` env var (`spec/cli-contract.md` §8.4):
> pointing that var at a fixture's `mocked-fetches/` directory makes the CLI
> satisfy every fetch from it, with no network. This is what lets a single
> black-box harness run the corpus against any implementation as a subprocess.
> The "conformance adapter" phrasing below describes the reference *in-process*
> path (a developer-loop convenience that MUST delegate to the same mocked
> transport); the normative consumption contract is §8.4. The directory layout
> and key encoding in this section are the shared source of truth for both.

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
> algorithm (`spec/identity.md`) is then applied to `dest` to compute
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
> identity algorithm (`spec/identity.md`) runs over all of `dest` and
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

#### 2.3.3  Mocked ref-resolution (default-branch discovery)

> NORMATIVE: When `MILPA_MOCKED_FETCHES` is set, **ref-resolution** (the
> `git ls-remote --symref HEAD` default-branch discovery that `add --git`
> performs when no `ref=` is given — `spec/cli-contract.md` §5.6) MUST also be
> answered from the `mocked-fetches/` tree, with no network. The implementation
> discovers the default branch for `<url>` by locating the unique
> `mocked-fetches/<key>/` whose decoded URL equals `<url>` and returning that
> entry's ref (the ref component of the URL-key, §2.3.1). The fetch then proceeds
> against that same entry. This reuses the single mock entry as the source of
> truth for both the ref and the `sha` (§2.3.2) — there is no separate
> ref→SHA table. If `add --git` is given `ref=` explicitly, no ref-resolution
> occurs and the fetch is satisfied directly from `mocked-fetches/<url-key>/`.

#### 2.3.4  Tarball mock entries

> NORMATIVE: A **tarball** dep is mocked by a `mocked-fetches/<key>/` entry whose
> key is `url_key(url, "")` (§2.3.1 with an **empty ref** component, i.e.
> `<sanitized-url>@`). A tarball has no ref, so the ref slot is always empty; this
> is consistent with the URL-prefix match used by ref-resolution (§2.3.3).

A tarball subdirectory under `mocked-fetches/<key>/` MUST contain:

**`archive_sha256`** (required)

> NORMATIVE: A plain text file containing exactly one line: the lowercase
> hexadecimal sha256 of the (notional) downloaded archive bytes — the value the
> mocked tarball transport reports as the archive digest. No trailing whitespace
> other than a single newline. This is the **archive receipt** (provenance), NOT
> the identity: the identity is still computed by hashing the materialized
> `content/` tree (`spec/identity.md`). The two are orthogonal
> (`lockfile-schema.md §5`).
>
> The mocked transport mirrors the real `TarballFetcher`: when the resolver
> supplies an `expected_sha256` (a manifest `sha256=` pin, or a TOFU pin reused
> from the prior lockfile per `resolver-semantics.md §8`), the transport compares
> it against `archive_sha256` and MUST raise `FETCH-SHA256-MISMATCH` on a
> mismatch — before staging any content. On a first fetch with no pin, the
> `archive_sha256` value is recorded as the tarball provenance `sha256` (TOFU
> first-use pinning).

**`content/`** (required) and **`<name>.nimble`** (optional)

> NORMATIVE: Identical semantics to the git case (§2.3.2): `content/` is the
> source tree staged into `dest` and hashed for the identity, and a sibling
> `<name>.nimble` is flattened into `dest` and included in the hash.

> NOTE: A tarball TOFU refetch fixture (a substituted-archive scenario) pairs
> this entry with a prior `milpa.lock` input (§2.9) whose tarball provenance
> records a `sha256` differing from `archive_sha256`, while `content/` still
> hashes to the locked `identity`. The identity gate alone then passes; only the
> archive-level §8 pin re-assertion catches the substitution — surfaced as
> `FETCH-ALL-FAILED` (the resolver's candidate-exhaustion code, §8a) wrapping the
> inner `FETCH-SHA256-MISMATCH`. On that failure the prior `milpa.lock` is left
> unchanged (atomic-write-on-failure).

**`archive`** (optional — raw-bytes mode; S4a)

> NORMATIVE: When present, `archive` is a raw binary file whose bytes are fed
> directly to the **real extractor** (the production `TarballFetcher` decode path,
> including magic-byte decompression auto-detect, decompression-bomb guard, and
> `safe_extract`). This mode takes **PRECEDENCE** over `format` (build mode) and
> `archive_sha256` (copy mode) — conformant implementations MUST check for
> `archive` first.
>
> On success, the receipt's `archive_sha256` MUST equal `sha256(raw bytes)`,
> identical to what the real `TarballFetcher` would compute for the same bytes.
> The content is extracted via the real extractor, not copied verbatim from
> `content/`; a `content/` directory or `format` file in the same key dir is
> ignored.
>
> On failure (corrupt or malformed archive), the real extractor raises the inner
> extract failure (Python: `FETCH-EXTRACT-FAILED` via `tarball.py`; Rust:
> `FETCH-EXTRACT-FAILED` via `fetchers.rs`). The mocked fetcher MUST NOT
> pre-validate or swallow errors — raw bytes go straight to the real extractor.
> At the resolver boundary, `FETCH-EXTRACT-FAILED` is wrapped to `FETCH-ALL-FAILED`
> (`resolver-semantics.md §8a`); fixtures that exercise this path assert the
> wrapper slug.
>
> This mode is the mechanism for adversarial corrupt-archive fixtures (S4 in
> `docs/rfc-conformance-parity.md §5`). The `archive` file has no TOFU pin
> re-assertion — it is treated as a first-fetch; the `expected_sha256` pin on the
> provenance is not consulted.

#### 2.3.5  OCI mock entries

> NORMATIVE: An **OCI** dep is mocked by a `mocked-fetches/<key>/` entry whose
> key is `url_key(f"{registry}/{repository}", digest)` (§2.3.1, applied to the
> `registry/repository` pair as the "location" half and `digest` as the "pointer"
> half). This mirrors the git split (§2.3.1: `url` = location, `ref` = pointer)
> and the tarball split (§2.3.4: `url` = location, empty pointer): for OCI, the
> registry+repository is the location and the content digest is the (already
> immutable) pointer. For example, `registry="ghcr.io"`, `repository="example/bar"`,
> `digest="sha256:aa..."` encodes to `ghcr.io_example_bar@sha256_aa...` — the same
> flat `mocked-fetches/` namespace shared by git and tarball entries, with no
> per-kind subdirectory prefix.

An OCI subdirectory under `mocked-fetches/<key>/` MUST contain:

**`content/`** (required) and **`<name>.nimble`** (optional)

> NORMATIVE: Identical semantics to the git and tarball cases (§2.3.2, §2.3.4):
> `content/` is the source tree staged into `dest` and hashed for the identity,
> and a sibling `<name>.nimble` is flattened into `dest` and included in the
> hash.

> NOTE: Unlike git (`sha`) and tarball (`archive_sha256`), an OCI mock entry
> carries **no separate receipt-input file**. The real `OciFetcher`'s receipt
> (`OciReceipt.layer_digest`) is exactly the `digest` field already present on
> the `OciProvenance` being fetched — an OCI digest is a content pointer chosen
> by the caller (the index entry or manifest dep block), not a mutable ref
> resolved by the transport (contrast git's mutable branch/tag → commit SHA).
> The mocked fetcher therefore has nothing new to disclose: it stages
> `content/` (+ `<name>.nimble`) verbatim and returns a receipt that echoes the
> provenance's own `digest`. `FETCH-MOCK-MISSING` is raised when the key
> directory does not exist, exactly as for git and tarball.

### 2.4  `expected/milpa.lock` — expected lockfile

> NORMATIVE: For a success fixture, `expected/milpa.lock` MUST be a valid
> lockfile as defined in `spec/lockfile-schema.md`. A conformant
> implementation's output MUST be byte-identical to this file. Diff of any
> single byte is a conformance failure.

> NOTE: The byte-exact requirement means that the expected file is generated
> by the reference implementation and checked in. If the lockfile format
> changes in a normative way, the spec version bumps and new fixtures are
> written. Existing `spec-v1/` fixtures are not regenerated.

### 2.4.1  `expected/milpa.kdl` — expected post-mutation manifest (mutation fixtures only)

> NORMATIVE: For a mutation success fixture whose verb rewrites the manifest
> (`add`, `remove`), `expected/milpa.kdl` MUST be the exact bytes of the
> rewritten `milpa.kdl` the verb leaves in the project directory. A conformant
> implementation's post-run `milpa.kdl` MUST be byte-identical after the §2.6
> normalization rules.

> NORMATIVE: The `update` verb MUST NOT mutate `milpa.kdl`. Therefore an
> `update` fixture MUST NOT contain `expected/milpa.kdl`.

### 2.5  `expected/nim.cfg` — expected compiler path config

> NORMATIVE: For a **single-package** success fixture, `expected/nim.cfg` MUST
> contain the nim.cfg output as defined in `spec/lockfile-schema.md`
> §nim.cfg emission. A conformant implementation's output MUST be
> byte-identical.

> NORMATIVE: For a **workspace** success fixture, there is no root
> `expected/nim.cfg`. Instead, each declared member `member "<path>"` has an
> `expected/<path>/nim.cfg` containing that member's nim.cfg output (the
> per-member emission defined in `spec/resolver-semantics.md` §11.4).
> Each member's `--path:` lines are relative to the member's own
> directory: sibling member references resolve to `../<other-member>/<src_dir>`
> and external deps to the shared `../_deps/<dep>/<src_dir>`. A conformant
> implementation's output for each member MUST be byte-identical to its
> `expected/<path>/nim.cfg`.

> NOTE: `nim.cfg` uses POSIX path separators regardless of the host OS
> (`spec/lockfile-schema.md` NORMATIVE item 8). Fixtures MUST use POSIX
> separators; a Windows implementation that produces `\` paths fails the
> byte-diff and is non-conformant.

### 2.6  `expected/_deps_structure.txt` — expected `_deps/` layout

`_deps_structure.txt` captures the expected filesystem structure of the `_deps/`
directory after `milpa fetch` completes. It serves as the conformance check for
the CAS-admission and symlink-creation steps defined in `spec/identity.md`
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
> `spec/identity.md` §3.4); `_deps_structure.txt` records the *resolved*
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

> NORMATIVE: If `cmd` is present, its **first whitespace-separated token** MUST
> be one of the following selectors. The `resolve` / `parse-lockfile` / `frozen`
> selectors take no further tokens. The mutation selectors (`add` / `remove` /
> `update`) and the liveness selectors (`show` / `--version`) take the argv
> tokens defined below. The `check-certificate` selector takes an optional
> verb token (`fetch` or `lock`; default `fetch`).
>
> - `resolve` — parse `milpa.kdl` (and optionally `index.kdl`) and resolve the
>   dep graph against mocked-fetches. This is the default when `cmd` is absent.
> - `parse-lockfile` — parse the fixture's `milpa.lock` input only. No
>   `milpa.kdl`, `index.kdl`, or `mocked-fetches/` are read. Used exclusively for
>   `LOCK-*` error fixtures. This entry point has no success variant (no output
>   files); every `parse-lockfile` fixture is an error fixture.
> - `lock-roundtrip` — parse the fixture's `milpa.lock` input, re-emit it via
>   the canonical emitter, and byte-compare against `expected/milpa.lock`. No
>   `milpa.kdl`, `index.kdl`, or `mocked-fetches/` are read. Tests parse+format
>   for lockfile fields not produced by the resolver pipeline (e.g. Phase B
>   `aliases`). MUST be a success fixture; error cases belong in `parse-lockfile`.
> - `frozen` — exercise the no-network frozen fast path: parse `milpa.kdl` and
>   `milpa.lock`, optionally seed the CAS from `cas-seed/`, then resolve without
>   fetching. Used for `FROZEN-*` fixtures; MAY be a success or error fixture.
> - `check-certificate` — resolve and assert the `--certificate` JSON output
>   alongside the normal exit/slug. MAY be a success or error fixture (see
>   §2.7.3).

#### 2.7.1  Mutation selectors (`add` / `remove` / `update`)

> NORMATIVE: The mutation selectors exercise the manifest/lockfile-rewriting
> verbs (`spec/cli-contract.md` §5.6–5.8). The `cmd` line mirrors the real CLI
> verb argv in a transport-neutral surface form; a runner maps each form to the
> implementation's actual verb flags (e.g. `git=<url>` → `--git <url>`). The
> recognized forms are:
>
> - `add <name> git=<url> ref=<ref>` — add a new git dep `<name>` with the given
>   URL and ref. The runner MUST supply `ref=<ref>` explicitly so the fixture is
>   deterministic (no default-branch discovery is required). When `ref=` is
>   omitted, the implementation discovers the default branch via the mocked
>   ref-resolution transport (§2.3.3) — never the network.
> - `remove <name>` — drop top-level dep `<name>` from `milpa.kdl` and
>   re-resolve. No fetch occurs for the removed dep; a `remove` fixture whose
>   resulting graph is empty needs no `index.kdl` or `mocked-fetches/`.
> - `update` / `update <name>` — re-resolve and refresh `milpa.lock` (does NOT
>   mutate `milpa.kdl`). Requires `milpa.lock` as an input.

> NORMATIVE: A mutation success fixture expresses its post-mutation outputs via
> `expected/milpa.kdl` (the rewritten manifest; required for `add`/`remove`,
> absent for `update` which MUST NOT mutate the manifest) and, when the verb
> rewrites the lockfile, `expected/milpa.lock`. Both are byte-compared after the
> §2.6 normalization rules (`<CAS_ROOT>` substitution applies to any CAS path
> that leaks into a normative output; manifest/lockfile bytes otherwise compare
> verbatim). `expected/nim.cfg` and `expected/_deps_structure.txt` MAY also be
> present when the verb materializes `_deps/`. A mutation error fixture expresses
> the failure via `expected/error` (§3) and MUST leave `milpa.kdl`/`milpa.lock`
> unmodified.

#### 2.7.2  Liveness selectors (`show` / `--version`)

> NORMATIVE: `show` and `--version` have **non-frozen** output formats
> (`spec/cli-contract.md` §5.3 and §9). A fixture exercising either is a
> **liveness fixture**: the runner asserts only that the implementation exits 0
> and writes non-empty stdout. There is NO `expected/stdout` slot and stdout is
> NOT byte-compared. A `show` fixture supplies a resolvable project plus a
> `milpa.lock` input; `--version` requires no project inputs. The `cmd` line is
> the bare selector (`show` or `--version`).

> NORMATIVE: When `cmd` is absent or contains `resolve`, `index.kdl` MAY be
> omitted; its absence causes the runner to pass `index=None`, which triggers
> `RES-NO-INDEX` / `RES-WS-NO-INDEX` when the manifest has named deps (see
> §2.2). When `cmd` is `parse-lockfile`, `index.kdl` and `mocked-fetches/`
> MAY be omitted. When `cmd` is `frozen`, `milpa.lock` MUST be present;
> `index.kdl` and `mocked-fetches/` MAY be omitted if the fixture does not
> exercise the resolve path.

#### 2.7.3  Certificate selector (`check-certificate`)

> NORMATIVE: The `check-certificate` selector exercises the `--certificate`
> flag defined in `spec/cli-contract.md` §2.5. The `cmd` line for this selector
> is the bare token `check-certificate`; the runner maps it to the invocation:
>
> ```
> milpa --certificate <tmp-path> fetch   # (or lock, per §2.7.3 verb choice)
> ```
>
> The verb is `fetch` unless the fixture's `cmd` line is
> `check-certificate lock`, in which case `lock` is used. When `cmd` is
> the bare `check-certificate`, `fetch` is the default verb.
>
> A `check-certificate` fixture is always a **resolve** fixture (not
> `parse-lockfile` or `frozen`): it requires `milpa.kdl` and MAY include
> `index.kdl`, `mocked-fetches/`, and `milpa.lock` (as a prior lockfile per
> §2.9). It MUST contain `expected/certificate.json`.

> NORMATIVE: The runner MUST:
>
> 1. Invoke the implementation with `--certificate <tmp-path>` as a global flag
>    alongside the designated verb and the fixture's standard inputs
>    (`MILPA_MOCKED_FETCHES`, `MILPA_INDEX_URL`, `MILPA_CACHE_DIR`, etc.
>    applied as usual).
> 2. After the verb exits, read the file at `<tmp-path>` (it MUST exist unless
>    the fixture is a non-resolver error fixture — see below).
> 3. Parse the emitted file as JSON and compare it to `expected/certificate.json`
>    (also parsed as JSON) using the **canonical JSON comparison** defined below.
> 4. Also assert the exit code and slug as for a normal success or error fixture
>    (§3): a `check-certificate` fixture asserts BOTH the certificate JSON AND
>    the verb's normal exit/slug. These are independent assertions; both MUST
>    pass.

> NORMATIVE: **Canonical JSON comparison for certificates.**
>
> The comparison is **structural** (parse-then-compare), never byte-exact.
> The runner MUST parse both the emitted file and `expected/certificate.json`
> as JSON before comparing; whitespace, key ordering, and number formatting in
> the serialised bytes are not significant. The primitive layer of this
> comparison corresponds to **RFC 8785 JSON Canonicalization Scheme (JCS)**
> semantics: two JSON texts that serialise to the same JCS canonical form are
> considered equal at the byte level. In practice the runner implements this by
> parsing both texts and comparing the resulting value trees.
>
> The following domain-specific rules apply on top of the JCS primitive:
>
> - **Object comparison is key-order-independent**: two JSON objects with the
>   same keys and values are equal regardless of their serialised key order.
>   (This is already implied by parse-then-compare but is stated explicitly so
>   a third impl's fixture-authoring tool need not emit any particular key
>   order in `expected/certificate.json`.)
> - **Array comparison for `resolved` and `witness` is order-sensitive**: entries
>   MUST appear in the order mandated by `cli-contract.md` §2.5.1 (lexicographic
>   by `package`, then by `satisfied_by` within `package`). A conformant
>   implementation that emits a different order fails the fixture.
> - **`message` is excluded from comparison**: the runner MUST NOT compare
>   `message` values. The `message` field is human-readable diagnostic prose
>   (`cli-contract.md §3.1`); it is non-normative and MAY differ per
>   implementation and per run. The expected `certificate.json` for a failure
>   fixture MUST set `message` to `null` to make the exclusion explicit and
>   machine-enforceable.
> - **`refutation` is compared for set equality** (order-independent), not
>   sequence equality. The runner MUST sort both arrays by `(package,
>   constraint)` before comparing. The expected `certificate.json` for a failure
>   fixture MAY list entries in any order.
> - **Numeric and string values are compared by value**, not by lexical form
>   (e.g. `1.0` and `1` are distinct JSON values and compare unequal).
>
> **Deterministic emission (SHOULD).** Implementations SHOULD emit
> `certificate.json` with sorted object keys and no insignificant whitespace
> variation — i.e. output that is already JCS-canonical. This is cheap to
> implement (Python: `json.dumps(doc, sort_keys=True)`; Rust: emit keys in
> lexicographic order in format strings) and aids debuggability, authoring of
> `expected/certificate.json` fixtures, and future byte-exact comparison by a
> third implementation. It is a SHOULD, not a MUST, because the normative gate
> is the structural comparison above; an impl that emits valid JSON with
> scrambled key order still passes the conformance check. Both current
> implementations (Python and Rust) already happen to emit keys in a consistent
> order matching the field declaration order in the schema — the SHOULD
> formalises this behaviour without requiring a serialiser change in either impl.

**`expected/` layout for `check-certificate` fixtures.**

> NORMATIVE: A `check-certificate` success fixture MUST contain:
>
> - `expected/certificate.json` — the expected certificate JSON (comparison
>   semantics above).
> - `expected/milpa.lock` — the expected lockfile (byte-exact, as for a normal
>   `resolve` success fixture). When the verb is `fetch`, `expected/nim.cfg`
>   and `expected/_deps_structure.txt` MUST also be present; when the verb is
>   `lock`, they MUST NOT be present (consistent with §5.2).
>
> A `check-certificate` error fixture (one where the verb exits 1 because the
> resolve is UNSATISFIABLE) MUST contain:
>
> - `expected/error` — the bare slug (e.g. `SOLVE-CONFLICT`), as for a normal
>   error fixture.
> - `expected/certificate.json` — the expected failure certificate. The
>   `message` field MUST be `null`. The `refutation` array MUST list the
>   contributing incompatibilities (compared as a set, not a sequence).
>
> An error fixture for a non-resolver error (e.g. `MAN-KDL-SYNTAX`) MUST NOT
> contain `expected/certificate.json`: no certificate is emitted when the
> resolver never runs, so the runner MUST NOT expect the file.

> NOTE: The `check-certificate` selector is the **only** mechanism for
> conformance-testing the `--certificate` flag. A `resolve` fixture does not
> assert the certificate even if `--certificate` were passed; conversely, a
> `check-certificate` fixture MUST pass `--certificate` and MUST assert the
> JSON. The two fixture types are orthogonal.

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

### 2.8.1  `project-dir` — project-root subpath (optional)

> NORMATIVE: If present, `project-dir` MUST be a plain text file whose single
> trimmed line names a path **relative to the fixture root**. The path MUST be
> relative (no leading `/`) and MUST NOT escape the fixture root after
> normalization (no `..` components that resolve above the fixture root). A
> runner MUST reject a `project-dir` value that violates either constraint. The
> runner MUST use `<fixture-root>/<project-dir>` as the project root for the
> run — i.e. the directory it passes to the implementation as `-C <dir>`
> (`spec/cli-contract.md` §2.1). When `project-dir` is absent, the project root
> is the fixture root itself. This lets a fixture place the project under a
> subdirectory of the fixture tree — required when the manifest or workspace root
> must be nested (for example, to test member-relative invocation, or a
> containment/symlink-escape case where the fixture root must sit *above* the
> workspace root).

> NORMATIVE: `project-dir` selects only the project root; all other control
> inputs (`mocked-fetches/`, `index.kdl`, `cas-seed/`, `dep-decl/`, `env`) and
> the `expected/` tree remain rooted at the fixture root. Every runner — the
> black-box CLI harness **and** each in-process adapter — MUST honor
> `project-dir` identically; an adapter that ignores it would resolve a different
> project root than the CLI and so produce a different normative output for the
> same fixture (the cross-runner consistency rule, §1).

> NOTE: Canonical examples — fixture-278/279/280 (`project-dir=member-a`, member
> -directory `add`/`remove`/`update`) and fixture-288 (`project-dir=workspace-root`,
> a member-symlink-escape case where the fixture root must be the parent of the
> workspace root).

### 2.9  `milpa.lock` — lockfile input (required for `parse-lockfile` and `frozen`)

> NORMATIVE: When `cmd` is `parse-lockfile`, `milpa.lock` MUST be present and
> is the sole input. The runner parses it and asserts the resulting error code
> (for error fixtures). This is the canonical way to test `LOCK-*` codes that
> arise during lockfile parsing; `LOCK-VERSION-UNSUPPORTED` is testable via this
> path (a fixture with `version 99` in `milpa.lock` triggers it reliably).

> NORMATIVE: When `cmd` is `frozen`, `milpa.lock` MUST be present. The runner
> parses both `milpa.kdl` and `milpa.lock` and runs the no-network frozen path.

> NORMATIVE: When `cmd` is `resolve` (the default), `milpa.lock` is OPTIONAL. If
> present, it is the **§8 prior lockfile**: the resolver MUST load it and reuse
> its pins (`resolver-semantics.md §8`), so repeated `fetch`/`lock` runs are
> idempotent and a moved ref or substituted tarball archive is caught. On an
> error in this path the prior `milpa.lock` MUST be left unchanged
> (atomic-write-on-failure); on success it is overwritten with the new lockfile.
> See fixture-126-tarball-tofu-refetch-mismatch for the canonical refetch example.

### 2.10  `cas-seed/` — CAS pre-population trees (optional, `frozen` only)

> NORMATIVE: When `cmd` is `frozen` and `cas-seed/` is present, the runner
> MUST compute the content hash of each immediate subdirectory of `cas-seed/`
> and admit those trees into the per-test CAS instance before running the frozen
> path. This lets a frozen success fixture prove that a dep whose identity IS in
> the CAS resolves correctly without a network fetch. The fixture's `milpa.lock`
> MUST pin the matching `sha256:...` identity for each seeded dep.

> NORMATIVE: The runner MUST seed the CAS in a way that leaves the `cas-seed/`
> fixture input intact after the run. Seeding MUST admit a copy of each tree,
> not move the original, so that repeated harness runs against the same fixture
> directory produce identical results.

> NOTE: The current Python adapter calls `store.admit(tree, identity)` which
> moves rather than copies the seed tree, consuming `cas-seed/` on the first
> run. This violates the idempotency requirement above. Tracked in #176;
> the fix is to copy each subdirectory (e.g. `shutil.copytree`) before
> calling `admit`.

### 2.11  `dep-decl/` — DepDecl artifact directory (optional)

`dep-decl/` contains pre-authored DepDecl artifact files that substitute for
the production `HttpDepDeclStore`'s network fetches during conformance testing.
It is a **fixture artifact directory** — not a control file — and is therefore
copied verbatim into the per-run scratch directory (alongside `mocked-fetches/`,
`cas-seed/`, and other artifact inputs) by `_copy_fixture_inputs`.

> NORMATIVE: `dep-decl/` is a **fixture artifact dir**, not a control
> file. It MUST be copied verbatim into the per-run scratch directory,
> exactly like `mocked-fetches/`. It MUST NOT be treated as a harness
> control input (i.e., it MUST appear in the copy-all set, not in the
> `_CONTROL_FILES` exclusion set).

> NORMATIVE: When `dep-decl/` is present in the scratch directory after
> copying, the runner MUST set the environment variable
> `MILPA_DEP_DECL_DIR=<scratch>/dep-decl/` in the subprocess environment
> — mirroring exactly how `MILPA_MOCKED_FETCHES` is set when
> `mocked-fetches/` is present and how `MILPA_INDEX_URL` is set when
> `index.kdl` is present. The value MUST be the resolved absolute path to
> `scratch/dep-decl/` (no trailing slash, per POSIX path conventions).

> NORMATIVE: When `dep-decl/` is **absent** from the fixture, the runner
> MUST NOT set `MILPA_DEP_DECL_DIR` in the subprocess environment. In
> particular, a `MILPA_DEP_DECL_DIR` present in the host environment
> MUST be stripped (it is a `MILPA_*` variable; the runner already strips
> all `MILPA_*` from the host environment before constructing the
> subprocess env — this rule is a consequence of that invariant, not an
> additional rule).

#### 2.11.1  Artifact file naming

> NORMATIVE: Each file inside `dep-decl/` MUST be named
> `<sha256_hex>.kdl`, where `<sha256_hex>` is the 64-character lowercase
> hex encoding of the artifact's sha256 digest — i.e., the `dep_decl`
> pointer recorded in the tianguis index version-node. The filename is
> the key the `FileDepDeclStore` uses to look up an artifact given a
> pointer from the index.

> NOTE: The sha256 digest naming mirrors how CAS entries are named
> (`spec/identity.md` §3.1: `<algo>/<hex>/`). The filename is derived
> from the artifact bytes themselves: `sha256(artifact_bytes).hexdigest()`.
> Fixture authors generate the filename by running `dep_decl_hash()` from
> `harness/dep_decl.py` over the artifact bytes and stripping the
> `sha256:` prefix.

#### 2.11.2  Artifact file contents

> NORMATIVE: Each `<sha256_hex>.kdl` file MUST be a valid DepDecl
> artifact as specified in `spec/dep-decl.md` §2. The `FileDepDeclStore`
> (S3b) MUST verify `sha256(bytes) == sha256_hex` before parsing — a
> mismatch MUST raise `TNG-DEPDECL-HASH-MISMATCH` (spec/errors.md).

> NOTE: The DepDecl artifact format is specified in `spec/dep-decl.md`.
> Fixture authors generate conformant artifact bytes using
> `make_dep_decl_fixture(EdgeSet(...))` from `harness/dep_decl.py` — the
> same S0 helper used by the golden vector. The resulting bytes are
> written verbatim into `dep-decl/<sha256_hex>.kdl`, with the filename
> computed from `dep_decl_hash(bytes)[len("sha256:"):]`.

#### 2.11.3  Relationship to `MILPA_MOCKED_FETCHES`

`dep-decl/` and `mocked-fetches/` are **orthogonal fixture slots**: a
fixture may contain both (when testing named deps that require both a
mocked git/tarball fetch AND a DepDecl artifact), one or neither.

> NORMATIVE: A fixture that exercises named-dep DepDecl resolution
> MUST include `dep-decl/` with the relevant artifacts AND `index.kdl`
> with the version-node `dep_decl` pointer. It MAY also include
> `mocked-fetches/` for URL deps declared by the DepDecl's `require`
> edges.

> NOTE: S3a (this slice) adds the harness plumbing only. The actual
> `FileDepDeclStore` behavior — swap-on-env-var, sha256 verify, KDL
> parse, error codes — is implemented in S3b. Until S3b lands, setting
> `MILPA_DEP_DECL_DIR` has no effect on either impl; the env var is
> injected by the harness runner but is silently ignored by the impls.

---

## 3  Error fixtures

An error fixture asserts that the resolver, manifest parser, or lockfile
verifier produces a specific error code for the given inputs, rather than
emitting `milpa.lock` and `nim.cfg`.

### 3.1  `expected/error` — expected error slug

> NORMATIVE: An error fixture MUST contain `expected/error`, a plain text file
> with exactly one line: the bare error slug from `spec/errors.md` (e.g.,
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
> if it exits 1 and emits a terminal `milpa-error: <slug>` line (per
> `cli-contract.md` §3, R1–R4) whose slug equals `expected/error`, as defined
> in `spec/errors.md`. The human-readable error message is **not** checked and
> is NOT byte-normative.

> NOTE: A per-impl in-process adapter (pytest / `cargo test`) MAY assert the
> raised exception's `.code` instead of parsing stderr — it tests the
> implementation's internal API, a developer convenience. The **normative**
> conformance gate is the black-box CLI check above (§5 item 4): the slug is
> observed on stderr, not read from an in-process exception.

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
> to promote into `conformance/spec-v1/`. Each row in a trigger table
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
> therefore exempt from the coverage floor. They are grouped by the structural
> reason they cannot be triggered via fixture inputs:
>
> **Router-shadowed (raise site unreachable due to caller routing):**
>
> - `MAN-WORKSPACE-IN-PACKAGE` — raised only by `parse_manifest()` (not
>   `parse_workspace_or_manifest()`); the runner always uses the latter, which
>   routes workspace blocks to the workspace parser before this error can fire.
> - `WS-NO-MANIFEST`, `WS-NOT-A-WORKSPACE` — the runner dispatches on
>   `parse_workspace_or_manifest()` output type and always passes a directory
>   that has a workspace-typed `milpa.kdl` to `load_workspace()`; the two
>   pre-conditions checked by those codes are therefore never false.
> - `VERIFY-DEPS-DIR-MISSING` — not black-box reachable via the `verify` cmd
>   token: both impls call `deps_dir.mkdir(parents=True, exist_ok=True)` at
>   the start of `resolve`, so any harness two-phase (`resolve` then `verify`)
>   run always creates `_deps/` before the verifier checks for it. Reachable
>   only via a direct `milpa verify` with no prior fetch, which the harness
>   fixture mechanism has no cmd token for.
> - `MAN-MUTATE-WORKSPACE-REFUSED` — shadowed at the CLI mutation verb layer:
>   `add`/`remove`/`update` call `parse_manifest()` before
>   `mutate_manifest_file()`, so a workspace-root manifest raises
>   `MAN-WORKSPACE-HAS-DEPS-OR-KIND` (or `MAN-ADD-DEP-EXISTS` on the add
>   pre-check) first; the raise site in `manifest_writer.py` is never reached
>   via any fixture cmd token.
>
> **Fetch-wrapping (inner codes always wrapped by an outer code at the
> fetcher-registry boundary):**
>
> - `FETCH-DOWNLOAD-FAILED`, `FETCH-GIT-FAILED`, `FETCH-GIT-COMMIT-ABSENT`,
>   `FETCH-MOCK-MISSING`, `FETCH-SHA256-MISMATCH`, `FETCH-OCI-PULL-FAILED`,
>   `FETCH-OCI-NO-TARBALL`, `FETCH-OCI-AMBIGUOUS-TARBALL`,
>   `FETCH-LOCAL-PATH-NOT-FOUND`, `FETCH-LOCAL-PATH-NOT-DIR`,
>   `FETCH-RECEIPT-EMPTY` — raised inside individual fetcher implementations
>   and caught by `fetch_any()` at `fetchers/types.py`; all are re-wrapped as
>   `FETCH-ALL-FAILED` before reaching the CLI error channel. The terminal
>   slug observed by the harness is always `FETCH-ALL-FAILED`; the inner
>   codes are implementation details not observable at the black-box boundary.
> - `EXTRACT-ZIP-SLIP`, `EXTRACT-SYMLINK-ESCAPE`, `EXTRACT-SIZE-LIMIT` —
>   raised by the safe-extractor and caught by `TarballFetcher`, which
>   re-wraps them as `FETCH-EXTRACT-FAILED`; same wrapping boundary.
> - `CAS-IDENTITY-MISMATCH` — raised by `CAStore.admit()` when the staged
>   tree's actual hash does not match the fetcher-computed identity; caught
>   by the outer `fetch_any()` handler and re-wrapped as `FETCH-ALL-FAILED`.
> - `CAS-NOT-IN-STORE` — raised by `CAStore.link()` when the identity has no
>   CAS entry; in the frozen path the implementation checks `store.contains()`
>   explicitly before calling `link()` and raises `FROZEN-IDENTITY-NOT-IN-STORE`
>   instead, so `CAS-NOT-IN-STORE` never reaches the CLI error channel.
>
> **ID-wrapping (identity codes always wrapped at the lockfile layer):**
>
> - `ID-NO-ALGORITHM-PREFIX`, `ID-NON-HEX-DIGEST`, `ID-NOT-A-STRING`,
>   `ID-UNSUPPORTED-ALGORITHM`, `ID-WRONG-DIGEST-LENGTH` — raised by
>   `parse_identity()` and caught by `parse_lockfile()`, which re-wraps them
>   as `LOCK-DEP-IDENTITY-INVALID`. The terminal slug observed by the harness
>   is always `LOCK-DEP-IDENTITY-INVALID` (fixture-073).
> - `ID-NON-UTF8-SYMLINK-TARGET` — raised by `compute_content_hash()` during
>   CAS admission; not wrappable via a fixture input (requires a source tree
>   with a non-UTF-8 symlink target, which cannot be expressed in the
>   platform-neutral fixture format).
>
> **Swallow (code raised internally then converted to a different observable
> outcome at the CLI boundary):**
>
> - `MILPA-INDEX-UNREACHABLE` *(pending spec inclusion at the 11c swap)* —
>   raised by the index-cache layer when the network is unreachable and no
>   cached index is available; caught by `cli.py` at the index-load site and
>   converted to `index=None`, which surfaces as `RES-NO-INDEX` or
>   `RES-WS-NO-INDEX` when the manifest has named deps. The harness always
>   operates with a fixture-supplied `index.kdl` (hermetic corpus); the
>   network-failure path is not constructible via fixture inputs alone.
>
> **Dead-catalog (no active raise site in the current implementation; code
> reserved or structurally prevented):**
>
> - `FROZEN-NO-CAS` — the CAS default store is always valid (constructed from
>   `MILPA_CACHE_DIR`, XDG, or `~/.cache/milpa`); `fetcher.store` is never
>   `None` in any path the CLI constructs.
> - `MAN-NIMBLE-PARSE` — `parse_nimble()` is a total scanner that skips
>   malformed entries rather than raising; this code is reserved for a future
>   strict-parse mode and currently has no raise site.
> - `MAN-MUTATE-NIMBLE-REFUSED` — mutation verbs (`add`/`remove`) always
>   operate on the hardcoded `milpa.kdl` path; the CLI never passes a `.nimble`
>   path to `mutate_manifest_file()`. Constructible only via a direct library
>   call, not via any fixture cmd token.
> - `TNG-BAD-VERSION` — explicitly reserved for a future strict-parse pass;
>   currently unparseable version strings are silently skipped.
> - `MILPA-INTERNAL` — the outermost catch-all; only fires if an unexpected
>   exception escapes all typed handlers. Not constructible from a fixture
>   input (by definition, fixtures trigger typed error paths).
> - `INTERNAL-PANIC` — Rust-only; emitted by a top-level panic handler. Has
>   no fixture-triggerable raise site (an unhandled panic is a crash verdict
>   under R4, not a slug match).
>
> **Permission/race-only (only triggerable by host filesystem permission
> errors or OS races, not by fixture inputs):**
>
> - `MAN-FILE-NOT-FOUND`, `MAN-FILE-UNREADABLE` — raised by `load_manifest()`
>   on disk-read failure; the harness always supplies `milpa.kdl` as a fixture
>   input, so the file is always present and readable.
> - `LOCK-FILE-UNREADABLE` — raised by `load_lockfile()` on a permission
>   error; distinct from `LOCK-FILE-NOT-FOUND` (which IS covered by
>   fixture-157 via the `show` cmd token, where the harness intentionally
>   omits `milpa.lock`).
> - `NIMBLE-FILE-NOT-FOUND`, `NIMBLE-FILE-UNREADABLE` — raised by the nimble
>   file reader on disk-read failure; the harness always writes the nimble file
>   into the scratch directory before invoking the implementation.
> - `WS-NO-MANIFEST`, `WS-NOT-A-WORKSPACE` — also listed under
>   router-shadowed above.
> - `MAN-MUTATE-FILE-NOT-FOUND` — raised by `mutate_manifest_file()` when the
>   target file is absent; in practice the mutation verbs always operate on a
>   manifest the CLI has already successfully parsed from disk.
> - `MAN-MIRROR-EDITABLE-PROVENANCE` — raised by `cmd_add_mirror()` when the
>   dep is not a git URL dep (local, member, named, or tarball deps cannot
>   carry mirrors). The `add --mirror` verb is CliOnly (pure manifest
>   mutation; no in-process resolver path), so this code is covered by
>   per-impl CLI tests, not corpus fixtures.
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
> - `LOCK-PROV-KIND-UNKNOWN` (registry) — fixture-114: lockfile with
>   `kind "registry"` provenance now hits the unknown-kind path (the registry
>   read-compat shim was deleted in S3).
> - `LOCK-STRATEGY-MISSING` — fixture-307: lockfile missing the `strategy` node
>   raises `LOCK-STRATEGY-MISSING` (S3 strict parser).
> - `LOCK-STRATEGY-MISSING` (malformed arg) — fixture-319: lockfile with `strategy
>   42` (integer arg, not a string) also raises `LOCK-STRATEGY-MISSING` — matches
>   Rust which leaves `strategy` unset when the arg is not a string.
> - `LOCK-PROV-FIELD-MISSING` (absent `origin`) — fixture-323: lockfile with a git
>   provenance block missing the required `origin` field raises
>   `LOCK-PROV-FIELD-MISSING` (S3 strict; `origin` no longer has a default).
> - `MAN-URL-ARG-TYPE` (plain string) — fixture-308: manifest dep with a bare
>   `git="..."` string (no `(url)` annotation) raises `MAN-URL-ARG-TYPE`
>   (S3 URL-annotation requirement).
> - Conditional-dep exclusion via profile predicates — fixture-115: `env` file
>   sets `MILPA_TARGET_PLATFORM=linux`; a dep gated on `platform="windows"` is
>   absent from the resolved graph.
> - `--path:"src"` self-path line — fixture-116: root manifest declares
>   `src_dir "src"`; the runner now passes `self_src_dir` to `format_nimcfg()`,
>   producing a leading self-path line before the dep paths.
> - `LOCK-FILE-NOT-FOUND` — fixture-157: `show` cmd token with no `milpa.lock`
>   input; the `show` verb calls `load_lockfile()` on the missing path before
>   printing, which triggers the disk-read error code. (Previously listed as
>   unreachable because the `parse-lockfile` cmd bypasses disk I/O; the `show`
>   cmd token is the correct harness vehicle for this code.)
> - `LOCK-GRAPH-MISMATCH` — fixture-159: `verify` cmd token with a
>   `milpa.lock` that contains a dep absent from the actually-resolved `_deps/`
>   tree; `milpa verify` calls the verifier, which detects the graph
>   divergence. (Previously listed as unreachable because the runner did not
>   exercise `milpa verify`; the `verify` cmd token added in Stage 11b is the
>   correct harness vehicle.)
>
> The following codes are **newly minted** for the content-addressed-metadata RFC
> (S0–S7) and are covered by fixtures added in that revision:
>
> - `TNG-DEPDECL-HASH-MISMATCH` — fixture-131: `dep-decl/` artifact file is
>   corrupted (filename sha256 ≠ sha256 of content); runner sets
>   `MILPA_DEP_DECL_DIR` and the FileDepDeclStore rejects the mismatch.
> - `TNG-DEPDECL-PARSE-ERROR` — fixture-132: `dep-decl/` artifact is not valid
>   KDL 2.0 / dep_decl document shape; hash matches but parse fails.
> - `TNG-DEPDECL-SCHEMA-MISMATCH` — fixture-133: artifact's embedded
>   `dep_decl_schema_version` disagrees with the index pointer's version.
> - `TNG-DEPDECL-SCHEMA-UNSUPPORTED` — fixture-134: artifact declares a
>   `dep_decl_schema_version` higher than the implementation's maximum.
> - `TNG-DEPDECL-FETCH-FAILED` (strict) — fixture-144: `dep-decl/` directory
>   is present but empty (no artifact file); `MILPA_REQUIRE_ATTESTED_METADATA=1`
>   forces a hard failure (strict policy, no nimble fallback).
> - `RES-UNATTESTED-METADATA` — fixture-140 (manifest `attestation-policy
>   "strict"`): named dep has no `dep_decl` pointer in the index → hard fail.
>   fixture-141 (`MILPA_REQUIRE_ATTESTED_METADATA=1` env flag): same fail via
>   the CLI flag path.
> - `VERIFY-EDGE-MISMATCH` — fixture-142: `milpa verify` detects that the
>   `dep_decl` hash recorded in `milpa.lock` differs from the live index pointer.
> - `LOCK-DEPDECL-PIN-MISSING` — fixture-143: `milpa verify` detects that a
>   `dep_decl` pin in `milpa.lock` has no corresponding pointer in the live index.
>
> The following fixtures cover **S5b namespace-qualified named deps**
> (`rfc-resolver-correctness.md` C1/H2/M2 fixes):
>
> - fixture-311 (`s5b-qualified-named-attr`): qualified named dep via `namespace=`
>   attribute; lockfile emits `dep "bar" { namespace "ns1"; ... }` (bare name as
>   node arg, namespace as first child); on-disk at `_deps/@ns1/bar/`.
> - fixture-312 (`s5b-qualified-named-slash`): qualified named dep via slash
>   shorthand `"ns1/bar"` — same expected output as fixture-311.
> - fixture-313 (`s5b-malformed-slash-name`): triple-segment slash `"a/b/c"` →
>   `MAN-DEP-NAME-INVALID`.
> - fixture-314 (`s5b-two-namespaces-payoff`): two qualified deps with the same
>   bare name from different namespaces (`ns1/bar` and `ns2/bar`) → both appear
>   in the lockfile and on disk (`_deps/@ns1/bar/` and `_deps/@ns2/bar/`).
> - fixture-315 (`depdecl-clause-c-overrides-in-tree`): depdecl overrides that
>   are transitive within the tree.
> - fixture-316 (`s5b-namespace-lock-roundtrip`): `lock-roundtrip` fixture proving
>   C1 fix — a lockfile with `dep "bar" { namespace "ns1"; ... }` parses and
>   re-emits byte-identically (cannot raise `LOCK-DEP-NAME-INVALID`).
> - fixture-317 (`s5b-transitive-qualified-named`): H2 fix proof — a URL dep's
>   transitive `milpa.kdl` declares `"ns1/baz"` (slash syntax); the namespace
>   survives the `NamedRequire` → `EdgeSet` boundary and appears in the lockfile
>   as `dep "baz" { namespace "ns1"; ... }`.
> - fixture-318 (`s5b-slash-namespace-disagreement`): M2 fix proof — a dep uses
>   both slash shorthand (`"ns1/bar"`) and a disagreeing `namespace="ns2"` attribute
>   → `MAN-DEP-NAME-INVALID` (agreeing values are accepted; disagreement is an error).
> - fixture-320 (`frozen-alias-dep-coverage`): single-package frozen path with a dep
>   that has an alias — verifies the alias-aware `_locked_index` lookup resolves
>   correctly and the `_deps/` symlinks appear for both canonical name and alias.
> - fixture-321 (`ws-frozen-alias-dep-coverage`): workspace frozen path variant of
>   fixture-320 — multi-member workspace with a shared dep carrying an alias entry in
>   the lockfile; both aliases appear in the resolved `_deps/`.
> - fixture-322 (`frozen-dev-dep-not-in-lock`): `FROZEN-MANIFEST-DEP-NOT-IN-LOCK`
>   via a dev dep — verifies that `resolve_frozen` checks `dev_deps` in addition to
>   `deps` (S1 #178 fix; both impls).
> - fixture-324 (`lock-dep-namespace-traversal`): `LOCK-DEP-NAME-INVALID` (security)
>   — lockfile dep with `namespace "ns/../../outside"` (traversal payload) is
>   rejected at the parse boundary by both impls; prevents `dep_dir_name` from
>   producing an escaping path like `@ns/../../outside/<name>` under `_deps/`.
> - fixture-325 (`s4c-qualified-named-flag-conflict`): `RESOLVE-FLAG-CONFLICT`
>   — a qualified named dep (`bar namespace="ns1"`) with two mutually-exclusive
>   `default=#true` flags exercises the S4c post-fixpoint conflict check on the
>   `@ns1/bar/milpa.kdl` path; without the C1/H2 S4c path fix both impls would
>   silently skip the check (nonexistent `_deps/ns1::bar/milpa.kdl`), resolve
>   successfully, and miss the conflict.

### 4.1  Imperative cross-fixture tests (harness-level)

Some conformance properties cannot be expressed as a single-fixture expected/
comparison — they require comparing the outputs of **two different fixtures**
against each other (a capability the per-fixture corpus runner does not provide).
These properties are expressed as **imperative pytest tests in `harness/`**,
not as declarative corpus directives (no new fixture-metadata format).

The first imperative cross-fixture capability is the **S4-ii differential gate**
(DepDecl translation fidelity), added in `harness/test_dep_decl.py`:

> **DG1 (clean pair, fixture-135 vs fixture-136):** A package whose `.nimble`
> is "clean" (no `when` block) is resolved two ways: once via an attested
> DepDecl pointer in the index (fixture-135) and once with no DepDecl pointer
> so the resolver falls back to the `.nimble` line-scan (fixture-136). The
> two resulting `milpa.lock` files MUST be byte-identical. This proves the
> DepDecl translation is faithful for well-formed `.nimble` inputs.
>
> **DG2 (when-block pair, fixture-137 vs fixture-138):** A package whose
> `.nimble` has a `when` block is resolved via the attested DepDecl (fixture-137,
> tianguis excluded the platform-conditional dep) and via the `.nimble` fallback
> (fixture-138, which unconditionally includes the when-block dep). The two
> lockfiles MAY differ; the attested arm (fixture-137) is authoritative and is
> asserted against its own `expected/`. This proves DepDecl authority over the
> `.nimble` heuristic for packages with conditional requires.

> NOTE: Both arms of each pair are **independently valid corpus fixtures** —
> they appear in `conformance/spec-v1/` and the normal corpus runner exercises
> them individually. Only the **cross-fixture equality / divergence** assertion
> lives in the imperative test. This separation keeps the corpus fixture format
> simple (no new metadata directives) while enabling the novel cross-fixture
> comparison capability.

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
> 4. For an error fixture: assert that the implementation exited 1 and emitted
>    exactly one terminal `milpa-error: <slug>` line on stderr (the unique
>    full-line match of `^milpa-error: <SLUG>$`, per `cli-contract.md` §3
>    R1–R4) whose slug matches `expected/error`. An exit ≠ 1, a missing line,
>    or two or more such lines is a failure (crash / protocol-violation
>    verdict), not a slug match.

> NORMATIVE: When the runner invokes `nim.cfg` emission, it MUST supply the deps
> directory as the literal relative path `_deps` (not an absolute scratch path).
> The checked-in `expected/nim.cfg` files encode `_deps/` as the `--path:`
> prefix; passing any other path fails the byte-diff. (This is the
> `deps_dir=_deps` argument to `format_nimcfg` in the reference adapter.)

> NOTE: The Python conformance adapter (S8b) wraps this protocol as a `pytest`
> parametrized test that discovers all `conformance/spec-v<N>/` fixture
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
conformance/spec-v1/fixture-003-single-url-dep/
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
conformance/spec-v1/fixture-001-man-kdl-syntax/
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
conformance/spec-v1/fixture-068-lock-version-unsupported/
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
conformance/spec-v1/fixture-083-frozen-identity-not-in-store/
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
