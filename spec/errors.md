# milpa error catalog

Normative spec of every error milpa can produce. Each entry's
`slug` is the conformance-stable identifier; consumers (CI
scripts, IDE integrations, alternate implementations) MAY rely
on slugs but MUST NOT rely on message wording.

Spec-owned — do not generate from any implementation. Implementations
bijection-check their catalogs against this file.

---

## Normative surface

Every catalog entry in this document is **normative**: a conformant
milpa implementation MUST raise the exact slug shown for the exact
condition described. The slug is the cross-implementation contract.

The human-readable **message text** (the string passed to the
exception constructor) is **incidental**: it is NOT byte-normative.
A conformant implementation MAY differ in phrasing, language, or
level of detail, provided the slug is correct.

The **Triggered** field describes the reference Python implementation's
raise site. Alternate implementations MUST produce the same slug for
the same condition but MAY structure their internals differently.

Bijection invariant: every slug in this catalog MUST have at least
one raise site in the reference implementation; every raise site MUST
reference a slug defined here. The test suite enforces both directions
via `check_catalog_orphan_slugs` for each category prefix.

---

## CAS

### `CAS-IDENTITY-MISMATCH`

Source tree bytes do not hash to the claimed identity string.

**Triggered:** CAStore.admit computes content_hash of src and finds it differs from the identity argument — possible tamper or corruption.

### `CAS-NOT-IN-STORE`

The requested identity is not present in the CAS.

**Triggered:** CAStore.link is called for an identity that has no entry under <root>/<algorithm>/<hex>/. Also raised by `milpa store path <identity>` when the exact identity is absent.

### `CAS-STORE-IO-ERROR`

A `_deps/<name>` symlink resolves to a CAS store entry but reading that entry raises an I/O error (e.g. network mount offline). Distinct from a dangling symlink (where the target is gone entirely) and from identity mismatch (where the content is corrupt).

**Triggered:** `verify_lockfile_against_deps` finds `_deps/<name>` is a symlink that resolves (`exists()` is true) but `compute_content_hash` raises an `OSError` (e.g. permission denied, network mount offline) rather than completing normally.

### `STORE-AMBIGUOUS-PREFIX`

`milpa store path <prefix>` matches more than one store entry, or the supplied prefix is shorter than the 16-hex-character minimum required to safely pin a single entry.

**Triggered:** `milpa store path` is called with a hex-digest prefix that resolves to zero or more than one store entries, or with a prefix whose hex portion is fewer than 16 characters.

## CLI

### `CLI-FEATURE-FLAGS-CONFLICT`

`--all-features` and `--no-default-features` are mutually exclusive and were both supplied on the same invocation.

**Triggered:** The CLI layer detects that `--all-features` and `--no-default-features` are both active (whether via command-line flags or the equivalent env vars `MILPA_ALL_FEATURES` + `MILPA_NO_DEFAULT_FEATURES` in the conformance harness). `--all-features` activates every declared root flag; `--no-default-features` suppresses all defaults and starts from an empty baseline — the two intents are contradictory. Cargo rejects this combination and milpa follows the same policy. Exit code 1 (diagnosed failure, single `milpa-error:` line on stderr).

**Fix:** Pass at most one of `--all-features` or `--no-default-features` per invocation.

## EXTRACT

### `EXTRACT-SIZE-LIMIT`

The archive exceeds a configured size or file-count limit (decompression bomb protection).

**Triggered:** extract_tar finds a single-file size, total decompressed size, or file count exceeds the configured caps.

### `EXTRACT-SYMLINK-ESCAPE`

A symlink entry's target resolves outside the destination directory (symlink-escape attack).

**Triggered:** extract_tar finds a symlink entry whose target, when resolved from its parent directory, exits the destination tree.

### `EXTRACT-ZIP-SLIP`

An archive entry's resolved path escapes the destination directory (zip-slip attack).

**Triggered:** extract_tar finds an entry whose path, after joining with dest, resolves outside the destination tree.

## FETCH

### `FETCH-ALL-FAILED`

Every candidate provenance failed — the dep cannot be fetched.

**Triggered:** The per-candidate fallback loop tries all candidate provenances in order and every one raises a transport error (network failure, git non-zero exit, dead mirror, etc.).  For the tarball path, a sha256 archive-pin mismatch is also folded in.  Identity divergence (fetched bytes ≠ locked hash) is a distinct condition raised as `FETCH-PROVENANCE-DIVERGENCE`, not folded here.

### `FETCH-DOWNLOAD-FAILED`

Could not download the tarball from the declared URL.

**Triggered:** TarballFetcher._download raises URLError, FileNotFoundError, or OSError.

### `FETCH-EXTRACT-FAILED`

Safe extraction of the tarball raised an ExtractionError.

**Triggered:** TarballFetcher calls safe_extract.extract_tar and it raises ZipSlipError, SymlinkEscapeError, or SizeLimitError.

### `FETCH-GIT-COMMIT-ABSENT`

The index-pinned commit SHA is absent even after a full history fetch.

**Triggered:** _ensure_commit_present cannot find commit_sha in the cloned repo after exhausting targeted + unshallow fetches.

### `FETCH-GIT-FAILED`

A git subprocess (clone/fetch/checkout) exited non-zero.

**Triggered:** _run_git receives a non-zero exit code from git.

### `FETCH-LOCAL-PATH-NOT-DIR`

The declared local source path is not a directory.

**Triggered:** LocalFetcher.fetch finds p.path exists but is not a directory.

### `FETCH-LOCAL-PATH-NOT-FOUND`

The declared local source path does not exist.

**Triggered:** LocalFetcher.fetch finds p.path does not exist on the filesystem.

### `FETCH-MOCK-MISSING`

No mocked-fetches entry for the requested url@ref under the mocked transport.

**Triggered:** MILPA_MOCKED_FETCHES is set and MockedFetcher.fetch is called with a (url, ref) pair whose encoded key directory does not exist under the mocked-fetches/ root.

### `FETCH-OCI-AMBIGUOUS-TARBALL`

OCI artifact contained more than one *.tar.gz blob.

**Triggered:** OciFetcher.fetch finds multiple *.tar.gz files; cannot determine which to extract.

### `FETCH-OCI-NO-TARBALL`

OCI artifact contained no *.tar.gz blob.

**Triggered:** OciFetcher.fetch pulls the artifact but finds no *.tar.gz in the scratch directory.

### `FETCH-OCI-PULL-FAILED`

oras pull exited non-zero.

**Triggered:** OciFetcher.fetch runs `oras pull` and receives a non-zero exit code.

### `FETCH-PROVENANCE-DIVERGENCE`

A candidate provenance successfully fetched a tree but its content hash does not match the locked identity — a supply-chain signal.

**Triggered:** The per-candidate fallback loop in the URL-dep resolver path calls `fetcher.fetch()` successfully (no transport error), computes the content hash of the materialized tree, and finds it differs from the `expected_identity` carried from the prior lockfile.  This is distinct from a transport failure (which is silently skipped to the next candidate) and from `FETCH-ALL-FAILED` (which fires when every candidate transport-fails).  A divergence is raised immediately and loudly — it MUST NOT fall through to the next candidate, because a mirror serving different bytes than the lock pinned is an active supply-chain signal that must not be silently worked around.

**Boundary:** `FETCH-PROVENANCE-DIVERGENCE` is raised only when `expected_identity` is set (i.e. a prior lockfile pin exists).  On a fresh resolve with no prior lock, no identity gate is applied and this code is never raised.

### `FETCH-RECEIPT-EMPTY`

A fetcher returned a receipt whose transport_fields() is empty — no provenance evidence was recorded.

**Triggered:** FetcherRegistry.fetch calls receipt.transport_fields() after a successful fetch and the returned dict is empty, violating the spec §3.2 non-empty-receipt contract.

### `FETCH-REF-DISCOVERY-FAILED`

`milpa add <name> git=<url>` (no `ref=`) failed to auto-discover the remote's default branch.

**Triggered:** `cmd_add` omits `--ref` and the ref auto-discovery path (via `git ls-remote --symref HEAD` on a live transport, or the mocked-fetches fixture tree on a mocked transport) returns no branch name — either the remote is unreachable, the URL is invalid, or the mocked fixture directory has no entry for this URL.  The command exits 1 without modifying `milpa.kdl` or `milpa.lock`.

### `FETCH-SHA256-MISMATCH`

Downloaded archive sha256 does not match the declared expected_sha256.

**Triggered:** TarballFetcher compares the archive's actual sha256 against TarballProvenance.expected_sha256 and finds a mismatch.

## FROZEN

### `FROZEN-ACTIVE-FLAGS-MISMATCH`

The CLI feature selection (``--features``, ``--no-default-features``, ``--all-features``) produces a root active-flag closure that does not match what the lockfile was produced under, or names a flag not declared in the root manifest.

**Triggered:** S9 (RFC #23 §3.4) — under ``--frozen``, the recomputed root active-flag closure differs from the lockfile (a flag-gated root dep is admitted by the closure but absent from the lock, or vice versa); OR ``--features`` names a flag not declared in the root manifest's ``flags {}`` block.

**Fix:** Re-run ``milpa fetch`` with the desired feature selection to regenerate the lockfile.

### `FROZEN-CONSTRAINT-UNSATISFIED`

A manifest NamedDep's version constraint is no longer satisfied by the locked version.

**Triggered:** _check_manifest_alignment checks VersionSet.from_constraint against the locked version and finds it fails.

### `FROZEN-IDENTITY-NOT-IN-STORE`

A dep's pinned identity is not present in the CAS.

**Triggered:** _link_external finds the dep's identity is absent or None, or CAStore.contains returns False.

### `FROZEN-LEGACY-REGISTRY-PROVENANCE`

A lock entry uses the legacy registry provenance and cannot be reconstructed by the frozen path.

**Triggered:** _source_from_provenance encounters a RegistryProvenanceRecord; the user must run `milpa update <name>` to re-resolve via tianguis.

### `FROZEN-LOCAL-DEP`

A dep has a local provenance; editable trees always re-resolve.

**Triggered:** resolve_frozen or resolve_workspace_frozen encounters a LocalProvenanceRecord.

### `FROZEN-LOCKED-VERSION-UNPARSEABLE`

A dep's locked version string is not a parseable X.Y.Z version.

**Triggered:** _check_manifest_alignment or _resolved_from_locked calls parse_version on the locked version and gets None.

### `FROZEN-MANIFEST-DEP-NOT-IN-LOCK`

A manifest dep has no lockfile entry; lockfile is stale.

**Triggered:** _check_manifest_alignment finds a manifest dep name absent from the lockfile's dep list.

### `FROZEN-MEMBER-DEP`

A dep is a workspace member; members always re-resolve.

**Triggered:** resolve_frozen encounters a MemberProvenanceRecord — single-package frozen path does not handle workspace members.

### `FROZEN-MEMBER-IDENTITY-DRIFT`

A workspace member's on-disk content hash differs from the lockfile pin.

**Triggered:** resolve_workspace_frozen computes the member directory's content hash and finds it differs from the lockfile's recorded identity.

### `FROZEN-MEMBER-NOT-IN-WORKSPACE`

The lockfile references a workspace member that is absent from the current workspace.

**Triggered:** resolve_workspace_frozen finds MemberProvenanceRecord.name is not in the workspace's member list.

### `FROZEN-NO-CAS`

The frozen fast path requires a content-addressed store, but the fetcher has none attached.

**Triggered:** _try_frozen / _try_workspace_frozen find fetcher.store is None; the frozen path cannot link _deps/ from a CAS that does not exist.

### `FROZEN-NO-LOCKFILE`

The frozen fast path requires a lockfile, but none is present.

**Triggered:** _try_frozen / _try_workspace_frozen find no milpa.lock at the project (or workspace) root; with --frozen this is exit 1 rather than a silent fall-through to full resolution.

### `FROZEN-STRATEGY-MISMATCH`

The requested resolution strategy differs from what the lockfile was built with.

**Triggered:** _check_strategy finds the requested strategy string does not match lockfile.strategy.

## ID

### `ID-NO-ALGORITHM-PREFIX`

Identity string is missing the `<algorithm>:` prefix (expected `<algorithm>:<digest>` form).

**Triggered:** parse_identity finds no `:` separator in the input string.

### `ID-NON-HEX-DIGEST`

Digest component contains non-lowercase-hex characters.

**Triggered:** parse_identity finds characters outside `0-9`, `a-f` in the digest.

### `ID-NON-UTF8-RELPATH`

A file or directory's relative path within the source tree cannot be encoded as UTF-8, so it cannot be included in the canonical byte stream of the content-hash algorithm. Distinct from `ID-NON-UTF8-SYMLINK-TARGET`, which covers non-UTF-8 symlink *targets* rather than non-UTF-8 *path components*.

**Triggered:** compute_content_hash encounters a file or symlink whose relative path (as an OS byte string) contains non-UTF-8 byte sequences — only possible on POSIX systems where filenames are byte sequences with no UTF-8 requirement.

### `ID-NON-UTF8-SYMLINK-TARGET`

A symlink in the source tree points to a target that is not valid UTF-8, so it cannot be encoded into the content-hash algorithm.

**Triggered:** compute_content_hash encounters a symlink whose os.readlink target fails to re-encode as UTF-8 (surrogate-escaped bytes on POSIX).

### `ID-NOT-A-STRING`

Identity value is not a string.

**Triggered:** parse_identity receives a non-str argument.

### `ID-UNSUPPORTED-ALGORITHM`

Identity string uses an algorithm milpa does not support.

**Triggered:** parse_identity finds an algorithm prefix not in SUPPORTED_ALGORITHMS (currently only `sha256` is supported).

### `ID-WRONG-DIGEST-LENGTH`

Digest component has the wrong number of hex characters.

**Triggered:** parse_identity finds the digest length does not match the expected length for the algorithm (sha256 requires exactly 64 hex chars).

## INTERNAL

### `INTERNAL-PANIC`

A Rust implementation's top-level panic handler fired — an internal failure that reached the panic boundary.

**Triggered:** A Rust impl installs a top-level panic handler that emits this slug to stderr before exiting 1.  An unhandled `panic!()` that exits 101 is a crash verdict under Gap-1 R4, not this coded error.

### `MILPA-INDEX-UNREACHABLE`

The tianguis index URL is unreachable (network failure) and no cached copy is available to fall back to.

**Triggered:** The index-loading layer (`load_index` / `load_cached_index`) exhausts all fetch attempts, finds no usable cached file on disk, and raises this code.  At the CLI boundary this is a §4 swallow-exemption: `maybe_index` catches the error and treats the index as absent rather than emitting a terminal slug, so the resolver will surface `RES-NO-INDEX` only if a named dep actually requires the index.  No conformance fixture exercises the terminal form; the entry exists to satisfy the bijection invariant and to name the internal condition precisely.

### `MILPA-INTERNAL`

An unexpected error escaped milpa's typed error handlers — an internal failure rather than a diagnosed condition.

**Triggered:** The outermost CLI entry-point wrapper catches an exception that no typed handler (ManifestError, SolverError, NotFrozen, …) accounted for, emits this sentinel slug to stderr, and exits 1.  Guarantees the R3 invariant — every exit-1 failure carries a `milpa-error:` line — is mechanically enforceable.

## LOCK

### `LOCK-DEP-FIELD-ARITY`

A dep child field must have exactly one string value.

**Triggered:** A `version`, `src_dir`, or similar child node of a `dep` block has wrong arity.

### `LOCK-DEP-IDENTITY-INVALID`

A dep's `identity` field is not a valid multihash-encoded content hash.

**Triggered:** parse_identity rejects the recorded identity string.

### `LOCK-DEP-NAME-ARITY`

A `dep` node requires exactly one string argument (the name).

**Triggered:** A `dep` node has wrong arity or a non-string arg.

### `LOCK-DEP-NAME-INVALID`

A dep's `name` or an entry in its `aliases` list in the lockfile contains characters outside the dep-name charset `[A-Za-z0-9_-]+`.

**Triggered:** The lockfile parse boundary validates the dep name and every alias against the same charset predicate as the manifest parse (`MAN-DEP-NAME-INVALID`; Python `_FLAG_NAME_CHARSET_RE`, Rust `valid_flag_name`).  A poisoned `milpa.lock` with a name like `../evil` (containing `/`) would otherwise flow to `nim.cfg --path:` via string concat and to the filesystem via `deps_dir / name`, enabling path traversal outside `_deps/`.  The charset predicate (not `contains_unsafe_char`) is used because `/` and `.` are not control characters.  Both impls validate at the lockfile parse boundary so all consumers (`verify`, `frozen`, `show`) are covered.

### `LOCK-DEP-NOT-FOUND`

A named dep is absent from the lockfile.

**Triggered:** `milpa update <dep>` or `milpa add --mirror <dep>` is asked to act on a dep that has no entry in milpa.lock.

### `LOCK-DEPDECL-PIN-MISSING`

A dep_decl pin is present in the lockfile but the live index version-node no longer carries a dep_decl pointer for that dep@version.

**Triggered:** `milpa verify` finds a `dep_decl` field on a locked dep but the current index either does not list that package, does not have that exact version, or that version-node has no `dep_decl` field — the DepDecl artifact has been retracted or the index has been rolled back.

### `LOCK-FIELD-ARITY`

A lockfile scalar field takes exactly one value.

**Triggered:** A `version` or similar scalar node has wrong arity.

### `LOCK-FIELD-TYPE`

A lockfile scalar field value has the wrong type.

**Triggered:** A scalar node's value cannot be coerced to the expected type (e.g. int).

### `LOCK-FILE-NOT-FOUND`

The lockfile path does not exist.

**Triggered:** load_lockfile is called with a path that doesn't exist.

### `LOCK-FILE-UNREADABLE`

The lockfile cannot be read (permissions, OS error).

**Triggered:** OS denies reading the lockfile file.

### `LOCK-GRAPH-MISMATCH`

The deps do not match the lockfile — either the resolved graph or the on-disk _deps/ tree diverges from what milpa.lock records.

**Triggered:** verify_against_graph finds missing, extra, or identity-mismatched deps; or `milpa verify` finds the on-disk _deps/ content hashes / membership diverge from the lockfile.

### `LOCK-KDL-SYNTAX`

The lockfile is not valid KDL.

**Triggered:** kdl-py's parser rejects the lockfile text.

### `LOCK-PROV-FIELD-ARITY`

A provenance child field must have exactly one value.

**Triggered:** A provenance block's child node has wrong arity.

### `LOCK-PROV-FIELD-MISSING`

A provenance block is missing a required field.

**Triggered:** A required field (e.g. `url` for git, `path` for local) is absent.

### `LOCK-PROV-KIND-MISSING`

A provenance block is missing the `kind` discriminator.

**Triggered:** No `kind` field is found in the provenance block.

### `LOCK-PROV-KIND-UNKNOWN`

Unknown provenance `kind` value.

**Triggered:** The `kind` field is not one of: git, tarball, local, member, oci, registry.

### `LOCK-SRC-DIR-UNSAFE`

A dep's `src_dir` value in the lockfile contains an unsafe character (ASCII control character 0x00–0x1F, 0x7F, or Unicode line separator U+2028/U+2029).

**Triggered:** The lockfile parse boundary validates `src_dir` against the same unsafe-char predicate as the manifest parse (`MAN-SRC-DIR-UNSAFE`).  A poisoned `milpa.lock` with a newline or control character in `src_dir` would otherwise flow to `nim.cfg --path:` on frozen reconstruction.  Both impls validate at the lockfile parse boundary so all consumers (`verify`, `frozen`, `show`) are covered.

### `LOCK-VERSION-MISSING`

Lockfile is missing the required top-level `version` node.

**Triggered:** parse_lockfile finds no `version` node in the KDL document.

### `LOCK-VERSION-UNSUPPORTED`

Lockfile schema version is not supported by this milpa.

**Triggered:** The `version` integer is higher than LOCKFILE_SCHEMA_VERSION.

## MAN

### `MAN-ADD-DEP-EXISTS`

`milpa add --git` rejected: the dep is already declared in milpa.kdl.

**Triggered:** cmd_add finds <dep> is already present in the manifest's deps block.

### `MAN-CAS-DIR-MISSING`

`cas` block requires a `dir` child node.

**Triggered:** A `cas { ... }` block is declared without a `dir "<path>"` entry.

### `MAN-CAS-DIR-TYPE`

`cas.dir` must take exactly one positional string argument.

**Triggered:** `cas.dir` value is missing, multi-valued, or non-string.

### `MAN-DEP-DUPLICATE`

A dep name appears more than once in the deps block.

**Triggered:** Two dep declarations resolve to the same name.

### `MAN-DEP-OPTIONAL-FLAG-CLASH`

An `optional=#true` dep's name collides with an already-declared flag, OR a
non-optional dep shares a name with a declared flag (namespace hygiene).

**Triggered:** During manifest validation, when an `optional=#true` dep's name
matches a flag already declared in the `flags` block (the auto-flag synthesized
from the dep name would collide with an explicitly-declared flag), OR when a
non-optional dep's name matches a declared flag name (fusing the dep and flag
namespaces in a confusing way).

### `MAN-DEP-OPTIONAL-INVALID-NAME`

An `optional=#true` dep's name contains characters not allowed in flag names
(must match `[A-Za-z0-9_-]+`).

**Triggered:** By `milpa add --optional <name>` when the supplied name contains
characters outside the flag-name charset (`[A-Za-z0-9_-]+`).  During manifest
parsing this error is not raised: the dep-name parser fires `MAN-DEP-NAME-INVALID`
first for any dep name that violates the charset, regardless of whether the dep
is optional, so `MAN-DEP-OPTIONAL-INVALID-NAME` is unreachable from the parse
path.

### `MAN-DEP-FLAG-BOOL`

A consumer `flag` child node's second arg must be a boolean.

**Triggered:** `flag "X" <non-bool>` is declared.

### `MAN-DEP-FLAG-NAME-MISSING`

A consumer `flag` child node requires a quoted name as the first arg.

**Triggered:** `flag` has no args or first arg is non-string.

### `MAN-DEP-FLAG-TOO-MANY-ARGS`

A consumer `flag` child node takes at most two args (name, optional bool).

**Triggered:** `flag` has 3+ positional args.

### `MAN-DEP-LOCAL-PATH`

LocalDep's `local` must be a non-empty string path.

**Triggered:** `local=` value is empty or non-string.

### `MAN-DEP-MEMBER-ARITY`

MemberDep takes exactly one positional string argument.

**Triggered:** `member` node has wrong arity or non-string arg.

### `MAN-DEP-MEMBER-PROPS`

MemberDep takes no properties.

**Triggered:** `member "name"` has any property.

### `MAN-DEP-NAME-INVALID`

A dep node name contains characters not allowed in the dep-name charset `[A-Za-z0-9_-]+`.

**Triggered:** A dep declaration's KDL node name contains characters outside `[A-Za-z0-9_-]+`. KDL 2.0 quoted node names can contain spaces, `\n`, `!`, and other characters not permitted in milpa dep names. Because dep names flow to nim.cfg path emission (`--path:"_deps/<name>"`) and feature-flag defines (`-d:<pkg>_<flag>`), the parse boundary MUST validate every dep name against the dep-name charset and reject invalid names before they can propagate. Alias names (derived from dep names via the optional desugar pass) inherit this protection automatically.

### `MAN-DEP-MIRROR-ARITY`

A `mirror` child node takes exactly one positional URL argument.

**Triggered:** `mirror` has wrong arity.

### `MAN-DEP-NAMED-ARITY`

NamedDep takes at most one positional argument (the version constraint).

**Triggered:** A bare-name dep has more than one positional arg.

### `MAN-DEP-NAMED-CONSTRAINT`

NamedDep's version constraint is invalid: either the positional arg is not a string, or the string is not a syntactically valid constraint.

**Triggered:** The positional arg is not a string, OR the string cannot be parsed by VersionSet.from_constraint (e.g. '@@@bad'). Validated at manifest parse time so the resolver always holds pre-typed VersionSets.

### `MAN-DEP-NAMED-PROPS`

NamedDep takes only a positional version constraint, no properties.

**Triggered:** A bare-name dep has properties (other than `git=...` which routes elsewhere).

### `MAN-DEP-REF-MISSING`

A UrlDep is missing the required `ref` property.

**Triggered:** `git=...` is set but `ref=...` is absent.

### `MAN-DEP-TARBALL-SHA`

TarballDep's `sha256` must be a string when provided.

**Triggered:** `sha256=` is not a string.

### `MAN-DEP-TARBALL-STRIP`

TarballDep's `strip_components` must be a non-negative integer.

**Triggered:** `strip_components=` is negative, non-numeric, or boolean.

### `MAN-DEP-TARBALL-URL`

TarballDep's `tarball` must be a non-empty URL string.

**Triggered:** `tarball=` value is empty or non-string.

### `MAN-DEP-UNKNOWN-CHILD`

Unknown child node in a UrlDep block.

**Triggered:** A dep block has a child not in {mirror, flag, <predicate>}.

### `MAN-DEP-UNKNOWN-PROPS`

Unknown property on a dep declaration.

**Triggered:** A dep child node carries a property not in the dep-form's allowed set.

### `MAN-FILE-NOT-FOUND`

The manifest file path does not exist.

**Triggered:** load_manifest is called with a path that doesn't exist.

### `MAN-FILE-UNREADABLE`

The manifest file cannot be read (permissions, etc.).

**Triggered:** OS denies reading the manifest file. Covers both milpa.kdl and a discovered .nimble: _load_manifest_from_nimble delegates the read to load_nimble and translates its NIMBLE-FILE-* IO error to this code.

### `MAN-FLAG-DEFAULT-TYPE`

Flag `default` must be a boolean.

**Triggered:** `default=` is not a bool.

### `MAN-FLAG-DEFINES-ARG-TYPE`

`defines` args must be strings.

**Triggered:** A `defines` child has a non-string arg.

### `MAN-FLAG-DEFINES-UNSAFE`

A `defines` string value contains a control character or Unicode line separator that would allow nim.cfg injection.

**Triggered:** A `defines` child has a string arg containing `\n`, `\r`, any other ASCII control character (codepoints 0x00–0x1F and 0x7F), or a Unicode line separator (U+2028 or U+2029). Parse-boundary validation: the data model must not be able to represent an unsafe defines value.

### `MAN-FLAG-DESCRIPTION-TYPE`

Flag `description` must be a string.

**Triggered:** `description=` is not a string.

### `MAN-FLAG-DUPLICATE`

Duplicate flag declaration.

**Triggered:** Two flags in `flags { }` have the same name.

### `MAN-FLAG-CONFLICTS-UNDECLARED`

A `conflicts` bare-name argument names a flag that is not declared in the same manifest's `flags {}` block.

**Triggered:** Post-parse pass over the fully-built flags table finds a same-package name in any `conflicts` node that has no matching declared flag. Forward references (flag declared later in the block) are legal. Scope: same-package only (cross-package `conflicts` is deferred, S4c RFC #23 §3.1.4).

### `MAN-FLAG-CONFLICTS-SELF`

A flag names itself in its own `conflicts` list.

**Triggered:** Post-parse pass finds a `conflicts` entry whose value equals the enclosing flag's own name. A flag cannot conflict with itself; this is always a manifest authoring error. Rejected before the conflict enters the solver or S4c validation.

### `MAN-FLAG-ENABLES-UNDECLARED`

An `enables` bare-name argument names a flag that is not declared in the same manifest's `flags {}` block.

**Triggered:** Post-parse pass over the fully-built flags table finds a same-package name in any `enables` node that has no matching declared flag. Forward references (flag declared later in the block) are legal. When the undeclared name is also a non-optional dep name in the same manifest, the diagnostic must add: `"<name>" is a dependency, not a flag — add optional=#true to make it a feature.` Cross-package `enables` children (dep-name child nodes) are not validated at parse time.

### `MAN-FLAG-NAME-INVALID`

A flag name declared in the `flags {}` block does not match the required charset `[A-Za-z0-9_-]+`.

**Triggered:** A flag node's KDL identifier (the name) contains characters outside `[A-Za-z0-9_-]+`. KDL 2.0 quoted node names can contain spaces, `!`, `\n`, and other characters not permitted in milpa flag names. The parse boundary MUST validate every declared flag name against the flag-name charset and reject invalid names before they can propagate to nim.cfg emission.

### `MAN-FLAG-POS-ARGS`

Flag declaration must not have positional args (use props).

**Triggered:** A flag node has positional args in addition to the identifier.

### `MAN-FLAG-UNDECLARED-REFERENCE`

A `when flag="X"` predicate references an undeclared flag.

**Triggered:** The manifest's own deps block uses a flag that isn't in `flags { }`.

### `MAN-FLAG-UNKNOWN-CHILD`

Unknown child node in a flag declaration.

**Triggered:** A flag has a child not named `defines`.

### `MAN-FLAG-UNKNOWN-PROPS`

Unknown property on a flag declaration.

**Triggered:** A flag has a property not in {default, description}.

### `MAN-GIT-URL-BAD-SCHEME`

Git URL scheme is not in the supported set (https, http, ssh, git).

**Triggered:** `git=` URL's scheme is unsupported.

### `MAN-GIT-URL-NO-SCHEME`

Git URL has no scheme (e.g. https://).

**Triggered:** `git=` value's urllib-parsed scheme is empty.

### `MAN-KDL-SYNTAX`

The manifest file is not valid KDL.

**Triggered:** kdl-py's parser rejects the input text.

### `MAN-KIND-ARITY`

`kind` takes exactly one value.

**Triggered:** The kind node has zero or multiple positional args.

### `MAN-KIND-INVALID`

`kind` value is not one of the allowed values (library, application).

**Triggered:** kind is anything other than the documented set.

### `MAN-MIRROR-EDITABLE-PROVENANCE`

`milpa add --mirror` rejected: the dep has a local or member provenance — editable sources cannot be mirrored.

**Triggered:** cmd_add_mirror finds the locked dep's provenance is local or member; a mirror would contradict the editable, mutable-by-design source.

### `MAN-MEMBER-WHEN-GATED`

A `member` dep node is declared inside a `when { … }` block, which is a category error. Workspace members are unconditional topology — every member is present in every resolution regardless of platform, arch, or flag predicates. Placing a `member` inside a `when` block either silently drops the predicates (producing an unconditional member, contradicting the author's apparent intent) or silently honors them (breaking the workspace invariant that every member is always resolved). The parser MUST reject this form rather than silently doing either.

**Triggered:** The manifest parser encounters a `member` node as a direct child of a `when` block inside a `deps` or `dev-deps` section. Raised at parse time before any resolution occurs.

**Fix:** Move the `member` declaration outside the `when` block. If conditional membership is intended, use a workspace-level mechanism rather than a dep-level predicate.

### `MAN-MIRRORS-ARITY`

Top-level `mirror` takes exactly one positional URL argument.

**Triggered:** Top-level `mirror` has wrong arity.

### `MAN-MIRRORS-UNKNOWN-CHILD`

Unknown child node in top-level mirrors block.

**Triggered:** Top-level `mirrors { ... }` has a child not named `mirror`.

### `MAN-MUTATE-FILE-NOT-FOUND`

mutate_manifest_file invoked on a non-existent path.

**Triggered:** No file at the path being mutated.

### `MAN-MUTATE-NIMBLE-REFUSED`

Refusing to mutate a .nimble file; promote to milpa.kdl first.

**Triggered:** Caller passes a .nimble path to mutate_manifest_file.

### `MAN-MUTATE-WORKSPACE-REFUSED`

Workspace manifests cannot be mutated via this helper.

**Triggered:** Caller passes a workspace-form manifest to mutate_manifest_file.

### `MAN-NAME-DUPLICATE`

Top-level `name` node declared more than once.

**Triggered:** A manifest has two `name "..."` lines.

### `MAN-NAME-MISSING`

Package manifest is missing the required top-level `name` node.

**Triggered:** A package-form manifest has no `name "..."` declaration.

### `MAN-NAME-TYPE`

`name` must take exactly one positional string argument.

**Triggered:** `name` node has wrong arity or non-string arg.

### `MAN-NIMBLE-AMBIGUOUS`

Multiple .nimble files in a project; cannot pick automatically.

**Triggered:** load_or_discover_manifest finds >1 .nimble and no project-named match.

### `MAN-NIMBLE-CONSTRAINT`

A transitive .nimble file's `requires` constraint string is malformed.

**Triggered:** resolver._build_terms tries VersionSet.from_constraint on a .nimble requires entry and gets an unparseable clause.

### `MAN-NIMBLE-PARSE`

A .nimble fallback file failed to parse.

**Triggered:** load_or_discover_manifest auto-promotes a .nimble and load_nimble raises a non-IO NimbleParseError. Reserved: parse_nimble is currently tolerant and does not raise on content.

### `MAN-NO-MANIFEST`

No milpa.kdl or .nimble found in the project directory.

**Triggered:** load_or_discover_manifest finds neither.

### `MAN-OVERRIDE-ARITY`

pkg override takes one positional argument (the dep name).

**Triggered:** `pkg "..."` arity is wrong or arg is non-string.

### `MAN-OVERRIDE-DUPLICATE`

Duplicate override for the same name.

**Triggered:** Two pkg overrides target the same name.

### `MAN-OVERRIDE-GIT-MISSING`

pkg override is missing required `git` property.

**Triggered:** `pkg "..."` has no `git=...`.

### `MAN-OVERRIDE-KIND`

Unknown override kind.

**Triggered:** An overrides-block child is not `pkg`.

### `MAN-OVERRIDE-REF-MISSING`

pkg override is missing required `ref` property.

**Triggered:** `pkg "..."` has no `ref=...`.

### `MAN-OVERRIDE-TARGET-AMBIGUOUS`

A `pkg` override rule must have exactly one provenance target form.

**Triggered:** A `pkg` override has zero target forms (no `git=`, `local=`, or
`member` child), or has multiple forms simultaneously (e.g. both `local=` and
`git=`). Exactly one of `git=(url)"..." ref="..."`, `local="<path>"`, or a
`{ member "<name>" }` child is required per `pkg` rule.

### `MAN-OVERRIDE-UNKNOWN-PROPS`

Unknown property on a pkg override.

**Triggered:** A pkg override has a property not in {git, ref, local}.

### `MAN-PREDICATE-CHILD-ARG-TYPE`

Predicate child-node arg must be a string.

**Triggered:** A `{ platform <non-string> }` has a non-string arg.

### `MAN-PREDICATE-CHILD-NO-ARGS`

Predicate child node requires at least one positional argument.

**Triggered:** A `{ platform }` child has no args.

### `MAN-PREDICATE-FORM-CONFLICT`

Same predicate declared in both inline-prop and child-node forms.

**Triggered:** A dep has both `platform="X"` and `{ platform "Y" }`.

### `MAN-PREDICATE-MIXED-NEGATION`

Predicate child mixes `(not)` and bare args — must agree on negation.

**Triggered:** `{ platform "x" (not)"y" }` is declared.

### `MAN-PREDICATE-UNKNOWN`

Unknown predicate name.

**Triggered:** A `when` block or inline prop uses a predicate not in {platform, arch, nim, milpa, flag}.

### `MAN-PREDICATE-UNSUPPORTED-ANNOTATION`

Predicate value has an unsupported type annotation (only `(not)` recognized).

**Triggered:** A predicate value carries a tag other than `not`.

### `MAN-PREDICATE-VALUE-TYPE`

Predicate value must be a string.

**Triggered:** A predicate's value is non-string.

### `MAN-REMOVE-DEP-ABSENT`

`milpa remove` rejected: the dep is not declared in milpa.kdl.

**Triggered:** cmd_remove finds <dep> is not present in the manifest's deps block.

### `MAN-SPEC-VERSION-TYPE`

`spec-version` must carry exactly one positional integer argument >= 1.

**Triggered:** spec-version node has wrong arity, non-integer arg, or value < 1.

### `MAN-SPEC-VERSION-UNSUPPORTED`

Manifest declares a spec-version epoch greater than this implementation supports.

**Triggered:** spec-version <N> where N > MANIFEST_SPEC_VERSION.

### `MAN-SRC-DIR-TYPE`

`src_dir` must take exactly one positional string argument.

**Triggered:** `src_dir` node has wrong arity or non-string arg.

### `MAN-SRC-DIR-UNSAFE`

A `src_dir` value contains a control character or Unicode line separator that would allow nim.cfg injection.

**Triggered:** The string value of a `src_dir` node (either the top-level package `src_dir` or a dep-level `src_dir`) contains `\n`, `\r`, any other ASCII control character (codepoints 0x00–0x1F and 0x7F), or a Unicode line separator (U+2028 or U+2029). Because `src_dir` is incorporated verbatim into nim.cfg `--path:` lines, the parse boundary MUST validate the value and reject any string that could inject new nim.cfg directives.

### `MAN-UNKNOWN-TOP-LEVEL`

Unknown top-level node in package manifest.

**Triggered:** A top-level node is not in the package manifest's allowed set.

### `MAN-URL-ARG-TYPE`

A URL-typed argument must be a string or (url)-annotated value.

**Triggered:** A URL position receives a non-string, non-ParseResult value.

### `MAN-WORKSPACE-HAS-DEPS-OR-KIND`

A workspace manifest must not declare `deps` or `kind`.

**Triggered:** A doc with `workspace { }` also has `deps { }` or `kind`.

### `MAN-WORKSPACE-IN-PACKAGE`

A `workspace` block appeared in a package-form manifest.

**Triggered:** parse_manifest sees `workspace { ... }`; workspace + package are disjoint.

### `MAN-WORKSPACE-MEMBER-ARITY`

`member` (in workspace) takes exactly one positional string path argument.

**Triggered:** A workspace member declaration has wrong arity or non-string arg.

### `MAN-WORKSPACE-MEMBER-DUPLICATE`

Duplicate workspace member path.

**Triggered:** Two member declarations have the same path.

### `MAN-WORKSPACE-UNKNOWN-NODE`

Unknown node in workspace block.

**Triggered:** A workspace block's child is not `member`.

### `MAN-WORKSPACE-UNKNOWN-TOP-LEVEL`

Unknown top-level node in workspace manifest.

**Triggered:** A workspace manifest has a top-level node outside the allowed set.

## NIMBLE

### `NIMBLE-FILE-NOT-FOUND`

The .nimble file path does not exist.

**Triggered:** load_nimble is called with a path that has no file on disk.

### `NIMBLE-FILE-UNREADABLE`

The .nimble file cannot be read (permissions, OS error).

**Triggered:** OS denies reading the .nimble file.

## RES

### `RES-NO-INDEX`

Manifest has named dep(s) but no tianguis index was provided.

**Triggered:** resolve() is called without index= when the manifest has NamedDep entries.

### `RESOLVE-FLAG-CONFLICT`

Two flags declared mutually-exclusive via `conflicts` are both active on the same dep after the dep×flag fixpoint converges.

**Triggered:** Post-fixpoint validation pass (S4c RFC #23 §3.1.4): for each dep D, for each flag `f ∈ active(D)`, for each `g` in `f.conflicts`: if `g ∈ active(D)`, raise `RESOLVE-FLAG-CONFLICT`. The pass only reads the converged set and never retracts; monotonicity is untouched. This is the ONLY source of this error — opt-out (`flag "x" #false`) never raises it.

**Payload (normative, required):** `{dep, flag_a, flag_b, sources_a, sources_b}` where `dep` is the dep name, `flag_a`/`flag_b` are the conflicting flag names (lexicographic order), and `sources_a`/`sources_b` are the activation-source sets for each flag. Source sets are serialized as a sorted list of source names using enum declaration order: `"default"`, `"edge_request"`, `"enables_rule"` (the three `ActivationSource` variants). The payload must be byte-identical across both impls.

### `RES-PROVENANCE-CONFLICT`

Two transitive deps declare different provenance (source) for the same package name and the root does not override that name. The resolver cannot unambiguously choose between two different source trees for the same package name.

**Triggered:** A package name is first encountered via one transport (URL/local/named) and then a transitive dep requests it via a different, incompatible transport/URL, and the root manifest has no authority over that name (it is not declared in deps, dev-deps, or overrides).

### `RES-UNATTESTED-METADATA`

Under strict attestation policy, one or more resolved deps used un-attested `.nimble` metadata (no `dep_decl` pointer in the index, or the `dep_decl` artifact was unreachable and the policy does not allow fallback).

**Triggered:** `resolve()` completes but the effective attestation policy is strict (either `attestation-policy "strict"` in `milpa.kdl` or `--require-attested-metadata` on the CLI) and at least one dep's edges came from the `NimbleFallback` source (no index-attested DepDecl). Under non-strict (default permissive) policy, a summary warning is emitted to stderr instead.

### `RES-WS-MEMBER-REF-UNKNOWN`

A workspace member references a `member "X"` dep that doesn't exist.

**Triggered:** A `MemberDep` (or a `member "X"` in `dev-deps`) name is not in the workspace's member list.  Both `deps` and `dev-deps` are checked.

### `RES-WS-MEMBER-VERSION-CONSTRAINT`

A named dep auto-coerced to a workspace member does not satisfy the declared version constraint.

**Triggered:** A `NamedDep` whose name matches a workspace member auto-coerces to that member (resolver-semantics §11.5), but the dep's declared version constraint is not satisfied by the member's sentinel version (`0.0.1`).  The constraint is not silently discarded — a `foo >= 2.0.0` dep where member `foo` is at sentinel `0.0.1` raises this error.

### `RES-WS-NO-INDEX`

Workspace has named dep(s) but no tianguis index was provided.

**Triggered:** resolve_workspace() is called without index= when members have NamedDep entries.

### `RES-WS-OVERRIDE-MEMBER-COLLISION`

A workspace override name also appears as a workspace member.

**Triggered:** The same name appears in both overrides and workspace members.

## SOLVE

### `SOLVE-CONFLICT`

No version solution exists — dep constraints are unsatisfiable.

**Triggered:** PubGrub exhausts all backtracking options and finds no consistent assignment.  SolverError.chain carries the structured ConflictChain narrating why.

## TNG

### `TNG-AMBIGUOUS-NAME`

The bare package name matches more than one namespace in the index.

**Triggered:** resolve_named (or resolve_named_all) calls lookup_bare and receives AmbiguousName — use a namespace-qualified reference to disambiguate.

### `TNG-BAD-COMMIT-SHA`

A git provenance commit_sha is not a valid 40-character lowercase hex SHA1.

**Triggered:** _validate_commit_sha finds the commit_sha field does not match `^[0-9a-f]{40}$` — rejects abbreviated SHAs and flag-injection vectors.

### `TNG-BAD-DEP-DECL`

A `dep_decl` pointer in the index version-node is not in `sha256:<64 lowercase hex>` format.

**Triggered:** _validate_dep_decl_pointer finds the dep_decl field does not match `^sha256:[0-9a-f]{64}$` — rejects path-traversal payloads and other malformed pointers at the index-parse boundary (registry-protocol §3.2 NORMATIVE). Validated before the value can reach FileDepDeclStore (filesystem path) or HttpDepDeclStore (URL path segment).

### `TNG-BAD-OCI-DIGEST`

An OCI provenance digest is not in `sha256:<64 lowercase hex>` format.

**Triggered:** _validate_oci_digest finds the digest field does not match `^sha256:[0-9a-f]{64}$` — rejects malformed oras pull references.

### `TNG-BAD-VERSION`

An index version string is not a parseable X.Y.Z semver.

**Triggered:** Reserved for a future strict-parse pass.  Currently unparseable version strings are silently skipped (forward-compat); this code will be raised when a strict mode is enabled.

### `TNG-DEPDECL-FETCH-FAILED`

The DepDecl artifact is unreachable — network error or file-not-found in the dep-decl store.

**Triggered:** `DepDeclStore.get` cannot retrieve the artifact at the derived URL or `MILPA_DEP_DECL_DIR` path.  In the non-strict path the resolver falls through to the `.nimble` fallback with an `RES-UNATTESTED-METADATA` warning; with `--require-attested-metadata` this is a hard failure.  Defined in `spec/dep-decl.md §6`.

### `TNG-DEPDECL-HASH-MISMATCH`

`sha256(received_bytes)` does not equal the `dep_decl` pointer from the index version-node.

**Triggered:** `DepDeclStore.get` computes sha256 of the received artifact bytes and finds they do not match the expected hash.  The artifact is rejected; no data from it is consumed.  Defined in `spec/dep-decl.md §6`.

### `TNG-DEPDECL-PARSE-ERROR`

The DepDecl artifact bytes are not valid KDL 2.0, or the KDL structure does not conform to `spec/dep-decl.md §2`.

**Triggered:** The DepDecl parser finds invalid KDL syntax, a missing `dep_decl` top node, missing required child fields, or malformed entry nodes.  Defined in `spec/dep-decl.md §6`.

### `TNG-DEPDECL-SCHEMA-MISMATCH`

The DepDecl artifact's embedded `dep_decl_schema_version` does not match the `dep_decl_schema_version` field from the index version-node pointer.

**Triggered:** The schema consistency check (§5 of `spec/dep-decl.md`) finds the two version integers disagree — indicating a partially-applied index update.  Defined in `spec/dep-decl.md §6`.

### `TNG-DEPDECL-SCHEMA-UNSUPPORTED`

The DepDecl artifact declares a `dep_decl_schema_version` greater than the implementation's maximum understood version.

**Triggered:** The consumer's version-enforcement check (§4.3 of `spec/dep-decl.md`) finds `artifact.dep_decl_schema_version > MAX_DEP_DECL_SCHEMA_VERSION`.  The user must upgrade their milpa installation.  Defined in `spec/dep-decl.md §6`.

### `TNG-KDL-SYNTAX`

The index text is not valid KDL and cannot be parsed.

**Triggered:** parse_index calls kdl.parse() and it raises kdl.errors.ParseError — the raw text supplied as the index is syntactically invalid KDL.

### `TNG-NO-IDENTITY`

An index entry carries no content_hash — identity verification is impossible.

**Triggered:** The resolver's identity gate (_fetch_and_build_named_candidate in resolver.py) finds IndexVersion.content_hash is empty or absent.  A content_hash is required before any fetch is attempted; absence is a malformed index entry.  The resolver MUST NOT attempt to fetch a named dep without a verifiable identity.

### `TNG-NO-PROVENANCE`

A package version has no fetchable provenance in the index.

**Triggered:** resolve_named_all finds a version whose provenances tuple is empty after skipping provenance-less entries, or IndexVersion.canonical_provenance is called on an entry with no provenances.

### `TNG-NO-SATISFYING-VERSION`

A named package is present in the index but enumerate-all Phase-A yields no
usable (provenance-bearing) candidate. This slug does NOT fire on constraint
incompatibility: per `resolver-semantics.md §2.1`, Phase-A enumeration MUST NOT
pre-filter by the declared constraint — the solver owns the satisfiability
verdict and emits `SOLVE-CONFLICT` when no enumerated version satisfies it.

**Triggered:** after enumerate-all Phase-A (no constraint filter), every
enumerated version of the package is discarded for lack of provenance (or has an
unparseable version string), leaving zero candidates to hand to the solver. When
at least one provenance-bearing candidate exists, an unsatisfiable constraint
surfaces as `SOLVE-CONFLICT` (the solver's refutation), not this slug.

### `TNG-NOT-FOUND`

The requested package name is not in the tianguis index.

**Triggered:** resolve_named_all looks up a bare name and finds no matching package in the index.  Every nim-lang/packages entry should be vendored; absence indicates a vendor-bot gap.

### `TNG-SCHEMA-UNKNOWN`

The index declares a schema_version higher than this milpa supports.

**Triggered:** _check_schema_version finds the index schema_version integer is greater than TIANGUIS_INDEX_SCHEMA_VERSION — the caller must upgrade milpa.

### `TNG-UNSAFE-NAME`

A package name contains path-traversal characters and is unsafe as a filesystem path component under `_deps/`.

**Triggered:** _validate_safe_name finds the name contains `..`, `/`, `\\`, or is an absolute path — would escape the _deps/ sandbox if used as a directory name.

### `TNG-UNSAFE-OCI-FIELD`

An OCI provenance field (registry or repository) begins with `-` and would be interpreted as a CLI flag.

**Triggered:** _validate_no_leading_dash finds an oci registry or repository value starting with `-` — flag-injection prevention for oras argv.

### `TNG-UNSAFE-REF`

A git ref begins with `-` and would be interpreted as a CLI flag.

**Triggered:** _validate_no_leading_dash finds a git ref value starting with `-` — flag-injection prevention at the index trust boundary.

### `TNG-UNSAFE-URL`

A git URL begins with `-` and would be interpreted as a CLI flag.

**Triggered:** _validate_no_leading_dash finds a git url value starting with `-` — flag-injection prevention at the index trust boundary.

## VERIFY

### `VERIFY-DEPS-DIR-MISSING`

`milpa verify` cannot run: there is no _deps/ directory.

**Triggered:** cmd_verify finds no _deps/ under the project (or workspace) root — nothing has been fetched, so there is nothing to verify against the lockfile. The user is directed to run `milpa fetch` first.

### `VERIFY-ALIAS-SYMLINK-MISSING`

An alias `_deps/<alias>` symlink is absent, dangling, or points to a different store entry than its canonical `_deps/<name>` symlink.

**Triggered:** `verify_lockfile_against_deps` iterates a dep's `aliases` list and finds that `_deps/<alias>` either does not exist, is a dangling symlink, or resolves to a different path than `_deps/<canonical>`. Each failing alias produces one divergence carrying this slug.

### `VERIFY-EDGE-MISMATCH`

The locked `dep_decl` pin no longer matches the current index pointer for a dep (§3.7, RFC content-addressed-metadata).

**Triggered:** `milpa verify` loads the live index and finds that the `dep_decl` hash recorded in `milpa.lock` for a dep differs from the `dep_decl` pointer the index now carries for that version — the dependency graph has drifted since the lockfile was written. Also raised when the edge check is required but the index is offline and strict mode (`--require-attested-metadata`) is active.

## WS

### `WS-MEMBER-DIR-MISSING`

A workspace member has no directory at the declared path.

**Triggered:** load_workspace resolves a member path and finds no directory there.

### `WS-MEMBER-DOT`

Member path "." is not supported; the workspace root cannot also be a package.

**Triggered:** A workspace member declaration uses "." as the member path.

### `WS-MEMBER-DUPLICATE-NAME`

Two workspace members claim the same package name.

**Triggered:** load_workspace finds two members whose milpa.kdl both declare the same name.

### `WS-MEMBER-HAS-OVERRIDES`

A workspace member declares its own `overrides` block; per-member overrides are not supported.

**Triggered:** load_workspace finds overrides declared in a member's manifest.

### `WS-MEMBER-IS-WORKSPACE`

A workspace member is itself a workspace; nested workspaces are not supported.

**Triggered:** load_workspace parses a member's milpa.kdl and finds a WorkspaceManifest.

### `WS-MEMBER-NO-MANIFEST`

A workspace member directory has no milpa.kdl.

**Triggered:** load_workspace finds the member directory but no milpa.kdl inside it.

### `WS-MEMBER-PATH-ESCAPE`

A workspace member path resolves outside the workspace root.

**Triggered:** load_workspace resolves a member path and finds it escapes the workspace root directory. This is a security boundary: a workspace must not be able to read or incorporate manifests from arbitrary locations on the filesystem.

Resolution algorithm (Option A — best-effort canonicalization): both root and candidate are resolved via the same algorithm: the **longest existing path prefix is fully canonicalized** (all symlinks followed), and the remaining non-existent suffix is normalized lexically — equivalent to Python `Path.resolve(strict=False)`. For a dangling-symlink final component, the link target is read and joined onto the canonicalized parent before lexical normalization. This single algorithm handles all cases uniformly: an existing path is fully canonicalized; a non-existent path is resolved with all symlinks in its existing prefix resolved first. The resolved candidate is an escape iff it does not start with the resolved root — this comparison is **inclusive**: a candidate that resolves to exactly the root is NOT an escape (it falls through to the `WS-MEMBER-IS-WORKSPACE` manifest-parse check, which fires because the root's own `milpa.kdl` is a workspace document). This inclusive semantics is what ensures `"pkg/.."` (which lexically reduces to the root) yields `WS-MEMBER-IS-WORKSPACE`, not `WS-MEMBER-PATH-ESCAPE`, even when the workspace root is accessed via a symlinked path.

The check runs after the dot-path check (so `"."` yields `WS-MEMBER-DOT`, not `WS-MEMBER-PATH-ESCAPE`) and before the directory-existence check (so an escaping path yields `WS-MEMBER-PATH-ESCAPE` regardless of whether the target directory exists).

### `WS-NO-MANIFEST`

No milpa.kdl found at the expected workspace root.

**Triggered:** load_workspace is called on a directory with no milpa.kdl.

### `WS-NOT-A-WORKSPACE`

The milpa.kdl at the root is a package manifest, not a workspace.

**Triggered:** load_workspace parses the root milpa.kdl and finds a Manifest, not WorkspaceManifest.

### `WS-REMOVE-MEMBER-NOT-FOUND`

The name or path given to `milpa workspace remove-member` does not match any declared workspace member.

**Triggered:** `cmd_workspace_remove_member` searches the workspace manifest's member list for the given name or path and finds no match. The user is directed to run `milpa show` or inspect the workspace `milpa.kdl` to see the current member list.

### `WS-REMOVE-MEMBER-TARGET-EXISTS`

The workspace root's `overrides {}` block contains a `MemberTarget` entry that points at the member being removed; removing the member would leave a dangling override reference.

**Triggered:** `cmd_workspace_remove_member` scans the root manifest's `overrides` for any `pkg { member "<name>" }` rule targeting the member to be removed and finds one. The user must update or remove the override before removing the member. (Distinct from `WS-MEMBER-HAS-OVERRIDES`, which fires when a member declares its *own* overrides block.)

### `WS-REMOVE-MEMBER-REFERENCED`

Another workspace member's `deps` or `dev_deps` carries a `member "<removed>"` edge; removing the member would leave a dangling member-dep reference.

**Triggered:** `cmd_workspace_remove_member` scans all remaining members' `deps` and `dev_deps` for a `member "<name>"` dep matching the member to be removed and finds one or more such references. The referencing member name(s) are included in the error message. The user must remove or replace the `member` dep in the referencing member(s) before removing the workspace member.
