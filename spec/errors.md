# milpa error catalog

Normative spec of every error milpa can produce. Each entry's
`slug` is the conformance-stable identifier; consumers (CI
scripts, IDE integrations, alternate implementations) MAY rely
on slugs but MUST NOT rely on message wording.

Generated from `milpa/error_catalog.py` — do not edit by hand.

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

**Triggered:** CAStore.link is called for an identity that has no entry under <root>/<algorithm>/<hex>/.

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

**Triggered:** fetch_any() tries all candidate provenances in order and every one either raises or produces a mismatched identity.  Identity-mismatch candidates are folded into the composite failure message.

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

### `FETCH-RECEIPT-EMPTY`

A fetcher returned a receipt whose transport_fields() is empty — no provenance evidence was recorded.

**Triggered:** FetcherRegistry.fetch calls receipt.transport_fields() after a successful fetch and the returned dict is empty, violating the spec §3.2 non-empty-receipt contract.

### `FETCH-SHA256-MISMATCH`

Downloaded archive sha256 does not match the declared expected_sha256.

**Triggered:** TarballFetcher compares the archive's actual sha256 against TarballProvenance.expected_sha256 and finds a mismatch.

## FROZEN

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

### `MAN-ADD-MIRROR-IDENTITY-MISMATCH`

`milpa add --mirror` rejected: the URL's bytes don't hash to the locked identity.

**Triggered:** The proposed mirror URL serves bytes that differ from what the lockfile pinned.

### `MAN-CAS-DIR-MISSING`

`cas` block requires a `dir` child node.

**Triggered:** A `cas { ... }` block is declared without a `dir "<path>"` entry.

### `MAN-CAS-DIR-TYPE`

`cas.dir` must take exactly one positional string argument.

**Triggered:** `cas.dir` value is missing, multi-valued, or non-string.

### `MAN-DEP-DUPLICATE`

A dep name appears more than once in the deps block.

**Triggered:** Two dep declarations resolve to the same name.

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

### `MAN-FLAG-DESCRIPTION-TYPE`

Flag `description` must be a string.

**Triggered:** `description=` is not a string.

### `MAN-FLAG-DUPLICATE`

Duplicate flag declaration.

**Triggered:** Two flags in `flags { }` have the same name.

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

### `MAN-OVERRIDE-UNKNOWN-PROPS`

Unknown property on a pkg override.

**Triggered:** A pkg override has a property not in {git, ref}.

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

### `RES-PROVENANCE-CONFLICT`

Two transitive deps declare different provenance (source) for the same package name and the root does not override that name. The resolver cannot unambiguously choose between two different source trees for the same package name.

**Triggered:** A package name is first encountered via one transport (URL/local/named) and then a transitive dep requests it via a different, incompatible transport/URL, and the root manifest has no authority over that name (it is not declared in deps, dev-deps, or overrides).

### `RES-UNATTESTED-METADATA`

Under strict attestation policy, one or more resolved deps used un-attested `.nimble` metadata (no `dep_decl` pointer in the index, or the `dep_decl` artifact was unreachable and the policy does not allow fallback).

**Triggered:** `resolve()` completes but the effective attestation policy is strict (either `attestation-policy "strict"` in `milpa.kdl` or `--require-attested-metadata` on the CLI) and at least one dep's edges came from the `NimbleFallback` source (no index-attested DepDecl). Under non-strict (default permissive) policy, a summary warning is emitted to stderr instead.

### `RES-WS-MEMBER-REF-UNKNOWN`

A workspace member references a `member "X"` dep that doesn't exist.

**Triggered:** A MemberDep name is not in the workspace's member list.

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

No version of the requested package satisfies the declared constraint.

**Triggered:** resolve_named_all applies VersionSet.from_constraint to every IndexVersion and finds none satisfying — the constraint is incompatible with all available versions.

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

### `WS-NO-MANIFEST`

No milpa.kdl found at the expected workspace root.

**Triggered:** load_workspace is called on a directory with no milpa.kdl.

### `WS-NOT-A-WORKSPACE`

The milpa.kdl at the root is a package manifest, not a workspace.

**Triggered:** load_workspace parses the root milpa.kdl and finds a Manifest, not WorkspaceManifest.
