# milpa error catalog

Normative spec of every error milpa can produce. Each entry's
`slug` is the conformance-stable identifier; consumers (CI
scripts, IDE integrations, alternate implementations) MAY rely
on slugs but MUST NOT rely on message wording.

Generated from `milpa/error_catalog.py` — do not edit by hand.

## MAN

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

NamedDep's version constraint must be a quoted string.

**Triggered:** The positional arg is not a string.

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

**Triggered:** OS denies reading the file.

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

### `MAN-NIMBLE-PARSE`

A .nimble fallback file failed to parse.

**Triggered:** load_or_discover_manifest auto-promotes a .nimble whose nimble_parse raises.

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
