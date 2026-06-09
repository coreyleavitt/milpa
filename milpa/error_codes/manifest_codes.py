"""ManifestError codes — every error the milpa.kdl parser /
validator / writer can produce. Codes use the `MAN-*` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries. Production code references the codes by their slug strings;
the registry guarantees the slug is defined."""

from milpa.error_catalog import register


_CAT = "MAN"

# ---------------------------------------------------------------------------
# KDL syntax & file I/O
# ---------------------------------------------------------------------------

KDL_SYNTAX = register(
    slug="MAN-KDL-SYNTAX", category=_CAT,
    description="The manifest file is not valid KDL.",
    when="kdl-py's parser rejects the input text.",
)

FILE_NOT_FOUND = register(
    slug="MAN-FILE-NOT-FOUND", category=_CAT,
    description="The manifest file path does not exist.",
    when="load_manifest is called with a path that doesn't exist.",
)

FILE_UNREADABLE = register(
    slug="MAN-FILE-UNREADABLE", category=_CAT,
    description="The manifest file cannot be read (permissions, etc.).",
    when=(
        "OS denies reading the manifest file. Covers both milpa.kdl and a "
        "discovered .nimble: _load_manifest_from_nimble delegates the read to "
        "load_nimble and translates its NIMBLE-FILE-* IO error to this code."
    ),
)

NIMBLE_PARSE_FAILED = register(
    slug="MAN-NIMBLE-PARSE", category=_CAT,
    description="A .nimble fallback file failed to parse.",
    when=(
        "load_or_discover_manifest auto-promotes a .nimble and load_nimble "
        "raises a non-IO NimbleParseError. Reserved: parse_nimble is currently "
        "tolerant and does not raise on content."
    ),
)

NIMBLE_AMBIGUOUS = register(
    slug="MAN-NIMBLE-AMBIGUOUS", category=_CAT,
    description="Multiple .nimble files in a project; cannot pick automatically.",
    when="load_or_discover_manifest finds >1 .nimble and no project-named match.",
)

NIMBLE_CONSTRAINT = register(
    slug="MAN-NIMBLE-CONSTRAINT", category=_CAT,
    description="A transitive .nimble file's `requires` constraint string is malformed.",
    when=(
        "resolver._build_terms tries VersionSet.from_constraint on a .nimble "
        "requires entry and gets an unparseable clause."
    ),
)

NO_MANIFEST = register(
    slug="MAN-NO-MANIFEST", category=_CAT,
    description="No milpa.kdl or .nimble found in the project directory.",
    when="load_or_discover_manifest finds neither.",
)

# ---------------------------------------------------------------------------
# Top-level structure
# ---------------------------------------------------------------------------

NAME_MISSING = register(
    slug="MAN-NAME-MISSING", category=_CAT,
    description="Package manifest is missing the required top-level `name` node.",
    when="A package-form manifest has no `name \"...\"` declaration.",
)

NAME_DUPLICATE = register(
    slug="MAN-NAME-DUPLICATE", category=_CAT,
    description="Top-level `name` node declared more than once.",
    when="A manifest has two `name \"...\"` lines.",
)

NAME_TYPE = register(
    slug="MAN-NAME-TYPE", category=_CAT,
    description="`name` must take exactly one positional string argument.",
    when="`name` node has wrong arity or non-string arg.",
)

SRC_DIR_TYPE = register(
    slug="MAN-SRC-DIR-TYPE", category=_CAT,
    description="`src_dir` must take exactly one positional string argument.",
    when="`src_dir` node has wrong arity or non-string arg.",
)

CAS_DIR_MISSING = register(
    slug="MAN-CAS-DIR-MISSING", category=_CAT,
    description="`cas` block requires a `dir` child node.",
    when="A `cas { ... }` block is declared without a `dir \"<path>\"` entry.",
)

CAS_DIR_TYPE = register(
    slug="MAN-CAS-DIR-TYPE", category=_CAT,
    description="`cas.dir` must take exactly one positional string argument.",
    when="`cas.dir` value is missing, multi-valued, or non-string.",
)

UNKNOWN_TOP_LEVEL = register(
    slug="MAN-UNKNOWN-TOP-LEVEL", category=_CAT,
    description="Unknown top-level node in package manifest.",
    when="A top-level node is not in the package manifest's allowed set.",
)

SPEC_VERSION_UNSUPPORTED = register(
    slug="MAN-SPEC-VERSION-UNSUPPORTED", category=_CAT,
    description="Manifest declares a spec-version epoch greater than this implementation supports.",
    when="spec-version <N> where N > MANIFEST_SPEC_VERSION.",
)

SPEC_VERSION_TYPE = register(
    slug="MAN-SPEC-VERSION-TYPE", category=_CAT,
    description="`spec-version` must carry exactly one positional integer argument >= 1.",
    when="spec-version node has wrong arity, non-integer arg, or value < 1.",
)

WORKSPACE_IN_PACKAGE = register(
    slug="MAN-WORKSPACE-IN-PACKAGE", category=_CAT,
    description="A `workspace` block appeared in a package-form manifest.",
    when="parse_manifest sees `workspace { ... }`; workspace + package are disjoint.",
)

# ---------------------------------------------------------------------------
# kind
# ---------------------------------------------------------------------------

KIND_ARITY = register(
    slug="MAN-KIND-ARITY", category=_CAT,
    description="`kind` takes exactly one value.",
    when="The kind node has zero or multiple positional args.",
)

KIND_INVALID = register(
    slug="MAN-KIND-INVALID", category=_CAT,
    description="`kind` value is not one of the allowed values (library, application).",
    when="kind is anything other than the documented set.",
)

# ---------------------------------------------------------------------------
# deps block
# ---------------------------------------------------------------------------

DEP_DUPLICATE = register(
    slug="MAN-DEP-DUPLICATE", category=_CAT,
    description="A dep name appears more than once in the deps block.",
    when="Two dep declarations resolve to the same name.",
)

DEP_UNKNOWN_PROPS = register(
    slug="MAN-DEP-UNKNOWN-PROPS", category=_CAT,
    description="Unknown property on a dep declaration.",
    when="A dep child node carries a property not in the dep-form's allowed set.",
)

DEP_REF_MISSING = register(
    slug="MAN-DEP-REF-MISSING", category=_CAT,
    description="A UrlDep is missing the required `ref` property.",
    when="`git=...` is set but `ref=...` is absent.",
)

DEP_LOCAL_PATH = register(
    slug="MAN-DEP-LOCAL-PATH", category=_CAT,
    description="LocalDep's `local` must be a non-empty string path.",
    when="`local=` value is empty or non-string.",
)

DEP_TARBALL_URL = register(
    slug="MAN-DEP-TARBALL-URL", category=_CAT,
    description="TarballDep's `tarball` must be a non-empty URL string.",
    when="`tarball=` value is empty or non-string.",
)

DEP_TARBALL_SHA = register(
    slug="MAN-DEP-TARBALL-SHA", category=_CAT,
    description="TarballDep's `sha256` must be a string when provided.",
    when="`sha256=` is not a string.",
)

DEP_TARBALL_STRIP = register(
    slug="MAN-DEP-TARBALL-STRIP", category=_CAT,
    description="TarballDep's `strip_components` must be a non-negative integer.",
    when="`strip_components=` is negative, non-numeric, or boolean.",
)

DEP_MEMBER_PROPS = register(
    slug="MAN-DEP-MEMBER-PROPS", category=_CAT,
    description="MemberDep takes no properties.",
    when="`member \"name\"` has any property.",
)

DEP_MEMBER_ARITY = register(
    slug="MAN-DEP-MEMBER-ARITY", category=_CAT,
    description="MemberDep takes exactly one positional string argument.",
    when="`member` node has wrong arity or non-string arg.",
)

DEP_NAMED_PROPS = register(
    slug="MAN-DEP-NAMED-PROPS", category=_CAT,
    description="NamedDep takes only a positional version constraint, no properties.",
    when="A bare-name dep has properties (other than `git=...` which routes elsewhere).",
)

DEP_NAMED_CONSTRAINT = register(
    slug="MAN-DEP-NAMED-CONSTRAINT", category=_CAT,
    description="NamedDep's version constraint must be a quoted string.",
    when="The positional arg is not a string.",
)

DEP_NAMED_ARITY = register(
    slug="MAN-DEP-NAMED-ARITY", category=_CAT,
    description="NamedDep takes at most one positional argument (the version constraint).",
    when="A bare-name dep has more than one positional arg.",
)

DEP_MIRROR_ARITY = register(
    slug="MAN-DEP-MIRROR-ARITY", category=_CAT,
    description="A `mirror` child node takes exactly one positional URL argument.",
    when="`mirror` has wrong arity.",
)

DEP_FLAG_NAME_MISSING = register(
    slug="MAN-DEP-FLAG-NAME-MISSING", category=_CAT,
    description="A consumer `flag` child node requires a quoted name as the first arg.",
    when="`flag` has no args or first arg is non-string.",
)

DEP_FLAG_TOO_MANY_ARGS = register(
    slug="MAN-DEP-FLAG-TOO-MANY-ARGS", category=_CAT,
    description="A consumer `flag` child node takes at most two args (name, optional bool).",
    when="`flag` has 3+ positional args.",
)

DEP_FLAG_BOOL = register(
    slug="MAN-DEP-FLAG-BOOL", category=_CAT,
    description="A consumer `flag` child node's second arg must be a boolean.",
    when="`flag \"X\" <non-bool>` is declared.",
)

DEP_UNKNOWN_CHILD = register(
    slug="MAN-DEP-UNKNOWN-CHILD", category=_CAT,
    description="Unknown child node in a UrlDep block.",
    when="A dep block has a child not in {mirror, flag, <predicate>}.",
)

# ---------------------------------------------------------------------------
# Git URL validation
# ---------------------------------------------------------------------------

GIT_URL_NO_SCHEME = register(
    slug="MAN-GIT-URL-NO-SCHEME", category=_CAT,
    description="Git URL has no scheme (e.g. https://).",
    when="`git=` value's urllib-parsed scheme is empty.",
)

GIT_URL_BAD_SCHEME = register(
    slug="MAN-GIT-URL-BAD-SCHEME", category=_CAT,
    description="Git URL scheme is not in the supported set (https, http, ssh, git).",
    when="`git=` URL's scheme is unsupported.",
)

# ---------------------------------------------------------------------------
# overrides block
# ---------------------------------------------------------------------------

OVERRIDE_KIND = register(
    slug="MAN-OVERRIDE-KIND", category=_CAT,
    description="Unknown override kind.",
    when="An overrides-block child is not `pkg`.",
)

OVERRIDE_ARITY = register(
    slug="MAN-OVERRIDE-ARITY", category=_CAT,
    description="pkg override takes one positional argument (the dep name).",
    when="`pkg \"...\"` arity is wrong or arg is non-string.",
)

OVERRIDE_UNKNOWN_PROPS = register(
    slug="MAN-OVERRIDE-UNKNOWN-PROPS", category=_CAT,
    description="Unknown property on a pkg override.",
    when="A pkg override has a property not in {git, ref}.",
)

OVERRIDE_GIT_MISSING = register(
    slug="MAN-OVERRIDE-GIT-MISSING", category=_CAT,
    description="pkg override is missing required `git` property.",
    when="`pkg \"...\"` has no `git=...`.",
)

OVERRIDE_REF_MISSING = register(
    slug="MAN-OVERRIDE-REF-MISSING", category=_CAT,
    description="pkg override is missing required `ref` property.",
    when="`pkg \"...\"` has no `ref=...`.",
)

OVERRIDE_DUPLICATE = register(
    slug="MAN-OVERRIDE-DUPLICATE", category=_CAT,
    description="Duplicate override for the same name.",
    when="Two pkg overrides target the same name.",
)

# ---------------------------------------------------------------------------
# flags block (top-level)
# ---------------------------------------------------------------------------

FLAG_DUPLICATE = register(
    slug="MAN-FLAG-DUPLICATE", category=_CAT,
    description="Duplicate flag declaration.",
    when="Two flags in `flags { }` have the same name.",
)

FLAG_POS_ARGS = register(
    slug="MAN-FLAG-POS-ARGS", category=_CAT,
    description="Flag declaration must not have positional args (use props).",
    when="A flag node has positional args in addition to the identifier.",
)

FLAG_UNKNOWN_PROPS = register(
    slug="MAN-FLAG-UNKNOWN-PROPS", category=_CAT,
    description="Unknown property on a flag declaration.",
    when="A flag has a property not in {default, description}.",
)

FLAG_DEFAULT_TYPE = register(
    slug="MAN-FLAG-DEFAULT-TYPE", category=_CAT,
    description="Flag `default` must be a boolean.",
    when="`default=` is not a bool.",
)

FLAG_DESCRIPTION_TYPE = register(
    slug="MAN-FLAG-DESCRIPTION-TYPE", category=_CAT,
    description="Flag `description` must be a string.",
    when="`description=` is not a string.",
)

FLAG_UNKNOWN_CHILD = register(
    slug="MAN-FLAG-UNKNOWN-CHILD", category=_CAT,
    description="Unknown child node in a flag declaration.",
    when="A flag has a child not named `defines`.",
)

FLAG_DEFINES_ARG_TYPE = register(
    slug="MAN-FLAG-DEFINES-ARG-TYPE", category=_CAT,
    description="`defines` args must be strings.",
    when="A `defines` child has a non-string arg.",
)

FLAG_UNDECLARED_REFERENCE = register(
    slug="MAN-FLAG-UNDECLARED-REFERENCE", category=_CAT,
    description="A `when flag=\"X\"` predicate references an undeclared flag.",
    when="The manifest's own deps block uses a flag that isn't in `flags { }`.",
)

# ---------------------------------------------------------------------------
# Predicate (when blocks + inline)
# ---------------------------------------------------------------------------

PREDICATE_UNKNOWN = register(
    slug="MAN-PREDICATE-UNKNOWN", category=_CAT,
    description="Unknown predicate name.",
    when="A `when` block or inline prop uses a predicate not in {platform, arch, nim, milpa, flag}.",
)

PREDICATE_VALUE_TYPE = register(
    slug="MAN-PREDICATE-VALUE-TYPE", category=_CAT,
    description="Predicate value must be a string.",
    when="A predicate's value is non-string.",
)

PREDICATE_UNSUPPORTED_ANNOTATION = register(
    slug="MAN-PREDICATE-UNSUPPORTED-ANNOTATION", category=_CAT,
    description="Predicate value has an unsupported type annotation (only `(not)` recognized).",
    when="A predicate value carries a tag other than `not`.",
)

PREDICATE_CHILD_NO_ARGS = register(
    slug="MAN-PREDICATE-CHILD-NO-ARGS", category=_CAT,
    description="Predicate child node requires at least one positional argument.",
    when="A `{ platform }` child has no args.",
)

PREDICATE_CHILD_ARG_TYPE = register(
    slug="MAN-PREDICATE-CHILD-ARG-TYPE", category=_CAT,
    description="Predicate child-node arg must be a string.",
    when="A `{ platform <non-string> }` has a non-string arg.",
)

PREDICATE_MIXED_NEGATION = register(
    slug="MAN-PREDICATE-MIXED-NEGATION", category=_CAT,
    description="Predicate child mixes `(not)` and bare args — must agree on negation.",
    when="`{ platform \"x\" (not)\"y\" }` is declared.",
)

PREDICATE_FORM_CONFLICT = register(
    slug="MAN-PREDICATE-FORM-CONFLICT", category=_CAT,
    description="Same predicate declared in both inline-prop and child-node forms.",
    when="A dep has both `platform=\"X\"` and `{ platform \"Y\" }`.",
)

# ---------------------------------------------------------------------------
# top-level mirrors
# ---------------------------------------------------------------------------

MIRRORS_UNKNOWN_CHILD = register(
    slug="MAN-MIRRORS-UNKNOWN-CHILD", category=_CAT,
    description="Unknown child node in top-level mirrors block.",
    when="Top-level `mirrors { ... }` has a child not named `mirror`.",
)

MIRRORS_ARITY = register(
    slug="MAN-MIRRORS-ARITY", category=_CAT,
    description="Top-level `mirror` takes exactly one positional URL argument.",
    when="Top-level `mirror` has wrong arity.",
)

# ---------------------------------------------------------------------------
# Workspace manifest
# ---------------------------------------------------------------------------

WORKSPACE_HAS_DEPS_OR_KIND = register(
    slug="MAN-WORKSPACE-HAS-DEPS-OR-KIND", category=_CAT,
    description="A workspace manifest must not declare `deps` or `kind`.",
    when="A doc with `workspace { }` also has `deps { }` or `kind`.",
)

WORKSPACE_UNKNOWN_NODE = register(
    slug="MAN-WORKSPACE-UNKNOWN-NODE", category=_CAT,
    description="Unknown node in workspace block.",
    when="A workspace block's child is not `member`.",
)

WORKSPACE_MEMBER_ARITY = register(
    slug="MAN-WORKSPACE-MEMBER-ARITY", category=_CAT,
    description="`member` (in workspace) takes exactly one positional string path argument.",
    when="A workspace member declaration has wrong arity or non-string arg.",
)

WORKSPACE_MEMBER_DUPLICATE = register(
    slug="MAN-WORKSPACE-MEMBER-DUPLICATE", category=_CAT,
    description="Duplicate workspace member path.",
    when="Two member declarations have the same path.",
)

WORKSPACE_UNKNOWN_TOP_LEVEL = register(
    slug="MAN-WORKSPACE-UNKNOWN-TOP-LEVEL", category=_CAT,
    description="Unknown top-level node in workspace manifest.",
    when="A workspace manifest has a top-level node outside the allowed set.",
)

# ---------------------------------------------------------------------------
# URL handling helper
# ---------------------------------------------------------------------------

URL_ARG_TYPE = register(
    slug="MAN-URL-ARG-TYPE", category=_CAT,
    description="A URL-typed argument must be a string or (url)-annotated value.",
    when="A URL position receives a non-string, non-ParseResult value.",
)

# ---------------------------------------------------------------------------
# Mutation helper (milpa/manifest_writer.py)
# ---------------------------------------------------------------------------

MUTATE_FILE_NOT_FOUND = register(
    slug="MAN-MUTATE-FILE-NOT-FOUND", category=_CAT,
    description="mutate_manifest_file invoked on a non-existent path.",
    when="No file at the path being mutated.",
)

MUTATE_NIMBLE_REFUSED = register(
    slug="MAN-MUTATE-NIMBLE-REFUSED", category=_CAT,
    description="Refusing to mutate a .nimble file; promote to milpa.kdl first.",
    when="Caller passes a .nimble path to mutate_manifest_file.",
)

MUTATE_WORKSPACE_REFUSED = register(
    slug="MAN-MUTATE-WORKSPACE-REFUSED", category=_CAT,
    description="Workspace manifests cannot be mutated via this helper.",
    when="Caller passes a workspace-form manifest to mutate_manifest_file.",
)

ADD_MIRROR_IDENTITY_MISMATCH = register(
    slug="MAN-ADD-MIRROR-IDENTITY-MISMATCH", category=_CAT,
    description="`milpa add --mirror` rejected: the URL's bytes don't hash to the locked identity.",
    when="The proposed mirror URL serves bytes that differ from what the lockfile pinned.",
)
