"""LockfileError codes — every error milpa's lockfile parser / formatter /
verifier can produce.  Codes use the `LOCK-*` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined."""

from milpa.error_catalog import register


_CAT = "LOCK"

# ---------------------------------------------------------------------------
# KDL syntax & file I/O
# ---------------------------------------------------------------------------

KDL_SYNTAX = register(
    slug="LOCK-KDL-SYNTAX", category=_CAT,
    description="The lockfile is not valid KDL.",
    when="kdl-py's parser rejects the lockfile text.",
)

FILE_NOT_FOUND = register(
    slug="LOCK-FILE-NOT-FOUND", category=_CAT,
    description="The lockfile path does not exist.",
    when="load_lockfile is called with a path that doesn't exist.",
)

FILE_UNREADABLE = register(
    slug="LOCK-FILE-UNREADABLE", category=_CAT,
    description="The lockfile cannot be read (permissions, OS error).",
    when="OS denies reading the lockfile file.",
)

# ---------------------------------------------------------------------------
# Schema / version node
# ---------------------------------------------------------------------------

VERSION_MISSING = register(
    slug="LOCK-VERSION-MISSING", category=_CAT,
    description="Lockfile is missing the required top-level `version` node.",
    when="parse_lockfile finds no `version` node in the KDL document.",
)

VERSION_UNSUPPORTED = register(
    slug="LOCK-VERSION-UNSUPPORTED", category=_CAT,
    description="Lockfile schema version is not supported by this milpa.",
    when="The `version` integer is higher than LOCKFILE_SCHEMA_VERSION.",
)

FIELD_ARITY = register(
    slug="LOCK-FIELD-ARITY", category=_CAT,
    description="A lockfile scalar field takes exactly one value.",
    when="A `version` or similar scalar node has wrong arity.",
)

FIELD_TYPE = register(
    slug="LOCK-FIELD-TYPE", category=_CAT,
    description="A lockfile scalar field value has the wrong type.",
    when="A scalar node's value cannot be coerced to the expected type (e.g. int).",
)

# ---------------------------------------------------------------------------
# dep block
# ---------------------------------------------------------------------------

DEP_NAME_ARITY = register(
    slug="LOCK-DEP-NAME-ARITY", category=_CAT,
    description="A `dep` node requires exactly one string argument (the name).",
    when="A `dep` node has wrong arity or a non-string arg.",
)

DEP_FIELD_ARITY = register(
    slug="LOCK-DEP-FIELD-ARITY", category=_CAT,
    description="A dep child field must have exactly one string value.",
    when="A `version`, `src_dir`, or similar child node of a `dep` block has wrong arity.",
)

DEP_IDENTITY_INVALID = register(
    slug="LOCK-DEP-IDENTITY-INVALID", category=_CAT,
    description="A dep's `identity` field is not a valid multihash-encoded content hash.",
    when="parse_identity rejects the recorded identity string.",
)

# ---------------------------------------------------------------------------
# provenance block
# ---------------------------------------------------------------------------

PROV_FIELD_ARITY = register(
    slug="LOCK-PROV-FIELD-ARITY", category=_CAT,
    description="A provenance child field must have exactly one value.",
    when="A provenance block's child node has wrong arity.",
)

PROV_KIND_MISSING = register(
    slug="LOCK-PROV-KIND-MISSING", category=_CAT,
    description="A provenance block is missing the `kind` discriminator.",
    when="No `kind` field is found in the provenance block.",
)

PROV_KIND_UNKNOWN = register(
    slug="LOCK-PROV-KIND-UNKNOWN", category=_CAT,
    description="Unknown provenance `kind` value.",
    when="The `kind` field is not one of: git, tarball, local, member, oci, registry.",
)

PROV_FIELD_MISSING = register(
    slug="LOCK-PROV-FIELD-MISSING", category=_CAT,
    description="A provenance block is missing a required field.",
    when="A required field (e.g. `url` for git, `path` for local) is absent.",
)

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

GRAPH_MISMATCH = register(
    slug="LOCK-GRAPH-MISMATCH", category=_CAT,
    description=(
        "The deps do not match the lockfile — either the resolved graph or "
        "the on-disk _deps/ tree diverges from what milpa.lock records."
    ),
    when=(
        "verify_against_graph finds missing, extra, or identity-mismatched "
        "deps; or `milpa verify` finds the on-disk _deps/ content hashes / "
        "membership diverge from the lockfile."
    ),
)

DEP_NOT_FOUND = register(
    slug="LOCK-DEP-NOT-FOUND", category=_CAT,
    description="A named dep is absent from the lockfile.",
    when=(
        "`milpa update <dep>` or `milpa add --mirror <dep>` is asked to act "
        "on a dep that has no entry in milpa.lock."
    ),
)
