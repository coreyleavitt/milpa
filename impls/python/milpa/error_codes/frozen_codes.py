"""NotFrozen codes — every precondition-failure reason the frozen fast
path can produce.  Codes use the ``FROZEN-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined.

Context: NotFrozen is a flow-control exception — when raised in the
normal resolve path it causes fallthrough to the slow resolve.  When
raised under ``--frozen`` (or its programmatic equivalent), it becomes
a terminal user-visible error.  All raise sites are catalogued because
they're all reachable from user-supplied state (manifest/lockfile
content, CAS state, strategy flag).
"""

from milpa.error_catalog import register


_CAT = "FROZEN"

STRATEGY_MISMATCH = register(
    slug="FROZEN-STRATEGY-MISMATCH", category=_CAT,
    description="The requested resolution strategy differs from what the lockfile was built with.",
    when=(
        "_check_strategy finds the requested strategy string does not match "
        "lockfile.strategy."
    ),
)

MANIFEST_DEP_NOT_IN_LOCK = register(
    slug="FROZEN-MANIFEST-DEP-NOT-IN-LOCK", category=_CAT,
    description="A manifest dep has no lockfile entry; lockfile is stale.",
    when=(
        "_check_manifest_alignment finds a manifest dep name absent from "
        "the lockfile's dep list."
    ),
)

LOCKED_VERSION_UNPARSEABLE = register(
    slug="FROZEN-LOCKED-VERSION-UNPARSEABLE", category=_CAT,
    description="A dep's locked version string is not a parseable X.Y.Z version.",
    when=(
        "_check_manifest_alignment or _resolved_from_locked calls "
        "parse_version on the locked version and gets None."
    ),
)

CONSTRAINT_UNSATISFIED = register(
    slug="FROZEN-CONSTRAINT-UNSATISFIED", category=_CAT,
    description=(
        "A manifest NamedDep's version constraint is no longer satisfied "
        "by the locked version."
    ),
    when=(
        "_check_manifest_alignment checks VersionSet.from_constraint against "
        "the locked version and finds it fails."
    ),
)

MEMBER_DEP = register(
    slug="FROZEN-MEMBER-DEP", category=_CAT,
    description="A dep is a workspace member; members always re-resolve.",
    when=(
        "resolve_frozen encounters a MemberProvenanceRecord — single-package "
        "frozen path does not handle workspace members."
    ),
)

LOCAL_DEP = register(
    slug="FROZEN-LOCAL-DEP", category=_CAT,
    description="A dep has a local provenance; editable trees always re-resolve.",
    when=(
        "resolve_frozen or resolve_workspace_frozen encounters a "
        "LocalProvenanceRecord."
    ),
)

MEMBER_NOT_IN_WORKSPACE = register(
    slug="FROZEN-MEMBER-NOT-IN-WORKSPACE", category=_CAT,
    description=(
        "The lockfile references a workspace member that is absent "
        "from the current workspace."
    ),
    when=(
        "resolve_workspace_frozen finds MemberProvenanceRecord.name is "
        "not in the workspace's member list."
    ),
)

MEMBER_IDENTITY_DRIFT = register(
    slug="FROZEN-MEMBER-IDENTITY-DRIFT", category=_CAT,
    description=(
        "A workspace member's on-disk content hash differs from the lockfile pin."
    ),
    when=(
        "resolve_workspace_frozen computes the member directory's content "
        "hash and finds it differs from the lockfile's recorded identity."
    ),
)

IDENTITY_NOT_IN_STORE = register(
    slug="FROZEN-IDENTITY-NOT-IN-STORE", category=_CAT,
    description="A dep's pinned identity is not present in the CAS.",
    when=(
        "_link_external finds the dep's identity is absent or None, or "
        "CAStore.contains returns False."
    ),
)

LEGACY_REGISTRY_PROVENANCE = register(
    slug="FROZEN-LEGACY-REGISTRY-PROVENANCE", category=_CAT,
    description=(
        "A lock entry uses the legacy registry provenance and cannot be "
        "reconstructed by the frozen path."
    ),
    when=(
        "_source_from_provenance encounters a RegistryProvenanceRecord; "
        "the user must run `milpa update <name>` to re-resolve via tianguis."
    ),
)

NO_LOCKFILE = register(
    slug="FROZEN-NO-LOCKFILE", category=_CAT,
    description=(
        "The frozen fast path requires a lockfile, but none is present."
    ),
    when=(
        "_try_frozen / _try_workspace_frozen find no milpa.lock at the "
        "project (or workspace) root; with --frozen this is exit 1 rather "
        "than a silent fall-through to full resolution."
    ),
)

NO_CAS = register(
    slug="FROZEN-NO-CAS", category=_CAT,
    description=(
        "The frozen fast path requires a content-addressed store, but the "
        "fetcher has none attached."
    ),
    when=(
        "_try_frozen / _try_workspace_frozen find fetcher.store is None; the "
        "frozen path cannot link _deps/ from a CAS that does not exist."
    ),
)
