"""WorkspaceError codes — every error the workspace loader can produce.
Codes use the ``WS-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined.

Note: ManifestError raised during a member's milpa.kdl parse propagates
with MAN-* codes (not WS-*) — the workspace loader does not wrap those.
WorkspaceError is specifically the workspace-topology layer.
"""

from milpa.error_catalog import register


_CAT = "WS"

NO_MANIFEST = register(
    slug="WS-NO-MANIFEST", category=_CAT,
    description="No milpa.kdl found at the expected workspace root.",
    when="load_workspace is called on a directory with no milpa.kdl.",
)

NOT_A_WORKSPACE = register(
    slug="WS-NOT-A-WORKSPACE", category=_CAT,
    description="The milpa.kdl at the root is a package manifest, not a workspace.",
    when="load_workspace parses the root milpa.kdl and finds a Manifest, not WorkspaceManifest.",
)

MEMBER_DOT = register(
    slug="WS-MEMBER-DOT", category=_CAT,
    description='Member path "." is not supported; the workspace root cannot also be a package.',
    when='A workspace member declaration uses "." as the member path.',
)

MEMBER_DIR_MISSING = register(
    slug="WS-MEMBER-DIR-MISSING", category=_CAT,
    description="A workspace member has no directory at the declared path.",
    when="load_workspace resolves a member path and finds no directory there.",
)

MEMBER_NO_MANIFEST = register(
    slug="WS-MEMBER-NO-MANIFEST", category=_CAT,
    description="A workspace member directory has no milpa.kdl.",
    when="load_workspace finds the member directory but no milpa.kdl inside it.",
)

MEMBER_IS_WORKSPACE = register(
    slug="WS-MEMBER-IS-WORKSPACE", category=_CAT,
    description="A workspace member is itself a workspace; nested workspaces are not supported.",
    when="load_workspace parses a member's milpa.kdl and finds a WorkspaceManifest.",
)

MEMBER_HAS_OVERRIDES = register(
    slug="WS-MEMBER-HAS-OVERRIDES", category=_CAT,
    description="A workspace member declares its own `overrides` block; per-member overrides are not supported.",
    when="load_workspace finds overrides declared in a member's manifest.",
)

MEMBER_DUPLICATE_NAME = register(
    slug="WS-MEMBER-DUPLICATE-NAME", category=_CAT,
    description="Two workspace members claim the same package name.",
    when="load_workspace finds two members whose milpa.kdl both declare the same name.",
)
