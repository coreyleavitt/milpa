"""ResolverError codes — every error the resolver can produce while building
the candidate set (structural problems, missing index, member references).
Codes use the `RES-*` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined."""

from milpa.error_catalog import register


_CAT = "RES"

# ---------------------------------------------------------------------------
# Named-dep without index
# ---------------------------------------------------------------------------

NO_INDEX = register(
    slug="RES-NO-INDEX", category=_CAT,
    description="Manifest has named dep(s) but no tianguis index was provided.",
    when="resolve() is called without index= when the manifest has NamedDep entries.",
)

# ---------------------------------------------------------------------------
# Workspace structural errors
# ---------------------------------------------------------------------------

WS_NO_INDEX = register(
    slug="RES-WS-NO-INDEX", category=_CAT,
    description="Workspace has named dep(s) but no tianguis index was provided.",
    when="resolve_workspace() is called without index= when members have NamedDep entries.",
)

WS_OVERRIDE_MEMBER_COLLISION = register(
    slug="RES-WS-OVERRIDE-MEMBER-COLLISION", category=_CAT,
    description="A workspace override name also appears as a workspace member.",
    when="The same name appears in both overrides and workspace members.",
)

WS_MEMBER_REF_UNKNOWN = register(
    slug="RES-WS-MEMBER-REF-UNKNOWN", category=_CAT,
    description="A workspace member references a `member \"X\"` dep that doesn't exist.",
    when="A MemberDep name is not in the workspace's member list.",
)

# ---------------------------------------------------------------------------
# Provenance conflict
# ---------------------------------------------------------------------------

PROVENANCE_CONFLICT = register(
    slug="RES-PROVENANCE-CONFLICT", category=_CAT,
    description=(
        "Two transitive deps declare different provenance (source) for the "
        "same package name and the root does not override that name. "
        "The resolver cannot unambiguously choose between two different "
        "source trees for the same package name."
    ),
    when=(
        "A package name is first encountered via one transport (URL/local/named) "
        "and then a transitive dep requests it via a different, incompatible "
        "transport/URL, and the root manifest has no authority over that name "
        "(it is not declared in deps, dev-deps, or overrides)."
    ),
)
