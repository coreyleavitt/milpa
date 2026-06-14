"""TianguisError codes — every error the tianguis index client can produce
while parsing, looking up, or resolving against the tianguis index.
Codes use the ``TNG-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  ``TianguisError.__init__`` validates the code against the
catalog so a typo fails loudly at raise time.

Source: ``tianguis_client.py`` and the resolver's identity gate.
"""

from milpa.error_catalog import register


_CAT = "TNG"

# ---------------------------------------------------------------------------
# Schema / index-level errors
# ---------------------------------------------------------------------------

KDL_SYNTAX = register(
    slug="TNG-KDL-SYNTAX", category=_CAT,
    description="The index text is not valid KDL and cannot be parsed.",
    when=(
        "parse_index calls kdl.parse() and it raises kdl.errors.ParseError — "
        "the raw text supplied as the index is syntactically invalid KDL."
    ),
)

SCHEMA_UNKNOWN = register(
    slug="TNG-SCHEMA-UNKNOWN", category=_CAT,
    description=(
        "The index declares a schema_version higher than this milpa supports."
    ),
    when=(
        "_check_schema_version finds the index schema_version integer is "
        "greater than TIANGUIS_INDEX_SCHEMA_VERSION — the caller must upgrade milpa."
    ),
)

# ---------------------------------------------------------------------------
# Package lookup errors
# ---------------------------------------------------------------------------

NOT_FOUND = register(
    slug="TNG-NOT-FOUND", category=_CAT,
    description="The requested package name is not in the tianguis index.",
    when=(
        "resolve_named_all looks up a bare name and finds no matching package "
        "in the index.  Every nim-lang/packages entry should be vendored; "
        "absence indicates a vendor-bot gap."
    ),
)

AMBIGUOUS_NAME = register(
    slug="TNG-AMBIGUOUS-NAME", category=_CAT,
    description=(
        "The bare package name matches more than one namespace in the index."
    ),
    when=(
        "resolve_named (or resolve_named_all) calls lookup_bare and receives "
        "AmbiguousName — use a namespace-qualified reference to disambiguate."
    ),
)

NO_SATISFYING_VERSION = register(
    slug="TNG-NO-SATISFYING-VERSION", category=_CAT,
    description=(
        "No version of the requested package satisfies the declared constraint."
    ),
    when=(
        "resolve_named_all applies VersionSet.from_constraint to every "
        "IndexVersion and finds none satisfying — the constraint is "
        "incompatible with all available versions."
    ),
)

# ---------------------------------------------------------------------------
# Provenance / identity errors
# ---------------------------------------------------------------------------

NO_PROVENANCE = register(
    slug="TNG-NO-PROVENANCE", category=_CAT,
    description=(
        "A package version has no fetchable provenance in the index."
    ),
    when=(
        "resolve_named_all finds a version whose provenances tuple is empty "
        "after skipping provenance-less entries, or IndexVersion.canonical_provenance "
        "is called on an entry with no provenances."
    ),
)

NO_IDENTITY = register(
    slug="TNG-NO-IDENTITY", category=_CAT,
    description=(
        "An index entry carries no content_hash — identity verification is impossible."
    ),
    when=(
        "The resolver's identity gate (_fetch_and_build_named_candidate in resolver.py) "
        "finds IndexVersion.content_hash is empty or absent.  A content_hash is required "
        "before any fetch is attempted; absence is a malformed index entry.  "
        "The resolver MUST NOT attempt to fetch a named dep without a verifiable identity."
    ),
)

# ---------------------------------------------------------------------------
# Index data validation errors (trust-boundary sanitization)
# ---------------------------------------------------------------------------

BAD_VERSION = register(
    slug="TNG-BAD-VERSION", category=_CAT,
    description="An index version string is not a parseable X.Y.Z semver.",
    when=(
        "Reserved for a future strict-parse pass.  Currently unparseable "
        "version strings are silently skipped (forward-compat); this code "
        "will be raised when a strict mode is enabled."
    ),
)

BAD_COMMIT_SHA = register(
    slug="TNG-BAD-COMMIT-SHA", category=_CAT,
    description=(
        "A git provenance commit_sha is not a valid 40-character lowercase hex SHA1."
    ),
    when=(
        "_validate_commit_sha finds the commit_sha field does not match "
        "`^[0-9a-f]{40}$` — rejects abbreviated SHAs and flag-injection vectors."
    ),
)

BAD_OCI_DIGEST = register(
    slug="TNG-BAD-OCI-DIGEST", category=_CAT,
    description=(
        "An OCI provenance digest is not in `sha256:<64 lowercase hex>` format."
    ),
    when=(
        "_validate_oci_digest finds the digest field does not match "
        "`^sha256:[0-9a-f]{64}$` — rejects malformed oras pull references."
    ),
)

BAD_DEP_DECL = register(
    slug="TNG-BAD-DEP-DECL", category=_CAT,
    description=(
        "A `dep_decl` pointer in the index version-node is not in "
        "`sha256:<64 lowercase hex>` format."
    ),
    when=(
        "_validate_dep_decl_pointer finds the dep_decl field does not match "
        "`^sha256:[0-9a-f]{64}$` — rejects path-traversal payloads and other "
        "malformed pointers at the index-parse boundary (registry-protocol §3.2 "
        "NORMATIVE). Validated before the value can reach FileDepDeclStore "
        "(filesystem path) or HttpDepDeclStore (URL path segment)."
    ),
)

UNSAFE_REF = register(
    slug="TNG-UNSAFE-REF", category=_CAT,
    description="A git ref begins with `-` and would be interpreted as a CLI flag.",
    when=(
        "_validate_no_leading_dash finds a git ref value starting with `-` — "
        "flag-injection prevention at the index trust boundary."
    ),
)

UNSAFE_URL = register(
    slug="TNG-UNSAFE-URL", category=_CAT,
    description="A git URL begins with `-` and would be interpreted as a CLI flag.",
    when=(
        "_validate_no_leading_dash finds a git url value starting with `-` — "
        "flag-injection prevention at the index trust boundary."
    ),
)

UNSAFE_NAME = register(
    slug="TNG-UNSAFE-NAME", category=_CAT,
    description=(
        "A package name contains path-traversal characters and is unsafe "
        "as a filesystem path component under `_deps/`."
    ),
    when=(
        "_validate_safe_name finds the name contains `..`, `/`, `\\\\`, or "
        "is an absolute path — would escape the _deps/ sandbox if used as "
        "a directory name."
    ),
)

UNSAFE_OCI_FIELD = register(
    slug="TNG-UNSAFE-OCI-FIELD", category=_CAT,
    description=(
        "An OCI provenance field (registry or repository) begins with `-` "
        "and would be interpreted as a CLI flag."
    ),
    when=(
        "_validate_no_leading_dash finds an oci registry or repository value "
        "starting with `-` — flag-injection prevention for oras argv."
    ),
)

# ---------------------------------------------------------------------------
# DepDecl (Dependency Declaration) errors — spec/dep-decl.md §6
# Raise-site wiring lands in S3b (DepDeclEdgeSource + DepDeclStore).
# Registered here in S0 so the catalog is aware and spec/errors.md is
# generated correctly; TOMBSTONED in bijection tests until S3b.
# ---------------------------------------------------------------------------

DEPDECL_HASH_MISMATCH = register(
    slug="TNG-DEPDECL-HASH-MISMATCH", category=_CAT,
    description=(
        "`sha256(received_bytes)` does not equal the `dep_decl` pointer "
        "from the index version-node."
    ),
    when=(
        "`DepDeclStore.get` computes sha256 of the received artifact bytes "
        "and finds they do not match the expected hash.  The artifact is "
        "rejected; no data from it is consumed.  Defined in "
        "`spec/dep-decl.md §6`."
    ),
)

DEPDECL_FETCH_FAILED = register(
    slug="TNG-DEPDECL-FETCH-FAILED", category=_CAT,
    description=(
        "The DepDecl artifact is unreachable — network error or "
        "file-not-found in the dep-decl store."
    ),
    when=(
        "`DepDeclStore.get` cannot retrieve the artifact at the derived URL "
        "or `MILPA_DEP_DECL_DIR` path.  In the non-strict path the resolver "
        "falls through to the `.nimble` fallback with an "
        "`RES-UNATTESTED-METADATA` warning; with `--require-attested-metadata` "
        "this is a hard failure.  Defined in `spec/dep-decl.md §6`."
    ),
)

DEPDECL_PARSE_ERROR = register(
    slug="TNG-DEPDECL-PARSE-ERROR", category=_CAT,
    description=(
        "The DepDecl artifact bytes are not valid KDL 2.0, or the KDL "
        "structure does not conform to `spec/dep-decl.md §2`."
    ),
    when=(
        "The DepDecl parser finds invalid KDL syntax, a missing `dep_decl` "
        "top node, missing required child fields, or malformed entry nodes.  "
        "Defined in `spec/dep-decl.md §6`."
    ),
)

DEPDECL_SCHEMA_UNSUPPORTED = register(
    slug="TNG-DEPDECL-SCHEMA-UNSUPPORTED", category=_CAT,
    description=(
        "The DepDecl artifact declares a `dep_decl_schema_version` greater "
        "than the implementation's maximum understood version."
    ),
    when=(
        "The consumer's version-enforcement check (§4.3 of "
        "`spec/dep-decl.md`) finds "
        "`artifact.dep_decl_schema_version > MAX_DEP_DECL_SCHEMA_VERSION`.  "
        "The user must upgrade their milpa installation.  "
        "Defined in `spec/dep-decl.md §6`."
    ),
)

DEPDECL_SCHEMA_MISMATCH = register(
    slug="TNG-DEPDECL-SCHEMA-MISMATCH", category=_CAT,
    description=(
        "The DepDecl artifact's embedded `dep_decl_schema_version` does not "
        "match the `dep_decl_schema_version` field from the index "
        "version-node pointer."
    ),
    when=(
        "The schema consistency check (§5 of `spec/dep-decl.md`) finds the "
        "two version integers disagree — indicating a partially-applied index "
        "update.  Defined in `spec/dep-decl.md §6`."
    ),
)
