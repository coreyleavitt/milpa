"""milpa error catalog — slug constants + MilpaError exception.

Every error slug milpa can produce is declared here as an importable named constant.
The constant name IS the slug with hyphens replaced by underscores (SCREAMING_SNAKE),
so a typo at a raise site produces a load-time NameError rather than a runtime
bijection miss.

``spec/errors.md`` is the spec-owned SSOT for the error catalog.  This module
bijection-checks against it: every slug constant here must appear in errors.md,
and every slug in errors.md must appear here.  The check is enforced by
``tests/test_errors.py``.

Bijection invariant (enforced by tests/test_errors.py):
    ALL_SLUGS == (spec/errors.md slugs)
"""

from __future__ import annotations

import re as _re
import sys as _sys
from typing import Any

# ---------------------------------------------------------------------------
# CAS — content-addressed store
# ---------------------------------------------------------------------------

CAS_IDENTITY_MISMATCH = "CAS-IDENTITY-MISMATCH"
CAS_NOT_IN_STORE = "CAS-NOT-IN-STORE"
STORE_AMBIGUOUS_PREFIX = "STORE-AMBIGUOUS-PREFIX"

# ---------------------------------------------------------------------------
# CLI — argument-validation errors (spec/errors.md §CLI)
# ---------------------------------------------------------------------------

CLI_FEATURE_FLAGS_CONFLICT = "CLI-FEATURE-FLAGS-CONFLICT"

# ---------------------------------------------------------------------------
# EXTRACT — safe tarball extraction
# ---------------------------------------------------------------------------

EXTRACT_SIZE_LIMIT = "EXTRACT-SIZE-LIMIT"
EXTRACT_SYMLINK_ESCAPE = "EXTRACT-SYMLINK-ESCAPE"
EXTRACT_ZIP_SLIP = "EXTRACT-ZIP-SLIP"

# ---------------------------------------------------------------------------
# FETCH — dep fetchers (git, tarball, local, OCI, mock)
# ---------------------------------------------------------------------------

FETCH_ALL_FAILED = "FETCH-ALL-FAILED"
FETCH_DOWNLOAD_FAILED = "FETCH-DOWNLOAD-FAILED"
FETCH_EXTRACT_FAILED = "FETCH-EXTRACT-FAILED"
FETCH_GIT_COMMIT_ABSENT = "FETCH-GIT-COMMIT-ABSENT"
FETCH_GIT_FAILED = "FETCH-GIT-FAILED"
FETCH_LOCAL_PATH_NOT_DIR = "FETCH-LOCAL-PATH-NOT-DIR"
FETCH_LOCAL_PATH_NOT_FOUND = "FETCH-LOCAL-PATH-NOT-FOUND"
FETCH_MOCK_MISSING = "FETCH-MOCK-MISSING"
FETCH_OCI_AMBIGUOUS_TARBALL = "FETCH-OCI-AMBIGUOUS-TARBALL"
FETCH_OCI_NO_TARBALL = "FETCH-OCI-NO-TARBALL"
FETCH_OCI_PULL_FAILED = "FETCH-OCI-PULL-FAILED"
FETCH_PROVENANCE_DIVERGENCE = "FETCH-PROVENANCE-DIVERGENCE"
FETCH_RECEIPT_EMPTY = "FETCH-RECEIPT-EMPTY"
FETCH_SHA256_MISMATCH = "FETCH-SHA256-MISMATCH"

FETCH_REF_DISCOVERY_FAILED = "FETCH-REF-DISCOVERY-FAILED"

# ---------------------------------------------------------------------------
# FROZEN — frozen fast-path (resolve_frozen / resolve_workspace_frozen / CLI guards)
# ---------------------------------------------------------------------------

FROZEN_ACTIVE_FLAGS_MISMATCH = "FROZEN-ACTIVE-FLAGS-MISMATCH"
FROZEN_CONSTRAINT_UNSATISFIED = "FROZEN-CONSTRAINT-UNSATISFIED"
FROZEN_IDENTITY_NOT_IN_STORE = "FROZEN-IDENTITY-NOT-IN-STORE"
FROZEN_LEGACY_REGISTRY_PROVENANCE = "FROZEN-LEGACY-REGISTRY-PROVENANCE"
FROZEN_LOCAL_DEP = "FROZEN-LOCAL-DEP"
FROZEN_LOCKED_VERSION_UNPARSEABLE = "FROZEN-LOCKED-VERSION-UNPARSEABLE"
FROZEN_MANIFEST_DEP_NOT_IN_LOCK = "FROZEN-MANIFEST-DEP-NOT-IN-LOCK"
FROZEN_MEMBER_DEP = "FROZEN-MEMBER-DEP"
FROZEN_MEMBER_IDENTITY_DRIFT = "FROZEN-MEMBER-IDENTITY-DRIFT"
FROZEN_MEMBER_NOT_IN_WORKSPACE = "FROZEN-MEMBER-NOT-IN-WORKSPACE"
FROZEN_NO_CAS = "FROZEN-NO-CAS"           # CLI-level guard (raised before resolve path)
FROZEN_NO_LOCKFILE = "FROZEN-NO-LOCKFILE"  # CLI-level guard (raised before resolve path)
FROZEN_STRATEGY_MISMATCH = "FROZEN-STRATEGY-MISMATCH"

# ---------------------------------------------------------------------------
# ID — content-hash identity
# ---------------------------------------------------------------------------

ID_NO_ALGORITHM_PREFIX = "ID-NO-ALGORITHM-PREFIX"
ID_NON_HEX_DIGEST = "ID-NON-HEX-DIGEST"
ID_NON_UTF8_RELPATH = "ID-NON-UTF8-RELPATH"
ID_NON_UTF8_SYMLINK_TARGET = "ID-NON-UTF8-SYMLINK-TARGET"
ID_NOT_A_STRING = "ID-NOT-A-STRING"
ID_UNSUPPORTED_ALGORITHM = "ID-UNSUPPORTED-ALGORITHM"
ID_WRONG_DIGEST_LENGTH = "ID-WRONG-DIGEST-LENGTH"

# ---------------------------------------------------------------------------
# INTERNAL — unexpected / unhandled failures
# ---------------------------------------------------------------------------

INTERNAL_PANIC = "INTERNAL-PANIC"    # Rust impl only: top-level panic handler
MILPA_INTERNAL = "MILPA-INTERNAL"    # catch-all sentinel; guarantees milpa-error: line

# ---------------------------------------------------------------------------
# LOCK — lockfile parse / verification
# ---------------------------------------------------------------------------

LOCK_DEP_FIELD_ARITY = "LOCK-DEP-FIELD-ARITY"
LOCK_DEP_IDENTITY_INVALID = "LOCK-DEP-IDENTITY-INVALID"
LOCK_DEP_NAME_ARITY = "LOCK-DEP-NAME-ARITY"
LOCK_DEP_NAME_INVALID = "LOCK-DEP-NAME-INVALID"
LOCK_DEP_NOT_FOUND = "LOCK-DEP-NOT-FOUND"
LOCK_FIELD_ARITY = "LOCK-FIELD-ARITY"
LOCK_FIELD_TYPE = "LOCK-FIELD-TYPE"
LOCK_FILE_NOT_FOUND = "LOCK-FILE-NOT-FOUND"
LOCK_FILE_UNREADABLE = "LOCK-FILE-UNREADABLE"
LOCK_GRAPH_MISMATCH = "LOCK-GRAPH-MISMATCH"
LOCK_KDL_SYNTAX = "LOCK-KDL-SYNTAX"
LOCK_PROV_FIELD_ARITY = "LOCK-PROV-FIELD-ARITY"
LOCK_PROV_FIELD_MISSING = "LOCK-PROV-FIELD-MISSING"
LOCK_PROV_KIND_MISSING = "LOCK-PROV-KIND-MISSING"
LOCK_PROV_KIND_UNKNOWN = "LOCK-PROV-KIND-UNKNOWN"
LOCK_SRC_DIR_UNSAFE = "LOCK-SRC-DIR-UNSAFE"
LOCK_VERSION_MISSING = "LOCK-VERSION-MISSING"
LOCK_VERSION_UNSUPPORTED = "LOCK-VERSION-UNSUPPORTED"

# ---------------------------------------------------------------------------
# MAN — manifest parse / mutation
# ---------------------------------------------------------------------------

MAN_ADD_DEP_EXISTS = "MAN-ADD-DEP-EXISTS"
MAN_CAS_DIR_MISSING = "MAN-CAS-DIR-MISSING"
MAN_CAS_DIR_TYPE = "MAN-CAS-DIR-TYPE"
MAN_DEP_DUPLICATE = "MAN-DEP-DUPLICATE"
MAN_DEP_FLAG_BOOL = "MAN-DEP-FLAG-BOOL"
MAN_DEP_OPTIONAL_FLAG_CLASH = "MAN-DEP-OPTIONAL-FLAG-CLASH"
MAN_DEP_OPTIONAL_INVALID_NAME = "MAN-DEP-OPTIONAL-INVALID-NAME"
MAN_DEP_FLAG_NAME_MISSING = "MAN-DEP-FLAG-NAME-MISSING"
MAN_DEP_FLAG_TOO_MANY_ARGS = "MAN-DEP-FLAG-TOO-MANY-ARGS"
MAN_DEP_LOCAL_PATH = "MAN-DEP-LOCAL-PATH"
MAN_DEP_MEMBER_ARITY = "MAN-DEP-MEMBER-ARITY"
MAN_DEP_MEMBER_PROPS = "MAN-DEP-MEMBER-PROPS"
MAN_DEP_MIRROR_ARITY = "MAN-DEP-MIRROR-ARITY"
MAN_DEP_NAME_INVALID = "MAN-DEP-NAME-INVALID"
MAN_DEP_NAMED_ARITY = "MAN-DEP-NAMED-ARITY"
MAN_DEP_NAMED_CONSTRAINT = "MAN-DEP-NAMED-CONSTRAINT"
MAN_DEP_NAMED_PROPS = "MAN-DEP-NAMED-PROPS"
MAN_DEP_REF_MISSING = "MAN-DEP-REF-MISSING"
MAN_DEP_TARBALL_SHA = "MAN-DEP-TARBALL-SHA"
MAN_DEP_TARBALL_STRIP = "MAN-DEP-TARBALL-STRIP"
MAN_DEP_TARBALL_URL = "MAN-DEP-TARBALL-URL"
MAN_DEP_UNKNOWN_CHILD = "MAN-DEP-UNKNOWN-CHILD"
MAN_DEP_UNKNOWN_PROPS = "MAN-DEP-UNKNOWN-PROPS"
MAN_FILE_NOT_FOUND = "MAN-FILE-NOT-FOUND"
MAN_FILE_UNREADABLE = "MAN-FILE-UNREADABLE"
MAN_FLAG_DEFAULT_TYPE = "MAN-FLAG-DEFAULT-TYPE"
MAN_FLAG_DEFINES_ARG_TYPE = "MAN-FLAG-DEFINES-ARG-TYPE"
MAN_FLAG_DEFINES_UNSAFE = "MAN-FLAG-DEFINES-UNSAFE"
MAN_FLAG_DESCRIPTION_TYPE = "MAN-FLAG-DESCRIPTION-TYPE"
MAN_FLAG_DUPLICATE = "MAN-FLAG-DUPLICATE"
MAN_FLAG_CONFLICTS_UNDECLARED = "MAN-FLAG-CONFLICTS-UNDECLARED"
MAN_FLAG_CONFLICTS_SELF = "MAN-FLAG-CONFLICTS-SELF"
MAN_FLAG_ENABLES_UNDECLARED = "MAN-FLAG-ENABLES-UNDECLARED"
MAN_FLAG_NAME_INVALID = "MAN-FLAG-NAME-INVALID"
MAN_FLAG_POS_ARGS = "MAN-FLAG-POS-ARGS"
MAN_FLAG_UNDECLARED_REFERENCE = "MAN-FLAG-UNDECLARED-REFERENCE"
MAN_FLAG_UNKNOWN_CHILD = "MAN-FLAG-UNKNOWN-CHILD"
MAN_FLAG_UNKNOWN_PROPS = "MAN-FLAG-UNKNOWN-PROPS"
MAN_GIT_URL_BAD_SCHEME = "MAN-GIT-URL-BAD-SCHEME"
MAN_GIT_URL_NO_SCHEME = "MAN-GIT-URL-NO-SCHEME"
MAN_KDL_SYNTAX = "MAN-KDL-SYNTAX"
MAN_KIND_ARITY = "MAN-KIND-ARITY"
MAN_KIND_INVALID = "MAN-KIND-INVALID"
MAN_MIRROR_EDITABLE_PROVENANCE = "MAN-MIRROR-EDITABLE-PROVENANCE"
MAN_MEMBER_WHEN_GATED = "MAN-MEMBER-WHEN-GATED"
MAN_MIRRORS_ARITY = "MAN-MIRRORS-ARITY"
MAN_MIRRORS_UNKNOWN_CHILD = "MAN-MIRRORS-UNKNOWN-CHILD"
MAN_MUTATE_FILE_NOT_FOUND = "MAN-MUTATE-FILE-NOT-FOUND"
MAN_MUTATE_NIMBLE_REFUSED = "MAN-MUTATE-NIMBLE-REFUSED"
MAN_MUTATE_WORKSPACE_REFUSED = "MAN-MUTATE-WORKSPACE-REFUSED"
MAN_NAME_DUPLICATE = "MAN-NAME-DUPLICATE"
MAN_NAME_MISSING = "MAN-NAME-MISSING"
MAN_NAME_TYPE = "MAN-NAME-TYPE"
MAN_NIMBLE_AMBIGUOUS = "MAN-NIMBLE-AMBIGUOUS"
MAN_NIMBLE_CONSTRAINT = "MAN-NIMBLE-CONSTRAINT"
MAN_NIMBLE_PARSE = "MAN-NIMBLE-PARSE"
MAN_NO_MANIFEST = "MAN-NO-MANIFEST"
MAN_OVERRIDE_ARITY = "MAN-OVERRIDE-ARITY"
MAN_OVERRIDE_DUPLICATE = "MAN-OVERRIDE-DUPLICATE"
MAN_OVERRIDE_GIT_MISSING = "MAN-OVERRIDE-GIT-MISSING"
MAN_OVERRIDE_KIND = "MAN-OVERRIDE-KIND"
MAN_OVERRIDE_REF_MISSING = "MAN-OVERRIDE-REF-MISSING"
MAN_OVERRIDE_TARGET_AMBIGUOUS = "MAN-OVERRIDE-TARGET-AMBIGUOUS"
MAN_OVERRIDE_UNKNOWN_PROPS = "MAN-OVERRIDE-UNKNOWN-PROPS"
MAN_PREDICATE_CHILD_ARG_TYPE = "MAN-PREDICATE-CHILD-ARG-TYPE"
MAN_PREDICATE_CHILD_NO_ARGS = "MAN-PREDICATE-CHILD-NO-ARGS"
MAN_PREDICATE_FORM_CONFLICT = "MAN-PREDICATE-FORM-CONFLICT"
MAN_PREDICATE_MIXED_NEGATION = "MAN-PREDICATE-MIXED-NEGATION"
MAN_PREDICATE_UNKNOWN = "MAN-PREDICATE-UNKNOWN"
MAN_PREDICATE_UNSUPPORTED_ANNOTATION = "MAN-PREDICATE-UNSUPPORTED-ANNOTATION"
MAN_PREDICATE_VALUE_TYPE = "MAN-PREDICATE-VALUE-TYPE"
MAN_REMOVE_DEP_ABSENT = "MAN-REMOVE-DEP-ABSENT"
MAN_SPEC_VERSION_TYPE = "MAN-SPEC-VERSION-TYPE"
MAN_SPEC_VERSION_UNSUPPORTED = "MAN-SPEC-VERSION-UNSUPPORTED"
MAN_SRC_DIR_TYPE = "MAN-SRC-DIR-TYPE"
MAN_SRC_DIR_UNSAFE = "MAN-SRC-DIR-UNSAFE"
MAN_UNKNOWN_TOP_LEVEL = "MAN-UNKNOWN-TOP-LEVEL"
MAN_URL_ARG_TYPE = "MAN-URL-ARG-TYPE"
MAN_WORKSPACE_HAS_DEPS_OR_KIND = "MAN-WORKSPACE-HAS-DEPS-OR-KIND"
MAN_WORKSPACE_IN_PACKAGE = "MAN-WORKSPACE-IN-PACKAGE"
MAN_WORKSPACE_MEMBER_ARITY = "MAN-WORKSPACE-MEMBER-ARITY"
MAN_WORKSPACE_MEMBER_DUPLICATE = "MAN-WORKSPACE-MEMBER-DUPLICATE"
MAN_WORKSPACE_UNKNOWN_NODE = "MAN-WORKSPACE-UNKNOWN-NODE"
MAN_WORKSPACE_UNKNOWN_TOP_LEVEL = "MAN-WORKSPACE-UNKNOWN-TOP-LEVEL"

# ---------------------------------------------------------------------------
# MILPA — top-level / index-cache
# ---------------------------------------------------------------------------

MILPA_INDEX_UNREACHABLE = "MILPA-INDEX-UNREACHABLE"

# ---------------------------------------------------------------------------
# NIMBLE — .nimble file I/O
# ---------------------------------------------------------------------------

NIMBLE_FILE_NOT_FOUND = "NIMBLE-FILE-NOT-FOUND"
NIMBLE_FILE_UNREADABLE = "NIMBLE-FILE-UNREADABLE"

# ---------------------------------------------------------------------------
# RES — resolver
# ---------------------------------------------------------------------------

RES_NO_INDEX = "RES-NO-INDEX"
RES_PROVENANCE_CONFLICT = "RES-PROVENANCE-CONFLICT"
RESOLVE_FLAG_CONFLICT = "RESOLVE-FLAG-CONFLICT"
RES_UNATTESTED_METADATA = "RES-UNATTESTED-METADATA"
RES_WS_MEMBER_REF_UNKNOWN = "RES-WS-MEMBER-REF-UNKNOWN"
RES_WS_NO_INDEX = "RES-WS-NO-INDEX"
RES_WS_OVERRIDE_MEMBER_COLLISION = "RES-WS-OVERRIDE-MEMBER-COLLISION"

# ---------------------------------------------------------------------------
# SOLVE — PubGrub solver
# ---------------------------------------------------------------------------

SOLVE_CONFLICT = "SOLVE-CONFLICT"

# ---------------------------------------------------------------------------
# TNG — tianguis index client
# ---------------------------------------------------------------------------

TNG_AMBIGUOUS_NAME = "TNG-AMBIGUOUS-NAME"
TNG_BAD_COMMIT_SHA = "TNG-BAD-COMMIT-SHA"
TNG_BAD_DEP_DECL = "TNG-BAD-DEP-DECL"
TNG_BAD_OCI_DIGEST = "TNG-BAD-OCI-DIGEST"
TNG_BAD_VERSION = "TNG-BAD-VERSION"
# TNG-DEPDECL-* codes (spec/dep-decl.md §6; raise sites are S3b)
TNG_DEPDECL_FETCH_FAILED = "TNG-DEPDECL-FETCH-FAILED"
TNG_DEPDECL_HASH_MISMATCH = "TNG-DEPDECL-HASH-MISMATCH"
TNG_DEPDECL_PARSE_ERROR = "TNG-DEPDECL-PARSE-ERROR"
TNG_DEPDECL_SCHEMA_MISMATCH = "TNG-DEPDECL-SCHEMA-MISMATCH"
TNG_DEPDECL_SCHEMA_UNSUPPORTED = "TNG-DEPDECL-SCHEMA-UNSUPPORTED"
TNG_KDL_SYNTAX = "TNG-KDL-SYNTAX"
TNG_NO_IDENTITY = "TNG-NO-IDENTITY"
TNG_NO_PROVENANCE = "TNG-NO-PROVENANCE"
TNG_NO_SATISFYING_VERSION = "TNG-NO-SATISFYING-VERSION"
TNG_NOT_FOUND = "TNG-NOT-FOUND"
TNG_SCHEMA_UNKNOWN = "TNG-SCHEMA-UNKNOWN"
TNG_UNSAFE_NAME = "TNG-UNSAFE-NAME"
TNG_UNSAFE_OCI_FIELD = "TNG-UNSAFE-OCI-FIELD"
TNG_UNSAFE_REF = "TNG-UNSAFE-REF"
TNG_UNSAFE_URL = "TNG-UNSAFE-URL"

# ---------------------------------------------------------------------------
# VERIFY — milpa verify
# ---------------------------------------------------------------------------

VERIFY_DEPS_DIR_MISSING = "VERIFY-DEPS-DIR-MISSING"
# S6: dep_decl graph-drift findings (§3.7 / spec/lockfile-schema.md §6.4)
VERIFY_EDGE_MISMATCH = "VERIFY-EDGE-MISMATCH"
LOCK_DEPDECL_PIN_MISSING = "LOCK-DEPDECL-PIN-MISSING"
# C-verify: symlink-state classification (RFC Phase C §6 item 6 + §6.4)
CAS_STORE_IO_ERROR = "CAS-STORE-IO-ERROR"
VERIFY_ALIAS_SYMLINK_MISSING = "VERIFY-ALIAS-SYMLINK-MISSING"

# ---------------------------------------------------------------------------
# WS — workspace
# ---------------------------------------------------------------------------

WS_MEMBER_DIR_MISSING = "WS-MEMBER-DIR-MISSING"
WS_MEMBER_DOT = "WS-MEMBER-DOT"
WS_MEMBER_DUPLICATE_NAME = "WS-MEMBER-DUPLICATE-NAME"
WS_MEMBER_HAS_OVERRIDES = "WS-MEMBER-HAS-OVERRIDES"
WS_MEMBER_IS_WORKSPACE = "WS-MEMBER-IS-WORKSPACE"
WS_MEMBER_NO_MANIFEST = "WS-MEMBER-NO-MANIFEST"
WS_NO_MANIFEST = "WS-NO-MANIFEST"
WS_NOT_A_WORKSPACE = "WS-NOT-A-WORKSPACE"


# ---------------------------------------------------------------------------
# Exported sets
# ---------------------------------------------------------------------------

#: Slugs defined in this module but not yet in spec/errors.md.
#: Empty post-swap (S11c): all codes are now in spec/errors.md.
PENDING_SPEC_INCLUSION: frozenset[str] = frozenset()

#: Complete set of all slug string values declared in this module.
#: Built by introspecting module globals so it stays in sync automatically.
_slug_re = _re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z][A-Z0-9]*)+$")
ALL_SLUGS: frozenset[str] = frozenset(
    val
    for name, val in vars(_sys.modules[__name__]).items()
    if not name.startswith("_") and isinstance(val, str) and _slug_re.match(val)
)


# ---------------------------------------------------------------------------
# MilpaError exception
# ---------------------------------------------------------------------------


class MilpaError(Exception):
    """Typed error carrying a conformance-stable slug, a human message, and structured context.

    Args:
        slug:    A slug constant from this module (e.g. ``MAN_KDL_SYNTAX``).
        message: Human-readable description; NOT byte-normative across implementations.
        **context: Arbitrary key/value structured context (path, dep name, etc.).

    The slug is the cross-implementation contract; the message and context are
    for human diagnostics only.

    Example::

        raise MilpaError(MAN_KDL_SYNTAX, "unexpected token at line 3", path="milpa.kdl")
    """

    slug: str
    message: str
    context: dict[str, Any]

    def __init__(self, slug: str, message: str, **context: Any) -> None:
        self.slug = slug
        self.message = message
        self.context = dict(context)
        super().__init__(f"milpa-error: {slug} — {message}")

    def __repr__(self) -> str:
        parts = [f"slug={self.slug!r}", f"message={self.message!r}"]
        if self.context:
            parts.append(f"context={self.context!r}")
        return f"MilpaError({', '.join(parts)})"
