"""CASError codes — errors the content-addressed store can produce.
Codes use the ``CAS-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined.

Scope: user-facing conditions — conditions reachable because the user's
environment (CAS state, identity mismatch from tampered bytes) is wrong.

Intentionally UNCATALOGUED:
  - OSError/IOError from CAStore.admit rename() — genuine OS-level
    storage failure; the non-race-loss branch re-raises the raw OSError,
    which is not a user-input condition and not catalogued.
"""

from milpa.error_catalog import register


_CAT = "CAS"

IDENTITY_MISMATCH = register(
    slug="CAS-IDENTITY-MISMATCH", category=_CAT,
    description=(
        "Source tree bytes do not hash to the claimed identity string."
    ),
    when=(
        "CAStore.admit computes content_hash of src and finds it differs "
        "from the identity argument — possible tamper or corruption."
    ),
)

NOT_IN_STORE = register(
    slug="CAS-NOT-IN-STORE", category=_CAT,
    description="The requested identity is not present in the CAS.",
    when=(
        "CAStore.link is called for an identity that has no entry under "
        "<root>/<algorithm>/<hex>/."
    ),
)
