"""IdentityError codes — errors the identity parser can produce.
Codes use the ``ID-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined.

Scope: all raises in parse_identity are user-facing (the function
validates lockfile-recorded identity strings that the user or another
tool wrote).
"""

from milpa.error_catalog import register


_CAT = "ID"

NOT_A_STRING = register(
    slug="ID-NOT-A-STRING", category=_CAT,
    description="Identity value is not a string.",
    when="parse_identity receives a non-str argument.",
)

NO_ALGORITHM_PREFIX = register(
    slug="ID-NO-ALGORITHM-PREFIX", category=_CAT,
    description=(
        "Identity string is missing the `<algorithm>:` prefix "
        "(expected `<algorithm>:<digest>` form)."
    ),
    when="parse_identity finds no `:` separator in the input string.",
)

UNSUPPORTED_ALGORITHM = register(
    slug="ID-UNSUPPORTED-ALGORITHM", category=_CAT,
    description="Identity string uses an algorithm milpa does not support.",
    when=(
        "parse_identity finds an algorithm prefix not in SUPPORTED_ALGORITHMS "
        "(currently only `sha256` is supported)."
    ),
)

WRONG_DIGEST_LENGTH = register(
    slug="ID-WRONG-DIGEST-LENGTH", category=_CAT,
    description="Digest component has the wrong number of hex characters.",
    when=(
        "parse_identity finds the digest length does not match the expected "
        "length for the algorithm (sha256 requires exactly 64 hex chars)."
    ),
)

NON_HEX_DIGEST = register(
    slug="ID-NON-HEX-DIGEST", category=_CAT,
    description="Digest component contains non-lowercase-hex characters.",
    when=(
        "parse_identity finds characters outside `0-9`, `a-f` in the digest."
    ),
)

NON_UTF8_SYMLINK_TARGET = register(
    slug="ID-NON-UTF8-SYMLINK-TARGET", category=_CAT,
    description=(
        "A symlink in the source tree points to a target that is not valid "
        "UTF-8, so it cannot be encoded into the content-hash algorithm."
    ),
    when=(
        "compute_content_hash encounters a symlink whose os.readlink target "
        "fails to re-encode as UTF-8 (surrogate-escaped bytes on POSIX)."
    ),
)
