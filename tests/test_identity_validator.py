"""parse_identity validator tests (#34 multihash encoding).

The identity string format is `<algorithm>:<digest-hex>`. Today only
sha256 is supported; future migration will extend SUPPORTED_ALGORITHMS
with sha3 / blake3 / etc., each carrying its own digest-length check.

parse_identity is the single validator called at every boundary where
an identity string crosses into milpa — lockfile load, manifest load
(eventually), public API entry points. The intent: catch malformed or
unsupported-algorithm identity strings as early as possible, with
diagnostic error messages naming the specific failure mode.

See docs/rfc-content-addressed-identity.md §Hash algorithm agility.
"""

import pytest

from milpa.identity import (
    SUPPORTED_ALGORITHMS,
    IdentityError,
    parse_identity,
)


VALID_SHA256 = "sha256:" + "a" * 64


def test_parse_identity_accepts_sha256_canonical_form():
    """Tracer: sha256 with a 64-char hex digest is valid; returns
    the input unchanged as the canonical form."""
    assert parse_identity(VALID_SHA256) == VALID_SHA256
    # And sha256 IS in the supported algorithm set
    assert "sha256" in SUPPORTED_ALGORITHMS


def test_parse_identity_rejects_unknown_algorithm():
    """md5, sha1, etc. — anything not in SUPPORTED_ALGORITHMS is
    rejected with a message naming the offender."""
    with pytest.raises(IdentityError) as exc:
        parse_identity("md5:" + "a" * 32)
    msg = str(exc.value).lower()
    assert "md5" in msg
    assert "unsupported" in msg


def test_parse_identity_rejects_bare_hex_no_prefix():
    """Bare hex (no algorithm prefix) is rejected — the canonical
    form requires the algorithm to be explicit."""
    with pytest.raises(IdentityError) as exc:
        parse_identity("a" * 64)
    msg = str(exc.value).lower()
    assert "algorithm" in msg or "prefix" in msg


def test_parse_identity_rejects_wrong_length_digest():
    """sha256 digest must be exactly 64 hex chars."""
    with pytest.raises(IdentityError) as exc:
        parse_identity("sha256:abc123")
    msg = str(exc.value).lower()
    assert "64" in msg
    assert "sha256" in msg


def test_parse_identity_rejects_non_hex_characters_in_digest():
    """Digest must be lowercase hex (0-9, a-f). Uppercase or other
    characters are rejected."""
    bad = "sha256:" + "Z" * 64
    with pytest.raises(IdentityError) as exc:
        parse_identity(bad)
    msg = str(exc.value).lower()
    assert "hex" in msg
