"""Tests for milpa.registry — S8a.

Covers:
  - ``parse_index`` with a valid full-featured ``index.kdl`` document.
  - Each ``TNG-*`` security validator slug (§4 NORMATIVE).
  - Named-dep resolution contract: ``resolve_named`` / ``resolve_named_all``.
  - Property tests on the security validators (valid inputs pass; malformed
    inputs raise the precise slug).
  - Forward-compat: unknown provenance kinds skipped, duplicate versions warn.
  - Schema-version negotiation (TNG-SCHEMA-UNKNOWN).
  - Sorting: parseable versions descend, unparseable trailing.

No network access; all inputs are inline KDL strings or conformance fixtures.
"""

from __future__ import annotations

import warnings
from datetime import datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from milpa.errors import (
    TNG_AMBIGUOUS_NAME,
    TNG_BAD_COMMIT_SHA,
    TNG_BAD_DEP_DECL,
    TNG_BAD_OCI_DIGEST,
    TNG_KDL_SYNTAX,
    TNG_NO_PROVENANCE,
    TNG_NO_SATISFYING_VERSION,
    TNG_NOT_FOUND,
    TNG_SCHEMA_UNKNOWN,
    TNG_UNSAFE_NAME,
    TNG_UNSAFE_OCI_FIELD,
    TNG_UNSAFE_REF,
    TNG_UNSAFE_URL,
    MilpaError,
)
from milpa.registry import (
    TIANGUIS_INDEX_SCHEMA_VERSION,
    AmbiguousName,
    AuthorSigned,
    GitIndexProvenance,
    Index,
    MilpaVendored,
    OciIndexProvenance,
    Package,
    _validate_commit_sha,
    _validate_dep_decl_pointer,
    _validate_no_leading_dash,
    _validate_oci_digest,
    _validate_safe_name,
    is_safe_name,
    parse_index,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CONFORMANCE = Path(__file__).parents[3] / "conformance" / "spec-v1"


def _fixture_index(name: str) -> str:
    """Read an index.kdl from the conformance corpus."""
    return (CONFORMANCE / name / "index.kdl").read_text()


# A minimal valid index.kdl for use as a baseline.
MINIMAL_INDEX = """\
schema_version 1

package "nimkdl" {
    namespace "coreyleavitt"
    upstream (url)"https://github.com/coreyleavitt/nimkdl"
    version "0.1.4" {
        content_hash "dag-sha256:1aaf2a95f53681c86f6dcd4c1267144401ba923f31afa42da3c5ae783dc7ab61"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "coreyleavitt/nimkdl"
            digest "sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24"
        }
        attestation "author-signed"
        signed_by "https://github.com/coreyleavitt/tianguis/.github/workflows/publish.yaml"
        published_at "2026-05-26T04:49:44Z"
        rekor {
            uuid "108e9186e8c5677abce5a62d285437741218f878474a02d9a4dac01dc12e39b979336e712890d636"
            log_index "1753541583"
            integrated_time "1780881469"
        }
    }
}

package "chronos" {
    namespace "status-im"
    upstream (url)"https://github.com/status-im/nim-chronos"
    version "4.0.3" {
        content_hash "dag-sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
        provenance {
            kind "git"
            url (url)"https://github.com/status-im/nim-chronos"
            ref "HEAD"
            commit_sha "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        }
        attestation "milpa-vendored"
    }
}
"""


# ---------------------------------------------------------------------------
# 1. parse_index — happy path
# ---------------------------------------------------------------------------


class TestParseIndexValid:
    def test_parses_two_packages(self) -> None:
        idx = parse_index(MINIMAL_INDEX)
        assert len(idx.packages) == 2

    def test_package_names_and_namespaces(self) -> None:
        idx = parse_index(MINIMAL_INDEX)
        names = {p.name: p.namespace for p in idx.packages}
        assert names["nimkdl"] == "coreyleavitt"
        assert names["chronos"] == "status-im"

    def test_oci_provenance_parsed(self) -> None:
        idx = parse_index(MINIMAL_INDEX)
        nimkdl = next(p for p in idx.packages if p.name == "nimkdl")
        assert len(nimkdl.versions) == 1
        iv = nimkdl.versions[0]
        assert iv.version == "0.1.4"
        assert iv.content_hash.startswith("dag-sha256:")
        assert len(iv.provenances) == 1
        prov = iv.provenances[0]
        assert isinstance(prov, OciIndexProvenance)
        assert prov.registry == "ghcr.io"
        assert prov.repository == "coreyleavitt/nimkdl"

    def test_git_provenance_parsed(self) -> None:
        idx = parse_index(MINIMAL_INDEX)
        chronos = next(p for p in idx.packages if p.name == "chronos")
        iv = chronos.versions[0]
        assert len(iv.provenances) == 1
        prov = iv.provenances[0]
        assert isinstance(prov, GitIndexProvenance)
        assert prov.url == "https://github.com/status-im/nim-chronos"
        assert prov.ref == "HEAD"
        assert prov.commit_sha == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

    def test_rekor_block_folds_into_attestation(self) -> None:
        """rekor folds into EntryAttestation.rekor when attestation is present.

        Inverts the prior tolerate-and-ignore behavior: registry-protocol.md
        §3.2 now parses `attestation`/`signed_by`/`rekor` into a typed
        `EntryAttestation` record instead of discarding them (RFC
        per-entry-attestation.md P2 slice).
        """
        idx = parse_index(MINIMAL_INDEX)
        nimkdl = next(p for p in idx.packages if p.name == "nimkdl")
        iv = nimkdl.versions[0]
        assert iv.attestation is not None
        assert isinstance(iv.attestation.kind, AuthorSigned)
        assert iv.attestation.kind.signer == (
            "https://github.com/coreyleavitt/tianguis/.github/workflows/publish.yaml"
        )
        assert iv.attestation.rekor is not None
        assert iv.attestation.rekor.uuid == (
            "108e9186e8c5677abce5a62d285437741218f878474a02d9a4dac01dc12e39b979336e712890d636"
        )
        assert iv.attestation.rekor.log_index == "1753541583"
        assert iv.attestation.rekor.integrated_time == "1780881469"
        assert iv.attestation.bundle_pin is None

    def test_rekor_without_attestation_is_tolerated_and_ignored(self) -> None:
        """A lone `rekor` block with no `attestation` kind is still forward-compat
        ignored — there is no kind to tag it with (registry-protocol §3.2 NORMATIVE)."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
        rekor {
            uuid "abc"
            log_index "1"
            integrated_time "2"
        }
    }
}
"""
        idx = parse_index(text)
        iv = idx.packages[0].versions[0]
        assert iv.attestation is None

    def test_milpa_vendored_has_no_signer(self) -> None:
        idx = parse_index(MINIMAL_INDEX)
        chronos = next(p for p in idx.packages if p.name == "chronos")
        iv = chronos.versions[0]
        assert iv.attestation is not None
        assert isinstance(iv.attestation.kind, MilpaVendored)
        assert iv.attestation.rekor is None
        assert iv.attestation.bundle_pin is None

    def test_unrecognized_attestation_kind_collapses_to_unattested(self) -> None:
        """Closed kind set (registry-protocol §3.2 NORMATIVE): an unrecognized
        `attestation` value MUST collapse to None with an observable diagnostic."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
        attestation "bogus-kind"
    }
}
"""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            idx = parse_index(text)
        iv = idx.packages[0].versions[0]
        assert iv.attestation is None
        messages = [str(w.message) for w in caught]
        assert any("bogus-kind" in m and "foo" in m for m in messages)

    def test_author_signed_missing_signed_by_collapses_to_unattested(self) -> None:
        """`author-signed` with no sibling `signed_by` is structurally invalid —
        MUST collapse to None with an observable diagnostic (registry-protocol §3.2)."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
        attestation "author-signed"
    }
}
"""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            idx = parse_index(text)
        iv = idx.packages[0].versions[0]
        assert iv.attestation is None
        messages = [str(w.message) for w in caught]
        assert any("author-signed" in m and "foo" in m for m in messages)

    def test_bundle_pin_captured_when_valid(self) -> None:
        hex64 = "a" * 64
        text = f"""\
schema_version 1
package "foo" {{
    version "1.0.0" {{
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {{
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }}
        attestation "author-signed"
        signed_by "https://example.com/workflow.yaml"
        bundle sha256="{hex64}"
    }}
}}
"""
        idx = parse_index(text)
        iv = idx.packages[0].versions[0]
        assert iv.attestation is not None
        assert iv.attestation.bundle_pin == hex64

    def test_malformed_bundle_pin_drops_pin_without_collapsing_kind(self) -> None:
        """A malformed `bundle sha256=` value normalizes ONLY bundle_pin to None
        — it MUST NOT collapse an otherwise well-formed kind/signer pairing
        (registry-protocol §3.2 NORMATIVE)."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
        attestation "author-signed"
        signed_by "https://example.com/workflow.yaml"
        bundle sha256="not-valid-hex"
    }
}
"""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            idx = parse_index(text)
        iv = idx.packages[0].versions[0]
        assert iv.attestation is not None
        assert isinstance(iv.attestation.kind, AuthorSigned)
        assert iv.attestation.bundle_pin is None
        messages = [str(w.message) for w in caught]
        assert any("bundle" in m and "not-valid-hex" in m for m in messages)

    def test_no_attestation_node_is_unattested(self) -> None:
        """A legacy entry with none of the four sibling nodes parses as unattested,
        with no diagnostic (absence is not a collapse — registry-protocol §3.2)."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
    }
}
"""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            idx = parse_index(text)
        iv = idx.packages[0].versions[0]
        assert iv.attestation is None
        assert len(caught) == 0

    def test_url_annotated_form_accepted(self) -> None:
        """(url)-annotated URL values must be accepted (registry-protocol §3.3 NORMATIVE)."""
        idx = parse_index(MINIMAL_INDEX)
        chronos = next(p for p in idx.packages if p.name == "chronos")
        prov = chronos.versions[0].provenances[0]
        assert isinstance(prov, GitIndexProvenance)
        assert prov.url == "https://github.com/status-im/nim-chronos"

    def test_absent_schema_version_tolerated(self) -> None:
        """Missing schema_version node is valid (legacy indexes predate the field)."""
        no_sv = """\
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
    }
}
"""
        idx = parse_index(no_sv)
        assert len(idx.packages) == 1

    def test_unknown_top_level_node_skipped(self) -> None:
        """Unknown top-level nodes are silently skipped (forward-compat §1)."""
        text = "schema_version 1\nfuture_thing \"x\"\n"
        idx = parse_index(text)
        assert len(idx.packages) == 0

    def test_unknown_provenance_kind_skipped(self) -> None:
        """Unknown provenance kind silently skipped (registry-protocol §3.3 NORMATIVE)."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "future-transport"
            url "https://example.com/foo"
        }
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
    }
}
"""
        idx = parse_index(text)
        foo = idx.packages[0]
        assert len(foo.versions[0].provenances) == 1
        assert isinstance(foo.versions[0].provenances[0], GitIndexProvenance)

    def test_version_sorted_newest_first(self) -> None:
        """Parseable versions must be sorted descending by semver."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance { kind "git" url "https://example.com/foo.git" ref "v1" }
    }
    version "3.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000003"
        provenance { kind "git" url "https://example.com/foo.git" ref "v3" }
    }
    version "2.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000002"
        provenance { kind "git" url "https://example.com/foo.git" ref "v2" }
    }
}
"""
        idx = parse_index(text)
        vers = [iv.version for iv in idx.packages[0].versions]
        assert vers == ["3.0.0", "2.0.0", "1.0.0"]

    def test_unparseable_version_trailing(self) -> None:
        """Unparseable version strings come after parseable ones (§5.2 NORMATIVE)."""
        text = """\
schema_version 1
package "foo" {
    version "not-semver" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000099"
        provenance { kind "git" url "https://example.com/foo.git" ref "main" }
    }
    version "2.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000002"
        provenance { kind "git" url "https://example.com/foo.git" ref "v2" }
    }
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance { kind "git" url "https://example.com/foo.git" ref "v1" }
    }
}
"""
        idx = parse_index(text)
        vers = [iv.version for iv in idx.packages[0].versions]
        assert vers[:2] == ["2.0.0", "1.0.0"]
        assert vers[2] == "not-semver"

    def test_duplicate_version_warns_and_keeps_first(self) -> None:
        """Duplicate version string: first wins; subsequent skip with UserWarning."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance { kind "git" url "https://example.com/foo.git" ref "v1" }
    }
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000002"
        provenance { kind "git" url "https://example.com/foo.git" ref "dup" }
    }
}
"""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            idx = parse_index(text)
        assert len(idx.packages[0].versions) == 1
        assert idx.packages[0].versions[0].content_hash.endswith("01")
        assert any("duplicate" in str(w.message).lower() for w in caught)

    def test_non_string_package_name_warns_and_skips(self) -> None:
        """Non-string (or missing) package name: UserWarning + skip (NOT hard error)."""
        text = "schema_version 1\npackage 42 {}\n"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            idx = parse_index(text)
        assert len(idx.packages) == 0
        assert any(
            "non-string" in str(w.message).lower() or "skipped" in str(w.message).lower()
            for w in caught
        )

    def test_commit_sha_absent_is_ok(self) -> None:
        """commit_sha is optional; absent is valid (fetcher falls back to ref tip)."""
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
    }
}
"""
        idx = parse_index(text)
        prov = idx.packages[0].versions[0].provenances[0]
        assert isinstance(prov, GitIndexProvenance)
        assert prov.commit_sha is None

    def test_conformance_fixture_valid_full(self) -> None:
        """Parse the canonical-selection conformance fixture (many packages, OCI + git)."""
        text = _fixture_index("fixture-063-canonical-selection")
        idx = parse_index(text)
        assert len(idx.packages) == 3
        names = {p.name for p in idx.packages}
        assert names == {"X", "Y", "Z"}


# ---------------------------------------------------------------------------
# 2. Schema-version negotiation
# ---------------------------------------------------------------------------


class TestSchemaVersion:
    def test_schema_version_exceeds_max_raises(self) -> None:
        """schema_version > TIANGUIS_INDEX_SCHEMA_VERSION → TNG-SCHEMA-UNKNOWN."""
        text = _fixture_index("fixture-087-tng-schema-unknown")
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_SCHEMA_UNKNOWN

    def test_schema_version_equal_ok(self) -> None:
        text = f"schema_version {TIANGUIS_INDEX_SCHEMA_VERSION}\n"
        idx = parse_index(text)
        assert idx.packages == []

    def test_schema_version_lower_ok(self) -> None:
        """schema_version < max is accepted forward-compatibly."""
        if TIANGUIS_INDEX_SCHEMA_VERSION > 1:
            text = f"schema_version {TIANGUIS_INDEX_SCHEMA_VERSION - 1}\n"
            idx = parse_index(text)
            assert idx.packages == []

    def test_kdl_syntax_error_raises_tng_slug(self) -> None:
        """Invalid KDL text raises MilpaError with TNG-KDL-SYNTAX."""
        with pytest.raises(MilpaError) as exc_info:
            parse_index("{ unclosed")
        assert exc_info.value.slug == TNG_KDL_SYNTAX


# ---------------------------------------------------------------------------
# 3. Security validators — unit tests (§4 NORMATIVE)
# ---------------------------------------------------------------------------


class TestValidators:
    # TNG-UNSAFE-NAME
    def test_unsafe_name_dotdot(self) -> None:
        text = _fixture_index("fixture-097-tng-unsafe-name")
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_UNSAFE_NAME

    def test_unsafe_name_slash(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            _validate_safe_name("foo/bar")
        assert exc_info.value.slug == TNG_UNSAFE_NAME

    def test_safe_name_passes(self) -> None:
        _validate_safe_name("valid-name")  # must not raise

    # TNG-BAD-COMMIT-SHA
    def test_bad_commit_sha_raises(self) -> None:
        text = _fixture_index("fixture-093-tng-bad-commit-sha")
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_BAD_COMMIT_SHA

    def test_bad_commit_sha_uppercase(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            _validate_commit_sha("A" * 40)
        assert exc_info.value.slug == TNG_BAD_COMMIT_SHA

    def test_bad_commit_sha_short(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            _validate_commit_sha("abc123")
        assert exc_info.value.slug == TNG_BAD_COMMIT_SHA

    def test_valid_commit_sha_passes(self) -> None:
        _validate_commit_sha("a" * 40)  # must not raise

    # TNG-UNSAFE-URL
    def test_unsafe_url_leading_dash(self) -> None:
        text = _fixture_index("fixture-096-tng-unsafe-url")
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_UNSAFE_URL

    def test_unsafe_url_via_validator(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            _validate_no_leading_dash("--upload-pack=evil", "git url", TNG_UNSAFE_URL)
        assert exc_info.value.slug == TNG_UNSAFE_URL

    def test_safe_url_passes(self) -> None:
        _validate_no_leading_dash("https://example.com/repo.git", "git url", TNG_UNSAFE_URL)

    # TNG-UNSAFE-REF
    def test_unsafe_ref_leading_dash(self) -> None:
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "-bad-ref"
        }
    }
}
"""
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_UNSAFE_REF

    def test_unsafe_ref_via_validator(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            _validate_no_leading_dash("-f", "git ref", TNG_UNSAFE_REF)
        assert exc_info.value.slug == TNG_UNSAFE_REF

    # TNG-BAD-OCI-DIGEST
    def test_bad_oci_digest_malformed(self) -> None:
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "example/foo"
            digest "not-a-digest"
        }
    }
}
"""
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_BAD_OCI_DIGEST

    def test_bad_oci_digest_via_validator(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            _validate_oci_digest("sha256:tooshort")
        assert exc_info.value.slug == TNG_BAD_OCI_DIGEST

    def test_valid_oci_digest_passes(self) -> None:
        _validate_oci_digest("sha256:" + "a" * 64)

    # TNG-BAD-DEP-DECL
    def test_bad_dep_decl_path_traversal(self) -> None:
        """A dep_decl path-traversal payload is rejected at parse time (R5 fix)."""
        text = """\
schema_version 1
package "bar" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        dep_decl "sha256:../../etc/passwd"
        dep_decl_schema_version 0
        provenance {
            kind "git"
            url "https://github.com/example/bar.git"
            ref "v1.0.0"
            commit_sha "cafef00dcafef00dcafef00dcafef00dcafef00d"
        }
    }
}
"""
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_BAD_DEP_DECL

    def test_bad_dep_decl_uppercase_hex(self) -> None:
        """Uppercase hex in dep_decl is rejected (pointer MUST be lowercase)."""
        pointer = "sha256:" + "A" * 64
        with pytest.raises(MilpaError) as exc_info:
            _validate_dep_decl_pointer(pointer)
        assert exc_info.value.slug == TNG_BAD_DEP_DECL

    def test_bad_dep_decl_too_short(self) -> None:
        """A dep_decl with fewer than 64 hex chars is rejected."""
        with pytest.raises(MilpaError) as exc_info:
            _validate_dep_decl_pointer("sha256:abc123")
        assert exc_info.value.slug == TNG_BAD_DEP_DECL

    def test_bad_dep_decl_wrong_prefix(self) -> None:
        """A dep_decl with wrong algorithm prefix is rejected."""
        with pytest.raises(MilpaError) as exc_info:
            _validate_dep_decl_pointer("md5:" + "a" * 32)
        assert exc_info.value.slug == TNG_BAD_DEP_DECL

    def test_bad_dep_decl_conformance_fixture(self) -> None:
        """Conformance fixture-149: path-traversal dep_decl rejected as TNG-BAD-DEP-DECL."""
        text = _fixture_index("fixture-149-tng-bad-dep-decl")
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_BAD_DEP_DECL

    def test_valid_dep_decl_passes(self) -> None:
        """A well-formed dep_decl pointer does not raise."""
        _validate_dep_decl_pointer("sha256:" + "a" * 64)  # must not raise

    def test_oci_digest_and_dep_decl_share_format_but_raise_distinct_codes(self) -> None:
        """Both validators reject/accept identical strings but raise distinct error codes.

        This asserts the SSOT invariant: _RE_SHA256_DIGEST is the shared
        predicate; _validate_oci_digest raises TNG-BAD-OCI-DIGEST and
        _validate_dep_decl_pointer raises TNG-BAD-DEP-DECL for the same bad input.
        """
        valid = "sha256:" + "a" * 64
        # Both accept a valid sha256 pointer.
        _validate_oci_digest(valid)         # must not raise
        _validate_dep_decl_pointer(valid)   # must not raise

        bad = "sha256:tooshort"
        # Both reject the same bad string, but with their own distinct error code.
        with pytest.raises(MilpaError) as exc_oci:
            _validate_oci_digest(bad)
        with pytest.raises(MilpaError) as exc_dep:
            _validate_dep_decl_pointer(bad)
        assert exc_oci.value.slug == TNG_BAD_OCI_DIGEST
        assert exc_dep.value.slug == TNG_BAD_DEP_DECL
        assert exc_oci.value.slug != exc_dep.value.slug  # codes are distinct

    # TNG-UNSAFE-OCI-FIELD
    def test_unsafe_oci_field_registry(self) -> None:
        text = _fixture_index("fixture-098-tng-unsafe-oci-field")
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD

    def test_unsafe_oci_field_repository(self) -> None:
        text = """\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "-bad/repo"
            digest "sha256:0000000000000000000000000000000000000000000000000000000000000001"
        }
    }
}
"""
        with pytest.raises(MilpaError) as exc_info:
            parse_index(text)
        assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD


# ---------------------------------------------------------------------------
# 4. Bare-name lookup
# ---------------------------------------------------------------------------


class TestLookupBare:
    def test_found(self) -> None:
        idx = parse_index(MINIMAL_INDEX)
        result = idx.lookup_bare("nimkdl")
        assert isinstance(result, Package)
        assert result.name == "nimkdl"

    def test_not_found(self) -> None:
        idx = parse_index(MINIMAL_INDEX)
        assert idx.lookup_bare("no-such-package") is None

    def test_ambiguous(self) -> None:
        text = _fixture_index("fixture-089-tng-ambiguous-name")
        idx = parse_index(text)
        result = idx.lookup_bare("bar")
        assert isinstance(result, AmbiguousName)
        assert set(result.namespaces) == {"ns1", "ns2"}


# ---------------------------------------------------------------------------
# 5. resolve_named / resolve_named_all
# ---------------------------------------------------------------------------


class TestResolveNamed:
    def _idx_with_bar(self) -> Index:
        text = """\
schema_version 1
package "bar" {
    version "2.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000002"
        provenance { kind "git" url "https://example.com/bar.git" ref "v2" }
    }
    version "1.0.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance { kind "git" url "https://example.com/bar.git" ref "v1" }
    }
}
"""
        return parse_index(text)

    def test_resolve_named_returns_highest(self) -> None:
        idx = self._idx_with_bar()
        iv = idx.resolve_named("bar", None)
        assert iv.version == "2.0.0"

    def test_resolve_named_all_returns_all(self) -> None:
        idx = self._idx_with_bar()
        results = idx.resolve_named_all("bar", None)
        assert [iv.version for iv in results] == ["2.0.0", "1.0.0"]

    def test_resolve_named_with_constraint(self) -> None:
        idx = self._idx_with_bar()
        iv = idx.resolve_named("bar", ">=2.0.0")
        assert iv.version == "2.0.0"

    def test_tng_not_found(self) -> None:
        idx = self._idx_with_bar()
        with pytest.raises(MilpaError) as exc_info:
            idx.resolve_named("no-such", None)
        assert exc_info.value.slug == TNG_NOT_FOUND

    def test_tng_not_found_conformance(self) -> None:
        """Conformance fixture for TNG-NOT-FOUND."""
        text = _fixture_index("fixture-090-solve-conflict-index-no-version")  # reuse: just a present pkg
        idx = parse_index(text)
        with pytest.raises(MilpaError) as exc_info:
            idx.resolve_named("nonexistent", None)
        assert exc_info.value.slug == TNG_NOT_FOUND

    def test_tng_ambiguous_name(self) -> None:
        text = _fixture_index("fixture-089-tng-ambiguous-name")
        idx = parse_index(text)
        with pytest.raises(MilpaError) as exc_info:
            idx.resolve_named("bar", None)
        assert exc_info.value.slug == TNG_AMBIGUOUS_NAME

    def test_tng_no_satisfying_version(self) -> None:
        text = _fixture_index("fixture-090-solve-conflict-index-no-version")
        idx = parse_index(text)
        with pytest.raises(MilpaError) as exc_info:
            idx.resolve_named("bar", ">=9.0.0")
        assert exc_info.value.slug == TNG_NO_SATISFYING_VERSION

    def test_tng_no_provenance(self) -> None:
        text = _fixture_index("fixture-091-tng-no-provenance")
        idx = parse_index(text)
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            with pytest.raises(MilpaError) as exc_info:
                idx.resolve_named("bar", None)
        assert exc_info.value.slug == TNG_NO_PROVENANCE

    def test_resolve_none_constraint_means_any(self) -> None:
        """None constraint selects all parseable versions (§5.2 NORMATIVE)."""
        idx = self._idx_with_bar()
        results = idx.resolve_named_all("bar", None)
        assert len(results) == 2

    def test_no_identity_stored_but_not_raised_here(self) -> None:
        """TNG-NO-IDENTITY is NOT raised at the enumeration step — only at selection."""
        text = _fixture_index("fixture-092-tng-no-identity")
        idx = parse_index(text)
        # resolve_named_all succeeds (empty content_hash stored as "")
        results = idx.resolve_named_all("bar", None)
        assert len(results) == 1
        assert results[0].content_hash == ""


# ---------------------------------------------------------------------------
# 6. is_safe_name — property tests
# ---------------------------------------------------------------------------


class TestIsSafeName:
    # Boundary examples
    def test_safe_normal_names(self) -> None:
        for name in ["foo", "bar-baz", "pkg123", "nim-chronos", "a", "A_B"]:
            assert is_safe_name(name), f"{name!r} should be safe"

    def test_unsafe_dotdot(self) -> None:
        assert not is_safe_name(".."), ".."
        assert not is_safe_name("a/../b"), "a/../b"

    def test_unsafe_slash(self) -> None:
        assert not is_safe_name("a/b")
        assert not is_safe_name("/absolute")

    def test_unsafe_backslash(self) -> None:
        assert not is_safe_name(r"a\b")

    def test_unsafe_absolute_unix(self) -> None:
        assert not is_safe_name("/etc/passwd")


# Property tests on is_safe_name

_SAFE_NAME_ALPHABET = st.characters(
    whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"
)


@given(st.text(alphabet=_SAFE_NAME_ALPHABET, min_size=1, max_size=30))
@settings(max_examples=200)
def test_alnum_names_are_safe(name: str) -> None:
    """Pure alphanum/dash/underscore names with no / or .. are always safe."""
    assert is_safe_name(name)


@given(st.text(min_size=1, max_size=50))
@settings(max_examples=200)
def test_names_with_slash_are_unsafe(name: str) -> None:
    """Any name containing '/' is unsafe."""
    name_with_slash = name + "/" + name
    assert not is_safe_name(name_with_slash)


# ---------------------------------------------------------------------------
# 7. Commit-SHA validator — property tests
# ---------------------------------------------------------------------------


@given(st.from_regex(r"^[0-9a-f]{40}$", fullmatch=True))
@settings(max_examples=200)
def test_valid_commit_sha_never_raises(sha: str) -> None:
    _validate_commit_sha(sha)  # must not raise


@given(
    st.one_of(
        st.text(alphabet="0123456789abcdef", min_size=1, max_size=39),  # too short
        st.text(alphabet="0123456789abcdef", min_size=41),  # too long
        # Force at least one uppercase letter (guaranteed invalid since spec requires lowercase).
        st.builds(
            lambda base, pos, up: base[:pos] + up + base[pos + 1:],
            base=st.text(alphabet="0123456789abcdef", min_size=40, max_size=40),
            pos=st.integers(min_value=0, max_value=39),
            up=st.sampled_from("ABCDEF"),
        ),
    )
)
@settings(max_examples=200)
def test_invalid_commit_sha_always_raises(sha: str) -> None:
    with pytest.raises(MilpaError) as exc_info:
        _validate_commit_sha(sha)
    assert exc_info.value.slug == TNG_BAD_COMMIT_SHA


# ---------------------------------------------------------------------------
# 8. OCI digest validator — property tests
# ---------------------------------------------------------------------------


@given(st.from_regex(r"^sha256:[0-9a-f]{64}$", fullmatch=True))
@settings(max_examples=200)
def test_valid_oci_digest_never_raises(digest: str) -> None:
    _validate_oci_digest(digest)  # must not raise


@given(
    st.one_of(
        st.text(min_size=1, max_size=20),  # arbitrary short garbage
        st.just("sha256:" + "a" * 63),  # one hex char short
        st.just("sha256:" + "a" * 65),  # one hex char too many
        st.just("sha256:" + "A" * 64),  # uppercase
        st.just("md5:" + "a" * 32),  # wrong algorithm
    )
)
@settings(max_examples=200)
def test_invalid_oci_digest_always_raises(digest: str) -> None:
    with pytest.raises(MilpaError) as exc_info:
        _validate_oci_digest(digest)
    assert exc_info.value.slug == TNG_BAD_OCI_DIGEST


# ---------------------------------------------------------------------------
# 9. No-leading-dash validator — property tests
# ---------------------------------------------------------------------------


@given(st.text(min_size=1).filter(lambda s: not s.startswith("-")))
@settings(max_examples=200)
def test_no_leading_dash_passes_when_safe(val: str) -> None:
    _validate_no_leading_dash(val, "field", TNG_UNSAFE_URL)  # must not raise


@given(st.text(min_size=0))
@settings(max_examples=200)
def test_leading_dash_always_raises(suffix: str) -> None:
    val = "-" + suffix
    with pytest.raises(MilpaError) as exc_info:
        _validate_no_leading_dash(val, "field", TNG_UNSAFE_URL)
    assert exc_info.value.slug == TNG_UNSAFE_URL


# ---------------------------------------------------------------------------
# 10. S2 — dep_decl + dep_decl_schema_version on IndexVersion
# ---------------------------------------------------------------------------

_DEP_DECL_HASH = "sha256:" + "7f3c" * 15 + "7f3c"  # 64-hex total

_INDEX_WITH_DEP_DECL = f"""\
schema_version 1

package "nkdl" {{
    namespace "coreyleavitt"
    version "0.2.0" {{
        content_hash "dag-sha256:{'0' * 64}"
        dep_decl "{_DEP_DECL_HASH}"
        dep_decl_schema_version 0
        provenance {{
            kind "git"
            url "https://github.com/coreyleavitt/nkdl"
            ref "v0.2.0"
        }}
    }}
}}
"""

_INDEX_WITHOUT_DEP_DECL = """\
schema_version 1

package "nkdl" {
    namespace "coreyleavitt"
    version "0.2.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://github.com/coreyleavitt/nkdl"
            ref "v0.2.0"
        }
    }
}
"""


class TestS2DepDeclOnIndexVersion:
    """S2: dep_decl + dep_decl_schema_version parsed from version nodes."""

    def test_dep_decl_present_is_surfaced(self) -> None:
        idx = parse_index(_INDEX_WITH_DEP_DECL)
        pkg = next(p for p in idx.packages if p.name == "nkdl")
        iv = pkg.versions[0]
        assert iv.dep_decl == _DEP_DECL_HASH

    def test_dep_decl_schema_version_present_is_surfaced(self) -> None:
        idx = parse_index(_INDEX_WITH_DEP_DECL)
        pkg = next(p for p in idx.packages if p.name == "nkdl")
        iv = pkg.versions[0]
        assert iv.dep_decl_schema_version == 0

    def test_dep_decl_absent_yields_none(self) -> None:
        idx = parse_index(_INDEX_WITHOUT_DEP_DECL)
        pkg = next(p for p in idx.packages if p.name == "nkdl")
        iv = pkg.versions[0]
        assert iv.dep_decl is None

    def test_dep_decl_schema_version_absent_yields_none(self) -> None:
        idx = parse_index(_INDEX_WITHOUT_DEP_DECL)
        pkg = next(p for p in idx.packages if p.name == "nkdl")
        iv = pkg.versions[0]
        assert iv.dep_decl_schema_version is None

    def test_existing_fixture_still_parses_without_dep_decl(self) -> None:
        """Existing index fixtures (no dep_decl) must stay green — forward-compat."""
        idx = parse_index(MINIMAL_INDEX)
        for pkg in idx.packages:
            for iv in pkg.versions:
                assert iv.dep_decl is None
                assert iv.dep_decl_schema_version is None


# ---------------------------------------------------------------------------
# 11. A2a — published_at + yank triple parse-to-typed extension
#     (registry-protocol.md §3.2 "published_at" + "Yank triple";
#     rfc-registry-append-only.md A2a — parse-to-typed only; no ratchet, no
#     baseline, no selection-time yank enforcement — those land in A2b/A5)
# ---------------------------------------------------------------------------

_INDEX_A2A_FULL = """\
schema_version 1

package "nkdl" {
    namespace "coreyleavitt"
    version "0.3.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000002"
        published_at "2026-06-01T00:00:00Z"
        yanked #true
        yanked_at "2026-07-01T12:00:00Z"
        yanked_reason "ships a vulnerable bearssl pin"
    }
}
"""

_INDEX_A2A_ABSENT = """\
schema_version 1

package "nkdl" {
    namespace "coreyleavitt"
    version "0.3.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000003"
    }
}
"""

_INDEX_A2A_MALFORMED = """\
schema_version 1

package "nkdl" {
    namespace "coreyleavitt"
    version "0.3.0" {
        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000004"
        published_at "not-a-timestamp"
        yanked "not-a-bool"
        yanked_at "also-not-a-timestamp"
    }
}
"""


def _first_version(idx: Index, pkg_name: str = "nkdl"):
    pkg = next(p for p in idx.packages if p.name == pkg_name)
    return pkg.versions[0]


class TestA2aPublishedAtAndYankTriple:
    """A2a: published_at and the yank triple parsed to typed IndexVersion fields.

    Parse-to-typed only (registry-protocol §3.2 NORMATIVE). No ratchet
    enforcement, no baseline comparison, no selection-time yank exclusion —
    those are later append-only-RFC slices (A2b/A2d/A5).
    """

    def test_published_at_parsed_to_datetime(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_FULL))
        assert iv.published_at == datetime.fromisoformat("2026-06-01T00:00:00Z")

    def test_published_at_absent_yields_none(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_ABSENT))
        assert iv.published_at is None

    def test_malformed_published_at_yields_none_no_warning(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            iv = _first_version(parse_index(_INDEX_A2A_MALFORMED))
        assert iv.published_at is None
        assert len(caught) == 0

    def test_yanked_true_parsed(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_FULL))
        assert iv.yanked is True

    def test_yanked_at_parsed_to_datetime(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_FULL))
        assert iv.yanked_at == datetime.fromisoformat("2026-07-01T12:00:00Z")

    def test_yanked_reason_parsed(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_FULL))
        assert iv.yanked_reason == "ships a vulnerable bearssl pin"

    def test_yanked_absent_defaults_false(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_ABSENT))
        assert iv.yanked is False

    def test_yanked_at_absent_yields_none(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_ABSENT))
        assert iv.yanked_at is None

    def test_yanked_reason_absent_yields_none(self) -> None:
        iv = _first_version(parse_index(_INDEX_A2A_ABSENT))
        assert iv.yanked_reason is None

    def test_malformed_yanked_defaults_false_no_warning(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            iv = _first_version(parse_index(_INDEX_A2A_MALFORMED))
        assert iv.yanked is False
        assert len(caught) == 0

    def test_malformed_yanked_at_yields_none_no_warning(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            iv = _first_version(parse_index(_INDEX_A2A_MALFORMED))
        assert iv.yanked_at is None
        assert len(caught) == 0

    def test_existing_fixture_still_parses_with_yank_defaults(self) -> None:
        """MINIMAL_INDEX predates the yank triple — must default cleanly."""
        idx = parse_index(MINIMAL_INDEX)
        chronos = next(p for p in idx.packages if p.name == "chronos")
        iv = chronos.versions[0]
        assert iv.yanked is False
        assert iv.yanked_at is None
        assert iv.yanked_reason is None

    def test_minimal_index_published_at_now_typed(self) -> None:
        """MINIMAL_INDEX's nimkdl entry already carries ``published_at`` (from
        the P2 attestation fixture) — confirm it now parses to a typed
        ``datetime`` rather than being silently ignored (item-6 amendment,
        registry-protocol §1 NORMATIVE)."""
        idx = parse_index(MINIMAL_INDEX)
        nimkdl = next(p for p in idx.packages if p.name == "nimkdl")
        iv = nimkdl.versions[0]
        assert iv.published_at == datetime.fromisoformat("2026-05-26T04:49:44Z")
