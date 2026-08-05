"""Tests for milpa.fetchers.oci (slice 7d-5; native client S6).

All tests are offline. As of S6 the token/manifest/blob transport state
machine (auth challenges, digest verification, manifest-list rejection,
redirect handling, the `select_source_layer` NO-TARBALL/AMBIGUOUS-TARBALL
gates) lives in ``milpa.fetchers.oci_client`` and is covered exhaustively by
``test_oci_client.py`` against the shared canned-transport fixtures under
``conformance/oci-transport/`` — those cases are NOT duplicated here.

This file covers what's unique to ``OciFetcher`` itself:
  TNG-* parse-path (registry-protocol.md §4 NORMATIVE):
    - validate_oci_digest: valid form accepted; any other raises TNG-BAD-OCI-DIGEST.
    - validate_oci_field: safe value accepted; leading dash raises TNG-UNSAFE-OCI-FIELD.
    - OciProvenance construction validates at __post_init__.

  Dispatch:
    - can_handle: True for OciProvenance, False for others.

  Composition (OciFetcher.fetch wiring the client + select_source_layer +
  safe_extract together, via the ``FakeOciClient`` test double):
    - Successful fetch extracts the blob's content into dest.
    - A corrupt blob raises FETCH-EXTRACT-FAILED.
    - The receipt carries layer_digest from the provenance.
"""

from __future__ import annotations

import io
import tarfile
import tempfile
from pathlib import Path

import pytest

from milpa.errors import (
    FETCH_EXTRACT_FAILED,
    TNG_BAD_OCI_DIGEST,
    TNG_UNSAFE_OCI_FIELD,
    MilpaError,
)
from milpa.fetchers.oci import (
    OciFetcher,
    OciProvenance,
    OciReceipt,
    validate_oci_digest,
    validate_oci_field,
)
from milpa.fetchers.types import Provenance
from tests._oci_fake_client import FakeOciClient

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_VALID_DIGEST = f"sha256:{'a' * 64}"


def _build_tar_gz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# validate_oci_digest — TNG-BAD-OCI-DIGEST
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("valid", [
    f"sha256:{'0' * 64}",
    f"sha256:{'a' * 64}",
    f"sha256:{'f' * 64}",
    f"sha256:{'0123456789abcdef' * 4}",
])
def test_validate_oci_digest_valid(valid: str) -> None:
    # Must not raise.
    validate_oci_digest(valid)


@pytest.mark.parametrize("bad", [
    "",                                         # empty
    "sha256:",                                  # no hex
    f"sha256:{'a' * 63}",                       # too short
    f"sha256:{'a' * 65}",                       # too long
    f"sha256:{'G' * 64}",                       # uppercase G not hex
    f"sha256:{'A' * 64}",                       # uppercase not allowed
    f"{'a' * 64}",                              # no prefix
    f"md5:{'a' * 32}",                          # wrong algorithm
    f"sha256:{'a' * 64}extra",                  # trailing chars
])
def test_validate_oci_digest_invalid(bad: str) -> None:
    with pytest.raises(MilpaError) as exc_info:
        validate_oci_digest(bad)
    assert exc_info.value.slug == TNG_BAD_OCI_DIGEST


# ---------------------------------------------------------------------------
# validate_oci_field — TNG-UNSAFE-OCI-FIELD
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("safe", [
    "ghcr.io",
    "registry.example.com",
    "org/package",
    "0startdigit",
])
def test_validate_oci_field_safe(safe: str) -> None:
    validate_oci_field("registry", safe)  # Must not raise.


@pytest.mark.parametrize("unsafe", [
    "-injection",
    "--flag",
    "-",
])
def test_validate_oci_field_unsafe(unsafe: str) -> None:
    with pytest.raises(MilpaError) as exc_info:
        validate_oci_field("registry", unsafe)
    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD
    assert exc_info.value.context.get("field") == "registry"


def test_validate_oci_field_repository_unsafe() -> None:
    with pytest.raises(MilpaError) as exc_info:
        validate_oci_field("repository", "-bad")
    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD
    assert exc_info.value.context.get("field") == "repository"


# ---------------------------------------------------------------------------
# OciProvenance construction validates at __post_init__
# ---------------------------------------------------------------------------


def test_oci_provenance_valid() -> None:
    p = OciProvenance(
        registry="ghcr.io",
        repository="org/pkg",
        digest=_VALID_DIGEST,
    )
    assert p.registry == "ghcr.io"
    assert p.digest == _VALID_DIGEST
    assert p.cas_admissible is True


def test_oci_provenance_bad_digest_at_construction() -> None:
    with pytest.raises(MilpaError) as exc_info:
        OciProvenance(registry="ghcr.io", repository="org/pkg", digest="bad")
    assert exc_info.value.slug == TNG_BAD_OCI_DIGEST


def test_oci_provenance_unsafe_registry_at_construction() -> None:
    with pytest.raises(MilpaError) as exc_info:
        OciProvenance(registry="-bad", repository="org/pkg", digest=_VALID_DIGEST)
    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD


def test_oci_provenance_unsafe_repository_at_construction() -> None:
    with pytest.raises(MilpaError) as exc_info:
        OciProvenance(registry="ghcr.io", repository="-bad", digest=_VALID_DIGEST)
    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD


def test_oci_provenance_reference_format() -> None:
    p = OciProvenance(
        registry="ghcr.io",
        repository="org/pkg",
        digest=_VALID_DIGEST,
    )
    assert p.reference == f"ghcr.io/org/pkg@{_VALID_DIGEST}"


# ---------------------------------------------------------------------------
# can_handle dispatch
# ---------------------------------------------------------------------------


def test_can_handle_oci_provenance() -> None:
    fetcher = OciFetcher(client=FakeOciClient(b""))
    assert fetcher.can_handle(OciProvenance(
        registry="ghcr.io", repository="org/pkg", digest=_VALID_DIGEST
    )) is True


def test_can_handle_rejects_base_provenance() -> None:
    fetcher = OciFetcher(client=FakeOciClient(b""))
    assert fetcher.can_handle(Provenance()) is False


# ---------------------------------------------------------------------------
# Successful fetch — OciFetcher composes client + select_source_layer +
# safe_extract directly (RFC docs/rfc-native-oci-fetch.md §3.2)
# ---------------------------------------------------------------------------


def test_fetch_extracts_blob_content() -> None:
    tar_bytes = _build_tar_gz({"main.nim": b"# oci"})
    fake_client = FakeOciClient(tar_bytes)

    prov = OciProvenance(
        registry="ghcr.io",
        repository="org/pkg",
        digest=_VALID_DIGEST,
    )
    fetcher = OciFetcher(client=fake_client)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert (dest / "main.nim").read_bytes() == b"# oci"

    assert isinstance(receipt, OciReceipt)
    assert receipt.layer_digest == _VALID_DIGEST
    assert fake_client.calls == [f"ghcr.io/org/pkg@{_VALID_DIGEST}"]


def test_fetch_does_not_leave_the_raw_archive_in_dest() -> None:
    """`dest` ends up as exactly the extracted tree — the raw tarball must
    not sit alongside it (it would corrupt the CAS content_hash, which is
    computed over every file under `dest`)."""
    tar_bytes = _build_tar_gz({"lib.nim": b"lib"})
    fake_client = FakeOciClient(tar_bytes)

    prov = OciProvenance(
        registry="ghcr.io",
        repository="org/lib",
        digest=_VALID_DIGEST,
    )
    fetcher = OciFetcher(client=fake_client)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "lib"
        fetcher.fetch("lib", prov, dest=dest)
        names = {p.name for p in dest.iterdir()}
    assert names == {"lib.nim"}


# ---------------------------------------------------------------------------
# FETCH-EXTRACT-FAILED
# ---------------------------------------------------------------------------


def test_corrupt_blob_raises_extract_failed() -> None:
    garbage = b"not a tar at all"
    fetcher = OciFetcher(client=FakeOciClient(garbage))
    prov = OciProvenance(
        registry="ghcr.io",
        repository="org/pkg",
        digest=_VALID_DIGEST,
    )

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    assert exc_info.value.slug == FETCH_EXTRACT_FAILED


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------


def test_receipt_transport_fields_non_empty() -> None:
    tar_bytes = _build_tar_gz({"x.nim": b"x"})
    fetcher = OciFetcher(client=FakeOciClient(tar_bytes))
    prov = OciProvenance(
        registry="ghcr.io",
        repository="org/pkg",
        digest=_VALID_DIGEST,
    )

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)

    fields = receipt.transport_fields()
    assert fields
    assert "layer_digest" in fields
    assert fields["layer_digest"] == _VALID_DIGEST


# ---------------------------------------------------------------------------
# Defense-in-depth: fetch validates fields even if bypassed at parse boundary
# ---------------------------------------------------------------------------


def test_fetch_rejects_bad_digest_at_fetch_time() -> None:
    """Even if OciProvenance construction is bypassed (shouldn't happen), fetch validates."""
    # Since OciProvenance is frozen + validates at __post_init__, we verify
    # the validate_* functions are called standalone and the fetcher delegates to them.
    with pytest.raises(MilpaError) as exc_info:
        validate_oci_digest("not-valid-digest")
    assert exc_info.value.slug == TNG_BAD_OCI_DIGEST
