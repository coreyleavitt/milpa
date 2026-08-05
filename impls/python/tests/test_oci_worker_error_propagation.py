"""S9 (rfc-native-oci-fetch.md §3.4, issue #198) — the OCI-override worker
must surface the DEFINITIVE fetch error unchanged, not rewrap it into
``FETCH-ALL-FAILED``.

An OCI dep (``OciTarget`` override — see ``_process_oci_worker``'s
docstring) has exactly ONE fetch candidate: the pinned
(registry, repository, digest) triple. There is no mirror list to "fall
back" across, so ``FETCH-ALL-FAILED`` (which means "every candidate in a
list failed") is a category error for this path — it masks the real
``FETCH-OCI-*`` slug (and any ``phase=`` context) that would tell the user
what actually went wrong (digest mismatch vs. transport failure vs. which
phase: token/manifest/blob).

These tests inject a client that raises a definitive ``MilpaError`` from
the very first client call (``token()``), and assert that error's slug
(and context) propagate out of ``resolve()`` unchanged.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import (
    FETCH_OCI_DIGEST_MISMATCH,
    FETCH_OCI_PULL_FAILED,
    MilpaError,
)
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.oci import OciFetcher
from milpa.fetchers.types import FetcherRegistry
from milpa.manifest import parse_manifest
from milpa.resolver import resolve


class _FailingOciClient:
    """Duck-typed ``OciRegistryClient`` replacement that raises a fixed
    ``MilpaError`` from the very first call (``token``) — mirrors a real
    definitive OCI-transport/digest failure without any real network."""

    def __init__(self, error: MilpaError) -> None:
        self._error = error

    def token(self, registry: str, repository: str) -> str:
        raise self._error

    def manifest(self, registry: str, repository: str, digest: str, token: str):
        raise self._error

    def blob(self, registry, repository, digest, size, token, *, dest):
        raise self._error


def _manifest_with_oci_override(dep_name: str, digest: str) -> object:
    root_kdl = textwrap.dedent(f"""\
        name "myapp"
        kind "application"
        deps {{
            {dep_name} git=(url)"https://example.com/{dep_name}-DO-NOT-FETCH.git" ref="main"
        }}
        overrides {{
            pkg "{dep_name}" oci="ghcr.io/acme/{dep_name}" digest="{digest}"
        }}
    """)
    return parse_manifest(root_kdl)


def _resolve_with_failing_client(tmp_path: Path, error: MilpaError):
    registry = FetcherRegistry()
    registry.register(OciFetcher(client=_FailingOciClient(error)))
    store = CAStore(root=tmp_path / ".cas")
    fetcher = CasAdmittingFetcher(registry, store)
    env = MilpaEnv(fetcher=fetcher, index=None, store=store)

    digest = "sha256:" + "d" * 64
    manifest = _manifest_with_oci_override("foo", digest)
    resolve(manifest, tmp_path / "_deps", env, ResolveParams())


class TestOciWorkerSurfacesDefinitiveError:
    def test_digest_mismatch_surfaces_unchanged(self, tmp_path: Path) -> None:
        inner = MilpaError(
            FETCH_OCI_DIGEST_MISMATCH,
            "blob digest mismatch",
            dep="foo",
            phase="blob",
        )
        with pytest.raises(MilpaError) as excinfo:
            _resolve_with_failing_client(tmp_path, inner)

        assert excinfo.value.slug == FETCH_OCI_DIGEST_MISMATCH
        assert excinfo.value.slug != "FETCH-ALL-FAILED"
        assert excinfo.value.context.get("phase") == "blob"

    def test_pull_failed_with_phase_surfaces_unchanged(self, tmp_path: Path) -> None:
        inner = MilpaError(
            FETCH_OCI_PULL_FAILED,
            "transport error acquiring token",
            dep="foo",
            phase="token",
        )
        with pytest.raises(MilpaError) as excinfo:
            _resolve_with_failing_client(tmp_path, inner)

        assert excinfo.value.slug == FETCH_OCI_PULL_FAILED
        assert excinfo.value.slug != "FETCH-ALL-FAILED"
        assert excinfo.value.context.get("phase") == "token"
