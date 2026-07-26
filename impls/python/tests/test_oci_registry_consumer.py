"""OCI consumer resolution — named registry dep with OCI index provenance.

Closes the resolver gap where an index entry whose provenance is ``oci`` (not
``git``) hit ``TNG-NO-IDENTITY: OCI provenance not yet supported in Phase B``
in ``_materialize``. This is the registry named-dep path only — NOT the
manifest ``oci=`` dep form (out of scope; see resolver.py::_materialize).

End-to-end: ``resolve()`` with a real ``OciFetcher`` (injected fake
``oci_pull`` transport — no real ``oras``/network) against an ``Index`` whose
single provenance is ``OciIndexProvenance``. Asserts:
  - the fetch is actually invoked (via the fake pull closure)
  - the resulting ``ResolvedDep`` carries an ``OciProvenanceRecord`` (not git)
  - the lockfile round-trips: ``from_graph`` -> format -> parse recovers the
    same ``kind "oci"`` record.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.oci import OciFetcher
from milpa.fetchers.types import FetcherRegistry
from milpa.lockfile import OciProvenanceRecord, format_lockfile, from_graph, parse_lockfile
from milpa.manifest import Manifest, NamedDep
from milpa.registry import Index, IndexVersion, OciIndexProvenance, Package
from milpa.resolver import resolve
from milpa.version import Strategy

_REGISTRY = "ghcr.io"
_REPOSITORY = "acme/widget"
_DIGEST = f"sha256:{'b' * 64}"
_CONTENT_HASH = "dag-sha256:" + "c" * 64


def _manifest(deps: list) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=deps,
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _index_with_oci() -> Index:
    return Index(
        packages=[
            Package(
                name="widget",
                namespace="acme",
                versions=(
                    IndexVersion(
                        version="1.0.0",
                        content_hash=_CONTENT_HASH,
                        provenances=(
                            OciIndexProvenance(
                                registry=_REGISTRY,
                                repository=_REPOSITORY,
                                digest=_DIGEST,
                            ),
                        ),
                    ),
                ),
            )
        ]
    )


def _build_tar_gz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_env(tmp_path: Path, index: Index, pull_calls: list[str]) -> MilpaEnv:
    """Build a MilpaEnv with a real OciFetcher whose ``oci_pull`` transport is
    faked (no real ``oras``/network) — mirrors test_oci_fetcher.py's pattern.
    """
    tar_bytes = _build_tar_gz(
        {"widget.nimble": b'version = "1.0.0"\nauthor = "a"\nlicense = "MIT"\n'}
    )

    def _fake_pull(reference: str, output_dir: Path) -> list[Path]:
        pull_calls.append(reference)
        out = output_dir / "widget.tar.gz"
        out.write_bytes(tar_bytes)
        return [out]

    registry = FetcherRegistry()
    registry.register(OciFetcher(oci_pull=_fake_pull))
    store = CAStore(root=tmp_path / ".cas")
    fetcher = CasAdmittingFetcher(registry, store)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


class TestOciNamedDepResolution:
    def test_named_dep_with_oci_provenance_resolves(self, tmp_path: Path) -> None:
        pull_calls: list[str] = []
        env = _make_env(tmp_path, _index_with_oci(), pull_calls)

        m = _manifest([NamedDep(name="widget", constraint=None)])
        graph = resolve(m, tmp_path / "_deps", env, ResolveParams(strategy=Strategy.MAXVER))

        assert len(graph.deps) == 1
        dep = graph.deps[0]
        assert dep.name == "widget"

        # The fake oras-pull transport was actually invoked, with the full
        # OCI reference built from the index's provenance fields.
        assert pull_calls == [f"{_REGISTRY}/{_REPOSITORY}@{_DIGEST}"]

        # The candidate carries an OciProvenanceRecord, not a GitProvenanceRecord.
        assert len(dep.provenances) == 1
        prov = dep.provenances[0]
        assert isinstance(prov, OciProvenanceRecord)
        assert prov.registry == _REGISTRY
        assert prov.repository == _REPOSITORY
        assert prov.digest == _DIGEST
        assert prov.kind == "oci"
        assert prov.origin == "observed"

    def test_oci_provenance_round_trips_through_lockfile(self, tmp_path: Path) -> None:
        pull_calls: list[str] = []
        env = _make_env(tmp_path, _index_with_oci(), pull_calls)

        m = _manifest([NamedDep(name="widget", constraint=None)])
        graph = resolve(m, tmp_path / "_deps", env, ResolveParams(strategy=Strategy.MAXVER))

        lockfile = from_graph(graph, strategy="maxver")
        locked = next(d for d in lockfile.deps if d.name == "widget")
        assert len(locked.provenances) == 1
        locked_prov = locked.provenances[0]
        assert isinstance(locked_prov, OciProvenanceRecord)
        assert locked_prov.registry == _REGISTRY
        assert locked_prov.repository == _REPOSITORY
        assert locked_prov.digest == _DIGEST

        # Full format -> parse round-trip.
        text = format_lockfile(lockfile)
        assert 'kind "oci"' in text
        reparsed = parse_lockfile(text)
        reparsed_dep = next(d for d in reparsed.deps if d.name == "widget")
        reparsed_prov = reparsed_dep.provenances[0]
        assert isinstance(reparsed_prov, OciProvenanceRecord)
        assert reparsed_prov == locked_prov
