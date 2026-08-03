"""RFC per-entry-attestation.md P2 — attribution surfacing WITHOUT gating.

End-to-end pipeline test: an index entry's ``EntryAttestation`` claim survives
the full path from `resolve()` through `ResolvedGraph` to a `Lockfile`
(`from_graph`) — i.e. the "lockfile emit iff non-collapsed registry dep"
normative rule (lockfile-schema.md §3.9) exercised through the real resolver,
not just the unit-level `_locked_from_resolved` conversion.

No gating, no error slugs, no verifier — those are P3a. This is pure
attribution-surfacing plumbing: registry parse → resolver candidate →
lockfile record.
"""

from __future__ import annotations

from pathlib import Path

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.lockfile import LockAttestation, from_graph
from milpa.manifest import Manifest, NamedDep, UrlDep
from milpa.registry import (
    AuthorSigned,
    EntryAttestation,
    GitIndexProvenance,
    Index,
    IndexVersion,
    Package,
    RekorRef,
)
from milpa.resolver import resolve
from milpa.version import Strategy

_GIT_URL = "https://example.com/widget.git"
_REF = "v1.0.0"
_CONTENT_HASH = "dag-sha256:" + "a" * 64


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


def _make_mocked_fixture(mocked_dir: Path, url: str, ref: str) -> None:
    key = url_key(url, ref)
    dep_dir = mocked_dir / key
    content_dir = dep_dir / "content"
    content_dir.mkdir(parents=True, exist_ok=True)
    (dep_dir / "sha").write_text("deadbeef", encoding="utf-8")
    (content_dir / "widget.nimble").write_text(
        'version = "1.0.0"\nauthor = "a"\nlicense = "MIT"\n', encoding="utf-8"
    )


def _make_env(mocked_dir: Path, tmp_path: Path, index: Index) -> MilpaEnv:
    store = CAStore(root=tmp_path / ".cas")
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _index_with(attestation: EntryAttestation | None) -> Index:
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
                            GitIndexProvenance(url=_GIT_URL, ref=_REF, commit_sha=None),
                        ),
                        attestation=attestation,
                    ),
                ),
            )
        ]
    )


class TestAttestationSurvivesResolveToLockfile:
    def test_author_signed_claim_survives_to_lockfile(self, tmp_path: Path) -> None:
        att = EntryAttestation(
            kind=AuthorSigned(signer="https://example.com/wf.yaml"),
            rekor=RekorRef(uuid="u", log_index="1", integrated_time="2"),
        )
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, _GIT_URL, _REF)
        env = _make_env(mocked_dir, tmp_path, _index_with(att))

        m = _manifest([NamedDep(name="widget", constraint=None)])
        graph = resolve(m, tmp_path / "_deps", env, ResolveParams(strategy=Strategy.MAXVER))

        assert len(graph.deps) == 1
        assert graph.deps[0].attestation == att

        lockfile = from_graph(graph, strategy="maxver")
        locked = next(d for d in lockfile.deps if d.name == "widget")
        # P3a: namespace mirrors the index entry's real namespace ("acme",
        # per _index_with below) — a pre-existing assertion gap this test
        # never updated after P3a added the field. RFC origin-as-identity.md
        # §4.4 (S5): now derived from source_id.namespace, not a separate
        # registry_namespace field, but the VALUE is unchanged.
        assert locked.attestation == LockAttestation(
            kind=att.kind, rekor=att.rekor, namespace="acme"
        )

    def test_unattested_entry_has_no_lockfile_block(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, _GIT_URL, _REF)
        env = _make_env(mocked_dir, tmp_path, _index_with(None))

        m = _manifest([NamedDep(name="widget", constraint=None)])
        graph = resolve(m, tmp_path / "_deps", env, ResolveParams(strategy=Strategy.MAXVER))

        assert graph.deps[0].attestation is None
        lockfile = from_graph(graph, strategy="maxver")
        locked = next(d for d in lockfile.deps if d.name == "widget")
        assert locked.attestation is None

    def test_url_dep_never_carries_attestation(self, tmp_path: Path) -> None:
        """URL deps have no index entry — attestation MUST always be absent
        (lockfile-schema.md §3.9 NORMATIVE: applies only to registry-resolved
        deps)."""
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, _GIT_URL, _REF)
        # Index has an attested entry for "widget" — but the manifest dep is a
        # URL dep, not a named dep, so it must never pick up the claim.
        env = _make_env(
            mocked_dir,
            tmp_path,
            _index_with(EntryAttestation(kind=AuthorSigned(signer="https://x/wf.yaml"))),
        )

        dep = UrlDep(
            name="widget", git=_GIT_URL, ref=_REF, mirrors=[], predicates=[], flag_requests=[]
        )
        m = _manifest([dep])
        graph = resolve(m, tmp_path / "_deps", env, ResolveParams(strategy=Strategy.MAXVER))

        assert graph.deps[0].attestation is None
        lockfile = from_graph(graph, strategy="maxver")
        locked = next(d for d in lockfile.deps if d.name == "widget")
        assert locked.attestation is None
