"""Named-dep resolution through the tianguis index (milpa#97, S4).

These pin the behaviors the registry→index swap introduces on the
resolver's named path:

  - a named dep resolves to the index-pinned git provenance + records it
    typed (not a `registry:` source string);
  - the index `content_hash` is the post-fetch identity gate (Invariant
    1 / R2) — matching bytes pass, mismatched bytes are rejected;
  - a `v`-prefixed index version resolves (the old `int(split)` path
    crashed on it); a genuinely unparseable version surfaces a coded
    TianguisError, never a Python crash;
  - a name absent from the index is a hard TNG-NOT-FOUND (no fallback).
"""

from dataclasses import dataclass, field

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.lockfile import GitProvenanceRecord, from_graph
from milpa.manifest import Manifest, NamedDep
from milpa.resolver import resolve
from milpa.tianguis_client import TianguisError
from tests.indexkdl import make_index


@dataclass
class _Fake:
    """Writes a fixed nimble; records the (url, ref) it was asked for."""
    nimble: str = 'srcDir = "src"\n'
    sha: str = "deadbeef"
    calls: list = field(default_factory=list)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((p.url, p.ref, p.commit_sha))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(self.nimble)
        return GitReceipt(commit_sha=self.sha)


def _reg(fake):
    r = FetcherRegistry()
    r.register(fake)
    return r


def test_named_dep_resolves_to_typed_git_provenance(tmp_path):
    fake = _Fake()
    # Use a valid 40-hex commit_sha (H2 validation now enforced at parse time)
    pin_sha = "cafef00dcafef00dcafef00dcafef00dcafef00d"
    index = make_index([
        {"name": "foo", "version": "1.2.3",
         "url": "https://example.com/foo.git", "ref": "v1.2.3",
         "commit_sha": pin_sha},
    ])
    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="foo", constraint=">= 1.0.0"),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
    )
    foo = next(d for d in graph.deps if d.name == "foo")
    assert foo.version == (1, 2, 3)
    assert foo.source == "https://example.com/foo.git"
    assert foo.ref == "v1.2.3"
    assert foo.sha == "deadbeef"            # from the receipt, not the index
    # The fetcher was asked to honor the index's immutable commit_sha pin.
    assert fake.calls == [("https://example.com/foo.git", "v1.2.3", pin_sha)]
    # Lockfile reconstructs a git record by TYPE (no source-string parse).
    locked = from_graph(graph).deps
    rec = next(d for d in locked if d.name == "foo").provenances[0]
    assert isinstance(rec, GitProvenanceRecord)
    assert rec.url == "https://example.com/foo.git"
    assert rec.ref == "v1.2.3"
    assert rec.commit_sha == "deadbeef"


def test_named_dep_v_prefixed_version_resolves(tmp_path):
    """A `v`-prefixed index version (`v2.0.0`) resolves — the old
    `int(version.split('.')[0])` path crashed on the `v`."""
    fake = _Fake()
    index = make_index([
        {"name": "foo", "version": "v2.0.0",
         "url": "https://example.com/foo.git", "ref": "v2.0.0"},
    ])
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
    )
    assert next(d for d in graph.deps if d.name == "foo").version == (2, 0, 0)


def test_named_dep_unparseable_version_raises_coded_error(tmp_path):
    """An index whose only version is unparseable surfaces a coded
    TianguisError — never a bare Python ValueError.

    The unparseable version is filtered inside tianguis_client.resolve_named
    (L2: the TNG-BAD-VERSION arm in _process_named is unreachable); the
    error that fires is TNG-NO-SATISFYING-VERSION."""
    fake = _Fake()
    # 1.2.3.4 (four components) is not a clean X.Y.Z; it's the lone version.
    index = make_index([
        {"name": "foo", "version": "1.2.3.4",
         "url": "https://example.com/foo.git", "ref": "main"},
    ])
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    with pytest.raises(TianguisError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
        )
    assert exc.value.code == "TNG-NO-SATISFYING-VERSION"


def test_named_dep_identity_gate_passes_on_matching_hash(tmp_path):
    """R2: when the index records the content_hash the fetched tree
    actually hashes to, the identity gate passes."""
    fake = _Fake()
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    # First resolve with the gate OFF to learn the real recomputed hash.
    probe = resolve(
        manifest, deps_dir=tmp_path / "_probe",
        index=make_index([
            {"name": "foo", "version": "1.0.0",
             "url": "https://example.com/foo.git", "ref": "v1.0.0"},
        ]),
        fetcher=_reg(_Fake()),
    )
    real_hash = next(d for d in probe.deps if d.name == "foo").identity
    assert real_hash and real_hash.startswith("sha256:")

    # Now the index claims that exact hash → gate passes.
    index = make_index([
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": real_hash},
    ])
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
    )
    assert next(d for d in graph.deps if d.name == "foo").identity == real_hash


def test_named_dep_identity_gate_rejects_mismatched_hash(tmp_path):
    """A hostile forge serving bytes that don't hash to the index's
    content_hash is rejected at fetch time (Invariant 1)."""
    from milpa.fetchers import FetchError
    fake = _Fake()
    index = make_index([
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": "sha256:" + "0" * 64},
    ])
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    with pytest.raises(FetchError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
        )
    assert "identity" in str(exc.value).lower()


def test_named_dep_absent_from_index_raises_not_found(tmp_path):
    """No nim-lang fallback: a name not in the index is a hard error."""
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="ghost", constraint=None),),
    )
    with pytest.raises(TianguisError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps",
            index=make_index([]), fetcher=_reg(_Fake()),
        )
    assert exc.value.code == "TNG-NOT-FOUND"


def test_named_dep_without_index_raises_clear_resolver_error(tmp_path):
    """M7: when a manifest has named deps and index=None is passed, the
    error is a clear ResolverError — not a misleading TNG-NOT-FOUND."""
    from milpa.resolver import ResolverError
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="results", constraint=None),),
    )
    with pytest.raises(ResolverError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps",
            index=None, fetcher=_reg(_Fake()),
        )
    assert "index" in str(exc.value).lower()
    assert "results" in str(exc.value)


# ---------------------------------------------------------------------------
# M8 — OCI named-dep path through the resolver in-process
# ---------------------------------------------------------------------------
# The chain parse_index → resolve_named → _process_named →
# fetch_any(OciProvenance) → from_graph → OciProvenanceRecord had been
# covered only by the gated live integration test. These tests close that gap
# with a fake OciFetcher injected via FetcherRegistry (no oras invocation).
# ---------------------------------------------------------------------------


@dataclass
class _FakeOci:
    """Fake OciFetcher: writes a fixed source tree and records calls.
    The content_hash produced must be pre-computed and passed to make_index
    so the identity gate passes (use fake_content_hash(name) for that)."""
    nimble: str = 'srcDir = "src"\n'
    calls: list = field(default_factory=list)

    def can_handle(self, p):
        from milpa.fetchers.oci import OciProvenance
        return isinstance(p, OciProvenance)

    def fetch(self, name, p, *, dest):
        from milpa.fetchers.oci import OciProvenance, OciReceipt
        assert isinstance(p, OciProvenance)
        self.calls.append((p.registry, p.repository, p.digest))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(self.nimble)
        return OciReceipt(oci_digest=p.digest)


def test_oci_named_dep_resolves_end_to_end(tmp_path):
    """M8: a named dep whose canonical provenance is OciProvenance resolves
    end-to-end through the resolver. The resulting ResolvedDep carries an
    OciProvenance; from_graph emits an OciProvenanceRecord with matching
    registry/repository/digest."""
    from milpa.lockfile import OciProvenanceRecord
    from milpa.fetchers.oci import OciProvenance
    from tests.indexkdl import fake_content_hash

    digest = "sha256:" + "e" * 64
    name = "nimkdl"
    ch = fake_content_hash(name)

    oci_fake = _FakeOci()
    r = FetcherRegistry()
    r.register(oci_fake)

    index = make_index([{
        "name": name,
        "kind": "oci",
        "registry": "ghcr.io",
        "repository": "user/nimkdl",
        "digest": digest,
        "content_hash": ch,
        "version": "0.2.0",
    }])

    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name=name, constraint=None),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=r,
    )

    dep = next(d for d in graph.deps if d.name == name)
    # Typed OCI provenance carried on the resolved dep.
    assert isinstance(dep.provenance, OciProvenance)
    assert dep.provenance.registry == "ghcr.io"
    assert dep.provenance.repository == "user/nimkdl"
    assert dep.provenance.digest == digest
    # source display string for OCI (milpa#97).
    assert dep.source == "oci:ghcr.io/user/nimkdl"

    # from_graph must emit an OciProvenanceRecord (not GitProvenanceRecord).
    from milpa.lockfile import from_graph
    locked_dep = next(
        d for d in from_graph(graph).deps if d.name == name
    )
    rec = locked_dep.provenances[0]
    assert isinstance(rec, OciProvenanceRecord)
    assert rec.registry == "ghcr.io"
    assert rec.repository == "user/nimkdl"
    assert rec.digest == digest

    # The fake OCI fetcher was called exactly once with the right coordinates.
    assert oci_fake.calls == [("ghcr.io", "user/nimkdl", digest)]
