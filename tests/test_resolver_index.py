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
    index = make_index([
        {"name": "foo", "version": "1.2.3",
         "url": "https://example.com/foo.git", "ref": "v1.2.3",
         "commit_sha": "cafef00d"},
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
    assert fake.calls == [("https://example.com/foo.git", "v1.2.3", "cafef00d")]
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
    TianguisError — never a bare Python ValueError."""
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
    assert exc.value.code in {"TNG-NO-SATISFYING-VERSION", "TNG-BAD-VERSION"}


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
