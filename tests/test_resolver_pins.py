"""Resolver wires expected_identity from prior lockfile (#82).

When a manifest dep's declared provenance still matches the lockfile's
recorded provenance, the resolver passes expected_identity through to
fetch_any. A hostile mirror or rewritten git tag serving different
bytes is rejected at fetch time — not later at verify time.

The pin DROPS when:
  - User changed the manifest (different ref, different URL, different
    constraint that resolves to a new tag)
  - Dep is a LocalDep (cas_admissible=False)
  - No prior lockfile is supplied

See docs/rfc-content-addressed-identity.md.
"""

from dataclasses import dataclass

import pytest

from milpa.tianguis_client import Index
from milpa.fetchers import (
    FetcherRegistry,
    FetchError,
    Provenance,
    ProvenanceReceipt,
)
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
)
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve


def test_resolve_passes_expected_identity_when_prior_lockfile_matches(tmp_path):
    """Tracer: prior_lockfile pins identity X. The fetcher returns
    bytes hashing to Y. Resolver rejects (via fetch_any's identity
    check), surfacing FetchError."""

    class StubFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    registry = FetcherRegistry()
    registry.register(StubFetcher())

    manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="x", git="https://example.com/x.git", ref="main",
        ),),
    )
    # Prior lockfile claims a DIFFERENT identity than what fetcher will produce
    bogus_identity = "sha256:" + "f" * 64
    prior = Lockfile(deps=(LockedDep(
        name="x", identity=bogus_identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://example.com/x.git",   # matches manifest
            ref="main",                         # matches manifest
            commit_sha="abc",
        ),),
    ),))

    with pytest.raises(Exception) as exc:
        resolve(
            manifest,
            deps_dir=tmp_path / "_deps",
            fetcher=registry,
            prior_lockfile=prior,
        )

    msg = str(exc.value).lower()
    assert "identity" in msg or "mismatch" in msg


def test_resolve_no_prior_lockfile_accepts_any_identity(tmp_path):
    """Without prior_lockfile, no pin enforcement — same shape as
    today's behavior. Fetch succeeds regardless of bytes."""

    class StubFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    registry = FetcherRegistry()
    registry.register(StubFetcher())

    manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(name="x", git="https://x/x.git", ref="main"),),
    )

    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        # No prior_lockfile
    )

    assert len(graph.deps) == 1
    assert graph.deps[0].name == "x"


def test_resolve_drops_pin_when_manifest_ref_changed(tmp_path):
    """User edited the ref from 'main' to 'v2'. Lockfile pinned an
    identity for 'main'. Resolver MUST accept the new bytes — the
    user's manifest edit is authoritative."""

    class StubFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="new-sha")

    registry = FetcherRegistry()
    registry.register(StubFetcher())

    # Manifest now declares ref="v2"
    manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(name="x", git="https://x/x.git", ref="v2"),),
    )
    # Lockfile recorded ref="main" with identity X
    bogus_identity = "sha256:" + "f" * 64
    prior = Lockfile(deps=(LockedDep(
        name="x", identity=bogus_identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://x/x.git", ref="main", commit_sha="old-sha",
        ),),
    ),))

    # Should NOT raise — user opted into a different ref
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        prior_lockfile=prior,
    )
    assert graph.deps[0].name == "x"
    assert graph.deps[0].sha == "new-sha"


def test_resolve_pin_applies_when_manifest_added_mirror_but_primary_unchanged(tmp_path):
    """Manifest gained a mirror; primary git+ref is unchanged. Pin
    must still apply: the primary is the same provenance the lockfile
    pinned, so byte-substitution is just as dangerous as before."""
    from milpa.identity import compute_content_hash

    locked_bytes = "expected-bytes"

    class BadByteFetcher:
        """Returns bytes that DON'T hash to the locked identity."""
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            (dest / "different").write_text("totally different bytes")
            return GitReceipt(commit_sha="abc")

    registry = FetcherRegistry()
    registry.register(BadByteFetcher())

    # Manifest: primary unchanged, mirror added
    manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="x", git="https://x/x.git", ref="main",
            mirrors=("https://mirror/x.git",),
        ),),
    )
    # Lockfile pinned identity X (won't match fetcher's bytes)
    bogus_identity = "sha256:" + "a" * 64
    prior = Lockfile(deps=(LockedDep(
        name="x", identity=bogus_identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://x/x.git",   # unchanged from manifest
            ref="main",
            commit_sha="abc",
        ),),
    ),))

    # Pin should apply → fetcher's bytes rejected → FetchError
    with pytest.raises(Exception) as exc:
        resolve(
            manifest,
            deps_dir=tmp_path / "_deps",
            fetcher=registry,
            prior_lockfile=prior,
        )
    assert "identity" in str(exc.value).lower()


def test_resolve_drops_pin_for_named_dep_when_constraint_picks_new_version(tmp_path):
    """A NamedDep with constraint='>= 1.2.3'; the tianguis index now
    serves v1.2.5 (where the lockfile had v1.2.4). The pin must drop —
    the locked identity won't match the newly-resolved version's
    content_hash, the constraint allows newer, and the user gets the
    newer bytes (milpa#97 §Re-lock pin semantics)."""
    from milpa.manifest import NamedDep
    from tests.indexkdl import make_index

    class StubFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="new-sha")

    registry = FetcherRegistry()
    registry.register(StubFetcher())

    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="results", constraint=">= 1.2.3"),),
    )

    # Index serves the newer v1.2.5 (content_hash omitted → no gate, so
    # the stub's arbitrary bytes resolve; the point is the *pin* drops).
    index = make_index([
        {"name": "results", "version": "1.2.5",
         "url": "https://example.com/results.git", "ref": "v1.2.5"},
    ])

    # Lockfile had v1.2.4 pinned to identity X — a git record, the modern
    # named-dep provenance shape.
    bogus_identity = "sha256:" + "f" * 64
    prior = Lockfile(deps=(LockedDep(
        name="results", identity=bogus_identity, version="1.2.4",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://example.com/results.git", ref="v1.2.4",
            commit_sha="old-sha",
        ),),
    ),))

    # Should NOT raise — locked identity != resolved v1.2.5 content_hash.
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        index=index,
        fetcher=registry,
        prior_lockfile=prior,
    )
    assert any(d.name == "results" for d in graph.deps)


# ---------------------------------------------------------------------------
# cmd_fetch / cmd_lock integration
# ---------------------------------------------------------------------------


def test_cmd_fetch_loads_prior_lockfile_and_enforces_pin(tmp_path, capsys):
    """End-to-end: a manifest + a lockfile pinning identity X, and a
    fetcher returning bytes hashing to something else. cmd_fetch must
    abort with the pin-enforcement error."""
    from milpa.cli import cmd_fetch
    from milpa.lockfile import format_lockfile

    (tmp_path / "milpa.kdl").write_text(
        'name "proj"\n'
        'kind "library"\n'
        'deps {\n'
        '    x git=(url)"https://x/x.git" ref="main"\n'
        '}\n'
    )
    bogus_identity = "sha256:" + "a" * 64
    prior = Lockfile(deps=(LockedDep(
        name="x", identity=bogus_identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://x/x.git", ref="main", commit_sha="abc",
        ),),
    ),))
    (tmp_path / "milpa.lock").write_text(format_lockfile(prior))

    class WrongByteFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            (dest / "junk").write_text("not what the lockfile pinned")
            return GitReceipt(commit_sha="abc")

    registry = FetcherRegistry()
    registry.register(WrongByteFetcher())

    rc = cmd_fetch(
        tmp_path, fetcher=registry,
        index_loader=lambda *, cache_dir: Index({}),
    )

    # cmd_fetch detects the identity mismatch (either via frozen-path
    # contains() OR via slow-path fetch_any pin enforcement) and exits 1.
    assert rc == 1
    err = capsys.readouterr().err
    assert "identity" in err.lower() or "mismatch" in err.lower()


def test_apply_manifest_change_with_resolve_threads_prior_lockfile(tmp_path):
    """cmd_add-style: adding a brand-new dep should NOT change existing
    pins. Existing dep with locked identity X; mid-fetch some hostile
    actor returns Y for it; apply_manifest_change_with_resolve must
    reject."""
    from milpa.manifest_writer import (
        apply_manifest_change_with_resolve,
        write_manifest,
    )
    from milpa.lockfile import format_lockfile

    # Existing project with one dep locked to identity X
    write_manifest(
        Manifest(
            kind="library", name="proj",
            deps=(UrlDep(name="existing", git="https://e/e.git", ref="main"),),
        ),
        tmp_path / "milpa.kdl",
    )
    bogus_identity = "sha256:" + "9" * 64
    prior = Lockfile(deps=(LockedDep(
        name="existing", identity=bogus_identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://e/e.git", ref="main", commit_sha="abc",
        ),),
    ),))
    (tmp_path / "milpa.lock").write_text(format_lockfile(prior))

    # Proposed: add a NEW dep, keep existing one untouched
    proposed = Manifest(
        kind="library", name="proj",
        deps=(
            UrlDep(name="existing", git="https://e/e.git", ref="main"),
            UrlDep(name="newdep", git="https://n/n.git", ref="main"),
        ),
    )

    class StubFetcher:
        """Returns generic bytes that won't match the bogus locked identity."""
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    registry_fetcher = FetcherRegistry()
    registry_fetcher.register(StubFetcher())

    from milpa.solver import Strategy
    with pytest.raises(Exception) as exc:
        apply_manifest_change_with_resolve(
            tmp_path,
            proposed_manifest=proposed,
            fetcher=registry_fetcher,
            index_loader=lambda *, cache_dir: Index({}),
            strategy=Strategy.MAXVER,
        )

    # The existing dep's pin was enforced
    assert "identity" in str(exc.value).lower()
