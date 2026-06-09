"""Resolver fetches the PINNED COMMIT when a prior lockfile pin exists.

Bug: _process_url built GitProvenance(url, ref) without commit_sha, so
GitFetcher cloned the (mutable) ref tip instead of the immutable pinned
commit. When the ref tip had moved, the fetched content didn't match the
pinned identity → FETCH-ALL-FAILED.

Fix: when the prior lockfile pins a git dep whose url+ref still match the
manifest, carry the locked commit_sha into the GitProvenance candidate so
GitFetcher checks out the exact pinned commit.

See resolver.py `_git_pin_for_url_dep` / `_process_url`.
"""

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.identity import compute_content_hash
from milpa.lockfile import GitProvenanceRecord, LockedDep, Lockfile
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PINNED_COMMIT = "21a1df6abc"
_URL = "https://github.com/example/proptest.git"


def _write_pinned_content(dest):
    """Write the deterministic 'pinned' source tree to dest."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "proptest.nimble").write_text('srcDir = "src"\n')
    (dest / "pinned_marker").write_text("pinned-commit-content")


def _write_tip_content(dest):
    """Write the 'moved tip' source tree to dest (different bytes)."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "proptest.nimble").write_text('srcDir = "src"\n')
    (dest / "tip_marker").write_text("moved-ref-tip-content")


def _compute_pinned_identity(tmp_path) -> str:
    """Compute the real content-hash of the pinned source tree."""
    probe = tmp_path / "_probe"
    _write_pinned_content(probe)
    return compute_content_hash(probe)


class _CommitAwareFetcher:
    """Fake fetcher: writes pinned content when commit_sha==PINNED_COMMIT,
    otherwise writes tip content (simulates the ref tip having moved)."""

    def __init__(self):
        self.calls: list[GitProvenance] = []

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append(p)
        if p.commit_sha == _PINNED_COMMIT:
            _write_pinned_content(dest)
        else:
            _write_tip_content(dest)
        return GitReceipt(commit_sha=p.commit_sha or "tip-sha")


def _prior_lockfile(pinned_identity: str) -> Lockfile:
    return Lockfile(deps=(LockedDep(
        name="proptest",
        identity=pinned_identity,
        version="0.0.1",
        src_dir="",
        requires=(),
        provenances=(GitProvenanceRecord(
            url=_URL,
            ref="main",
            commit_sha=_PINNED_COMMIT,
        ),),
    ),))


def _manifest() -> Manifest:
    return Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="proptest",
            git=_URL,
            ref="main",   # same ref as lockfile — pin should apply
        ),),
    )


# ---------------------------------------------------------------------------
# RED → GREEN test: fetcher is invoked with commit_sha == PINNED_COMMIT
# ---------------------------------------------------------------------------

def test_pinned_commit_is_fetched_not_ref_tip(tmp_path):
    """When the lockfile pins a git dep with commit_sha=C, resolve() MUST
    pass commit_sha=C into the GitProvenance candidate so GitFetcher checks
    out the immutable commit, not the (possibly moved) ref tip.

    The fake fetcher writes distinct content depending on commit_sha:
    - commit_sha==PINNED_COMMIT  → 'pinned' content (identity=PINNED_IDENTITY)
    - commit_sha is None          → 'moved tip' content (different identity)

    If the bug is present: resolver builds GitProvenance(commit_sha=None)
    → tip content fetched → identity mismatch → FETCH-ALL-FAILED.
    If the fix is present: resolver carries pinned commit_sha → pinned content
    → identity matches → success.
    """
    pinned_identity = _compute_pinned_identity(tmp_path)

    stub = _CommitAwareFetcher()
    registry = FetcherRegistry()
    registry.register(stub)

    graph = resolve(
        _manifest(),
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        prior_lockfile=_prior_lockfile(pinned_identity),
    )

    # Resolved successfully with the pinned identity
    dep = next(d for d in graph.deps if d.name == "proptest")
    assert dep.identity == pinned_identity, (
        f"expected pinned identity {pinned_identity!r}, got {dep.identity!r}"
    )

    # The fetcher was called with the pinned commit_sha
    assert stub.calls, "fetcher was never called"
    primary_call = stub.calls[0]
    assert primary_call.commit_sha == _PINNED_COMMIT, (
        f"GitProvenance.commit_sha should be {_PINNED_COMMIT!r}, "
        f"got {primary_call.commit_sha!r} — resolver is fetching the ref "
        f"tip instead of the pinned commit"
    )


# ---------------------------------------------------------------------------
# Guard test: changed ref → commit_sha NOT reused
# ---------------------------------------------------------------------------

def test_changed_ref_does_not_reuse_pinned_commit_sha(tmp_path):
    """User changed manifest ref from 'main' to 'v2'. The lockfile's
    commit_sha for 'main' must NOT be carried into the new fetch —
    the user's intent changed. The fetcher is called with commit_sha=None
    (tip of v2) and any identity is accepted."""

    pinned_identity = _compute_pinned_identity(tmp_path)

    class RefCheckFetcher:
        def __init__(self):
            self.calls: list[GitProvenance] = []

        def can_handle(self, p):
            return isinstance(p, GitProvenance)

        def fetch(self, name, p, *, dest):
            self.calls.append(p)
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            (dest / "v2_content").write_text("v2 bytes")
            return GitReceipt(commit_sha="v2-sha")

    stub = RefCheckFetcher()
    registry = FetcherRegistry()
    registry.register(stub)

    # Manifest now requests ref="v2"
    manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="proptest",
            git=_URL,
            ref="v2",   # CHANGED from lockfile's "main"
        ),),
    )

    # Prior lockfile pinned ref="main" with commit_sha=PINNED_COMMIT
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        prior_lockfile=_prior_lockfile(pinned_identity),
    )

    assert graph.deps[0].name == "proptest"

    # Fetcher was called without the stale commit_sha
    assert stub.calls, "fetcher was never called"
    primary_call = stub.calls[0]
    assert primary_call.commit_sha is None, (
        f"stale commit_sha {primary_call.commit_sha!r} was reused "
        f"after manifest ref changed — resolver must NOT reuse a pin "
        f"when the user's declared ref differs from the locked ref"
    )
    # ref should be the new one
    assert primary_call.ref == "v2"
