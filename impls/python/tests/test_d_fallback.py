"""D-fallback tests: provenance fallback distinguishes transport-failure from
identity-divergence (RFC rfc-content-addressed-identity.md Phase D item 3).

Acceptance criteria:
  DF-1  Primary transport-fails, mirror succeeds with CORRECT identity →
        resolve succeeds, mirror becomes observed (transport-failure fell
        through to next candidate).  Tracer bullet.

  DF-2  Primary fetch SUCCEEDS but returns WRONG identity (≠ prior-locked
        identity) → resolve RAISES FETCH-PROVENANCE-DIVERGENCE immediately;
        the mirror is NOT tried.  Load-bearing acceptance test.
        Verifies: fake fetcher was NOT called for mirror after divergence.

  DF-3  ALL candidates transport-fail → FETCH-ALL-FAILED (preserved behavior).

  DF-4  Fresh resolve, no prior pin, first candidate succeeds → no divergence
        check, adopted as observed.  Regression guard.

Implementation note: a programmable fake fetcher is injected via kwarg into
resolve().  It handles real GitProvenance objects (from milpa.fetchers.git)
and records calls so we can assert the mirror was NOT contacted after a
divergence.  NO unittest.mock.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import FETCH_ALL_FAILED, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.fetchers.types import (
    FetchError,
    Fetcher,
    FetcherRegistry,
    Provenance,
)
from milpa.lockfile import GitProvenanceRecord, Lockfile, LockedDep
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve


# ---------------------------------------------------------------------------
# Programmable fake fetcher
#
# Handles real GitProvenance objects (the type the resolver builds).
# Per-URL behaviour is configured via an outcomes dict at construction.
# Tracks which URLs were contacted in order (self.calls).
# ---------------------------------------------------------------------------


class _ProgrammableFetcher(Fetcher):
    """Fake git fetcher whose per-URL behaviour is fully configurable.

    outcomes: {url: ("transport_fail", None)}
           or {url: ("success", nimble_body_str)}

    Handles real GitProvenance objects — no custom provenance subclass.
    Tracks contacted URLs in self.calls.
    """

    def __init__(
        self,
        outcomes: dict[str, tuple[str, str | None]],
        dep_name: str,
    ) -> None:
        # outcomes: url → ("transport_fail", None) | ("success", nimble_body)
        self._outcomes = outcomes
        self._dep_name = dep_name
        self.calls: list[str] = []

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, GitProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> GitReceipt:
        assert isinstance(p, GitProvenance)
        self.calls.append(p.url)
        kind, body = self._outcomes.get(p.url, ("transport_fail", None))
        if kind == "transport_fail":
            raise MilpaError(
                "FETCH-GIT-FAILED",
                f"simulated transport failure for {p.url!r}",
                dep=name,
                url=p.url,
            )
        # success: write nimble body so identity is deterministic
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(body or "", encoding="utf-8")
        return GitReceipt(commit_sha="deadbeef")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_env(fetcher: _ProgrammableFetcher, tmp_path: Path) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    registry = FetcherRegistry()
    registry.register(fetcher)
    cas_fetcher = CasAdmittingFetcher(registry, store)
    return MilpaEnv(fetcher=cas_fetcher, index=None, store=store)


def _manifest(deps: list[UrlDep]) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=list(deps),
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _url_dep(name: str, url: str, ref: str = "main", mirrors: tuple[str, ...] = ()) -> UrlDep:
    return UrlDep(
        name=name,
        git=url,
        ref=ref,
        mirrors=mirrors,
        predicates=[],
        flag_requests=[],
    )


def _compute_identity(dep_name: str, nimble_body: str, tmp_path: Path) -> str:
    """Compute the content hash of a tree containing one nimble file."""
    from milpa.identity import compute_content_hash
    d = tmp_path / "_id_probe"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{dep_name}.nimble").write_text(nimble_body, encoding="utf-8")
    return compute_content_hash(d)


def _prior_with_identity(dep_name: str, url: str, identity: str) -> Lockfile:
    """Build a minimal prior lockfile pinning dep_name to the given identity."""
    return Lockfile(
        version=1,
        strategy="maxver",
        deps=[LockedDep(
            name=dep_name,
            identity=identity,
            version="0.0.1",
            src_dir="",
            requires=[],
            provenances=[GitProvenanceRecord(
                url=url,
                ref="main",
                commit_sha=None,
                origin="observed",
            )],
            active_flags=[],
            dep_decl=None,
            cond_requires=[],
            aliases=[],
        )],
    )


# ---------------------------------------------------------------------------
# DF-1: primary transport-fails, mirror succeeds → mirror becomes observed
# ---------------------------------------------------------------------------

PRIMARY = "https://primary.example.com/foo.git"
MIRROR = "https://mirror.example.com/foo.git"
NIMBLE_BODY = 'version = "1.0.0"\nauthor = "a"\ndescription = "d"\n'


class TestDF1TransportFallThrough:
    """DF-1 tracer: primary dead-mirror, backup succeeds → success, mirror observed."""

    def _fetcher(self) -> _ProgrammableFetcher:
        return _ProgrammableFetcher(
            outcomes={
                PRIMARY: ("transport_fail", None),
                MIRROR: ("success", NIMBLE_BODY),
            },
            dep_name="foo",
        )

    def test_resolve_succeeds(self, tmp_path: Path) -> None:
        fetcher = self._fetcher()
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY, mirrors=(MIRROR,))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())
        assert len(graph.deps) == 1
        assert graph.deps[0].name == "foo"

    def test_mirror_becomes_observed(self, tmp_path: Path) -> None:
        fetcher = self._fetcher()
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY, mirrors=(MIRROR,))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        foo = graph.deps[0]
        observed = [p for p in foo.provenances if p.origin == "observed"]
        assert len(observed) == 1
        assert observed[0].url == MIRROR  # type: ignore[union-attr]

    def test_primary_contacted_then_mirror(self, tmp_path: Path) -> None:
        """Fetcher sees primary first, then mirror — transport-failure fell through."""
        fetcher = self._fetcher()
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY, mirrors=(MIRROR,))
        resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())
        assert fetcher.calls == [PRIMARY, MIRROR]


# ---------------------------------------------------------------------------
# DF-2: primary SUCCEEDS but returns WRONG identity → FETCH-PROVENANCE-DIVERGENCE
#        mirror must NOT be tried
# ---------------------------------------------------------------------------

CORRECT_NIMBLE = 'version = "1.0.0"\nauthor = "correct"\ndescription = "d"\n'
WRONG_NIMBLE = 'version = "9.9.9"\nauthor = "attacker"\ndescription = "d"\n'


class TestDF2DivergenceRaisedImmediately:
    """DF-2 load-bearing: divergent bytes from a successful fetch → loud error, no try-next."""

    def test_raises_provenance_divergence(self, tmp_path: Path) -> None:
        """Primary delivers wrong bytes against a locked identity → FETCH-PROVENANCE-DIVERGENCE."""
        correct_identity = _compute_identity("foo", CORRECT_NIMBLE, tmp_path)

        fetcher = _ProgrammableFetcher(
            outcomes={
                PRIMARY: ("success", WRONG_NIMBLE),   # wrong bytes!
                MIRROR: ("success", CORRECT_NIMBLE),  # never reached
            },
            dep_name="foo",
        )
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY, mirrors=(MIRROR,))
        prior = _prior_with_identity("foo", PRIMARY, correct_identity)

        with pytest.raises(MilpaError) as exc_info:
            resolve(
                _manifest([dep]),
                deps_dir=tmp_path / "_deps",
                env=env,
                params=ResolveParams(prior=prior),
            )
        assert exc_info.value.slug == "FETCH-PROVENANCE-DIVERGENCE"

    def test_mirror_not_tried_after_divergence(self, tmp_path: Path) -> None:
        """After divergence, the resolver MUST NOT fall through to the mirror."""
        correct_identity = _compute_identity("foo", CORRECT_NIMBLE, tmp_path)

        fetcher = _ProgrammableFetcher(
            outcomes={
                PRIMARY: ("success", WRONG_NIMBLE),
                MIRROR: ("success", CORRECT_NIMBLE),
            },
            dep_name="foo",
        )
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY, mirrors=(MIRROR,))
        prior = _prior_with_identity("foo", PRIMARY, correct_identity)

        with pytest.raises(MilpaError) as exc_info:
            resolve(
                _manifest([dep]),
                deps_dir=tmp_path / "_deps",
                env=env,
                params=ResolveParams(prior=prior),
            )
        assert exc_info.value.slug == "FETCH-PROVENANCE-DIVERGENCE"
        # Mirror URL must NOT have been contacted.
        assert MIRROR not in fetcher.calls, (
            f"mirror was contacted after primary diverged — divergence must not fall through; "
            f"calls: {fetcher.calls}"
        )

    def test_divergence_context_carries_expected_and_got(self, tmp_path: Path) -> None:
        """Error context must carry the expected and observed (wrong) identity."""
        correct_identity = _compute_identity("foo", CORRECT_NIMBLE, tmp_path)

        fetcher = _ProgrammableFetcher(
            outcomes={PRIMARY: ("success", WRONG_NIMBLE)},
            dep_name="foo",
        )
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY)
        prior = _prior_with_identity("foo", PRIMARY, correct_identity)

        with pytest.raises(MilpaError) as exc_info:
            resolve(
                _manifest([dep]),
                deps_dir=tmp_path / "_deps",
                env=env,
                params=ResolveParams(prior=prior),
            )
        err = exc_info.value
        assert err.slug == "FETCH-PROVENANCE-DIVERGENCE"
        # Context carries expected + got for human diagnostics.
        ctx = err.context
        assert "expected" in ctx or "expected_identity" in ctx, (
            f"error context should carry expected identity; context={ctx}"
        )
        assert "got" in ctx or "got_identity" in ctx, (
            f"error context should carry observed identity; context={ctx}"
        )


# ---------------------------------------------------------------------------
# DF-3: ALL candidates transport-fail → FETCH-ALL-FAILED (preserved)
# ---------------------------------------------------------------------------


class TestDF3AllTransportFail:
    """DF-3: all candidates die on transport → FETCH-ALL-FAILED (no change)."""

    def test_all_failed_raised(self, tmp_path: Path) -> None:
        fetcher = _ProgrammableFetcher(
            outcomes={
                PRIMARY: ("transport_fail", None),
                MIRROR: ("transport_fail", None),
            },
            dep_name="foo",
        )
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY, mirrors=(MIRROR,))

        with pytest.raises(MilpaError) as exc_info:
            resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())
        assert exc_info.value.slug == FETCH_ALL_FAILED

    def test_both_candidates_contacted(self, tmp_path: Path) -> None:
        """Both candidates must be tried before giving up on transport failure."""
        fetcher = _ProgrammableFetcher(
            outcomes={
                PRIMARY: ("transport_fail", None),
                MIRROR: ("transport_fail", None),
            },
            dep_name="foo",
        )
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY, mirrors=(MIRROR,))

        with pytest.raises(MilpaError):
            resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())
        assert PRIMARY in fetcher.calls
        assert MIRROR in fetcher.calls


# ---------------------------------------------------------------------------
# DF-4: fresh resolve, no prior pin, first candidate succeeds → no identity check
# ---------------------------------------------------------------------------


class TestDF4FreshResolveNoPrior:
    """DF-4 regression: no prior lock → no identity gate, first success adopted."""

    def test_fresh_resolve_succeeds(self, tmp_path: Path) -> None:
        fetcher = _ProgrammableFetcher(
            outcomes={PRIMARY: ("success", NIMBLE_BODY)},
            dep_name="foo",
        )
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY)
        graph = resolve(
            _manifest([dep]),
            deps_dir=tmp_path / "_deps",
            env=env,
            params=ResolveParams(),
        )
        assert len(graph.deps) == 1
        assert graph.deps[0].name == "foo"

    def test_fresh_resolve_adopts_first_candidate(self, tmp_path: Path) -> None:
        fetcher = _ProgrammableFetcher(
            outcomes={PRIMARY: ("success", NIMBLE_BODY)},
            dep_name="foo",
        )
        env = _make_env(fetcher, tmp_path)
        dep = _url_dep("foo", PRIMARY)
        graph = resolve(
            _manifest([dep]),
            deps_dir=tmp_path / "_deps",
            env=env,
            params=ResolveParams(),
        )
        foo = graph.deps[0]
        observed = [p for p in foo.provenances if p.origin == "observed"]
        assert len(observed) == 1
        assert observed[0].url == PRIMARY  # type: ignore[union-attr]
