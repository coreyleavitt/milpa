"""D-lifecycle tests: multi-provenance emission (observed + declared mirrors).

RFC rfc-content-addressed-identity.md Phase D item 2:
``milpa lock``/``milpa fetch`` must record for EACH dep:
  - ONE observed provenance (the candidate that was fetched + identity-verified).
  - ONE declared provenance per mirror URL (manifest ``mirrors`` + prior declared
    mirrors) that is NOT identical to the observed URL.

Behaviours tested:
  DL-1  git dep with TWO milpa.kdl mirrors, primary fetch succeeds → 3 provenances
        (primary as observed, both mirrors as declared), sorted canonically.
  DL-2  Idempotent: re-lock with same prior lockfile → identical provenances
        (declared mirrors preserved, not duplicated, not dropped).
  DL-3  Promotion: primary fails, first mirror succeeds → that mirror is observed,
        primary + second mirror are declared (tests promotion-via-recompute).
  DL-4  dep with NO mirrors → single observed provenance (regression guard).
  DL-5  declared mirror URL identical to primary URL → no duplicate declared record.
  DL-RT lockfile round-trip: format_lockfile → parse_lockfile preserves full set.

No mocking: real files + injected fake fetcher kwarg (mocked_registry pattern).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.lockfile import (
    GitProvenanceRecord,
    from_graph,
    format_lockfile,
    parse_lockfile,
)
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env(mocked_dir: Path, tmp_path: Path) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


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


def _write_mock_git(
    mocked_dir: Path,
    url: str,
    ref: str,
    dep_name: str,
    *,
    sha: str = "aabbccddeeff",
    extra_files: dict[str, str] | None = None,
) -> None:
    """Write a mocked-fetches git fixture (nimble-based, no milpa.kdl)."""
    key = url_key(url, ref)
    key_dir = mocked_dir / key
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / "sha").write_text(sha, encoding="utf-8")
    # Write a minimal .nimble so the resolver can extract edges.
    (key_dir / f"{dep_name}.nimble").write_text(
        f'version = "1.0.0"\nauthor = "test"\ndescription = "test"\n',
        encoding="utf-8",
    )
    if extra_files:
        for fname, content in extra_files.items():
            fpath = key_dir / fname
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# DL-1: primary succeeds → observed + two declared mirrors
# ---------------------------------------------------------------------------


class TestPrimarySuccessTwoMirrors:
    """DL-1 tracer bullet: dep with 2 mirrors, primary fetch OK → 3 provenances."""

    def test_graph_has_three_provenances(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        mirror1_url = "https://mirror1.example.com/foo.git"
        mirror2_url = "https://mirror2.example.com/foo.git"
        ref = "main"

        # Only primary is available; mirrors have no fixture (so fetcher raises on them).
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="deadbeef")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror1_url, mirror2_url))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        assert len(graph.deps) == 1
        foo = graph.deps[0]
        assert foo.name == "foo"
        provs = foo.provenances
        assert len(provs) == 3, f"expected 3 provenances, got {len(provs)}: {provs}"

    def test_observed_is_primary(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        mirror1_url = "https://mirror1.example.com/foo.git"
        mirror2_url = "https://mirror2.example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="deadbeef")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror1_url, mirror2_url))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        foo = graph.deps[0]
        observed = [p for p in foo.provenances if p.origin == "observed"]
        assert len(observed) == 1
        assert isinstance(observed[0], GitProvenanceRecord)
        assert observed[0].url == primary_url

    def test_mirrors_are_declared(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        mirror1_url = "https://mirror1.example.com/foo.git"
        mirror2_url = "https://mirror2.example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="deadbeef")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror1_url, mirror2_url))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        foo = graph.deps[0]
        declared_urls = {p.url for p in foo.provenances if p.origin == "declared"}
        assert declared_urls == {mirror1_url, mirror2_url}

    def test_provenances_sorted_canonically(self, tmp_path: Path) -> None:
        """format_lockfile sorts provenances: declared < observed in emitted text."""
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        mirror1_url = "https://mirror1.example.com/foo.git"
        mirror2_url = "https://mirror2.example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="deadbeef")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror1_url, mirror2_url))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        # format_lockfile sorts provenances canonically (declared < observed).
        lock = from_graph(graph)
        text = format_lockfile(lock)
        # Parse the emitted text back; the re-parsed provenances are in emission order.
        reparsed = parse_lockfile(text)
        reparsed_foo = next(d for d in reparsed.deps if d.name == "foo")
        provs = reparsed_foo.provenances
        origins = [p.origin for p in provs]
        # All "declared" entries must precede all "observed" entries in the emitted order.
        saw_observed = False
        for o in origins:
            if o == "observed":
                saw_observed = True
            elif saw_observed:
                pytest.fail(f"declared record after observed in emitted provenances: {origins}")

    def test_lockfile_round_trip(self, tmp_path: Path) -> None:
        """format_lockfile → parse_lockfile preserves all provenances with origins."""
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        mirror1_url = "https://mirror1.example.com/foo.git"
        mirror2_url = "https://mirror2.example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="deadbeef")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror1_url, mirror2_url))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        lock = from_graph(graph)
        text = format_lockfile(lock)
        reparsed = parse_lockfile(text)
        reparsed_foo = next(d for d in reparsed.deps if d.name == "foo")
        assert len(reparsed_foo.provenances) == 3
        observed = [p for p in reparsed_foo.provenances if p.origin == "observed"]
        declared = [p for p in reparsed_foo.provenances if p.origin == "declared"]
        assert len(observed) == 1
        assert len(declared) == 2
        assert observed[0].url == primary_url  # type: ignore[union-attr]
        declared_urls = {p.url for p in declared}  # type: ignore[union-attr]
        assert declared_urls == {mirror1_url, mirror2_url}


# ---------------------------------------------------------------------------
# DL-2: Idempotency — re-lock with same prior lockfile
# ---------------------------------------------------------------------------


class TestIdempotency:
    """DL-2: re-locking with prior lockfile preserves declared provenances."""

    def test_re_lock_same_provenances(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        mirror_url = "https://mirror.example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="deadbeef")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror_url,))

        # First lock.
        graph1 = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())
        lock1 = from_graph(graph1)

        # Second lock with prior = lock1.
        graph2 = resolve(
            _manifest([dep]),
            deps_dir=tmp_path / "_deps",
            env=env,
            params=ResolveParams(prior=lock1),
        )
        lock2 = from_graph(graph2)

        foo1 = next(d for d in lock1.deps if d.name == "foo")
        foo2 = next(d for d in lock2.deps if d.name == "foo")

        # Same number of provenances.
        assert len(foo1.provenances) == len(foo2.provenances), (
            f"first lock has {len(foo1.provenances)} provenances, "
            f"second has {len(foo2.provenances)}"
        )
        # Same origins.
        assert sorted(p.origin for p in foo1.provenances) == sorted(p.origin for p in foo2.provenances)

    def test_declared_not_duplicated(self, tmp_path: Path) -> None:
        """Prior declared mirror must not accumulate duplicates across locks."""
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        mirror_url = "https://mirror.example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="deadbeef")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror_url,))

        # First lock.
        graph1 = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())
        lock1 = from_graph(graph1)

        # Second lock with prior = lock1 (mirror already in prior as declared).
        graph2 = resolve(
            _manifest([dep]),
            deps_dir=tmp_path / "_deps",
            env=env,
            params=ResolveParams(prior=lock1),
        )
        lock2 = from_graph(graph2)

        foo2 = next(d for d in lock2.deps if d.name == "foo")
        # Should be 2 total: 1 observed + 1 declared. Not 3 (not duplicated).
        assert len(foo2.provenances) == 2, (
            f"expected 2 provenances (no dup), got {len(foo2.provenances)}: {foo2.provenances}"
        )


# ---------------------------------------------------------------------------
# DL-3: Promotion — primary fails, first mirror succeeds
# ---------------------------------------------------------------------------


class TestPromotion:
    """DL-3: mirror fetch succeeds when primary fails → mirror is observed."""

    def test_mirror_becomes_observed(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://primary.example.com/foo.git"
        mirror_url = "https://mirror.example.com/foo.git"
        ref = "main"
        # Only mirror is available; primary has no fixture.
        _write_mock_git(mocked_dir, mirror_url, ref, "foo", sha="cafebabe")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror_url,))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        foo = graph.deps[0]
        observed = [p for p in foo.provenances if p.origin == "observed"]
        declared = [p for p in foo.provenances if p.origin == "declared"]
        assert len(observed) == 1
        assert observed[0].url == mirror_url, f"expected mirror as observed, got {observed[0].url}"
        assert len(declared) == 1
        assert declared[0].url == primary_url, f"expected primary as declared, got {declared[0].url}"

    def test_promotion_three_candidates(self, tmp_path: Path) -> None:
        """Two mirrors; primary fails; first mirror fails; second mirror succeeds."""
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://primary.example.com/foo.git"
        mirror1_url = "https://mirror1.example.com/foo.git"
        mirror2_url = "https://mirror2.example.com/foo.git"
        ref = "main"
        # Only mirror2 is available.
        _write_mock_git(mocked_dir, mirror2_url, ref, "foo", sha="cafebabe")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror1_url, mirror2_url))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        foo = graph.deps[0]
        observed = [p for p in foo.provenances if p.origin == "observed"]
        declared = [p for p in foo.provenances if p.origin == "declared"]
        assert len(observed) == 1
        assert observed[0].url == mirror2_url
        declared_urls = {p.url for p in declared}
        assert declared_urls == {primary_url, mirror1_url}


# ---------------------------------------------------------------------------
# DL-4: No mirrors → single observed provenance
# ---------------------------------------------------------------------------


class TestNoMirrors:
    """DL-4: dep with no mirrors emits exactly one observed provenance."""

    def test_single_observed_provenance(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="11223344")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref)  # no mirrors
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        foo = graph.deps[0]
        assert len(foo.provenances) == 1
        assert foo.provenances[0].origin == "observed"

    def test_lockfile_has_single_provenance(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="11223344")

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref)
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        lock = from_graph(graph)
        foo = next(d for d in lock.deps if d.name == "foo")
        assert len(foo.provenances) == 1
        assert foo.provenances[0].origin == "observed"


# ---------------------------------------------------------------------------
# DL-5: Declared mirror URL equal to primary → no duplicate declared record
# ---------------------------------------------------------------------------


class TestMirrorDuplicatePrimary:
    """DL-5: mirror URL == primary URL produces only observed (no duplicate declared)."""

    def test_no_duplicate_declared(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        primary_url = "https://example.com/foo.git"
        ref = "main"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="aabbcc")

        env = _make_env(mocked_dir, tmp_path)
        # Mirror URL is the same as primary — must not produce a duplicate.
        dep = _url_dep("foo", primary_url, ref, mirrors=(primary_url,))
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=ResolveParams())

        foo = graph.deps[0]
        # Exactly 1 provenance (the observed one); the duplicate declared is deduped.
        assert len(foo.provenances) == 1
        assert foo.provenances[0].origin == "observed"
        assert foo.provenances[0].url == primary_url  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# DL-6: mirror-sorts-first bug regression (Fix R1-4)
#
# When the prior lockfile has a declared mirror record that sorts BEFORE the
# observed record (D-provenance canonical sort: declared < observed by origin
# rank), _git_pin_for_url_dep must still find the observed URL's pin.  The
# old code took the first GitProvenanceRecord regardless of URL match — so
# if a declared mirror URL sorted first, the primary URL's pin was lost and
# the dep was refetched unnecessarily.
# ---------------------------------------------------------------------------


class TestMirrorSortsFirstPinStillReused:
    """Prior lockfile has declared mirror sorting before observed → pin still reused.

    R1-4 regression: the old ``_git_pin_for_url_dep`` took the first
    ``GitProvenanceRecord`` regardless of URL.  When a declared mirror record
    sorts before the observed primary record (D-provenance canonical sort:
    origin="declared" < "observed"), the primary URL's pin was silently dropped.
    """

    def test_pin_reused_when_mirror_declared_sorts_first(self, tmp_path: Path) -> None:
        """Re-lock with a prior that has declared mirror before observed:
        the commit_sha from the observed primary record must be passed to the
        fetcher (pin reuse), not discarded because a mirror record sorted first.
        """
        from milpa.lockfile import Lockfile, LockedDep, GitProvenanceRecord as GPR
        from milpa.identity import compute_content_hash

        primary_url = "https://primary.example.com/foo.git"
        mirror_url = "https://mirror.example.com/foo.git"
        ref = "main"

        # Mock: primary URL is fetchable and delivers a fixed tree.
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_git(mocked_dir, primary_url, ref, "foo", sha="pinnedcommit01")

        # Compute the identity of the tree that the mocked fetcher delivers.
        # (The mocked fetcher stages foo.nimble into dest; compute_content_hash
        # over that tree gives us the canonical identity to put in the prior lock.)
        import tempfile
        import shutil
        from milpa.fetchers.mocked import url_key as _url_key
        _key_dir = mocked_dir / _url_key(primary_url, ref)
        with tempfile.TemporaryDirectory() as _staging:
            _dest = Path(_staging) / "foo"
            _dest.mkdir()
            _nimble = _key_dir / "foo.nimble"
            if _nimble.is_file():
                shutil.copy2(_nimble, _dest / "foo.nimble")
            _content = _key_dir / "content"
            if _content.is_dir():
                for _src in _content.rglob("*"):
                    if _src.is_file():
                        _rel = _src.relative_to(_content)
                        (_dest / _rel).parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(_src, _dest / _rel)
            pinned_identity = compute_content_hash(_dest)

        # Construct a prior lockfile where the declared mirror sorts BEFORE the
        # observed primary (canonical sort: origin="declared" < "observed").
        prior_lock = Lockfile(
            version=1,
            strategy="maxver",
            deps=(
                LockedDep(
                    name="foo",
                    identity=pinned_identity,
                    version="0.0.1",
                    src_dir="",
                    requires=(),
                    provenances=(
                        # declared mirror sorts first (origin="declared" < "observed")
                        GPR(url=mirror_url, ref=ref, commit_sha=None, origin="declared"),
                        # observed primary sorts second
                        GPR(url=primary_url, ref=ref, commit_sha="pinnedcommit01", origin="observed"),
                    ),
                    active_flags=(),
                    dep_decl=None,
                    cond_requires=(),
                    aliases=(),
                ),
            ),
        )

        env = _make_env(mocked_dir, tmp_path)
        dep = _url_dep("foo", primary_url, ref, mirrors=(mirror_url,))
        params = ResolveParams(prior=prior_lock)
        graph = resolve(_manifest([dep]), deps_dir=tmp_path / "_deps", env=env, params=params)

        assert len(graph.deps) == 1
        foo = graph.deps[0]
        # Identity must match the pinned value.
        assert foo.identity == pinned_identity, (
            f"expected pinned identity {pinned_identity!r}, got {foo.identity!r}"
        )
        # The observed provenance must have pinnedcommit01 (from pin).
        observed = [p for p in foo.provenances if p.origin == "observed"]
        assert len(observed) == 1
        assert isinstance(observed[0], GitProvenanceRecord)
        assert observed[0].commit_sha == "pinnedcommit01", (
            f"expected pinned commit_sha 'pinnedcommit01', got {observed[0].commit_sha!r}"
        )
