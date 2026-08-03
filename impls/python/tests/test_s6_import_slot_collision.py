"""S6 (rfc-origin-as-identity.md §4.6/§10) — the v1 directory-slot import
floor: ``check_directory_slot_collisions`` + ``RES-IMPORT-COLLISION``.

Two distinct origins that would materialize into the same ``_deps/<slot>/``
directory cannot coexist unless their bytes are proven identical.

Coverage:
1. Pure-function tests (``check_directory_slot_collisions`` called directly on
   hand-built ``ResolvedDep``s) — the raise/no-raise/short-circuit/None-identity
   branches. These exercise states the LIVE resolve() pipeline structurally
   cannot reach today (``BindingResolver`` already prevents two origins from
   sharing one label pre-fetch, and S4b's own dedup already folds any same-
   content pair together before this function runs) — see the function's
   docstring in ``lockfile.py``. Testing the pure function directly is the
   only way to exercise its raise/short-circuit logic in isolation.
2. Frozen-path wiring tests (``resolve_frozen``) — the REAL exposure window
   (RFC §10 S6 "F4"): a hand-edited/corrupted lockfile has no BindingResolver
   protecting it, so two ``dep "foo"`` entries with the identical name can
   coexist on disk with nothing to stop them pre-S6.
3. fixture-458's shape does NOT raise through the live resolve() pipeline —
   the content_hash short-circuit's regression guard for milpa's own
   cross-origin-identity edge (§3.3).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import RES_IMPORT_COLLISION, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.frozen import resolve_frozen
from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
    ResolvedDep,
    ResolvedGraph,
    check_directory_slot_collisions,
)
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve
from milpa.source_id import GitSourceId, OciSourceId, normalize_source

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dep(
    name: str,
    identity: str | None,
    *,
    source_id: object | None = None,
    url: str = "https://example.com/x.git",
    namespace: str | None = None,
) -> ResolvedDep:
    return ResolvedDep(
        name=name,
        identity=identity,
        version="0.0.1",
        src_dir="src",
        requires=(),
        provenances=(GitProvenanceRecord(url=url),),
        namespace=namespace,
        source_id=source_id,
    )


_HASH_A = "sha256:" + "a" * 64
_HASH_B = "sha256:" + "b" * 64


# ---------------------------------------------------------------------------
# 1. Pure-function tests
# ---------------------------------------------------------------------------


class TestRaisesOnDifferentContent:
    """Same slot, distinct source-ids, DIFFERENT content_hash → raises."""

    def test_raises_res_import_collision(self) -> None:
        a = _dep(
            "foo",
            _HASH_A,
            source_id=normalize_source(GitSourceId(url="https://example.com/a.git")),
            url="https://example.com/a.git",
        )
        b = _dep(
            "foo",
            _HASH_B,
            source_id=normalize_source(OciSourceId(registry="reg.example.com", repository="foo")),
            url="https://example.com/b.git",
        )
        graph = ResolvedGraph(deps=(a, b))

        with pytest.raises(MilpaError) as exc_info:
            check_directory_slot_collisions(graph)
        assert exc_info.value.slug == RES_IMPORT_COLLISION

    def test_message_names_both_origins(self) -> None:
        a = _dep(
            "foo", _HASH_A,
            source_id=normalize_source(GitSourceId(url="https://example.com/a.git")),
        )
        b = _dep(
            "foo", _HASH_B,
            source_id=normalize_source(GitSourceId(url="https://example.com/b.git")),
        )
        graph = ResolvedGraph(deps=(a, b))

        with pytest.raises(MilpaError) as exc_info:
            check_directory_slot_collisions(graph)
        msg = str(exc_info.value)
        # normalize_source strips the trailing ".git" — assert on the host+path.
        assert "example.com/a" in msg
        assert "example.com/b" in msg
        assert "foo" in msg

    def test_message_carries_the_partial_check_caveat(self) -> None:
        """RFC §4.6/G9: the diagnostic MUST carry the durable "directory-slot
        only, not full import collision" caveat — a CI gate keyed on this
        slug alone must not read silence as a general all-clear."""
        a = _dep("foo", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("foo", _HASH_B, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))

        with pytest.raises(MilpaError) as exc_info:
            check_directory_slot_collisions(graph)
        msg = str(exc_info.value)
        assert "directory slot" in msg or "directory-slot" in msg
        assert "symbol" in msg


class TestContentHashShortCircuit:
    """Same slot, distinct source-ids, SAME content_hash → does NOT raise.

    This is the exact fixture-458 shape (a RegistrySourceId and a GitSourceId
    fetching byte-identical trees) — milpa's §3.3 edge over Cargo. It MUST
    NOT false-positive.
    """

    def test_no_raise_when_identity_matches(self) -> None:
        a = _dep(
            "chronos", _HASH_A,
            source_id=normalize_source(GitSourceId(url="https://example.com/chronos.git")),
        )
        b = _dep(
            "chronos", _HASH_A,  # SAME identity as a — proven byte-identical
            source_id=normalize_source(GitSourceId(url="https://example.com/chronos-fork.git")),
        )
        graph = ResolvedGraph(deps=(a, b))

        check_directory_slot_collisions(graph)  # must not raise

    def test_three_way_same_identity_no_raise(self) -> None:
        """Group size > 2, all sharing one slot and one identity, also
        short-circuits cleanly (not just the pairwise case)."""
        deps = tuple(
            _dep("shared", _HASH_A, source_id=normalize_source(GitSourceId(url=f"https://example.com/{n}.git")))
            for n in ("x", "y", "z")
        )
        graph = ResolvedGraph(deps=deps)

        check_directory_slot_collisions(graph)  # must not raise


class TestNoneIdentityIsNotProvenEqual:
    """A missing identity (content_hash absent) can never be proven equal to
    another dep's identity — the short-circuit must NOT fire just because
    both happen to be ``None`` (that is "unknown", not "proven identical")."""

    def test_both_none_identity_raises(self) -> None:
        a = _dep("foo", None, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("foo", None, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))

        with pytest.raises(MilpaError) as exc_info:
            check_directory_slot_collisions(graph)
        assert exc_info.value.slug == RES_IMPORT_COLLISION

    def test_one_none_one_real_raises(self) -> None:
        a = _dep("foo", None, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("foo", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))

        with pytest.raises(MilpaError):
            check_directory_slot_collisions(graph)


class TestNoCollisionOrdinaryGraph:
    """A normal, non-colliding graph never raises."""

    def test_distinct_slots_no_raise(self) -> None:
        a = _dep("foo", _HASH_A, source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("bar", _HASH_B, source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))

        check_directory_slot_collisions(graph)  # must not raise

    def test_namespace_disambiguates_bare_name_collision(self) -> None:
        """Two deps named 'baz' in DIFFERENT namespaces project to distinct
        ``_deps/@ns/baz`` slots (dep_dir_name's own collision-free design) —
        never a false positive."""
        a = _dep("baz", _HASH_A, namespace="ns1", source_id=normalize_source(GitSourceId(url="https://example.com/a.git")))
        b = _dep("baz", _HASH_B, namespace="ns2", source_id=normalize_source(GitSourceId(url="https://example.com/b.git")))
        graph = ResolvedGraph(deps=(a, b))

        check_directory_slot_collisions(graph)  # must not raise

    def test_single_dep_no_raise(self) -> None:
        graph = ResolvedGraph(deps=(_dep("foo", _HASH_A),))
        check_directory_slot_collisions(graph)


# ---------------------------------------------------------------------------
# 2. Frozen-path wiring (RFC §10 S6 "F4" — no deferral)
# ---------------------------------------------------------------------------


def _make_env_with_tree(tmp_path: Path) -> tuple[MilpaEnv, str]:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "foo.nim").write_text("# minimal nim source\n", encoding="utf-8")
    from milpa.identity import compute_content_hash

    identity = compute_content_hash(seed)
    store.admit(seed, identity)
    return MilpaEnv(fetcher=None, index=None, store=store), identity  # type: ignore[arg-type]


def _manifest_with_dep(name: str) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=[
            UrlDep(
                name=name,
                git=f"https://example.com/{name}.git",
                ref="main",
                mirrors=[],
                predicates=[],
                flag_requests=[],
            )
        ],
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _locked_dep(name: str, identity: str | None, url: str) -> LockedDep:
    return LockedDep(
        name=name,
        identity=identity,
        version="0.0.1",
        src_dir="src",
        requires=(),
        provenances=(GitProvenanceRecord(url=url),),
    )


class TestFrozenPathReachability:
    """The floor runs on the frozen path TOO, with no new source_id plumbing
    needed in frozen.py (see check_directory_slot_collisions's docstring for
    why: it needs only .name/.namespace/.identity, all already present on a
    frozen-reconstructed ResolvedDep). No deferral to S5."""

    def test_frozen_raises_on_hand_edited_lockfile_slot_collision(self, tmp_path: Path) -> None:
        """A lockfile with two 'foo' entries at different content — nothing a
        real `milpa fetch` would ever produce (BindingResolver prevents it
        pre-fetch), but a hand-edited/corrupted lockfile has no such guard on
        the frozen path. The floor must catch it here."""
        env, _identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked_a = _locked_dep("foo", None, "https://example.com/a.git")
        locked_b = _locked_dep("foo", None, "https://example.com/b.git")
        lockfile = Lockfile(deps=(locked_a, locked_b), strategy="maxver")
        manifest = _manifest_with_dep("foo")

        with pytest.raises(MilpaError) as exc_info:
            resolve_frozen(manifest, lockfile, env, deps_dir)
        assert exc_info.value.slug == RES_IMPORT_COLLISION

    def test_frozen_no_raise_when_identity_matches(self, tmp_path: Path) -> None:
        """Same slot, same (real, CAS-verified) identity — the short-circuit
        holds on the frozen path too; resolve_frozen must succeed."""
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked_a = _locked_dep("foo", identity, "https://example.com/a.git")
        locked_b = _locked_dep("foo", identity, "https://example.com/b.git")
        lockfile = Lockfile(deps=(locked_a, locked_b), strategy="maxver")
        manifest = _manifest_with_dep("foo")

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)
        assert len(graph.deps) == 2


# ---------------------------------------------------------------------------
# 3. fixture-458's shape does not raise through the LIVE resolve() pipeline
# ---------------------------------------------------------------------------


def _make_live_env(mocked_dir: Path, tmp_path: Path) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _write_mock_fetch_milpa_kdl(
    mocked_dir: Path, url: str, ref: str, kdl_body: str, sha: str,
) -> None:
    import re

    def _safe(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", s)

    fetch_dir = mocked_dir / f"{_safe(url)}@{_safe(ref)}"
    content_dir = fetch_dir / "content"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "milpa.kdl").write_text(kdl_body, encoding="utf-8")
    (fetch_dir / "sha").write_text(sha, encoding="utf-8")


class TestLiveResolveNeverFalsePositives:
    """The S6 wiring into resolve() must not false-positive on the exact
    cross-origin-identical-bytes shape fixture-458 pins."""

    def test_two_url_deps_identical_bytes_no_collision_raised(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        shared_kdl = 'name "shared"\nkind "library"\nsrc_dir "src"\n'
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/foo.git", "main", shared_kdl, "sha1")
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/bar.git", "main", shared_kdl, "sha2")

        env = _make_live_env(mocked_dir, tmp_path)
        m = Manifest(
            name="testapp",
            kind="application",
            src_dir="",
            deps=[
                UrlDep(name="foo", git="https://example.com/foo.git", ref="main", mirrors=[], predicates=[], flag_requests=[]),
                UrlDep(name="bar", git="https://example.com/bar.git", ref="main", mirrors=[], predicates=[], flag_requests=[]),
            ],
            dev_deps=[],
            overrides=[],
            flags=[],
            self_mirrors=[],
            cas_dir="",
            spec_version=1,
            spec_version_explicit=False,
            attestation_policy=None,
        )
        deps_dir = tmp_path / "_deps"

        # Must not raise RES-IMPORT-COLLISION — S4b's own dedup already
        # collapses this pair before check_directory_slot_collisions runs.
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())
        assert len(graph.deps) == 1
