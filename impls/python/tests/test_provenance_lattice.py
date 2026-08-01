"""#193 (resolver-semantics.md §10.0 — the three-tier provenance authority
lattice), end to end through ``resolve()``, plus direct unit tests of the
tier-aware gate AND the registry-validation mechanism.

Authority tiers (§10.0 NORMATIVE):
    Tier 1 (highest)  Root      — root/member deps + dev-deps + overrides.
    Tier 2            Registry — a ``named``/index claim (tianguis).
    Tier 3 (lowest)   Self-URL — a transitive git=/local=/tarball= claim.

A higher tier suppresses a lower-tier DISAGREEMENT (two claims for the same
non-root name with different provenance keys), deterministically and without
error. ``RES-PROVENANCE-CONFLICT`` fires only for a disagreement WITHIN the
untrusted tier-3 tier, and only when no tier-2 claim exists for that name.

**Design revision (validate-against-registry, resolver-semantics.md §10.0/
§10.3 as revised):** the registry is a TRUSTED DEFAULT, not an explicit
per-build choice. For a non-root name present in the registry index, a
transitive self-declared ``git=``/``tarball=`` claim is VALIDATED against the
registry's recorded source for the name:
  - AGREES (same git repository the registry records — a differing ``ref``
    is still agreement, the ref only selects a version) → the claim is
    ACCEPTED and resolves normally, exactly like an ordinary tier-3 url dep
    (it is fetched; content-hash dedup / ordinary solver version-negotiation
    reconciles it with any registry-version candidate for the same name).
    This SUPERSEDES the prior "membership-based redirect" design (a lone
    agreeing url pin is no longer silently redirected to the registry — it
    is accepted AS ITSELF).
  - DISAGREES (a different source repository, or an incomparable transport,
    e.g. this git= claim against an OCI-only registry entry) → the resolver
    raises ``RES-PROVENANCE-CONFLICT`` — even for a LONE disagreeing claim,
    with no competing claim anywhere else in the graph (this is the
    headline behavioral change from the old disagreement-only design: a
    transitive can no longer silently substitute a registry name's source,
    nor can it silently redirect to the registry against the transitive's
    own wishes).

This file's resolver-level scenarios exercise BOTH BFS discovery orderings
(the ordering the mechanism must not be sensitive to, per §10.5) and prove
the validation is a static, per-claim decision, never dependent on which
other claims exist or when they are discovered.

``tests/test_provenance_gate.py`` already covers the pre-#193 tier-3-vs-
tier-3 shape (fixture-099) with real declared-version data; this file adds
the registry (tier-2) validation dimension, plus a regression pin that the
tier-3-vs-tier-3 case (no registry entry at all) still conflicts.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import MilpaError, RES_PROVENANCE_CONFLICT
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import ResolvedGraph
from milpa.manifest import parse_manifest
from milpa.registry import (
    GitIndexProvenance,
    IndexVersion,
    OciIndexProvenance,
    Package,
    parse_index,
)
from milpa.resolver import (
    TIER_REGISTRY,
    TIER_ROOT,
    TIER_SELF_URL,
    _check_provenance_gate,
    _NAMED_PKEY,
    _normalize_git_source_url,
    _validate_transitive_url_against_registry,
    resolve,
)


# ---------------------------------------------------------------------------
# Shared staging helpers
# ---------------------------------------------------------------------------


def _stage(mocked_dir: Path, url: str, ref: str, *, sha: str, kdl: str | None = None, marker: str = "x") -> None:
    """Stage one ``mocked-fetches/<url_key>/`` dir. ``kdl`` (a milpa.kdl body)
    is optional — a leaf package with no further deps just gets a marker
    ``.nim`` file so its content hash is distinct per ``marker``."""
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / "marker.nim").write_text(f"# {marker}\n", encoding="utf-8")
    if kdl is not None:
        (content / "milpa.kdl").write_text(kdl, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")


def _content_hash_for(mocked_dir: Path, url: str, ref: str) -> str:
    key_dir = mocked_dir / url_key(url, ref)
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td)
        content = key_dir / "content"
        for src in content.rglob("*"):
            if src.is_file():
                rel = src.relative_to(content)
                tgt = dest / rel
                tgt.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, tgt)
        return compute_content_hash(dest)


def _index_kdl_one_pkg(
    name: str, *, url: str, ref: str, content_hash: str, commit_sha: str
) -> str:
    return f"""\
schema_version 1
package "{name}" {{
    version "1.0.0" {{
        content_hash "{content_hash}"
        provenance {{
            kind "git"
            url "{url}"
            ref "{ref}"
            commit_sha "{commit_sha}"
        }}
    }}
}}
"""


def _index_kdl_two_pkgs(
    name1: str, *, url1: str, ref1: str, content_hash1: str, commit_sha1: str,
    name2: str, url2: str, ref2: str, content_hash2: str, commit_sha2: str,
) -> str:
    return f"""\
schema_version 1
package "{name1}" {{
    version "1.0.0" {{
        content_hash "{content_hash1}"
        provenance {{
            kind "git"
            url "{url1}"
            ref "{ref1}"
            commit_sha "{commit_sha1}"
        }}
    }}
}}
package "{name2}" {{
    version "1.0.0" {{
        content_hash "{content_hash2}"
        provenance {{
            kind "git"
            url "{url2}"
            ref "{ref2}"
            commit_sha "{commit_sha2}"
        }}
    }}
}}
"""


def _env(tmp_path: Path, mocked_dir: Path, index_kdl: str | None) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl) if index_kdl is not None else None
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _resolve(root_kdl: str, env: MilpaEnv, tmp_path: Path) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(manifest, deps_dir, env, ResolveParams())


def _dep(graph: ResolvedGraph, name: str):
    return next(d for d in graph.deps if d.name == name)


# ---------------------------------------------------------------------------
# Resolver-level scenarios: DISAGREEING transitive url vs a registry name
# ---------------------------------------------------------------------------


class TestDisagreeingUrlConflictsUrlDiscoveredFirst:
    """A tier-3 URL claim for ``foo`` (a registry-known name) is reachable in
    ONE hop from root (wave 1); a tier-2 named claim for ``foo`` is reachable
    only in TWO hops (wave 2). The url claim's source (``pin.example.com``)
    is a DIFFERENT repository from the registry's recorded source
    (``registry.example.com``) — it DISAGREES.

    Under validate-against-registry, this raises ``RES-PROVENANCE-CONFLICT``
    at the url claim's OWN discovery (wave 1) — before the competing named
    claim (wave 2) is ever even reached, and regardless of it. This is the
    order-independence guarantee (§10.5): the decision is a static function
    of the url claim + the (already-loaded) registry record alone."""

    def test_conflict_raised_when_url_claim_precedes_named_claim(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        wrap_a_url = "https://example.com/wrapA.git"
        wrap_b_url = "https://example.com/wrapB.git"
        wrap_b2_url = "https://example.com/wrapB2.git"
        foo_pin_url = "https://pin.example.com/foo.git"
        foo_registry_url = "https://registry.example.com/foo.git"

        _stage(
            mocked_dir, wrap_a_url, "main", sha="a" * 40,
            kdl=(
                'name "wrapA"\nkind "library"\n'
                "deps {\n"
                f'    foo git=(url)"{foo_pin_url}" ref="v9.9.9"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, wrap_b_url, "main", sha="b" * 40,
            kdl=(
                'name "wrapB"\nkind "library"\n'
                "deps {\n"
                f'    wrapB2 git=(url)"{wrap_b2_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, wrap_b2_url, "main", sha="c" * 40,
            kdl='name "wrapB2"\nkind "library"\ndeps {\n    foo\n}\n',
        )
        _stage(mocked_dir, foo_pin_url, "v9.9.9", sha="1" * 40, marker="url-pin")
        _stage(mocked_dir, foo_registry_url, "v1.0.0", sha="2" * 40, marker="registry")

        foo_registry_hash = _content_hash_for(mocked_dir, foo_registry_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg(
            "foo", url=foo_registry_url, ref="v1.0.0",
            content_hash=foo_registry_hash, commit_sha="d" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    wrapA git=(url)"{wrap_a_url}" ref="main"\n'
            f'    wrapB git=(url)"{wrap_b_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT
        assert "foo" in exc_info.value.message

        # The disagreeing pin must genuinely never have been fetched —
        # validated and rejected BEFORE any fetch is dispatched (§10.5).
        foo_pin_hash = _content_hash_for(mocked_dir, foo_pin_url, "v9.9.9")
        assert not env.store.contains(foo_pin_hash)


class TestDisagreeingUrlConflictsNamedDiscoveredFirst:
    """Same shape, roles swapped: the tier-2 named claim is reachable in ONE
    hop (wave 1, enumerated inline), the disagreeing tier-3 URL claim only in
    TWO hops (wave 2). The outcome MUST be identical: the url claim still
    conflicts, at its own discovery, regardless of the registry claim already
    being on record."""

    def test_conflict_raised_when_named_claim_precedes_url_claim(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        wrap_a_url = "https://example.com/wrapA.git"
        wrap_b_url = "https://example.com/wrapB.git"
        wrap_b2_url = "https://example.com/wrapB2.git"
        foo_pin_url = "https://pin.example.com/foo.git"
        foo_registry_url = "https://registry.example.com/foo.git"

        _stage(
            mocked_dir, wrap_a_url, "main", sha="a" * 40,
            kdl='name "wrapA"\nkind "library"\ndeps {\n    foo\n}\n',
        )
        _stage(
            mocked_dir, wrap_b_url, "main", sha="b" * 40,
            kdl=(
                'name "wrapB"\nkind "library"\n'
                "deps {\n"
                f'    wrapB2 git=(url)"{wrap_b2_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, wrap_b2_url, "main", sha="c" * 40,
            kdl=(
                'name "wrapB2"\nkind "library"\n'
                "deps {\n"
                f'    foo git=(url)"{foo_pin_url}" ref="v9.9.9"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_pin_url, "v9.9.9", sha="1" * 40, marker="url-pin")
        _stage(mocked_dir, foo_registry_url, "v1.0.0", sha="2" * 40, marker="registry")

        foo_registry_hash = _content_hash_for(mocked_dir, foo_registry_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg(
            "foo", url=foo_registry_url, ref="v1.0.0",
            content_hash=foo_registry_hash, commit_sha="d" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    wrapA git=(url)"{wrap_a_url}" ref="main"\n'
            f'    wrapB git=(url)"{wrap_b_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT
        assert "foo" in exc_info.value.message

        foo_pin_hash = _content_hash_for(mocked_dir, foo_pin_url, "v9.9.9")
        assert not env.store.contains(foo_pin_hash)


class TestMidSolveResidualClosedByImmediateValidation:
    """THE old residual (docs/rfc-provenance-lattice.handoff.md) — now closed
    by construction under validate-against-registry, the same way the prior
    membership-based redesign closed it, but via immediate REJECTION instead
    of immediate redirect.

    ``foo`` is a registry-known name. An eager tier-3 URL transitive
    (``wrapA``) claims ``foo`` via ``git=`` at a DIFFERENT repository than
    the registry's — this is discovered and validated during the EAGER BFS
    (before solve() ever starts), and conflicts immediately. The ONLY
    competing tier-2 claim for ``foo`` lives inside the manifest of ANOTHER
    registry package (``outer``), discoverable only mid-solve (when the
    solver materialises ``outer``'s selected candidate) — strictly AFTER
    wrapA's claim has already been validated and rejected. The conflict
    fires without ever needing ``outer``'s claim to exist or be discovered:
    the registry index alone (a static, pre-loaded fact) is enough."""

    def test_conflict_raised_before_mid_solve_claim_ever_surfaces(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        wrap_a_url = "https://example.com/wrapA.git"
        outer_url = "https://registry.example.com/outer.git"
        foo_pin_url = "https://pin.example.com/foo.git"
        foo_registry_url = "https://registry.example.com/foo.git"

        _stage(
            mocked_dir, wrap_a_url, "main", sha="a" * 40,
            kdl=(
                'name "wrapA"\nkind "library"\n'
                "deps {\n"
                f'    foo git=(url)"{foo_pin_url}" ref="v9.9.9"\n'
                "}\n"
            ),
        )
        # outer (a registry package) — its OWN manifest requires foo by bare
        # name. Never even needs to be fetched: wrapA's own claim already
        # aborts resolution before outer is ever selected/materialised.
        _stage(
            mocked_dir, outer_url, "v1.0.0", sha="b" * 40,
            kdl='name "outer"\nkind "library"\ndeps {\n    foo\n}\n',
        )
        _stage(mocked_dir, foo_pin_url, "v9.9.9", sha="1" * 40, marker="url-pin")
        _stage(mocked_dir, foo_registry_url, "v1.0.0", sha="2" * 40, marker="registry")

        outer_hash = _content_hash_for(mocked_dir, outer_url, "v1.0.0")
        foo_registry_hash = _content_hash_for(mocked_dir, foo_registry_url, "v1.0.0")
        index_kdl = _index_kdl_two_pkgs(
            "outer", url1=outer_url, ref1="v1.0.0",
            content_hash1=outer_hash, commit_sha1="c" * 40,
            name2="foo", url2=foo_registry_url, ref2="v1.0.0",
            content_hash2=foo_registry_hash, commit_sha2="d" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    wrapA git=(url)"{wrap_a_url}" ref="main"\n'
            "    outer\n"
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT
        assert "foo" in exc_info.value.message

        foo_pin_hash = _content_hash_for(mocked_dir, foo_pin_url, "v9.9.9")
        assert not env.store.contains(foo_pin_hash)


class TestTwoDisagreeingUrlsForRegistryNameBothConflict:
    """Three transitives claim ``shared``: one by bare name (registry), and
    two via DIFFERENT self-declared URLs — both of which DISAGREE with the
    registry's recorded source. Under validate-against-registry, EACH
    disagreeing url is independently invalid (not merely "loses an
    arbitration") — whichever the BFS reaches first raises
    ``RES-PROVENANCE-CONFLICT``. (Under the prior membership-based redesign
    this fixture demonstrated "registry wins, no conflict" — the design
    revision inverts that outcome: a transitive can no longer silently
    redirect to, or be silently overridden by, the registry.)"""

    def test_conflict_raised(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        q_url = "https://example.com/q.git"
        r1_url = "https://example.com/r1.git"
        r2_url = "https://example.com/r2.git"
        mid1_url = "https://example.com/mid1.git"
        mid2_url = "https://example.com/mid2.git"
        shared_x_url = "https://x.example.com/shared.git"
        shared_y_url = "https://y.example.com/shared.git"
        shared_registry_url = "https://registry.example.com/shared.git"

        _stage(
            mocked_dir, q_url, "main", sha="q" * 40,
            kdl='name "q"\nkind "library"\ndeps {\n    shared\n}\n',
        )
        _stage(
            mocked_dir, r1_url, "main", sha="1" * 40,
            kdl=(
                'name "r1"\nkind "library"\ndeps {\n'
                f'    mid1 git=(url)"{mid1_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, r2_url, "main", sha="2" * 40,
            kdl=(
                'name "r2"\nkind "library"\ndeps {\n'
                f'    mid2 git=(url)"{mid2_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, mid1_url, "main", sha="3" * 40,
            kdl=(
                'name "mid1"\nkind "library"\ndeps {\n'
                f'    shared git=(url)"{shared_x_url}" ref="v8.0.0"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, mid2_url, "main", sha="4" * 40,
            kdl=(
                'name "mid2"\nkind "library"\ndeps {\n'
                f'    shared git=(url)"{shared_y_url}" ref="v9.0.0"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, shared_x_url, "v8.0.0", sha="5" * 40, marker="x")
        _stage(mocked_dir, shared_y_url, "v9.0.0", sha="6" * 40, marker="y")
        _stage(mocked_dir, shared_registry_url, "v1.0.0", sha="7" * 40, marker="registry")

        shared_registry_hash = _content_hash_for(mocked_dir, shared_registry_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg(
            "shared", url=shared_registry_url, ref="v1.0.0",
            content_hash=shared_registry_hash, commit_sha="8" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    q git=(url)"{q_url}" ref="main"\n'
            f'    r1 git=(url)"{r1_url}" ref="main"\n'
            f'    r2 git=(url)"{r2_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT
        assert "shared" in exc_info.value.message


class TestRootBeatsBothRegistryAndUrl:
    """Root declares ``shared`` directly (tier 1). A transitive claims
    ``shared`` by bare name (tier 2, registry-known), and ANOTHER transitive
    claims it via a different self-declared URL (tier 3, disagreeing with
    the registry). Root wins over BOTH — no conflict, no validation is even
    attempted (root_authority excludes ``shared`` from the validate-against-
    registry branch entirely); the resolved provenance is root's own."""

    def test_root_wins_over_registry_and_url(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        root_shared_url = "https://root.example.com/shared.git"
        t1_url = "https://example.com/t1.git"
        t2_url = "https://example.com/t2.git"
        evil_shared_url = "https://evil.example.com/shared.git"
        shared_registry_url = "https://registry.example.com/shared.git"

        _stage(mocked_dir, root_shared_url, "main", sha="0" * 40, marker="root-pin")
        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl='name "t1"\nkind "library"\ndeps {\n    shared\n}\n',
        )
        _stage(
            mocked_dir, t2_url, "main", sha="2" * 40,
            kdl=(
                'name "t2"\nkind "library"\ndeps {\n'
                f'    shared git=(url)"{evil_shared_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, evil_shared_url, "main", sha="3" * 40, marker="evil")
        _stage(mocked_dir, shared_registry_url, "v1.0.0", sha="4" * 40, marker="registry")

        shared_registry_hash = _content_hash_for(mocked_dir, shared_registry_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg(
            "shared", url=shared_registry_url, ref="v1.0.0",
            content_hash=shared_registry_hash, commit_sha="5" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_pin_hash = _content_hash_for(mocked_dir, root_shared_url, "main")

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    shared git=(url)"{root_shared_url}" ref="main"\n'
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            f'    t2 git=(url)"{t2_url}" ref="main"\n'
            "}\n"
        )
        graph = _resolve(root_kdl, env, tmp_path)

        shared = _dep(graph, "shared")
        assert shared.identity == root_pin_hash
        assert shared.provenances[0].url == root_shared_url


# ---------------------------------------------------------------------------
# Resolver-level scenarios: AGREEING transitive url vs a registry name
# ---------------------------------------------------------------------------


class TestLoneUrlPinOfRegistryNameAgreesIsAccepted:
    """A transitive url-pins ``foo`` — a name that ALSO exists in the
    registry — at the SAME repository the registry records, just a
    DIFFERENT ``ref`` (an older tag). No competing named claim exists
    anywhere else in the graph.

    Under validate-against-registry, this is ACCEPTED (not redirected): the
    claim agrees with the registry's own source, so it is a legitimate pin
    of a specific version of the registry's own package. ``foo`` resolves
    from the transitive's OWN pinned ref/commit, genuinely fetched — this
    supersedes the prior membership-based design, under which this exact
    shape was silently redirected to the registry's version instead."""

    def test_lone_agreeing_url_pin_is_accepted_and_fetched(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        foo_registry_url = "https://registry.example.com/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_registry_url}" ref="v0.9.0"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_registry_url, "v0.9.0", sha="2" * 40, marker="older-tag")
        _stage(mocked_dir, foo_registry_url, "v1.0.0", sha="3" * 40, marker="registry")

        foo_pin_hash = _content_hash_for(mocked_dir, foo_registry_url, "v0.9.0")
        foo_registry_hash = _content_hash_for(mocked_dir, foo_registry_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg(
            "foo", url=foo_registry_url, ref="v1.0.0",
            content_hash=foo_registry_hash, commit_sha="4" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        graph = _resolve(root_kdl, env, tmp_path)

        foo = _dep(graph, "foo")
        # Accepted AS ITSELF: resolves from the transitive's own pinned ref,
        # NOT redirected to the registry's version.
        assert foo.identity == foo_pin_hash
        assert foo.identity != foo_registry_hash
        assert foo.version == "0.9.0"

        # Genuinely fetched (accepted claims are ordinary tier-3 url deps).
        assert env.store.contains(foo_pin_hash)


class TestLoneUrlPinOfRegistryNameDisagreesConflicts:
    """A transitive url-pins ``foo`` — a name that ALSO exists in the
    registry — at a DIFFERENT repository than the registry records, with NO
    competing claim anywhere else in the graph. This is the headline
    behavioral change from the pure disagreement-only design: a LONE
    transitive claim can conflict with a KNOWN registry name, with no second
    claim needed to arbitrate against."""

    def test_lone_disagreeing_url_pin_conflicts(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        foo_pin_url = "https://pin.example.com/foo.git"
        foo_registry_url = "https://registry.example.com/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_pin_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_pin_url, "main", sha="2" * 40, marker="url-pin")
        _stage(mocked_dir, foo_registry_url, "v1.0.0", sha="3" * 40, marker="registry")

        foo_pin_hash = _content_hash_for(mocked_dir, foo_pin_url, "main")
        foo_registry_hash = _content_hash_for(mocked_dir, foo_registry_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg(
            "foo", url=foo_registry_url, ref="v1.0.0",
            content_hash=foo_registry_hash, commit_sha="4" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT
        assert "foo" in exc_info.value.message

        assert not env.store.contains(foo_pin_hash)


class TestTwoAgreeingUrlPinsOfSameRegistryNameCoexist:
    """Two DIFFERENT transitives each pin ``foo`` — a registry-known name —
    at the registry's OWN repository, but at two DIFFERENT refs. Both
    AGREE with the registry (same repo), so BOTH are accepted: they must
    coexist as independent candidates, never conflict with EACH OTHER
    (agreement is validated per-claim against the static registry record,
    never between claims). Ordinary solver version-negotiation (maxver)
    then picks the higher version."""

    def test_both_accepted_solver_picks_higher_version(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        t2_url = "https://example.com/t2.git"
        foo_registry_url = "https://registry.example.com/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_registry_url}" ref="v2.0.0"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, t2_url, "main", sha="2" * 40,
            kdl=(
                'name "t2"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_registry_url}" ref="v3.0.0"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_registry_url, "v1.0.0", sha="3" * 40, marker="registry")
        _stage(mocked_dir, foo_registry_url, "v2.0.0", sha="4" * 40, marker="v2")
        _stage(mocked_dir, foo_registry_url, "v3.0.0", sha="5" * 40, marker="v3")

        foo_registry_hash = _content_hash_for(mocked_dir, foo_registry_url, "v1.0.0")
        foo_v2_hash = _content_hash_for(mocked_dir, foo_registry_url, "v2.0.0")
        foo_v3_hash = _content_hash_for(mocked_dir, foo_registry_url, "v3.0.0")
        index_kdl = _index_kdl_one_pkg(
            "foo", url=foo_registry_url, ref="v1.0.0",
            content_hash=foo_registry_hash, commit_sha="6" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            f'    t2 git=(url)"{t2_url}" ref="main"\n'
            "}\n"
        )
        graph = _resolve(root_kdl, env, tmp_path)

        foo = _dep(graph, "foo")
        assert foo.version == "3.0.0"
        assert foo.identity == foo_v3_hash

        # Both agreeing pins were genuinely fetched (peacefully coexisting
        # candidates) — neither was blocked by the other.
        assert env.store.contains(foo_v2_hash)
        assert env.store.contains(foo_v3_hash)


class TestLoneUrlPinOfNonRegistryNameStands:
    """A transitive url-pins a name that is NOT in the registry index at
    all — there is nothing to validate against, so this is the plain
    tier-3 case (§10.3's SECOND rule). The url pin stands, exactly as
    before."""

    def test_lone_url_pin_of_unknown_name_stands(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        bar_pin_url = "https://pin.example.com/bar.git"
        unrelated_url = "https://registry.example.com/unrelated.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    bar git=(url)"{bar_pin_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, bar_pin_url, "main", sha="2" * 40, marker="bar-pin")
        _stage(mocked_dir, unrelated_url, "v1.0.0", sha="3" * 40, marker="unrelated")

        bar_pin_hash = _content_hash_for(mocked_dir, bar_pin_url, "main")
        unrelated_hash = _content_hash_for(mocked_dir, unrelated_url, "v1.0.0")
        # The index exists (and is non-trivial) but has no entry for "bar" —
        # this is the "genuinely not index-member" case, distinct from an
        # entirely absent index (env(index=None), covered elsewhere).
        index_kdl = _index_kdl_one_pkg(
            "unrelated", url=unrelated_url, ref="v1.0.0",
            content_hash=unrelated_hash, commit_sha="9" * 40,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        graph = _resolve(root_kdl, env, tmp_path)

        bar = _dep(graph, "bar")
        assert bar.identity == bar_pin_hash


class TestUrlVsUrlStillConflictsWithNoRegistry:
    """Regression pin (fixture-099's shape): two transitives claim the same
    non-root name from two DIFFERENT urls, and the name has NO registry
    entry at all — the lattice must NOT have weakened this case. Still
    raises RES-PROVENANCE-CONFLICT."""

    def test_raises_conflict(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        a_url = "https://example.com/a.git"
        b_url = "https://example.com/b.git"
        shared_x_url = "https://x.example.com/shared.git"
        shared_y_url = "https://y.example.com/shared.git"

        _stage(
            mocked_dir, a_url, "main", sha="a" * 40,
            kdl=(
                'name "a"\nkind "library"\ndeps {\n'
                f'    shared git=(url)"{shared_x_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(
            mocked_dir, b_url, "main", sha="b" * 40,
            kdl=(
                'name "b"\nkind "library"\ndeps {\n'
                f'    shared git=(url)"{shared_y_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, shared_x_url, "main", sha="1" * 40, marker="x")
        _stage(mocked_dir, shared_y_url, "main", sha="2" * 40, marker="y")

        env = _env(tmp_path, mocked_dir, index_kdl=None)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    a git=(url)"{a_url}" ref="main"\n'
            f'    b git=(url)"{b_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT
        assert "shared" in exc_info.value.message


# ---------------------------------------------------------------------------
# Unit tests: the tier-aware gate directly (no resolve() plumbing)
# ---------------------------------------------------------------------------


class TestCheckProvenanceGateTierSemantics:
    """Direct unit tests of ``_check_provenance_gate``'s tier arithmetic —
    resolver-semantics.md §10.0. Complements the resolver-level scenarios
    above (which prove the mechanism wired correctly into the BFS) with a
    fast, plumbing-free check of the gate's own decision table.

    NOTE: since the validate-against-registry rework, a registry-index url
    claim never reaches this gate at TIER_SELF_URL at all (it is validated
    and either accepted-bypassing-the-gate or rejected outright at its own
    discovery — see ``TestValidateTransitiveUrlAgainstRegistry`` below). So
    these tests exercise the gate's OWN tier arithmetic in isolation
    (root suppression, tier-2/tier-3 arbitration for a NON-index name that
    happens to receive both a ``named`` and a ``git=`` claim, tier-3-vs-
    tier-3 conflict) — the same decision table as before #193's revision;
    only the CALLERS' routing for registry-owned url claims changed."""

    def test_first_claim_registers_and_proceeds(self) -> None:
        gate: dict = {}
        assert _check_provenance_gate(
            "foo", ("url", "u1", "main"), gate, set(), tier=TIER_SELF_URL,
        ) is True
        assert gate["foo"] == (("url", "u1", "main"), TIER_SELF_URL)

    def test_same_pkey_dedups(self) -> None:
        gate: dict = {}
        _check_provenance_gate("foo", ("url", "u1", "main"), gate, set(), tier=TIER_SELF_URL)
        assert _check_provenance_gate(
            "foo", ("url", "u1", "main"), gate, set(), tier=TIER_SELF_URL,
        ) is False

    def test_named_claims_always_dedup_same_sentinel(self) -> None:
        gate: dict = {}
        _check_provenance_gate("foo", _NAMED_PKEY, gate, set(), tier=TIER_REGISTRY)
        assert _check_provenance_gate(
            "foo", _NAMED_PKEY, gate, set(), tier=TIER_REGISTRY,
        ) is False

    def test_root_wins_over_tier3_url(self) -> None:
        gate: dict = {}
        root_authority = {"foo"}
        _check_provenance_gate(
            "foo", ("url", "root-u", "main"), gate, root_authority, tier=TIER_SELF_URL,
        )
        assert _check_provenance_gate(
            "foo", ("url", "evil-u", "main"), gate, root_authority, tier=TIER_SELF_URL,
        ) is False
        # Root's own entry is untouched.
        assert gate["foo"] == (("url", "root-u", "main"), TIER_ROOT)

    def test_root_wins_over_tier2_named(self) -> None:
        gate: dict = {}
        root_authority = {"foo"}
        _check_provenance_gate(
            "foo", ("url", "root-u", "main"), gate, root_authority, tier=TIER_SELF_URL,
        )
        assert _check_provenance_gate(
            "foo", _NAMED_PKEY, gate, root_authority, tier=TIER_REGISTRY,
        ) is False
        assert gate["foo"] == (("url", "root-u", "main"), TIER_ROOT)

    def test_tier2_beats_tier3_arriving_after(self) -> None:
        """Tier-3 registers first; a differently-keyed tier-2 claim arrives
        second — it wins (overwrites the gate), proceed=True. (Reachable
        only for a NON-index name: an index-member name's url claims never
        reach this gate — see the class docstring.)"""
        gate: dict = {}
        _check_provenance_gate(
            "foo", ("url", "u1", "main"), gate, set(), tier=TIER_SELF_URL,
        )
        assert _check_provenance_gate(
            "foo", _NAMED_PKEY, gate, set(), tier=TIER_REGISTRY,
        ) is True
        assert gate["foo"] == (_NAMED_PKEY, TIER_REGISTRY)

    def test_tier3_suppressed_when_arriving_after_tier2(self) -> None:
        """Tier-2 registers first; a tier-3 claim arrives second — it is
        suppressed BEFORE any fetch would be dispatched, proceed=False."""
        gate: dict = {}
        _check_provenance_gate("foo", _NAMED_PKEY, gate, set(), tier=TIER_REGISTRY)
        assert _check_provenance_gate(
            "foo", ("url", "u1", "main"), gate, set(), tier=TIER_SELF_URL,
        ) is False
        # The registry entry stays authoritative.
        assert gate["foo"] == (_NAMED_PKEY, TIER_REGISTRY)

    def test_tier3_vs_tier3_conflicts_when_no_tier2(self) -> None:
        gate: dict = {}
        _check_provenance_gate(
            "foo", ("url", "u1", "main"), gate, set(), tier=TIER_SELF_URL,
        )
        with pytest.raises(MilpaError) as exc_info:
            _check_provenance_gate(
                "foo", ("url", "u2", "main"), gate, set(), tier=TIER_SELF_URL,
            )
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT

    def test_tier3_vs_tier3_no_conflict_once_tier2_on_record(self) -> None:
        """Once a tier-2 claim has been recorded for a name, a differing
        tier-3 claim is just suppressed (registry already won) — the
        tier-3-vs-tier-3 conflict branch is never reached."""
        gate: dict = {}
        _check_provenance_gate("foo", _NAMED_PKEY, gate, set(), tier=TIER_REGISTRY)
        _check_provenance_gate(
            "foo", ("url", "u1", "main"), gate, set(), tier=TIER_SELF_URL,
        )
        # A SECOND, differently-keyed tier-3 claim must also just be
        # suppressed, not raise — the registry entry already resolved the
        # disagreement for this name.
        assert _check_provenance_gate(
            "foo", ("url", "u2", "main"), gate, set(), tier=TIER_SELF_URL,
        ) is False


# ---------------------------------------------------------------------------
# Unit tests: the registry-validation mechanism directly (no resolve()
# plumbing) — resolver-semantics.md §10.0/§10.3, the validate-against-
# registry rework.
# ---------------------------------------------------------------------------


class TestNormalizeGitSourceUrl:
    """Direct unit tests of ``_normalize_git_source_url`` — the comparison
    normalization used by ``_validate_transitive_url_against_registry``."""

    def test_trailing_git_suffix_stripped(self) -> None:
        assert (
            _normalize_git_source_url("https://example.com/foo.git")
            == _normalize_git_source_url("https://example.com/foo")
        )

    def test_trailing_slash_stripped(self) -> None:
        assert (
            _normalize_git_source_url("https://example.com/foo/")
            == _normalize_git_source_url("https://example.com/foo")
        )

    def test_scheme_and_host_case_insensitive(self) -> None:
        assert (
            _normalize_git_source_url("HTTPS://Example.COM/foo.git")
            == _normalize_git_source_url("https://example.com/foo.git")
        )

    def test_path_case_preserved(self) -> None:
        # Path casing is NOT normalized — many git hosts are path-case-sensitive.
        assert (
            _normalize_git_source_url("https://example.com/Foo.git")
            != _normalize_git_source_url("https://example.com/foo.git")
        )

    def test_different_hosts_differ(self) -> None:
        assert (
            _normalize_git_source_url("https://a.example.com/foo.git")
            != _normalize_git_source_url("https://b.example.com/foo.git")
        )


class TestValidateTransitiveUrlAgainstRegistry:
    """Direct unit tests of ``_validate_transitive_url_against_registry`` —
    the agree/disagree/incomparable decision (resolver-semantics.md
    §10.0/§10.3 NORMATIVE "Registry validation")."""

    def test_agrees_same_url_same_ref(self) -> None:
        pkg = Package(
            name="foo", namespace="",
            versions=(
                _iv_git("1.0.0", url="https://registry.example.com/foo.git", ref="v1.0.0"),
            ),
        )
        # No raise == agreement.
        _validate_transitive_url_against_registry(
            "foo", "https://registry.example.com/foo.git", pkg,
        )

    def test_agrees_same_repo_different_ref(self) -> None:
        pkg = Package(
            name="foo", namespace="",
            versions=(
                _iv_git("1.0.0", url="https://registry.example.com/foo.git", ref="v1.0.0"),
            ),
        )
        # Different ref, same repo: still an agreement (ref only selects a version).
        _validate_transitive_url_against_registry(
            "foo", "https://registry.example.com/foo.git", pkg,
        )

    def test_agrees_matches_an_older_versions_provenance(self) -> None:
        # The claim matches version 1.0.0's recorded source, not the newest
        # (2.0.0's) — agreement checks EVERY version's provenance, not just
        # the latest.
        pkg = Package(
            name="foo", namespace="",
            versions=(
                _iv_git("2.0.0", url="https://registry.example.com/foo-v2.git", ref="v2.0.0"),
                _iv_git("1.0.0", url="https://registry.example.com/foo.git", ref="v1.0.0"),
            ),
        )
        _validate_transitive_url_against_registry(
            "foo", "https://registry.example.com/foo.git", pkg,
        )

    def test_agrees_normalized_git_suffix_and_case(self) -> None:
        pkg = Package(
            name="foo", namespace="",
            versions=(
                _iv_git("1.0.0", url="https://Registry.example.com/foo.git", ref="v1.0.0"),
            ),
        )
        # No ".git" suffix on the claim, different host casing: still agrees.
        _validate_transitive_url_against_registry(
            "foo", "https://registry.example.com/foo", pkg,
        )

    def test_disagrees_different_repository(self) -> None:
        pkg = Package(
            name="foo", namespace="",
            versions=(
                _iv_git("1.0.0", url="https://registry.example.com/foo.git", ref="v1.0.0"),
            ),
        )
        with pytest.raises(MilpaError) as exc_info:
            _validate_transitive_url_against_registry(
                "foo", "https://pin.example.com/foo.git", pkg,
            )
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT
        assert "foo" in exc_info.value.message

    def test_disagrees_incomparable_oci_only_entry(self) -> None:
        # The registry entry is OCI-only — a git= claim can never be
        # compared to it, so it is treated as a disagreement (conservative).
        pkg = Package(
            name="foo", namespace="",
            versions=(
                IndexVersion(
                    version="1.0.0",
                    content_hash="sha256:" + "a" * 64,
                    provenances=(
                        OciIndexProvenance(
                            registry="ghcr.io", repository="example/foo",
                            digest="sha256:" + "b" * 64,
                        ),
                    ),
                ),
            ),
        )
        with pytest.raises(MilpaError) as exc_info:
            _validate_transitive_url_against_registry(
                "foo", "https://example.com/foo.git", pkg,
            )
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT

    def test_disagrees_no_provenance_at_all(self) -> None:
        # A package version with no provenance recorded whatsoever — also
        # incomparable, also a disagreement.
        pkg = Package(
            name="foo", namespace="",
            versions=(
                IndexVersion(version="1.0.0", content_hash="", provenances=()),
            ),
        )
        with pytest.raises(MilpaError) as exc_info:
            _validate_transitive_url_against_registry(
                "foo", "https://example.com/foo.git", pkg,
            )
        assert exc_info.value.slug == RES_PROVENANCE_CONFLICT


def _iv_git(version: str, *, url: str, ref: str):
    """Build a minimal ``IndexVersion`` carrying one git provenance, for the
    ``_validate_transitive_url_against_registry`` unit tests above."""
    return IndexVersion(
        version=version,
        content_hash="sha256:" + "0" * 64,
        provenances=(GitIndexProvenance(url=url, ref=ref, commit_sha=None),),
    )
