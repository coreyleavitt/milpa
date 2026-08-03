"""#193 (source selection / registry-shadow), end to end through ``resolve()``.

**Post RFC origin-as-identity (S3a/S3b):** the old three-tier
``provenance_gate``/``TIER_*``/``_check_provenance_gate``/
``_validate_transitive_url_against_registry`` machinery this file used to
exercise directly is DELETED (`docs/rfc-origin-as-identity.md` §6). Source
selection is now two orthogonal mechanisms, both exercised below:

- **``BindingResolver`` (``binding.py``, §4.3)** — the deterministic binding
  phase. A root/override claim always wins; two disagreeing TRANSITIVE
  claims for the same name (no root claim to arbitrate) raise
  ``RES-BINDING-CONFLICT``.
- **The registry-shadow tripwire (``binding.check_registry_shadow``, §6.1)**
  — a pre-fetch, name-triggered, URL-refined dependency-confusion check: a
  transitive ``git=``/``tarball=``/``oci=`` claim whose bare name is also a
  tianguis-owned coordinate is silently accepted if its source matches the
  registry's recorded upstream, else raises ``RES-REGISTRY-SHADOW`` (warn by
  default, hard-fail under ``attestation-policy strict``).

This file's resolver-level scenarios exercise BOTH BFS discovery orderings
(the ordering neither mechanism may be sensitive to) and prove each decision
is static and per-claim, never dependent on which other claims exist or when
they are discovered.

``tests/test_provenance_gate.py`` covers the tier-3-vs-tier-3-shaped (now
``RES-BINDING-CONFLICT``) case with real declared-version data end to end
through ``resolve()``.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import MilpaError, RES_BINDING_CONFLICT, RES_REGISTRY_SHADOW
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import ResolvedGraph
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import resolve


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


def _index_kdl_one_pkg_oci(
    name: str, *, registry: str, repository: str, digest: str, content_hash: str
) -> str:
    """An OCI-only registry entry (no comparable git source recorded) —
    the shape ``_validate_transitive_url_against_registry`` must fall back
    to content-identity comparison for (resolver-semantics.md §10.0/§10.3
    "incomparable transport" clause)."""
    return f"""\
schema_version 1
package "{name}" {{
    version "1.0.0" {{
        content_hash "{content_hash}"
        provenance {{
            kind "oci"
            registry "{registry}"
            repository "{repository}"
            digest "{digest}"
        }}
    }}
}}
"""


def _index_kdl_one_pkg_oci_with_source(
    name: str, *, registry: str, repository: str, digest: str, content_hash: str,
    source_url: str,
) -> str:
    """An OCI registry entry that also records the ``source_url`` the
    artifact was published FROM (registry-protocol §3.3 oci provenance's
    optional ``source`` child) — the shape
    ``_validate_transitive_url_against_registry`` URL-matches against
    BEFORE falling back to content-hash (resolver-semantics.md §10.0/§10.3
    "OCI source_url" clause)."""
    return f"""\
schema_version 1
package "{name}" {{
    version "1.0.0" {{
        content_hash "{content_hash}"
        provenance {{
            kind "oci"
            registry "{registry}"
            repository "{repository}"
            digest "{digest}"
            source "{source_url}"
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
    """A ``git=`` claim for ``foo`` (a registry-known name) is reachable in
    ONE hop from root (wave 1); a ``named`` claim for ``foo`` is reachable
    only in TWO hops (wave 2). The url claim's source (``pin.example.com``)
    is a DIFFERENT repository from the registry's recorded source
    (``registry.example.com``).

    Under ``BindingResolver`` (RFC origin-as-identity §4.3), this is TWO
    EXPLICIT, competing non-root claims for one name — wrapA's git= claim
    (wave 1, accepted — with a registry-shadow WARNING, S3c, since its bare
    name shadows a registry coordinate at a different URL, but a fork of a
    registry package is legitimate and warn-only by default) and wrapB2's
    bare ``named`` claim (wave 2) — so it raises ``RES-BINDING-CONFLICT``
    once the second claim arrives, regardless of discovery order."""

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
        import warnings as _warnings
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore")
            with pytest.raises(MilpaError) as exc_info:
                _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_BINDING_CONFLICT
        assert "foo" in exc_info.value.message

        # wrapA's pin WAS fetched (warn, not hard-fail, under the default
        # policy) — the conflict is with wrapB2's LATER named claim, not a
        # static pre-fetch rejection of wrapA's own claim.
        foo_pin_hash = _content_hash_for(mocked_dir, foo_pin_url, "v9.9.9")
        assert env.store.contains(foo_pin_hash)


class TestDisagreeingUrlConflictsNamedDiscoveredFirst:
    """Same shape, roles swapped: the bare ``named`` claim is reachable in
    ONE hop (wave 1, enumerated inline), the disagreeing ``git=`` claim only
    in TWO hops (wave 2). The outcome MUST be identical to the reverse
    ordering: ``BindingResolver`` raises ``RES-BINDING-CONFLICT`` once both
    competing claims are on record, regardless of which arrived first."""

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
        import warnings as _warnings
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore")
            with pytest.raises(MilpaError) as exc_info:
                _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_BINDING_CONFLICT
        assert "foo" in exc_info.value.message

        # Here the disagreeing git= claim is the SECOND claim for "foo"
        # (the bare named claim was already bound first) — the conflict is
        # raised by ``BindingResolver.submit()`` itself, before this claim
        # is ever dispatched to fetch.
        foo_pin_hash = _content_hash_for(mocked_dir, foo_pin_url, "v9.9.9")
        assert not env.store.contains(foo_pin_hash)


class TestMidSolveResidualClosedByImmediateValidation:
    """THE old residual (docs/rfc-provenance-lattice.handoff.md) — closed by
    ``BindingResolver`` (RFC origin-as-identity §4.3), the same way the
    prior membership-based redesign closed it, but via genuine multi-claim
    conflict detection rather than a discovery-order-sensitive gate.

    ``foo`` is a registry-known name. An eager ``git=`` transitive
    (``wrapA``) claims ``foo`` at a DIFFERENT repository than the
    registry's — discovered during the EAGER BFS (before solve() ever
    starts); its bare name shadows a registry coordinate at a different
    URL, so the registry-shadow tripwire (S3c) WARNS (default policy, not a
    hard error — a fork is legitimate), and the claim is accepted and
    fetched. The ONLY competing claim for ``foo`` lives inside the manifest
    of ANOTHER registry package (``outer``), discoverable only mid-solve
    (when the solver materialises ``outer``'s selected candidate) —
    strictly AFTER wrapA's claim is already bound. When outer's own bare
    ``foo`` claim is submitted, it disagrees with wrapA's already-bound
    source-id and ``RES-BINDING-CONFLICT`` fires — regardless of how late
    the competing claim surfaces."""

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
        import warnings as _warnings
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore")
            with pytest.raises(MilpaError) as exc_info:
                _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_BINDING_CONFLICT
        assert "foo" in exc_info.value.message

        # wrapA's claim was the FIRST (only) claim on record when it was
        # discovered — accepted (with a shadow warning) and genuinely
        # fetched; outer's later, competing claim is what raises.
        foo_pin_hash = _content_hash_for(mocked_dir, foo_pin_url, "v9.9.9")
        assert env.store.contains(foo_pin_hash)


class TestTwoDisagreeingUrlsForRegistryNameBothConflict:
    """Three transitives claim ``shared``: one by bare name (registry), and
    two via DIFFERENT self-declared URLs — neither of which matches the
    registry's recorded source (each independently WARNS via the
    registry-shadow tripwire, S3c, but is accepted). Under
    ``BindingResolver`` (RFC origin-as-identity §4.3), these are THREE
    mutually-disagreeing non-root claims for one name — whichever pair
    ``BindingResolver`` compares second raises ``RES-BINDING-CONFLICT``."""

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
        import warnings as _warnings
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore")
            with pytest.raises(MilpaError) as exc_info:
                _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_BINDING_CONFLICT
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
    competing claim anywhere else in the graph. Under the registry-shadow
    tripwire (RFC origin-as-identity §6.1/§11 D-Fork1, S3c) this is
    NAME-TRIGGERED (bare name shadows a registry coordinate) +
    URL-REFINED (the source doesn't match) — WARN by default (a fork is
    legitimate and common; the claim still resolves and is genuinely
    fetched), HARD-FAIL under ``attestation-policy strict``."""

    def _stage_fixture(self, tmp_path: Path):
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
        return t1_url, foo_pin_hash, env

    def test_warns_and_resolves_under_default_policy(self, tmp_path: Path) -> None:
        t1_url, foo_pin_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            graph = _resolve(root_kdl, env, tmp_path)
        assert any("foo" in str(w.message) for w in caught)
        foo = _dep(graph, "foo")
        assert foo.identity == foo_pin_hash
        assert env.store.contains(foo_pin_hash)

    def test_hard_fails_under_strict_policy(self, tmp_path: Path) -> None:
        t1_url, foo_pin_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\nattestation-policy "strict"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_REGISTRY_SHADOW
        assert "foo" in exc_info.value.message
        assert not env.store.contains(foo_pin_hash)


class TestOciOnlyRegistryEntryContentHashMatchAccepted:
    """Historical note: under the retired validate-against-registry design
    this fixture demonstrated ACCEPTANCE via a post-fetch content-hash
    match (amoxtli's ``softlink`` case) — an OCI-only registry entry has no
    git source recorded to URL-compare against, so that design deferred to
    content identity. Under the registry-shadow tripwire (RFC
    origin-as-identity §6.1/§11 D-Fork1, S3c, final design), there is NO
    post-fetch content-hash reconciliation at all: an OCI-only entry has no
    comparable upstream URL, so a git= claim shadowing its bare name always
    WARNS (default policy — not a hard error; ``content_hash`` still
    verifies bytes at materialization independently, just no longer
    participates in this admission decision) and HARD-FAILS under
    ``attestation-policy strict`` — regardless of whether the fetched
    content happens to match the registry's recorded content_hash."""

    def _stage_fixture(self, tmp_path: Path):
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        foo_source_url = "https://github.com/example/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_source_url}" ref="v1.0.0"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_source_url, "v1.0.0", sha="2" * 40, marker="foo-src")

        foo_hash = _content_hash_for(mocked_dir, foo_source_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg_oci(
            "foo", registry="ghcr.io", repository="example/foo",
            digest="sha256:" + "b" * 64, content_hash=foo_hash,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)
        return t1_url, foo_hash, env

    def test_warns_and_resolves_under_default_policy(self, tmp_path: Path) -> None:
        t1_url, foo_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            graph = _resolve(root_kdl, env, tmp_path)
        assert any("foo" in str(w.message) for w in caught)
        foo = _dep(graph, "foo")
        assert foo.identity == foo_hash
        assert env.store.contains(foo_hash)

    def test_hard_fails_under_strict_policy(self, tmp_path: Path) -> None:
        t1_url, foo_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\nattestation-policy "strict"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_REGISTRY_SHADOW
        assert "foo" in exc_info.value.message
        assert not env.store.contains(foo_hash)


class TestOciOnlyRegistryEntryContentHashMismatchConflicts:
    """Same OCI-only shape, except the transitive's git source fetches to
    DIFFERENT content than anything the registry has recorded for ``foo``.
    Under the retired design this MUST raise post-fetch (content-hash is
    the only comparable fact for an OCI-only entry). Under the
    registry-shadow tripwire (S3c) the outcome is identical to the
    content-hash-MATCH case above — content_hash no longer participates in
    this decision at all — WARN by default, HARD-FAIL under strict."""

    def _stage_fixture(self, tmp_path: Path):
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        foo_fork_url = "https://github.com/example/foo-fork.git"
        foo_registry_oci_source_url = "https://github.com/example/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_fork_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_fork_url, "main", sha="2" * 40, marker="fork")
        _stage(
            mocked_dir, foo_registry_oci_source_url, "v1.0.0", sha="3" * 40,
            marker="registry-original",
        )

        foo_fork_hash = _content_hash_for(mocked_dir, foo_fork_url, "main")
        foo_registry_hash = _content_hash_for(
            mocked_dir, foo_registry_oci_source_url, "v1.0.0"
        )
        assert foo_fork_hash != foo_registry_hash
        index_kdl = _index_kdl_one_pkg_oci(
            "foo", registry="ghcr.io", repository="example/foo",
            digest="sha256:" + "b" * 64, content_hash=foo_registry_hash,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)
        return t1_url, foo_fork_hash, env

    def test_warns_and_resolves_under_default_policy(self, tmp_path: Path) -> None:
        t1_url, foo_fork_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            graph = _resolve(root_kdl, env, tmp_path)
        assert any("foo" in str(w.message) for w in caught)
        foo = _dep(graph, "foo")
        assert foo.identity == foo_fork_hash
        assert env.store.contains(foo_fork_hash)

    def test_hard_fails_under_strict_policy(self, tmp_path: Path) -> None:
        t1_url, foo_fork_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\nattestation-policy "strict"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_REGISTRY_SHADOW
        assert "foo" in exc_info.value.message
        assert not env.store.contains(foo_fork_hash)


class TestOciOnlyRegistryEntryEmptyContentHashConflicts:
    """The registry entry is OCI-only AND carries no ``content_hash``
    (legacy entry, predating the identity mandate). Under the retired
    design there was nothing to validate against, even deferred, so this
    conflicted immediately. Under the registry-shadow tripwire (S3c) the
    outcome is identical to the other OCI-only shapes above — an OCI-only
    entry has no comparable URL regardless of whether it carries a
    content_hash at all — WARN by default, HARD-FAIL under strict."""

    def _stage_fixture(self, tmp_path: Path):
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        foo_source_url = "https://github.com/example/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_source_url}" ref="v1.0.0"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_source_url, "v1.0.0", sha="2" * 40, marker="foo-src")

        foo_hash = _content_hash_for(mocked_dir, foo_source_url, "v1.0.0")
        index_kdl = _index_kdl_one_pkg_oci(
            "foo", registry="ghcr.io", repository="example/foo",
            digest="sha256:" + "b" * 64, content_hash="",
        )
        env = _env(tmp_path, mocked_dir, index_kdl)
        return t1_url, foo_hash, env

    def test_warns_and_resolves_under_default_policy(self, tmp_path: Path) -> None:
        t1_url, foo_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            graph = _resolve(root_kdl, env, tmp_path)
        assert any("foo" in str(w.message) for w in caught)
        foo = _dep(graph, "foo")
        assert foo.identity == foo_hash
        assert env.store.contains(foo_hash)

    def test_hard_fails_under_strict_policy(self, tmp_path: Path) -> None:
        t1_url, foo_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\nattestation-policy "strict"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_REGISTRY_SHADOW
        assert "foo" in exc_info.value.message
        assert not env.store.contains(foo_hash)


class TestOciSourceUrlMatchAcceptedAcrossVersionDrift:
    """The real gap this fixture closes (the amoxtli/softlink@main case in
    miniature): the registry entry for ``foo`` is OCI-only, but records the
    ``source_url`` it was published FROM. A transitive pins ``foo`` by that
    SAME git URL, but at a ref (``main``) that was NEVER published as a
    registry version (the registry only has ``v1.0.0``). Content-hash
    comparison would conflict here (``main``'s tree differs from the
    published ``v1.0.0`` tree) — but the ``source_url`` URL-match accepts
    it outright, regardless of version/ref drift, because it is
    unambiguously the same source repository. Conformance fixture-452
    mirrors this scenario."""

    def test_transitive_pinned_ahead_of_published_version_is_accepted(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        foo_source_url = "https://github.com/example/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_source_url}" ref="main"\n'
                "}\n"
            ),
        )
        # The transitive pins `main`, a ref AHEAD of (and with different
        # content than) the published v1.0.0 — content-hash would conflict.
        _stage(mocked_dir, foo_source_url, "main", sha="2" * 40, marker="foo-at-main")
        _stage(
            mocked_dir, foo_source_url, "v1.0.0", sha="3" * 40,
            marker="foo-at-v1.0.0",
        )

        foo_v1_hash = _content_hash_for(mocked_dir, foo_source_url, "v1.0.0")
        foo_main_hash = _content_hash_for(mocked_dir, foo_source_url, "main")
        assert foo_v1_hash != foo_main_hash

        index_kdl = _index_kdl_one_pkg_oci_with_source(
            "foo", registry="ghcr.io", repository="example/foo",
            digest="sha256:" + "b" * 64, content_hash=foo_v1_hash,
            source_url=foo_source_url,
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
        # Accepted as the `main`-pinned identity — NOT reconciled against
        # (or rejected in favor of) the registry's v1.0.0 content_hash.
        assert foo.identity == foo_main_hash
        assert env.store.contains(foo_main_hash)


class TestOciSourceUrlMismatchConflicts:
    """Same OCI-with-``source_url`` shape as above, except the transitive
    pins a DIFFERENT repository. The registry-shadow tripwire (S3c)
    compares the claim's normalized URL against the OCI entry's recorded
    ``source_url`` (a directly comparable fact, same as a git provenance
    URL) — a mismatch WARNS by default (the claim still resolves and is
    genuinely fetched) and HARD-FAILS under ``attestation-policy strict``
    (never fetched)."""

    def _stage_fixture(self, tmp_path: Path):
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        t1_url = "https://example.com/t1.git"
        foo_fork_url = "https://github.com/example/foo-fork.git"
        foo_registry_source_url = "https://github.com/example/foo.git"

        _stage(
            mocked_dir, t1_url, "main", sha="1" * 40,
            kdl=(
                'name "t1"\nkind "library"\ndeps {\n'
                f'    foo git=(url)"{foo_fork_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, foo_fork_url, "main", sha="2" * 40, marker="fork")
        _stage(
            mocked_dir, foo_registry_source_url, "v1.0.0", sha="3" * 40,
            marker="registry-original",
        )

        foo_registry_hash = _content_hash_for(
            mocked_dir, foo_registry_source_url, "v1.0.0"
        )
        index_kdl = _index_kdl_one_pkg_oci_with_source(
            "foo", registry="ghcr.io", repository="example/foo",
            digest="sha256:" + "b" * 64, content_hash=foo_registry_hash,
            source_url=foo_registry_source_url,
        )
        env = _env(tmp_path, mocked_dir, index_kdl)
        foo_fork_hash = _content_hash_for(mocked_dir, foo_fork_url, "main")
        return t1_url, foo_fork_hash, env

    def test_warns_and_resolves_under_default_policy(self, tmp_path: Path) -> None:
        t1_url, foo_fork_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            graph = _resolve(root_kdl, env, tmp_path)
        assert any("foo" in str(w.message) for w in caught)
        foo = _dep(graph, "foo")
        assert foo.identity == foo_fork_hash
        assert env.store.contains(foo_fork_hash)

    def test_hard_fails_under_strict_policy(self, tmp_path: Path) -> None:
        t1_url, foo_fork_hash, env = self._stage_fixture(tmp_path)
        root_kdl = (
            'name "myapp"\nkind "application"\nattestation-policy "strict"\n'
            "deps {\n"
            f'    t1 git=(url)"{t1_url}" ref="main"\n'
            "}\n"
        )
        with pytest.raises(MilpaError) as exc_info:
            _resolve(root_kdl, env, tmp_path)
        assert exc_info.value.slug == RES_REGISTRY_SHADOW
        assert "foo" in exc_info.value.message
        assert not env.store.contains(foo_fork_hash)


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
    entry at all — no shadow check is even possible (nothing to shadow).
    ``BindingResolver`` (RFC origin-as-identity §4.3) still raises
    ``RES-BINDING-CONFLICT``: two non-root claims for one name, no root
    claim to arbitrate."""

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
        assert exc_info.value.slug == RES_BINDING_CONFLICT
        assert "shared" in exc_info.value.message
