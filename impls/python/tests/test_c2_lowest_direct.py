"""C2 (resolver-semantics RFC §3 Axis C / §4 stage 4, D-C2, #111): `--strategy
lowest-direct` end to end through `resolve()`.

``tests/test_solver.py``'s ``TestEffectiveStrategyPrecompute`` covers the
solver-internal mechanism (``_effective_strategy_for``'s MINVER/MAXVER split,
and ``solve()`` over a synthetic in-memory provider) in isolation. This file
proves the RESOLVER wires the real ``root_authority`` set into that mechanism
for real named/index deps via ``_Provider.is_root_direct`` — the whole point
of the design deepening being that a ROOT-DIRECT dep and a PURELY TRANSITIVE
dep, both with multiple candidate versions, get opposite picks under the
SAME configured strategy.

No mocking: real git-backed mocked fetches (``mocked_registry``) + a real
in-memory ``Index`` (``parse_index``), same infra as
``test_b2_prior_lock_preference.py``.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import ResolvedGraph
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import resolve
from milpa.version import Strategy


def _make_git_mock(
    mocked_dir: Path,
    url: str,
    ref: str,
    *,
    sha: str,
    nim_name: str,
    marker: str,
    requires: str = "",
) -> None:
    """Stage one ``mocked-fetches/<url_key>/`` dir with distinct content per
    ``marker`` so each (url, ref) pair gets its own content_hash.

    ``requires`` (bare-name, unconstrained form — nimble.py's §5.1 form 1) is
    injected into the ``.nimble`` body so a version can introduce a
    TRANSITIVE named dep — the shape this file's contrast test needs.
    """
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / f"{nim_name}.nim").write_text(f"# {nim_name} {marker}\n", encoding="utf-8")
    requires_line = f'requires "{requires}"\n' if requires else ""
    (d / f"{nim_name}.nimble").write_text(
        f'# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n{requires_line}',
        encoding="utf-8",
    )
    (d / "sha").write_text(sha, encoding="utf-8")


def _content_hash_for(mocked_dir: Path, url: str, ref: str, name: str) -> str:
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
        nimble_src = key_dir / f"{name}.nimble"
        if nimble_src.is_file():
            shutil.copy2(nimble_src, dest / f"{name}.nimble")
        return compute_content_hash(dest)


def _stage_two_versions(
    mocked_dir: Path, name: str, *, sha_prefix: str, requires: str = ""
) -> tuple[str, str]:
    """Stage v1.0.0 + v2.0.0 mocked git content for a named dep, return their
    (content_hash_v1, content_hash_v2)."""
    url = f"https://example.com/{name}.git"
    _make_git_mock(
        mocked_dir, url, "v1.0.0", sha=f"{sha_prefix}1" * 20, nim_name=name,
        marker="v1", requires=requires,
    )
    _make_git_mock(
        mocked_dir, url, "v2.0.0", sha=f"{sha_prefix}2" * 20, nim_name=name,
        marker="v2", requires=requires,
    )
    h1 = _content_hash_for(mocked_dir, url, "v1.0.0", name)
    h2 = _content_hash_for(mocked_dir, url, "v2.0.0", name)
    return h1, h2


def _index_kdl_two_pkgs(
    *,
    direct_hashes: tuple[str, str],
    transitive_hashes: tuple[str, str],
) -> str:
    def pkg_block(name: str, hashes: tuple[str, str]) -> str:
        h1, h2 = hashes
        return f"""\
package "{name}" {{
    version "1.0.0" {{
        content_hash "{h1}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v1.0.0"
            commit_sha "{'a' * 40}"
        }}
    }}
    version "2.0.0" {{
        content_hash "{h2}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v2.0.0"
            commit_sha "{'b' * 40}"
        }}
    }}
}}
"""

    return (
        "schema_version 1\n"
        + pkg_block("direct", direct_hashes)
        + pkg_block("transitive", transitive_hashes)
    )


def _env(tmp_path: Path, mocked_dir: Path, index_kdl: str) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _versions(graph: ResolvedGraph) -> dict[str, str]:
    return {d.name: d.version for d in graph.deps}


def _resolve(root_kdl: str, env: MilpaEnv, tmp_path: Path, *, strategy: Strategy) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(manifest, deps_dir, env, ResolveParams(strategy=strategy))


# Root manifest declares ONLY "direct" — "transitive" is never root-declared;
# it is discovered lazily via "direct"'s own `.nimble` `requires` line.
_ROOT_KDL = (
    'name "myapp"\nkind "application"\n'
    "deps {\n"
    "    direct\n"
    "}\n"
)


class TestLowestDirectContrast:
    """The whole point of the effective-strategy precompute: under ONE
    configured strategy (``lowest-direct``), a root-direct dep and a purely
    transitive dep — both with multiple satisfying candidates — get OPPOSITE
    picks."""

    def test_root_direct_picks_lowest_transitive_picks_highest(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        direct_hashes = _stage_two_versions(
            mocked_dir, "direct", sha_prefix="1", requires="transitive"
        )
        transitive_hashes = _stage_two_versions(mocked_dir, "transitive", sha_prefix="2")
        index_kdl = _index_kdl_two_pkgs(
            direct_hashes=direct_hashes, transitive_hashes=transitive_hashes
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        graph = _resolve(_ROOT_KDL, env, tmp_path, strategy=Strategy.LOWEST_DIRECT)
        versions = _versions(graph)
        assert versions["direct"] == "1.0.0"  # root-direct -> MINVER
        assert versions["transitive"] == "2.0.0"  # transitive -> MAXVER (unchanged default)

    def test_plain_maxver_picks_highest_for_both(self, tmp_path: Path) -> None:
        """Sanity control: with the ORDINARY default strategy (maxver), both
        deps pick highest — proving the contrast above is really caused by
        `lowest-direct`'s root-direct/transitive split, not some unrelated
        effect of the two-package/requires shape."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        direct_hashes = _stage_two_versions(
            mocked_dir, "direct", sha_prefix="1", requires="transitive"
        )
        transitive_hashes = _stage_two_versions(mocked_dir, "transitive", sha_prefix="2")
        index_kdl = _index_kdl_two_pkgs(
            direct_hashes=direct_hashes, transitive_hashes=transitive_hashes
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        graph = _resolve(_ROOT_KDL, env, tmp_path, strategy=Strategy.MAXVER)
        versions = _versions(graph)
        assert versions["direct"] == "2.0.0"
        assert versions["transitive"] == "2.0.0"


# ---------------------------------------------------------------------------
# R6 regression: `is_root_direct` must compare FULL identity (name AND
# namespace), not just the bare name — see resolver.py's `_Provider.
# is_root_direct` / `root_direct_keys`.
# ---------------------------------------------------------------------------


class TestIsRootDirectNamespaceAware:
    """Direct unit coverage of ``_Provider.is_root_direct`` against a
    hand-built namespace-aware authority set — no fetch/solve involved.

    Pre-fix, ``is_root_direct`` decomposed ``package`` to its bare name and
    checked membership in a BARE-NAME authority set, so a root dep
    ``ns1::foo`` would wrongly make an unrelated ``ns2::foo`` look
    root-direct. The fix (R6) compares the FULL ``DepKey`` (name + namespace)
    against a namespace-aware ``root_direct_keys`` set.
    """

    def _provider(self, root_direct_keys: set) -> object:
        from milpa.resolver import _Provider

        return _Provider(
            env=MilpaEnv(fetcher=None, index=None, store=None),  # type: ignore[arg-type]
            deps_dir=Path("/nonexistent"),
            params=ResolveParams(),
            overrides_by_name={},
            root_authority=set(),
            root_direct_keys=root_direct_keys,
            seen_named=set(),
            seen_url=set(),
            provenance_gate={},
        )

    def test_matches_same_name_same_namespace(self) -> None:
        from milpa.version import DepKey

        provider = self._provider({DepKey(name="foo", namespace="ns1")})
        assert provider.is_root_direct("ns1::foo") is True

    def test_does_not_match_same_name_different_namespace(self) -> None:
        """The R6 bug: a root ``ns1::foo`` must NOT make an unrelated,
        purely-transitive ``ns2::foo`` look root-direct."""
        from milpa.version import DepKey

        provider = self._provider({DepKey(name="foo", namespace="ns1")})
        assert provider.is_root_direct("ns2::foo") is False

    def test_bare_package_not_matched_by_namespaced_root_dep(self) -> None:
        from milpa.version import DepKey

        provider = self._provider({DepKey(name="foo", namespace="ns1")})
        assert provider.is_root_direct("foo") is False

    def test_bare_root_dep_still_matches_bare_package(self) -> None:
        """No-namespace common case is unaffected by the fix — a bare root
        dep still makes the bare package look root-direct."""
        from milpa.version import DepKey

        provider = self._provider({DepKey(name="foo", namespace=None)})
        assert provider.is_root_direct("foo") is True


def _stage_two_versions_ns(
    mocked_dir: Path, name: str, namespace: str, *, sha_prefix: str
) -> tuple[str, str]:
    """Like ``_stage_two_versions`` but keys the git fixture by a
    namespace-distinct URL, so ``ns1::foo`` and ``ns2::foo`` are backed by
    DISTINCT content (never confused with each other)."""
    url = f"https://example.com/{namespace}/{name}.git"
    _make_git_mock(
        mocked_dir, url, "v1.0.0", sha=f"{sha_prefix}1" * 20, nim_name=name,
        marker=f"{namespace}-v1",
    )
    _make_git_mock(
        mocked_dir, url, "v2.0.0", sha=f"{sha_prefix}2" * 20, nim_name=name,
        marker=f"{namespace}-v2",
    )
    h1 = _content_hash_for(mocked_dir, url, "v1.0.0", name)
    h2 = _content_hash_for(mocked_dir, url, "v2.0.0", name)
    return h1, h2


def _index_kdl_namespaced_pkg(
    name: str, namespace: str, hashes: tuple[str, str]
) -> str:
    h1, h2 = hashes
    url = f"https://example.com/{namespace}/{name}.git"
    return f"""\
package "{name}" {{
    namespace "{namespace}"
    version "1.0.0" {{
        content_hash "{h1}"
        provenance {{
            kind "git"
            url "{url}"
            ref "v1.0.0"
            commit_sha "{'a' * 40}"
        }}
    }}
    version "2.0.0" {{
        content_hash "{h2}"
        provenance {{
            kind "git"
            url "{url}"
            ref "v2.0.0"
            commit_sha "{'b' * 40}"
        }}
    }}
}}
"""


def _stage_carrier(mocked_dir: Path, milpakdl_text: str) -> None:
    """Stage a URL dep ('carrier') whose fetched content is JUST a
    ``milpa.kdl`` (no ``.nimble``) declaring a namespace-qualified named dep
    — the transitive-declaration path (H2/S5b: transitive milpa.kdl deps
    carry their declared namespace through, unlike `.nimble` requires lines
    which have no namespace syntax)."""
    url = "https://example.com/carrier.git"
    key_dir = mocked_dir / url_key(url, "main")
    content_dir = key_dir / "content"
    content_dir.mkdir(parents=True)
    (content_dir / "milpa.kdl").write_text(milpakdl_text, encoding="utf-8")
    (key_dir / "sha").write_text("c" * 40, encoding="utf-8")


# Root manifest: "foo" is root-DIRECT under namespace "ns1". "carrier" is a
# root-direct URL dep whose own milpa.kdl declares a TRANSITIVE named dep on
# "foo" under a DIFFERENT namespace "ns2" — same bare name, unrelated
# package. Pre-fix, root's ns1::foo would leak into ns2::foo's
# classification via the bare-name-only root_authority check.
_ROOT_KDL_NS = (
    'name "myapp"\nkind "application"\n'
    "deps {\n"
    '    foo namespace="ns1"\n'
    '    carrier git=(url)"https://example.com/carrier.git" ref="main"\n'
    "}\n"
)

_CARRIER_KDL = (
    'name "carrier"\nkind "library"\n'
    "deps {\n"
    '    foo namespace="ns2"\n'
    "}\n"
)


def _stage_ns_fixture(tmp_path: Path) -> MilpaEnv:
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    ns1_hashes = _stage_two_versions_ns(mocked_dir, "foo", "ns1", sha_prefix="1")
    ns2_hashes = _stage_two_versions_ns(mocked_dir, "foo", "ns2", sha_prefix="2")
    _stage_carrier(mocked_dir, _CARRIER_KDL)
    index_kdl = (
        "schema_version 1\n"
        + _index_kdl_namespaced_pkg("foo", "ns1", ns1_hashes)
        + _index_kdl_namespaced_pkg("foo", "ns2", ns2_hashes)
    )
    return _env(tmp_path, mocked_dir, index_kdl)


def _by_name_namespace(graph: ResolvedGraph) -> dict[tuple[str, str | None], str]:
    return {(d.name, d.namespace): d.version for d in graph.deps}


class TestNamespaceQualifiedTransitiveNotConfusedWithRootDirect:
    """R6: a namespace-qualified TRANSITIVE dep sharing a bare name with an
    unrelated ROOT-direct dep (different namespace) must be classified as
    transitive, not root-direct."""

    def test_transitive_gets_transitive_default_not_minver(
        self, tmp_path: Path
    ) -> None:
        env = _stage_ns_fixture(tmp_path)

        graph = _resolve(_ROOT_KDL_NS, env, tmp_path, strategy=Strategy.LOWEST_DIRECT)
        versions = _by_name_namespace(graph)
        assert versions[("foo", "ns1")] == "1.0.0", (
            "root-direct ns1::foo -> MINVER under lowest-direct"
        )
        assert versions[("foo", "ns2")] == "2.0.0", (
            "purely-transitive ns2::foo must get the TRANSITIVE default "
            "(MAXVER), not MINVER — pre-fix, the bare-name root_authority "
            "check misclassified it as root-direct because an unrelated "
            "root dep 'ns1::foo' shares its bare name"
        )

    def test_transitive_keeps_lock_preference_root_direct_still_bypasses(
        self, tmp_path: Path
    ) -> None:
        """C3 bypass scoping: under an EXPLICIT lowest-direct strategy
        diverging from a maxver-recorded lock, root-direct ns1::foo bypasses
        its lock pin (as always), but the purely-transitive ns2::foo must
        KEEP its lock pin — pre-fix it would ALSO bypass (misclassified as
        root-direct) and fresh-pick MINVER instead."""
        from milpa.lockfile import Lockfile, LockedDep

        env = _stage_ns_fixture(tmp_path)

        def _locked_dep_ns(name: str, namespace: str, version: str) -> LockedDep:
            return LockedDep(
                name=name,
                namespace=namespace,
                identity="sha256:" + ("0" * 64),
                version=version,
                src_dir="",
                requires=(),
                provenances=(),
            )

        # Both pins are the OPPOSITE of what each package's fresh MINVER
        # pick would be (1.0.0), so "bypassed" (fresh MINVER wins) and
        # "kept" (locked pin wins) are unambiguous for BOTH deps.
        prior = Lockfile(
            deps=(
                _locked_dep_ns("foo", "ns1", "2.0.0"),
                _locked_dep_ns("foo", "ns2", "2.0.0"),
            ),
            strategy="maxver",
        )

        manifest = parse_manifest(_ROOT_KDL_NS)
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir(exist_ok=True)
        graph = resolve(
            manifest,
            deps_dir,
            env,
            ResolveParams(
                strategy=Strategy.LOWEST_DIRECT,
                strategy_explicit=True,
                prior=prior,
            ),
        )
        versions = _by_name_namespace(graph)
        assert versions[("foo", "ns1")] == "1.0.0", (
            "root-direct ns1::foo must BYPASS its lock pin under a "
            "diverging lowest-direct strategy and pick MINVER fresh"
        )
        assert versions[("foo", "ns2")] == "2.0.0", (
            "purely-transitive ns2::foo must KEEP its lock pin (2.0.0) — "
            "pre-fix it would be misclassified as root-direct, wrongly "
            "bypass, and fresh-pick MINVER (1.0.0) instead"
        )
