"""D3 (resolution-semantics RFC §3 Axis D / §4 stage 2 — #86): the
exclude-newer hard cut on index/named candidates, applied at the
ENUMERATION layer, end to end through ``resolve()``.

``tests/test_registry.py``'s ``TestFilterByExcludeNewer`` covers the pure
filtering function in isolation. This file proves the resolver actually
wires ``params.exclude_newer`` into ``_enumerate_named_stubs`` for a real
named/index dep — selection (an older version is chosen because a newer one
is filtered out), fail-closed exclusion (no provable ``published_at`` is
never permissively kept), the distinct ``RES-EXCLUDE-NEWER-EMPTY`` error
class (never a generic ``TNG-NO-SATISFYING-VERSION``/``SOLVE-CONFLICT``),
and the no-bound regression (behavior is byte-identical to pre-D3 when
``exclude_newer`` is unset).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import MilpaError, RES_EXCLUDE_NEWER_EMPTY
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import ResolvedGraph
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import _resolve_effective_exclude_newer, resolve


def _make_git_mock(mocked_dir: Path, url: str, ref: str, *, sha: str, nim_name: str, marker: str) -> None:
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / f"{nim_name}.nim").write_text(f"# {nim_name} {marker}\n", encoding="utf-8")
    (d / f"{nim_name}.nimble").write_text(
        '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n', encoding="utf-8"
    )
    (d / "sha").write_text(sha, encoding="utf-8")


def _content_hash_for(mocked_dir: Path, url: str, ref: str, name: str) -> str:
    import shutil
    import tempfile

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


def _index_kdl_one_pkg(
    name: str,
    versions: list[tuple[str, str, str | None]],
) -> str:
    """*versions* is a list of ``(version, commit_sha_char, published_at)``;
    ``published_at`` is ``None`` to omit the node entirely (fail-closed
    exclusion case — an absent field, not a malformed one, but the filter
    treats both identically per ``IndexVersion.published_at``'s own
    absent-or-malformed-collapses-to-None contract)."""
    blocks = []
    for version, sha_char, published_at in versions:
        published_at_line = f'        published_at "{published_at}"\n' if published_at else ""
        blocks.append(
            f"""\
    version "{version}" {{
        content_hash "{_hash_placeholder(name, version)}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v{version}"
            commit_sha "{sha_char * 40}"
        }}
{published_at_line}    }}
"""
        )
    return f'package "{name}" {{\n' + "".join(blocks) + "}\n"


def _hash_placeholder(name: str, version: str) -> str:
    # Overwritten by the real computed hash after staging; see _build_index.
    return f"__HASH__{name}__{version}__"


def _build_index(
    mocked_dir: Path,
    name: str,
    versions: list[tuple[str, str, str | None]],
) -> str:
    """Stage mocked git content for each version and return a real index.kdl
    with real content_hash values substituted in."""
    kdl = _index_kdl_one_pkg(name, versions)
    for version, sha_char, _published_at in versions:
        url = f"https://example.com/{name}.git"
        ref = f"v{version}"
        _make_git_mock(mocked_dir, url, ref, sha=sha_char * 40, nim_name=name, marker=version)
        real_hash = _content_hash_for(mocked_dir, url, ref, name)
        kdl = kdl.replace(_hash_placeholder(name, version), real_hash)
    return "schema_version 1\n" + kdl


def _env(tmp_path: Path, mocked_dir: Path, index_kdl: str) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _resolve(root_kdl: str, env: MilpaEnv, tmp_path: Path, *, exclude_newer: datetime | None = None) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(manifest, deps_dir, env, ResolveParams(exclude_newer=exclude_newer))


def _resolve_and_expect_error(
    root_kdl: str, env: MilpaEnv, tmp_path: Path, *, exclude_newer: datetime | None
) -> MilpaError:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    with pytest.raises(MilpaError) as exc_info:
        resolve(manifest, deps_dir, env, ResolveParams(exclude_newer=exclude_newer))
    return exc_info.value


_ROOT = 'name "myapp"\nkind "application"\ndeps {\n    libfoo\n}\n'


class TestSelectionFiltersNewerCandidates:
    """A newer version whose published_at is after the bound is dropped at
    enumeration, so the solver picks the newest SURVIVING (older) version —
    not the newest overall."""

    def test_older_version_selected_when_newer_is_excluded(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        index_kdl = _build_index(
            mocked_dir,
            "libfoo",
            [
                ("1.0.0", "1", "2026-01-01T00:00:00Z"),
                ("2.0.0", "2", "2026-12-01T00:00:00Z"),
            ],
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        # No bound: newest (2.0.0) wins, as before D3 (regression baseline).
        fresh = _resolve(_ROOT, env, tmp_path, exclude_newer=None)
        assert {d.name: d.version for d in fresh.deps} == {"libfoo": "2.0.0"}

        # Bound between the two publish dates: 2.0.0 is excluded, 1.0.0 wins.
        bounded = _resolve(
            _ROOT, env, tmp_path, exclude_newer=datetime.fromisoformat("2026-06-01T00:00:00Z")
        )
        assert {d.name: d.version for d in bounded.deps} == {"libfoo": "1.0.0"}

    def test_manifest_resolution_offsetless_exclude_newer_does_not_raise(
        self, tmp_path: Path
    ) -> None:
        """R2 end-to-end: a manifest ``resolution { exclude-newer "<ts>" }``
        with NO trailing ``Z``/offset (a very natural thing to type) must
        drive the exact same enumeration-layer index filter as the
        ``Z``-suffixed spelling — never a naive-vs-aware ``TypeError``
        comparing against the index's tz-aware ``published_at`` values."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        index_kdl = _build_index(
            mocked_dir,
            "libfoo",
            [
                ("1.0.0", "1", "2026-01-01T00:00:00Z"),
                ("2.0.0", "2", "2026-12-01T00:00:00Z"),
            ],
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        root_with_offsetless_bound = (
            'name "myapp"\nkind "application"\n'
            'resolution {\n    exclude-newer "2026-06-01T00:00:00"\n}\n'
            "deps {\n    libfoo\n}\n"
        )
        manifest = parse_manifest(root_with_offsetless_bound)
        effective = _resolve_effective_exclude_newer(None, manifest)
        assert effective is not None
        assert effective.tzinfo is not None  # normalized, not left naive

        bounded = _resolve(root_with_offsetless_bound, env, tmp_path, exclude_newer=effective)
        assert {d.name: d.version for d in bounded.deps} == {"libfoo": "1.0.0"}


class TestFailClosedExcludesUnprovableTimestamp:
    """A version with no published_at (absent) is excluded once a bound is
    active, even though it would otherwise satisfy — the RFC's explicit
    override of published_at's ordinarily-permissive default."""

    def test_no_published_at_is_excluded_not_permissively_kept(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        index_kdl = _build_index(
            mocked_dir,
            "libfoo",
            [
                ("1.0.0", "1", "2026-01-01T00:00:00Z"),
                ("2.0.0", "2", None),  # no published_at at all
            ],
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        # No bound: 2.0.0 (no published_at) still wins on maxver — unaffected.
        fresh = _resolve(_ROOT, env, tmp_path, exclude_newer=None)
        assert {d.name: d.version for d in fresh.deps} == {"libfoo": "2.0.0"}

        # Bound active: 2.0.0 is fail-closed excluded (unprovable), 1.0.0 wins
        # — NOT 2.0.0, even though an absent published_at would otherwise be
        # treated permissively everywhere else in the registry layer.
        bounded = _resolve(
            _ROOT, env, tmp_path, exclude_newer=datetime.fromisoformat("2026-06-01T00:00:00Z")
        )
        assert {d.name: d.version for d in bounded.deps} == {"libfoo": "1.0.0"}


class TestEmptiedCandidateSetRaisesDistinctSlug:
    """When the bound excludes EVERY candidate, milpa raises the distinct
    ``RES-EXCLUDE-NEWER-EMPTY`` — never a generic no-satisfying-version /
    solve-conflict — reporting the dropped count."""

    def test_all_candidates_excluded_raises_res_exclude_newer_empty(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        index_kdl = _build_index(
            mocked_dir,
            "libfoo",
            [
                ("1.0.0", "1", "2026-01-01T00:00:00Z"),
                ("2.0.0", "2", "2026-12-01T00:00:00Z"),
            ],
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        err = _resolve_and_expect_error(
            _ROOT, env, tmp_path, exclude_newer=datetime.fromisoformat("2020-01-01T00:00:00Z")
        )
        assert err.slug == RES_EXCLUDE_NEWER_EMPTY
        assert err.context.get("dropped") == 2
        assert err.context.get("name") == "libfoo"

    def test_single_unprovable_candidate_empties_and_raises(self, tmp_path: Path) -> None:
        """The fail-closed case can ALSO empty the set on its own (a package
        with exactly one version and no published_at, under an active
        bound)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        index_kdl = _build_index(mocked_dir, "libfoo", [("1.0.0", "1", None)])
        env = _env(tmp_path, mocked_dir, index_kdl)

        err = _resolve_and_expect_error(
            _ROOT, env, tmp_path, exclude_newer=datetime.fromisoformat("2026-06-01T00:00:00Z")
        )
        assert err.slug == RES_EXCLUDE_NEWER_EMPTY
        assert err.context.get("dropped") == 1


class TestNoBoundIsUnaffected:
    """Regression: with no exclude_newer at all, behavior is byte-identical
    to pre-D3 — newest (maxver) wins regardless of published_at."""

    def test_no_bound_picks_newest_regardless_of_published_at(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        index_kdl = _build_index(
            mocked_dir,
            "libfoo",
            [
                ("1.0.0", "1", "2026-12-01T00:00:00Z"),  # newer publish date...
                ("2.0.0", "2", "2026-01-01T00:00:00Z"),  # ...than this "newer" version
            ],
        )
        env = _env(tmp_path, mocked_dir, index_kdl)
        graph = _resolve(_ROOT, env, tmp_path, exclude_newer=None)
        # maxver picks the highest SEMVER (2.0.0), published_at is irrelevant
        # when no bound is active.
        assert {d.name: d.version for d in graph.deps} == {"libfoo": "2.0.0"}
