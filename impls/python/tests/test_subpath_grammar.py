"""S8 — subpath grammar (rfc-origin-as-identity.md §4.1/§10 item 14).

``subpath=`` on git=/tarball= deps, threaded into ``SourceId.subpath`` at
source-id construction (``binding.py``'s ``_dep_declared_raw_origin``) and
escape-guarded by ``source_id.normalize_source`` (single validation
boundary — the manifest parser itself does not validate the string).

Coverage:
  - ``subpath=`` parses on a git dep and a tarball dep; round-trips through
    ``format_manifest`` -> ``parse_manifest``.
  - Absent ``subpath=`` still parses as ``None`` (repo root) — no regression.
  - Two deps on the same URL with different ``subpath=`` values produce
    DIFFERENT ``SourceId``s (and DIFFERENT canonical solver keys) — same
    repo + different subpath is a different origin.
  - A traversing (``..``) or absolute subpath raises ``SRC-ID-MALFORMED``
    at ``normalize_source`` time (the parser accepts the raw string; the
    escape-guard fires when a SourceId is actually constructed for it,
    i.e. at resolve() time).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from milpa.errors import SRC_ID_MALFORMED, MilpaError
from milpa.manifest import TarballDep, UrlDep, format_manifest, parse_manifest
from milpa.source_id import GitSourceId, TarballSourceId, canonical, normalize_source

# ---------------------------------------------------------------------------
# Parse + round-trip
# ---------------------------------------------------------------------------


class TestSubpathParse:
    def test_git_dep_subpath_parses(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                react-dom git=(url)"https://github.com/facebook/react.git" ref="main" subpath="packages/react-dom"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.subpath == "packages/react-dom"

    def test_git_dep_no_subpath_is_none(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://example.com/foo.git" ref="main"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.subpath is None

    def test_tarball_dep_subpath_parses(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball=(url)"https://example.com/pkg.tar.gz" subpath="pkg/foo"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, TarballDep)
        assert dep.subpath == "pkg/foo"

    def test_tarball_dep_no_subpath_is_none(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball=(url)"https://example.com/pkg.tar.gz"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, TarballDep)
        assert dep.subpath is None

    def test_git_dep_subpath_wrong_type_raises(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://example.com/foo.git" ref="main" subpath=#true
            }
        """)
        with pytest.raises(MilpaError):
            parse_manifest(text)

    def test_git_dep_subpath_round_trips(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                react-dom git=(url)"https://github.com/facebook/react.git" ref="main" subpath="packages/react-dom"
            }
        """)
        m = parse_manifest(text)
        out = format_manifest(m)
        assert 'subpath="packages/react-dom"' in out
        m2 = parse_manifest(out)
        assert m2.deps[0].subpath == "packages/react-dom"

    def test_tarball_dep_subpath_round_trips(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball=(url)"https://example.com/pkg.tar.gz" subpath="pkg/foo"
            }
        """)
        m = parse_manifest(text)
        out = format_manifest(m)
        assert 'subpath="pkg/foo"' in out
        m2 = parse_manifest(out)
        assert m2.deps[0].subpath == "pkg/foo"


# ---------------------------------------------------------------------------
# Same repo + different subpath = different SourceId (injectivity / distinct
# origins) — RFC §4.1: "Same repo + different subpath = different source-ids"
# ---------------------------------------------------------------------------


class TestSubpathDistinctOrigins:
    def test_same_url_different_subpath_distinct_source_ids(self) -> None:
        url = "https://github.com/facebook/react.git"
        a = normalize_source(GitSourceId(url=url, subpath="packages/react-dom"))
        b = normalize_source(GitSourceId(url=url, subpath="packages/react"))
        c = normalize_source(GitSourceId(url=url, subpath=None))
        assert a != b
        assert a != c
        assert b != c
        assert canonical(a) != canonical(b) != canonical(c)

    def test_same_url_same_subpath_equal_source_ids(self) -> None:
        url = "https://example.com/pkg.tar.gz"
        a = normalize_source(TarballSourceId(url=url, subpath="pkg/foo"))
        b = normalize_source(TarballSourceId(url=url, subpath="pkg/foo"))
        assert a == b
        assert canonical(a) == canonical(b)


# ---------------------------------------------------------------------------
# Escape-guard: malformed/traversing subpath -> SRC-ID-MALFORMED
# ---------------------------------------------------------------------------


class TestSubpathEscapeGuard:
    def test_traversing_subpath_raises_src_id_malformed(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            normalize_source(GitSourceId(url="https://example.com/foo.git", subpath="../x"))
        assert exc_info.value.slug == SRC_ID_MALFORMED

    def test_absolute_subpath_raises_src_id_malformed(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            normalize_source(GitSourceId(url="https://example.com/foo.git", subpath="/abs"))
        assert exc_info.value.slug == SRC_ID_MALFORMED

    def test_empty_subpath_raises_src_id_malformed(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            normalize_source(TarballSourceId(url="https://example.com/pkg.tar.gz", subpath=""))
        assert exc_info.value.slug == SRC_ID_MALFORMED

    def test_nested_traversal_segment_raises_src_id_malformed(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            normalize_source(
                GitSourceId(url="https://example.com/foo.git", subpath="pkg/../../etc")
            )
        assert exc_info.value.slug == SRC_ID_MALFORMED

    def test_manifest_parse_accepts_traversing_subpath_string(self) -> None:
        """The parser itself does NOT validate subpath — normalize_source is
        the SOLE validation boundary (source_id.py's module docstring); a
        traversing string parses fine at the manifest layer and only fails
        when a SourceId is actually constructed from it (resolve() time)."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://example.com/foo.git" ref="main" subpath="../escape"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert dep.subpath == "../escape"
        with pytest.raises(MilpaError) as exc_info:
            normalize_source(GitSourceId(url=dep.git, subpath=dep.subpath))
        assert exc_info.value.slug == SRC_ID_MALFORMED


# ---------------------------------------------------------------------------
# End-to-end: subpath threaded through resolve() (binding.py's
# _dep_declared_raw_origin) — a traversing subpath on a REAL root dep raises
# SRC-ID-MALFORMED during resolve(), and two deps on the same URL with
# different subpaths resolve as distinct nodes.
# ---------------------------------------------------------------------------


def _build_mocked_env(tmp_path: Path, url: str, ref: str, kdl: str, sha: str):
    from milpa.context import MilpaEnv
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.cas import CAStore

    mocked_dir = tmp_path / "mocked-fetches"
    key = url_key(url, ref)
    d = mocked_dir / key
    (d / "content").mkdir(parents=True)
    (d / "content" / "milpa.kdl").write_text(kdl, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")

    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


class TestSubpathEndToEnd:
    def test_traversing_subpath_on_root_dep_raises_during_resolve(self, tmp_path: Path) -> None:
        from milpa.context import ResolveParams
        from milpa.resolver import resolve

        env = _build_mocked_env(
            tmp_path, "https://example.com/foo.git", "main",
            'name "foo"\nkind "library"\n', "a" * 40,
        )
        root_kdl = textwrap.dedent("""\
            name "myapp"
            kind "application"
            deps {
                foo git=(url)"https://example.com/foo.git" ref="main" subpath="../escape"
            }
        """)
        manifest = parse_manifest(root_kdl)
        with pytest.raises(MilpaError) as exc_info:
            resolve(manifest, tmp_path / "_deps", env, ResolveParams())
        assert exc_info.value.slug == SRC_ID_MALFORMED


# ---------------------------------------------------------------------------
# S8 completeness — BFS candidate dedup (``seen_url``) must be keyed by
# (url, ref, subpath), not (url, ref).  Two root deps sharing the same git
# url + ref but DIFFERENT subpaths are DIFFERENT source-ids (RFC §7 "same
# repo + different subpath = different source-ids, correctly") — each MUST
# get its own claim, candidate, and fetch.  Before the fix, the second dep's
# solver term had no backing ``_Candidate`` at all (the BFS ``seen_url`` gate
# at ``resolver.py``'s ``_run_bfs_wave_loop`` dropped it as an already-seen
# (url, ref) pair, subpath un-consulted): PubGrub then reported the missing
# package as unsatisfiable — ``SOLVE-CONFLICT: ... has no satisfying
# version`` — a hard crash, not a silent single-node resolve.
#
# Note on the post-fix shape: subpath is (per fixture-463 and this RFC slice)
# a pure IDENTITY discriminator, not a partial-checkout mechanism — the
# fetcher still checks out the whole repo and ``compute_content_hash`` still
# hashes the whole tree, so two same-url+ref deps that differ only in
# subpath fetch byte-IDENTICAL content. The separate, pre-existing Phase-B
# merge-on-content-identity pass (``_dedup_candidates``, RFC §3.3
# "merge-on-proof") therefore legitimately folds them into one canonical
# lockfile entry — but VISIBLY (an alias + a collapse note), never silently,
# and only AFTER both independently got their own claim/candidate/fetch.
# That's the completeness bar this test enforces: no crash, both names
# physically fetched, distinct source-ids up to the point of the (correct,
# unrelated) content-identity merge.
# ---------------------------------------------------------------------------


class TestSubpathSeenUrlDedup:
    def test_same_url_ref_different_subpath_resolves_without_conflict(
        self, tmp_path: Path
    ) -> None:
        """RED (pre-fix): raised SOLVE-CONFLICT — pkg-b's solver term had no
        candidate because ``seen_url`` (keyed by bare (url, ref)) silently
        absorbed it into pkg-a's already-seen entry."""
        from milpa.context import ResolveParams
        from milpa.resolver import resolve

        url = "https://example.com/monorepo.git"
        ref = "main"
        env = _build_mocked_env(
            tmp_path, url, ref, 'name "monorepo"\nkind "library"\n', "b" * 40,
        )
        root_kdl = textwrap.dedent(f"""\
            name "myapp"
            kind "application"
            deps {{
                pkg-a git=(url)"{url}" ref="{ref}" subpath="packages/a"
                pkg-b git=(url)"{url}" ref="{ref}" subpath="packages/b"
            }}
        """)
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        # Must not raise SOLVE-CONFLICT (pre-fix behavior).
        graph = resolve(manifest, deps_dir, env, ResolveParams())

        # Both names were independently claimed, candidated, and fetched to
        # disk — proof neither was dropped at the BFS seen_url gate itself
        # (only later, visibly, folded by the unrelated content-identity pass).
        assert (deps_dir / "pkg-a").exists()
        assert (deps_dir / "pkg-b").exists()

        by_name = {d.name: d for d in graph.deps}
        # Byte-identical fetches (subpath is identity-only, not a partial
        # checkout — see module note above) legitimately collapse to ONE
        # canonical top-level entry; which name survives is BFS-declaration-
        # order (pkg-a first), and the collapse is recorded as a VISIBLE
        # alias, never a silent disappearance (RFC §4.7).
        assert "pkg-a" in by_name
        survivor = by_name["pkg-a"]
        assert survivor.source_id is not None
        assert survivor.source_id.subpath == "packages/a"
        assert "pkg-b" in survivor.aliases

        from milpa.lockfile import collapse_notes
        notes = collapse_notes(list(graph.deps))
        assert any("pkg-b" in n and "pkg-a" in n for n in notes)

    def test_same_url_ref_same_subpath_same_name_still_dedups(self, tmp_path: Path) -> None:
        """No regression: TRUE identity (same url+ref+subpath) for the SAME
        name still collapses to one candidate — a root dep re-arriving
        through the BFS arm (e.g. re-declared identically) is a harmless
        re-submission, not a second node."""
        from milpa.context import ResolveParams
        from milpa.resolver import resolve

        url = "https://example.com/monorepo.git"
        ref = "main"
        env = _build_mocked_env(
            tmp_path, url, ref, 'name "monorepo"\nkind "library"\n', "c" * 40,
        )
        root_kdl = textwrap.dedent(f"""\
            name "myapp"
            kind "application"
            deps {{
                pkg-a git=(url)"{url}" ref="{ref}" subpath="packages/a"
            }}
        """)
        manifest = parse_manifest(root_kdl)
        graph = resolve(manifest, tmp_path / "_deps", env, ResolveParams())

        matches = [d for d in graph.deps if d.name == "pkg-a"]
        assert len(matches) == 1
        assert matches[0].source_id is not None
        assert matches[0].source_id.subpath == "packages/a"
