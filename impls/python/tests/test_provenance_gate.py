"""resolver-semantics RFC §10.3: the provenance gate fires BEFORE a generic
version-level conflict for the url-vs-url shape, end to end through
``resolve()``.

Existing coverage (conformance fixture-099, Rust's
``resolve_non_root_provenance_disagreement_conflicts``) uses two BARE
no-version deps, so the gate fires trivially — it never actually races a
real version-level conflict, since neither candidate ever carries a version
at all. This file strengthens that: two non-root-authoritative transitives
(``a``, ``b``) each declare the SAME package name (``shared``) from two
DIFFERENT URLs, and EACH url's own ``shared`` carries a DIFFERENT REAL
declared version (via its own ``.nimble`` ``version =``) — the shape a
naive solver could plausibly resolve into a version-level SOLVE-CONFLICT
on the shared name, rather than a provenance disagreement. The root has no
authority over ``shared`` (no direct dep, no override), so the resolver
must still raise ``RES-PROVENANCE-CONFLICT`` — the provenance gate wins,
BEFORE any version data from either candidate is ever consulted.

SCOPE: url-vs-url only (both impls agree the gate fires for two
url-transport claims). A named/index-vs-url case is the #193 divergence
and is deliberately out of scope here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import MilpaError, RES_PROVENANCE_CONFLICT
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.manifest import parse_manifest
from milpa.resolver import resolve


def _make_git_mock(mocked_dir: Path, url: str, ref: str, *, nim_name: str, nimble: str, sha: str) -> None:
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / f"{nim_name}.nim").write_text(f"# {nim_name}\n", encoding="utf-8")
    (d / f"{nim_name}.nimble").write_text(nimble, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")


class TestProvenanceGateWinsOverDifferingRealVersions:
    """Two transitives (a, b) claim ``shared`` from different URLs; each
    URL's ``shared`` carries a genuinely different REAL declared version
    (1.0.0 vs 2.0.0) — the provenance gate must still win, raising
    RES-PROVENANCE-CONFLICT rather than ever reaching a version-level
    SOLVE-CONFLICT (or resolving one of the two arbitrarily)."""

    def test_gate_wins_before_version_data_is_ever_consulted(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        a_url = "https://example.com/a.git"
        b_url = "https://example.com/b.git"
        shared_x_url = "https://x.example.com/shared.git"
        shared_y_url = "https://y.example.com/shared.git"

        _make_git_mock(
            mocked_dir,
            a_url,
            "main",
            nim_name="a",
            nimble=(
                '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n'
                f'requires "{shared_x_url}"\n'
            ),
            sha="a" * 40,
        )
        _make_git_mock(
            mocked_dir,
            b_url,
            "main",
            nim_name="b",
            nimble=(
                '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n'
                f'requires "{shared_y_url}"\n'
            ),
            sha="b" * 40,
        )
        # shared, as claimed by `a` via x.example.com: a REAL declared version.
        _make_git_mock(
            mocked_dir,
            shared_x_url,
            "main",
            nim_name="shared",
            nimble=(
                '# Package\nversion = "1.0.0"\nauthor = "e"\ndescription = "d"\n'
                'license = "MIT"\nsrcDir = "src"\n'
            ),
            sha="1" * 40,
        )
        # shared, as claimed by `b` via y.example.com: a DIFFERENT REAL
        # declared version — a naive solver seeing both candidates under the
        # same name "shared" would face a genuine version-level conflict
        # (1.0.0 vs 2.0.0), not just an unversioned identity clash.
        _make_git_mock(
            mocked_dir,
            shared_y_url,
            "main",
            nim_name="shared",
            nimble=(
                '# Package\nversion = "2.0.0"\nauthor = "e"\ndescription = "d"\n'
                'license = "MIT"\nsrcDir = "src"\n'
            ),
            sha="2" * 40,
        )

        store = CAStore(tmp_path / "cas")
        fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
        env = MilpaEnv(fetcher=fetcher, index=None, store=store)

        # Root has NO direct dep on "shared" and no override — root has no
        # authority over it, so the gate cannot suppress via root-wins;
        # it must raise on the transitive-vs-transitive disagreement.
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    a git=(url)"{a_url}" ref="main"\n'
            f'    b git=(url)"{b_url}" ref="main"\n'
            "}\n"
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir()

        with pytest.raises(MilpaError) as exc_info:
            resolve(manifest, deps_dir, env, ResolveParams())
        err = exc_info.value
        assert err.slug == RES_PROVENANCE_CONFLICT
        assert "shared" in err.message
