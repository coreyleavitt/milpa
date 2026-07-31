"""A4 (resolver-semantics RFC §3 Axis A (c) / §6 D-A1): the version-unknown
constrained/unconstrained partition, end to end through ``resolve()``.

The conformance corpus (fixture-418/419/420) proves cross-impl slug parity
for these same scenarios; this file asserts on the MESSAGE TEXT the
conformance harness deliberately does not check (only ``MilpaError.slug``) —
in particular the two branches of ``RES-VERSION-UNKNOWN-CONSTRAINED``'s
remedy and the multi-constrainer enumeration. ``tests/test_solver.py``
covers the solver-internal mechanism (decision priority + classification) in
isolation from the resolver's candidate-labeling/lazy-materialization glue.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import MilpaError, RES_VERSION_UNKNOWN_CONSTRAINED
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import resolve


def _make_git_mock(
    mocked_dir: Path,
    url: str,
    ref: str,
    *,
    sha: str,
    nimble: str | None = None,
    kdl: str | None = None,
    nim_name: str = "pkg",
) -> None:
    """Stage one ``mocked-fetches/<url_key>/`` dir (matches _stage_mock_content)."""
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / f"{nim_name}.nim").write_text(f"# {nim_name}\n", encoding="utf-8")
    if kdl is not None:
        (content / "milpa.kdl").write_text(kdl, encoding="utf-8")
    if nimble is not None:
        name = url.rsplit("/", 1)[-1].removesuffix(".git")
        (d / f"{name}.nimble").write_text(nimble, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")


def _content_hash_for(mocked_dir: Path, url: str, ref: str, name: str) -> str:
    """Compute the real content_hash a named-dep candidate would resolve to
    (nimble/milpa.kdl merged with content/, mirroring _stage_mock_content)."""
    import shutil
    import tempfile

    from milpa.identity import compute_content_hash

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


def _env(tmp_path: Path, index_kdl: str | None) -> tuple[MilpaEnv, Path]:
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir(exist_ok=True)
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl) if index_kdl is not None else None
    env = MilpaEnv(fetcher=fetcher, index=index, store=store)
    return env, mocked_dir


def _resolve_and_expect_error(tmp_path: Path, root_kdl: str, env: MilpaEnv) -> MilpaError:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    with pytest.raises(MilpaError) as exc_info:
        resolve(manifest, deps_dir, env, ResolveParams())
    return exc_info.value


class TestVersionUnknownConstrainedRootDeclared:
    """bearssl is root-declared → remedy = annotate it here."""

    def test_root_declared_remedy_branch(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir,
            "https://example.com/bearssl.git",
            "main",
            sha="b" * 40,
            nimble='# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n',
            nim_name="bearssl",
        )
        _make_git_mock(
            mocked_dir,
            "https://example.com/chronos.git",
            "v1.0.0",
            sha="c" * 40,
            nimble=(
                '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n'
                'requires "bearssl >= 0.2.8"\n'
            ),
            nim_name="chronos",
        )
        chronos_hash = _content_hash_for(
            mocked_dir, "https://example.com/chronos.git", "v1.0.0", "chronos"
        )
        index_kdl = f"""\
schema_version 1
package "bearssl" {{
    version "0.1.0" {{
        content_hash "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        provenance {{
            kind "git"
            url "https://example.com/bearssl-index-only.git"
            ref "v0.1.0"
            commit_sha "{'a' * 40}"
        }}
    }}
}}
package "chronos" {{
    version "1.0.0" {{
        content_hash "{chronos_hash}"
        provenance {{
            kind "git"
            url "https://example.com/chronos.git"
            ref "v1.0.0"
            commit_sha "{'c' * 40}"
        }}
    }}
}}
"""
        env, _ = _env(tmp_path, index_kdl)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            '    bearssl git=(url)"https://example.com/bearssl.git" ref="main"\n'
            "    chronos\n"
            "}\n"
        )
        err = _resolve_and_expect_error(tmp_path, root_kdl, env)
        assert err.slug == RES_VERSION_UNKNOWN_CONSTRAINED
        assert "'bearssl'" in err.message
        assert "'chronos' requires '>=0.2.8'" in err.message
        assert "version= annotation" in err.message
        assert "root-level pin" not in err.message


class TestVersionUnknownConstrainedMultipleRealConstrainers:
    """The amoxtli incident, at RESOLVER-message granularity (not just the
    solver-internal exception object, tests/test_solver.py's
    ``test_constrained_version_unknown_enumerates_all_constrainers``): TWO
    independent real consumers (``chronos``, ``asyncdispatch``) each floor
    the same version-unknown ``bearssl`` — the rendered
    ``RES-VERSION-UNKNOWN-CONSTRAINED`` remedy message must name BOTH, not
    just the first one found, so a user fixes every constraint in one pass
    instead of a serial fail-fix-rerun loop."""

    def test_both_constrainers_appear_in_rendered_message(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir,
            "https://example.com/bearssl.git",
            "main",
            sha="b" * 40,
            nimble='# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n',
            nim_name="bearssl",
        )
        _make_git_mock(
            mocked_dir,
            "https://example.com/chronos.git",
            "v1.0.0",
            sha="c" * 40,
            nimble=(
                '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n'
                'requires "bearssl >= 0.2.8"\n'
            ),
            nim_name="chronos",
        )
        _make_git_mock(
            mocked_dir,
            "https://example.com/asyncdispatch.git",
            "v1.0.0",
            sha="d" * 40,
            nimble=(
                '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n'
                'requires "bearssl <= 0.9.0"\n'
            ),
            nim_name="asyncdispatch",
        )
        chronos_hash = _content_hash_for(
            mocked_dir, "https://example.com/chronos.git", "v1.0.0", "chronos"
        )
        asyncdispatch_hash = _content_hash_for(
            mocked_dir, "https://example.com/asyncdispatch.git", "v1.0.0", "asyncdispatch"
        )
        index_kdl = f"""\
schema_version 1
package "bearssl" {{
    version "0.1.0" {{
        content_hash "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        provenance {{
            kind "git"
            url "https://example.com/bearssl-index-only.git"
            ref "v0.1.0"
            commit_sha "{'a' * 40}"
        }}
    }}
}}
package "chronos" {{
    version "1.0.0" {{
        content_hash "{chronos_hash}"
        provenance {{
            kind "git"
            url "https://example.com/chronos.git"
            ref "v1.0.0"
            commit_sha "{'c' * 40}"
        }}
    }}
}}
package "asyncdispatch" {{
    version "1.0.0" {{
        content_hash "{asyncdispatch_hash}"
        provenance {{
            kind "git"
            url "https://example.com/asyncdispatch.git"
            ref "v1.0.0"
            commit_sha "{'d' * 40}"
        }}
    }}
}}
"""
        env, _ = _env(tmp_path, index_kdl)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            '    bearssl git=(url)"https://example.com/bearssl.git" ref="main"\n'
            "    chronos\n"
            "    asyncdispatch\n"
            "}\n"
        )
        err = _resolve_and_expect_error(tmp_path, root_kdl, env)
        assert err.slug == RES_VERSION_UNKNOWN_CONSTRAINED
        assert "'bearssl'" in err.message
        # BOTH real constrainers must be named in the rendered message — not
        # just the first one the solver happened to record.
        assert "'chronos' requires '>=0.2.8'" in err.message
        assert "'asyncdispatch' requires '<=0.9.0'" in err.message
        # And the ``constrainers`` structured payload (err.context) mirrors
        # the message: both entries present, order-independent.
        by_name = {c["by"]: c["constraint"] for c in err.context["constrainers"]}
        assert by_name == {"chronos": ">=0.2.8", "asyncdispatch": "<=0.9.0"}


class TestVersionUnknownConstrainedTransitive:
    """bearssl is introduced only by a transitive package's OWN milpa.kdl —
    no root declaration, no override — → remedy = root-level pin/overrides."""

    def test_purely_transitive_remedy_branch(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir,
            "https://example.com/wrapper.git",
            "main",
            sha="e" * 40,
            kdl=(
                'name "wrapper"\nkind "library"\n'
                "deps {\n"
                '    bearssl git=(url)"https://example.com/bearssl.git" ref="main"\n'
                "}\n"
            ),
            nim_name="wrapper",
        )
        _make_git_mock(
            mocked_dir,
            "https://example.com/bearssl.git",
            "main",
            sha="b" * 40,
            nimble='# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n',
            nim_name="bearssl",
        )
        _make_git_mock(
            mocked_dir,
            "https://example.com/chronos.git",
            "v1.0.0",
            sha="c" * 40,
            nimble=(
                '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n'
                'requires "bearssl >= 0.2.8"\n'
            ),
            nim_name="chronos",
        )
        chronos_hash = _content_hash_for(
            mocked_dir, "https://example.com/chronos.git", "v1.0.0", "chronos"
        )
        index_kdl = f"""\
schema_version 1
package "bearssl" {{
    version "0.1.0" {{
        content_hash "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        provenance {{
            kind "git"
            url "https://example.com/bearssl-index-only.git"
            ref "v0.1.0"
            commit_sha "{'a' * 40}"
        }}
    }}
}}
package "chronos" {{
    version "1.0.0" {{
        content_hash "{chronos_hash}"
        provenance {{
            kind "git"
            url "https://example.com/chronos.git"
            ref "v1.0.0"
            commit_sha "{'c' * 40}"
        }}
    }}
}}
"""
        env, _ = _env(tmp_path, index_kdl)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            '    wrapper git=(url)"https://example.com/wrapper.git" ref="main"\n'
            "    chronos\n"
            "}\n"
        )
        err = _resolve_and_expect_error(tmp_path, root_kdl, env)
        assert err.slug == RES_VERSION_UNKNOWN_CONSTRAINED
        assert "'bearssl'" in err.message
        assert "root-level pin" in err.message
        assert "overrides { bearssl" in err.message
        assert "version= annotation" not in err.message


class TestVersionUnknownUnconstrainedRegression:
    """The fresco/intonaco untagged-branch-pin case: resolves fine, no error."""

    def test_unconstrained_git_dep_resolves(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir,
            "https://example.com/intonaco.git",
            "main",
            sha="i" * 40,
            nimble='# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n',
            nim_name="intonaco",
        )
        env, _ = _env(tmp_path, index_kdl=None)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            '    intonaco git=(url)"https://example.com/intonaco.git" ref="main"\n'
            "}\n"
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir()
        graph = resolve(manifest, deps_dir, env, ResolveParams())
        dep = next(d for d in graph.deps if d.name == "intonaco")
        # A5: a version-unknown dep flattens to "0.0.0" at the lockfile
        # boundary (paired with declared_version_source=None) — not the
        # internal solver sentinel "0.0.1", which stays a decision token
        # only (§5 NORMATIVE).
        assert dep.version == "0.0.0"
        assert dep.declared_version_source is None
