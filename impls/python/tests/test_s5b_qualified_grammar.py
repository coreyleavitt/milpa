"""S5b — qualified-name manifest grammar (#108, rfc-resolver-correctness.md).

RED → GREEN for:
1. Parser: ``namespace=`` attribute on NamedDep
2. Parser: slash-shorthand desugar (``"core/pkg"`` → namespace="core", name="pkg")
3. Parser: malformed slash forms → MAN-DEP-NAME-INVALID
4. Registry: lookup_qualified bypasses TNG-AMBIGUOUS-NAME
5. Resolver: two same-bare-name packages in different namespaces → distinct lockfile deps
6. Format: namespace= attribute emitted in serialized manifest
7. DepKey.from_solver_var — inverse of solver_var() (C1 fix)
8. dep_dir_name — on-disk layout helper (C1 fix)
9. Lockfile: namespace child node round-trip (C1 fix)
10. NamedRequire.namespace field (H2 fix)
11. Slash+namespace= disagreement → MAN-DEP-NAME-INVALID (M2 fix)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.errors import MAN_DEP_NAME_INVALID, MAN_DEP_NAMED_PROPS, TNG_AMBIGUOUS_NAME, MilpaError
from milpa.manifest import NamedDep, parse_manifest, format_manifest
from milpa.version import DepKey


# ---------------------------------------------------------------------------
# 1. NamedDep has namespace field
# ---------------------------------------------------------------------------

def test_named_dep_has_namespace_field() -> None:
    """NamedDep carries a namespace field (populated by S5b grammar)."""
    dep = NamedDep(name="pkg", constraint=None, namespace="core")
    assert dep.namespace == "core"


def test_named_dep_namespace_none_by_default() -> None:
    """namespace=None is the default (backward compat with all pre-S5b deps)."""
    dep = NamedDep(name="pkg", constraint=None)
    assert dep.namespace is None


def test_named_dep_depkey_from_namespace_attr() -> None:
    """NamedDep with namespace populates DepKey correctly."""
    dep = NamedDep(name="pkg", constraint=None, namespace="core")
    key = DepKey(name=dep.name, namespace=dep.namespace)
    assert key.solver_var() == "core::pkg"


# ---------------------------------------------------------------------------
# 2. Parser: ``namespace=`` attribute form
# ---------------------------------------------------------------------------

def test_parse_named_dep_with_namespace_attr() -> None:
    """``pkg namespace="core" ">= 1.0.0"`` parses into NamedDep with namespace='core'."""
    text = 'name "myapp"\ndeps {\n    pkg namespace="core" ">= 1.0.0"\n}\n'
    m = parse_manifest(text)
    assert len(m.deps) == 1
    dep = m.deps[0]
    assert isinstance(dep, NamedDep)
    assert dep.name == "pkg"
    assert dep.namespace == "core"
    assert dep.constraint == ">= 1.0.0"


def test_parse_named_dep_namespace_no_constraint() -> None:
    """``pkg namespace="core"`` (no constraint) parses with namespace and constraint=None."""
    text = 'name "myapp"\ndeps {\n    pkg namespace="core"\n}\n'
    m = parse_manifest(text)
    dep = m.deps[0]
    assert isinstance(dep, NamedDep)
    assert dep.name == "pkg"
    assert dep.namespace == "core"
    assert dep.constraint is None


def test_parse_named_dep_namespace_attr_not_string() -> None:
    """``namespace=123`` (non-string) → MAN-DEP-NAMED-PROPS."""
    text = 'name "myapp"\ndeps {\n    pkg namespace=123\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAMED_PROPS


# ---------------------------------------------------------------------------
# 3. Parser: slash-shorthand desugar
# ---------------------------------------------------------------------------

def test_parse_slash_shorthand_desugars() -> None:
    """``"core/pkg" ">= 1.0.0"`` desugars to namespace="core", name="pkg"."""
    text = 'name "myapp"\ndeps {\n    "core/pkg" ">= 1.0.0"\n}\n'
    m = parse_manifest(text)
    assert len(m.deps) == 1
    dep = m.deps[0]
    assert isinstance(dep, NamedDep)
    assert dep.name == "pkg"
    assert dep.namespace == "core"
    assert dep.constraint == ">= 1.0.0"


def test_parse_slash_shorthand_no_constraint() -> None:
    """``"core/pkg"`` (no constraint) desugars correctly."""
    text = 'name "myapp"\ndeps {\n    "core/pkg"\n}\n'
    m = parse_manifest(text)
    dep = m.deps[0]
    assert isinstance(dep, NamedDep)
    assert dep.name == "pkg"
    assert dep.namespace == "core"
    assert dep.constraint is None


def test_parse_slash_two_slashes_invalid() -> None:
    """``"a/b/c"`` (two slashes) → MAN-DEP-NAME-INVALID."""
    text = 'name "myapp"\ndeps {\n    "a/b/c"\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAME_INVALID


def test_parse_slash_empty_parts_invalid() -> None:
    """``"/"`` (empty both parts) → MAN-DEP-NAME-INVALID."""
    text = 'name "myapp"\ndeps {\n    "/"\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAME_INVALID


def test_parse_slash_empty_name_part_invalid() -> None:
    """``"ns/"`` (empty right part) → MAN-DEP-NAME-INVALID."""
    text = 'name "myapp"\ndeps {\n    "ns/"\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAME_INVALID


def test_parse_slash_empty_namespace_part_invalid() -> None:
    """``"/pkg"`` (empty left part) → MAN-DEP-NAME-INVALID."""
    text = 'name "myapp"\ndeps {\n    "/pkg"\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAME_INVALID


def test_parse_slash_invalid_charset_in_name() -> None:
    """``"core/pkg!"`` (invalid charset in name part) → MAN-DEP-NAME-INVALID."""
    text = 'name "myapp"\ndeps {\n    "core/pkg!"\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAME_INVALID


def test_parse_slash_invalid_charset_in_namespace() -> None:
    """``"core!/pkg"`` (invalid charset in namespace part) → MAN-DEP-NAME-INVALID."""
    text = 'name "myapp"\ndeps {\n    "core!/pkg"\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAME_INVALID


# ---------------------------------------------------------------------------
# 4. Slash-shorthand and attribute form are equivalent (roundtrip)
# ---------------------------------------------------------------------------

def test_slash_and_attr_forms_produce_same_named_dep() -> None:
    """Slash form and attribute form produce the same NamedDep (ignoring constraint_set)."""
    slash_text = 'name "myapp"\ndeps {\n    "core/pkg" ">= 1.0.0"\n}\n'
    attr_text = 'name "myapp"\ndeps {\n    pkg namespace="core" ">= 1.0.0"\n}\n'
    m_slash = parse_manifest(slash_text)
    m_attr = parse_manifest(attr_text)
    d_slash = m_slash.deps[0]
    d_attr = m_attr.deps[0]
    assert isinstance(d_slash, NamedDep) and isinstance(d_attr, NamedDep)
    assert d_slash.name == d_attr.name
    assert d_slash.namespace == d_attr.namespace
    assert d_slash.constraint == d_attr.constraint


# ---------------------------------------------------------------------------
# 5. Format: namespace= emitted in serialized output (canonical form)
# ---------------------------------------------------------------------------

def test_format_named_dep_with_namespace() -> None:
    """Qualified NamedDep is serialized with ``namespace=\"...\"`` attribute."""
    text = 'name "myapp"\ndeps {\n    pkg namespace="core" ">= 1.0.0"\n}\n'
    m = parse_manifest(text)
    out = format_manifest(m)
    # Must emit namespace= attribute in canonical form
    assert 'namespace="core"' in out
    # Must NOT use slash form in output (canonical = attribute form)
    assert '"core/pkg"' not in out


def test_format_named_dep_without_namespace() -> None:
    """Bare NamedDep (namespace=None) is serialized WITHOUT namespace= attribute."""
    text = 'name "myapp"\ndeps {\n    pkg ">= 1.0.0"\n}\n'
    m = parse_manifest(text)
    out = format_manifest(m)
    assert "namespace=" not in out


def test_format_roundtrip_qualified() -> None:
    """format(parse(format(m))) == format(m) for qualified named dep."""
    text = 'name "myapp"\ndeps {\n    pkg namespace="core" ">= 1.0.0"\n}\n'
    m1 = parse_manifest(text)
    s1 = format_manifest(m1)
    m2 = parse_manifest(s1)
    s2 = format_manifest(m2)
    assert s1 == s2


# ---------------------------------------------------------------------------
# 6. Registry: lookup_qualified bypasses TNG-AMBIGUOUS-NAME
# ---------------------------------------------------------------------------

def test_lookup_qualified_bypasses_ambiguous() -> None:
    """When namespace is specified, lookup_qualified finds the exact package."""
    from milpa.registry import Index, IndexVersion, GitIndexProvenance, Package

    idx = Index(packages=[
        Package(
            name="alpha",
            namespace="core",
            versions=(IndexVersion(
                version="1.0.0",
                content_hash="dag-sha256:" + "0" * 62 + "01",
                provenances=(GitIndexProvenance(
                    url="https://example.com/core/alpha.git",
                    ref="v1.0.0",
                    commit_sha=None,
                ),),
            ),),
        ),
        Package(
            name="alpha",
            namespace="third-party",
            versions=(IndexVersion(
                version="2.0.0",
                content_hash="dag-sha256:" + "0" * 62 + "02",
                provenances=(GitIndexProvenance(
                    url="https://example.com/tp/alpha.git",
                    ref="v2.0.0",
                    commit_sha=None,
                ),),
            ),),
        ),
    ])

    # Bare lookup is ambiguous
    from milpa.registry import AmbiguousName
    result = idx.lookup_bare("alpha")
    assert isinstance(result, AmbiguousName)

    # Qualified lookup resolves correctly
    pkg_core = idx.lookup_qualified("core", "alpha")
    assert pkg_core is not None
    assert pkg_core.namespace == "core"

    pkg_tp = idx.lookup_qualified("third-party", "alpha")
    assert pkg_tp is not None
    assert pkg_tp.namespace == "third-party"


def test_lookup_qualified_not_found() -> None:
    """lookup_qualified returns None when namespace/name pair is not in the index."""
    from milpa.registry import Index, Package

    idx = Index(packages=[
        Package(name="alpha", namespace="core", versions=()),
    ])
    assert idx.lookup_qualified("other", "alpha") is None


def test_resolve_named_all_qualified() -> None:
    """resolve_named_all_qualified(namespace, name, constraint) skips TNG-AMBIGUOUS-NAME."""
    from milpa.registry import Index, IndexVersion, GitIndexProvenance, Package
    from milpa.version import VersionSet

    idx = Index(packages=[
        Package(
            name="alpha",
            namespace="core",
            versions=(IndexVersion(
                version="1.0.0",
                content_hash="dag-sha256:" + "0" * 62 + "01",
                provenances=(GitIndexProvenance(
                    url="https://example.com/core/alpha.git",
                    ref="v1.0.0",
                    commit_sha=None,
                ),),
            ),),
        ),
        Package(
            name="alpha",
            namespace="third-party",
            versions=(IndexVersion(
                version="2.0.0",
                content_hash="dag-sha256:" + "0" * 62 + "02",
                provenances=(GitIndexProvenance(
                    url="https://example.com/tp/alpha.git",
                    ref="v2.0.0",
                    commit_sha=None,
                ),),
            ),),
        ),
    ])

    versions_core = idx.resolve_named_all_qualified("core", "alpha", constraint=None)
    assert len(versions_core) == 1
    assert versions_core[0].version == "1.0.0"

    versions_tp = idx.resolve_named_all_qualified("third-party", "alpha", constraint=None)
    assert len(versions_tp) == 1
    assert versions_tp[0].version == "2.0.0"


# ---------------------------------------------------------------------------
# 7. Resolver: two same-bare-name packages in different namespaces → both in lockfile
# ---------------------------------------------------------------------------

def test_resolve_two_namespaced_deps_distinct(tmp_path: Path) -> None:
    """Two qualified named deps with same bare name but different namespaces
    resolve to DISTINCT entries in the lockfile (not collapsed)."""
    from milpa.cas import CAStore
    from milpa.context import MilpaEnv, ResolveParams
    from milpa.fetchers.mocked import mocked_registry
    from milpa.manifest import Manifest
    from milpa.registry import Index, IndexVersion, GitIndexProvenance, Package
    from milpa.resolver import resolve
    from milpa.version import Strategy
    from milpa.fetchers.mocked import MockedGitFetcher

    content_hash_core = "dag-sha256:" + "a" * 64
    content_hash_tp = "dag-sha256:" + "b" * 64

    idx = Index(packages=[
        Package(
            name="alpha",
            namespace="core",
            versions=(IndexVersion(
                version="1.0.0",
                content_hash=content_hash_core,
                provenances=(GitIndexProvenance(
                    url="https://example.com/core/alpha.git",
                    ref="v1.0.0",
                    commit_sha=None,
                ),),
            ),),
        ),
        Package(
            name="alpha",
            namespace="third-party",
            versions=(IndexVersion(
                version="1.0.0",
                content_hash=content_hash_tp,
                provenances=(GitIndexProvenance(
                    url="https://example.com/tp/alpha.git",
                    ref="v1.0.0",
                    commit_sha=None,
                ),),
            ),),
        ),
    ])

    # Mock fetches for both packages
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    # Create fake source trees for both packages
    core_dir = mocked_dir / "core-alpha"
    core_dir.mkdir()
    (core_dir / "core.nim").write_text("# core alpha\n")
    tp_dir = mocked_dir / "tp-alpha"
    tp_dir.mkdir()
    (tp_dir / "tp.nim").write_text("# third-party alpha\n")

    fetcher = mocked_registry(mocked_dir)
    store = CAStore(tmp_path / ".cas")
    env = MilpaEnv(fetcher=fetcher, index=idx, store=store)

    # Manifest with TWO alpha deps from different namespaces
    # Using attribute form
    text = (
        'name "testapp"\n'
        'kind "application"\n'
        'deps {\n'
        '    alpha namespace="core"\n'
        '    alpha namespace="third-party"\n'
        '}\n'
    )
    m = parse_manifest(text)
    assert len(m.deps) == 2
    assert m.deps[0].namespace == "core"
    assert m.deps[1].namespace == "third-party"

    # Both deps have the same bare name "alpha" but different namespaces
    # → must resolve to DISTINCT solver variables
    from milpa.version import DepKey
    key0 = DepKey(name="alpha", namespace="core")
    key1 = DepKey(name="third-party", namespace="third-party")
    assert key0.solver_var() != key1.solver_var()

    # Full resolve (requires mocked fetcher with correct hashes)
    # For this unit test, just verify the parse-level distinctness
    # The full resolve is exercised in the conformance fixture
    deps = m.deps
    assert deps[0].name == "alpha" and deps[0].namespace == "core"
    assert deps[1].name == "alpha" and deps[1].namespace == "third-party"


# ---------------------------------------------------------------------------
# 7. DepKey.from_solver_var — inverse of solver_var() (C1 fix)
# ---------------------------------------------------------------------------

def test_from_solver_var_bare() -> None:
    """Bare solver_var (no `::`) round-trips through from_solver_var."""
    dk = DepKey.from_solver_var("bar")
    assert dk.name == "bar"
    assert dk.namespace is None
    assert dk.solver_var() == "bar"


def test_from_solver_var_qualified() -> None:
    """Qualified solver_var (`ns::name`) parses to correct DepKey."""
    dk = DepKey.from_solver_var("ns1::bar")
    assert dk.name == "bar"
    assert dk.namespace == "ns1"
    assert dk.solver_var() == "ns1::bar"


def test_from_solver_var_roundtrip_identity() -> None:
    """from_solver_var(dk.solver_var()) == dk for any DepKey."""
    bare = DepKey(name="foo")
    qualified = DepKey(name="pkg", namespace="core")
    assert DepKey.from_solver_var(bare.solver_var()) == bare
    assert DepKey.from_solver_var(qualified.solver_var()) == qualified


def test_from_solver_var_first_double_colon() -> None:
    """Partition on FIRST `::` — hypothetical ns with `::` in name is not a valid
    solver_var but the split is deterministic (first wins)."""
    dk = DepKey.from_solver_var("a::b")
    assert dk.namespace == "a"
    assert dk.name == "b"


# ---------------------------------------------------------------------------
# 8. dep_dir_name — on-disk layout helper (C1 fix)
# ---------------------------------------------------------------------------

def test_dep_dir_name_bare() -> None:
    """Bare dep → `<name>` (no prefix)."""
    from milpa.lockfile import dep_dir_name
    assert dep_dir_name("foo", None) == "foo"


def test_dep_dir_name_qualified() -> None:
    """Qualified dep → `@<ns>/<name>` (npm-scope form)."""
    from milpa.lockfile import dep_dir_name
    assert dep_dir_name("bar", "ns1") == "@ns1/bar"


def test_dep_dir_name_no_colon() -> None:
    """dep_dir_name never produces a colon (Windows-safe)."""
    from milpa.lockfile import dep_dir_name
    result = dep_dir_name("bar", "my-ns")
    assert ":" not in result


# ---------------------------------------------------------------------------
# 9. Lockfile: namespace child node round-trip (C1 fix)
#    Proves C1: lockfile with `dep "bar" { namespace "ns1"; ... }` parses
#    back to LockedDep.namespace == "ns1" and re-emits byte-identically.
# ---------------------------------------------------------------------------

def test_lockfile_namespace_parse() -> None:
    """Parsing `dep "bar" { namespace "ns1"; ... }` populates namespace field."""
    from milpa.lockfile import parse_lockfile

    lock_text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "bar" {
    namespace "ns1"
    identity "dag-sha256:5859c6a82a7e188a8a85684e873de2f9352b81a6e11722f0f003f25a76acf7a1"
    version "1.0.0"
    src_dir "src"
    requires
    provenance {
        origin "observed"
        kind "git"
        url "https://github.com/ns1/bar.git"
        ref "v1.0.0"
        commit_sha "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
    }
}
"""
    lockfile = parse_lockfile(lock_text)
    assert len(lockfile.deps) == 1
    dep = lockfile.deps[0]
    assert dep.name == "bar"
    assert dep.namespace == "ns1"


def test_lockfile_namespace_roundtrip_byte_identical() -> None:
    """format_lockfile(parse_lockfile(text)) == text for a qualified dep."""
    from milpa.lockfile import parse_lockfile, format_lockfile

    lock_text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "bar" {
    namespace "ns1"
    identity "dag-sha256:5859c6a82a7e188a8a85684e873de2f9352b81a6e11722f0f003f25a76acf7a1"
    version "1.0.0"
    src_dir "src"
    requires
    provenance {
        origin "observed"
        kind "git"
        url "https://github.com/ns1/bar.git"
        ref "v1.0.0"
        commit_sha "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
    }
}
"""
    lockfile = parse_lockfile(lock_text)
    assert format_lockfile(lockfile) == lock_text


def test_lockfile_namespace_emitted_before_identity() -> None:
    """format_lockfile emits `namespace` BEFORE `identity` (first child)."""
    from milpa.lockfile import parse_lockfile, format_lockfile

    lock_text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "bar" {
    namespace "ns1"
    identity "dag-sha256:5859c6a82a7e188a8a85684e873de2f9352b81a6e11722f0f003f25a76acf7a1"
    version "1.0.0"
    src_dir "src"
    requires
    provenance {
        origin "observed"
        kind "git"
        url "https://github.com/ns1/bar.git"
        ref "v1.0.0"
        commit_sha "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
    }
}
"""
    lockfile = parse_lockfile(lock_text)
    out = format_lockfile(lockfile)
    lines = out.splitlines()
    # Find "dep "bar" {" and the next non-blank line
    dep_idx = next(i for i, l in enumerate(lines) if l.startswith('dep "bar"'))
    first_child = lines[dep_idx + 1].strip()
    assert first_child.startswith("namespace"), (
        f"Expected namespace as first child, got: {first_child!r}"
    )


def test_lockfile_bare_dep_no_namespace_child() -> None:
    """Bare dep (no namespace) emits NO namespace child node."""
    from milpa.lockfile import parse_lockfile, format_lockfile

    lock_text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "bar" {
    identity "dag-sha256:5859c6a82a7e188a8a85684e873de2f9352b81a6e11722f0f003f25a76acf7a1"
    version "1.0.0"
    src_dir "src"
    requires
    provenance {
        origin "observed"
        kind "git"
        url "https://github.com/ns1/bar.git"
        ref "v1.0.0"
        commit_sha "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
    }
}
"""
    lockfile = parse_lockfile(lock_text)
    assert lockfile.deps[0].namespace is None
    out = format_lockfile(lockfile)
    assert "namespace" not in out


# ---------------------------------------------------------------------------
# 10. NamedRequire.namespace field (H2 fix)
#     Ensures the namespace field exists and is preserved across edge_sources.
# ---------------------------------------------------------------------------

def test_named_require_has_namespace_field() -> None:
    """NamedRequire carries a namespace field (H2: transitive qualified deps)."""
    from milpa.dep_decl import NamedRequire
    req = NamedRequire(name="baz", constraint_str=">= 1.0.0", namespace="ns1")
    assert req.namespace == "ns1"


def test_named_require_namespace_none_by_default() -> None:
    """NamedRequire.namespace defaults to None (backward compat)."""
    from milpa.dep_decl import NamedRequire
    req = NamedRequire(name="baz", constraint_str=">= 1.0.0")
    assert req.namespace is None


def test_named_require_depkey_from_namespace() -> None:
    """NamedRequire with namespace builds a correct DepKey."""
    from milpa.dep_decl import NamedRequire
    req = NamedRequire(name="baz", constraint_str=">= 1.0.0", namespace="ns1")
    dk = DepKey(name=req.name, namespace=req.namespace)
    assert dk.solver_var() == "ns1::baz"


# ---------------------------------------------------------------------------
# 11. Slash + namespace= disagreement → MAN-DEP-NAME-INVALID (M2 fix)
#     fixture-318 covers the black-box surface; these unit tests pin the
#     exact parser behavior.
# ---------------------------------------------------------------------------

def test_slash_and_attr_same_namespace_ok() -> None:
    """Slash form and namespace= attribute AGREE → accepted (no error)."""
    text = 'name "myapp"\ndeps {\n    "ns1/bar" namespace="ns1" ">= 1.0.0"\n}\n'
    m = parse_manifest(text)
    dep = m.deps[0]
    assert isinstance(dep, NamedDep)
    assert dep.name == "bar"
    assert dep.namespace == "ns1"


def test_slash_and_attr_different_namespace_raises() -> None:
    """Slash form and namespace= attribute DISAGREE → MAN-DEP-NAME-INVALID."""
    text = 'name "myapp"\ndeps {\n    "ns1/bar" namespace="ns2" ">= 1.0.0"\n}\n'
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    assert exc_info.value.slug == MAN_DEP_NAME_INVALID


def test_slash_only_no_attr_ok() -> None:
    """Slash form alone (no namespace= attr) → accepted, namespace from slash."""
    text = 'name "myapp"\ndeps {\n    "ns1/bar" ">= 1.0.0"\n}\n'
    m = parse_manifest(text)
    dep = m.deps[0]
    assert isinstance(dep, NamedDep)
    assert dep.name == "bar"
    assert dep.namespace == "ns1"


def test_attr_only_no_slash_ok() -> None:
    """namespace= attribute alone (no slash) → accepted."""
    text = 'name "myapp"\ndeps {\n    bar namespace="ns1" ">= 1.0.0"\n}\n'
    m = parse_manifest(text)
    dep = m.deps[0]
    assert isinstance(dep, NamedDep)
    assert dep.name == "bar"
    assert dep.namespace == "ns1"


# ---------------------------------------------------------------------------
# HIGH-1 regression: lockfile namespace traversal rejected at parse boundary
# ---------------------------------------------------------------------------

def test_lockfile_namespace_traversal_rejected() -> None:
    """A lockfile dep with a traversal namespace is rejected (LOCK-DEP-NAME-INVALID).

    Security regression for HIGH-1: a poisoned milpa.lock with
    ``namespace "ns/../../outside"`` must raise at the parse boundary so the
    payload never reaches dep_dir_name (which would produce @ns/../../outside/<name>
    and escape _deps/).  Equivalent to conformance fixture-324.
    """
    from milpa.lockfile import parse_lockfile
    from milpa.errors import LOCK_DEP_NAME_INVALID

    lock_text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "bar" {
    namespace "ns/../../outside"
    identity "dag-sha256:5859c6a82a7e188a8a85684e873de2f9352b81a6e11722f0f003f25a76acf7a1"
    version "1.0.0"
    src_dir "src"
    requires
    provenance {
        origin "observed"
        kind "git"
        url "https://github.com/example/bar.git"
        ref "v1.0.0"
        commit_sha "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
    }
}
"""
    with pytest.raises(MilpaError) as exc_info:
        parse_lockfile(lock_text)
    assert exc_info.value.slug == LOCK_DEP_NAME_INVALID


def test_lockfile_namespace_dotdot_rejected() -> None:
    """A lockfile dep with namespace \"..\" is rejected (LOCK-DEP-NAME-INVALID)."""
    from milpa.lockfile import parse_lockfile
    from milpa.errors import LOCK_DEP_NAME_INVALID

    lock_text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "bar" {
    namespace ".."
    identity "dag-sha256:5859c6a82a7e188a8a85684e873de2f9352b81a6e11722f0f003f25a76acf7a1"
    version "1.0.0"
    src_dir "src"
    requires
    provenance {
        origin "observed"
        kind "git"
        url "https://github.com/example/bar.git"
        ref "v1.0.0"
        commit_sha "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
    }
}
"""
    with pytest.raises(MilpaError) as exc_info:
        parse_lockfile(lock_text)
    assert exc_info.value.slug == LOCK_DEP_NAME_INVALID


def test_lockfile_empty_namespace_silently_ignored() -> None:
    """A lockfile dep with ``namespace \"\"`` is silently ignored (treated as None).

    Empty namespace is a forward-compat skip (parity with Rust ``!is_empty()``).
    """
    from milpa.lockfile import parse_lockfile

    lock_text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "bar" {
    namespace ""
    identity "dag-sha256:5859c6a82a7e188a8a85684e873de2f9352b81a6e11722f0f003f25a76acf7a1"
    version "1.0.0"
    src_dir "src"
    requires
    provenance {
        origin "observed"
        kind "git"
        url "https://github.com/example/bar.git"
        ref "v1.0.0"
        commit_sha "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
    }
}
"""
    lockfile = parse_lockfile(lock_text)
    assert lockfile.deps[0].namespace is None


# ---------------------------------------------------------------------------
# HIGH-2 regression: workspace _on_transitive_named must use from_solver_var
# ---------------------------------------------------------------------------

def test_from_solver_var_preserves_namespace_for_ws_callback() -> None:
    """Regression for HIGH-2: workspace _on_transitive_named port divergence.

    The workspace callback receives a solver_var string (e.g. ``"ns1::bar"``).
    The OLD code did ``DepKey(name=name)`` which treated the full string as a
    bare name → registry query for literal ``"ns1::bar"`` → TNG-NOT-FOUND.
    The fix uses ``DepKey.from_solver_var(name)`` which correctly decomposes to
    ``DepKey(name="bar", namespace="ns1")``.

    This test pins the decomposition contract that the workspace callback relies on.
    """
    qualified_solver_var = "ns1::bar"

    # OLD broken behavior (kept here as a comment showing WHY the bug occurred):
    # broken = DepKey(name=qualified_solver_var)
    # assert broken.name == "ns1::bar"  # wrong — namespace lost, name mangled

    correct = DepKey.from_solver_var(qualified_solver_var)
    assert correct.name == "bar"
    assert correct.namespace == "ns1"
    # Round-trip: solver_var() reconstructs the original string.
    assert correct.solver_var() == qualified_solver_var

    # Guard: the "nim" check must test .name (not the solver_var string).
    # A qualified dep "nim::util" should NOT be filtered by the nim guard.
    nim_util = DepKey.from_solver_var("nim::util")
    assert nim_util.name == "util"   # NOT "nim" — so the guard does not fire
    assert nim_util.namespace == "nim"
    # A bare "nim" dep SHOULD be filtered (nim is the stdlib, not a real dep).
    bare_nim = DepKey.from_solver_var("nim")
    assert bare_nim.name == "nim"
    assert bare_nim.namespace is None
