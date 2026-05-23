"""Manifest parser tests.

milpa.kdl → Manifest. Only the public surface (parse_manifest,
load_manifest, Manifest, UrlDep, ManifestError) is exercised; kdl-py
types are an internal detail.
"""

from pathlib import Path

import pytest

from milpa.manifest import (
    Manifest,
    ManifestError,
    UrlDep,
    load_manifest,
    parse_manifest,
)


def test_minimal_manifest_with_one_url_dep():
    text = """
name "test"
deps {
    chronos git="https://github.com/coreyleavitt/chronos.git" ref="feat/contextvars"
}
"""
    m = parse_manifest(text)
    assert m == Manifest(
        deps=(
            UrlDep(
                name="chronos",
                git="https://github.com/coreyleavitt/chronos.git",
                ref="feat/contextvars",
            ),
        ),
        kind="library",
        name="test",
    )


def test_kind_application_parses():
    text = """
name "test"
deps {
    chronos git="https://github.com/x/y.git" ref="main"
}
kind "application"
"""
    m = parse_manifest(text)
    assert m.kind == "application"


def test_missing_kind_defaults_to_library():
    text = """
name "test"
deps {
    chronos git="https://github.com/x/y.git" ref="main"
}
"""
    m = parse_manifest(text)
    assert m.kind == "library"


def test_two_deps_preserve_declaration_order():
    text = """
name "test"
deps {
    chronos git="https://github.com/coreyleavitt/chronos.git" ref="feat/contextvars"
    intonaco git="https://github.com/coreyleavitt/intonaco.git" ref="main"
}
"""
    m = parse_manifest(text)
    assert [d.name for d in m.deps] == ["chronos", "intonaco"]


def test_missing_git_raises_naming_the_dep():
    text = """
deps {
    chronos ref="main"
}
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "git" in str(exc.value)


def test_missing_ref_raises_naming_the_dep():
    text = """
deps {
    chronos git="https://github.com/x/y.git"
}
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "ref" in str(exc.value)


def test_unknown_dep_property_raises():
    text = """
deps {
    chronos git="https://github.com/x/y.git" ref="main" branch="oops"
}
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "branch" in str(exc.value)
    assert "chronos" in str(exc.value)


def test_unknown_top_level_node_raises():
    text = """
deps {
    chronos git="https://github.com/x/y.git" ref="main"
}
license "MIT"
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "license" in str(exc.value)


def test_invalid_kind_value_raises():
    text = """
deps {
    chronos git="https://github.com/x/y.git" ref="main"
}
kind "framework"
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "framework" in str(exc.value)
    assert "library" in str(exc.value) and "application" in str(exc.value)


def test_url_without_scheme_raises():
    text = """
deps {
    chronos git="github.com/x/y.git" ref="main"
}
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "scheme" in str(exc.value).lower() or "url" in str(exc.value).lower()


def test_url_with_unsupported_scheme_raises():
    text = """
deps {
    chronos git="ftp://example.com/y.git" ref="main"
}
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "ftp" in str(exc.value).lower() or "scheme" in str(exc.value).lower()


def test_malformed_kdl_raises_manifest_error():
    # `}` with no matching `{` — kdl-py will reject this at parse time.
    text = """
deps }
    chronos git="https://github.com/x/y.git" ref="main"
}
"""
    with pytest.raises(ManifestError):
        parse_manifest(text)


def test_duplicate_dep_names_raise():
    text = """
deps {
    chronos git="https://github.com/x/y.git" ref="main"
    chronos git="https://github.com/x/y.git" ref="other"
}
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "duplicate" in str(exc.value).lower()


def test_load_manifest_reads_from_disk(tmp_path: Path):
    manifest_path = tmp_path / "milpa.kdl"
    manifest_path.write_text(
        'name "test"\n'
        'deps {\n  chronos git="https://github.com/x/y.git" ref="main"\n}\n'
    )
    m = load_manifest(manifest_path)
    assert m.deps[0].name == "chronos"


def test_load_manifest_missing_file_raises_with_path(tmp_path: Path):
    missing = tmp_path / "nonexistent.kdl"
    with pytest.raises(ManifestError) as exc:
        load_manifest(missing)
    assert str(missing) in str(exc.value)


def test_schema_documentation_file_ships_with_package():
    import milpa
    pkg_root = Path(milpa.__file__).parent
    schema = pkg_root / "schema" / "milpa.schema.kdl"
    assert schema.exists(), (
        "milpa/schema/milpa.schema.kdl is missing — the schema "
        "documentation file is part of the package contract"
    )
    # Trivial readability check
    content = schema.read_text()
    assert "deps" in content
    assert "kind" in content


def test_named_dep_no_constraint_parses():
    """A bare name in deps {} is a named (registry-resolved) dep with
    no version constraint."""
    from milpa.manifest import NamedDep
    text = '''
name "test"
deps {
    results
}
'''
    m = parse_manifest(text)
    assert m.deps == (NamedDep(name="results", constraint=None),)


def test_named_dep_with_constraint_parses():
    """`<name> "<constraint>"` form."""
    from milpa.manifest import NamedDep
    text = '''
name "test"
deps {
    stew ">= 0.5.0"
}
'''
    m = parse_manifest(text)
    assert m.deps == (NamedDep(name="stew", constraint=">= 0.5.0"),)


def test_mixed_url_and_named_deps_in_manifest():
    """A single deps block can carry both URL deps and named deps."""
    from milpa.manifest import NamedDep
    text = '''
name "test"
deps {
    chronos git=(url)"https://github.com/x/chronos.git" ref="main"
    results
    stew ">= 0.5.0"
}
'''
    m = parse_manifest(text)
    names = [d.name for d in m.deps]
    assert names == ["chronos", "results", "stew"]
    # Identify by type
    chronos = m.deps[0]
    results = m.deps[1]
    stew = m.deps[2]
    assert isinstance(chronos, UrlDep)
    assert isinstance(results, NamedDep)
    assert results.constraint is None
    assert isinstance(stew, NamedDep)
    assert stew.constraint == ">= 0.5.0"


def test_local_dep_parses():
    """`local="../path"` form declares a local-filesystem dep.

    The path string is preserved verbatim (relative or absolute);
    relative-to-project resolution is the resolver's responsibility,
    not the parser's."""
    from milpa.manifest import LocalDep
    text = '''
name "test"
deps {
    intonaco local="../intonaco"
}
'''
    m = parse_manifest(text)
    assert m.deps == (LocalDep(name="intonaco", path="../intonaco"),)


def test_local_dep_round_trips_through_format_and_parse():
    """A Manifest with a LocalDep must survive format → parse identity."""
    from milpa.manifest import LocalDep, format_manifest
    original = Manifest(
        deps=(LocalDep(name="intonaco", path="../intonaco"),),
        kind="library",
        name="test",
    )
    text = format_manifest(original)
    reparsed = parse_manifest(text)
    assert reparsed == original


def test_workspace_block_with_one_member_parses():
    """Tracer: a manifest with a workspace block declaring one member
    parses to a Workspace value (distinct from Manifest). This is the
    new top-level role: workspace root, no deps, no kind.

    Per W1 / #73: virtual-workspace-only — a manifest is either a
    workspace OR a package, never both. Hence Workspace is its own
    value type; the parser routes based on which top-level node is
    present.
    """
    from milpa.manifest import Workspace, parse_workspace_or_manifest
    text = '''
workspace {
    member "fresco"
}
'''
    result = parse_workspace_or_manifest(text)
    assert isinstance(result, Workspace)
    assert result.members == ("fresco",)


def test_workspace_with_deps_block_is_rejected():
    """Virtual-workspace-only: a manifest is workspace OR package,
    never both. A workspace block coexisting with deps is structural
    ambiguity and must be a parse error."""
    from milpa.manifest import parse_workspace_or_manifest
    text = '''
workspace {
    member "fresco"
}

deps {
    chronos git=(url)"https://example.com/x.git" ref="main"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_workspace_or_manifest(text)
    msg = str(exc.value).lower()
    assert "workspace" in msg
    assert "deps" in msg or "package" in msg


def test_empty_workspace_block_parses():
    """A workspace { } with no members is grammatically valid — useful
    for newly-initialized workspaces before any package is added.
    Higher layers (W2 discovery) may emit a hint, but the parser
    accepts."""
    from milpa.manifest import Workspace, parse_workspace_or_manifest
    text = '''
workspace {
}
'''
    result = parse_workspace_or_manifest(text)
    assert isinstance(result, Workspace)
    assert result.members == ()


def test_multiple_members_preserve_declaration_order():
    """Order matters for tooling determinism (per-member nim.cfg
    emission, lockfile entries, etc.). The Workspace value's members
    tuple reflects the source order."""
    from milpa.manifest import Workspace, parse_workspace_or_manifest
    text = '''
workspace {
    member "c"
    member "a"
    member "b"
}
'''
    result = parse_workspace_or_manifest(text)
    assert isinstance(result, Workspace)
    assert result.members == ("c", "a", "b")


def test_name_top_level_node_parses_and_is_recorded():
    """Intrinsic identity: `name "<x>"` at top level records the
    package's self-claimed name on the Manifest."""
    text = '''
name "fresco"

deps {
    chronos git=(url)"https://example.com/x.git" ref="main"
}
'''
    m = parse_manifest(text)
    assert m.name == "fresco"


def test_package_manifest_without_name_raises():
    """Intrinsic identity is required for every package. A manifest
    with deps or kind must have a `name`."""
    text = '''
deps {
    chronos git=(url)"https://example.com/x.git" ref="main"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value).lower()
    assert "name" in msg


def test_package_manifest_with_only_kind_still_requires_name():
    """Even a manifest with no deps but a `kind` declaration is a
    package manifest and must self-identify."""
    text = '''
kind "library"
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value).lower()
    assert "name" in msg


def test_duplicate_member_paths_rejected():
    """Same hygiene as duplicate dep names — every member is uniquely
    identified by its path string. Duplicates are structural ambiguity."""
    from milpa.manifest import parse_workspace_or_manifest
    text = '''
workspace {
    member "fresco"
    member "fresco"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_workspace_or_manifest(text)
    msg = str(exc.value).lower()
    assert "fresco" in msg
    assert "duplicate" in msg or "already" in msg


def test_member_dep_kind_parses():
    """A workspace-internal dep is `member "<name>"` — reserved keyword
    leading the line, positional name argument. Symmetric with the
    overrides `pkg "<name>"` form. KDL doesn't permit bare-identifier
    arguments, so this is the cleanest way to mark a dep as
    workspace-routed without conflicting with the NamedDep grammar."""
    from milpa.manifest import MemberDep
    text = '''
name "fresco"
deps {
    member "intonaco"
}
'''
    m = parse_manifest(text)
    assert m.deps == (MemberDep(name="intonaco"),)


def test_member_dep_with_extra_properties_is_rejected():
    """`member` takes no properties — `member "foo" ref="bar"` is
    malformed."""
    text = '''
name "fresco"
deps {
    member "intonaco" ref="main"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value).lower()
    assert "member" in msg


def test_member_dep_without_name_argument_is_rejected():
    """`member` requires exactly one positional string (the member
    name)."""
    text = '''
name "fresco"
deps {
    member
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value).lower()
    assert "member" in msg


def test_member_dep_with_multiple_positional_args_is_rejected():
    text = '''
name "fresco"
deps {
    member "intonaco" "extra"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value).lower()
    assert "member" in msg


def test_member_dep_round_trips_through_format_and_parse():
    """Member dep in a manifest survives format → parse identity."""
    from milpa.manifest import MemberDep, format_manifest
    original = Manifest(
        deps=(
            MemberDep(name="intonaco"),
            UrlDep(name="chronos", git="https://example.com/x.git", ref="main"),
        ),
        kind="library",
        name="fresco",
    )
    text = format_manifest(original)
    reparsed = parse_manifest(text)
    assert reparsed == original


def test_workspace_round_trips_through_format_and_parse():
    """A Workspace value survives format → parse identity. format_workspace
    emits a workspace { member "..." } block; parse_workspace_or_manifest
    reads it back as the same Workspace."""
    from milpa.manifest import (
        Workspace, format_workspace, parse_workspace_or_manifest,
    )
    original = Workspace(members=("fresco", "intonaco", "sinopia"))
    text = format_workspace(original)
    reparsed = parse_workspace_or_manifest(text)
    assert reparsed == original


def test_workspace_with_kind_is_rejected():
    """Same disjoint-union rule for `kind`."""
    from milpa.manifest import parse_workspace_or_manifest
    text = '''
workspace {
    member "fresco"
}

kind "library"
'''
    with pytest.raises(ManifestError) as exc:
        parse_workspace_or_manifest(text)
    msg = str(exc.value).lower()
    assert "workspace" in msg
    assert "kind" in msg or "package" in msg


def test_dep_with_both_git_and_local_raises():
    """A dep must declare exactly one transport. Mixing `git=` and
    `local=` is a manifest error — the parser must reject it explicitly
    rather than silently picking one."""
    text = '''
deps {
    intonaco git=(url)"https://example.com/x.git" ref="main" local="../intonaco"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value).lower()
    assert "intonaco" in msg
    assert "git" in msg and "local" in msg


def test_named_dep_with_unknown_property_raises():
    """Named deps don't take properties (only positional constraint).
    Unknown properties are an error so typos surface loudly."""
    text = '''
deps {
    results version=">= 0.5"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "results" in str(exc.value)


def test_named_dep_with_multiple_positional_args_raises():
    """At most one positional argument (the version constraint)."""
    text = '''
deps {
    foo ">= 1.0" "extra-thing"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "foo" in str(exc.value)
    assert "one positional" in str(exc.value).lower() or "constraint" in str(exc.value).lower()


def test_format_manifest_round_trips_overrides():
    """A Manifest with an overrides tuple round-trips through
    format_manifest → parse_manifest."""
    from milpa.manifest import Override, format_manifest
    m = Manifest(
        deps=(UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),),
        kind="library",
        name="test",
        overrides=(
            Override(
                name="chronos",
                git="https://github.com/my-fork/chronos.git",
                ref="my-fix",
            ),
        ),
    )
    text = format_manifest(m)
    assert parse_manifest(text) == m


def test_manifest_without_overrides_has_empty_tuple():
    """Backwards compat: a manifest with no overrides block produces
    Manifest.overrides == ()."""
    text = '''
name "test"
deps {
    foo git="https://example.com/foo.git" ref="main"
}
'''
    m = parse_manifest(text)
    assert m.overrides == ()


def test_override_missing_git_property_raises():
    text = '''
overrides {
    pkg "chronos" ref="my-fix"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "git" in str(exc.value)


def test_override_missing_ref_property_raises():
    text = '''
overrides {
    pkg "chronos" git="https://example.com/x.git"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "ref" in str(exc.value)


def test_override_with_unknown_property_raises():
    text = '''
overrides {
    pkg "chronos" git="https://x.git" ref="main" foo="bar"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "foo" in str(exc.value)


def test_unknown_override_kind_raises():
    """Only 'pkg' is supported in v0.x; other kinds error."""
    text = '''
overrides {
    url "https://from.git" "https://to.git"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "url" in str(exc.value).lower() or "pkg" in str(exc.value).lower()


def test_duplicate_override_for_same_name_raises():
    text = '''
overrides {
    pkg "chronos" git="https://a.git" ref="main"
    pkg "chronos" git="https://b.git" ref="main"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "chronos" in str(exc.value)
    assert "duplicate" in str(exc.value).lower()


def test_overrides_block_parses():
    """A manifest with an `overrides { pkg ... }` block parses into
    Manifest.overrides as a tuple of Override values."""
    from milpa.manifest import Override
    text = '''
name "test"
deps {
    foo git="https://example.com/foo.git" ref="main"
}

overrides {
    pkg "chronos" git=(url)"https://github.com/my-fork/chronos.git" ref="my-fix"
}
'''
    m = parse_manifest(text)
    assert m.overrides == (
        Override(
            name="chronos",
            git="https://github.com/my-fork/chronos.git",
            ref="my-fix",
        ),
    )


def test_format_empty_manifest_round_trips():
    """An empty library manifest should round-trip through format/parse."""
    from milpa.manifest import format_manifest
    m = Manifest(deps=(), kind="library", name="test")
    text = format_manifest(m)
    assert parse_manifest(text) == m


def test_format_single_url_dep_round_trips():
    from milpa.manifest import format_manifest
    m = Manifest(
        deps=(UrlDep(name="chronos",
                     git="https://github.com/x/chronos.git",
                     ref="feat/contextvars"),),
        kind="library",
        name="test",
    )
    text = format_manifest(m)
    assert parse_manifest(text) == m


def test_format_emits_url_annotation():
    from milpa.manifest import format_manifest
    m = Manifest(
        deps=(UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),),
        kind="library",
    )
    text = format_manifest(m)
    # The recommended `(url)` annotation is emitted
    assert "(url)" in text


def test_format_application_kind_round_trips():
    from milpa.manifest import format_manifest
    m = Manifest(deps=(), kind="application", name="test")
    text = format_manifest(m)
    assert 'kind "application"' in text
    assert parse_manifest(text) == m


def test_format_named_dep_no_constraint_round_trips():
    from milpa.manifest import NamedDep, format_manifest
    m = Manifest(deps=(NamedDep(name="results", constraint=None),), kind="library", name="test")
    text = format_manifest(m)
    assert parse_manifest(text) == m


def test_format_named_dep_with_constraint_round_trips():
    from milpa.manifest import NamedDep, format_manifest
    m = Manifest(deps=(NamedDep(name="stew", constraint=">= 0.5.0"),), kind="library", name="test")
    text = format_manifest(m)
    assert parse_manifest(text) == m


def test_format_mixed_deps_round_trips():
    from milpa.manifest import NamedDep, format_manifest
    m = Manifest(
        deps=(
            UrlDep(name="chronos", git="https://example.com/chronos.git", ref="main"),
            NamedDep(name="results", constraint=None),
            NamedDep(name="stew", constraint=">= 0.5.0"),
        ),
        kind="library",
        name="test",
    )
    text = format_manifest(m)
    assert parse_manifest(text) == m


def test_url_dep_missing_git_property_now_routes_to_named_path():
    """Regression: previously a child without `git=` raised 'missing
    required property git'. Now it's parsed as a named dep. A
    truly-invalid manifest (e.g. URL-looking child with `ref=` but no
    `git=`) is now a named dep with weird props — still errors via
    the unknown-property path."""
    text = '''
deps {
    chronos ref="main"
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    # The named-dep parser surfaces it as unknown property 'ref'
    assert "chronos" in str(exc.value)
    assert "ref" in str(exc.value)


def test_url_with_kdl_type_annotation_parses():
    # `(url)` is a KDL type annotation; the spec allows it as a
    # self-documenting decoration. Both annotated and unannotated
    # forms must produce identical results. (Future stricter parsers
    # may enforce more at the annotation site; today's parser treats
    # it as a hint.)
    annotated = """
name "test"
deps {
    chronos git=(url)"https://github.com/coreyleavitt/chronos.git" ref="feat/contextvars"
}
"""
    plain = """
name "test"
deps {
    chronos git="https://github.com/coreyleavitt/chronos.git" ref="feat/contextvars"
}
"""
    assert parse_manifest(annotated) == parse_manifest(plain)
