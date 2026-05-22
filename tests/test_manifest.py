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
    )


def test_kind_application_parses():
    text = """
deps {
    chronos git="https://github.com/x/y.git" ref="main"
}
kind "application"
"""
    m = parse_manifest(text)
    assert m.kind == "application"


def test_missing_kind_defaults_to_library():
    text = """
deps {
    chronos git="https://github.com/x/y.git" ref="main"
}
"""
    m = parse_manifest(text)
    assert m.kind == "library"


def test_two_deps_preserve_declaration_order():
    text = """
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
deps {
    chronos git=(url)"https://github.com/coreyleavitt/chronos.git" ref="feat/contextvars"
}
"""
    plain = """
deps {
    chronos git="https://github.com/coreyleavitt/chronos.git" ref="feat/contextvars"
}
"""
    assert parse_manifest(annotated) == parse_manifest(plain)
