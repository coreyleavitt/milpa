"""nimble file parser tests.

Real-world .nimble files use a mix of single-line, comma-separated,
and multi-line continuation forms for `requires`. We test each form
plus srcDir extraction and edge cases.
"""

from pathlib import Path

import pytest

from milpa.nimble_parse import (
    NamedRequirement,
    NimbleManifest,
    NimbleParseError,
    UrlRequirement,
    load_nimble,
    parse_nimble,
)


def test_single_named_requirement():
    text = 'requires "results"\n'
    m = parse_nimble(text)
    assert m.requires == (NamedRequirement(spec="results", name="results", constraint=None),)


def test_named_with_version_constraint():
    text = 'requires "stew >= 0.5.0"\n'
    m = parse_nimble(text)
    assert m.requires == (
        NamedRequirement(spec="stew >= 0.5.0", name="stew", constraint=">= 0.5.0"),
    )


def test_url_requirement_no_ref():
    text = 'requires "https://github.com/x/y.git"\n'
    m = parse_nimble(text)
    assert m.requires == (
        UrlRequirement(
            spec="https://github.com/x/y.git",
            url="https://github.com/x/y.git",
            ref=None,
        ),
    )


def test_url_requirement_with_ref():
    text = 'requires "https://github.com/x/y.git#feat/contextvars"\n'
    m = parse_nimble(text)
    assert m.requires == (
        UrlRequirement(
            spec="https://github.com/x/y.git#feat/contextvars",
            url="https://github.com/x/y.git",
            ref="feat/contextvars",
        ),
    )


def test_comma_separated_single_line():
    text = 'requires "a", "b", "c"\n'
    m = parse_nimble(text)
    assert [r.name for r in m.requires] == ["a", "b", "c"]


def test_multi_line_continuation_chronos_form():
    text = '''requires "nim >= 1.6.16",
         "results",
         "stew >= 0.5.0",
         "bearssl >= 0.2.8",
         "httputils",
         "unittest2"
'''
    m = parse_nimble(text)
    assert [r.name for r in m.requires] == [
        "nim", "results", "stew", "bearssl", "httputils", "unittest2",
    ]


def test_multiple_requires_lines_preserve_order():
    text = '''requires "nim >= 2.0.0"
requires "https://github.com/x/y.git#main"
requires "results"
'''
    m = parse_nimble(text)
    names_or_urls = [
        r.url if isinstance(r, UrlRequirement) else r.name
        for r in m.requires
    ]
    assert names_or_urls == ["nim", "https://github.com/x/y.git", "results"]


def test_srcDir_extracted():
    text = '''srcDir = "src"
requires "results"
'''
    m = parse_nimble(text)
    assert m.src_dir == "src"


def test_missing_srcDir_is_none():
    text = 'requires "results"\n'
    m = parse_nimble(text)
    assert m.src_dir is None


def test_trailing_comments_stripped():
    text = '''requires "results"  # the workhorse
srcDir = "src"  # standard layout
'''
    m = parse_nimble(text)
    assert [r.name for r in m.requires] == ["results"]
    assert m.src_dir == "src"


def test_indented_requires_and_blank_lines_tolerated():
    text = '''
# a header comment

    requires "results"


srcDir = "src"
'''
    m = parse_nimble(text)
    assert [r.name for r in m.requires] == ["results"]
    assert m.src_dir == "src"


def test_nim_as_named_requirement():
    text = 'requires "nim >= 2.0.0"\n'
    m = parse_nimble(text)
    assert m.requires == (
        NamedRequirement(spec="nim >= 2.0.0", name="nim", constraint=">= 2.0.0"),
    )


def test_empty_file_produces_empty_manifest():
    m = parse_nimble("")
    assert m.requires == ()
    assert m.src_dir is None


def test_url_with_tag_shaped_ref():
    text = 'requires "https://github.com/x/y.git#v1.2.3"\n'
    m = parse_nimble(text)
    assert m.requires == (
        UrlRequirement(
            spec="https://github.com/x/y.git#v1.2.3",
            url="https://github.com/x/y.git",
            ref="v1.2.3",
        ),
    )


def test_load_nimble_reads_from_disk(tmp_path: Path):
    p = tmp_path / "fake.nimble"
    p.write_text('requires "results"\nsrcDir = "src"\n')
    m = load_nimble(p)
    assert [r.name for r in m.requires] == ["results"]
    assert m.src_dir == "src"


def test_load_nimble_missing_path_raises_with_path(tmp_path: Path):
    missing = tmp_path / "nope.nimble"
    with pytest.raises(NimbleParseError) as exc:
        load_nimble(missing)
    assert str(missing) in str(exc.value)


# Integration: real-world fixtures from sibling projects.
# These pin the behavior against actual files the resolver will read.

_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "nimble"


def test_chronos_nimble_fixture():
    m = load_nimble(_FIXTURES_DIR / "chronos.nimble")
    names = [r.name for r in m.requires if isinstance(r, NamedRequirement)]
    assert names == ["nim", "results", "stew", "bearssl", "httputils", "unittest2"]
    # chronos has no srcDir line at the top-level
    assert m.src_dir is None


def test_intonaco_nimble_fixture():
    m = load_nimble(_FIXTURES_DIR / "intonaco.nimble")
    # intonaco requires nim + the chronos fork URL
    assert m.src_dir == "src"
    assert len(m.requires) == 2
    named = [r for r in m.requires if isinstance(r, NamedRequirement)]
    urls = [r for r in m.requires if isinstance(r, UrlRequirement)]
    assert [n.name for n in named] == ["nim"]
    assert len(urls) == 1
    assert "chronos" in urls[0].url
    assert urls[0].ref == "feat/contextvars"
