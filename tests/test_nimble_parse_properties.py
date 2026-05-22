"""Property-based tests for milpa.nimble_parse line-form extraction.

Per docs/rfc-property-based-testing.md Tier C-2.

Property: for any list of `requires` specs we declare, the round-trip
through formatted-nimble-text and parse_nimble preserves the specs in
declaration order, regardless of formatting style (single-line,
comma-separated, multi-line continuation, multiple requires lines).

Out of scope: arbitrary nimscript robustness. We don't claim to parse
when-blocks, computed deps, or variable-based requires.
"""

from hypothesis import given, strategies as st

from milpa.nimble_parse import (
    NamedRequirement,
    UrlRequirement,
    parse_nimble,
)


# ---------------------------------------------------------------------------
# Strategies — KDL-and-nimble-safe alphabets to avoid ambiguity
# ---------------------------------------------------------------------------

# Names exclude operators (>, <, =), commas, quotes — anything that
# would collide with the spec-parser at the boundary
_NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"


def names():
    """Package names: non-empty, alphanumeric + _ -"""
    return st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=10)


def version_triples():
    """`<a>.<b>.<c>` strings."""
    return st.builds(
        lambda a, b, c: f"{a}.{b}.{c}",
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
    )


def named_spec_strs():
    """A named-requirement spec: 'name' or 'name <op> X.Y.Z'."""
    bare = names()
    constrained = st.builds(
        lambda n, op, v: f"{n} {op} {v}",
        names(),
        st.sampled_from([">=", "<=", ">", "<", "=="]),
        version_triples(),
    )
    return st.one_of(bare, constrained)


def url_spec_strs():
    """A URL-requirement spec: 'https://...git' or 'https://...git#ref'."""
    base = st.builds(
        lambda host, repo: f"https://{host}/{repo}.git",
        st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=10),
        st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=10),
    )
    with_ref = st.builds(
        lambda base, ref: f"{base}#{ref}",
        base,
        # Refs: safe alphabet + `/` (e.g. `feat/contextvars`). No `#`.
        st.text(alphabet=_NAME_ALPHABET + "/", min_size=1, max_size=15),
    )
    return st.one_of(base, with_ref)


def requirement_spec_strs():
    """A single spec string: either named or URL."""
    return st.one_of(named_spec_strs(), url_spec_strs())


def specs_lists():
    """A list of 1-6 spec strings."""
    return st.lists(requirement_spec_strs(), min_size=1, max_size=6)


# ---------------------------------------------------------------------------
# Formatting helpers — produce nimble file text in various styles
# ---------------------------------------------------------------------------

def _format_single_line(specs: list[str]) -> str:
    """Each spec on its own `requires "..."` line."""
    return "\n".join(f'requires "{s}"' for s in specs) + "\n"


def _format_comma_one_line(specs: list[str]) -> str:
    """All specs on one `requires "a", "b", "c"` line."""
    if not specs:
        return ""
    quoted = ", ".join(f'"{s}"' for s in specs)
    return f"requires {quoted}\n"


def _format_multiline_continuation(specs: list[str]) -> str:
    """Chronos-shape: `requires "a",\n         "b",\n         "c"`."""
    if not specs:
        return ""
    lines = [f'requires "{specs[0]}"']
    if len(specs) > 1:
        lines[0] += ","
        for i, s in enumerate(specs[1:]):
            suffix = "," if i < len(specs) - 2 else ""
            lines.append(f'         "{s}"{suffix}')
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

@given(named_spec_strs())
def test_single_named_spec_round_trips(spec):
    """One named spec on its own line → one NamedRequirement with the
    same .spec string."""
    text = f'requires "{spec}"\n'
    nm = parse_nimble(text)
    assert len(nm.requires) == 1
    assert nm.requires[0].spec == spec


@given(specs_lists())
def test_one_per_line_format_preserves_specs_in_order(specs):
    """N specs on N separate `requires` lines → N Requirements with
    matching .spec strings in declaration order."""
    text = _format_single_line(specs)
    nm = parse_nimble(text)
    assert [r.spec for r in nm.requires] == specs


@given(url_spec_strs())
def test_url_spec_with_ref_round_trips(spec):
    """A URL spec like `https://x.git#ref` round-trips, and after
    parsing the URL and ref are correctly split."""
    text = f'requires "{spec}"\n'
    nm = parse_nimble(text)
    assert len(nm.requires) == 1
    req = nm.requires[0]
    assert isinstance(req, UrlRequirement)
    assert req.spec == spec
    if "#" in spec:
        expected_url, _, expected_ref = spec.partition("#")
        assert req.url == expected_url
        assert req.ref == expected_ref
    else:
        assert req.url == spec
        assert req.ref is None


@given(specs_lists())
def test_comma_separated_one_line_round_trips(specs):
    """All specs on a single `requires "a", "b", "c"` line → same
    Requirements in declaration order as the one-per-line form."""
    text = _format_comma_one_line(specs)
    nm = parse_nimble(text)
    assert [r.spec for r in nm.requires] == specs


@given(specs_lists())
def test_multiline_continuation_round_trips(specs):
    """Chronos-shape multi-line continuation preserves order + count."""
    text = _format_multiline_continuation(specs)
    nm = parse_nimble(text)
    assert [r.spec for r in nm.requires] == specs


@given(specs_lists())
def test_all_formatting_styles_yield_same_parsed_list(specs):
    """The same specs formatted in different styles produce the same
    parsed list — extraction is style-invariant."""
    via_per_line = parse_nimble(_format_single_line(specs))
    via_comma = parse_nimble(_format_comma_one_line(specs))
    via_multiline = parse_nimble(_format_multiline_continuation(specs))

    per_line_specs = [r.spec for r in via_per_line.requires]
    comma_specs = [r.spec for r in via_comma.requires]
    multiline_specs = [r.spec for r in via_multiline.requires]

    assert per_line_specs == comma_specs == multiline_specs
