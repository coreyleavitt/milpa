"""Property-based tests for milpa.manifest round-trip.

Per docs/rfc-property-based-testing.md Tier B-2.

Property: for any valid Manifest M,
    parse_manifest(format_manifest(M)) == M

Hypothesis generates Manifests composed of UrlDep + NamedDep entries
with KDL-safe alphabets. Names are unique within a manifest (the
parser enforces a single namespace; duplicates raise).
"""

from hypothesis import given, strategies as st

from milpa.manifest import (
    Manifest,
    NamedDep,
    Override,
    UrlDep,
    format_manifest,
    parse_manifest,
)


_NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"


def names():
    """Package names: alphanumeric + - and _, non-empty.
    First char non-numeric to keep KDL parsing unambiguous (a node
    starting with a digit could be parsed as a number by some KDL
    impls)."""
    first = st.sampled_from(_NAME_ALPHABET[:52] + "_")   # letters + underscore
    rest = st.text(alphabet=_NAME_ALPHABET, max_size=15)
    return st.builds(lambda f, r: f + r, first, rest)


def git_urls():
    """URL-shaped strings — KDL-safe alphabet."""
    return st.builds(
        lambda host, repo: f"https://{host}/{repo}.git",
        st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=15),
        st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=15),
    )


def git_refs():
    """Git ref strings — alphanumeric + / (for `feat/contextvars`-style)."""
    return st.text(
        alphabet=_NAME_ALPHABET + "/",
        min_size=1, max_size=20,
    )


def constraints():
    """Version constraint strings as the parser accepts them."""
    op = st.sampled_from([">=", "<=", ">", "<", "=="])
    triple = st.builds(
        lambda a, b, c: f"{a}.{b}.{c}",
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
    )
    clause = st.builds(lambda o, v: f"{o} {v}", op, triple)
    return st.one_of(
        st.none(),
        clause,
        # Conjunctions (rare)
        st.builds(lambda a, b: f"{a} & {b}", clause, clause),
    )


@st.composite
def manifests(draw):
    """A valid Manifest with unique dep names across both URL and
    named variants. Also generates 0-3 overrides with unique names
    that don't conflict with the dep names (they're in their own
    namespace per the spec)."""
    n_deps = draw(st.integers(min_value=0, max_value=6))
    n_overrides = draw(st.integers(min_value=0, max_value=3))
    all_names = draw(st.lists(
        names(),
        min_size=n_deps + n_overrides,
        max_size=n_deps + n_overrides,
        unique=True,
    ))
    dep_names = all_names[:n_deps]
    override_names = all_names[n_deps:n_deps + n_overrides]

    deps: list = []
    for name in dep_names:
        if draw(st.booleans()):
            deps.append(UrlDep(
                name=name,
                git=draw(git_urls()),
                ref=draw(git_refs()),
            ))
        else:
            deps.append(NamedDep(name=name, constraint=draw(constraints())))

    overrides: list = []
    for name in override_names:
        overrides.append(Override(
            name=name,
            git=draw(git_urls()),
            ref=draw(git_refs()),
        ))

    return Manifest(
        deps=tuple(deps),
        overrides=tuple(overrides),
        kind=draw(st.sampled_from(["library", "application"])),
    )


@given(manifests())
def test_manifest_format_parse_round_trip(m):
    """parse(format(M)) == M for any valid Manifest."""
    text = format_manifest(m)
    assert parse_manifest(text) == m
