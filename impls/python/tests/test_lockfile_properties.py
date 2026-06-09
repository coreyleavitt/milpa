"""Property-based tests for milpa.lockfile round-trip.

Per docs/rfc-property-based-testing.md Tier B-1.

Property: for any valid Lockfile L,
    parse_lockfile(format_lockfile(L)) == L

The Hypothesis strategy generates Lockfiles with realistic-shaped
data: hex SHAs of length 40, hex content_hashes of length 64,
plausible source URLs / `registry:<name>` strings, alphanumeric
names and version triples.

Alphabet is intentionally KDL-safe (no quotes, newlines, NUL bytes)
because milpa's formatter doesn't currently escape. If we widen the
alphabet to fancier strings, the formatter needs to gain escape
handling — that would be a separate hardening pass driven by the
counterexamples Hypothesis surfaces.
"""

from hypothesis import HealthCheck, given, settings, strategies as st

from milpa.lockfile import (
    GitProvenanceRecord,
    Lockfile,
    LockedDep,
    format_lockfile,
    parse_lockfile,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# KDL-safe characters: alphanumeric + a small safe set. Excludes any
# character that would need escaping in a double-quoted KDL string.
_NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
_URL_ALPHABET = _NAME_ALPHABET + "./:"   # for URLs and paths


def names():
    """Package / requires names: alphanumeric + - and _, non-empty."""
    return st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=20)


def source_urls():
    """URL or registry-prefixed source strings."""
    return st.one_of(
        # URL shape
        st.builds(
            lambda host, repo: f"https://{host}/{repo}.git",
            st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=15),
            st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=15),
        ),
        # Registry shape
        st.builds(lambda n: f"registry:{n}", names()),
    )


def hex_strings(length):
    """Fixed-length hex strings (for SHAs, content_hashes)."""
    return st.text(alphabet="0123456789abcdef", min_size=length, max_size=length)


def multihash_identities():
    """Multihash-encoded identity strings — `sha256:<64-hex>` (#34)."""
    return st.builds(lambda h: f"sha256:{h}", hex_strings(64))


def version_triples():
    """`<major>.<minor>.<patch>` strings."""
    return st.builds(
        lambda a, b, c: f"{a}.{b}.{c}",
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
    )


def _git_provenance_record(draw_):
    """Build a single GitProvenanceRecord for tests."""
    return GitProvenanceRecord(
        url=draw_(source_urls()),
        ref=draw_(st.one_of(st.none(), names())),
        commit_sha=draw_(st.one_of(st.none(), hex_strings(40))),
    )


@st.composite
def locked_deps(draw, allowed_requires_names=None):
    """A single LockedDep value (v2 shape) with KDL-safe components."""
    name = draw(names())
    return LockedDep(
        name=name,
        identity=draw(st.one_of(st.none(), multihash_identities())),
        version=draw(version_triples()),
        src_dir=draw(st.text(alphabet=_NAME_ALPHABET, max_size=20)),
        requires=tuple(draw(st.lists(
            st.sampled_from(allowed_requires_names) if allowed_requires_names
            else names(),
            max_size=5,
            unique=True,
        ))),
        provenances=(_git_provenance_record(draw),),
    )


@st.composite
def lockfiles(draw):
    """A valid Lockfile.

    Constraint: dep names are unique within a lockfile (the parser
    builds a dict keyed by name, so duplicates would collapse on
    round-trip).
    """
    n_deps = draw(st.integers(min_value=0, max_value=8))
    unique_names = draw(st.lists(names(), min_size=n_deps, max_size=n_deps, unique=True))
    deps = []
    for name in unique_names:
        # requires refers to other dep names in this lockfile (or none)
        other_names = [n for n in unique_names if n != name]
        require_strategy = (
            st.sampled_from(other_names) if other_names
            else st.nothing()
        )
        deps.append(LockedDep(
            name=name,
            identity=draw(st.one_of(st.none(), multihash_identities())),
            version=draw(version_triples()),
            src_dir=draw(st.text(alphabet=_NAME_ALPHABET, max_size=20)),
            requires=tuple(draw(st.lists(
                require_strategy, max_size=3, unique=True,
            ))) if other_names else (),
            provenances=(_git_provenance_record(draw),),
        ))
    # Lockfile sorts by name on output, so canonical form sorts here too
    deps.sort(key=lambda d: d.name)
    return Lockfile(
        version=1,
        deps=tuple(deps),
        strategy=draw(st.sampled_from(["maxver", "minver", "semver"])),
    )


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

@given(lockfiles())
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_lockfile_format_parse_round_trip(L):
    """parse(format(L)) == L for any valid Lockfile.

    The lockfile's canonical form on output (sorted by name) must be
    invariant under parse/format cycle."""
    text = format_lockfile(L)
    parsed = parse_lockfile(text)
    assert parsed == L
