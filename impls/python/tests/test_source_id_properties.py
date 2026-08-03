"""Property-based tests for ``milpa.source_id`` (rfc-origin-as-identity.md
§10 S1, F9; revised round-2.5, [[provenance_source_selection]]).

**There is no round-trip law any more** — ``parse()`` is deleted;
``canonical()`` is a ONE-WAY key, never parsed back (the authoritative
representation is the frozen dataclass itself). The only law left is
**injectivity**:

    canonical(a) == canonical(b)  iff  a == b

Two distinct composite Hypothesis generators drive it:

  (a) ``pkg+`` alias/namespace(variable-arity, possibly ``/``-bearing,
      host-qualified-realistic)/name generation — probes the "namespace may
      contain `/`, name-last" injectivity argument directly.
  (b) the injectivity law across ALL SIX kinds, over URL-shaped alphabets
      (not bare identifiers) restricted to the WELL-FORMED domain (the
      domain ``normalize_source`` accepts) — a base alphabet that excludes
      the literal ``#subdirectory=`` delimiter substring, since injectivity
      over the *unvalidated* domain is a known, guarded-against non-law (see
      ``test_source_id.py``'s ``TestNormalizeDelimCollisionGuard`` /
      ``TestNormalizeOciRegistrySegmentGuard`` for explicit collision proofs
      and the guard that rejects them).

All generators draw from URL-shaped alphabets per the RFC's own instruction.

Hypothesis database: ``impls/python/.hypothesis/`` (gitignored, project convention).
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from milpa.source_id import (
    GitSourceId,
    LocalSourceId,
    MemberSourceId,
    OciSourceId,
    RegistrySourceId,
    SourceId,
    TarballSourceId,
    canonical,
)

# ---------------------------------------------------------------------------
# Shared alphabets — URL-shaped, restricted to the WELL-FORMED domain
# ---------------------------------------------------------------------------

#: Ordinary URL characters, deliberately EXCLUDING '#' — a base containing a
#: literal '#subdirectory=' substring is the one pathological case
#: normalize_source rejects (SRC-ID-MALFORMED) rather than escapes; the
#: injectivity law is over the domain normalize_source accepts, so the
#: property-test alphabet stays inside that domain. (The collision itself,
#: and the guard, are proven directly in test_source_id.py.)
_URL_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789%?=&/:.-_~"
_URL_CHARS_NO_SLASH = _URL_CHARS.replace("/", "")

#: The manifest package-name alphabet — used for RegistrySourceId's
#: `/`-free anchors (`alias`, `name`).
_DEP_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

#: A namespace SEGMENT's alphabet is looser than a dep-name's: real tianguis
#: namespaces are host-qualified domain names (`codeberg.org`) which contain
#: `.` — a character `_DEP_NAME_CHARS` excludes. Segments must still avoid
#: '/' (the separator) and must not equal '..' (filtered below).
_NAMESPACE_SEGMENT_CHARS = _DEP_NAME_CHARS + "."

_SUBPATH_SEGMENT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_-."


@st.composite
def url_like_st(draw: st.DrawFn, *, no_slash: bool = False, max_size: int = 40) -> str:
    alphabet = _URL_CHARS_NO_SLASH if no_slash else _URL_CHARS
    return draw(st.text(alphabet=alphabet, min_size=1, max_size=max_size))


@st.composite
def dep_name_like_st(draw: st.DrawFn, max_size: int = 12) -> str:
    return draw(st.text(alphabet=_DEP_NAME_CHARS, min_size=1, max_size=max_size))


@st.composite
def namespace_segment_st(draw: st.DrawFn) -> str:
    seg = draw(st.text(alphabet=_NAMESPACE_SEGMENT_CHARS, min_size=1, max_size=10))
    return draw(st.just(seg).filter(lambda s: s != ".."))


@st.composite
def namespace_st(draw: st.DrawFn, min_segs: int = 1, max_segs: int = 3) -> str:
    """A `/`-joined namespace — variable segment count, each segment
    possibly host-qualified (containing '.')."""
    n = draw(st.integers(min_value=min_segs, max_value=max_segs))
    segs = [draw(namespace_segment_st()) for _ in range(n)]
    return "/".join(segs)


@st.composite
def maybe_namespace_st(draw: st.DrawFn) -> str | None:
    if draw(st.booleans()):
        return draw(namespace_st())
    return None


@st.composite
def subpath_segment_st(draw: st.DrawFn) -> str:
    seg = draw(st.text(alphabet=_SUBPATH_SEGMENT_CHARS, min_size=1, max_size=10))
    return draw(st.just(seg).filter(lambda s: s != ".."))


@st.composite
def subpath_st(draw: st.DrawFn, min_segs: int = 1, max_segs: int = 3) -> str:
    n = draw(st.integers(min_value=min_segs, max_value=max_segs))
    segs = [draw(subpath_segment_st()) for _ in range(n)]
    return "/".join(segs)


@st.composite
def maybe_subpath_st(draw: st.DrawFn) -> str | None:
    if draw(st.booleans()):
        return draw(subpath_st())
    return None


# ---------------------------------------------------------------------------
# (a) pkg+ variable-arity, `/`-bearing namespace generation
# ---------------------------------------------------------------------------


@st.composite
def registry_source_id_st(draw: st.DrawFn) -> RegistrySourceId:
    return RegistrySourceId(
        registry=draw(dep_name_like_st()),
        namespace=draw(maybe_namespace_st()),
        name=draw(dep_name_like_st()),
    )


class TestPkgVariableArityInjectivity:
    @given(registry_source_id_st(), registry_source_id_st())
    @settings(max_examples=400)
    def test_canonical_injective(self, a: RegistrySourceId, b: RegistrySourceId) -> None:
        """canonical(a) == canonical(b) iff a == b — including when
        `namespace` is `/`-bearing (variable segment count) or absent."""
        if a == b:
            assert canonical(a) == canonical(b)
        if canonical(a) == canonical(b):
            assert a == b

    @given(dep_name_like_st(), namespace_st(min_segs=1, max_segs=1), dep_name_like_st())
    @settings(max_examples=200)
    def test_single_segment_namespace_matches_two_segment_form(
        self, alias: str, ns: str, name: str
    ) -> None:
        sid = RegistrySourceId(registry=alias, namespace=ns, name=name)
        assert canonical(sid) == f"pkg+{alias}/{ns}/{name}"

    @given(dep_name_like_st(), dep_name_like_st())
    @settings(max_examples=100)
    def test_no_namespace_form(self, alias: str, name: str) -> None:
        sid = RegistrySourceId(registry=alias, namespace=None, name=name)
        assert canonical(sid) == f"pkg+{alias}/{name}"


# ---------------------------------------------------------------------------
# (b) injectivity law across all six kinds, well-formed domain
# ---------------------------------------------------------------------------


@st.composite
def any_source_id_st(draw: st.DrawFn) -> SourceId:
    kind = draw(st.sampled_from(["git", "tar", "oci", "local", "registry", "member"]))
    if kind == "git":
        return GitSourceId(url=draw(url_like_st()), subpath=draw(maybe_subpath_st()))
    if kind == "tar":
        return TarballSourceId(url=draw(url_like_st()), subpath=draw(maybe_subpath_st()))
    if kind == "oci":
        return OciSourceId(
            registry=draw(url_like_st(no_slash=True, max_size=15)),
            repository=draw(url_like_st()),
            subpath=draw(maybe_subpath_st()),
        )
    if kind == "local":
        return LocalSourceId(path=draw(url_like_st()))
    if kind == "registry":
        return RegistrySourceId(
            registry=draw(dep_name_like_st()),
            namespace=draw(maybe_namespace_st()),
            name=draw(dep_name_like_st()),
        )
    return MemberSourceId(member_name=draw(dep_name_like_st()))


class TestInjectivityLawAllKinds:
    @given(any_source_id_st(), any_source_id_st())
    @settings(max_examples=400)
    def test_canonical_injective(self, a: SourceId, b: SourceId) -> None:
        """``canonical(a) == canonical(b) iff a == b`` — both directions,
        over the well-formed domain (the domain normalize_source accepts).
        This is the ONLY law left now that canonical() is one-way."""
        if a == b:
            assert canonical(a) == canonical(b)
        if canonical(a) == canonical(b):
            assert a == b

    @given(any_source_id_st())
    @settings(max_examples=200)
    def test_different_kinds_never_collide(self, sid: SourceId) -> None:
        """A cross-kind sanity check: canonical() always starts with the
        kind's own reserved prefix, so no two DIFFERENT kinds can ever
        produce the same canonical string regardless of field content."""
        s = canonical(sid)
        prefixes = ("git+", "oci+", "tar+", "pkg+", "file+", "member+")
        matches = [p for p in prefixes if s.startswith(p)]
        assert len(matches) == 1
