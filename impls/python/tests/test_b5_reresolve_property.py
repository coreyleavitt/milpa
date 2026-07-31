"""B5 (resolution-semantics RFC §3 Axis B / §7 slice B5 — #70 acceptance): the
steady-state round-trip property.

    resolve(M) -> G;  L = lockfile_from_graph(G);  resolve(M, prior=L) == G

Re-resolving a manifest with the lockfile *it just produced* must reproduce
byte-for-byte the same graph (same version, identity, provenance, requires,
namespace, declared_version_source per dep) — minimal-change idempotence.
This is the acceptance test for B1/B2 (preference-aware pick fed from
``params.prior``).

**Scoped to steady state — the RFC names two exceptions this property must
exclude, not merely tolerate:**

1. **The one-time Axis-A migration window.** A prior lock recorded under the
   pre-Axis-A ``0.0.1`` sentinel would not match a fresh resolve's real
   declared version even though nothing else changed. This property never
   constructs such a lock: every dep here is a **named/index dep**, whose
   version has always been a real semver string (index versions were never
   subject to the ``0.0.1`` sentinel — that only ever applied to git/url/
   local/tarball singletons, Axis A). No git/url/local/tarball dep appears
   in the generated graphs at all, so the migration window cannot arise.

2. **Index yanks.** A version present in the first resolve's lock could, in
   principle, be yanked before the second resolve, legitimately forcing the
   dep to move (RFC: "a yanked version never becomes a candidate" — not a
   property violation). This property holds the **same in-memory `Index`**
   (parsed once from one generated ``index.kdl``, no ``yanked`` markers ever
   emitted) across both resolves in the pair — the candidate universe is
   provably identical for both calls.

**Multi-candidate coverage (what makes this a real property, not a
tautology):** the generator produces 1-3 named packages, each with 2-4
distinct, distinctly-content-hashed candidate versions in the index, with a
root constraint that is either absent (bare name — exercises the full
candidate set) or a randomly-chosen floor (``>=<version>``) that still
leaves at least one candidate. This is exactly the "named/index deps with
multiple candidate versions" shape the RFC calls out as "where minimal-
change actually bites" — a single-candidate git-only graph would pass
trivially and prove nothing.

The lockfile is round-tripped through the REAL on-disk text format
(``format_lockfile`` + ``parse_lockfile``), not just the in-memory
``from_graph`` object — this is what actually happens between two CLI
invocations, and is where a silent field-drop/mis-format bug (the exact
class of bug ``format.rs``'s own doc comment warns about, per this repo's
regen-corpus notes) would surface as a preference-lookup miss.

No mocking: real mocked-fetches git content + a real in-memory ``Index``,
same infra as ``test_b2_prior_lock_preference.py`` / ``test_a4_version_
unknown_constrained.py``, generalized to N packages x M versions.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import ResolvedDep, ResolvedGraph, format_lockfile, from_graph, parse_lockfile
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import resolve

# ---------------------------------------------------------------------------
# Generator: N named packages x M candidate versions each + a root constraint
# per package (none, or a floor that still leaves >=1 candidate).
# ---------------------------------------------------------------------------

_PKG_NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyz"

# KDL 2.0 bareword keywords ("null"/"true"/"false"/"nan"/"inf" parse as
# literal values, not identifiers) -- a package generated with one of these
# exact names is a KDL-authoring/quoting concern (any milpa.kdl node name
# collides the same way), not a resolution-semantics one, so it is excluded
# from the generator rather than "fixed" in the resolver. Mirrors the
# KDL-safe-alphabet discipline other property-test files in this repo use.
#
# "member" is ALSO excluded: it is milpa's own reserved dep-kind node name
# (manifest.py's `_parse_dep_node` disambiguation order, §3.2 step 1 --
# a node literally named "member" is always parsed as a MemberDep, never a
# NamedDep, regardless of context). A generated package named "member" is a
# manifest-grammar-collision concern identical in kind to the KDL barewords
# above, not a resolution-semantics one -- excluded from the generator for
# the same reason, not "fixed" by relaxing the parser's dispatch rule.
_KDL_RESERVED_WORDS = frozenset({"null", "true", "false", "nan", "inf", "member"})


@st.composite
def _pkg_names_st(draw: st.DrawFn, min_pkgs: int = 1, max_pkgs: int = 3) -> list[str]:
    n = draw(st.integers(min_value=min_pkgs, max_value=max_pkgs))
    names = draw(
        st.lists(
            st.text(alphabet=_PKG_NAME_ALPHABET, min_size=3, max_size=8).filter(
                lambda s: s not in _KDL_RESERVED_WORDS
            ),
            min_size=n,
            max_size=n,
            unique=True,
        )
    )
    return names


@st.composite
def _pkg_spec_st(draw: st.DrawFn, name: str) -> dict:
    """One package's generated shape: its version ladder + root constraint."""
    num_versions = draw(st.integers(min_value=2, max_value=4))
    versions = [f"{i}.0.0" for i in range(1, num_versions + 1)]
    # constraint: None (bare dep name) or a floor at one of the versions
    # (index 0..num_versions-1 inclusive -- may leave just the top candidate,
    # which is a legitimate degenerate case Hypothesis will also explore).
    has_constraint = draw(st.booleans())
    floor_idx = draw(st.integers(min_value=0, max_value=num_versions - 1)) if has_constraint else None
    return {"name": name, "versions": versions, "floor_idx": floor_idx}


@st.composite
def multi_candidate_graph_st(draw: st.DrawFn) -> list[dict]:
    names = draw(_pkg_names_st())
    return [draw(_pkg_spec_st(name)) for name in names]


# ---------------------------------------------------------------------------
# Fixture staging: real mocked git content + index.kdl, generalized to N
# packages x M versions (test_b2_prior_lock_preference.py's 2-version-only
# helpers generalized).
# ---------------------------------------------------------------------------


def _stage_pkg_versions(mocked_dir: Path, name: str, versions: list[str]) -> dict[str, str]:
    """Stage one mocked git dir per version with distinct content; return
    ``{version: content_hash}``."""
    url = f"https://example.com/{name}.git"
    hashes: dict[str, str] = {}
    for version in versions:
        ref = f"v{version}"
        d = mocked_dir / url_key(url, ref)
        content = d / "content"
        content.mkdir(parents=True)
        (content / f"{name}.nim").write_text(f"# {name} {version}\n", encoding="utf-8")
        (d / f"{name}.nimble").write_text(
            '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n', encoding="utf-8"
        )
        sha = hashlib.sha1(f"{name}-{version}".encode()).hexdigest()
        (d / "sha").write_text(sha, encoding="utf-8")
        hashes[version] = compute_content_hash(content.parent)
    return hashes


def _index_kdl(specs: list[dict], hashes_by_pkg: dict[str, dict[str, str]]) -> str:
    blocks = []
    for spec in specs:
        name = spec["name"]
        version_blocks = []
        for version in spec["versions"]:
            content_hash = hashes_by_pkg[name][version]
            commit_sha = hashlib.sha1(f"{name}-{version}-commit".encode()).hexdigest()
            version_blocks.append(
                f"""    version "{version}" {{
        content_hash "{content_hash}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v{version}"
            commit_sha "{commit_sha}"
        }}
    }}
"""
            )
        blocks.append(f'package "{name}" {{\n' + "".join(version_blocks) + "}\n")
    return "schema_version 1\n" + "".join(blocks)


def _root_manifest_kdl(specs: list[dict]) -> str:
    lines = ['name "myapp"', 'kind "application"', "deps {"]
    for spec in specs:
        name = spec["name"]
        floor_idx = spec["floor_idx"]
        if floor_idx is None:
            lines.append(f"    {name}")
        else:
            floor_version = spec["versions"][floor_idx]
            lines.append(f'    {name} ">={floor_version}"')
    lines.append("}")
    return "\n".join(lines) + "\n"


def _env(tmp_path: Path, mocked_dir: Path, index_kdl: str) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _dep_signature(d: ResolvedDep) -> tuple:
    """Canonical, order-insensitive signature of everything that identifies a
    resolved dep's steady state -- version label, identity, provenance,
    requires, namespace, and the Axis-A declared-version-source sidecar."""
    return (
        d.version,
        d.identity,
        tuple(sorted(repr(p) for p in d.provenances)),
        tuple(sorted(d.requires)),
        d.namespace,
        d.declared_version_source,
    )


def _graph_signature(graph: ResolvedGraph) -> dict[str, tuple]:
    return {d.name: _dep_signature(d) for d in graph.deps}


# ---------------------------------------------------------------------------
# The property
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(specs=multi_candidate_graph_st())
def test_b5_reresolve_with_own_lock_reproduces_same_graph(specs: list[dict]) -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp_path = Path(td)
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        hashes_by_pkg = {
            spec["name"]: _stage_pkg_versions(mocked_dir, spec["name"], spec["versions"])
            for spec in specs
        }
        index_kdl = _index_kdl(specs, hashes_by_pkg)
        env = _env(tmp_path, mocked_dir, index_kdl)
        manifest = parse_manifest(_root_manifest_kdl(specs))

        deps_dir1 = tmp_path / "_deps1"
        graph1 = resolve(manifest, deps_dir1, env, ResolveParams(prior=None))

        lock1 = from_graph(graph1)
        # Real on-disk text round-trip (write, not just the in-memory
        # from_graph object) -- this is the boundary a silent field-drop
        # bug would cross undetected.
        prior = parse_lockfile(format_lockfile(lock1))

        deps_dir2 = tmp_path / "_deps2"
        graph2 = resolve(manifest, deps_dir2, env, ResolveParams(prior=prior))

        assert _graph_signature(graph2) == _graph_signature(graph1)
