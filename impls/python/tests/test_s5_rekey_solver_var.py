"""RFC ``docs/rfc-origin-as-identity.md`` §4.4 (S5-rekey), Stage B (Python).

Headline collapse: two DISTINCT consumer labels for a named/registry dep
that bind to the SAME source-id — a root-declared BARE label and a
TRANSITIVE package's own ``milpa.kdl``-declared NAMESPACE-QUALIFIED label
for the identical underlying registry package — must be treated as ONE
PubGrub package variable, so their constraints are INTERSECTED by the
solver itself, not resolved as two independent picks reconciled after the
fact.

Before S5-rekey: the PubGrub package variable is ``DepKey.solver_var()``
(``name`` or ``ns::name``) — a function of the CONSUMER'S label alone. The
root's bare ``foo`` and the transitive ``wrapper`` package's qualified
``acme::foo`` requirement are two solver variables; each is solved
independently against its OWN constraint, so ``maxver`` picks a DIFFERENT
version for each. Because the two picked versions have genuinely different
fetched-bytes identity, the existing post-solve S4b cross-origin dedup
(``_dedup_candidates``, keyed by content ``identity``) does NOT merge them
— it only merges when two labels' solver picks happen to land on
byte-identical content. Result: two resolved nodes for one origin, at two
different versions, in one build — a real correctness bug.

After S5-rekey: the PubGrub package variable is
``BindingResolver.canonical_for(dep_key)`` — a function of the BOUND
source-id. Both labels bind to the identical ``RegistrySourceId(registry=
"tianguis", namespace="acme", name="foo")``, so they collapse to ONE
PubGrub variable BEFORE the solver runs. PubGrub then intersects both
labels' constraints natively, picking the single highest version that
satisfies both — one resolved node, one version.
"""

from __future__ import annotations

from pathlib import Path

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.manifest import Manifest, NamedDep, UrlDep
from milpa.registry import GitIndexProvenance, Index, IndexVersion, Package
from milpa.resolver import resolve

WRAPPER_URL = "https://example.com/wrapper.git"
WRAPPER_REF = "main"

# Three distinct versions of the registry package "foo" (namespace "acme"),
# each at its OWN url/ref so fetched-bytes identity genuinely differs per
# version (no accidental S4b identity-merge across versions).
_VERSIONS = {
    "1.0.0": "https://example.com/foo-v1.0.0.git",
    "1.2.0": "https://example.com/foo-v1.2.0.git",
    "1.3.0": "https://example.com/foo-v1.3.0.git",
}
_FOO_REF = "main"


def _stage(mocked_dir: Path, url: str, ref: str, *, content_text: str) -> None:
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / "marker.nim").write_text(content_text, encoding="utf-8")
    (d / "sha").write_text("a" * 40, encoding="utf-8")


def _stage_all(mocked_dir: Path) -> None:
    for ver, url in _VERSIONS.items():
        _stage(mocked_dir, url, _FOO_REF, content_text=f"# foo {ver}\n")
    # wrapper: a transitive package whose OWN milpa.kdl requires "foo" under
    # the EXPLICIT qualified namespace "acme" — a DIFFERENT consumer label
    # than the root's bare "foo", binding to the SAME registry origin.
    _stage(
        mocked_dir,
        WRAPPER_URL,
        WRAPPER_REF,
        content_text="# wrapper\n",
    )
    d = mocked_dir / url_key(WRAPPER_URL, WRAPPER_REF)
    (d / "content" / "milpa.kdl").write_text(
        'name "wrapper"\nkind "library"\n'
        "deps {\n"
        '    foo namespace="acme" ">= 1.0.0"\n'
        "}\n",
        encoding="utf-8",
    )


def _index_with_foo_under_acme() -> Index:
    """A single registry package (namespace ``acme``, name ``foo``) at three
    versions, each with distinct content so identity genuinely differs."""
    return Index(
        packages=[
            Package(
                name="foo",
                namespace="acme",
                versions=tuple(
                    IndexVersion(
                        version=ver,
                        content_hash="sha256:" + str(i + 1).rjust(64, "0"),
                        provenances=(
                            GitIndexProvenance(url=url, ref=_FOO_REF, commit_sha=None),
                        ),
                    )
                    for i, (ver, url) in enumerate(_VERSIONS.items())
                ),
            )
        ]
    )


def _make_env(tmp_path: Path, index: Index) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir(parents=True, exist_ok=True)
    _stage_all(mocked_dir)
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _manifest(deps: list) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=deps,
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


class TestRootBareAndTransitiveQualifiedLabelsForSameOriginCollapse:
    """Root declares the registry package bare: ``foo`` constrained
    ``< 1.3.0`` (best independently = 1.2.0). A fetched transitive package
    (``wrapper``) declares, in its OWN ``milpa.kdl``, a namespace-qualified
    requirement on the SAME origin: ``foo namespace="acme" ">= 1.0.0"``
    (best independently = 1.3.0, MAXVER default).

    Solved as ONE PubGrub variable (bare and qualified both bind to the
    identical ``RegistrySourceId``), the intersected constraint
    (``>= 1.0.0, < 1.3.0``) has exactly one MAXVER pick: 1.2.0 — a single
    resolved node. Solved as two INDEPENDENT variables (pre-rekey), each
    picks its own best version — two resolved nodes, two different
    versions, for what is by origin ONE package."""

    def test_bare_root_and_qualified_transitive_collapse_to_one_node(
        self, tmp_path: Path
    ) -> None:
        index = _index_with_foo_under_acme()
        env = _make_env(tmp_path, index)
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir(exist_ok=True)

        manifest = _manifest(
            [
                NamedDep(name="foo", constraint="< 1.3.0", namespace=None),
                UrlDep(name="wrapper", git=WRAPPER_URL, ref=WRAPPER_REF),
            ]
        )

        graph = resolve(manifest, deps_dir, env, ResolveParams())

        foo_nodes = [d for d in graph.deps if d.name == "foo"]
        assert len(foo_nodes) == 1, (
            f"expected ONE resolved node for the shared origin (constraints "
            f"intersected by a single solver variable), got {len(foo_nodes)}: "
            f"{[(d.name, d.namespace, d.version) for d in graph.deps]}"
        )
        assert foo_nodes[0].version == "1.2.0"


BEARSSL_URL = "https://example.com/bearssl.git"
BEARSSL_REF = "v1"
CHRONOS_URL = "https://example.com/chronos.git"
CHRONOS_REF = "main"


class TestRootGitDepUnifiesWithTransitiveBareNamedRequire:
    """RFC §4.4.1 (the normative two-phase design): root declares
    ``bearssl git=<url>`` directly (a phase-1 kind-default git claim, bound
    at ``BindingResolver.__init__``). A transitive package (``chronos``,
    also root-declared via git) has its OWN ``.nimble`` with a BARE
    ``requires "bearssl >= 0.2.8"`` — an ordinary ``NamedRequire``, which
    would naively guess a fictional registry coordinate for "bearssl".

    Phase 1 step 1 (binding-aware) intercepts this: ``bearssl``'s ``DepKey``
    is ALREADY bound (root's own git claim), so the transitive's guess is
    never even computed — it resolves to the SAME ``canonical(GitSourceId
    (url=...))`` string root's own term uses. One PubGrub variable, unified
    PRE-fetch. Must resolve to ONE node whose source is the git URL — not
    two nodes, and not a spurious SOLVE-CONFLICT (the historical failure
    mode this exact shape hit before the binding-first check existed —
    conformance fixture-415 pins the regression at the corpus level; this
    is the same shape as a direct, explicit unit assertion)."""

    def test_root_git_dep_and_transitive_bare_named_require_collapse_to_one_git_node(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()

        bearssl_dir = mocked_dir / url_key(BEARSSL_URL, BEARSSL_REF)
        (bearssl_dir / "content").mkdir(parents=True)
        (bearssl_dir / "content" / "bearssl.nimble").write_text(
            '# Package\nversion = "0.5.0"\nauthor = "example"\n'
            'description = "bearssl"\nlicense = "MIT"\n',
            encoding="utf-8",
        )
        (bearssl_dir / "sha").write_text("b" * 40, encoding="utf-8")

        chronos_dir = mocked_dir / url_key(CHRONOS_URL, CHRONOS_REF)
        (chronos_dir / "content").mkdir(parents=True)
        (chronos_dir / "content" / "chronos.nimble").write_text(
            '# Package\nauthor = "example"\n'
            'description = "chronos (no version declared)"\n'
            'license = "MIT"\nrequires "bearssl >= 0.2.8"\n',
            encoding="utf-8",
        )
        (chronos_dir / "sha").write_text("c" * 40, encoding="utf-8")

        store = CAStore(tmp_path / ".cas")
        fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
        env = MilpaEnv(fetcher=fetcher, index=None, store=store)
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir(exist_ok=True)

        manifest = _manifest(
            [
                UrlDep(name="bearssl", git=BEARSSL_URL, ref=BEARSSL_REF),
                UrlDep(name="chronos", git=CHRONOS_URL, ref=CHRONOS_REF),
            ]
        )

        graph = resolve(manifest, deps_dir, env, ResolveParams())

        bearssl_nodes = [d for d in graph.deps if d.name == "bearssl"]
        assert len(bearssl_nodes) == 1, (
            f"expected ONE resolved node for 'bearssl' (root git claim and "
            f"transitive bare NamedRequire must unify PRE-fetch via phase-1 "
            f"binding resolution), got {len(bearssl_nodes)}: "
            f"{[(d.name, d.version, d.provenances) for d in graph.deps]}"
        )
        assert bearssl_nodes[0].version == "0.5.0"
        assert bearssl_nodes[0].provenances[0].url == BEARSSL_URL
        # chronos itself must have resolved too (no SOLVE-CONFLICT).
        assert any(d.name == "chronos" for d in graph.deps)
