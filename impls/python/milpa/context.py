"""Execution-context seam — MilpaEnv + ResolveParams.

RFC §4.4 execution-context seam.  Two frozen dataclasses with an explicit cut
between injectable environment seams (constant per process, DI'd by the
conformance adapter) and per-call resolution parameters (may differ verb-to-
verb / fixture-to-fixture).

The cut is load-bearing:

- ``MilpaEnv`` carries the DI seams: ``fetcher``, ``index``, ``store``.
  Built **once** per process; read from the environment at construction time.
  MILPA_MOCKED_FETCHES, MILPA_CACHE_DIR, MILPA_INDEX_URL are read in exactly
  one place: here (in the CLI) or injected by the conformance adapter.

- ``ResolveParams`` carries per-call resolution parameters: ``strategy``,
  ``max_parallel``, ``profile``, ``prior``.  May differ between ``fetch`` /
  ``lock`` / ``update`` verbs within one process.

``resolve(manifest, deps_dir, env, params)`` takes both.
``resolve_frozen(lockfile, env)`` takes **only** env — it has no ResolveParams
and therefore no strategy/max_parallel/prior, making "frozen never fetches"
enforceable by signature, not by discipline (RFC §4.4 NORMATIVE).

Index is loaded EAGERLY (RFC §4.4 note): a frozen=True dataclass cannot
replace a None field after construction, so lazy-load is not expressible here.
``index=None`` means "this invocation does not require index resolution," never
"load it later."

Spec: docs/rfc-python-clean-room-rewrite.md §4.4 (S9a).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from milpa.cas import CAStore
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.index_trust import IndexTrustConfig
from milpa.lockfile import Lockfile
from milpa.profile import Profile
from milpa.registry import Index
from milpa.version import Strategy


@dataclass(frozen=True)
class MilpaEnv:
    """Injectable seams — constant per process, DI'd by the conformance adapter.

    Fields
    ------
    fetcher:
        The ``CasAdmittingFetcher`` used by ``resolve``/``resolve_workspace``.
        Default registry for live invocations; a mocked registry wrapped in
        ``CasAdmittingFetcher`` for the in-process conformance adapter.

    index:
        Loaded tianguis ``Index`` (for named-dep resolution), or ``None`` when
        the verb does not require named-dep resolution
        (``show``/``verify``/``clean`` and the frozen fast-path).
        Loaded EAGERLY — ``None`` is NOT "load later," it is "not needed here."

    store:
        The ``CAStore`` instance.  Used by the frozen path
        (``resolve_frozen``/``resolve_workspace_frozen``) to locate admitted
        trees without any fetcher invocation.

    dep_decl_store:
        The ``DepDeclStore`` for fetching/caching DepDecl artifacts (S3b).
        ``None`` disables the attested-metadata path (DepDecl branch in
        ``resolve_edges`` falls through to MilpaKdl/Nimble).

        Production: ``HttpDepDeclStore`` derived from ``MILPA_INDEX_URL``.
        Conformance harness: ``FileDepDeclStore`` from ``MILPA_DEP_DECL_DIR``.
        Frozen / show / verify paths: ``None`` (no DepDecl fetch needed).
    """

    fetcher: CasAdmittingFetcher
    index: Index | None
    store: CAStore
    dep_decl_store: object | None = None  # DepDeclStore protocol (S3b)

    #: True when the user explicitly requested no index (``--no-index`` flag).
    #: An explicit alias of empty ``MILPA_INDEX_URL`` that OVERRIDES any
    #: configured index (env or default). Read by ``_load_index_for_verb`` and
    #: ``_build_dep_decl_store`` to suppress index loading. (cli-contract §8.1)
    no_index: bool = False

    # S5 (RFC registry-trust-federation §6.4 / §10.1): index-trust configuration.
    # ``None`` disables the index-trust gate (legacy / no-bundle path).
    # When set, ``load_index`` consults it for every index fetch/cache-read.
    # No circular import: index_trust.py imports only milpa.errors + milpa.trust;
    # context.py's own imports (cas, fetchers, lockfile, profile, registry, version)
    # do not import index_trust.py.
    index_trust_config: IndexTrustConfig | None = None

    #: Force fresh index+bundle fetch, bypassing cache TTL (``--refresh-index``).
    refresh_index: bool = False

    #: True when ``--require-attested-index`` CLI flag was passed.
    #: Escalates the effective index-trust policy from warn → strict (never touches off).
    #: Stored here (not read from env) because it comes from CLI arg parsing in main().
    require_attested_index: bool = False


@dataclass(frozen=True)
class ResolveParams:
    """Per-call resolution parameters — may differ verb-to-verb / fixture-to-fixture.

    Fields
    ------
    strategy:
        Version-selection rule for named deps (default ``maxver``).
        Recorded in the lockfile; the frozen fast-path checks for mismatch.

    max_parallel:
        Parallelism level for the fetch stage (``ThreadPoolExecutor`` workers).
        MUST NOT affect the contents of any output artifact — only throughput.

    profile:
        Runtime profile for conditional-dep predicate evaluation.
        ``None`` disables predicate filtering (every dep is included).
        ``None`` is NOT "detect at runtime later" — it is "no profile."
        Passed as a fixed string from the fixture's ``env`` file in the
        conformance adapter (no live ``nim --version`` subprocess).

    prior:
        A previously-resolved lockfile to reuse pins from (§8 prior-lockfile
        pin reuse).  ``None`` means no prior / ``update`` with no ``<dep>``
        (drops all pins).  The frozen path does NOT accept ``ResolveParams``
        — it never has a ``prior`` because it never re-resolves.
    """

    strategy: Strategy = Strategy.MAXVER
    max_parallel: int = 4
    profile: Profile | None = None
    prior: Lockfile | None = None
    manifest_dir: Path | None = None  # project root; used by resolver to resolve local dep paths
    require_attested_metadata: bool = False  # S5: --require-attested-metadata CLI flag
    # S9 (RFC #23 §3.4 / §7 S9): CLI feature selection.
    # features: additional root flags to activate (beyond defaults/all).
    # no_default_features: suppress root default-true flags (absence-of-request, §3.1.3).
    # all_features: activate every declared root flag.
    features: frozenset[str] = frozenset()
    no_default_features: bool = False
    all_features: bool = False
