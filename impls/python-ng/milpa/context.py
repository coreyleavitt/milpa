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
    """

    fetcher: CasAdmittingFetcher
    index: Index | None
    store: CAStore


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
