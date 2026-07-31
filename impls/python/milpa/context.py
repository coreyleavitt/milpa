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
from datetime import datetime
from pathlib import Path

from milpa.cas import CAStore
from milpa.entry_trust import EntryTrustConfig
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

    #: Force fresh index+bundle fetch, bypassing cache TTL (``--refresh-index``).
    refresh_index: bool = False

    #: True when ``--require-attested-index`` CLI flag was passed.
    #: Escalates the effective index-trust policy from warn → strict (never touches off).
    #: Stored here (not read from env) because it comes from CLI arg parsing in main().
    require_attested_index: bool = False

    #: P3a (RFC per-entry-attestation.md §4): True when
    #: ``--require-attested-entries`` CLI flag was passed. Escalates the
    #: effective entry-trust policy from warn → strict (never touches off).
    #: Mirrors ``require_attested_index`` — stored here (not read from env)
    #: because it comes from CLI arg parsing in main().
    require_attested_entries: bool = False


@dataclass(frozen=True)
class ResolveParams:
    """Per-call resolution parameters — may differ verb-to-verb / fixture-to-fixture.

    Fields
    ------
    strategy:
        Version-selection rule for named deps (default ``maxver``).
        Recorded in the lockfile; the frozen fast-path checks for mismatch.

    strategy_explicit:
        R9 (resolution-semantics RFC §3 Axis C / D-C2): whether ``strategy``
        above was EXPLICITLY sourced (CLI ``--strategy`` or manifest
        ``resolution { strategy }``), as opposed to default-filled (neither
        present). Computed by the CLI layer alongside ``strategy`` itself
        (derived from ``resolver._resolve_effective_strategy``'s
        ``Strategy | None`` result via ``decl is not None``). Consumed ONLY by
        ``_Provider._bypasses_lock_preference`` (never the picker) — the
        lockfile-recorded strategy is diagnostic/frozen-parity only, never
        a live input, so a merely default-filled ``strategy`` must never
        bypass B2's lock-preference even when it numerically differs from
        the lock's recorded value.

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

    exclude_newer:
        D2 (resolution-semantics RFC §3 Axis D): the EFFECTIVE time-bound for
        this resolve, already resolved by the CLI layer's precedence chain
        (``_resolve_effective_exclude_newer``: CLI ``--exclude-newer`` >
        manifest ``resolution { exclude-newer }`` > ``None``).  ``None``
        means no time bound is active.  Stored here — mirroring ``strategy``
        — so it rides ``self._params`` all the way into ``_Provider``;
        nothing consumes it yet (D3 filters index candidates by
        ``published_at``, D4 validates a pinned git ref's committer date —
        both later slices).
    """

    strategy: Strategy = Strategy.MAXVER
    strategy_explicit: bool = False
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
    # P3a (RFC per-entry-attestation.md §3, §4): the entry-trust gate config.
    # ``None`` disables the gate entirely (equivalent to policy "off" but also
    # covers "not wired for this call site yet" — e.g. verbs that don't touch
    # the index).  Unlike index-trust (gated once at index load, BEFORE
    # resolve() runs, via MilpaEnv), entry-trust gates at the selection step
    # INSIDE the resolver (§3), so it travels on the per-call ResolveParams,
    # not the per-process MilpaEnv.
    entry_trust: "EntryTrustConfig | None" = None
    # D2 (resolution-semantics RFC §3 Axis D): the effective exclude-newer
    # time-bound (CLI > manifest > None). See the docstring above.
    exclude_newer: datetime | None = None
