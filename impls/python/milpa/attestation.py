"""Attestation-policy helpers — S5 (RFC: Content-Addressed Attested Dependency Metadata).

Spec authority: spec/resolver-semantics.md §S5; docs/rfc-content-addressed-metadata.md §9.

The effective strict policy is the logical OR of:
  - the manifest ``attestation-policy "strict"`` field (committed, project default)
  - the ``--require-attested-metadata`` CLI flag (CI, where the manifest can't be edited)

The flag MUST NOT weaken a manifest-declared strict policy (OR semantics):
  once either source says strict, the policy is strict.  There is no flag value
  that turns manifest-strict off.

Post-resolve enforcement (called at the end of ``resolve()``):

Non-strict (default):
  If any resolved dep used ``EdgeSource.NIMBLE_FALLBACK``, emit a SINGLE summary
  warning to stderr enumerating those dep names.

Strict:
  (a) A named dep with no ``dep_decl`` pointer in the index (resolved via
      MilpaKdl or NimbleFallback because it had no DepDecl) →
      ``RES-UNATTESTED-METADATA``.
  (b) A named dep whose ``dep_decl`` artifact was unreachable (FETCH-FAILED
      in S3b; now a hard error under strict) →
      ``TNG-DEPDECL-FETCH-FAILED`` (already raised before reaching here).

SECURITY NOTE (not enforced here — enforced by DepDeclEdgeSource / DepDeclStore):
  Integrity failures (TNG-DEPDECL-HASH-MISMATCH, TNG-DEPDECL-PARSE-ERROR,
  TNG-DEPDECL-SCHEMA-MISMATCH, TNG-DEPDECL-SCHEMA-UNSUPPORTED) are ALWAYS
  hard errors — no fallback, regardless of strict/non-strict.  Only the benign
  *unreachable* case (FETCH-FAILED) is policy-gated.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from milpa.dep_decl import EdgeSource
from milpa.errors import RES_UNATTESTED_METADATA, MilpaError

if TYPE_CHECKING:
    from milpa.dep_decl import EdgeSet
    from milpa.manifest import AttestationPolicy, Manifest


# ---------------------------------------------------------------------------
# Effective-policy computation (the normative OR rule)
# ---------------------------------------------------------------------------


def effective_strict_policy(
    manifest_policy: "AttestationPolicy",
    flag: bool,
) -> bool:
    """Compute the effective strict policy.

    Returns ``True`` (strict) iff EITHER source says strict.
    The flag CANNOT weaken a manifest-declared strict policy.

    Parameters
    ----------
    manifest_policy:
        The ``attestation-policy`` field from the root manifest
        (``"permissive"`` or ``"strict"``).
    flag:
        ``True`` when ``--require-attested-metadata`` was passed on the CLI.

    Returns
    -------
    bool
        ``True`` if effective policy is strict; ``False`` if permissive.
    """
    # OR semantics: strict if either source says strict.
    return manifest_policy == "strict" or flag


# ---------------------------------------------------------------------------
# Post-resolve policy enforcement
# ---------------------------------------------------------------------------


def enforce_attestation_policy(
    resolved_edge_map: dict[str, "EdgeSet"],
    is_strict: bool,
) -> None:
    """Enforce the attestation policy after resolution completes.

    Called at the end of ``resolve()`` with the per-dep EdgeSet map.

    Parameters
    ----------
    resolved_edge_map:
        Mapping from dep name → EdgeSet (from the resolver's ``edge_cache``
        for named/URL deps, or the EdgeSet recorded per dep during the BFS).
    is_strict:
        ``True`` if the effective policy is strict (manifest OR flag).

    Raises
    ------
    MilpaError(RES-UNATTESTED-METADATA):
        Under strict: any dep whose EdgeSet has ``source == NIMBLE_FALLBACK``
        or ``source == MILPA_KDL`` (i.e., no index-attested DepDecl).
        Under non-strict this does NOT raise — only the summary warning fires.

    Side effects
    ------------
    Under non-strict: emits one summary warning to stderr if any dep used
    ``NimbleFallback``.  The warning text is human-readable (not a
    machine-readable slug).  It is written to stderr (alongside the eventual
    milpa-error slug for error paths, but this path is a SUCCESS path with a
    warning, so there is no slug emitted here).
    """
    nimble_fallback_names: list[str] = [
        name
        for name, es in sorted(resolved_edge_map.items())
        if es.source == EdgeSource.NIMBLE_FALLBACK
    ]

    if is_strict:
        # Under strict, any dep that did not come from an attested DepDecl is
        # an error.  The attested DepDecl path sets source == DEP_DECL (S3b).
        # Both NIMBLE_FALLBACK and MILPA_KDL mean "no index dep_decl pointer
        # was used," but only NIMBLE_FALLBACK is the *fallback risk* described
        # in §S5(a) for strict.  The warning (non-strict) is scoped to
        # NIMBLE_FALLBACK; the strict error is also scoped to NIMBLE_FALLBACK
        # because MILPA_KDL is declarative (acceptable).
        #
        # See BLOCKER-DISAMBIGUATION: the task description specifies "(a) a dep
        # with no dep_decl in the index → RES-UNATTESTED-METADATA."  For named
        # deps in the index that lack a dep_decl pointer, the resolver falls
        # through to MilpaKdl (if present) or NimbleFallback; in practice
        # NimbleFallback is the observable signal of "was in the index but no
        # dep_decl."  MilpaKdl is also relevant (URL deps that shipped
        # milpa.kdl), but URL deps are NOT index-resolved — they can't have a
        # dep_decl by design.  So RES-UNATTESTED-METADATA applies when source
        # == NIMBLE_FALLBACK (the risk case the spec calls out).
        if nimble_fallback_names:
            names_str = ", ".join(f"{n!r}" for n in nimble_fallback_names)
            raise MilpaError(
                RES_UNATTESTED_METADATA,
                f"strict attestation policy: {len(nimble_fallback_names)} dep(s) "
                f"resolved from un-attested .nimble metadata: {names_str}. "
                f"Ensure all deps are indexed with a dep_decl pointer, or relax "
                f"'attestation-policy' to 'permissive' in milpa.kdl.",
                names=nimble_fallback_names,
            )
    else:
        # Non-strict: emit one summary warning if any nimble-fallback deps exist.
        if nimble_fallback_names:
            names_str = ", ".join(nimble_fallback_names)
            n = len(nimble_fallback_names)
            print(
                f"[milpa] warning: {n} dep(s) resolved from un-attested "
                f".nimble metadata: {names_str}; "
                f"see spec §4.1 (attestation-policy / --require-attested-metadata).",
                file=sys.stderr,
            )
