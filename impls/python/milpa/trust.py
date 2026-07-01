"""SSOT policy type and helpers for attestation and index-trust axes.

RFC: docs/rfc-registry-trust-federation.md §6.6 (S1 — SSOT policy unification;
S5 — full 3-source authority model with ``off`` handling and env strengthening).

Both ``attestation-policy`` and ``index-trust`` parse to ``TrustPolicy`` via
``_parse_trust_policy``.  The effective policy for any axis is computed by
``effective_trust_policy``.

This module replaces ``attestation.py``'s ``effective_strict_policy`` and is
the single source of truth for policy values and parsing.

S5 note: ``effective_trust_policy`` now implements the FULL §6.6 authority
formula, matching the Rust ``effective_trust_policy`` in
``milpa-core/src/resolver.rs``.  The formula:
  - ``manifest=off`` always returns ``off`` (project-only auditable opt-out;
    env and flag cannot set or clear ``off``).
  - ``base = strict`` if ``env_override == "strict"``, else the manifest value.
    (``env=off`` and ``env=warn`` are no-op floors — they cannot weaken the
    manifest; only ``env=strict`` can strengthen a manifest ``warn``.)
  - Flag escalates: if ``flag`` is True, return ``strict`` (never touches ``off``).
"""

from __future__ import annotations

from typing import Literal

from milpa.errors import MAN_UNKNOWN_TOP_LEVEL, MilpaError

# ---------------------------------------------------------------------------
# Single source of truth for policy values
# ---------------------------------------------------------------------------

TrustPolicy = Literal["warn", "strict", "off"]

_VALID_TRUST_POLICIES: frozenset[str] = frozenset({"warn", "strict", "off"})


# ---------------------------------------------------------------------------
# Shared parse helper — used by manifest parser for both axes
# ---------------------------------------------------------------------------


def _parse_trust_policy(value: str, node: str = "attestation-policy") -> "TrustPolicy":
    """Parse a policy string to ``TrustPolicy``.

    Raises ``MilpaError(MAN-UNKNOWN-TOP-LEVEL)`` if the value is not one of
    ``"warn"``, ``"strict"``, or ``"off"``.  The old ``"permissive"`` value is
    intentionally rejected (pre-v1 breaking rename).

    Parameters
    ----------
    value:
        Raw string from the manifest or environment.
    node:
        The manifest node name (used in the error message).
    """
    if value not in _VALID_TRUST_POLICIES:
        raise MilpaError(
            MAN_UNKNOWN_TOP_LEVEL,
            f"'{node}' must be 'warn', 'strict', or 'off', got {value!r}",
            node=node,
            value=value,
        )
    return value  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Shared effective-policy computation
# ---------------------------------------------------------------------------


def effective_trust_policy(
    manifest_policy: "TrustPolicy | None",
    flag: bool,
    env_override: str | None = None,
) -> "TrustPolicy":
    """Compute the effective trust policy for an axis.

    Implements the FULL §6.6 authority-model formula (S5), matching the Rust
    ``effective_trust_policy`` in ``milpa-core/src/resolver.rs``.

    Authority model:
    1. ``manifest=off`` → always returns ``"off"``.  ``off`` is a project-only
       auditable opt-out; env and the CLI flag CANNOT set or clear it.
    2. ``base = max(manifest, env)`` where ``strict > warn``; ``env=off`` and
       ``env=warn`` are no-op floors and cannot weaken a manifest ``warn``/``strict``.
       Only ``env=strict`` can strengthen a manifest ``warn`` to ``strict``.
    3. If ``flag`` → return ``"strict"`` (escalates warn→strict; never touches off).

    Differences from S1:
    - ``env_override="strict"`` NOW strengthens the base (not ignored).
    - ``env_override="off"`` is still a no-op floor (cannot weaken manifest).
    - ``manifest_policy="off"`` NOW returns ``"off"`` immediately.

    Parameters
    ----------
    manifest_policy:
        The parsed ``TrustPolicy`` field from the manifest, or ``None`` if
        absent (defaults to ``"warn"``).
    flag:
        ``True`` when the corresponding CLI flag escalates to strict (e.g.
        ``--require-attested-index`` for the index-trust axis,
        ``--require-attested-metadata`` for the attestation axis).
    env_override:
        Raw ``TrustPolicy`` string from the corresponding env var
        (``MILPA_INDEX_TRUST`` / ``MILPA_REQUIRE_ATTESTED_METADATA``), or
        ``None`` if absent.  ``env=off`` cannot weaken manifest ``warn``/``strict``.

    Returns
    -------
    TrustPolicy
        One of ``"warn"``, ``"strict"``, or ``"off"``.
    """
    # Resolve None → default "warn".
    effective_manifest: TrustPolicy = manifest_policy if manifest_policy is not None else "warn"

    # Step 1: off is an auditable project-only opt-out; env/flag cannot override it.
    if effective_manifest == "off":
        return "off"

    # Step 2: base = max(manifest, env) over {warn, strict}.
    # env=off and env=warn cannot strengthen beyond the manifest value;
    # only env=strict can escalate a manifest-warn to strict.
    if env_override == "strict":
        base: TrustPolicy = "strict"
    else:
        base = effective_manifest

    # Step 3: CLI flag can only escalate warn→strict; never touches off.
    if flag:
        return "strict"
    return base
