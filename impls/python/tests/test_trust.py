"""Tests for the trust.py SSOT policy module.

RFC: docs/rfc-registry-trust-federation.md §6.6 (S1 — SSOT policy unification).

Covers:
- ``_parse_trust_policy``: accepts warn/strict/off; rejects permissive and
  other garbage with MilpaError(MAN-UNKNOWN-TOP-LEVEL).
- ``effective_trust_policy``: returns TrustPolicy values; semantics match the
  ported effective_strict_policy (OR of manifest + flag).
"""

from __future__ import annotations

import pytest

from milpa.errors import MAN_UNKNOWN_TOP_LEVEL, MilpaError
from milpa.trust import TrustPolicy, _parse_trust_policy, effective_trust_policy


# ---------------------------------------------------------------------------
# _parse_trust_policy — acceptance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["warn", "strict", "off"])
def test_parse_trust_policy_accepts_valid(value: str) -> None:
    result = _parse_trust_policy(value)
    assert result == value


def test_parse_trust_policy_returns_trust_policy_type_warn() -> None:
    result = _parse_trust_policy("warn")
    # The return value is the string literal — check it's one of the valid values.
    assert result in ("warn", "strict", "off")


# ---------------------------------------------------------------------------
# _parse_trust_policy — rejection
# ---------------------------------------------------------------------------


def test_parse_trust_policy_rejects_permissive() -> None:
    """The old 'permissive' value is rejected — pre-v1 breaking rename."""
    with pytest.raises(MilpaError) as exc_info:
        _parse_trust_policy("permissive")
    assert exc_info.value.slug == MAN_UNKNOWN_TOP_LEVEL


def test_parse_trust_policy_rejects_garbage() -> None:
    with pytest.raises(MilpaError) as exc_info:
        _parse_trust_policy("enable")
    assert exc_info.value.slug == MAN_UNKNOWN_TOP_LEVEL


def test_parse_trust_policy_rejects_empty_string() -> None:
    with pytest.raises(MilpaError) as exc_info:
        _parse_trust_policy("")
    assert exc_info.value.slug == MAN_UNKNOWN_TOP_LEVEL


def test_parse_trust_policy_node_name_in_error() -> None:
    """The node name is included in the error for diagnostics."""
    with pytest.raises(MilpaError) as exc_info:
        _parse_trust_policy("permissive", node="index-trust")
    assert "index-trust" in str(exc_info.value)


# ---------------------------------------------------------------------------
# effective_trust_policy — TrustPolicy return values
# ---------------------------------------------------------------------------


def test_effective_trust_policy_no_manifest_no_flag_returns_warn() -> None:
    result = effective_trust_policy(None, False)
    assert result == "warn"


def test_effective_trust_policy_warn_manifest_no_flag_returns_warn() -> None:
    result = effective_trust_policy("warn", False)
    assert result == "warn"


def test_effective_trust_policy_strict_manifest_returns_strict() -> None:
    result = effective_trust_policy("strict", False)
    assert result == "strict"


def test_effective_trust_policy_flag_escalates_to_strict() -> None:
    """Flag escalates warn → strict (OR semantics)."""
    result = effective_trust_policy("warn", True)
    assert result == "strict"


def test_effective_trust_policy_flag_with_none_manifest_returns_strict() -> None:
    result = effective_trust_policy(None, True)
    assert result == "strict"


def test_effective_trust_policy_strict_manifest_flag_false_returns_strict() -> None:
    """Manifest strict without flag still returns strict."""
    result = effective_trust_policy("strict", True)
    assert result == "strict"


def test_effective_trust_policy_returns_trust_policy_value() -> None:
    """Return value is always one of the TrustPolicy literals."""
    for manifest_val in [None, "warn", "strict"]:
        for flag in [False, True]:
            result = effective_trust_policy(manifest_val, flag)  # type: ignore[arg-type]
            assert result in ("warn", "strict", "off"), (
                f"expected TrustPolicy literal, got {result!r} "
                f"(manifest={manifest_val!r}, flag={flag})"
            )


def test_effective_trust_policy_env_override_param_accepted() -> None:
    """env_override is now evaluated (S5 full §6.6 formula).

    S5 update: env_override='strict' CAN strengthen a manifest-warn.
    This test was 'S1: not evaluated → returns warn'; now the correct
    S5 behaviour is 'env=strict strengthens warn → strict'.
    """
    result = effective_trust_policy("warn", False, env_override="strict")
    # S5: env=strict CAN strengthen manifest=warn.
    assert result == "strict"


# ---------------------------------------------------------------------------
# effective_trust_policy — S5 authority model (§6.6)
# ---------------------------------------------------------------------------


def test_effective_trust_policy_off_manifest_returns_off() -> None:
    """manifest=off always returns off — project-only auditable opt-out."""
    result = effective_trust_policy("off", False)
    assert result == "off"


def test_effective_trust_policy_off_manifest_flag_still_off() -> None:
    """Flag CANNOT escalate manifest=off to strict (off is auditable opt-out)."""
    result = effective_trust_policy("off", True)
    assert result == "off"


def test_effective_trust_policy_off_manifest_env_strict_still_off() -> None:
    """env=strict CANNOT override manifest=off (project-only opt-out, RFC §6.6)."""
    result = effective_trust_policy("off", False, env_override="strict")
    assert result == "off"


def test_effective_trust_policy_off_manifest_all_sources_still_off() -> None:
    """All three sources cannot override manifest=off."""
    result = effective_trust_policy("off", True, env_override="strict")
    assert result == "off"


def test_effective_trust_policy_env_off_cannot_weaken_manifest_warn() -> None:
    """env=off is a no-op floor — cannot weaken manifest=warn (RFC §6.6)."""
    result = effective_trust_policy("warn", False, env_override="off")
    # env=off cannot weaken manifest=warn; result stays warn.
    assert result == "warn"


def test_effective_trust_policy_env_off_cannot_weaken_manifest_strict() -> None:
    """env=off is a no-op floor — cannot weaken manifest=strict (RFC §6.6)."""
    result = effective_trust_policy("strict", False, env_override="off")
    # env=off cannot weaken manifest=strict; result stays strict.
    assert result == "strict"


def test_effective_trust_policy_env_warn_is_noop_on_manifest_warn() -> None:
    """env=warn cannot weaken; manifest=warn stays warn."""
    result = effective_trust_policy("warn", False, env_override="warn")
    assert result == "warn"


def test_effective_trust_policy_env_strict_strengthens_warn() -> None:
    """env=strict CAN strengthen manifest=warn to strict (RFC §6.6)."""
    result = effective_trust_policy("warn", False, env_override="strict")
    assert result == "strict"


def test_effective_trust_policy_env_strict_and_flag_both_strict() -> None:
    """env=strict + flag → strict (redundant but consistent)."""
    result = effective_trust_policy("warn", True, env_override="strict")
    assert result == "strict"


def test_effective_trust_policy_none_manifest_env_strict() -> None:
    """None manifest + env=strict → strict."""
    result = effective_trust_policy(None, False, env_override="strict")
    assert result == "strict"


def test_effective_trust_policy_none_manifest_env_off() -> None:
    """None manifest (defaults to warn) + env=off → warn (env=off is no-op)."""
    result = effective_trust_policy(None, False, env_override="off")
    assert result == "warn"


def test_effective_trust_policy_all_off() -> None:
    """off + no-flag + env=None → off."""
    result = effective_trust_policy("off", False, env_override=None)
    assert result == "off"
