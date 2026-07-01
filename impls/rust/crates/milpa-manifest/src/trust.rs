//! `TrustPolicy` — single source of truth for attestation-policy and
//! index-trust policy values.  Both manifest fields parse to this type
//! via [`parse_trust_policy`].
//!
//! S1 (RFC rfc-registry-trust-federation.md): unified type replacing the old
//! `AttestationPolicy { Permissive, Strict }` pair.  The `permissive` user-
//! facing value is renamed to `warn` (pre-v1 breaking cutover; no legacy alias).
//! `Off` is added as a new value: an auditable opt-out that can only be declared
//! in the manifest (env/flag cannot set or clear it).

/// Unified trust policy governing both the dep-metadata attestation axis
/// (`attestation-policy`) and the future whole-index trust axis (`index-trust`).
///
/// Ordering for "strength": `Strict > Warn > Off` (see effective-policy formula
/// in RFC §6.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Verification runs; failures emit a warning but the resolve proceeds.
    /// This is the default value (equivalent to the old `permissive` value,
    /// which has been renamed here for clarity).
    #[default]
    Warn,
    /// Verification failure is a hard error; resolve is rejected.
    Strict,
    /// Verification is skipped entirely.  Can only be declared in `milpa.kdl`
    /// (auditable in version control); env and CLI flag cannot set or clear it.
    Off,
}

/// Parse a trust-policy string from a KDL manifest field.
///
/// Accepts `"warn"` | `"strict"` | `"off"`.  Rejects the legacy `"permissive"`
/// value — that is a pre-v1 breaking rename; no alias is provided.
///
/// `field` is the manifest field name used in error messages (e.g.
/// `"attestation-policy"`).
pub fn parse_trust_policy(val: &str, field: &str) -> Result<TrustPolicy, String> {
    match val {
        "warn" => Ok(TrustPolicy::Warn),
        "strict" => Ok(TrustPolicy::Strict),
        "off" => Ok(TrustPolicy::Off),
        other => Err(format!(
            "'{field}' must be 'warn', 'strict', or 'off', got {other:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_warn() {
        assert_eq!(parse_trust_policy("warn", "attestation-policy").unwrap(), TrustPolicy::Warn);
    }

    #[test]
    fn parse_strict() {
        assert_eq!(parse_trust_policy("strict", "attestation-policy").unwrap(), TrustPolicy::Strict);
    }

    #[test]
    fn parse_off() {
        assert_eq!(parse_trust_policy("off", "attestation-policy").unwrap(), TrustPolicy::Off);
    }

    #[test]
    fn reject_permissive() {
        // Legacy value: clean pre-v1 cutover, no compat alias.
        let err = parse_trust_policy("permissive", "attestation-policy").unwrap_err();
        assert!(err.contains("permissive"), "error should name the bad value: {err}");
        assert!(err.contains("attestation-policy"), "error should name the field: {err}");
    }

    #[test]
    fn reject_unknown() {
        let err = parse_trust_policy("bogus", "index-trust").unwrap_err();
        assert!(err.contains("bogus"));
        assert!(err.contains("index-trust"));
    }

    #[test]
    fn default_is_warn() {
        assert_eq!(TrustPolicy::default(), TrustPolicy::Warn);
    }
}
