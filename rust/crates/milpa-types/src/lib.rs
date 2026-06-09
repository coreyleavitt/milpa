//! `milpa-types` — the zero-logic shared vocabulary (RFC §4.1).
//!
//! Data only: every other crate imports these so they share one data model
//! without importing each other. Logic lives elsewhere by design —
//! `parse_version` / `VersionSet` algebra in `milpa-solver`, the identity
//! algorithm / fetch / resolve in `milpa-core`. The crate boundary turns the
//! "single source of truth per concern" convention into a compile-time
//! guarantee.
//!
//! S1 (scaffold): these are type skeletons. Fields and methods are filled in
//! by their owning slices; nothing here carries algorithm logic.

/// A package version.
///
/// Raw newtype (RFC §4.1 type-placement table): the *parse* and the comparison
/// algebra live in `milpa-solver` (`parse_version`, `VersionSet`). Holding the
/// canonical numeric components plus the original text keeps ordering derivable
/// as data (lexicographic over `components`) while preserving the source form
/// for byte-exact emission. Real construction/validation arrives in S6.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Canonical numeric release components, most-significant first.
    pub components: Vec<u64>,
    /// The version exactly as written (for byte-exact lockfile emission).
    pub raw: String,
}

/// Where a resolved dep's bytes come from. A **closed enum** (RFC §4.6): the
/// spec fixes exactly four transport kinds, so dispatch is an exhaustive
/// `match` and a new transport is an auditable variant, not an injectable
/// trait object. Provenance is mutable/trust-dependent metadata — orthogonal
/// to identity (the content hash), which lives on `ResolvedDep`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    Git {
        url: String,
        ref_spec: String,
        commit_sha: Option<String>,
    },
    Tarball {
        url: String,
        expected_sha256: Option<String>,
        strip_components: u32,
    },
    Local {
        path: String,
    },
    Oci {
        registry: String,
        repository: String,
        digest: String,
    },
}

impl Provenance {
    /// Whether this dep may be admitted into the content-addressed store.
    /// `Local` is never CAS-admissible, so `milpa fetch` on a workspace member
    /// (local path) does not freeze the user's in-progress edits (RFC §4.6).
    pub fn cas_admissible(&self) -> bool {
        !matches!(self, Provenance::Local { .. })
    }
}

/// One dep after resolution: identity (content hash) ⊥ provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDep {
    pub name: String,
    /// Content hash, e.g. `sha256:…` — immutable, recomputable from bytes.
    pub identity: String,
    pub version: Version,
    pub src_dir: String,
    pub requires: Vec<String>,
    pub provenance: Provenance,
}

/// The resolved dependency graph — the resolver's output, the emitters' input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedGraph {
    pub deps: Vec<ResolvedDep>,
}

/// One recorded provenance in a lockfile entry (lockfile-schema §4).
///
/// **Distinct from the transport [`Provenance`] enum**, deliberately. `Provenance`
/// models the four *transport* kinds a fetcher dispatches on; `ProvenanceRecord`
/// models what a `milpa.lock` *records about where bytes came from* — six kinds,
/// because it additionally carries workspace-internal `Member` references and the
/// read-compat legacy `Registry` kind (milpa#97), neither of which is a transport.
/// They are different sets by design, so they are different types (mirrors the
/// Python `ProvenanceRecord` union in `lockfile.py`). Optional fields are `None`
/// when omitted from the KDL — never an empty string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceRecord {
    Git {
        url: String,
        ref_spec: Option<String>,
        commit_sha: Option<String>,
    },
    Tarball {
        url: String,
        /// Archive sha256 (transport receipt, NOT identity); `None` pre-TOFU.
        sha256: Option<String>,
    },
    Local {
        /// As-declared relative path from the project root (never absolutized).
        path: String,
    },
    Member {
        name: String,
    },
    Oci {
        registry: String,
        repository: String,
        digest: String,
    },
    /// Read-compat only (milpa#97): the writer never emits this; the parser
    /// still accepts it so pre-#97 lockfiles round-trip.
    Registry {
        name: String,
        tag: Option<String>,
        commit_sha: Option<String>,
    },
}

/// A single dep entry in a `milpa.lock` (lockfile-schema §3).
///
/// Structurally distinct from [`ResolvedDep`]: the lockfile records `identity`
/// as **optional** (Phase A partial — a dep not yet content-hashed stores
/// `None`), carries `ProvenanceRecord`s (the metadata model) rather than a
/// transport `Provenance`, and adds `active_flags` / `self_mirrors`. Mirrors the
/// Python `LockedDep`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedDep {
    pub name: String,
    pub identity: Option<String>,
    pub version: String,
    pub src_dir: String,
    pub requires: Vec<String>,
    pub provenances: Vec<ProvenanceRecord>,
    pub active_flags: Vec<String>,
    pub self_mirrors: Vec<String>,
}

/// The parsed `milpa.lock` as data (parse/emit logic lives in `milpa-core`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    /// Lockfile schema epoch (`LOCKFILE_SCHEMA_VERSION`, currently `1`); a
    /// distinct namespace from the manifest `spec-version` (lockfile-schema §2.1).
    pub version: u32,
    pub strategy: String,
    pub deps: Vec<LockedDep>,
}

impl Default for Lockfile {
    /// An empty `maxver` lockfile at the current schema version. (A bare
    /// `version: 0` default would be a non-existent schema epoch, so `Default`
    /// is written by hand rather than derived.)
    fn default() -> Self {
        Lockfile {
            version: LOCKFILE_SCHEMA_VERSION,
            strategy: "maxver".to_string(),
            deps: Vec::new(),
        }
    }
}

/// The current `milpa.lock` schema epoch (lockfile-schema §2.1). A v2 schema is
/// a spec amendment, independent of the manifest `spec-version` epoch.
pub const LOCKFILE_SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_local_is_not_cas_admissible() {
        let local = Provenance::Local {
            path: "../member-a".into(),
        };
        assert!(!local.cas_admissible());

        let git = Provenance::Git {
            url: "https://example.com/X.git".into(),
            ref_spec: "v2.0.0".into(),
            commit_sha: None,
        };
        assert!(git.cas_admissible());
    }

    #[test]
    fn version_orders_by_components() {
        let v1 = Version {
            components: vec![1, 0, 0],
            raw: "1.0.0".into(),
        };
        let v2 = Version {
            components: vec![2, 0, 0],
            raw: "2.0.0".into(),
        };
        assert!(v1 < v2);
    }
}
