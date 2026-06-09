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

/// The parsed `milpa.lock` as data (parse/emit logic lives in `milpa-core`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lockfile {
    pub strategy: String,
    pub deps: Vec<ResolvedDep>,
}

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
