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
//!
//! S6 note: [`Version`] is the one type here that owns hand-written `Ord` / `Eq`
//! / `Hash`. That is not "algorithm logic" in the sense the zero-logic rule
//! forbids — a value type's *total order and equality are part of its data-model
//! definition* (semver 2.0 §11), and Rust's orphan rule requires those `impl`s
//! to live in the crate that defines the type. The *resolution* algebra
//! (`parse_version`, `VersionSet`, the solver) still lives in `milpa-solver`.

use std::cmp::Ordering;
use std::fmt;

/// One identifier in a semver pre-release tag (semver 2.0 §9).
///
/// Numeric identifiers compare numerically and always have *lower* precedence
/// than alphanumeric ones (§11.4.3) — so the variant order here (`Numeric`
/// before `Alpha`) makes the derived `Ord` exactly the semver rule, and
/// `Vec<PreId>` comparison is the field-by-field, shorter-is-lower rule of
/// §11.4.4 for free.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PreId {
    Numeric(u64),
    Alpha(String),
}

/// A package version with the semver-2.0 total order (mirrors the Python
/// `solver.Version`).
///
/// Carries `major`/`minor`/`patch`, a `pre` tag (empty ⇒ a release), and
/// `build` metadata. Build metadata is preserved for round-trip emission but
/// **ignored for ordering, equality, and hashing** (semver 2.0 §10) — which is
/// why `Eq`/`Ord`/`Hash` are hand-written over [`Version::precedence_key`]
/// rather than derived. The *parser* (`parse_version`) and the comparison
/// *algebra* (`VersionSet`) live in `milpa-solver`; this type only knows how to
/// order itself.
#[derive(Debug, Clone)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Pre-release identifiers; empty for a normal release.
    pub pre: Vec<PreId>,
    /// Build metadata; empty when absent. Ignored for ord/eq/hash.
    pub build: String,
}

impl Version {
    /// A release version (no pre-release tag, no build metadata).
    pub fn release(major: u64, minor: u64, patch: u64) -> Self {
        Version {
            major,
            minor,
            patch,
            pre: Vec::new(),
            build: String::new(),
        }
    }

    /// The semver precedence key (build metadata excluded). `is_release` sorts a
    /// release *above* any pre-release of the same `M.m.p` (§11.3): releases get
    /// `1`, pre-releases `0`, and a larger value wins.
    fn precedence_key(&self) -> (u64, u64, u64, u8, &[PreId]) {
        let is_release = u8::from(self.pre.is_empty());
        (self.major, self.minor, self.patch, is_release, &self.pre)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.precedence_key() == other.precedence_key()
    }
}

impl Eq for Version {}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.precedence_key().hash(state);
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.precedence_key().cmp(&other.precedence_key())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The canonical semver string `major.minor.patch[-pre][+build]`. This is the
/// single source of truth for rendering a [`Version`] — `milpa-solver`'s
/// `format_version_str` delegates here, and the `pubgrub` traits (which bound
/// `V: Display`) consume it. Like `Ord`/`Eq`, a value type's string form is part
/// of its data-model definition and the orphan rule keeps the impl in this crate.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            f.write_str("-")?;
            for (i, id) in self.pre.iter().enumerate() {
                if i > 0 {
                    f.write_str(".")?;
                }
                match id {
                    PreId::Numeric(n) => write!(f, "{n}")?,
                    PreId::Alpha(a) => f.write_str(a)?,
                }
            }
        }
        if !self.build.is_empty() {
            write!(f, "+{}", self.build)?;
        }
        Ok(())
    }
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
///
/// `provenance` is the emission-level [`ProvenanceRecord`] (6 kinds), **not** the
/// 4-kind transport [`Provenance`]: a resolved dep is post-fetch, so what matters
/// downstream (lockfile emission, frozen rebuild) is *what to record about where
/// the bytes came from* — including the non-transport `Member` (workspace) and
/// `Registry` (legacy) kinds a workspace resolve / lockfile read produce. The
/// resolver maps its internal transport `Provenance` → `ProvenanceRecord` when
/// building the graph; `from_graph` is then a near-trivial clone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDep {
    pub name: String,
    /// Content hash, e.g. `sha256:…` — immutable, recomputable from bytes.
    pub identity: String,
    pub version: Version,
    pub src_dir: String,
    pub requires: Vec<String>,
    pub provenance: ProvenanceRecord,
    /// S6: dep_decl pin — `sha256:<hex>` hash of the DepDecl artifact used
    /// during resolution (lockfile-schema §3.7).  `None` when the dep was
    /// not resolved via a DepDecl edge source (milpa.kdl or .nimble fallback).
    pub dep_decl: Option<String>,
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
    /// S6: dep_decl pin — `sha256:<hex>` hash of the DepDecl artifact used
    /// during resolution (lockfile-schema §3.7).  `None` when absent (forward-
    /// compat: older lockfile entries without this field are fine).
    pub dep_decl: Option<String>,
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

// ---------------------------------------------------------------------------
// EdgeSet — the single shared dependency-edge type (spec/dep-decl.md §1)
// ---------------------------------------------------------------------------

/// Fidelity tag for an in-memory `EdgeSet` (spec/dep-decl.md §1).
///
/// Identifies which source produced the `EdgeSet` so the resolver and
/// diagnostics layer can distinguish fidelity at runtime.
///
/// > NORMATIVE: this field is **in-memory only**. It MUST NOT appear in any
/// > serialized artifact (lockfile, DepDecl, index).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeSource {
    /// Parsed from a DepDecl artifact (`milpa-core::dep_decl`).
    DepDecl,
    /// Parsed from a `milpa.kdl` manifest.
    MilpaKdl,
    /// Produced by the `.nimble` heuristic scanner.
    NimbleFallback,
}

/// A named (registry-resolved) requires entry (spec/dep-decl.md §1 `NamedRequire`).
///
/// `constraint_str` is the raw declaration string, whitespace preserved verbatim
/// (spec §2 Rule 5): `">= 0.5.0"` and `">=0.5.0"` are distinct byte sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedRequire {
    pub name: String,
    /// Raw constraint string as declared; empty string means "any version".
    pub constraint_str: String,
}

/// A URL-based requires entry (spec/dep-decl.md §1 `UrlRequire`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRequire {
    pub url: String,
    pub ref_: String,
}

/// One entry in `EdgeSet.requires`: either a named dep or a URL dep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequireEntry {
    Named(NamedRequire),
    Url(UrlRequire),
}

/// Language-neutral in-memory edge type (spec/dep-decl.md §1).
///
/// Single shared type consumed by the resolver regardless of which source
/// supplied the edges. There MUST NOT be a parallel type duplicating this.
///
/// `requires` entries MUST be maintained in authored order — the order in
/// which they appear in the source (spec §1 NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeSet {
    /// Declared dependency edges in authored order.
    pub requires: Vec<RequireEntry>,
    /// Source directory; empty string when unset.
    pub src_dir: String,
    /// Fidelity tag — in-memory only, MUST NOT be serialized.
    pub source: EdgeSource,
}

impl EdgeSet {
    /// Construct a DepDecl-sourced `EdgeSet` (the common consumer-path case).
    pub fn from_dep_decl(requires: Vec<RequireEntry>, src_dir: String) -> Self {
        EdgeSet {
            requires,
            src_dir,
            source: EdgeSource::DepDecl,
        }
    }
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
    fn version_orders_by_release_components() {
        assert!(Version::release(1, 0, 0) < Version::release(2, 0, 0));
        assert!(Version::release(0, 9, 9) < Version::release(1, 0, 0));
        assert_eq!(Version::release(1, 0, 0), Version::release(1, 0, 0));
    }

    #[test]
    fn prerelease_sorts_below_its_release() {
        // semver §11.3: 1.0.0-alpha < 1.0.0
        let alpha = Version {
            pre: vec![PreId::Alpha("alpha".into())],
            ..Version::release(1, 0, 0)
        };
        assert!(alpha < Version::release(1, 0, 0));
    }

    #[test]
    fn build_metadata_ignored_for_eq_and_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let plain = Version::release(1, 2, 3);
        let built = Version {
            build: "20260609".into(),
            ..Version::release(1, 2, 3)
        };
        assert_eq!(plain, built);

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        plain.hash(&mut h1);
        built.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn display_renders_canonical_semver_string() {
        assert_eq!(Version::release(1, 2, 3).to_string(), "1.2.3");
        let full = Version {
            pre: vec![PreId::Alpha("rc".into()), PreId::Numeric(1)],
            build: "build.9".into(),
            ..Version::release(2, 3, 4)
        };
        assert_eq!(full.to_string(), "2.3.4-rc.1+build.9");
    }

    #[test]
    fn numeric_pre_id_sorts_below_alpha() {
        // semver §11.4.3: numeric identifiers < alphanumeric.
        assert!(PreId::Numeric(99) < PreId::Alpha("0".into()));
    }
}
