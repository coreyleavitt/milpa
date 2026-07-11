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

/// Resolver-level dep identity key (S1, rfc-resolver-correctness.md #108/#142).
///
/// `name` is the canonical bare name (always present).
/// `namespace` is `None` in S1; populated by S5 when the manifest grammar
/// supports namespace-qualified `NamedDep` references.
///
/// Used as a map key in `_locked_index` (frozen.rs) and `seen_named`
/// (resolver.rs, S5a). A named struct — not a tuple — gives call-site
/// guardrails and forces Python and Rust to converge on the same shape.
///
/// Spec: `spec/resolver-semantics.md` DepKey fields+ordering clause.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DepKey {
    pub name: String,
    pub namespace: Option<String>,
}

impl DepKey {
    /// Construct a bare-name key (S1: `namespace` is always `None`).
    pub fn bare(name: impl Into<String>) -> Self {
        DepKey { name: name.into(), namespace: None }
    }

    /// Canonical PubGrub solver-variable string for this dep.
    ///
    /// `namespace == None` → bare name (backward-compatible with all pre-S5b
    /// deps; the solver key is unchanged from before S5a).
    /// `namespace == Some("ns")` → `"ns::name"` — a distinct key from the bare
    /// name and from every other namespace, so `(ns1, foo)` and `(ns2, foo)`
    /// become distinct solver variables.
    ///
    /// Agrees with `seen_named` (`BTreeSet<DepKey>`): both uniquely identify
    /// the same dep and neither can collapse two different namespaces to one key.
    pub fn solver_var(&self) -> String {
        match &self.namespace {
            None => self.name.clone(),
            Some(ns) => format!("{}::{}", ns, self.name),
        }
    }

    /// Reconstruct a `DepKey` from a solver-variable string produced by `solver_var()`.
    ///
    /// `"ns::name"` → `DepKey { name: "name", namespace: Some("ns") }`.
    /// `"name"` (no `::`) → `DepKey::bare("name")`.
    ///
    /// This is the SOLE place a `"ns::name"` string is split back to its
    /// components in the Rust impl (M1 SSOT fix, rfc-resolver-correctness.md).
    pub fn from_solver_var(s: &str) -> Self {
        match s.split_once("::") {
            Some((ns, name)) => DepKey { name: name.into(), namespace: Some(ns.into()) },
            None => DepKey::bare(s),
        }
    }
}

/// Canonical `_deps/` directory entry name for a dep (C1, rfc-resolver-correctness.md).
///
/// Bare dep (`namespace=None`): `"<name>"` → `_deps/<name>`.
/// Qualified dep (`namespace="ns"`): `"@<ns>/<name>"` → `_deps/@ns/<name>`.
///
/// The `@<ns>/` prefix (npm-scope form) is:
/// - Windows-safe (no `:` or `*` forbidden characters)
/// - Collision-free with bare names (bare names cannot start with `@`)
/// - Human-readable (analogous to npm `@scope/pkg` convention)
///
/// This is the SSOT for the on-disk path decision. Called from `rebuild_deps_view`,
/// `materialize_named`, `nimcfg::path_for`, `frozen::check_manifest_alignment`,
/// and `lockfile::verify_lockfile_against_deps`.
pub fn dep_dir_name(name: &str, namespace: Option<&str>) -> String {
    match namespace {
        None => name.to_string(),
        Some(ns) => format!("@{}/{}", ns, name),
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
    /// `Local` deps (local-path sources) are never CAS-admissible so that
    /// `milpa fetch` does not freeze the user's in-progress edits (RFC §4.6).
    ///
    /// Workspace members (`ProvenanceRecord::Member` at the lockfile layer) are
    /// handled entirely outside the transport enum and never reach this method;
    /// they are non-CAS-admissible by virtue of not appearing here at all
    /// (see `spec/identity.md §4.1` for the two-axis model).
    pub fn cas_admissible(&self) -> bool {
        !matches!(self, Provenance::Local { .. })
    }
}

/// Durable Rekor transparency-log reference (registry-protocol §3.2).
///
/// Kind-independent — carried on [`EntryAttestation`] and [`LockAttestation`]
/// regardless of `AttestationKind`. Fields default to `""` on parse when a
/// sub-node is absent (robustness — mirrors the Python `_parse_rekor_block`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorRef {
    pub uuid: String,
    pub log_index: String,
    pub integrated_time: String,
}

/// Per-entry Layer 2 attestation kind (registry-protocol §3.2 NORMATIVE —
/// CLOSED set: `"author-signed"` | `"milpa-vendored"` are the only recognized
/// values; anything else collapses to unattested at the parse boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationKind {
    /// `attestation "author-signed"` — `signer` is REQUIRED for this kind.
    AuthorSigned { signer: String },
    /// `attestation "milpa-vendored"` — no per-entry signer field by design.
    /// The effective signer for this kind is derived at *verification* time
    /// (not parse time) from Layer 1's resolved vendor-bot identity (RFC
    /// per-entry-attestation.md §5). The parser never reads or stores a
    /// signer for this kind.
    MilpaVendored,
}

/// Per-entry Layer 2 author-attribution CLAIM (attribution, not integrity),
/// index-side (registry-protocol §3.2). Parsed from the `attestation` /
/// `signed_by` / `rekor` / `bundle` sibling child nodes on one `version` node.
/// Records the CLAIM only — whether it is cryptographically true is a later
/// (P3) question; this type carries zero verification state.
///
/// `bundle_pin` — sha256 hex of the attestation bundle BYTES (the `bundle
/// sha256=` delivery-integrity pin). `None` is the normal, expected state
/// before per-entry bundle delivery ships (P4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAttestation {
    pub kind: AttestationKind,
    pub rekor: Option<RekorRef>,
    pub bundle_pin: Option<String>,
}

/// Per-entry Layer 2 attestation CLAIM, lockfile-side (lockfile-schema §3.9).
///
/// P3a addition (RFC per-entry-attestation.md §7): `bundle_pin` and
/// `namespace` were added alongside `kind`/`rekor`. `bundle_pin` carries the
/// SAME delivery-integrity hash as `EntryAttestation::bundle_pin` (the
/// `bundle sha256=` node) — recorded so `milpa verify`'s offline
/// re-verification can locate the cached bundle for a locked dep with no
/// index available. `namespace` is the entry's REAL index namespace
/// (`registry::IndexVersion::namespace`), distinct from `LockedDep::namespace`
/// (manifest-qualification only) — mandatory whenever the attestation block
/// itself is present (mirrors `kind`), defaulting to `""` on pre-P3a
/// lockfiles (forward-compat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockAttestation {
    pub kind: AttestationKind,
    pub rekor: Option<RekorRef>,
    pub bundle_pin: Option<String>,
    pub namespace: String,
}

/// One dep after resolution: identity (content hash) ⊥ provenances.
///
/// `provenances` is a `Vec` of emission-level [`ProvenanceRecord`]s (6 kinds each),
/// **not** the 4-kind transport [`Provenance`]. D-lifecycle: there is now at least
/// one "observed" record (the fetched+verified candidate) plus zero or more "declared"
/// records (manifest mirrors + prior declared mirrors, deduped vs observed). The
/// resolver maps its internal transport `Provenance` → `ProvenanceRecord`s when
/// building the graph; `from_graph` is then a near-trivial clone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDep {
    /// Bare dep name (no `::` separator). For qualified deps, the namespace is in
    /// `namespace`. The pair `(name, namespace)` uniquely identifies a dep.
    pub name: String,
    /// C1 (rfc-resolver-correctness.md): namespace for qualified named deps.
    /// `None` for all bare-name and URL/local/tarball/member deps.
    /// Serialized as a KDL child node `namespace "<ns>"` in the lockfile (§3.9).
    pub namespace: Option<String>,
    /// Content hash, e.g. `sha256:…` — immutable, recomputable from bytes.
    pub identity: String,
    pub version: Version,
    pub src_dir: String,
    pub requires: Vec<String>,
    /// D-lifecycle: one observed provenance + zero or more declared mirror provenances.
    /// Empty only for the synthetic root (excluded from the graph before emission).
    pub provenances: Vec<ProvenanceRecord>,
    /// S6: dep_decl pin — `sha256:<hex>` hash of the DepDecl artifact used
    /// during resolution (lockfile-schema §3.7).  `None` when the dep was
    /// not resolved via a DepDecl edge source (milpa.kdl or .nimble fallback).
    pub dep_decl: Option<String>,
    /// S4: conditional require annotations propagated from `EdgeSetTerms.requires_predicates`
    /// (RFC cond-requires §3.4.3). Sorted by name.
    pub cond_requires: Vec<CondRequire>,
    /// Phase B: alternate dep names when one content-identity is reached via
    /// multiple manifest names (dedup). Lexicographically sorted. Empty for
    /// non-deduped deps. The canonical name is the BFS-insertion-order earliest.
    /// Populated by the resolver's `finalize()` dedup pass; carried through
    /// `from_graph` → `LockedDep.aliases` → lockfile emission.
    pub aliases: Vec<String>,
    /// S5 (RFC #23 §4): unified per-dep active flag set, lexicographically sorted.
    /// Authoritative: populated from the converged `dep_active_flags` map after
    /// the S4a fixpoint; carried through `build_graph` → lockfile emission.
    /// Empty when no flags are declared or none are active.
    pub active_flags: Vec<String>,
    /// RFC per-entry-attestation.md P2: the index's `EntryAttestation` CLAIM,
    /// carried through unconditionally from `IndexVersion.attestation` for
    /// registry-named deps. `None` for URL/tarball/local/member deps (no
    /// index entry) and for named deps whose index entry carried no
    /// attestation (or one that collapsed — registry-protocol §3.2).
    /// Converted to `LockAttestation` at the `locked_from_resolved` boundary
    /// — P3a: `bundle_pin` is carried through unconditionally (NOT dropped;
    /// see `test_locked_from_resolved_carries_bundle_pin_and_namespace` in
    /// `lockfile.rs`), so `milpa verify`'s offline re-verification can
    /// locate the cached bundle for a locked dep with no index available.
    pub attestation: Option<EntryAttestation>,
    /// P3a addition (RFC per-entry-attestation.md §3): the entry's REAL index
    /// namespace (`registry::IndexVersion::namespace`), populated only for
    /// registry-resolved candidates. `None` for URL/tarball/local/member deps
    /// and for the synthetic root. Distinct from `namespace` above (manifest-
    /// qualification only) — a bare (unqualified) named dep still resolves
    /// through a real namespaced index entry. Folded into
    /// `LockAttestation::namespace` at the `locked_from_resolved` boundary;
    /// not otherwise emitted.
    pub registry_namespace: Option<String>,
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
/// models what a `milpa.lock` *records about where bytes came from* — five kinds,
/// because it additionally carries workspace-internal `Member` references,
/// which is not a transport.
/// They are different sets by design, so they are different types (mirrors the
/// Python `ProvenanceRecord` union in `lockfile.py`). Optional fields are `None`
/// when omitted from the KDL — never an empty string.
///
/// `origin`: `"observed"` (milpa fetched+verified these bytes) or `"declared"`
/// (author-claimed mirror, unverified until first use). Per-lockfile annotation —
/// never a CAS-entry property. Required (S3 strict). D-provenance (lockfile-schema §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceRecord {
    Git {
        url: String,
        ref_spec: Option<String>,
        commit_sha: Option<String>,
        /// "observed" or "declared".
        origin: String,
        /// H5: submodule path → 40-hex gitlink SHA, path-sorted.
        /// Empty for deps with no submodules.
        submodule_shas: Vec<(String, String)>,
    },
    Tarball {
        url: String,
        /// Archive sha256 (transport receipt, NOT identity); `None` pre-TOFU.
        sha256: Option<String>,
        /// "observed" or "declared".
        origin: String,
    },
    Local {
        /// As-declared relative path from the project root (never absolutized).
        path: String,
        /// "observed" or "declared".
        origin: String,
    },
    Member {
        name: String,
        /// "observed" or "declared".
        origin: String,
    },
    Oci {
        registry: String,
        repository: String,
        digest: String,
        /// "observed" or "declared".
        origin: String,
    },
}

impl ProvenanceRecord {
    /// Return the `origin` field for this record ("observed" or "declared").
    pub fn origin(&self) -> &str {
        match self {
            ProvenanceRecord::Git { origin, .. } => origin,
            ProvenanceRecord::Tarball { origin, .. } => origin,
            ProvenanceRecord::Local { origin, .. } => origin,
            ProvenanceRecord::Member { origin, .. } => origin,
            ProvenanceRecord::Oci { origin, .. } => origin,
        }
    }

    /// Return the kind discriminator string for this record.
    pub fn kind(&self) -> &str {
        match self {
            ProvenanceRecord::Git { .. } => "git",
            ProvenanceRecord::Tarball { .. } => "tarball",
            ProvenanceRecord::Local { .. } => "local",
            ProvenanceRecord::Member { .. } => "member",
            ProvenanceRecord::Oci { .. } => "oci",
        }
    }
}

/// One conditional-require annotation on a locked dep (S4 — RFC
/// `rfc-conditional-requires.md` §3.4.1 / §3.4.2).
///
/// `name` is the require name (MUST also appear in `LockedDep.requires`).
/// `predicates` is the non-empty ordered `Vec` of `Predicate` clauses (AND).
/// Stored sorted by name across all `cond_requires` on a dep (lexicographic).
///
/// Never consulted by `frozen` / `verify` / `nimcfg` — they read `requires` only.
/// Present so `#110` can read the annotation for build-time activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondRequire {
    pub name: String,
    pub predicates: Vec<Predicate>,
}

/// A single dep entry in a `milpa.lock` (lockfile-schema §3).
///
/// Structurally distinct from [`ResolvedDep`]: the lockfile records `identity`
/// as **optional** (Phase A partial — a dep not yet content-hashed stores
/// `None`), carries `ProvenanceRecord`s (the metadata model). Mirrors the
/// Python `LockedDep`. D-provenance: `self_mirrors` removed; declared mirrors
/// are stored as `ProvenanceRecord` with `origin="declared"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedDep {
    /// Bare dep name (no `::` separator). The namespace is in `namespace`.
    pub name: String,
    /// C1 (rfc-resolver-correctness.md): namespace for qualified named deps.
    /// `None` for all bare-name and non-named deps. Parsed from the optional
    /// `namespace "<ns>"` child node in the lockfile dep block (§3.9).
    pub namespace: Option<String>,
    pub identity: Option<String>,
    pub version: String,
    pub src_dir: String,
    pub requires: Vec<String>,
    pub provenances: Vec<ProvenanceRecord>,
    pub active_flags: Vec<String>,
    /// S6: dep_decl pin — `sha256:<hex>` hash of the DepDecl artifact used
    /// during resolution (lockfile-schema §3.7).  `None` when absent (forward-
    /// compat: older lockfile entries without this field are fine).
    pub dep_decl: Option<String>,
    /// S4: additive cond-require annotations (RFC cond-requires §3.4.1).
    /// Sorted by name. Never consulted by frozen/verify/nimcfg.
    pub cond_requires: Vec<CondRequire>,
    /// Phase B: alternate dep names when one content-identity is reached via
    /// multiple manifest names (dedup). Lexicographically sorted. Omitted from
    /// KDL entirely when empty. See lockfile-schema §3.8.
    pub aliases: Vec<String>,
    /// RFC per-entry-attestation.md P2 (lockfile-schema §3.9): the per-entry
    /// attestation CLAIM, narrowed from `ResolvedDep.attestation` — P3a:
    /// `bundle_pin` and `namespace` are carried through unconditionally (NOT
    /// dropped; see `locked_from_resolved` in `lockfile.rs`), the same two
    /// fields `LockAttestation`'s own doc comment above describes. `None`
    /// for non-named deps and for named deps with no (or a collapsed) index
    /// attestation record.
    pub attestation: Option<LockAttestation>,
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
// Predicate — one conditional clause (grammar §6; dep-decl.md S2)
// ---------------------------------------------------------------------------

/// One conditional clause on a dep (grammar §6). `negated` applies De Morgan
/// across `values`: `negated=false` is satisfied if the profile matches ANY
/// value (OR); `negated=true` if it matches NONE.
///
/// Extracted here (milpa-types) so `dep_decl.py`-analog types (`NamedRequire` /
/// `UrlRequire`) can carry predicates without a circular crate dependency.
/// `milpa-manifest` re-exports this as `pub use milpa_types::Predicate` for
/// back-compat (all existing `milpa_manifest::Predicate` references compile
/// unchanged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    pub name: String,
    pub values: Vec<String>,
    pub negated: bool,
}

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
///
/// `predicates` carries optional `when`-gate annotations (S2 — RFC
/// `rfc-conditional-requires.md` §3.3). Defaults to an empty `Vec` (back-compat:
/// unconditional requires are unaffected). Nothing populates it until S3b.
///
/// `namespace` carries the registry namespace from `namespace="..."` or slash-shorthand
/// desugaring (H2 fix, rfc-resolver-correctness.md). `None` for bare-name deps and
/// nimble-sourced deps (which have no namespace concept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedRequire {
    pub name: String,
    /// Raw constraint string as declared; empty string means "any version".
    pub constraint_str: String,
    /// Optional `when`-gate predicates (S2; empty = unconditional).
    pub predicates: Vec<Predicate>,
    /// H2: namespace qualifier, carried from manifest NamedDep through EdgeSet to
    /// the resolver so transitive qualified deps preserve their namespace end-to-end.
    /// `None` for bare-name deps and nimble-sourced requires.
    pub namespace: Option<String>,
}

/// S4b (RFC #23 §3.1.3): a consumer-side flag request carried in a dep
/// declaration (grammar §3.6).  Lives here (milpa-types) so both
/// `milpa-manifest` (parse output) and `milpa-types` (EdgeSet/UrlRequire)
/// share one definition without a circular crate dependency.
/// `milpa-manifest` re-exports this as `pub use milpa_types::FlagRequest`
/// for back-compat — all `milpa_manifest::FlagRequest` references compile
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagRequest {
    pub name: String,
    pub enabled: bool,
}

/// A URL-based requires entry (spec/dep-decl.md §1 `UrlRequire`).
///
/// `predicates` carries optional `when`-gate annotations (S2 — RFC
/// `rfc-conditional-requires.md` §3.3). Defaults to an empty `Vec` (back-compat).
///
/// `flag_requests` carries S4b consumer-side flag requests (RFC #23 §3.1.3).
/// Non-empty only when the dep declaration in a transitive milpa.kdl uses
/// `flag "..."` children — so the resolver can propagate them to
/// `process_url` for union semantics.  Empty for all non-flag-parameterised
/// transitive deps and for all DepDecl / Nimble / edge_source paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRequire {
    pub url: String,
    pub ref_: String,
    /// Optional `when`-gate predicates (S2; empty = unconditional).
    pub predicates: Vec<Predicate>,
    /// S4b: consumer-side flag requests (RFC #23 §3.1.3); empty by default.
    pub flag_requests: Vec<FlagRequest>,
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

// ---------------------------------------------------------------------------
// ActivationSource — S3 RFC #23 (cross-package flag-request activation)
// ---------------------------------------------------------------------------

/// Why a flag is active on a dep after S3 activation.
///
/// Mirrors `resolver.py:ActivationSource` — identical variants required for
/// cross-impl byte-identity. Names are normative (RFC #23 §3.1.2).
///
/// `DEFAULT`       — flag is `default=#true` in the dep's own `flags` block.
/// `EDGE_REQUEST`  — consumer dep-declaration requested this flag
///                   (positive `flag "x"` in the dep's deps block).
/// `ENABLES_RULE`  — flag was activated transitively by same-package `enables`
///                   closure (S2 monotone closure, single-package scope).
/// `CLI`           — flag was activated by the CLI `--features` / `--all-features`
///                   selection on the root manifest (S9, RFC #23 §3.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActivationSource {
    Default,
    EdgeRequest,
    EnablesRule,
    Cli,
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

    // -----------------------------------------------------------------------
    // S2 — RequireEntry.predicates (RFC rfc-conditional-requires.md §3.3)
    // -----------------------------------------------------------------------

    /// A `NamedRequire` with a non-empty `predicates` vec must NOT equal one
    /// with an empty vec (field participates in derived `PartialEq`).
    #[test]
    fn named_require_predicate_field_participates_in_equality() {
        let plain = NamedRequire {
            name: "foo".into(),
            constraint_str: "".into(),
            predicates: Vec::new(),
            namespace: None,
        };
        let predicated = NamedRequire {
            name: "foo".into(),
            constraint_str: "".into(),
            predicates: vec![Predicate {
                name: "platform".into(),
                values: vec!["linux".into()],
                negated: false,
            }],
            namespace: None,
        };
        assert_ne!(plain, predicated);
    }

    /// A `UrlRequire` with a non-empty `predicates` vec must NOT equal one
    /// with an empty vec.
    #[test]
    fn url_require_predicate_field_participates_in_equality() {
        let plain = UrlRequire {
            url: "https://example.com/foo.git".into(),
            ref_: "main".into(),
            predicates: Vec::new(),
            flag_requests: Vec::new(),
        };
        let predicated = UrlRequire {
            url: "https://example.com/foo.git".into(),
            ref_: "main".into(),
            predicates: vec![Predicate {
                name: "arch".into(),
                values: vec!["amd64".into()],
                negated: false,
            }],
            flag_requests: Vec::new(),
        };
        assert_ne!(plain, predicated);
    }

    // -----------------------------------------------------------------------
    // S5a — DepKey.solver_var() (rfc-resolver-correctness.md)
    // -----------------------------------------------------------------------

    #[test]
    fn dep_key_solver_var_bare_name_is_identity() {
        // namespace=None → solver_var() == bare name (backward compat)
        let k = DepKey { name: "chronos".into(), namespace: None };
        assert_eq!(k.solver_var(), "chronos");
    }

    #[test]
    fn dep_key_solver_var_with_namespace() {
        // namespace="core" → solver_var() == "core::chronos"
        let k = DepKey { name: "chronos".into(), namespace: Some("core".into()) };
        assert_eq!(k.solver_var(), "core::chronos");
    }

    #[test]
    fn dep_key_solver_var_two_namespaces_are_distinct() {
        // (ns1, foo) and (ns2, foo) produce DISTINCT solver vars
        let k1 = DepKey { name: "foo".into(), namespace: Some("ns1".into()) };
        let k2 = DepKey { name: "foo".into(), namespace: Some("ns2".into()) };
        assert_ne!(k1.solver_var(), k2.solver_var());
    }

    #[test]
    fn dep_key_seen_named_set_distinguishes_namespaces() {
        // After S5a: BTreeSet<DepKey> correctly keeps two same-bare-name/
        // different-namespace DepKeys as distinct (no collapse).
        use std::collections::BTreeSet;

        let k_ns1 = DepKey { name: "foo".into(), namespace: Some("ns1".into()) };
        let k_ns2 = DepKey { name: "foo".into(), namespace: Some("ns2".into()) };
        let k_none = DepKey::bare("foo");

        // OLD (BTreeSet<String>): both map to "foo" → collapse (bug)
        let mut old_seen: BTreeSet<String> = BTreeSet::new();
        old_seen.insert(k_ns1.name.clone());
        assert!(old_seen.contains(&k_ns2.name)); // demonstrates the collapse

        // NEW (BTreeSet<DepKey>): distinct keys
        let mut new_seen: BTreeSet<DepKey> = BTreeSet::new();
        new_seen.insert(k_ns1.clone());
        assert!(!new_seen.contains(&k_ns2)); // different namespace → NOT dropped (fix)
        assert!(!new_seen.contains(&k_none)); // None also distinct from "ns1"

        // None-namespace still deduplicates correctly (no regression)
        let mut new_seen2: BTreeSet<DepKey> = BTreeSet::new();
        new_seen2.insert(k_none.clone());
        assert!(new_seen2.contains(&DepKey::bare("foo"))); // same name + None → dedup OK
    }

    // M1 / C1 SSOT: from_solver_var is the SOLE split site for DepKey reconstruction
    // from "::" in Rust.  (lockfile.rs req_name_to_lockfile also splits "::" but
    // only to format requires entries, not to reconstruct a DepKey.)

    #[test]
    fn dep_key_from_solver_var_bare_name() {
        // No "::" → bare key.
        let k = DepKey::from_solver_var("chronos");
        assert_eq!(k.name, "chronos");
        assert_eq!(k.namespace, None);
    }

    #[test]
    fn dep_key_from_solver_var_qualified() {
        // "ns::name" → namespace=Some("ns"), name="name".
        let k = DepKey::from_solver_var("ns1::bar");
        assert_eq!(k.name, "bar");
        assert_eq!(k.namespace, Some("ns1".to_string()));
    }

    #[test]
    fn dep_key_from_solver_var_round_trips() {
        // solver_var() → from_solver_var() round-trip is identity.
        let original = DepKey { name: "baz".into(), namespace: Some("core".into()) };
        let var = original.solver_var();
        let recovered = DepKey::from_solver_var(&var);
        assert_eq!(recovered, original);
    }

    // C1: dep_dir_name SSOT.

    #[test]
    fn dep_dir_name_bare() {
        assert_eq!(dep_dir_name("chronos", None), "chronos");
    }

    #[test]
    fn dep_dir_name_qualified() {
        assert_eq!(dep_dir_name("bar", Some("ns1")), "@ns1/bar");
    }

}
