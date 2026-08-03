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
        /// registry-protocol §3.3: the OPTIONAL `source` child on an `oci`
        /// index-provenance record — the git repository this artifact was
        /// packed and published from (e.g. what `milpa publish` resolved
        /// from the source repo's `origin` remote at publish time). `None`
        /// for every construction site OTHER than `registry::parse_version_node`
        /// (manifest `oci=` dep declarations and resolved-dep transport
        /// dispatch have no `source` concept — registry-protocol §3.3's
        /// manifest-grammar carve-out) and for registry entries published
        /// before this field existed. Mirrors Python's
        /// `OciIndexProvenance.source_url` — this shared enum conflates the
        /// registry-index-provenance role Python splits into a separate
        /// `OciIndexProvenance` type with the manifest/resolved-dep transport
        /// role `Provenance` otherwise plays; `source_url` only has meaning
        /// in the former.
        source_url: Option<String>,
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

/// A version-independent origin — the solver variable (rfc-origin-as-identity.md
/// §3/§4.1, S1). Origins that are fetched, hashed, and materialized under
/// `_deps/`. Mirrors Python's `FetchableOrigin` union (`source_id.py`).
///
/// A **closed enum** (five kinds; `ref`/commit/digest are VERSIONS, not the
/// origin, and are deliberately excluded from every variant here).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FetchableOrigin {
    /// A `git=` dependency's origin: the normalized repository URL. `url` is
    /// ALWAYS normalized (`source_id::normalize_source`) by every trusted
    /// caller; no `source_id::parse` exists (round-2.5, rfc-origin-as-
    /// identity.md §4.1) — the frozen struct is the authoritative
    /// representation, never reconstructed from a flat string.
    Git {
        url: String,
        /// Normalized posix; `None` = repo root.
        subpath: Option<String>,
    },
    /// An `oci=` dependency's origin: registry + repository, no digest/tag.
    Oci {
        registry: String,
        repository: String,
        subpath: Option<String>,
    },
    /// A `tarball=` dependency's origin. Each distinct URL is a distinct source.
    Tarball {
        url: String,
        subpath: Option<String>,
    },
    /// A `local=` dependency's origin: a filesystem path. Canonicalized by
    /// the caller (workspace-relative when under root, else absolute) —
    /// case-SENSITIVE and case-PRESERVING by definition (RFC §4.1 D6: on a
    /// case-insensitive filesystem, `Deps/Foo` and `deps/foo` are two
    /// distinct origins, a known missed-unification limitation left to
    /// `overrides {}`, not remedied here).
    Local { path: String },
    /// A `named`/registry-coordinate dependency's origin. `registry` is a
    /// CONFIGURED ALIAS slug (`[A-Za-z0-9_-]+`), never a base URL (RFC §4.1
    /// "Registry component is an alias, never a base URL"). `namespace` is
    /// the REAL resolved index namespace, never the manifest qualifier.
    Registry {
        registry: String,
        namespace: Option<String>,
        name: String,
    },
}

/// The full closed union — `FetchableOrigin` plus a workspace member (RFC
/// §4.1 G4: `Member` is split OUT of `FetchableOrigin` deliberately — a
/// member is never fetched, never CAS-hashed, and never carries an
/// attestation subject; conflict-free by construction (W1-W5 name
/// uniqueness). Code that types over `FetchableOrigin` gets "members do not
/// participate in fetch/CAS/attestation" enforced by the type checker, not
/// left as a convention to remember. Mirrors Python's `SourceId` union.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceId {
    Fetchable(FetchableOrigin),
    /// A workspace member's origin.
    Member { member_name: String },
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
    // RFC origin-as-identity §4.4 (B2/G10 field-duplication audit, S5):
    // `registry_namespace` (formerly a field here, mirroring
    // `_Candidate::registry_namespace`) is DELETED — it duplicated
    // `source_id`'s namespace for a `FetchableOrigin::Registry` (the SAME
    // real index namespace, populated by the SAME `resolved_registry_namespace`
    // call at binding time). `LockAttestation::namespace` is now derived from
    // `source_id`'s namespace at the `locked_from_resolved` construction
    // boundary instead of from this field.
    /// A5 (resolution-semantics RFC §3 Axis A (b) / §5): the sibling field to
    /// `version` — WHICH precedence step (`manifest`/`nimble`/`tag`/
    /// `annotation`) produced a git/url/local/tarball/member dep's declared
    /// version. Stored as the plain lockfile-schema string (mirrors
    /// `Lockfile.strategy: String` — `milpa-types` cannot depend on
    /// `milpa-solver`, which owns the `VersionSource` enum, so the value is
    /// converted to its canonical spelling at the `milpa-core` boundary).
    /// `None` for a version-unknown dep (which also always has
    /// `version == 0.0.0` — a combination no `Known` case ever produces, §5
    /// NORMATIVE) and for named/index-resolved deps (out of Axis A's scope).
    pub declared_version_source: Option<String>,
    /// RFC origin-as-identity §4.4 (S3a): the version-independent origin the
    /// binding phase (`binding::BindingResolver`) selected for this dep's
    /// `DepKey` — IN-MEMORY ONLY. Deliberately NOT threaded into the on-disk
    /// lockfile schema yet (that is a later slice's structured `source { … }`
    /// node); `None` for the synthetic root dep and for any dep constructed
    /// outside the live `resolve()`/`resolve_workspace()` path (e.g. frozen
    /// reconstruction, until a later slice populates it there too). Mirrors
    /// Python's `ResolvedDep.source_id`.
    pub source_id: Option<SourceId>,
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
/// because it additionally carries workspace-internal `Member` references and
/// the standalone-root self-reference `Root` (resolver-semantics §14), neither
/// of which is a transport.
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
    /// resolver-semantics §14 "root satisfies its own name": a transitive
    /// reference to the resolving STANDALONE root's own declared `name`,
    /// satisfied by the root itself — never a second, separately-fetched
    /// copy. The non-workspace analog of `Member`; a DISTINCT kind (not a
    /// reuse of `Member`) because `frozen.rs`'s `FROZEN-MEMBER-DEP` guard
    /// hard-rejects a `Member`-kind provenance in a single-package
    /// (non-workspace) lockfile — conflating the two would trip that
    /// invariant. `origin` is always `"observed"` (the root is never a
    /// "declared" mirror source).
    Root {
        name: String,
        /// "observed" or "declared" (always "observed" in practice).
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
            ProvenanceRecord::Root { origin, .. } => origin,
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
            ProvenanceRecord::Root { .. } => "root",
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
    /// A5 (resolution-semantics RFC §3 Axis A (b) / §5): sibling field to
    /// `version` — see `ResolvedDep.declared_version_source` for the full
    /// contract. Always emitted when a source exists; `None` for a
    /// version-unknown dep (`version == "0.0.0"`, no source — the
    /// unambiguous boundary pairing, §5 NORMATIVE) and for named/index deps.
    pub declared_version_source: Option<String>,
    /// RFC origin-as-identity §4.1/§7 (S5): the version-independent origin,
    /// serialized STRUCTURED as a `source { … }` node with typed children
    /// (uv's model) — never a flat parsed string (no `parse()` exists).
    /// `None` only for a lockfile predating S5 (forward-compat) — a
    /// conformant S5+ emitter always writes this for every real dep. The
    /// `FROZEN-SOURCE-ID-MISMATCH` / `FROZEN-REGISTRY-ALIAS-UNRESOLVED`
    /// preconditions (`frozen.rs`, §7.1) read this field.
    pub source_id: Option<SourceId>,
}

/// The parsed `milpa.lock` as data (parse/emit logic lives in `milpa-core`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    /// Lockfile schema epoch (`LOCKFILE_SCHEMA_VERSION`, currently `1`); a
    /// distinct namespace from the manifest `spec-version` (lockfile-schema §2.1).
    pub version: u32,
    pub strategy: String,
    /// D5 (resolution-semantics RFC §3 Axis D / §5): the EFFECTIVE
    /// `exclude_newer` time-bound this lockfile was resolved under, recorded
    /// for diagnostics and the frozen fast-path `FROZEN-EXCLUDE-NEWER-MISMATCH`
    /// check (mirrors `strategy`'s exact role for `FROZEN-STRATEGY-MISMATCH`).
    /// `None` when no bound was in effect — a conformant emitter omits the
    /// top-level `exclude_newer` node entirely in that case (never a sentinel
    /// timestamp), the same "emit only when present" rule `strategy` does NOT
    /// get (strategy is unconditionally required) but `declared_version_source`
    /// and other additive fields do.
    pub exclude_newer: Option<Timestamp>,
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
            exclude_newer: None,
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
    /// The declared dep name when sourced from a `milpa.kdl` (the KDL node
    /// name) — mirrors `milpa/dep_decl.py`'s `UrlRequire.name`. `None` when
    /// sourced from a DepDecl artifact (URL + ref only, no name) or a
    /// `.nimble` file (nimble `requires` lines have no separate node name).
    ///
    /// This is THE fix for the alias-name bug (spec §10.1 override-a-
    /// transitive workflow): a transitive `milpa.kdl` may declare a git
    /// sub-dep under a node name that differs from its URL's tail (e.g.
    /// `"z3" git=(url)"https://…/nim-z3.git"`). The parent's solver term,
    /// the BFS child enqueue, the provenance-gate key, and root-authority/
    /// overrides suppression must all agree on ONE name — the DECLARED name
    /// when present, falling back to the URL-tail derivation only when no
    /// declared name exists. See `edgeset_to_terms` / `resolver.rs`'s
    /// `edgeset_to_extracted`, both of which prefer this field over
    /// `url_tail_name`/`name_from_url`.
    pub name: Option<String>,
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

// ---------------------------------------------------------------------------
// A2a timestamp parsing (registry-protocol §3.2) — no external date crate:
// the ratchet engine (`milpa-core::ratchet`) only needs EQUALITY over this
// type (the set-once dominance check), never arithmetic or formatting, so a
// minimal hand-rolled ISO-8601/RFC-3339 parser normalizing to a UTC instant is
// sufficient and keeps this crate dep-light. Mirrors Python's
// `_parse_timestamp` (`datetime.fromisoformat`): malformed input -> `None`,
// never an error.
//
// D0 (rfc-resolution-semantics.md Axis D prerequisite): moved here from
// `milpa-core::registry` so `milpa-manifest` can reach it too (D1 parses and
// validates a manifest `resolution { exclude-newer }` timestamp at parse
// time) without `milpa-manifest` depending on its own downstream crate
// `milpa-core`, which would be a cargo cycle. Pure move — no behavior change.
// `milpa-core::registry` re-exports both items for back-compat (all existing
// `milpa_core::registry::{Timestamp, parse_iso8601_timestamp}` references
// compile unchanged).
// ---------------------------------------------------------------------------

/// A parsed timestamp, normalized to a UTC instant: seconds since the Unix
/// epoch plus a sub-second nanosecond remainder. `Eq`-able (no floats) so it
/// can ride `IndexVersion`'s derived `PartialEq + Eq`. `Ord` (D3,
/// resolution-semantics RFC §3 Axis D / §6 D-D3) is the derived
/// lexicographic order over `(unix_seconds, nanos)` — exactly chronological
/// order, since both fields are already a normalized UTC instant — used by
/// the exclude-newer `published_at <= ts` comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub unix_seconds: i64,
    pub nanos: u32,
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction][Z|±HH:MM]` (`T` may also be a space
/// or lowercase `t`; an absent offset is treated as UTC). Returns `None` on
/// any malformed input — the caller's absence posture, never a raised error.
pub fn parse_iso8601_timestamp(raw: &str) -> Option<Timestamp> {
    let bytes = raw.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let digit = |i: usize| -> Option<i64> {
        bytes.get(i).filter(|b| b.is_ascii_digit()).map(|b| (*b - b'0') as i64)
    };
    let two = |i: usize| -> Option<i64> { Some(digit(i)? * 10 + digit(i + 1)?) };
    let four = |i: usize| -> Option<i64> {
        Some(digit(i)? * 1000 + digit(i + 1)? * 100 + digit(i + 2)? * 10 + digit(i + 3)?)
    };

    let year = four(0)?;
    if bytes.get(4) != Some(&b'-') {
        return None;
    }
    let month = two(5)?;
    if bytes.get(7) != Some(&b'-') {
        return None;
    }
    let day = two(8)?;
    match bytes.get(10) {
        Some(b'T') | Some(b't') | Some(b' ') => {}
        _ => return None,
    }
    let hour = two(11)?;
    if bytes.get(13) != Some(&b':') {
        return None;
    }
    let minute = two(14)?;
    if bytes.get(16) != Some(&b':') {
        return None;
    }
    let second = two(17)?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=60).contains(&second) {
        return None;
    }

    let mut idx = 19;
    let mut nanos: u32 = 0;
    if matches!(bytes.get(idx), Some(b'.') | Some(b',')) {
        idx += 1;
        let start = idx;
        while bytes.get(idx).is_some_and(u8::is_ascii_digit) {
            idx += 1;
        }
        if idx == start {
            return None; // "." with no digits following
        }
        let frac = &raw[start..idx];
        let mut digits: String = frac.chars().take(9).collect();
        while digits.len() < 9 {
            digits.push('0');
        }
        nanos = digits.parse().ok()?;
    }

    let offset_seconds: i64 = match bytes.get(idx) {
        None => 0, // naive: treated as UTC
        Some(b'Z') | Some(b'z') => {
            idx += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            let sign_mult: i64 = if *sign == b'+' { 1 } else { -1 };
            let oh = two(idx + 1)?;
            if bytes.get(idx + 3) != Some(&b':') {
                return None;
            }
            let om = two(idx + 4)?;
            if !(0..=23).contains(&oh) || !(0..=59).contains(&om) {
                return None;
            }
            idx += 6;
            sign_mult * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    if idx != bytes.len() {
        return None; // trailing garbage
    }

    let days = days_from_civil(year, month as u32, day as u32);
    let unix_seconds = days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds;
    Some(Timestamp { unix_seconds, nanos })
}

/// Howard Hinnant's `days_from_civil` — days since the Unix epoch
/// (1970-01-01) for a proleptic-Gregorian civil date. `m` is 1-12.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(m) + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Howard Hinnant's `civil_from_days` — the inverse of [`days_from_civil`]:
/// a proleptic-Gregorian civil date (year, month `1-12`, day `1-31`) for a
/// day count since the Unix epoch (1970-01-01). Used by
/// [`format_iso8601_timestamp`] (D1, rfc-resolution-semantics.md §3 Axis D)
/// to render a normalized [`Timestamp`] back to a wire ISO 8601 string.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format a [`Timestamp`] back to canonical UTC ISO 8601
/// (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`) — the inverse of
/// [`parse_iso8601_timestamp`]. `Timestamp` is always a normalized UTC
/// instant (no separate offset is retained from the original text), so the
/// canonical wire form always ends in `Z` — matching the RFC's own
/// `resolution { exclude-newer "…Z" }` example (D1). Sub-second precision
/// is included only when `nanos != 0` (never a fake trailing `.000000000`).
pub fn format_iso8601_timestamp(ts: &Timestamp) -> String {
    let (y, m, d) = civil_from_days(ts.unix_seconds.div_euclid(86400));
    let secs_of_day = ts.unix_seconds.rem_euclid(86400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    if ts.nanos == 0 {
        format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        let mut frac = format!("{:09}", ts.nanos);
        while frac.ends_with('0') {
            frac.pop();
        }
        format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{frac}Z")
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
            name: None,
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
            name: None,
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

    // ISO-8601 timestamp parser — malformed/edge cases (moved from
    // `milpa-core::registry_tests` in D0; see `parse_iso8601_timestamp` docs
    // above for why this is hand-rolled rather than an external date crate).

    #[test]
    fn iso8601_parses_z_suffixed() {
        let t = parse_iso8601_timestamp("2026-05-26T04:49:44Z").unwrap();
        // 2026-05-26T04:49:44Z: sanity-check against an independently computed
        // Unix timestamp (via `date -u -d ... +%s`-equivalent reasoning is not
        // available offline here, so this pins internal consistency: re-parsing
        // the same string is idempotent and two different instants differ).
        let t2 = parse_iso8601_timestamp("2026-05-26T04:49:44Z").unwrap();
        assert_eq!(t, t2);
        let t3 = parse_iso8601_timestamp("2026-05-26T04:49:45Z").unwrap();
        assert_ne!(t, t3);
        assert_eq!(t3.unix_seconds, t.unix_seconds + 1);
    }

    #[test]
    fn iso8601_offset_and_z_agree_on_same_instant() {
        let z = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let offset = parse_iso8601_timestamp("2026-01-01T01:00:00+01:00").unwrap();
        assert_eq!(z, offset);
    }

    #[test]
    fn iso8601_offsetless_assumes_utc() {
        // R2 (cross-impl parity): an offsetless-but-otherwise-valid timestamp
        // (no trailing `Z`/offset — a very natural thing to type in a
        // manifest `resolution { exclude-newer }` or `--exclude-newer` CLI
        // value) must parse the same as its `Z`-suffixed spelling. Rust
        // already does this by construction (`offset_seconds = 0` when no
        // offset is present); this pins the behavior so it can't regress,
        // and matches Python's `_parse_timestamp`, which normalizes a naive
        // `datetime.fromisoformat` result to UTC for the same reason.
        let naive = parse_iso8601_timestamp("2026-01-01T00:00:00").unwrap();
        let z = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(naive, z);
    }

    #[test]
    fn iso8601_rejects_garbage() {
        assert!(parse_iso8601_timestamp("not-a-timestamp").is_none());
        assert!(parse_iso8601_timestamp("").is_none());
        assert!(parse_iso8601_timestamp("2026-13-01T00:00:00Z").is_none()); // month 13
        assert!(parse_iso8601_timestamp("2026-01-01T00:00:00+99:99").is_none());
    }

    // format_iso8601_timestamp (D1, rfc-resolution-semantics.md §3 Axis D) —
    // the inverse of parse_iso8601_timestamp, used by the manifest
    // `resolution { exclude-newer }` round-trip emitter.

    #[test]
    fn format_iso8601_round_trips_whole_seconds() {
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(format_iso8601_timestamp(&ts), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn format_iso8601_round_trips_arbitrary_instant() {
        let ts = parse_iso8601_timestamp("2026-06-15T12:30:45Z").unwrap();
        assert_eq!(format_iso8601_timestamp(&ts), "2026-06-15T12:30:45Z");
    }

    #[test]
    fn format_iso8601_normalizes_an_offset_to_utc_z() {
        let ts = parse_iso8601_timestamp("2026-01-01T01:00:00+01:00").unwrap();
        assert_eq!(format_iso8601_timestamp(&ts), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn format_iso8601_omits_fraction_when_zero() {
        let ts = Timestamp {
            unix_seconds: 0,
            nanos: 0,
        };
        assert_eq!(format_iso8601_timestamp(&ts), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_iso8601_includes_fraction_when_present() {
        let ts = Timestamp {
            unix_seconds: 0,
            nanos: 500_000_000,
        };
        assert_eq!(format_iso8601_timestamp(&ts), "1970-01-01T00:00:00.5Z");
    }

    #[test]
    fn civil_from_days_is_the_inverse_of_days_from_civil() {
        for (y, m, d) in [
            (1970, 1, 1),
            (2026, 1, 1),
            (2026, 6, 15),
            (2000, 2, 29), // leap day
            (1969, 12, 31),
            (1900, 3, 1),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "round-trip for {y}-{m}-{d}");
        }
    }
}
