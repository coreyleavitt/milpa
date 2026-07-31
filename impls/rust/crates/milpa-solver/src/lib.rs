//! `milpa-solver` — version parsing + constraint algebra + the PubGrub seam
//! (RFC §4.1/§4.6). `VersionSet`'s `contains`/`intersect`/`complement` and its
//! `pubgrub::DependencyProvider` wiring are the type's *inherent* methods;
//! Rust's orphan rule keeps them in the crate that owns the type. Only the raw
//! `Version` newtype (with its semver total order) is shared, via `milpa-types`.
//!
//! S6: `parse_version` / `format_version_str`, the `VersionSet` interval
//! algebra, and the `Strategy` enum land here — a faithful port of
//! `milpa/solver.py`'s version layer. The PubGrub `solve()` loop + conflict
//! narration follow in S7 (wired per the S0(b) decision to `pubgrub` 0.4.0).

use milpa_types::{PreId, Version};

/// Version-selection strategy (resolver-semantics §4.2/§4.3). `Maxver` is the
/// default; `Minver` locks to the floor; `Semver` stays within the constraint
/// lower bound's major.
///
/// `LowestDirect` (resolver-semantics RFC §3 Axis C, #111; wire string
/// `lowest-direct`, matching uv's `--resolution lowest-direct`): applies
/// `Minver` to root-direct deps and `Maxver` to everything else — the
/// practical way to test that advertised lower bounds actually build. This is
/// a **surface value only** (CLI flag / lockfile `strategy` node): the
/// provider resolves it to a concrete per-package `EffectiveStrategy` before
/// the pick ever runs (`effective_strategy`, D-C2) — `pick_version`'s
/// `strategy` argument has NO `LowestDirect` case; its type (`EffectiveStrategy`)
/// structurally cannot represent it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Strategy {
    #[default]
    Maxver,
    Minver,
    Semver,
    LowestDirect,
}

impl Strategy {
    /// Canonical lockfile spelling (`strategy "maxver"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Strategy::Maxver => "maxver",
            Strategy::Minver => "minver",
            Strategy::Semver => "semver",
            Strategy::LowestDirect => "lowest-direct",
        }
    }

    /// Parse the canonical wire string (`as_str`'s inverse). `None` for an
    /// unrecognized value — never a panic, so callers decide the error slug
    /// (C3, resolver-semantics RFC §3 Axis C / §5): the CLI `--strategy` flag
    /// and the manifest `resolution { strategy }` block both reuse this SSOT
    /// rather than duplicating the match.
    pub fn parse(s: &str) -> Option<Strategy> {
        match s {
            "maxver" => Some(Strategy::Maxver),
            "minver" => Some(Strategy::Minver),
            "semver" => Some(Strategy::Semver),
            "lowest-direct" => Some(Strategy::LowestDirect),
            _ => None,
        }
    }
}

/// C2 (resolver-semantics RFC §3 Axis C / §4 stage 4, D-C2): the concrete
/// strategy the picker (`pick_version`) can execute — deliberately narrower
/// than the surface `Strategy` (it has no `LowestDirect` variant). The
/// provider's `effective_strategy` precompute is the ONLY place a `Strategy`
/// value is converted to this type; `LowestDirect` is interpreted there
/// (`Minver` for a root-direct package, `Maxver` otherwise) and never flows
/// any further — `pick_version`'s `match` is exhaustive over exactly these
/// three variants, so a future accidental attempt to pass `LowestDirect` into
/// the picker is a compile error, not a runtime footgun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveStrategy {
    Maxver,
    Minver,
    Semver,
}

/// C2 (resolver-semantics RFC §3 Axis C / §4 stage 4, D-C2): resolve the
/// provider's configured `Strategy` — which may be the surface-only
/// `LowestDirect` — to a concrete `EffectiveStrategy` for one package.
/// `LowestDirect` becomes `Minver` for a root-direct package
/// (`is_root_direct`) and `Maxver` otherwise; every other strategy passes
/// through unchanged. This is the provider-level effective-strategy
/// precompute the RFC's design deepening calls for — `pick_version` never
/// learns `LowestDirect` exists.
fn effective_strategy(strategy: Strategy, is_root_direct: bool) -> EffectiveStrategy {
    match strategy {
        Strategy::Maxver => EffectiveStrategy::Maxver,
        Strategy::Minver => EffectiveStrategy::Minver,
        Strategy::Semver => EffectiveStrategy::Semver,
        Strategy::LowestDirect => {
            if is_root_direct {
                EffectiveStrategy::Minver
            } else {
                EffectiveStrategy::Maxver
            }
        }
    }
}

/// A5 (resolution-semantics RFC §3 Axis A (b) / §5): which precedence branch
/// produced a git/url/local/tarball/member dep's declared-version label
/// (`declared_version_for`, `edge_sources.rs`). Mirrors `milpa/version.py`'s
/// `VersionSource` StrEnum.
///
/// `Manifest` names the *role* — "this package's own manifest" — not the
/// literal file syntax of the day, so the wire value in the lockfile survives
/// a future manifest-format evolution. The four values mirror precedence
/// steps 1-4 exactly:
///
/// - `Manifest`: the fetched package's own `milpa.kdl version` field (step 1).
/// - `Nimble`: the fetched package's `.nimble version` (step 2, A1 scanner).
/// - `Tag`: a version-shaped git ref tag, `v?X.Y.Z` (step 3, A3).
/// - `Annotation`: the dep declaration's `version=` annotation, or an
///   `overrides { … version= }` rule's (step 4, A3b).
///
/// A version-unknown dep (no step matched) carries no `VersionSource` at all
/// — `None` (Option, not a 5th variant; §5 NORMATIVE: the lockfile pairs
/// `0.0.0` + absent source for that case, a combination no `Known` case ever
/// produces since a `Known` always names its source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    Manifest,
    Nimble,
    Tag,
    Annotation,
}

impl VersionSource {
    /// Canonical lockfile spelling (`declared_version_source "manifest"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            VersionSource::Manifest => "manifest",
            VersionSource::Nimble => "nimble",
            VersionSource::Tag => "tag",
            VersionSource::Annotation => "annotation",
        }
    }

    /// Parse a lockfile-recorded value back into a `VersionSource`. `None`
    /// for any unrecognized value — forward-compat lenient collapse (mirrors
    /// the attestation `kind` collapse convention, lockfile-schema §3.9); no
    /// new error slug is warranted for a purely additive field.
    pub fn from_str_lenient(s: &str) -> Option<VersionSource> {
        match s {
            "manifest" => Some(VersionSource::Manifest),
            "nimble" => Some(VersionSource::Nimble),
            "tag" => Some(VersionSource::Tag),
            "annotation" => Some(VersionSource::Annotation),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Version parse + format (SSOT for the semver string grammar — mirrors
// `milpa/solver.py:parse_version` / `_format_version_str`).
// ---------------------------------------------------------------------------

/// Parse a semver string into a [`Version`].
///
/// Accepts an optional `v` prefix (`v0.5.1` and `0.5.1` both parse). Pre-release
/// identifiers are stored in `pre`; build metadata in `build` (preserved for
/// round-trip, ignored for ordering/equality per semver 2.0 §10).
///
/// Returns `None` for non-canonical tags (e.g. `nimble-1.2.3`) — the single
/// source of truth used by both the solver (constraint clauses) and the registry
/// (filtering available tags). Callers decide whether `None` is a skip or a
/// coded error (mirrors the Python `parse_version` returning `None`).
pub fn parse_version(text: &str) -> Option<Version> {
    let s = text.trim();
    let s = s.strip_prefix('v').unwrap_or(s);

    // Per the grammar, build metadata (introduced by `+`) follows the optional
    // pre-release tag, and neither charset contains `+`, so a single split is
    // unambiguous.
    let (rest, build) = match s.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (s, None),
    };
    // The first `-` delimits the pre-release tag; further `-` are legal *inside*
    // pre-release identifiers, so `split_once` (not `split`) is correct.
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };

    let mut parts = core.split('.');
    let major = parse_numeric_component(parts.next()?)?;
    let minor = parse_numeric_component(parts.next()?)?;
    let patch = parse_numeric_component(parts.next()?)?;
    if parts.next().is_some() {
        return None; // more than three release components
    }

    let pre_ids = match pre {
        Some(p) => parse_pre_identifiers(p)?,
        None => Vec::new(),
    };
    let build_str = match build {
        Some(b) => {
            if !is_valid_dotted_idents(b) {
                return None;
            }
            b.to_string()
        }
        None => String::new(),
    };

    Some(Version {
        major,
        minor,
        patch,
        pre: pre_ids,
        build: build_str,
    })
}

/// A release component: one or more ASCII digits (leading zeros tolerated and
/// normalized, mirroring Python's `int("01")`).
fn parse_numeric_component(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// Validate a dot-separated identifier list (`[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*`):
/// at least one part, every part non-empty and within the charset.
fn is_valid_dotted_idents(s: &str) -> bool {
    !s.is_empty()
        && s.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(is_ident_char))
}

/// Parse a pre-release tag into identifiers. An all-digits identifier becomes
/// [`PreId::Numeric`] (normalized via `u64`); anything else stays
/// [`PreId::Alpha`]. Returns `None` if any identifier is empty or out of charset.
fn parse_pre_identifiers(pre: &str) -> Option<Vec<PreId>> {
    if pre.is_empty() {
        return None;
    }
    let mut ids = Vec::new();
    for part in pre.split('.') {
        if part.is_empty() || !part.bytes().all(is_ident_char) {
            return None;
        }
        if part.bytes().all(|b| b.is_ascii_digit()) {
            // All-digits: numeric identifier (u64 normalizes leading zeros).
            // Overflow is implausible for real versions; fall back to Alpha so
            // parsing never panics or rejects a charset-valid identifier.
            match part.parse::<u64>() {
                Ok(n) => ids.push(PreId::Numeric(n)),
                Err(_) => ids.push(PreId::Alpha(part.to_string())),
            }
        } else {
            ids.push(PreId::Alpha(part.to_string()));
        }
    }
    Some(ids)
}

/// Format a [`Version`] as a lossless semver string `major.minor.patch[-pre][+build]`
/// (mirrors `milpa/solver.py:_format_version_str`). The inverse of
/// [`parse_version`] modulo a dropped `v` prefix and leading-zero normalization.
///
/// The rendering itself is the `Display` impl on [`Version`] (the SSOT, living in
/// `milpa-types` because the `pubgrub` trait bounds also need it); this is the
/// named entry point the lockfile/nim.cfg emitters call.
pub fn format_version_str(v: &Version) -> String {
    v.to_string()
}

/// Convert a `VersionSet` to a constraint string parseable by
/// `VersionSet::from_constraint` (mirrors Python's `_vs_to_constraint_str`).
///
/// Each interval becomes a conjunction of `>=`/`>`/`<=`/`<` clauses joined by
/// ` & `; multiple intervals are joined by ` | `. This is the SSOT for the
/// `constraint` field in the §5.1 success-certificate witness and the §5.2
/// failure-certificate refutation.
///
/// Special cases:
/// - Empty → `">0.0.0 & <0.0.0"` (canonical always-empty expression)
/// - Full (None, None) → `"any version"`
pub fn vs_to_constraint_str(vs: &VersionSet) -> String {
    if vs.is_empty() {
        return ">0.0.0 & <0.0.0".to_string();
    }
    let mut arms: Vec<String> = Vec::new();
    for iv in &vs.intervals {
        if iv.lo.is_none() && iv.hi.is_none() {
            return "any version".to_string();
        }
        let mut clauses: Vec<String> = Vec::new();
        if let Some(lo) = &iv.lo {
            let op = if iv.lo_closed { ">=" } else { ">" };
            clauses.push(format!("{op}{lo}"));
        }
        if let Some(hi) = &iv.hi {
            let op = if iv.hi_closed { "<=" } else { "<" };
            clauses.push(format!("{op}{hi}"));
        }
        if clauses.is_empty() {
            return "any version".to_string();
        }
        arms.push(clauses.join(" & "));
    }
    arms.join(" | ")
}

// ---------------------------------------------------------------------------
// Constraint parse error — uncoded, mirroring the bare `ValueError` Python's
// `VersionSet.from_constraint` raises. The resolver (S7b) maps this to the
// catalog code `MAN-NIMBLE-CONSTRAINT` at its layer; the solver owns no slug
// for it, so it stays out of every `all_codes()`.
// ---------------------------------------------------------------------------

/// An unparseable version-constraint string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintError(pub String);

impl std::fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConstraintError {}

// ---------------------------------------------------------------------------
// VersionSet — union of disjoint generalized intervals over Version.
//
// Each interval is (lo, hi, lo_closed, hi_closed):
//   lo = Some(v) | None (None = -∞, always exclusive)
//   hi = Some(v) | None (None = +∞, always exclusive)
//   lo_closed: true → lo inclusive ([lo,..), false → exclusive ((lo,..)
//   hi_closed: true → hi inclusive (..,hi]), false → exclusive (..,hi)
//
// eq(v) is the true closed singleton (v, v, true, true) — the P3.1b fix that
// keeps prereleases of the next version out of `{v}`. A faithful port of
// `milpa/solver.py`'s `VersionSet`.
// ---------------------------------------------------------------------------

/// A single generalized interval. The fields mirror the Python 4-tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Interval {
    lo: Option<Version>,
    hi: Option<Version>,
    lo_closed: bool,
    hi_closed: bool,
}

impl Interval {
    fn new(lo: Option<Version>, hi: Option<Version>, lo_closed: bool, hi_closed: bool) -> Self {
        Interval {
            lo,
            hi,
            lo_closed,
            hi_closed,
        }
    }
}

/// A set of versions as a canonical union of disjoint intervals. Canonical form
/// (sorted by `lo`, non-overlapping, no empties, adjacent-merged) makes
/// structural `PartialEq` equal to semantic equality — so the derived `Eq` is
/// the set equality the property tests rely on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionSet {
    intervals: Vec<Interval>,
}

impl VersionSet {
    /// The set of every version.
    pub fn full() -> Self {
        VersionSet {
            intervals: vec![Interval::new(None, None, true, false)],
        }
    }

    /// The empty set.
    pub fn empty() -> Self {
        VersionSet { intervals: vec![] }
    }

    /// `>= v`.
    pub fn gte(v: Version) -> Self {
        VersionSet {
            intervals: vec![Interval::new(Some(v), None, true, false)],
        }
    }

    /// `> v`.
    pub fn gt(v: Version) -> Self {
        Self::gte(v.clone()).intersect(&Self::eq(v).complement())
    }

    /// `< v`.
    pub fn lt(v: Version) -> Self {
        VersionSet {
            intervals: vec![Interval::new(None, Some(v), true, false)],
        }
    }

    /// `<= v`.
    pub fn lte(v: Version) -> Self {
        Self::lt(v.clone()).union(&Self::eq(v))
    }

    /// The closed singleton `{v}` (P3.1b closed-point representation).
    pub fn eq(v: Version) -> Self {
        VersionSet {
            intervals: vec![Interval::new(Some(v.clone()), Some(v), true, true)],
        }
    }

    /// Parse a constraint string into a `VersionSet`. OR (`||` / `|`) has lower
    /// precedence than AND (`&`): split into arms, intersect each arm's clauses,
    /// union the arms. `None` / `""` / `"any version"` ⇒ [`VersionSet::full`].
    pub fn from_constraint(constraint: Option<&str>) -> Result<Self, ConstraintError> {
        let raw = match constraint {
            None => return Ok(Self::full()),
            Some(c) => c,
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "any version" {
            return Ok(Self::full());
        }
        let mut result = Self::empty();
        // OR splits on `||` or `|`; splitting on the single `|` also covers `||`
        // (the empty arm between the two pipes is an empty clause set ⇒ full(),
        // matching Python's `re.split(r"\|\|?")` only at non-empty arms). Guard
        // empties to keep parity with Python, which yields `""` arms it parses
        // as full() — but an empty clause inside an arm is an error there. We
        // mirror Python by treating a wholly-empty arm as contributing nothing.
        for arm in split_or(trimmed) {
            let mut arm_result = Self::full();
            for clause in arm.split('&') {
                let clause = clause.trim();
                arm_result = arm_result.intersect(&Self::parse_clause(clause)?);
            }
            result = result.union(&arm_result);
        }
        Ok(result)
    }

    fn parse_clause(clause: &str) -> Result<Self, ConstraintError> {
        let clause = clause.trim();
        // Longest operators first so `>=` wins over `>`, etc.
        for op in [">=", "<=", "==", "!=", ">", "<", "~", "^", "="] {
            if let Some(rest) = clause.strip_prefix(op) {
                let ver_str = rest.trim();
                let v = parse_version(ver_str).ok_or_else(|| {
                    ConstraintError(format!("unparseable version in constraint: {ver_str:?}"))
                })?;
                return Ok(match op {
                    ">=" => Self::gte(v),
                    "<=" => Self::lte(v),
                    ">" => Self::gt(v),
                    "<" => Self::lt(v),
                    "==" | "=" => Self::eq(v),
                    "!=" => Self::eq(v).complement(),
                    "~" => Self::tilde(&v),
                    "^" => Self::caret(&v),
                    _ => unreachable!("operator table and match arms are in lockstep"),
                });
            }
        }
        Err(ConstraintError(format!(
            "unparseable constraint clause: {clause:?}"
        )))
    }

    /// `~M.m.p` → `>=M.m.p <M.(m+1).0`; `~M.0.0` → `>=M.0.0 <(M+1).0.0`.
    fn tilde(v: &Version) -> Self {
        let lo = Self::gte(v.clone());
        let hi = if v.minor == 0 && v.patch == 0 {
            Self::lt(Version::release(v.major + 1, 0, 0))
        } else {
            Self::lt(Version::release(v.major, v.minor + 1, 0))
        };
        lo.intersect(&hi)
    }

    /// `^` compatible-with: bump the left-most non-zero component for the upper
    /// bound; `^0.0.0` → `>=0.0.0 <0.1.0`.
    fn caret(v: &Version) -> Self {
        let lo = Self::gte(v.clone());
        let hi = if v.major > 0 {
            Self::lt(Version::release(v.major + 1, 0, 0))
        } else if v.minor > 0 {
            Self::lt(Version::release(0, v.minor + 1, 0))
        } else if v.patch > 0 {
            Self::lt(Version::release(0, 0, v.patch + 1))
        } else {
            Self::lt(Version::release(0, 1, 0))
        };
        lo.intersect(&hi)
    }

    /// Whether `v` is a member.
    pub fn contains(&self, v: &Version) -> bool {
        self.intervals.iter().any(|iv| interval_contains(iv, v))
    }

    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// Whether this set admits every version (no constrainer has narrowed it
    /// at all). Canonical form makes structural equality exact set equality
    /// (see the struct doc), so this is just an equality check against
    /// [`VersionSet::full`] — used by A4's version-unknown partition to
    /// classify a package's accumulated range at its decision point
    /// (resolver-semantics RFC §3 Axis A (c)).
    pub fn is_full(&self) -> bool {
        self == &VersionSet::full()
    }

    /// Set intersection.
    pub fn intersect(&self, other: &VersionSet) -> VersionSet {
        let mut out: Vec<Interval> = Vec::new();
        for a in &self.intervals {
            for b in &other.intervals {
                let (lo, lo_c) =
                    max_lo_with_closed(a.lo.as_ref(), a.lo_closed, b.lo.as_ref(), b.lo_closed);
                let (hi, hi_c) =
                    min_hi_with_closed(a.hi.as_ref(), a.hi_closed, b.hi.as_ref(), b.hi_closed);
                if interval_nonempty(lo.as_ref(), hi.as_ref(), lo_c, hi_c) {
                    out.push(Interval::new(lo, hi, lo_c, hi_c));
                }
            }
        }
        VersionSet {
            intervals: normalize_intervals(out),
        }
    }

    /// Set union.
    pub fn union(&self, other: &VersionSet) -> VersionSet {
        let mut all = self.intervals.clone();
        all.extend(other.intervals.iter().cloned());
        VersionSet {
            intervals: normalize_intervals(all),
        }
    }

    /// Set complement.
    pub fn complement(&self) -> VersionSet {
        if self.intervals.is_empty() {
            return VersionSet::full();
        }
        let mut out: Vec<Interval> = Vec::new();
        let first = &self.intervals[0];
        if let Some(lo0) = &first.lo {
            // Left gap: (-∞, lo0) with hi openness = not lo0_closed.
            out.push(Interval::new(
                None,
                Some(lo0.clone()),
                true,
                !first.lo_closed,
            ));
        }
        for w in self.intervals.windows(2) {
            let (a, b) = (&w[0], &w[1]);
            // Gap between interval a's hi and interval b's lo.
            out.push(Interval::new(
                a.hi.clone(),
                b.lo.clone(),
                !a.hi_closed,
                !b.lo_closed,
            ));
        }
        let last = self.intervals.last().expect("non-empty checked above");
        if let Some(last_hi) = &last.hi {
            // Right tail: (last_hi, +∞) with lo openness = not last_hi_closed.
            out.push(Interval::new(
                Some(last_hi.clone()),
                None,
                !last.hi_closed,
                false,
            ));
        }
        VersionSet {
            intervals: normalize_intervals(out),
        }
    }

    /// `self ⊆ other` iff `self ∩ other^c = ∅`.
    pub fn is_subset_of(&self, other: &VersionSet) -> bool {
        self.intersect(&other.complement()).is_empty()
    }

    /// The minimum inclusive lower bound across all intervals; `None` if any
    /// interval is unbounded below (resolver-semantics §4.3.1, `_lower_bound_of`).
    /// Drives the `semver` strategy's "compatible major" selection in S7.
    pub fn lower_bound(&self) -> Option<Version> {
        if self.intervals.is_empty() {
            return None;
        }
        let mut min: Option<&Version> = None;
        for iv in &self.intervals {
            match &iv.lo {
                None => return None, // unbounded below
                Some(v) => {
                    min = Some(match min {
                        Some(m) if m <= v => m,
                        _ => v,
                    });
                }
            }
        }
        min.cloned()
    }
}

/// Human-readable interval rendering (mirrors `solver.py:_format_set`). Only the
/// `pubgrub` conflict reporter consumes it, but the trait bound `VS: Display`
/// makes it mandatory, and a readable form keeps `SOLVE-CONFLICT` narration legible.
impl std::fmt::Display for VersionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.intervals.is_empty() {
            return f.write_str("(empty)");
        }
        let mut parts: Vec<String> = Vec::new();
        for iv in &self.intervals {
            parts.push(match (&iv.lo, &iv.hi) {
                (None, None) => "any".to_string(),
                (None, Some(hi)) => format!("(-∞, {}{}", hi, if iv.hi_closed { ']' } else { ')' }),
                (Some(lo), None) => format!("{}{}, +∞)", if iv.lo_closed { '[' } else { '(' }, lo),
                (Some(lo), Some(hi)) if lo == hi && iv.lo_closed && iv.hi_closed => {
                    format!("{{{lo}}}")
                }
                (Some(lo), Some(hi)) => format!(
                    "{}{}, {}{}",
                    if iv.lo_closed { '[' } else { '(' },
                    lo,
                    hi,
                    if iv.hi_closed { ']' } else { ')' }
                ),
            });
        }
        f.write_str(&parts.join(" ∪ "))
    }
}

/// Bridge milpa's `VersionSet` into `pubgrub`'s set protocol (the S0(b) seam: the
/// crate drives resolution, milpa owns the set algebra). The five required
/// methods delegate to the inherent algebra; `full`/`union`/`subset_of` are
/// overridden to milpa's canonical implementations so set equality stays exact.
impl pubgrub::VersionSet for VersionSet {
    type V = Version;

    fn empty() -> Self {
        VersionSet::empty()
    }

    fn singleton(v: Self::V) -> Self {
        VersionSet::eq(v)
    }

    fn complement(&self) -> Self {
        VersionSet::complement(self)
    }

    fn intersection(&self, other: &Self) -> Self {
        VersionSet::intersect(self, other)
    }

    fn contains(&self, v: &Self::V) -> bool {
        VersionSet::contains(self, v)
    }

    fn full() -> Self {
        VersionSet::full()
    }

    fn union(&self, other: &Self) -> Self {
        VersionSet::union(self, other)
    }

    fn subset_of(&self, other: &Self) -> bool {
        self.is_subset_of(other)
    }
}

fn interval_contains(iv: &Interval, v: &Version) -> bool {
    if let Some(lo) = &iv.lo {
        if iv.lo_closed {
            if v < lo {
                return false;
            }
        } else if v <= lo {
            return false;
        }
    }
    if let Some(hi) = &iv.hi {
        if iv.hi_closed {
            if v > hi {
                return false;
            }
        } else if v >= hi {
            return false;
        }
    }
    true
}

/// Larger of two lower bounds (closedness preserved; equal ⇒ open if either is).
/// `None` is -∞ (smallest).
fn max_lo_with_closed(
    a: Option<&Version>,
    a_c: bool,
    b: Option<&Version>,
    b_c: bool,
) -> (Option<Version>, bool) {
    match (a, b) {
        (None, _) => (b.cloned(), b_c),
        (_, None) => (a.cloned(), a_c),
        (Some(av), Some(bv)) => match av.cmp(bv) {
            std::cmp::Ordering::Greater => (Some(av.clone()), a_c),
            std::cmp::Ordering::Less => (Some(bv.clone()), b_c),
            std::cmp::Ordering::Equal => (Some(av.clone()), a_c && b_c),
        },
    }
}

/// Smaller of two upper bounds (closedness preserved; equal ⇒ open if either is).
/// `None` is +∞ (largest).
fn min_hi_with_closed(
    a: Option<&Version>,
    a_c: bool,
    b: Option<&Version>,
    b_c: bool,
) -> (Option<Version>, bool) {
    match (a, b) {
        (None, _) => (b.cloned(), b_c),
        (_, None) => (a.cloned(), a_c),
        (Some(av), Some(bv)) => match av.cmp(bv) {
            std::cmp::Ordering::Less => (Some(av.clone()), a_c),
            std::cmp::Ordering::Greater => (Some(bv.clone()), b_c),
            std::cmp::Ordering::Equal => (Some(av.clone()), a_c && b_c),
        },
    }
}

fn interval_nonempty(lo: Option<&Version>, hi: Option<&Version>, lo_c: bool, hi_c: bool) -> bool {
    match (lo, hi) {
        (None, _) | (_, None) => true,
        (Some(lo), Some(hi)) => {
            if lo < hi {
                true
            } else {
                lo == hi && lo_c && hi_c // closed point [v, v] = {v}
            }
        }
    }
}

/// Sort + merge a list of intervals into canonical form (mirrors
/// `_normalize_intervals`). The lo=None merge-gap that Hypothesis found
/// (issue #63) is covered by the sort placing `None` lows first and the
/// connectability check below — pinned by a unit test.
fn normalize_intervals(mut intervals: Vec<Interval>) -> Vec<Interval> {
    // Canonicalize unbounded endpoints (lo=None ⇒ closed irrelevant→true;
    // hi=None ⇒ exclusive→false) so equal sets compare equal structurally.
    for iv in &mut intervals {
        if iv.lo.is_none() {
            iv.lo_closed = true;
        }
        if iv.hi.is_none() {
            iv.hi_closed = false;
        }
    }
    intervals.sort_by(|a, b| lo_sort_key(a).cmp(&lo_sort_key(b)));

    let mut merged: Vec<Interval> = Vec::new();
    for iv in intervals {
        if !interval_nonempty(iv.lo.as_ref(), iv.hi.as_ref(), iv.lo_closed, iv.hi_closed) {
            continue;
        }
        match merged.last() {
            None => merged.push(iv),
            Some(prev) => {
                if intervals_connectable(prev, &iv) {
                    let (new_hi, new_hi_c) = max_bound(
                        prev.hi.as_ref(),
                        prev.hi_closed,
                        iv.hi.as_ref(),
                        iv.hi_closed,
                    );
                    let last = merged.last_mut().expect("just matched Some");
                    last.hi = new_hi;
                    last.hi_closed = new_hi_c;
                } else {
                    merged.push(iv);
                }
            }
        }
    }
    merged
}

/// Sort key: `None` lo first; then by `lo` value; then closed before open.
/// Encoded as a comparable tuple `(group, lo, closed_rank)`.
fn lo_sort_key(iv: &Interval) -> (u8, Option<&Version>, u8) {
    match &iv.lo {
        None => (0, None, 0),
        Some(v) => (1, Some(v), u8::from(!iv.lo_closed)),
    }
}

/// True if A and B overlap or are adjacent at a point closed on either side
/// (A is sorted before B, so `a.lo <= b.lo` semantically).
fn intervals_connectable(a: &Interval, b: &Interval) -> bool {
    let a_hi = match &a.hi {
        None => return true, // A extends to +∞
        Some(h) => h,
    };
    let b_lo = match &b.lo {
        None => return true, // B starts at -∞
        Some(l) => l,
    };
    match a_hi.cmp(b_lo) {
        std::cmp::Ordering::Less => false,                       // gap
        std::cmp::Ordering::Greater => true,                     // overlap
        std::cmp::Ordering::Equal => a.hi_closed || b.lo_closed, // shared point
    }
}

/// Larger of two upper bounds for a merged interval (`None` = +∞; equal ⇒ keep
/// closed if either is, since the union includes the point).
fn max_bound(
    a: Option<&Version>,
    a_c: bool,
    b: Option<&Version>,
    b_c: bool,
) -> (Option<Version>, bool) {
    match (a, b) {
        (None, _) => (None, a_c),
        (_, None) => (None, b_c),
        (Some(av), Some(bv)) => match av.cmp(bv) {
            std::cmp::Ordering::Greater => (Some(av.clone()), a_c),
            std::cmp::Ordering::Less => (Some(bv.clone()), b_c),
            std::cmp::Ordering::Equal => (Some(av.clone()), a_c || b_c),
        },
    }
}

/// Split a constraint on OR (`||` or a single `|`), mirroring Python's
/// `re.split(r"\|\|?", c)`. `||` produces an extra empty arm between the pipes,
/// which `from_constraint`'s clause loop turns into `full()`; we replicate that
/// by splitting on each `|` run as one separator.
fn split_or(s: &str) -> Vec<&str> {
    // `re.split(r"\|\|?")` treats `||` or `|` as a single delimiter. Replace by
    // scanning: collapse runs of 1-2 pipes into one boundary.
    let mut arms = Vec::new();
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'|' {
            arms.push(&s[start..i]);
            // consume one or two pipes (matches \|\|?)
            i += 1;
            if i < bytes.len() && bytes[i] == b'|' {
                i += 1;
            }
            start = i;
        } else {
            i += 1;
        }
    }
    arms.push(&s[start..]);
    arms
}

// ---------------------------------------------------------------------------
// Solver core (S7a) — PubGrub via the `pubgrub` 0.4.0 crate.
//
// The Python `milpa/solver.py` hand-rolls a teaching-clean PubGrub (Term /
// Incompatibility / PartialSolution / the unit-propagate loop). The S0(b)
// decision is to USE the crate here instead, so this slice ports the *contract*
// — a `PackageProvider` seam, a `solve()` entry point, MaxVer/MinVer/SemVer
// candidate selection, and a `SOLVE-CONFLICT` error carrying a conflict
// narration — not the hand-rolled loop. `pubgrub` owns the partial solution,
// incompatibility learning, backjumping, and the derivation tree.
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::BTreeMap;

/// One dependency edge: a required package plus the version set it is constrained
/// to. Mirrors a positive `Term` from the Python provider's `dependencies`
/// (the solver only ever consumes positive requirements; negation is internal to
/// `pubgrub`). The resolver (S7b) builds these from parsed `.nimble`/`milpa.kdl`
/// requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub package: String,
    pub constraint: VersionSet,
}

impl Dep {
    pub fn new(package: impl Into<String>, constraint: VersionSet) -> Self {
        Dep {
            package: package.into(),
            constraint,
        }
    }
}

/// The two queries the solver makes against the dependency universe (mirrors the
/// Python `PackageProvider` protocol). The resolver (S7b) supplies a
/// fetch-backed implementation; tests supply an in-memory one.
pub trait PackageProvider {
    /// Every available version of `package` (order irrelevant — the solver
    /// selects per `Strategy`). An unknown package yields an empty list, which
    /// the solver reports as "no version of <package>".
    fn versions(&self, package: &str) -> Vec<Version>;

    /// The dependencies of `package` at `version`.
    fn dependencies(&self, package: &str, version: &Version) -> Vec<Dep>;

    /// A4 (resolver-semantics RFC §3 Axis A (c)): true iff `package` has no
    /// declared version — a git/url/local/tarball dep whose manifest/
    /// `.nimble`/tag/`version=` precedence chain (Axis A (b)) all missed, so
    /// it carries only the internal sentinel label. Drives two things in the
    /// solver seam: `prioritize` gives such packages strictly lowest decision
    /// priority (decided only after every reachable constrainer, including a
    /// lazily-materialized named/index dep, is already expanded — §3 Axis A
    /// (c) explains why this can't be a pre-solve pre-pass), and
    /// `choose_version` classifies at that decision point (range `full()` →
    /// unconstrained, unaffected; range non-`full()` → hard error, never a
    /// guessed candidate). Default `false`: providers with no version-unknown
    /// concept (in-memory test fakes) are unaffected.
    fn is_version_unknown(&self, _package: &str) -> bool {
        false
    }

    /// B2 (resolver-semantics RFC §4 stage 4): the prior lockfile's recorded
    /// version for `package`, if one exists — assembled upstream by the
    /// resolver's provider from `params.prior`/`maybe_prior_lockfile` (an
    /// O(1) lookup per package). Fed to `pick_version` as the RFC's
    /// `FromLock(v)` preference, which short-circuits strategy ordering when
    /// `v` survives the constraint filter (B1). Default `None`: providers
    /// with no prior-lock concept (in-memory test fakes) are unaffected.
    fn preference(&self, _package: &str) -> Option<Version> {
        None
    }

    /// C2 (resolver-semantics RFC §3 Axis C, D-C2): true iff `package` is a
    /// root-declared or override-named dep (the resolver's `root_authority`
    /// set, §10 provenance precedence). Drives the `LowestDirect`
    /// effective-strategy precompute (`effective_strategy`): `Minver` for a
    /// root-direct package, `Maxver` otherwise. Default `false`: providers
    /// with no root-authority concept (in-memory test fakes) treat every
    /// package as transitive.
    fn is_root_direct(&self, _package: &str) -> bool {
        false
    }

    /// R3 (resolver-semantics RFC §4.2.1, NORMATIVE): the BFS-insertion index
    /// at which `package` was FIRST reached from the root manifest — root
    /// deps in their manifest declaration order, then transitives in first-
    /// occurrence order. `prioritize` uses this as its tie-break AMONG
    /// non-version-unknown packages (Reverse of this value, so the smallest
    /// index — earliest declared/reached — decides first), so Rust's
    /// decision order matches Python's `_next_undecided` (which walks
    /// partial-solution assignments in that exact insertion order) instead of
    /// alphabetical package name. This is load-bearing for which canonical
    /// solution an AMBIGUOUS (diamond) graph resolves to — §4.2.1's worked
    /// example is normative on it.
    ///
    /// Default `usize::MAX`: providers with no BFS-order concept (in-memory
    /// test fakes) tie at the same sentinel for every package, so
    /// `prioritize` falls through to its OWN name tie-break unchanged —
    /// every pre-R3 test's decision order is preserved byte-for-byte.
    fn declaration_order(&self, _package: &str) -> usize {
        usize::MAX
    }
}

/// One refutation entry: a package name and its constraint string. Used in the
/// §5.2 failure certificate's `refutation` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefutationEntry {
    pub package: String,
    pub constraint: String,
}

/// Resolve the dependency closure of `(root, root_version)`, returning the chosen
/// version for every package in the solution (root included). `strategy` governs
/// candidate selection when more than one version satisfies the accumulated
/// constraint (resolver-semantics §4.2/§4.3).
///
/// Returns [`SolverError::Conflict`] (`SOLVE-CONFLICT`) when the constraints are
/// unsatisfiable, carrying a human-readable derivation from `pubgrub`'s
/// derivation tree.
pub fn solve<P: PackageProvider>(
    provider: &P,
    root: &str,
    root_version: Version,
    strategy: Strategy,
) -> Result<BTreeMap<String, Version>, SolverError> {
    let adapter = ProviderAdapter::new(provider, strategy);
    match pubgrub::resolve(&adapter, root.to_string(), root_version) {
        Ok(selected) => Ok(selected.into_iter().collect()),
        // A4: `choose_version` raised this at a version-unknown package's own
        // (last-scheduled) decision point, before returning any candidate —
        // `pubgrub` never saw an out-of-range choice. Surface the structured
        // facts as their own `SolverError` variant (not stringified into
        // `Conflict`) so the resolver can build the root-authority-aware
        // remedy text.
        Err(pubgrub::PubGrubError::ErrorChoosingVersion {
            source: ProviderError::VersionUnknownConstrained { package, constrainers },
            ..
        }) => Err(SolverError::VersionUnknownConstrained { package, constrainers }),
        Err(pubgrub::PubGrubError::NoSolution(mut tree)) => {
            // Collapse chains of "no versions" derivations into their external
            // cause so the narration names the exhausted package directly.
            tree.collapse_no_versions();
            let prose =
                <pubgrub::DefaultStringReporter as pubgrub::Reporter<_, _, _>>::report(&tree);
            Err(SolverError::Conflict(prose))
        }
        // The other `PubGrubError` variants only arise when the provider's
        // associated `Err` is produced with a variant not matched above —
        // unreachable today (`ProviderError` has one variant); render
        // defensively rather than panic.
        Err(other) => Err(SolverError::Conflict(other.to_string())),
    }
}

/// Solve and also return refutation entries when the constraints are
/// unsatisfiable (for building the §5.2 failure certificate). On success returns
/// `Ok(solution)` with an empty refutation vec; on conflict returns
/// `Err((error, refutation))` with the weak UNSAT core extracted from the
/// derivation tree.
pub fn solve_with_refutation<P: PackageProvider>(
    provider: &P,
    root: &str,
    root_version: Version,
    strategy: Strategy,
) -> Result<BTreeMap<String, Version>, (SolverError, Vec<RefutationEntry>)> {
    let adapter = ProviderAdapter::new(provider, strategy);
    match pubgrub::resolve(&adapter, root.to_string(), root_version) {
        Ok(selected) => Ok(selected.into_iter().collect()),
        // A4: not a SOLVE-CONFLICT — no refutation to extract (mirrors how a
        // non-solver MilpaError failure carries an empty FailureCert).
        Err(pubgrub::PubGrubError::ErrorChoosingVersion {
            source: ProviderError::VersionUnknownConstrained { package, constrainers },
            ..
        }) => Err((
            SolverError::VersionUnknownConstrained { package, constrainers },
            Vec::new(),
        )),
        Err(pubgrub::PubGrubError::NoSolution(mut tree)) => {
            tree.collapse_no_versions();
            let prose =
                <pubgrub::DefaultStringReporter as pubgrub::Reporter<_, _, _>>::report(&tree);
            let refutation = extract_refutation(&tree);
            Err((SolverError::Conflict(prose), refutation))
        }
        Err(other) => Err((SolverError::Conflict(other.to_string()), Vec::new())),
    }
}

/// Walk the pubgrub derivation tree and produce the §5.2 weak UNSAT core.
///
/// Strategy: collect every `FromDependencyOf(_, _, dep, range)` leaf, grouping
/// by dep package.  A package is "conflicted" when the intersection of ALL its
/// accumulated ranges is empty — those are the packages whose constraints are
/// mutually exclusive.  Non-conflicted packages (packages that appear in the
/// tree only as transitive declarants, e.g. `left`/`right` in fixture-128, not
/// `shared`) are excluded from the refutation.
fn extract_refutation(
    tree: &pubgrub::DerivationTree<String, VersionSet, String>,
) -> Vec<RefutationEntry> {
    use pubgrub::{DerivationTree, External};
    use std::collections::BTreeMap;

    // pkg → list of (constraint_str, VersionSet) pairs seen in the tree.
    let mut by_pkg: BTreeMap<String, Vec<(String, VersionSet)>> = BTreeMap::new();
    let mut stack = vec![tree];

    while let Some(node) = stack.pop() {
        match node {
            DerivationTree::External(External::FromDependencyOf(_, _, dep, range)) => {
                let cstr = vs_to_constraint_str(range);
                let entry = by_pkg.entry(dep.clone()).or_default();
                // Deduplicate by constraint string (same constraint from two paths = one entry).
                if !entry.iter().any(|(c, _)| c == &cstr) {
                    entry.push((cstr, range.clone()));
                }
            }
            DerivationTree::Derived(derived) => {
                stack.push(&derived.cause1);
                stack.push(&derived.cause2);
            }
            _ => {}
        }
    }

    let mut out: Vec<RefutationEntry> = Vec::new();
    for (pkg, constraints) in &by_pkg {
        // A package is conflicted iff the intersection of ALL its ranges is empty.
        // Single-entry packages are never conflicted on their own; they only appear
        // in the refutation when a conflict manifests between ≥2 constraints.
        if constraints.len() < 2 {
            continue;
        }
        let intersection = constraints
            .iter()
            .fold(VersionSet::full(), |acc, (_, vs)| acc.intersect(vs));
        if intersection.is_empty() {
            for (cstr, _) in constraints {
                out.push(RefutationEntry {
                    package: pkg.clone(),
                    constraint: cstr.clone(),
                });
            }
        }
    }

    // Sort for determinism (the harness checks set-equality so order doesn't matter,
    // but stable output makes tests easier to read).
    out.sort_by(|a, b| a.package.cmp(&b.package).then(a.constraint.cmp(&b.constraint)));
    out
}

/// Errors a [`PackageProvider`] implementation can signal back through the
/// `pubgrub` callback seam (`DependencyProvider::Err`). The sole variant is
/// A4's version-unknown-constrained classification, raised from
/// `choose_version` at a version-unknown package's (last-scheduled) decision
/// point, before any candidate is returned — so `pubgrub` never sees an
/// out-of-range choice (no panic exposure, `solver.rs:217` in the vendored
/// `pubgrub` 0.4.0 source).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderError {
    /// `package` has no declared version (a git/url/local/tarball dep whose
    /// manifest/`.nimble`/tag/`version=` precedence chain all missed) but the
    /// accumulated range at its decision point is non-`full()`.
    /// `constrainers` names EVERY `(consumer, constraint)` pair that
    /// contributed — never just the first (the amoxtli incident floored two
    /// packages at once).
    VersionUnknownConstrained {
        package: String,
        constrainers: Vec<(String, String)>,
    },
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::VersionUnknownConstrained { package, constrainers } => {
                write!(
                    f,
                    "{package} is version-unknown but constrained by {constrainers:?}"
                )
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// Adapts a milpa [`PackageProvider`] + [`Strategy`] into `pubgrub`'s
/// `DependencyProvider`. Routes `pubgrub`'s callbacks to the milpa queries,
/// applies the strategy in `choose_version`, and (A4) records which consumer
/// places which constraint on which target package as `get_dependencies`
/// discovers them — read back at the target's own decision point so
/// `RES-VERSION-UNKNOWN-CONSTRAINED` can enumerate every accumulated
/// constrainer, not just the first.
struct ProviderAdapter<'a, P: PackageProvider> {
    provider: &'a P,
    strategy: Strategy,
    /// target package name → { consumer name → constraint_str }, recorded as
    /// `get_dependencies` returns them. `get_dependencies` is always called
    /// for a consumer BEFORE that consumer's constraint can appear in any
    /// other package's accumulated `range` (that is how `pubgrub` accumulates
    /// ranges at all), so this map is guaranteed complete for `package` by
    /// the time `choose_version(package, _)` runs — no separate ordering
    /// mechanism needed beyond `prioritize` itself.
    ///
    /// R8: keyed by consumer name (not appended as a growing list) so a
    /// consumer's entry is OVERWRITTEN, never merely added to, on every
    /// `get_dependencies` call for that consumer — see `consumer_targets`'s
    /// doc for how a stale/phantom entry from an abandoned (backtracked-past)
    /// decision gets cleared, not just superseded.
    constrainers: RefCell<BTreeMap<String, BTreeMap<String, String>>>,
    /// R8: consumer name → the target package names it recorded a
    /// non-`full()` constraint against on its MOST RECENT `get_dependencies`
    /// call. `pubgrub` calls `get_dependencies` exactly once per (package,
    /// version) decision attempt, and a consumer that is later backtracked
    /// past is always EITHER re-decided (a fresh `get_dependencies` call for
    /// the same consumer name) or the whole resolve fails outright — so
    /// "clear this consumer's previously-recorded targets, then record
    /// today's" on every call makes the running `constrainers` map
    /// self-healing: an entry from an abandoned decision (recorded, then the
    /// consumer backtracked and re-decided to a version that drops or
    /// changes the constraint) never lingers as a phantom past the consumer's
    /// next `get_dependencies` call. Mirrors the backtrack-correctness
    /// Python's `_accumulated_constrainers` was DESIGNED to have (its
    /// docstring: "only ever names constrainers that actually apply to the
    /// accepted solve state") — Rust achieves it structurally since
    /// `pubgrub`'s `DependencyProvider` callbacks expose no direct partial-
    /// solution introspection to derive it any other way.
    consumer_targets: RefCell<BTreeMap<String, Vec<String>>>,
}

impl<'a, P: PackageProvider> ProviderAdapter<'a, P> {
    fn new(provider: &'a P, strategy: Strategy) -> Self {
        ProviderAdapter {
            provider,
            strategy,
            constrainers: RefCell::new(BTreeMap::new()),
            consumer_targets: RefCell::new(BTreeMap::new()),
        }
    }
}

impl<P: PackageProvider> pubgrub::DependencyProvider for ProviderAdapter<'_, P> {
    type P = String;
    type V = Version;
    type VS = VersionSet;
    type M = String;
    // A4: version-unknown packages get strictly lowest priority — the leading
    // `bool` dominates tuple `Ord` regardless of the rest of the tuple, so a
    // version-unknown package is decided only after every reachable
    // non-version-unknown package (§3 Axis A (c): this guarantees its
    // accumulated range is complete before classification). R3 (resolver-
    // semantics RFC §4.2.1, NORMATIVE): within each class, the tie-break is
    // `Reverse` of the package's BFS-insertion `declaration_order` — smallest
    // index (earliest declared/reached from root) → highest priority — NOT
    // alphabetical name. This matches Python's `_next_undecided`, which walks
    // partial-solution assignments in that exact insertion order; alphabetical
    // name is now only the LAST-resort tie-break, for providers with no
    // declaration-order concept (every package ties at `usize::MAX`).
    type Priority = (bool, Reverse<usize>, Reverse<String>);
    type Err = ProviderError;

    fn prioritize(
        &self,
        package: &Self::P,
        _range: &Self::VS,
        _stats: &pubgrub::PackageResolutionStatistics,
    ) -> Self::Priority {
        (
            !self.provider.is_version_unknown(package),
            Reverse(self.provider.declaration_order(package)),
            Reverse(package.clone()),
        )
    }

    fn choose_version(
        &self,
        package: &Self::P,
        range: &Self::VS,
    ) -> Result<Option<Self::V>, Self::Err> {
        // A4: classify at this (last-scheduled, by `prioritize`) decision
        // point — range is guaranteed complete. `full()` → unconstrained,
        // fall through to the ordinary pick (the existing sentinel candidate
        // is trivially in-range, no panic). Non-`full()` → hard error before
        // any candidate is returned.
        if self.provider.is_version_unknown(package) && !range.is_full() {
            // R8: read back the per-consumer map (self-healed on every
            // `get_dependencies` call — see `consumer_targets`'s doc), never
            // a raw append-only history. Sorted by consumer name (BTreeMap
            // iteration) for deterministic output.
            let constrainers: Vec<(String, String)> = self
                .constrainers
                .borrow()
                .get(package)
                .map(|m| m.iter().map(|(c, s)| (c.clone(), s.clone())).collect())
                .unwrap_or_default();
            return Err(ProviderError::VersionUnknownConstrained {
                package: package.clone(),
                constrainers,
            });
        }
        let candidates: Vec<Version> = self
            .provider
            .versions(package)
            .into_iter()
            .filter(|v| range.contains(v))
            .collect();
        // B2: the provider assembles the preference from `params.prior` (an
        // O(1) lookup, per-package) — `pick_version` itself never learns
        // about lockfiles. A provider with no prior-lock concept (in-memory
        // test fakes) falls through to `None` via the trait's default
        // `preference`, so pre-B2 callers are unaffected.
        let preference = self.provider.preference(package);
        // C2: resolve the configured strategy (which may be the surface-only
        // `LowestDirect`) to a concrete per-package `EffectiveStrategy` BEFORE
        // the pick — `pick_version` never sees `Strategy::LowestDirect`.
        let strategy = effective_strategy(self.strategy, self.provider.is_root_direct(package));
        Ok(pick_version(candidates, range, strategy, preference))
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<pubgrub::Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        // `DependencyConstraints` is an ordered (P, VS) list, so merge duplicate
        // packages here: a package depending on another twice intersects the
        // constraints (the solver treats both as simultaneous requirements). A
        // BTreeMap also makes the emitted order deterministic.
        let mut merged: BTreeMap<String, VersionSet> = BTreeMap::new();
        for dep in self.provider.dependencies(package, version) {
            merged
                .entry(dep.package)
                .and_modify(|vs| *vs = vs.intersect(&dep.constraint))
                .or_insert(dep.constraint);
        }
        // A4/R8: record every non-full() constraint `package` places on
        // another package, keyed by the TARGET so RES-VERSION-UNKNOWN-
        // CONSTRAINED can read back "who constrains me" at the target's own
        // decision point. full() constraints are never load-bearing for a
        // conflict (D-A2), so they are skipped here too (mirrors the §5.2
        // refutation's own skip).
        //
        // R8: `package` (the consumer) OVERWRITES its own entries every call
        // — first clearing whatever targets it recorded on its PREVIOUS
        // `get_dependencies` call (if any), then recording today's. This is
        // what makes the map backtrack-correct: if `package` was decided,
        // recorded a constraint, then got backtracked past and re-decided to
        // a different (or no) constraint, the stale entry from the abandoned
        // decision is cleared here — never left as a phantom for a version-
        // unknown target's error message to name.
        {
            let mut constrainers = self.constrainers.borrow_mut();
            let mut consumer_targets = self.consumer_targets.borrow_mut();
            if let Some(prev_targets) = consumer_targets.remove(package) {
                for prev_target in prev_targets {
                    if let Some(m) = constrainers.get_mut(&prev_target) {
                        m.remove(package);
                    }
                }
            }
            let mut current_targets: Vec<String> = Vec::new();
            for (target, vs) in &merged {
                if vs.is_full() {
                    continue;
                }
                let cstr = vs_to_constraint_str(vs);
                constrainers
                    .entry(target.clone())
                    .or_default()
                    .insert(package.clone(), cstr);
                current_targets.push(target.clone());
            }
            if !current_targets.is_empty() {
                consumer_targets.insert(package.clone(), current_targets);
            }
        }
        Ok(pubgrub::Dependencies::Available(
            merged.into_iter().collect(),
        ))
    }
}

/// Axis B (resolver-semantics RFC §4 stage 4): a plain preference value
/// threaded into the pure pick. `None` means no preference (today's
/// behavior). `Some(v)` is the RFC's `FromLock(v)` — the prior lockfile's
/// recorded version for this package, assembled *upstream* (B2) from the
/// resolve params. The picker never learns about lockfiles, manifests, or
/// provenance; it only ever sees this plain value.
type Preference = Option<Version>;

/// Pick a version from `candidates` (already filtered to `range`) per `strategy`.
/// `None` (no candidate) makes `pubgrub` derive a "no versions" conflict and
/// backtrack — which is also how `SemVer`'s cross-major refusal surfaces.
///
/// `preference` (Axis B, RFC §4 stage 4) short-circuits the strategy
/// ordering — NOT a candidate reorder, which would be inert against the
/// order-independent `max`/lower-bound pick below. If `preference` is
/// `FromLock(v)` (i.e. `Some(v)`) and `v` survived the constraint filter
/// (`candidates.contains(v)`, which already implies `v` is in `range`), it
/// wins outright. Otherwise fall through to the ordinary strategy pick,
/// unchanged.
fn pick_version(
    candidates: Vec<Version>,
    range: &VersionSet,
    strategy: EffectiveStrategy,
    preference: Preference,
) -> Option<Version> {
    if candidates.is_empty() {
        return None;
    }
    if let Some(pref) = &preference {
        if candidates.contains(pref) {
            return Some(pref.clone());
        }
    }
    match strategy {
        EffectiveStrategy::Maxver => candidates.into_iter().max(),
        EffectiveStrategy::Minver => candidates.into_iter().min(),
        EffectiveStrategy::Semver => pick_semver(candidates, range),
    }
}

/// SemVer: the highest candidate sharing the major of the constraint's lower
/// bound (resolver-semantics §4.3.1, `_pick_semver`). No lower bound ⇒ fall back
/// to MaxVer; a lower bound with no same-major candidate ⇒ `None` (refuse the
/// cross-major jump → `pubgrub` reports the conflict).
fn pick_semver(candidates: Vec<Version>, range: &VersionSet) -> Option<Version> {
    match range.lower_bound() {
        None => candidates.into_iter().max(),
        Some(lb) => candidates.into_iter().filter(|v| v.major == lb.major).max(),
    }
}

// ---------------------------------------------------------------------------
// SolverError — the catalog-coded solve error. Constraint-parse failures use
// the uncoded `ConstraintError`.
// ---------------------------------------------------------------------------

/// Errors from solving. `SOLVE-CONFLICT` is the only solver code the
/// resolver ever wraps as `MilpaError::Solver(_)` unchanged; the `String`
/// payload is the `pubgrub` derivation-tree narration (the structured form
/// lives in the tree, mirroring how the Python impl carries a
/// `ConflictChain`).
///
/// `VersionUnknownConstrained` (A4, resolver-semantics RFC §3 Axis A (c)) is
/// the OTHER outcome `solve`/`solve_with_refutation` can return, but it is
/// never surfaced to the user as `MilpaError::Solver(_)` — the resolver
/// (which alone knows whether the package has a user-owned declaration site)
/// always intercepts this variant explicitly and rebuilds
/// `RES-VERSION-UNKNOWN-CONSTRAINED` with the branching remedy text
/// (`res_err`, not `From<SolverError>`). `code()`/`all_codes()` still cover
/// it defensively so no match here is ever silently partial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverError {
    /// No assignment satisfies the constraints.
    Conflict(String),
    /// `package` has no declared version but its accumulated range is
    /// non-`full()` at its (last-scheduled) decision point. `constrainers`
    /// names every `(consumer, constraint)` pair that contributed — never
    /// just the first (the amoxtli incident floored two packages at once).
    VersionUnknownConstrained {
        package: String,
        constrainers: Vec<(String, String)>,
    },
}

impl SolverError {
    pub fn code(&self) -> &'static str {
        match self {
            SolverError::Conflict(_) => "SOLVE-CONFLICT",
            SolverError::VersionUnknownConstrained { .. } => "RES-VERSION-UNKNOWN-CONSTRAINED",
        }
    }

    /// Every catalog code this domain can emit (companion to `code()` for
    /// error-catalog parity). Every entry MUST be a real spec slug.
    ///
    /// `RES-VERSION-UNKNOWN-CONSTRAINED` is deliberately NOT listed here: the
    /// resolver always intercepts `SolverError::VersionUnknownConstrained`
    /// before it can be wrapped as `MilpaError::Solver(_)` (see the enum doc
    /// comment), so the code never actually reaches the user via this path —
    /// it is listed once, honestly, in `CoreError::all_codes()` instead
    /// (where `res_err` actually constructs it).
    pub fn all_codes() -> &'static [&'static str] {
        &["SOLVE-CONFLICT"]
    }
}

impl std::fmt::Display for SolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolverError::Conflict(narration) => f.write_str(narration),
            SolverError::VersionUnknownConstrained { package, constrainers } => {
                write!(
                    f,
                    "{package} is version-unknown but constrained by {constrainers:?}"
                )
            }
        }
    }
}

impl std::error::Error for SolverError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // --- helpers -----------------------------------------------------------

    fn v(major: u64, minor: u64, patch: u64) -> Version {
        Version::release(major, minor, patch)
    }

    // --- Strategy ----------------------------------------------------------

    #[test]
    fn strategy_default_is_maxver() {
        assert_eq!(Strategy::default(), Strategy::Maxver);
        assert_eq!(Strategy::Maxver.as_str(), "maxver");
        assert_eq!(Strategy::Minver.as_str(), "minver");
        assert_eq!(Strategy::Semver.as_str(), "semver");
    }

    // --- B1: preference-aware pick (resolver-semantics RFC §4 stage 4) -----
    //
    // Unit-tests `pick_version` directly (not through `solve()` — B1 is
    // pick-only mechanism; feeding a real preference from the prior lockfile
    // is B2). `preference` is the RFC's `FromLock(v) | None` as a plain
    // `Option<Version>` value.

    fn pick_candidates() -> Vec<Version> {
        vec![v(1, 0, 0), v(1, 5, 0), v(2, 0, 0)]
    }

    #[test]
    fn pick_no_preference_reproduces_maxver() {
        let chosen = pick_version(
            pick_candidates(),
            &VersionSet::full(),
            EffectiveStrategy::Maxver,
            None,
        );
        assert_eq!(chosen, Some(v(2, 0, 0)));
    }

    #[test]
    fn pick_no_preference_reproduces_minver() {
        let chosen = pick_version(
            pick_candidates(),
            &VersionSet::full(),
            EffectiveStrategy::Minver,
            None,
        );
        assert_eq!(chosen, Some(v(1, 0, 0)));
    }

    #[test]
    fn pick_preference_in_range_wins_over_maxver() {
        let chosen = pick_version(
            pick_candidates(),
            &VersionSet::full(),
            EffectiveStrategy::Maxver,
            Some(v(1, 5, 0)),
        );
        assert_eq!(chosen, Some(v(1, 5, 0)));
    }

    #[test]
    fn pick_preference_in_range_wins_over_minver() {
        let chosen = pick_version(
            pick_candidates(),
            &VersionSet::full(),
            EffectiveStrategy::Minver,
            Some(v(1, 5, 0)),
        );
        assert_eq!(chosen, Some(v(1, 5, 0)));
    }

    #[test]
    fn pick_preference_out_of_range_falls_through_to_maxver() {
        let chosen = pick_version(
            pick_candidates(),
            &VersionSet::full(),
            EffectiveStrategy::Maxver,
            Some(v(9, 9, 9)),
        );
        assert_eq!(chosen, Some(v(2, 0, 0)));
    }

    #[test]
    fn pick_preference_out_of_range_falls_through_to_minver() {
        let chosen = pick_version(
            pick_candidates(),
            &VersionSet::full(),
            EffectiveStrategy::Minver,
            Some(v(9, 9, 9)),
        );
        assert_eq!(chosen, Some(v(1, 0, 0)));
    }

    /// A preference that is within `range` (the accumulated constraint) but
    /// is not one of the actual `candidates` (e.g. never enumerated / never
    /// published) is exactly the "out of range" case — it cannot bypass the
    /// real candidate list to force an otherwise-unavailable version through.
    #[test]
    fn pick_preference_not_in_candidates_even_if_in_range() {
        let chosen = pick_version(
            vec![v(1, 0, 0), v(2, 0, 0)],
            &VersionSet::gte(v(1, 0, 0)),
            EffectiveStrategy::Maxver,
            Some(v(1, 5, 0)), // in `range` but not a real candidate
        );
        assert_eq!(chosen, Some(v(2, 0, 0)));
    }

    // --- C2: LowestDirect effective-strategy precompute (resolver-semantics
    // RFC §3 Axis C / §4 stage 4, D-C2, #111) ---------------------------------
    //
    // `effective_strategy` resolves the surface-only `Strategy::LowestDirect`
    // to a concrete `EffectiveStrategy` — `Minver` for a root-direct package,
    // `Maxver` otherwise — BEFORE `pick_version` ever runs. `pick_version`'s
    // `match` above is exhaustive over exactly `EffectiveStrategy`'s three
    // variants; there is no `LowestDirect` case, and the type cannot express
    // one.

    #[test]
    fn effective_strategy_passes_through_non_lowest_direct() {
        assert_eq!(
            effective_strategy(Strategy::Maxver, true),
            EffectiveStrategy::Maxver
        );
        assert_eq!(
            effective_strategy(Strategy::Minver, false),
            EffectiveStrategy::Minver
        );
        assert_eq!(
            effective_strategy(Strategy::Semver, true),
            EffectiveStrategy::Semver
        );
    }

    #[test]
    fn effective_strategy_lowest_direct_root_direct_is_minver() {
        assert_eq!(
            effective_strategy(Strategy::LowestDirect, true),
            EffectiveStrategy::Minver
        );
    }

    #[test]
    fn effective_strategy_lowest_direct_transitive_is_maxver() {
        assert_eq!(
            effective_strategy(Strategy::LowestDirect, false),
            EffectiveStrategy::Maxver
        );
    }

    /// A provider with no root-authority concept (the trait's default
    /// `is_root_direct` — `false`) treats every package as transitive under
    /// `LowestDirect`.
    struct NoRootAuthorityProvider {
        versions_map: BTreeMap<String, Vec<Version>>,
        deps_map: BTreeMap<(String, Version), Vec<Dep>>,
    }

    impl PackageProvider for NoRootAuthorityProvider {
        fn versions(&self, package: &str) -> Vec<Version> {
            self.versions_map.get(package).cloned().unwrap_or_default()
        }
        fn dependencies(&self, package: &str, version: &Version) -> Vec<Dep> {
            self.deps_map
                .get(&(package.to_string(), version.clone()))
                .cloned()
                .unwrap_or_default()
        }
    }

    /// A synthetic provider carrying an explicit root-direct package-name set
    /// (mirrors `ResolveProvider::is_root_direct`, isolating the SOLVER-side
    /// mechanism from resolver-level root-authority construction — covered by
    /// `milpa-core`'s `resolve_c2_*` resolver-level tests instead).
    struct RootAuthorityProvider {
        versions_map: BTreeMap<String, Vec<Version>>,
        deps_map: BTreeMap<(String, Version), Vec<Dep>>,
        root_direct: BTreeSet<String>,
    }

    impl PackageProvider for RootAuthorityProvider {
        fn versions(&self, package: &str) -> Vec<Version> {
            self.versions_map.get(package).cloned().unwrap_or_default()
        }
        fn dependencies(&self, package: &str, version: &Version) -> Vec<Dep> {
            self.deps_map
                .get(&(package.to_string(), version.clone()))
                .cloned()
                .unwrap_or_default()
        }
        fn is_root_direct(&self, package: &str) -> bool {
            self.root_direct.contains(package)
        }
    }

    /// End-to-end through `solve()` — the whole point of the design
    /// deepening. A root-direct dep with multiple candidates picks the
    /// LOWEST satisfying version; a transitive dep with multiple candidates
    /// still picks the HIGHEST — under the SAME `Strategy::LowestDirect`.
    #[test]
    fn solve_lowest_direct_contrast_root_direct_minver_transitive_maxver() {
        let mut versions_map = BTreeMap::new();
        versions_map.insert("__root__".to_string(), vec![v(0, 0, 1)]);
        versions_map.insert("direct".to_string(), vec![v(1, 0, 0), v(2, 0, 0)]);
        versions_map.insert("transitive".to_string(), vec![v(1, 0, 0), v(2, 0, 0)]);

        let mut deps_map = BTreeMap::new();
        deps_map.insert(
            ("__root__".to_string(), v(0, 0, 1)),
            vec![Dep {
                package: "direct".to_string(),
                constraint: VersionSet::full(),
            }],
        );
        for ver in [v(1, 0, 0), v(2, 0, 0)] {
            deps_map.insert(
                ("direct".to_string(), ver),
                vec![Dep {
                    package: "transitive".to_string(),
                    constraint: VersionSet::full(),
                }],
            );
        }
        deps_map.insert(("transitive".to_string(), v(1, 0, 0)), vec![]);
        deps_map.insert(("transitive".to_string(), v(2, 0, 0)), vec![]);

        let mut root_direct = BTreeSet::new();
        root_direct.insert("direct".to_string());
        let provider = RootAuthorityProvider {
            versions_map,
            deps_map,
            root_direct,
        };

        let sol = solve(&provider, "__root__", v(0, 0, 1), Strategy::LowestDirect).unwrap();
        assert_eq!(sol["direct"], v(1, 0, 0)); // root-direct -> Minver
        assert_eq!(sol["transitive"], v(2, 0, 0)); // transitive -> Maxver
    }

    /// Regression: a provider with no root-authority concept treats every
    /// package as transitive, so `LowestDirect` degenerates to plain `Maxver`
    /// everywhere (the optional-hook-absence contract, mirroring A4/B2's own
    /// hook-default regression tests).
    #[test]
    fn solve_lowest_direct_no_root_authority_hook_is_all_maxver() {
        let mut versions_map = BTreeMap::new();
        versions_map.insert("__root__".to_string(), vec![v(0, 0, 1)]);
        versions_map.insert("dep".to_string(), vec![v(1, 0, 0), v(2, 0, 0)]);
        let mut deps_map = BTreeMap::new();
        deps_map.insert(
            ("__root__".to_string(), v(0, 0, 1)),
            vec![Dep {
                package: "dep".to_string(),
                constraint: VersionSet::full(),
            }],
        );
        deps_map.insert(("dep".to_string(), v(1, 0, 0)), vec![]);
        deps_map.insert(("dep".to_string(), v(2, 0, 0)), vec![]);
        let provider = NoRootAuthorityProvider {
            versions_map,
            deps_map,
        };

        let sol = solve(&provider, "__root__", v(0, 0, 1), Strategy::LowestDirect).unwrap();
        assert_eq!(sol["dep"], v(2, 0, 0));
    }

    #[test]
    fn solver_error_codes_are_stable() {
        assert_eq!(SolverError::Conflict("x".into()).code(), "SOLVE-CONFLICT");
        assert_eq!(SolverError::all_codes(), &["SOLVE-CONFLICT"]);
    }

    // --- B2: feeding prior-lock versions as preferences through `solve()` --
    // (resolver-semantics RFC §4 stage 4, Axis B — #192/#70)
    //
    // B1 (above) unit-tests `pick_version`'s short-circuit in isolation. B2's
    // job is *feeding* the preference from the prior lockfile — the
    // resolver-level wiring (`ResolveProvider::preference`) is exercised end
    // to end in `milpa-core`'s `resolver_tests.rs`; here we prove the
    // SOLVER-side threading (`solve()` → `ProviderAdapter::choose_version` →
    // `PackageProvider::preference` → `pick_version`) with a synthetic
    // in-memory provider, isolating the solver mechanism from resolver/
    // index/fetch concerns.

    /// `DictProvider` + an explicit `package -> Version` preference map.
    /// Mirrors `DictProvider`'s plain-default-trait-method pattern: a real
    /// production provider derives `preference` from the prior lockfile
    /// (`ResolveProvider::preference`); this test double just takes the
    /// answer directly.
    struct PreferenceDictProvider {
        inner: DictProvider,
        preferences: BTreeMap<String, Version>,
    }

    impl PreferenceDictProvider {
        fn new(entries: Vec<ProviderEntry<'_>>, preferences: Vec<(&str, Version)>) -> Self {
            PreferenceDictProvider {
                inner: DictProvider::new(entries),
                preferences: preferences.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            }
        }
    }

    impl PackageProvider for PreferenceDictProvider {
        fn versions(&self, package: &str) -> Vec<Version> {
            self.inner.versions(package)
        }

        fn dependencies(&self, package: &str, version: &Version) -> Vec<Dep> {
            self.inner.dependencies(package, version)
        }

        fn preference(&self, package: &str) -> Option<Version> {
            self.preferences.get(package).cloned()
        }
    }

    // RED → GREEN: a provider with NO `preference` override (plain
    // `DictProvider`) is unaffected — the trait's default `preference`
    // returns `None` unconditionally, so a fresh resolve (no prior lock) is
    // byte-for-byte unchanged. Every other `DictProvider`-based test in this
    // module is an implicit proof of this too; this test states it
    // explicitly for B2.
    #[test]
    fn provider_without_preference_override_is_unaffected() {
        let p = DictProvider::new(vec![
            (
                "root",
                vec![(v(0, 0, 1), vec![Dep::new("dep", VersionSet::full())])],
            ),
            ("dep", vec![(v(1, 0, 0), vec![]), (v(2, 0, 0), vec![])]),
        ]);
        let sol = solve(&p, "root", v(0, 0, 1), Strategy::Maxver).unwrap();
        assert_eq!(sol.get("dep"), Some(&v(2, 0, 0)));
    }

    // RED → GREEN: a locked version still within the accumulated constraint
    // wins over the strategy's newest pick — the minimal-change default.
    #[test]
    fn locked_version_wins_when_still_satisfiable() {
        let p = PreferenceDictProvider::new(
            vec![
                (
                    "root",
                    vec![(v(0, 0, 1), vec![Dep::new("dep", VersionSet::full())])],
                ),
                (
                    "dep",
                    vec![
                        (v(1, 0, 0), vec![]),
                        (v(1, 5, 0), vec![]),
                        (v(2, 0, 0), vec![]),
                    ],
                ),
            ],
            vec![("dep", v(1, 5, 0))],
        );
        let sol = solve(&p, "root", v(0, 0, 1), Strategy::Maxver).unwrap();
        assert_eq!(sol.get("dep"), Some(&v(1, 5, 0)));
    }

    // RED → GREEN: a locked version no longer satisfying the accumulated
    // constraint is FORCED to move — the preference falls through to the
    // ordinary strategy pick over the surviving candidates.
    #[test]
    fn locked_version_forced_out_when_no_longer_satisfiable() {
        let p = PreferenceDictProvider::new(
            vec![
                (
                    "root",
                    vec![(
                        v(0, 0, 1),
                        vec![Dep::new("dep", VersionSet::from_constraint(Some(">=2.0.0")).unwrap())],
                    )],
                ),
                (
                    "dep",
                    vec![
                        (v(1, 0, 0), vec![]),
                        (v(1, 5, 0), vec![]),
                        (v(2, 0, 0), vec![]),
                    ],
                ),
            ],
            vec![("dep", v(1, 0, 0))], // no longer >= 2.0.0
        );
        let sol = solve(&p, "root", v(0, 0, 1), Strategy::Maxver).unwrap();
        assert_eq!(sol.get("dep"), Some(&v(2, 0, 0)));
    }

    // RED → GREEN (the #192 core win): bumping ONE dep's constraint so its
    // locked version no longer satisfies forces ONLY that dep to move; an
    // unrelated, unconstrained dep stays at its locked version even though a
    // newer version exists and a fresh maxver resolve would pick it.
    #[test]
    fn bump_one_dep_leaves_unrelated_dep_pinned() {
        let p = PreferenceDictProvider::new(
            vec![
                (
                    "root",
                    vec![(
                        v(0, 0, 1),
                        vec![
                            Dep::new("bumped", VersionSet::from_constraint(Some(">=2.0.0")).unwrap()),
                            Dep::new("unrelated", VersionSet::full()),
                        ],
                    )],
                ),
                ("bumped", vec![(v(1, 0, 0), vec![]), (v(2, 0, 0), vec![])]),
                ("unrelated", vec![(v(1, 0, 0), vec![]), (v(2, 0, 0), vec![])]),
            ],
            vec![("bumped", v(1, 0, 0)), ("unrelated", v(1, 0, 0))],
        );
        let sol = solve(&p, "root", v(0, 0, 1), Strategy::Maxver).unwrap();
        assert_eq!(sol.get("bumped"), Some(&v(2, 0, 0))); // forced: 1.0.0 no longer >= 2.0.0
        assert_eq!(sol.get("unrelated"), Some(&v(1, 0, 0))); // stays locked, NOT newest-wins-bumped
    }

    // --- parse_version -----------------------------------------------------

    #[test]
    fn parse_plain_and_v_prefixed() {
        assert_eq!(parse_version("1.2.3"), Some(v(1, 2, 3)));
        assert_eq!(parse_version("v0.5.1"), Some(v(0, 5, 1)));
        assert_eq!(parse_version("  1.0.0  "), Some(v(1, 0, 0)));
    }

    #[test]
    fn parse_rejects_non_canonical() {
        assert_eq!(parse_version("nimble-1.2.3"), None);
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("1.2.x"), None);
        assert_eq!(parse_version("1.2.3-"), None);
        assert_eq!(parse_version("1.2.3+"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn parse_oversized_and_overflowing_component_returns_none() {
        // R10 (cross-impl parity): a crafted tag/version with an oversized
        // or u64-overflowing numeric component (attacker-controlled input —
        // a git tag, a `.nimble`/`milpa.kdl` `version=` string, a registry
        // index entry) must return `None`, never panic or wrap. Rust already
        // does this by construction (`str::parse::<u64>()` fails closed on
        // overflow); this pins the behavior and matches Python's
        // `parse_version`, which is bounded to the same u64 ceiling so a
        // crafted digit run that overflows CPython's own int<->str
        // conversion limit (~4300 digits) can't diverge between impls.
        let huge = "9".repeat(6000);
        assert_eq!(parse_version(&format!("v{huge}.0.0")), None);
        let one_past_u64_max = (u64::MAX as u128 + 1).to_string();
        assert_eq!(parse_version(&format!("{one_past_u64_max}.0.0")), None);
        // The boundary itself is still valid.
        assert_eq!(parse_version(&format!("{}.0.0", u64::MAX)), Some(v(u64::MAX, 0, 0)));
    }

    #[test]
    fn parse_prerelease_and_build() {
        let parsed = parse_version("1.0.0-alpha.1+build.7").unwrap();
        assert_eq!(parsed.major, 1);
        assert_eq!(
            parsed.pre,
            vec![PreId::Alpha("alpha".into()), PreId::Numeric(1)]
        );
        assert_eq!(parsed.build, "build.7");
    }

    #[test]
    fn parse_prerelease_with_internal_hyphen() {
        // The first `-` delimits; further hyphens stay inside the identifier.
        let parsed = parse_version("1.0.0-x-y.z").unwrap();
        assert_eq!(
            parsed.pre,
            vec![PreId::Alpha("x-y".into()), PreId::Alpha("z".into())]
        );
    }

    // --- format_version_str (round trip) -----------------------------------

    #[test]
    fn format_round_trips() {
        for s in ["1.2.3", "0.0.1", "1.0.0-alpha.1", "2.3.4-rc.1+build.9"] {
            let parsed = parse_version(s).unwrap();
            assert_eq!(format_version_str(&parsed), s, "round-trip {s}");
        }
    }

    #[test]
    fn format_drops_v_prefix_and_normalizes_leading_zeros() {
        assert_eq!(
            format_version_str(&parse_version("v1.2.3").unwrap()),
            "1.2.3"
        );
        assert_eq!(
            format_version_str(&parse_version("1.02.3").unwrap()),
            "1.2.3"
        );
    }

    // --- Version ordering (semver) -----------------------------------------

    #[test]
    fn prerelease_orders_below_release() {
        assert!(parse_version("1.0.0-alpha").unwrap() < v(1, 0, 0));
        assert!(parse_version("1.0.0-alpha.1").unwrap() < parse_version("1.0.0-alpha.2").unwrap());
        // numeric < alphanumeric (§11.4.3)
        assert!(parse_version("1.0.0-1").unwrap() < parse_version("1.0.0-alpha").unwrap());
        // larger identifier set wins when prefixes equal (§11.4.4)
        assert!(parse_version("1.0.0-alpha").unwrap() < parse_version("1.0.0-alpha.1").unwrap());
    }

    // --- VersionSet basics -------------------------------------------------

    #[test]
    fn gte_contains() {
        let s = VersionSet::gte(v(0, 5, 0));
        assert!(s.contains(&v(0, 5, 0)));
        assert!(s.contains(&v(1, 0, 0)));
        assert!(!s.contains(&v(0, 4, 9)));
    }

    #[test]
    fn from_constraint_shapes() {
        let full = VersionSet::from_constraint(None).unwrap();
        assert!(full.contains(&v(0, 0, 0)) && full.contains(&v(99, 99, 99)));

        let any_kw = VersionSet::from_constraint(Some("any version")).unwrap();
        assert!(any_kw.contains(&v(0, 0, 0)));

        let gte = VersionSet::from_constraint(Some(">= 0.5.0")).unwrap();
        assert!(gte.contains(&v(0, 5, 0)) && gte.contains(&v(1, 0, 0)));
        assert!(!gte.contains(&v(0, 4, 0)));

        let eq = VersionSet::from_constraint(Some("== 0.5.0")).unwrap();
        assert!(eq.contains(&v(0, 5, 0)) && !eq.contains(&v(0, 5, 1)));

        let rng = VersionSet::from_constraint(Some(">= 0.5.0 & < 1.0.0")).unwrap();
        assert!(rng.contains(&v(0, 5, 0)) && rng.contains(&v(0, 9, 9)));
        assert!(!rng.contains(&v(1, 0, 0)) && !rng.contains(&v(0, 4, 9)));
    }

    #[test]
    fn from_constraint_unparseable_errors() {
        assert!(VersionSet::from_constraint(Some(">= not.a.version")).is_err());
        assert!(VersionSet::from_constraint(Some("garbage")).is_err());
    }

    #[test]
    fn eq_is_closed_singleton_excludes_prerelease() {
        // P3.1b: eq(1.2.4) must NOT contain 1.2.4-rc.1.
        let vs = VersionSet::eq(v(1, 2, 4));
        assert!(vs.contains(&v(1, 2, 4)));
        assert!(!vs.contains(&parse_version("1.2.4-rc.1").unwrap()));
    }

    #[test]
    fn tilde_and_caret() {
        let t = VersionSet::from_constraint(Some("~ 1.2.3")).unwrap();
        assert!(t.contains(&v(1, 2, 3)) && t.contains(&v(1, 2, 9)));
        assert!(!t.contains(&v(1, 3, 0)) && !t.contains(&v(1, 2, 2)));

        let c = VersionSet::from_constraint(Some("^ 1.2.3")).unwrap();
        assert!(c.contains(&v(1, 2, 3)) && c.contains(&v(1, 9, 9)));
        assert!(!c.contains(&v(2, 0, 0)));

        let c0 = VersionSet::from_constraint(Some("^ 0.2.3")).unwrap();
        assert!(c0.contains(&v(0, 2, 9)) && !c0.contains(&v(0, 3, 0)));

        let c00 = VersionSet::from_constraint(Some("^ 0.0.3")).unwrap();
        assert!(c00.contains(&v(0, 0, 3)) && !c00.contains(&v(0, 0, 4)));
    }

    #[test]
    fn not_equal_and_disjunction() {
        let ne = VersionSet::from_constraint(Some("!= 1.2.3")).unwrap();
        assert!(ne.contains(&v(1, 2, 4)) && ne.contains(&v(1, 2, 2)));
        assert!(!ne.contains(&v(1, 2, 3)));
        assert!(ne.contains(&parse_version("1.2.3-rc.1").unwrap()));

        for sep in [" || ", " | "] {
            let s = VersionSet::from_constraint(Some(&format!(">= 1.0.0 & < 2.0.0{sep}>= 3.0.0")))
                .unwrap();
            assert!(s.contains(&v(1, 5, 0)) && s.contains(&v(3, 1, 0)));
            assert!(!s.contains(&v(2, 5, 0)), "gap between arms (sep {sep:?})");
        }
    }

    #[test]
    fn complement_examples() {
        let c = VersionSet::gte(v(0, 5, 0)).complement();
        assert!(c.contains(&v(0, 4, 9)) && !c.contains(&v(0, 5, 0)) && !c.contains(&v(1, 0, 0)));

        let rng = VersionSet::from_constraint(Some(">= 0.5.0 & < 1.0.0"))
            .unwrap()
            .complement();
        assert!(rng.contains(&v(0, 4, 9)) && rng.contains(&v(1, 0, 0)));
        assert!(!rng.contains(&v(0, 5, 0)) && !rng.contains(&v(0, 9, 9)));

        assert!(VersionSet::empty().complement().contains(&v(0, 0, 0)));
        assert!(!VersionSet::full().complement().contains(&v(0, 0, 0)));
    }

    #[test]
    fn lower_bound_semver_input() {
        assert_eq!(
            VersionSet::from_constraint(Some(">= 1.2.0"))
                .unwrap()
                .lower_bound(),
            Some(v(1, 2, 0))
        );
        // unbounded below ⇒ None (semver strategy falls back to maxver)
        assert_eq!(
            VersionSet::from_constraint(Some("< 5.0.0"))
                .unwrap()
                .lower_bound(),
            None
        );
    }

    // --- Hypothesis-found regression (#63) ---------------------------------

    #[test]
    fn union_lt_with_full_is_full_regression_63() {
        // lt(v).union(full()) once produced two -∞ intervals; the lo=None merge
        // gap must collapse to full().
        let result = VersionSet::lt(v(0, 0, 0)).union(&VersionSet::full());
        assert_eq!(result, VersionSet::full());
    }

    // --- bounded exhaustive algebra ("property" without a fuzz dep) ---------

    /// All primitive sets over a tiny version domain — enough boundary cases to
    /// exercise the interval algebra exhaustively while staying deterministic
    /// and dependency-free (the Python suite uses Hypothesis; here we enumerate).
    fn primitive_sets() -> Vec<VersionSet> {
        let mut sets = vec![VersionSet::full(), VersionSet::empty()];
        for a in 0..3u64 {
            for b in 0..3u64 {
                let ver = v(a, b, 0);
                sets.push(VersionSet::gte(ver.clone()));
                sets.push(VersionSet::gt(ver.clone()));
                sets.push(VersionSet::lt(ver.clone()));
                sets.push(VersionSet::lte(ver.clone()));
                sets.push(VersionSet::eq(ver));
            }
        }
        sets
    }

    fn sample_versions() -> Vec<Version> {
        let mut out = Vec::new();
        for a in 0..3u64 {
            for b in 0..3u64 {
                out.push(v(a, b, 0));
            }
        }
        out
    }

    #[test]
    fn algebraic_laws_hold_exhaustively() {
        let sets = primitive_sets();
        let full = VersionSet::full();
        let empty = VersionSet::empty();
        for a in &sets {
            // idempotency + identity + involution
            assert_eq!(a.intersect(a), *a, "intersect idempotent");
            assert_eq!(a.union(a), *a, "union idempotent");
            assert_eq!(a.intersect(&full), *a, "∩ full identity");
            assert_eq!(a.union(&empty), *a, "∪ empty identity");
            assert_eq!(a.intersect(&empty), empty, "∩ empty annihilates");
            assert_eq!(a.union(&full), full, "∪ full universe");
            assert_eq!(a.complement().complement(), *a, "double complement");
            // contains ⇔ ∩ eq(v) non-empty
            for ver in sample_versions() {
                let via_contains = a.contains(&ver);
                let via_intersect = !a.intersect(&VersionSet::eq(ver)).is_empty();
                assert_eq!(via_contains, via_intersect, "contains via intersect");
            }
        }
    }

    #[test]
    fn binary_laws_hold_exhaustively() {
        // A bounded subset keeps the O(n²)/O(n³) loops fast.
        let sets: Vec<VersionSet> = primitive_sets().into_iter().take(10).collect();
        for a in &sets {
            for b in &sets {
                assert_eq!(a.intersect(b), b.intersect(a), "∩ commutative");
                assert_eq!(a.union(b), b.union(a), "∪ commutative");
                // De Morgan
                assert_eq!(
                    a.intersect(b).complement(),
                    a.complement().union(&b.complement()),
                    "De Morgan ∩"
                );
                assert_eq!(
                    a.union(b).complement(),
                    a.complement().intersect(&b.complement()),
                    "De Morgan ∪"
                );
                // subset agreement
                assert_eq!(
                    a.is_subset_of(b),
                    a.intersect(b) == *a,
                    "subset via intersect"
                );
            }
        }
    }

    // --- solver core (S7a) -------------------------------------------------

    /// In-test [`PackageProvider`] backed by a static map (mirrors the Python
    /// `DictProvider`): package → version → its dependency list.
    /// `(package, [(version, deps)])` — the literal shape the tests build.
    type ProviderEntry<'a> = (&'a str, Vec<(Version, Vec<Dep>)>);

    struct DictProvider {
        data: BTreeMap<String, BTreeMap<Version, Vec<Dep>>>,
    }

    impl DictProvider {
        fn new(entries: Vec<ProviderEntry<'_>>) -> Self {
            let mut data = BTreeMap::new();
            for (pkg, versions) in entries {
                data.insert(pkg.to_string(), versions.into_iter().collect());
            }
            DictProvider { data }
        }
    }

    impl PackageProvider for DictProvider {
        fn versions(&self, package: &str) -> Vec<Version> {
            self.data
                .get(package)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default()
        }

        fn dependencies(&self, package: &str, version: &Version) -> Vec<Dep> {
            self.data
                .get(package)
                .and_then(|m| m.get(version))
                .cloned()
                .unwrap_or_default()
        }
    }

    fn require(package: &str, constraint: &str) -> Dep {
        Dep::new(
            package,
            VersionSet::from_constraint(Some(constraint)).unwrap(),
        )
    }

    fn solution(pairs: &[(&str, Version)]) -> BTreeMap<String, Version> {
        pairs
            .iter()
            .map(|(p, v)| (p.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn solve_single_root_no_deps() {
        let p = DictProvider::new(vec![("root", vec![(v(1, 0, 0), vec![])])]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(sol, solution(&[("root", v(1, 0, 0))]));
    }

    #[test]
    fn solve_single_named_dep_one_version() {
        let p = DictProvider::new(vec![
            (
                "root",
                vec![(v(1, 0, 0), vec![Dep::new("foo", VersionSet::full())])],
            ),
            ("foo", vec![(v(1, 0, 0), vec![])]),
        ]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(sol, solution(&[("root", v(1, 0, 0)), ("foo", v(1, 0, 0))]));
    }

    #[test]
    fn solve_picks_highest_matching_version() {
        let p = DictProvider::new(vec![
            ("root", vec![(v(1, 0, 0), vec![require("foo", ">= 0.5.0")])]),
            (
                "foo",
                vec![
                    (v(0, 4, 0), vec![]),
                    (v(0, 5, 0), vec![]),
                    (v(0, 6, 0), vec![]),
                    (v(1, 0, 0), vec![]),
                ],
            ),
        ]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(sol["foo"], v(1, 0, 0));
    }

    #[test]
    fn solve_unifies_compatible_constraints_across_packages() {
        let p = DictProvider::new(vec![
            (
                "root",
                vec![(
                    v(1, 0, 0),
                    vec![
                        Dep::new("a", VersionSet::full()),
                        Dep::new("b", VersionSet::full()),
                    ],
                )],
            ),
            ("a", vec![(v(1, 0, 0), vec![require("shared", ">= 0.5.0")])]),
            ("b", vec![(v(1, 0, 0), vec![require("shared", "< 1.0.0")])]),
            (
                "shared",
                vec![
                    (v(0, 5, 0), vec![]),
                    (v(0, 9, 0), vec![]),
                    (v(1, 0, 0), vec![]),
                ],
            ),
        ]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        // Intersection [0.5.0, 1.0.0) → highest matching is 0.9.0.
        assert_eq!(sol["shared"], v(0, 9, 0));
    }

    #[test]
    fn solve_incompatible_constraints_conflict_names_package() {
        let p = DictProvider::new(vec![
            (
                "root",
                vec![(
                    v(1, 0, 0),
                    vec![
                        Dep::new("a", VersionSet::full()),
                        Dep::new("b", VersionSet::full()),
                    ],
                )],
            ),
            ("a", vec![(v(1, 0, 0), vec![require("shared", ">= 1.0.0")])]),
            ("b", vec![(v(1, 0, 0), vec![require("shared", "< 1.0.0")])]),
            ("shared", vec![(v(0, 9, 0), vec![]), (v(1, 0, 0), vec![])]),
        ]);
        let err = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap_err();
        assert_eq!(err.code(), "SOLVE-CONFLICT");
        // The narration (pubgrub's derivation) must implicate the conflict point.
        let msg = err.to_string();
        assert!(msg.contains("shared"), "narration must name shared: {msg}");
    }

    #[test]
    fn solve_diamond_conflict_narration_names_dependers() {
        let p = DictProvider::new(vec![
            (
                "root",
                vec![(
                    v(1, 0, 0),
                    vec![
                        Dep::new("a", VersionSet::full()),
                        Dep::new("b", VersionSet::full()),
                    ],
                )],
            ),
            ("a", vec![(v(1, 0, 0), vec![require("shared", ">= 1.0.0")])]),
            ("b", vec![(v(1, 0, 0), vec![require("shared", "< 1.0.0")])]),
            ("shared", vec![(v(0, 9, 0), vec![]), (v(1, 0, 0), vec![])]),
        ]);
        let msg = solve(&p, "root", v(1, 0, 0), Strategy::Maxver)
            .unwrap_err()
            .to_string();
        // The diamond's two dependers and the shared consequent all appear.
        for needle in ["a", "b", "shared"] {
            assert!(
                msg.contains(needle),
                "narration must mention {needle}: {msg}"
            );
        }
    }

    #[test]
    fn solve_missing_dep_conflict_names_the_dep() {
        let p = DictProvider::new(vec![(
            "root",
            vec![(
                v(1, 0, 0),
                vec![Dep::new("missing_pkg", VersionSet::full())],
            )],
        )]);
        let err = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap_err();
        assert_eq!(err.code(), "SOLVE-CONFLICT");
        assert!(
            err.to_string().contains("missing_pkg"),
            "narration must name the missing package: {err}"
        );
    }

    #[test]
    fn solve_cycle_resolves_without_hanging() {
        // a→b→a, each with one version; the cycle resolves.
        let p = DictProvider::new(vec![
            (
                "a",
                vec![(v(1, 0, 0), vec![Dep::new("b", VersionSet::full())])],
            ),
            (
                "b",
                vec![(v(1, 0, 0), vec![Dep::new("a", VersionSet::full())])],
            ),
        ]);
        let sol = solve(&p, "a", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(sol, solution(&[("a", v(1, 0, 0)), ("b", v(1, 0, 0))]));
    }

    #[test]
    fn solve_backtracks_to_compatible_version() {
        // a@2 requires b>=2 (no such b); the solver must backtrack to a@1.
        let p = DictProvider::new(vec![
            (
                "root",
                vec![(v(1, 0, 0), vec![Dep::new("a", VersionSet::full())])],
            ),
            (
                "a",
                vec![
                    (v(1, 0, 0), vec![require("b", ">= 1.0.0")]),
                    (v(2, 0, 0), vec![require("b", ">= 2.0.0")]),
                ],
            ),
            ("b", vec![(v(1, 0, 0), vec![])]),
        ]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(sol["a"], v(1, 0, 0));
        assert_eq!(sol["b"], v(1, 0, 0));
    }

    #[test]
    fn solve_minver_picks_lowest_satisfying() {
        let p = DictProvider::new(vec![
            ("root", vec![(v(1, 0, 0), vec![require("foo", ">= 0.5.0")])]),
            (
                "foo",
                vec![
                    (v(0, 4, 0), vec![]),
                    (v(0, 5, 0), vec![]),
                    (v(0, 6, 0), vec![]),
                    (v(1, 0, 0), vec![]),
                ],
            ),
        ]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Minver).unwrap();
        assert_eq!(sol["foo"], v(0, 5, 0));
    }

    #[test]
    fn solve_semver_locks_to_lower_bound_major() {
        let p = DictProvider::new(vec![
            ("root", vec![(v(1, 0, 0), vec![require("foo", ">= 1.2.0")])]),
            (
                "foo",
                vec![
                    (v(1, 2, 0), vec![]),
                    (v(1, 5, 0), vec![]),
                    (v(2, 0, 0), vec![]),
                    (v(2, 3, 0), vec![]),
                ],
            ),
        ]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Semver).unwrap();
        assert_eq!(sol["foo"], v(1, 5, 0));
    }

    #[test]
    fn solve_semver_unbounded_falls_back_to_maxver() {
        let p = DictProvider::new(vec![
            ("root", vec![(v(1, 0, 0), vec![require("foo", "< 5.0.0")])]),
            (
                "foo",
                vec![
                    (v(1, 0, 0), vec![]),
                    (v(2, 0, 0), vec![]),
                    (v(3, 0, 0), vec![]),
                    (v(4, 0, 0), vec![]),
                ],
            ),
        ]);
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Semver).unwrap();
        assert_eq!(sol["foo"], v(4, 0, 0));
    }

    #[test]
    fn solve_semver_rejects_cross_major_only() {
        let p = DictProvider::new(vec![
            ("root", vec![(v(1, 0, 0), vec![require("foo", ">= 1.0.0")])]),
            ("foo", vec![(v(2, 0, 0), vec![]), (v(2, 5, 0), vec![])]),
        ]);
        let err = solve(&p, "root", v(1, 0, 0), Strategy::Semver).unwrap_err();
        assert_eq!(err.code(), "SOLVE-CONFLICT");
    }

    // -------------------------------------------------------------------
    // R3 (resolver-semantics RFC §4.2.1, NORMATIVE): `prioritize`'s
    // tie-break must be BFS-insertion `declaration_order`, not alphabetical
    // package name — the same ambiguous-diamond shape as conformance
    // fixture-444-declaration-order-tiebreak, exercised directly at the
    // solver level (no fetch/resolver plumbing).
    // -------------------------------------------------------------------

    struct DeclOrderProvider {
        inner: DictProvider,
        order: BTreeMap<String, usize>,
    }

    impl PackageProvider for DeclOrderProvider {
        fn versions(&self, package: &str) -> Vec<Version> {
            self.inner.versions(package)
        }
        fn dependencies(&self, package: &str, version: &Version) -> Vec<Dep> {
            self.inner.dependencies(package, version)
        }
        fn declaration_order(&self, package: &str) -> usize {
            self.order.get(package).copied().unwrap_or(usize::MAX)
        }
    }

    /// "zeta" and "alpha" each have an ambiguous 2-version choice that forks
    /// on "shared": zeta@2.0.0 requires shared<=1.0.0, alpha@2.0.0 requires
    /// shared>=2.0.0 — mutually exclusive, so only ONE of the two can keep
    /// its max version once "shared"'s accumulated range would otherwise go
    /// empty; the other gets backtracked to 1.0.0 (no constraint on shared).
    /// Whichever is DECIDED FIRST wins — this is exactly the tie-break R3
    /// fixes.
    fn ambiguous_diamond() -> DictProvider {
        DictProvider::new(vec![
            (
                "root",
                vec![(
                    v(1, 0, 0),
                    vec![
                        Dep::new("zeta", VersionSet::full()),
                        Dep::new("alpha", VersionSet::full()),
                    ],
                )],
            ),
            (
                "zeta",
                vec![
                    (v(2, 0, 0), vec![require("shared", "<= 1.0.0")]),
                    (v(1, 0, 0), vec![]),
                ],
            ),
            (
                "alpha",
                vec![
                    (v(2, 0, 0), vec![require("shared", ">= 2.0.0")]),
                    (v(1, 0, 0), vec![]),
                ],
            ),
            ("shared", vec![(v(1, 0, 0), vec![]), (v(2, 0, 0), vec![])]),
        ])
    }

    #[test]
    fn solve_prioritizes_declaration_order_over_alphabetical_name() {
        // zeta declared FIRST (index 0), alpha SECOND (index 1) — matches
        // conformance fixture-444's manifest (`deps { zeta; alpha }`).
        // Alphabetically alpha < zeta, so a name tie-break would pick the
        // OPPOSITE winner; declaration order must make zeta win.
        let p = DeclOrderProvider {
            inner: ambiguous_diamond(),
            order: BTreeMap::from([("zeta".to_string(), 0), ("alpha".to_string(), 1)]),
        };
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(
            sol["zeta"],
            v(2, 0, 0),
            "declaration-order-first package must win its max version: {sol:?}"
        );
        assert_eq!(
            sol["alpha"],
            v(1, 0, 0),
            "declaration-order-second package must roll back: {sol:?}"
        );
        assert_eq!(sol["shared"], v(1, 0, 0));
    }

    #[test]
    fn solve_reversed_declaration_order_flips_the_canonical_solution() {
        // SAME graph, order reversed (alpha declared first this time) —
        // proves the tie-break is genuinely order-driven (not a hidden
        // per-name bias): whichever package's declaration_order is smaller
        // wins, regardless of which name it is.
        let p = DeclOrderProvider {
            inner: ambiguous_diamond(),
            order: BTreeMap::from([("alpha".to_string(), 0), ("zeta".to_string(), 1)]),
        };
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(sol["alpha"], v(2, 0, 0));
        assert_eq!(sol["zeta"], v(1, 0, 0));
        assert_eq!(sol["shared"], v(2, 0, 0));
    }

    #[test]
    fn solve_falls_back_to_alphabetical_name_without_declaration_order() {
        // Plain `DictProvider` has no `declaration_order` override — every
        // package ties at the trait's `usize::MAX` default, so `prioritize`
        // falls through to its LAST-resort name tie-break unchanged
        // (byte-for-byte the pre-R3 behavior): alphabetically-first "alpha"
        // decides before "zeta" and wins.
        let p = ambiguous_diamond();
        let sol = solve(&p, "root", v(1, 0, 0), Strategy::Maxver).unwrap();
        assert_eq!(sol["alpha"], v(2, 0, 0));
        assert_eq!(sol["zeta"], v(1, 0, 0));
        assert_eq!(sol["shared"], v(2, 0, 0));
    }

    // -------------------------------------------------------------------
    // R8: `constrainers` must be backtrack-correct — a consumer decided,
    // recording a constraint, then backtracked past and re-decided
    // differently, must NOT leave a phantom entry for a version-unknown
    // target's error message to name.
    // -------------------------------------------------------------------

    /// `DictProvider` + an explicit version-unknown package-name set (A4),
    /// mirroring the Python test double `VersionUnknownDictProvider`
    /// (impls/python/tests/test_solver.py) — isolates the SOLVER-side
    /// mechanism from resolver-level concerns (candidate labeling, lazy
    /// stub materialization).
    struct VersionUnknownDictProvider {
        inner: DictProvider,
        version_unknown_names: BTreeSet<String>,
    }

    impl PackageProvider for VersionUnknownDictProvider {
        fn versions(&self, package: &str) -> Vec<Version> {
            self.inner.versions(package)
        }
        fn dependencies(&self, package: &str, version: &Version) -> Vec<Dep> {
            self.inner.dependencies(package, version)
        }
        fn is_version_unknown(&self, package: &str) -> bool {
            self.version_unknown_names.contains(package)
        }
    }

    #[test]
    fn version_unknown_constrained_names_real_constrainer_not_phantom_after_backtrack() {
        // root -> A (full), C (full, version-unknown target).
        // A has two candidates:
        //   A@2.0.0 depends on C >= 5.0.0 (a REAL-looking constraint — but
        //     this decision gets abandoned) AND Z >= 9.0.0 (Z's only version
        //     is 1.0.0, so this is impossible and forces a backtrack of A's
        //     own decision).
        //   A@1.0.0 depends on C <= 8.0.0 (the ONE constraint that survives
        //     to the final, accepted solve state).
        // Pre-R8, Rust's never-pruned `constrainers` map would ALSO retain
        // A's abandoned ">=5.0.0" entry from the first (backtracked) decision
        // alongside the real "<=8.0.0" one. Post-R8, `get_dependencies`
        // re-decides A@1.0.0 and OVERWRITES A's previously-recorded targets,
        // clearing the phantom.
        let p = VersionUnknownDictProvider {
            inner: DictProvider::new(vec![
                (
                    "root",
                    vec![(
                        v(0, 0, 1),
                        vec![Dep::new("A", VersionSet::full()), Dep::new("C", VersionSet::full())],
                    )],
                ),
                (
                    "A",
                    vec![
                        (
                            v(2, 0, 0),
                            vec![require("C", ">= 5.0.0"), require("Z", ">= 9.0.0")],
                        ),
                        (v(1, 0, 0), vec![require("C", "<= 8.0.0")]),
                    ],
                ),
                ("C", vec![(v(1, 0, 0), vec![])]),
                ("Z", vec![(v(1, 0, 0), vec![])]),
            ]),
            version_unknown_names: BTreeSet::from(["C".to_string()]),
        };
        let err = solve(&p, "root", v(0, 0, 1), Strategy::Maxver).unwrap_err();
        match err {
            SolverError::VersionUnknownConstrained { package, constrainers } => {
                assert_eq!(package, "C");
                assert_eq!(
                    constrainers,
                    vec![("A".to_string(), "<=8.0.0".to_string())],
                    "must name ONLY the real, final constrainer — no phantom from A's \
                     abandoned 2.0.0 decision: {constrainers:?}"
                );
            }
            other => panic!("expected VersionUnknownConstrained, got {other:?}"),
        }
    }

    #[test]
    fn version_unknown_constrained_enumerates_multiple_real_constrainers() {
        // Mirrors conformance fixture-419 (A4 multi-constrainer): two
        // INDEPENDENT, non-conflicting consumers each floor the same
        // version-unknown target — no backtracking here, both must survive.
        let p = VersionUnknownDictProvider {
            inner: DictProvider::new(vec![
                (
                    "root",
                    vec![(
                        v(0, 0, 1),
                        vec![
                            Dep::new("bar", VersionSet::full()),
                            Dep::new("baz", VersionSet::full()),
                            Dep::new("foo", VersionSet::full()),
                        ],
                    )],
                ),
                ("bar", vec![(v(1, 0, 0), vec![require("foo", ">= 0.2.8")])]),
                ("baz", vec![(v(1, 0, 0), vec![require("foo", "<= 0.9.0")])]),
                ("foo", vec![(v(0, 0, 1), vec![])]),
            ]),
            version_unknown_names: BTreeSet::from(["foo".to_string()]),
        };
        let err = solve(&p, "root", v(0, 0, 1), Strategy::Maxver).unwrap_err();
        match err {
            SolverError::VersionUnknownConstrained { package, constrainers } => {
                assert_eq!(package, "foo");
                let got: BTreeSet<(String, String)> = constrainers.into_iter().collect();
                assert_eq!(
                    got,
                    BTreeSet::from([
                        ("bar".to_string(), ">=0.2.8".to_string()),
                        ("baz".to_string(), "<=0.9.0".to_string()),
                    ])
                );
            }
            other => panic!("expected VersionUnknownConstrained, got {other:?}"),
        }
    }
}
