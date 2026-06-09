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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Strategy {
    #[default]
    Maxver,
    Minver,
    Semver,
}

impl Strategy {
    /// Canonical lockfile spelling (`strategy "maxver"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Strategy::Maxver => "maxver",
            Strategy::Minver => "minver",
            Strategy::Semver => "semver",
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
pub fn format_version_str(v: &Version) -> String {
    let mut s = format!("{}.{}.{}", v.major, v.minor, v.patch);
    if !v.pre.is_empty() {
        s.push('-');
        let pre: Vec<String> = v
            .pre
            .iter()
            .map(|id| match id {
                PreId::Numeric(n) => n.to_string(),
                PreId::Alpha(a) => a.clone(),
            })
            .collect();
        s.push_str(&pre.join("."));
    }
    if !v.build.is_empty() {
        s.push('+');
        s.push_str(&v.build);
    }
    s
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
// SolverError — the catalog-coded solve error (S7 wires the PubGrub loop that
// raises it). Constraint-parse failures use the uncoded `ConstraintError`.
// ---------------------------------------------------------------------------

/// Errors from solving. `SOLVE-CONFLICT` is the only solver code in
/// `docs/spec/errors.md` (unsatisfiable constraints). The PubGrub loop + the
/// structured conflict chain it carries land in S7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverError {
    /// No assignment satisfies the constraints.
    Conflict(String),
}

impl SolverError {
    pub fn code(&self) -> &'static str {
        match self {
            SolverError::Conflict(_) => "SOLVE-CONFLICT",
        }
    }

    /// Every catalog code this domain can emit (companion to `code()` for
    /// error-catalog parity). Every entry MUST be a real spec slug.
    pub fn all_codes() -> &'static [&'static str] {
        &["SOLVE-CONFLICT"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn solver_error_codes_are_stable() {
        assert_eq!(SolverError::Conflict("x".into()).code(), "SOLVE-CONFLICT");
        assert_eq!(SolverError::all_codes(), &["SOLVE-CONFLICT"]);
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
}
