//! `.nimble` line-form compat parser (manifest-grammar §5; mirrors
//! `milpa/nimble_parse.py`).
//!
//! `.nimble` files are NimScript (Turing-complete Nim); milpa never executes
//! them — the no-code-execution rule is structural, not best-effort. This is a
//! heuristic line scan that extracts the `requires` and `srcDir` lines in the
//! four real-world forms (single-line, comma-separated, multi-line
//! continuation, multiple `requires` statements). `when` blocks are **not**
//! evaluated: every `requires` is included unconditionally, because
//! over-including is harmless to the resolver while under-including would
//! silently break the build (the Python reference also emits a runtime warning;
//! Rust has no warnings channel here, so the conservative inclusion is the whole
//! behaviour — see backlog #26 for predicate-aware extraction).

/// URL requirement schemes recognised by `_parse_spec` (nimble_parse.py).
const URL_SCHEMES: [&str; 5] = ["http://", "https://", "ssh://", "git://", "file://"];

/// One `requires` entry parsed from a `.nimble` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NimbleRequirement {
    /// A URL requirement (`requires "https://…/foo#ref"`).
    Url {
        /// Verbatim spec (for round-trip + diagnostics).
        spec: String,
        url: String,
        /// `None` when no `#ref` was appended.
        ref_spec: Option<String>,
    },
    /// A named requirement (`requires "foo >= 0.5.0"`).
    Named {
        spec: String,
        name: String,
        /// `None` for an any-version requirement.
        constraint: Option<String>,
    },
}

/// The extract of a `.nimble` file milpa cares about: transitive `requires`
/// plus the optional `srcDir`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NimbleManifest {
    pub requires: Vec<NimbleRequirement>,
    pub src_dir: Option<String>,
}

/// Parse a `.nimble` file's text into a [`NimbleManifest`]. Never fails: an
/// unrecognised file simply yields no requires and no `srcDir` (the heuristic
/// scan is total).
pub fn parse_nimble(text: &str) -> NimbleManifest {
    let mut specs: Vec<String> = Vec::new();
    let mut src_dir: Option<String> = None;

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_comment(lines[i]);

        if let Some(dir) = match_src_dir(&line) {
            src_dir = Some(dir);
            i += 1;
            continue;
        }

        if let Some(rest) = match_requires(&line) {
            let mut tail = rest.trim().to_string();
            // Trailing-comma continuation: a `requires` clause that ends with a
            // comma continues on the next line.
            while tail.ends_with(',') {
                i += 1;
                if i >= lines.len() {
                    break;
                }
                tail.push(' ');
                tail.push_str(strip_comment(lines[i]).trim());
            }
            extract_quoted(&tail, &mut specs);
        }

        i += 1;
    }

    NimbleManifest {
        requires: specs.iter().map(|s| parse_spec(s)).collect(),
        src_dir,
    }
}

/// Strip a `# …` comment from a line, ignoring `#` inside double-quoted strings,
/// then trim trailing whitespace (mirrors `_strip_comment`).
fn strip_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_string = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_string = !in_string;
                out.push(ch);
            }
            '#' if !in_string => break,
            _ => out.push(ch),
        }
    }
    out.trim_end().to_string()
}

/// Match `srcDir = "value"` (or unquoted). The value is a single non-quote,
/// non-whitespace token; anything else after it (besides a closing quote and
/// trailing space) means no match — exactly the `_SRCDIR_RE` regex.
fn match_src_dir(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("srcDir")?;
    let rest = rest.trim_start().strip_prefix('=')?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    // value = run of non-quote, non-whitespace characters.
    let value: String = rest
        .chars()
        .take_while(|c| *c != '"' && !c.is_whitespace())
        .collect();
    if value.is_empty() {
        return None;
    }
    // The remainder must be only an optional closing quote + trailing space.
    let remainder = &rest[value.len()..];
    let remainder = remainder.strip_prefix('"').unwrap_or(remainder);
    if remainder.trim().is_empty() {
        Some(value)
    } else {
        None
    }
}

/// Match a `requires …` line, returning everything after `requires` + at least
/// one whitespace (mirrors `_REQUIRES_RE`).
fn match_requires(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("requires")?;
    // `requires` must be followed by whitespace (not `requiresX`).
    if rest.starts_with(char::is_whitespace) {
        Some(rest.trim_start())
    } else {
        None
    }
}

/// Append every double-quoted substring of `s` to `out` (mirrors `_QUOTED_RE`).
fn extract_quoted(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let content_start = i + 1;
        match s[content_start..].find('"') {
            Some(rel) => {
                let end = content_start + rel;
                out.push(s[content_start..end].to_string());
                i = end + 1; // resume after the closing quote
            }
            None => break,
        }
    }
}

// ---------------------------------------------------------------------------
// parse_when_condition — RFC §3.1 S1
// ---------------------------------------------------------------------------

/// Platform token vocabulary.  The tuple is (input_token, canonical_value).
/// Aliases normalize to the canonical name (e.g. "win" → "windows").
const PLATFORM_TOKENS: &[(&str, &str)] = &[
    ("linux",   "linux"),
    ("macosx",  "macosx"),
    ("macos",   "macosx"),   // alias
    ("windows", "windows"),
    ("win",     "windows"),  // alias
    ("freebsd", "freebsd"),
    ("openbsd", "openbsd"),
    ("netbsd",  "netbsd"),
];

/// Arch token vocabulary.
const ARCH_TOKENS: &[&str] = &["amd64", "arm64", "i386"];

/// Recognized comparison operators for all Nim version forms.
const NIM_OPS: &[&str] = &[">=", ">", "<=", "<", "=="];

/// Map a NimScript `when`/`elif` condition string to zero or more
/// [`crate::Predicate`]s, returning `None` when the condition is not in
/// the recognized grammar table (RFC §3.1).
///
/// # Postcondition
/// A recognized condition ALWAYS returns `Some(v)` where `v.is_empty() == false`.
///
/// # Recognized forms
/// - `defined(token)` → platform or arch Predicate
/// - `not defined(token)` → negated platform or arch Predicate
/// - `NimMajor OP X` → nim Predicate `"OPX.0.0"`
/// - `(NimMajor, NimMinor) OP (X, Y)` → nim Predicate `"OPX.Y.0"`
/// - `(NimMajor, NimMinor, NimPatch) OP (X, Y, Z)` → nim Predicate `"OPX.Y.Z"`
/// - `<nim-tuple-cmp> and <nim-tuple-cmp>` → two nim Predicates
///
/// Deliberately NOT recognized (→ `None`):
/// - `defined(posix)` — cross-platform abstraction, deliberately excluded
/// - Any unknown `defined(token)`
/// - `or` / compound non-nim `and`
/// - Empty / blank input
pub fn parse_when_condition(cond: &str) -> Option<Vec<crate::Predicate>> {
    let stripped = cond.trim();
    if stripped.is_empty() {
        return None;
    }

    // --- `not <single>` form ---
    if let Some(inner) = strip_not_prefix(stripped) {
        let inner_pred = parse_single(inner)?;
        let pred = crate::Predicate {
            name: inner_pred.name,
            values: inner_pred.values,
            negated: true,
        };
        let result = vec![pred];
        debug_assert!(!result.is_empty());
        return Some(result);
    }

    // --- Two-sided `and` form ---
    if let Some((left_str, right_str)) = split_on_and(stripped) {
        let left_pred = parse_nim_comparison(left_str)?;
        let right_pred = parse_nim_comparison(right_str)?;
        let result = vec![left_pred, right_pred];
        debug_assert!(!result.is_empty());
        return Some(result);
    }

    // --- Single predicate forms ---
    let p = parse_single(stripped)?;
    let result = vec![p];
    debug_assert!(!result.is_empty());
    Some(result)
}

/// Strip a leading `not` keyword (followed by one or more spaces/tabs).
/// Returns the remainder (trimmed) if present, otherwise `None`.
fn strip_not_prefix(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("not")?;
    // Must be followed by whitespace (not `notfoo`).
    if rest.starts_with(char::is_whitespace) {
        Some(rest.trim())
    } else {
        None
    }
}

/// Try to parse `defined(token)` into a platform or arch Predicate.
fn parse_defined(cond: &str) -> Option<crate::Predicate> {
    // Strip "defined(" prefix and ")" suffix, then trim interior whitespace.
    let inner = cond
        .trim()
        .strip_prefix("defined(")?
        .strip_suffix(')')?
        .trim();
    if inner.is_empty() {
        return None;
    }
    // Platform tokens (with aliases).
    for &(tok, canonical) in PLATFORM_TOKENS {
        if inner == tok {
            return Some(crate::Predicate {
                name: "platform".to_string(),
                values: vec![canonical.to_string()],
                negated: false,
            });
        }
    }
    // Arch tokens.
    if ARCH_TOKENS.contains(&inner) {
        return Some(crate::Predicate {
            name: "arch".to_string(),
            values: vec![inner.to_string()],
            negated: false,
        });
    }
    None
}

/// Parse a NimMajor / tuple comparison into a single nim Predicate, or `None`.
///
/// Handles:
/// - `NimMajor OP X`
/// - `(NimMajor, NimMinor) OP (X, Y)`
/// - `(NimMajor, NimMinor, NimPatch) OP (X, Y, Z)`
fn parse_nim_comparison(cond: &str) -> Option<crate::Predicate> {
    let s = cond.trim();

    // Form 1: NimMajor OP X
    if let Some(value) = try_nim_major_single(s) {
        return Some(crate::Predicate {
            name: "nim".to_string(),
            values: vec![value],
            negated: false,
        });
    }

    // Form 2/3: tuple forms — must start with "("
    if s.starts_with('(') {
        if let Some(value) = try_nim_tuple(s) {
            return Some(crate::Predicate {
                name: "nim".to_string(),
                values: vec![value],
                negated: false,
            });
        }
    }

    None
}

/// `NimMajor OP X` → `"OPX.0.0"`, or `None`.
fn try_nim_major_single(s: &str) -> Option<String> {
    // Strip "NimMajor" prefix.
    let rest = s.strip_prefix("NimMajor")?.trim_start();
    let (op, after_op) = extract_op(rest)?;
    let major: u32 = after_op.trim().parse().ok()?;
    Some(format!("{op}{major}.0.0"))
}

/// `(NimMajor, NimMinor[, NimPatch]) OP (X, Y[, Z])` → version string, or `None`.
fn try_nim_tuple(s: &str) -> Option<String> {
    // Strip leading "(".
    let rest = s.strip_prefix('(')?;
    // Try three-component first (more specific).
    if let Some(val) = try_tuple3(rest) {
        return Some(val);
    }
    try_tuple2(rest)
}

/// Parse `NimMajor, NimMinor, NimPatch) OP (X, Y, Z)` (leading `(` already stripped).
fn try_tuple3(s: &str) -> Option<String> {
    let rest = s.trim_start();
    let rest = rest.strip_prefix("NimMajor")?.trim_start();
    let rest = rest.strip_prefix(',')?.trim_start();
    let rest = rest.strip_prefix("NimMinor")?.trim_start();
    let rest = rest.strip_prefix(',')?.trim_start();
    let rest = rest.strip_prefix("NimPatch")?.trim_start();
    let rest = rest.strip_prefix(')')?.trim_start();
    let (op, after_op) = extract_op(rest)?;
    let after_op = after_op.trim_start().strip_prefix('(')?;
    let after_op = after_op.trim_start();
    // Parse X
    let (major_str, after_major) = split_on_comma(after_op)?;
    let major: u32 = major_str.trim().parse().ok()?;
    // Parse Y
    let (minor_str, after_minor) = split_on_comma(after_major.trim_start())?;
    let minor: u32 = minor_str.trim().parse().ok()?;
    // Parse Z (then closing paren)
    let rest = after_minor.trim_start();
    let (patch_str, remainder) = split_before_rparen(rest)?;
    let patch: u32 = patch_str.trim().parse().ok()?;
    // Ensure nothing follows the closing paren (whole expr consumed).
    if !remainder.trim().is_empty() {
        return None;
    }
    Some(format!("{op}{major}.{minor}.{patch}"))
}

/// Parse `NimMajor, NimMinor) OP (X, Y)` (leading `(` already stripped).
fn try_tuple2(s: &str) -> Option<String> {
    let rest = s.trim_start();
    let rest = rest.strip_prefix("NimMajor")?.trim_start();
    let rest = rest.strip_prefix(',')?.trim_start();
    let rest = rest.strip_prefix("NimMinor")?.trim_start();
    let rest = rest.strip_prefix(')')?.trim_start();
    let (op, after_op) = extract_op(rest)?;
    let after_op = after_op.trim_start().strip_prefix('(')?;
    let after_op = after_op.trim_start();
    // Parse X
    let (major_str, after_major) = split_on_comma(after_op)?;
    let major: u32 = major_str.trim().parse().ok()?;
    // Parse Y then closing paren, then verify nothing remains.
    let rest = after_major.trim_start();
    let (minor_str, remainder) = split_before_rparen(rest)?;
    let minor: u32 = minor_str.trim().parse().ok()?;
    // Ensure nothing follows the closing paren (whole expr consumed).
    if !remainder.trim().is_empty() {
        return None;
    }
    Some(format!("{op}{major}.{minor}.0"))
}

/// Extract a recognized operator from the start of `s`.
/// Returns `(op, remainder_after_op)` or `None`.
fn extract_op(s: &str) -> Option<(&'static str, &str)> {
    for &op in NIM_OPS {
        if let Some(rest) = s.strip_prefix(op) {
            return Some((op, rest));
        }
    }
    None
}

/// Split `s` on the first `,`, returning `(before, after_comma)` or `None`.
fn split_on_comma(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(',')?;
    Some((&s[..idx], &s[idx + 1..]))
}

/// Split `s` on the first `)`, returning `(before_rparen, after_rparen)` or `None`.
fn split_before_rparen(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(')')?;
    Some((&s[..idx], &s[idx + 1..]))
}

/// Parse a single (non-compound, non-not) condition.
fn parse_single(cond: &str) -> Option<crate::Predicate> {
    parse_defined(cond).or_else(|| parse_nim_comparison(cond))
}

/// Split `cond` on the first standalone `and` keyword token.
///
/// Returns `(left, right)` both trimmed, or `None` if no valid split.
/// The `and` must not be part of a larger identifier (word-boundary check).
fn split_on_and(cond: &str) -> Option<(&str, &str)> {
    let bytes = cond.as_bytes();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] == b"and" {
            // Check left boundary: preceding char must be non-word.
            let left_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
            // Check right boundary: following char must be non-word or end of string.
            let right_ok = i + 3 >= bytes.len()
                || (!bytes[i + 3].is_ascii_alphanumeric() && bytes[i + 3] != b'_');
            if left_ok && right_ok {
                let left = cond[..i].trim();
                let right = cond[i + 3..].trim();
                if !left.is_empty() && !right.is_empty() {
                    return Some((left, right));
                }
            }
        }
        i += 1;
    }
    None
}

/// Classify a single requirement spec into the right variant (`_parse_spec`).
fn parse_spec(spec: &str) -> NimbleRequirement {
    if URL_SCHEMES.iter().any(|s| spec.starts_with(s)) {
        if let Some((url, refp)) = spec.split_once('#') {
            return NimbleRequirement::Url {
                spec: spec.to_string(),
                url: url.to_string(),
                ref_spec: Some(refp.to_string()),
            };
        }
        return NimbleRequirement::Url {
            spec: spec.to_string(),
            url: spec.to_string(),
            ref_spec: None,
        };
    }
    let mut parts = spec.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("").to_string();
    let constraint = parts
        .next()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    NimbleRequirement::Named {
        spec: spec.to_string(),
        name,
        constraint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_srcdir_quoted_and_unquoted() {
        assert_eq!(
            parse_nimble("srcDir = \"src\"\n").src_dir.as_deref(),
            Some("src")
        );
        assert_eq!(
            parse_nimble("srcDir = lib\n").src_dir.as_deref(),
            Some("lib")
        );
        assert_eq!(
            parse_nimble("  srcDir=\"src\"\n").src_dir.as_deref(),
            Some("src")
        );
    }

    #[test]
    fn parses_named_requirement_with_constraint() {
        let nm = parse_nimble("requires \"foo >= 0.5.0\"\n");
        assert_eq!(
            nm.requires,
            vec![NimbleRequirement::Named {
                spec: "foo >= 0.5.0".into(),
                name: "foo".into(),
                constraint: Some(">= 0.5.0".into()),
            }]
        );
    }

    #[test]
    fn parses_bare_named_requirement() {
        let nm = parse_nimble("requires \"foo\"\n");
        assert_eq!(
            nm.requires,
            vec![NimbleRequirement::Named {
                spec: "foo".into(),
                name: "foo".into(),
                constraint: None,
            }]
        );
    }

    #[test]
    fn parses_url_requirement_with_ref() {
        let nm = parse_nimble("requires \"https://example.com/bar.git#v1\"\n");
        assert_eq!(
            nm.requires,
            vec![NimbleRequirement::Url {
                spec: "https://example.com/bar.git#v1".into(),
                url: "https://example.com/bar.git".into(),
                ref_spec: Some("v1".into()),
            }]
        );
    }

    #[test]
    fn parses_url_requirement_without_ref() {
        let nm = parse_nimble("requires \"https://example.com/bar.git\"\n");
        assert_eq!(
            nm.requires,
            vec![NimbleRequirement::Url {
                spec: "https://example.com/bar.git".into(),
                url: "https://example.com/bar.git".into(),
                ref_spec: None,
            }]
        );
    }

    #[test]
    fn parses_comma_separated_and_multiline_requires() {
        let nm = parse_nimble("requires \"a >= 1.0.0\", \"b\"\n");
        assert_eq!(nm.requires.len(), 2);

        let multi = parse_nimble("requires \"a\",\n  \"b\"\n");
        assert_eq!(multi.requires.len(), 2);
    }

    #[test]
    fn ignores_nim_compiler_and_handles_multiple_statements() {
        let nm = parse_nimble("requires \"nim >= 2.0.0\"\nrequires \"foo\"\n");
        // The parser keeps `nim` (the resolver drops it); both statements parse.
        assert_eq!(nm.requires.len(), 2);
    }

    #[test]
    fn strips_comments_outside_strings() {
        let nm = parse_nimble("requires \"foo\"  # a comment\n");
        assert_eq!(nm.requires.len(), 1);
        assert_eq!(parse_nimble("# requires \"x\"\n").requires.len(), 0);
    }

    #[test]
    fn when_block_includes_requires_unconditionally() {
        // `when` is never evaluated; the requires inside it are still extracted.
        let nm = parse_nimble("when defined(windows):\n  requires \"winfoo\"\n");
        assert_eq!(nm.requires.len(), 1);
    }
}

#[cfg(test)]
mod when_condition_tests {
    use super::parse_when_condition;
    use crate::Predicate;

    // ----- helpers -----

    fn plat(name: &str) -> Predicate {
        Predicate { name: "platform".into(), values: vec![name.into()], negated: false }
    }
    fn plat_neg(name: &str) -> Predicate {
        Predicate { name: "platform".into(), values: vec![name.into()], negated: true }
    }
    fn arch(name: &str) -> Predicate {
        Predicate { name: "arch".into(), values: vec![name.into()], negated: false }
    }
    fn arch_neg(name: &str) -> Predicate {
        Predicate { name: "arch".into(), values: vec![name.into()], negated: true }
    }
    fn nim(c: &str) -> Predicate {
        Predicate { name: "nim".into(), values: vec![c.into()], negated: false }
    }

    fn ok(cond: &str, expected: Vec<Predicate>) {
        let result = parse_when_condition(cond);
        assert!(result.is_some(), "Expected recognized, got None for: {:?}", cond);
        let v = result.unwrap();
        assert!(!v.is_empty(), "Recognized condition returned empty vec for: {:?}", cond);
        assert_eq!(v, expected, "For {:?}: got {:?}", cond, v);
    }

    fn unrecognized(cond: &str) {
        let result = parse_when_condition(cond);
        assert!(result.is_none(), "Expected None, got {:?} for: {:?}", result, cond);
    }

    // ----- C1: platform tokens + aliases -----

    #[test] fn platform_linux() { ok("defined(linux)", vec![plat("linux")]); }
    #[test] fn platform_macosx() { ok("defined(macosx)", vec![plat("macosx")]); }
    #[test] fn platform_windows() { ok("defined(windows)", vec![plat("windows")]); }
    #[test] fn platform_freebsd() { ok("defined(freebsd)", vec![plat("freebsd")]); }
    #[test] fn platform_openbsd() { ok("defined(openbsd)", vec![plat("openbsd")]); }
    #[test] fn platform_netbsd() { ok("defined(netbsd)", vec![plat("netbsd")]); }
    #[test] fn alias_win_to_windows() { ok("defined(win)", vec![plat("windows")]); }
    #[test] fn alias_macos_to_macosx() { ok("defined(macos)", vec![plat("macosx")]); }
    #[test] fn platform_whitespace_inside_parens() { ok("defined( linux )", vec![plat("linux")]); }
    #[test] fn platform_leading_trailing_whitespace() { ok("  defined(linux)  ", vec![plat("linux")]); }

    // ----- C2: arch tokens -----

    #[test] fn arch_amd64() { ok("defined(amd64)", vec![arch("amd64")]); }
    #[test] fn arch_arm64() { ok("defined(arm64)", vec![arch("arm64")]); }
    #[test] fn arch_i386() { ok("defined(i386)", vec![arch("i386")]); }
    #[test] fn arch_whitespace_tolerance() { ok("defined( amd64 )", vec![arch("amd64")]); }

    // ----- C3: not negation -----

    #[test] fn not_linux() { ok("not defined(linux)", vec![plat_neg("linux")]); }
    #[test] fn not_windows() { ok("not defined(windows)", vec![plat_neg("windows")]); }
    #[test] fn not_amd64() { ok("not defined(amd64)", vec![arch_neg("amd64")]); }
    #[test] fn not_extra_space() { ok("not  defined(linux)", vec![plat_neg("linux")]); }
    #[test] fn not_alias_win() { ok("not defined(win)", vec![plat_neg("windows")]); }

    #[test]
    fn not_unrecognized_inner_yields_none() {
        unrecognized("not defined(posix)");
    }

    #[test]
    fn not_two_sided_range_yields_none() {
        unrecognized("not (NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0)");
    }

    // ----- C4: single NimMajor OP X -----

    #[test] fn nim_major_gte() { ok("NimMajor >= 1", vec![nim(">=1.0.0")]); }
    #[test] fn nim_major_gt() { ok("NimMajor > 1", vec![nim(">1.0.0")]); }
    #[test] fn nim_major_lt() { ok("NimMajor < 2", vec![nim("<2.0.0")]); }
    #[test] fn nim_major_lte() { ok("NimMajor <= 1", vec![nim("<=1.0.0")]); }
    #[test] fn nim_major_eq() { ok("NimMajor == 1", vec![nim("==1.0.0")]); }
    #[test] fn nim_major_no_spaces() { ok("NimMajor>=1", vec![nim(">=1.0.0")]); }
    #[test] fn nim_major_leading_trailing() { ok("  NimMajor >= 2  ", vec![nim(">=2.0.0")]); }
    #[test] fn nim_major_large_value() { ok("NimMajor >= 10", vec![nim(">=10.0.0")]); }

    // ----- C5: tuple forms -----

    #[test] fn nim_tuple2_gte() { ok("(NimMajor, NimMinor) >= (1, 4)", vec![nim(">=1.4.0")]); }
    #[test] fn nim_tuple2_lt() { ok("(NimMajor, NimMinor) < (2, 0)", vec![nim("<2.0.0")]); }
    #[test] fn nim_tuple2_gt() { ok("(NimMajor, NimMinor) > (1, 6)", vec![nim(">1.6.0")]); }
    #[test] fn nim_tuple2_lte() { ok("(NimMajor, NimMinor) <= (1, 9)", vec![nim("<=1.9.0")]); }
    #[test] fn nim_tuple2_eq() { ok("(NimMajor, NimMinor) == (2, 0)", vec![nim("==2.0.0")]); }
    #[test] fn nim_tuple3_gte() {
        ok("(NimMajor, NimMinor, NimPatch) >= (1, 6, 0)", vec![nim(">=1.6.0")]);
    }
    #[test] fn nim_tuple3_lt() {
        ok("(NimMajor, NimMinor, NimPatch) < (2, 0, 1)", vec![nim("<2.0.1")]);
    }
    #[test] fn nim_tuple2_no_spaces() { ok("(NimMajor,NimMinor)>=(1,4)", vec![nim(">=1.4.0")]); }
    #[test] fn nim_tuple2_mixed_spacing() { ok("(NimMajor, NimMinor) >= (1,4)", vec![nim(">=1.4.0")]); }
    #[test] fn nim_tuple3_patch_nonzero() {
        ok("(NimMajor, NimMinor, NimPatch) == (1, 6, 14)", vec![nim("==1.6.14")]);
    }

    // ----- C6: two-sided range -----

    #[test]
    fn two_sided_range_basic() {
        ok(
            "(NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0)",
            vec![nim(">=1.4.0"), nim("<2.0.0")],
        );
    }

    #[test]
    fn two_sided_range_no_spaces() {
        ok(
            "(NimMajor,NimMinor)>=(1,4)and(NimMajor,NimMinor)<(2,0)",
            vec![nim(">=1.4.0"), nim("<2.0.0")],
        );
    }

    #[test]
    fn two_sided_range_three_component() {
        ok(
            "(NimMajor, NimMinor, NimPatch) >= (1, 6, 0) and (NimMajor, NimMinor, NimPatch) < (2, 0, 0)",
            vec![nim(">=1.6.0"), nim("<2.0.0")],
        );
    }

    #[test]
    fn and_non_nim_tuple_yields_none() {
        unrecognized("defined(linux) and defined(macosx)");
    }

    #[test]
    fn and_one_side_not_nim_tuple_yields_none() {
        unrecognized("defined(linux) and (NimMajor, NimMinor) < (2, 0)");
    }

    // ----- C7: UNRECOGNIZED battery -----

    #[test] fn empty_string() { unrecognized(""); }
    #[test] fn blank_string() { unrecognized("   "); }
    #[test] fn posix_deliberately_unrecognized() { unrecognized("defined(posix)"); }
    #[test] fn unknown_token_release() { unrecognized("defined(release)"); }
    #[test] fn unknown_token_js() { unrecognized("defined(js)"); }
    #[test] fn unknown_token_solaris() { unrecognized("defined(solaris)"); }
    #[test] fn unknown_token_custom() { unrecognized("defined(custom)"); }
    #[test] fn compound_or() { unrecognized("defined(linux) or defined(macosx)"); }
    #[test] fn compound_and_non_nim() { unrecognized("defined(linux) and defined(windows)"); }
    #[test] fn unknown_nimscript_expr() { unrecognized("system.hostOS == \"linux\""); }
    #[test] fn case_sensitive_Linux() { unrecognized("defined(Linux)"); }
    #[test] fn case_sensitive_Windows() { unrecognized("defined(Windows)"); }
    #[test] fn defined_no_arg() { unrecognized("defined()"); }
    #[test] fn lowercase_nimmajor() { unrecognized("nimmajor >= 1"); }
    #[test] fn unknown_operator_ne() { unrecognized("NimMajor != 1"); }
    #[test] fn nim_tuple_wrong_order() { unrecognized("(NimMinor, NimMajor) >= (4, 1)"); }

    #[test]
    fn arch_predicate_name_is_arch_not_platform() {
        let result = parse_when_condition("defined(amd64)").unwrap();
        assert_eq!(result[0].name, "arch");
    }
}
