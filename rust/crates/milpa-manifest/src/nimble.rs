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
