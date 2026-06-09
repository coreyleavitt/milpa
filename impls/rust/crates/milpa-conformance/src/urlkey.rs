//! URL-key encoding for `mocked-fetches/<key>/` (conformance-fixtures.md §2.3.1).
//!
//! NORMATIVE rule: encode the URL by replacing every character outside
//! `[A-Za-z0-9._-]` with `_`, append a literal `@` separator, then append the
//! ref encoded by the same substitution. The `@` *separator* is preserved; a
//! `@` *inside the ref* is replaced like any other out-of-class character (so
//! ref `v1@beta` → `v1_beta`). This is the single source of truth shared by the
//! fixture generator and the fake fetcher — no lookup table.

/// Replace every character outside `[A-Za-z0-9._-]` with `_`.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Encode a `(url, ref)` pair to its `mocked-fetches/` subdirectory name.
pub fn url_key(url: &str, ref_spec: &str) -> String {
    format!("{}@{}", sanitize(url), sanitize(ref_spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_spec_example() {
        // §2.3.1 worked example.
        assert_eq!(
            url_key("https://github.com/example/foo.git", "main"),
            "https___github.com_example_foo.git@main"
        );
    }

    #[test]
    fn separator_at_is_literal_but_ref_at_is_substituted() {
        // The single `@` between url and ref is preserved; a `@` inside the ref
        // is substituted to `_` like any other out-of-class character.
        assert_eq!(
            url_key("https://x.example/r.git", "v1@beta"),
            "https___x.example_r.git@v1_beta"
        );
    }

    #[test]
    fn preserves_the_allowed_class() {
        // Dots, underscores, hyphens, and alphanumerics pass through unchanged.
        assert_eq!(url_key("a.b_c-d", "1.2.3-rc.4"), "a.b_c-d@1.2.3-rc.4");
    }
}
