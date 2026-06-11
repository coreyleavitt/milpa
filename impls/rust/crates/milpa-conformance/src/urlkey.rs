//! URL-key encoding for `mocked-fetches/<key>/` (conformance-fixtures.md §2.3.1).
//!
//! The single source of truth is [`milpa_core::url_key`]; this module re-exports
//! it so conformance code keeps its existing `crate::urlkey::url_key` call sites
//! unchanged.

pub use milpa_core::url_key;

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
