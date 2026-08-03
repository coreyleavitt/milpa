//! Unit tests for `source_id.rs` (rfc-origin-as-identity.md S1; revised
//! round-2.5, [[provenance_source_selection]]).
//!
//! Mirrors Python's `test_source_id.py` example-based coverage. **There is
//! no `parse()` any more** — the frozen enum value is the authoritative
//! representation; `canonical()` is a one-way key, never parsed back.
//! Validation now lives in `normalize_source` (the sole boundary since
//! `parse()` is gone). Property-based / Hypothesis coverage is Python-only
//! (`rfc-property-based-testing.md`: Rust proptest is deliberately not
//! wired up yet — see `resolver_tests.rs`'s own note on this); the
//! injectivity law itself is proven in `test_source_id_properties.py`.

use super::*;
use milpa_types::{FetchableOrigin, SourceId};

fn git(url: &str) -> SourceId {
    SourceId::Fetchable(FetchableOrigin::Git { url: url.to_string(), subpath: None })
}

fn assert_malformed(result: Result<SourceId, MilpaError>) {
    let err = result.unwrap_err();
    assert_eq!(err.code(), "SRC-ID-MALFORMED");
}

// ---------------------------------------------------------------------------
// canonical() — one example per kind, matching the RFC §4.1 worked examples
// ---------------------------------------------------------------------------

#[test]
fn canonical_git_no_subpath() {
    let sid = git("https://github.com/coreyleavitt/nim-z3");
    assert_eq!(canonical(&sid), "git+https://github.com/coreyleavitt/nim-z3");
}

#[test]
fn canonical_git_with_subpath() {
    let sid = SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://github.com/facebook/react".into(),
        subpath: Some("packages/react-dom".into()),
    });
    assert_eq!(
        canonical(&sid),
        "git+https://github.com/facebook/react#subdirectory=packages/react-dom"
    );
}

#[test]
fn canonical_oci_no_subpath() {
    let sid = SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "ghcr.io".into(),
        repository: "coreyleavitt/softlink".into(),
        subpath: None,
    });
    assert_eq!(canonical(&sid), "oci+ghcr.io/coreyleavitt/softlink");
}

#[test]
fn canonical_tarball() {
    let sid = SourceId::Fetchable(FetchableOrigin::Tarball {
        url: "https://example.com/dist/pkg-1.4.0.tar.gz".into(),
        subpath: None,
    });
    assert_eq!(canonical(&sid), "tar+https://example.com/dist/pkg-1.4.0.tar.gz");
}

#[test]
fn canonical_pkg_no_namespace() {
    let sid = SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: None,
        name: "softlink".into(),
    });
    assert_eq!(canonical(&sid), "pkg+tianguis/softlink");
}

#[test]
fn canonical_pkg_with_namespace() {
    let sid = SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("acme".into()),
        name: "utils".into(),
    });
    assert_eq!(canonical(&sid), "pkg+tianguis/acme/utils");
}

#[test]
fn canonical_pkg_host_qualified_namespace() {
    // RFC §4.1 round-2.5: variable-arity, name-last — `namespace` MAY
    // itself contain '/' (884/886 real tianguis namespaces are
    // host-qualified, e.g. codeberg.org/eris).
    let sid = SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("codeberg.org/eris".into()),
        name: "mypkg".into(),
    });
    assert_eq!(canonical(&sid), "pkg+tianguis/codeberg.org/eris/mypkg");
}

#[test]
fn canonical_pkg_host_qualified_namespace_distinct_from_no_namespace() {
    let with_ns = SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("codeberg.org/eris".into()),
        name: "mypkg".into(),
    });
    let without_ns = SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: None,
        name: "mypkg".into(),
    });
    assert_ne!(with_ns, without_ns);
    assert_ne!(canonical(&with_ns), canonical(&without_ns));
}

#[test]
fn canonical_file_relative() {
    let sid = SourceId::Fetchable(FetchableOrigin::Local {
        path: "relative/path/from/workspace/root".into(),
    });
    assert_eq!(canonical(&sid), "file+relative/path/from/workspace/root");
}

#[test]
fn canonical_file_absolute() {
    let sid = SourceId::Fetchable(FetchableOrigin::Local { path: "/abs/path/outside/workspace".into() });
    assert_eq!(canonical(&sid), "file+/abs/path/outside/workspace");
}

#[test]
fn canonical_member() {
    let sid = SourceId::Member { member_name: "intonaco".into() };
    assert_eq!(canonical(&sid), "member+intonaco");
}

fn worked_examples() -> Vec<SourceId> {
    vec![
        git("https://github.com/coreyleavitt/nim-z3"),
        SourceId::Fetchable(FetchableOrigin::Git {
            url: "https://github.com/facebook/react".into(),
            subpath: Some("packages/react-dom".into()),
        }),
        SourceId::Fetchable(FetchableOrigin::Oci {
            registry: "ghcr.io".into(),
            repository: "coreyleavitt/softlink".into(),
            subpath: None,
        }),
        SourceId::Fetchable(FetchableOrigin::Tarball {
            url: "https://example.com/dist/pkg-1.4.0.tar.gz".into(),
            subpath: None,
        }),
        SourceId::Fetchable(FetchableOrigin::Registry {
            registry: "tianguis".into(),
            namespace: None,
            name: "softlink".into(),
        }),
        SourceId::Fetchable(FetchableOrigin::Registry {
            registry: "tianguis".into(),
            namespace: Some("acme".into()),
            name: "utils".into(),
        }),
        SourceId::Fetchable(FetchableOrigin::Local { path: "relative/path/from/workspace/root".into() }),
        SourceId::Fetchable(FetchableOrigin::Local { path: "/abs/path/outside/workspace".into() }),
        SourceId::Member { member_name: "intonaco".into() },
    ]
}

// ---------------------------------------------------------------------------
// format_source_id — B6 diagnostic formatter
// ---------------------------------------------------------------------------

#[test]
fn format_includes_kind_label_and_canonical_string() {
    let sid = git("https://github.com/coreyleavitt/nim-z3");
    let msg = format_source_id(&sid);
    assert!(msg.to_lowercase().contains("git"));
    assert!(msg.contains(&canonical(&sid)));
}

#[test]
fn format_distinct_labels_per_kind() {
    let sids = vec![
        git("https://x/y"),
        SourceId::Fetchable(FetchableOrigin::Oci {
            registry: "ghcr.io".into(),
            repository: "x/y".into(),
            subpath: None,
        }),
        SourceId::Fetchable(FetchableOrigin::Tarball { url: "https://x/y.tar.gz".into(), subpath: None }),
        SourceId::Fetchable(FetchableOrigin::Local { path: "x/y".into() }),
        SourceId::Fetchable(FetchableOrigin::Registry {
            registry: "tianguis".into(),
            namespace: None,
            name: "x".into(),
        }),
        SourceId::Member { member_name: "x".into() },
    ];
    let labels: std::collections::HashSet<String> =
        sids.iter().map(|s| format_source_id(s).split(" \"").next().unwrap().to_string()).collect();
    assert_eq!(labels.len(), sids.len());
}

// ---------------------------------------------------------------------------
// Cross-kind prefix sanity (no two kinds can ever collide)
// ---------------------------------------------------------------------------

#[test]
fn every_kind_has_a_distinct_reserved_prefix() {
    for sid in worked_examples() {
        let s = canonical(&sid);
        let prefixes = ["git+", "oci+", "tar+", "pkg+", "file+", "member+"];
        let matches: Vec<&&str> = prefixes.iter().filter(|p| s.starts_with(**p)).collect();
        assert_eq!(matches.len(), 1, "expected exactly one prefix match for {s:?}");
    }
}

// ---------------------------------------------------------------------------
// normalize_source — git three-tier rule (D4)
// ---------------------------------------------------------------------------

#[test]
fn normalize_kept_lowercase_and_strip() {
    let sid = normalize_source(&git("HTTPS://GitHub.com/Org/Repo.git/")).unwrap();
    assert_eq!(sid, git("https://github.com/Org/Repo"));
}

#[test]
fn normalize_kept_path_case_preserved() {
    let sid = normalize_source(&git("https://github.com/CoreyLeavitt/Nim-Z3")).unwrap();
    match sid {
        SourceId::Fetchable(FetchableOrigin::Git { url, .. }) => {
            assert_eq!(url, "https://github.com/CoreyLeavitt/Nim-Z3");
        }
        _ => panic!("expected Git"),
    }
}

#[test]
fn normalize_added_strip_userinfo() {
    let sid = normalize_source(&git("ssh://git@host/org/repo")).unwrap();
    assert_eq!(sid, git("ssh://host/org/repo"));
}

#[test]
fn normalize_added_strip_default_port_ssh() {
    let a = normalize_source(&git("ssh://user@host:22/org/repo")).unwrap();
    let b = normalize_source(&git("ssh://host/org/repo")).unwrap();
    assert_eq!(a, b);
}

#[test]
fn normalize_added_strip_default_port_https() {
    let a = normalize_source(&git("https://host:443/org/repo")).unwrap();
    let b = normalize_source(&git("https://host/org/repo")).unwrap();
    assert_eq!(a, b);
}

#[test]
fn normalize_added_strip_default_port_http() {
    let a = normalize_source(&git("http://host:80/org/repo")).unwrap();
    let b = normalize_source(&git("http://host/org/repo")).unwrap();
    assert_eq!(a, b);
}

#[test]
fn normalize_added_strip_default_port_git_scheme() {
    let a = normalize_source(&git("git://host:9418/org/repo")).unwrap();
    let b = normalize_source(&git("git://host/org/repo")).unwrap();
    assert_eq!(a, b);
}

#[test]
fn normalize_non_default_port_preserved() {
    let sid = normalize_source(&git("ssh://host:2222/org/repo")).unwrap();
    assert_eq!(sid, git("ssh://host:2222/org/repo"));
}

#[test]
fn normalize_not_attempted_ssh_https_not_unified() {
    let a = normalize_source(&git("ssh://host/org/repo")).unwrap();
    let b = normalize_source(&git("https://host/org/repo")).unwrap();
    assert_ne!(a, b);
}

#[test]
fn normalize_subpath_untouched() {
    let sid = normalize_source(&SourceId::Fetchable(FetchableOrigin::Git {
        url: "HTTPS://Host/Org/Repo.git".into(),
        subpath: Some("pkg/foo".into()),
    }))
    .unwrap();
    assert_eq!(
        sid,
        SourceId::Fetchable(FetchableOrigin::Git {
            url: "https://host/Org/Repo".into(),
            subpath: Some("pkg/foo".into()),
        })
    );
}

#[test]
fn normalize_total_never_panics_on_scp_style() {
    // SCP-style git@host:org/repo is unreachable from the manifest parser
    // (validate_git_url rejects any git= without a scheme), but
    // normalize_source itself must still be total (never panic on THIS
    // input) — no netloc detected, so it falls back to a lowercased whole
    // string.
    let sid = normalize_source(&git("git@host:org/repo")).unwrap();
    match sid {
        SourceId::Fetchable(FetchableOrigin::Git { url, .. }) => {
            assert_eq!(url, "git@host:org/repo");
        }
        _ => panic!("expected Git"),
    }
}

#[test]
fn normalize_ipv6_host_bracketed() {
    let sid = normalize_source(&git("https://[::1]:443/org/repo")).unwrap();
    assert_eq!(sid, git("https://[::1]/org/repo"));
}

// ---------------------------------------------------------------------------
// normalize_source — other kinds are identity (modulo validation)
// ---------------------------------------------------------------------------

#[test]
fn normalize_oci_identity() {
    let raw = SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "ghcr.io".into(),
        repository: "Org/Repo".into(),
        subpath: None,
    });
    assert_eq!(normalize_source(&raw).unwrap(), raw);
}

#[test]
fn normalize_tarball_identity() {
    let raw = SourceId::Fetchable(FetchableOrigin::Tarball { url: "https://example.com/PKG.tar.gz".into(), subpath: None });
    assert_eq!(normalize_source(&raw).unwrap(), raw);
}

#[test]
fn normalize_local_identity() {
    let raw = SourceId::Fetchable(FetchableOrigin::Local { path: "Deps/Foo".into() });
    assert_eq!(normalize_source(&raw).unwrap(), raw);
}

#[test]
fn normalize_registry_identity() {
    let raw = SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("acme".into()),
        name: "utils".into(),
    });
    assert_eq!(normalize_source(&raw).unwrap(), raw);
}

#[test]
fn normalize_registry_identity_host_qualified_namespace() {
    let raw = SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("codeberg.org/eris".into()),
        name: "utils".into(),
    });
    assert_eq!(normalize_source(&raw).unwrap(), raw);
}

#[test]
fn normalize_member_identity() {
    let raw = SourceId::Member { member_name: "intonaco".into() };
    assert_eq!(normalize_source(&raw).unwrap(), raw);
}

// ---------------------------------------------------------------------------
// normalize_source — subpath escape guard (RFC §4.1 normative)
// ---------------------------------------------------------------------------

#[test]
fn subpath_absolute_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://example.com/x".into(),
        subpath: Some("/abs/path".into()),
    })));
}

#[test]
fn subpath_dotdot_traversal_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://example.com/x".into(),
        subpath: Some("../escape".into()),
    })));
}

#[test]
fn subpath_dotdot_mid_segment_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://example.com/x".into(),
        subpath: Some("pkg/../../escape".into()),
    })));
}

#[test]
fn subpath_empty_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://example.com/x".into(),
        subpath: Some("".into()),
    })));
}

#[test]
fn subpath_ordinary_relative_accepted() {
    let sid = normalize_source(&SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://example.com/x".into(),
        subpath: Some("pkg/foo".into()),
    }))
    .unwrap();
    assert_eq!(
        sid,
        SourceId::Fetchable(FetchableOrigin::Git {
            url: "https://example.com/x".into(),
            subpath: Some("pkg/foo".into()),
        })
    );
}

#[test]
fn subpath_tarball_guarded_too() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Tarball {
        url: "https://example.com/x.tar.gz".into(),
        subpath: Some("/abs".into()),
    })));
}

#[test]
fn subpath_oci_guarded_too() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "ghcr.io".into(),
        repository: "x/y".into(),
        subpath: Some("../escape".into()),
    })));
}

// ---------------------------------------------------------------------------
// normalize_source — the #subdirectory= delimiter-collision injectivity guard
// ---------------------------------------------------------------------------

#[test]
fn git_url_with_literal_delim_rejected() {
    // Any '#' fragment in a git url is now rejected unconditionally by
    // `normalize_source` (code-review D1) before this delim-collision guard
    // is ever reached, so this is (for git specifically) exercising the
    // fragment guard's slug rather than the collision guard's — both raise
    // the same SRC-ID-MALFORMED, so the assertion below still holds.
    assert_malformed(normalize_source(&git("https://example.com/x#subdirectory=evil")));
}

#[test]
fn tarball_url_with_literal_delim_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Tarball {
        url: "https://example.com/x#subdirectory=evil".into(),
        subpath: None,
    })));
}

#[test]
fn oci_coordinate_with_literal_delim_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "ghcr.io".into(),
        repository: "x#subdirectory=evil".into(),
        subpath: None,
    })));
}

#[test]
fn unvalidated_canonical_would_collide_without_the_guard() {
    // Demonstrates WHY the guard is needed: canonical() itself does no
    // validation, so bypassing normalize_source, two structurally different
    // GitSourceIds collide under canonical(). This is exactly the
    // pathological input normalize_source rejects.
    let folded = SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://example.com/x#subdirectory=pkg".into(),
        subpath: None,
    });
    let split = SourceId::Fetchable(FetchableOrigin::Git {
        url: "https://example.com/x".into(),
        subpath: Some("pkg".into()),
    });
    assert_ne!(folded, split);
    assert_eq!(canonical(&folded), canonical(&split)); // the collision, unvalidated
    assert_malformed(normalize_source(&folded));
}

// ---------------------------------------------------------------------------
// normalize_source — OCI registry segment-boundary guard
// ---------------------------------------------------------------------------

#[test]
fn oci_registry_with_slash_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "a/b".into(),
        repository: "c".into(),
        subpath: None,
    })));
}

#[test]
fn oci_registry_slash_collision_without_the_guard() {
    let a = SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "a/b".into(),
        repository: "c".into(),
        subpath: None,
    });
    let b = SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "a".into(),
        repository: "b/c".into(),
        subpath: None,
    });
    assert_ne!(a, b);
    assert_eq!(canonical(&a), canonical(&b)); // the collision, unvalidated
    assert_malformed(normalize_source(&a));
}

// ---------------------------------------------------------------------------
// normalize_source — RegistrySourceId alias/namespace/name validation
// ---------------------------------------------------------------------------

#[test]
fn alias_bad_charset_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "ac me".into(),
        namespace: None,
        name: "x".into(),
    })));
}

#[test]
fn name_bad_charset_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: None,
        name: "soft link".into(),
    })));
}

#[test]
fn namespace_empty_segment_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("a//b".into()),
        name: "x".into(),
    })));
}

#[test]
fn namespace_dotdot_segment_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("a/../b".into()),
        name: "x".into(),
    })));
}

#[test]
fn namespace_control_char_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("a\tb".into()),
        name: "x".into(),
    })));
}

#[test]
fn namespace_host_qualified_dot_segment_accepted() {
    // The load-bearing positive case: a host-qualified namespace segment
    // containing '.' (e.g. a real domain name) is NOT rejected — only the
    // stricter valid_flag_name charset would reject it, and that charset is
    // deliberately NOT applied per-segment (884/886 real tianguis
    // namespaces are host-qualified).
    let sid = normalize_source(&SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("codeberg.org/eris".into()),
        name: "mypkg".into(),
    }))
    .unwrap();
    assert_eq!(
        sid,
        SourceId::Fetchable(FetchableOrigin::Registry {
            registry: "tianguis".into(),
            namespace: Some("codeberg.org/eris".into()),
            name: "mypkg".into(),
        })
    );
    assert_eq!(canonical(&sid), "pkg+tianguis/codeberg.org/eris/mypkg");
}

#[test]
fn namespace_unicode_line_separator_rejected() {
    // Code-review S2 broadening: the previous namespace guard was
    // ASCII-controls-only; U+2028 (Unicode LINE SEPARATOR) must be rejected
    // too, mirroring `contains_unsafe_char`'s full charset.
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Registry {
        registry: "tianguis".into(),
        namespace: Some("a\u{2028}b".into()),
        name: "x".into(),
    })));
}

// ---------------------------------------------------------------------------
// normalize_source — control-char / Unicode-line-separator injection guard
// (code-review S2): a crafted, network-fetched `milpa.kdl` must not be able
// to smuggle a terminal-escape sequence through a free-text origin field
// into a diagnostic sink (e.g. `milpa show`'s provenance formatter).
// ---------------------------------------------------------------------------

#[test]
fn git_url_with_control_char_rejected() {
    assert_malformed(normalize_source(&git("https://evil.example/z3\x1b]0;PWNED\x07")));
}

#[test]
fn git_url_with_unicode_line_separator_rejected() {
    assert_malformed(normalize_source(&git("https://evil.example/\u{2028}repo")));
}

#[test]
fn tarball_url_with_control_char_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Tarball {
        url: "https://evil.example/x\x1b.tar.gz".into(),
        subpath: None,
    })));
}

#[test]
fn oci_registry_with_control_char_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "ghcr.io\x1b".into(),
        repository: "x".into(),
        subpath: None,
    })));
}

#[test]
fn oci_repository_with_control_char_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Oci {
        registry: "ghcr.io".into(),
        repository: "x\x1by".into(),
        subpath: None,
    })));
}

#[test]
fn local_path_with_control_char_rejected() {
    assert_malformed(normalize_source(&SourceId::Fetchable(FetchableOrigin::Local {
        path: "deps/foo\x1bbar".into(),
    })));
}

#[test]
fn ordinary_git_url_unaffected_by_control_char_guard() {
    let sid = normalize_source(&git("https://github.com/coreyleavitt/nim-z3")).unwrap();
    assert_eq!(sid, git("https://github.com/coreyleavitt/nim-z3"));
}

// ---------------------------------------------------------------------------
// normalize_source — git URL query/fragment handling (code-review D1 —
// Python/Rust cross-impl convergence)
// ---------------------------------------------------------------------------

#[test]
fn git_url_query_stripped() {
    let sid = normalize_source(&git("https://example.com/org/repo?ref=main")).unwrap();
    assert_eq!(sid, git("https://example.com/org/repo"));
}

#[test]
fn git_url_fragment_rejected() {
    assert_malformed(normalize_source(&git("https://example.com/org/repo#subdirectory=x")));
}

#[test]
fn git_url_fragment_without_subdirectory_form_also_rejected() {
    // Any fragment is rejected, not just the `#subdirectory=` form — the
    // whole '#' namespace is reserved for milpa's own delimiter.
    assert_malformed(normalize_source(&git("https://example.com/org/repo#readme")));
}
