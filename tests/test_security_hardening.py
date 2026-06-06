"""Security hardening regression tests (milpa#97 Stage-4 code review).

Covers all HIGH/MEDIUM/LOW findings that require behavioral fixes:

  H1 — empty content_hash silently disabling the identity gate
  H2 — git argv injection via index-supplied commit_sha / ref / url
  H3 — path traversal via dep name (index name + _name_from_url)
  M1 — OCI field injection + digest format unchecked
  L10 — no commit re-check after unshallow fallback
  L12 — malformed package name silently dropped

Each test is a pinned regression: the exact failure mode from the
review ledger, narrowed to a unit assertion, written RED first.
"""

import pytest

from milpa.tianguis_client import TianguisError, parse_index


# ---------------------------------------------------------------------------
# H1 — empty content_hash must raise TNG-NO-IDENTITY, NOT silently fetch
# ---------------------------------------------------------------------------


def test_h1_named_dep_with_empty_content_hash_raises_no_identity(tmp_path):
    """A named dep whose index entry carries no content_hash must be a
    hard error (TNG-NO-IDENTITY), not a silent unverified fetch.
    Invariant 1: the identity gate must never be disabled by an empty hash.

    Uses parse_index directly with an index text that explicitly omits
    `content_hash` from the version node, producing Version(content_hash="").
    """
    from dataclasses import dataclass, field

    from milpa.fetchers import FetcherRegistry
    from milpa.fetchers.git import GitProvenance, GitReceipt
    from milpa.manifest import Manifest, NamedDep
    from milpa.resolver import resolve
    from milpa.tianguis_client import parse_index

    @dataclass
    class _FetchSpy:
        calls: list = field(default_factory=list)

        def can_handle(self, p):
            return isinstance(p, GitProvenance)

        def fetch(self, name, p, *, dest):
            self.calls.append(name)
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text("")
            return GitReceipt(commit_sha="deadbeef")

    spy = _FetchSpy()
    # Build index with no content_hash field in the version node.
    # parse_index will produce Version(content_hash="").
    index = parse_index("""\
package "foo" {
    version "1.0.0" {
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "main"
        }
    }
}
""")

    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="foo", constraint=None),),
    )
    r = FetcherRegistry()
    r.register(spy)

    with pytest.raises(TianguisError) as exc:
        resolve(manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=r)

    assert exc.value.code == "TNG-NO-IDENTITY"
    # The fetcher must NOT have been called — raise before fetch
    assert spy.calls == [], "fetch must not be called when content_hash is missing"


# ---------------------------------------------------------------------------
# H2 — git argument injection: commit_sha / ref / url with leading `-`
# ---------------------------------------------------------------------------


def test_h2_commit_sha_non_40hex_rejected_at_parse():
    """A commit_sha that is not exactly 40 lowercase hex chars must be
    rejected at index-parse time with TNG-BAD-COMMIT-SHA."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/foo"
            ref "main"
            commit_sha "--upload-pack=x"
        }
    }
}
""")
    assert exc.value.code == "TNG-BAD-COMMIT-SHA"


def test_h2_commit_sha_uppercase_rejected_at_parse():
    """Uppercase hex is not valid — we require lowercase 40-hex."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/foo"
            ref "main"
            commit_sha "CAFEF00DCAFEF00DCAFEF00DCAFEF00DCAFEF00D"
        }
    }
}
""")
    assert exc.value.code == "TNG-BAD-COMMIT-SHA"


def test_h2_ref_leading_dash_rejected_at_parse():
    """A ref beginning with `-` is flag-injection; must be rejected with
    TNG-UNSAFE-REF at index-parse time."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/foo"
            ref "--evil-flag"
            commit_sha "0000000000000000000000000000000000000000"
        }
    }
}
""")
    assert exc.value.code == "TNG-UNSAFE-REF"


def test_h2_url_leading_dash_rejected_at_parse():
    """A git URL beginning with `-` is flag-injection; must be rejected
    with TNG-UNSAFE-URL at index-parse time."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "--upload-pack=rce"
            ref "main"
            commit_sha "0000000000000000000000000000000000000000"
        }
    }
}
""")
    assert exc.value.code == "TNG-UNSAFE-URL"


def test_h2_valid_40hex_commit_sha_is_accepted():
    """A well-formed 40-hex commit_sha parses without error."""
    idx = parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/foo"
            ref "main"
            commit_sha "cafef00dcafef00dcafef00dcafef00dcafef00d"
        }
    }
}
""")
    from milpa.fetchers.git import GitProvenance
    p = idx.lookup("foo")[0].provenances[0]
    assert isinstance(p, GitProvenance)
    assert p.commit_sha == "cafef00dcafef00dcafef00dcafef00dcafef00d"


# ---------------------------------------------------------------------------
# H3 — path traversal via dep name
# ---------------------------------------------------------------------------


def test_h3_dotdot_name_in_index_raises_unsafe_name():
    """A package name containing `..` is a path-traversal vector and must
    be rejected at index-parse time with TNG-UNSAFE-NAME."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "../evil" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/evil"
            ref "main"
        }
    }
}
""")
    assert exc.value.code == "TNG-UNSAFE-NAME"


def test_h3_slash_in_name_rejected():
    """A package name containing `/` escapes _deps/ when used as a path
    component."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo/bar" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/foo"
            ref "main"
        }
    }
}
""")
    assert exc.value.code == "TNG-UNSAFE-NAME"


def test_h3_absolute_name_rejected():
    """An absolute path as a package name escapes _deps/."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "/etc/passwd" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/x"
            ref "main"
        }
    }
}
""")
    assert exc.value.code == "TNG-UNSAFE-NAME"


def test_h3_name_from_url_dotdot_raises():
    """_name_from_url('https://x.com/..') must not produce `..` as a
    path component — must raise a resolver-level error."""
    from milpa.resolver import _name_from_url

    with pytest.raises(ValueError, match="unsafe"):
        _name_from_url("https://evil.com/..")


def test_h3_name_from_url_double_dot_tail_raises():
    """A URL whose trailing path segment is `..` (common traversal) must
    raise, not return `..` as a name."""
    from milpa.resolver import _name_from_url

    # e.g. "https://evil.com/foo/.." — the tail IS ".."
    with pytest.raises(ValueError, match="unsafe"):
        _name_from_url("https://evil.com/foo/..")


def test_h3_safe_name_accepted():
    """A normal package name passes without error."""
    idx = parse_index("""\
package "nim-chronos" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/chronos"
            ref "main"
        }
    }
}
""")
    assert idx.lookup("nim-chronos")[0].version == "1.0.0"


# ---------------------------------------------------------------------------
# M1 — OCI field injection + digest format
# ---------------------------------------------------------------------------


def test_m1_oci_digest_wrong_format_rejected():
    """An OCI digest that is not `sha256:<64 hex>` must be rejected at
    index-parse time with TNG-BAD-OCI-DIGEST."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "user/pkg"
            digest "sha256:tooshort"
        }
    }
}
""")
    assert exc.value.code == "TNG-BAD-OCI-DIGEST"


def test_m1_oci_registry_leading_dash_rejected():
    """OCI registry beginning with `-` is flag injection for oras."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "oci"
            registry "--evil"
            repository "user/pkg"
            digest "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    }
}
""")
    assert exc.value.code == "TNG-UNSAFE-OCI-FIELD"


def test_m1_oci_repository_leading_dash_rejected():
    """OCI repository beginning with `-` is flag injection for oras."""
    with pytest.raises(TianguisError) as exc:
        parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "--evil/pkg"
            digest "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    }
}
""")
    assert exc.value.code == "TNG-UNSAFE-OCI-FIELD"


def test_m1_valid_oci_provenance_accepted():
    """A well-formed OCI provenance (valid digest, no leading dashes) parses."""
    idx = parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "user/pkg"
            digest "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    }
}
""")
    from milpa.fetchers.oci import OciProvenance
    p = idx.lookup("foo")[0].provenances[0]
    assert isinstance(p, OciProvenance)
    assert p.digest == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# L10 — commit re-check after unshallow fallback
# ---------------------------------------------------------------------------


def test_l10_clear_error_when_commit_not_found_after_full_fetch(tmp_path):
    """After the unshallow + full-history fallback, if the commit is
    STILL absent, the error message must say so clearly — not let a
    later `git checkout` fail with an opaque message."""
    import subprocess
    from milpa.fetchers import FetchError
    from milpa.fetchers.git import GitFetcher, GitProvenance

    src = tmp_path / "src"
    src.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(src)], check=True)
    (src / "a.txt").write_text("hello\n")
    subprocess.run(
        ["git", "-C", str(src), "-c", "user.email=t@e", "-c", "user.name=t",
         "add", "."], check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(src), "-c", "user.email=t@e", "-c", "user.name=t",
         "commit", "-q", "-m", "init"], check=True, capture_output=True,
    )

    fetcher = GitFetcher()
    nonexistent_sha = "a" * 40  # 40-hex valid format but never committed

    with pytest.raises(FetchError) as exc:
        fetcher.fetch(
            "foo",
            GitProvenance(
                url=f"file://{src}",
                ref="main",
                commit_sha=nonexistent_sha,
            ),
            dest=tmp_path / "_deps" / "foo",
        )
    # The error must mention the SHA, making the failure actionable.
    assert nonexistent_sha in str(exc.value), (
        "error message must name the missing commit SHA"
    )
    assert "not found" in str(exc.value).lower(), (
        "error message must say the commit was not found"
    )


# ---------------------------------------------------------------------------
# L12 — malformed (non-string) package name warning
# ---------------------------------------------------------------------------


def test_l12_non_string_package_name_warns():
    """A package node whose first arg is not a string must warn (not
    silently skip) — consistent with the duplicate-version warn style."""
    import warnings

    # KDL integer as the package name arg
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        parse_index("""\
package 42 {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/x"
            ref "main"
        }
    }
}
""")
    # At least one warning mentioning the malformed entry
    assert any("malformed" in str(warning.message).lower() or
               "package" in str(warning.message).lower()
               for warning in w), (
        "a malformed (non-string) package name must emit a warning"
    )


# ---------------------------------------------------------------------------
# RS1 — fullmatch: trailing newline must not slip past the validators
# ---------------------------------------------------------------------------


def test_rs1_commit_sha_with_trailing_newline_rejected():
    """A commit_sha that is exactly 40 hex chars but has a trailing newline
    must be rejected — `$` matches before a final newline in Python regex,
    so the old `re.match` would silently accept it. `re.fullmatch` (or `\\Z`)
    closes this gap."""
    sha_with_newline = "cafef00dcafef00dcafef00dcafef00dcafef00d\n"
    with pytest.raises(TianguisError) as exc:
        parse_index(f"""\
package "foo" {{
    version "1.0.0" {{
        content_hash "sha256:abc"
        provenance {{
            kind "git"
            url "https://example.com/foo"
            ref "main"
            commit_sha "{sha_with_newline}"
        }}
    }}
}}
""")
    assert exc.value.code == "TNG-BAD-COMMIT-SHA", (
        "a commit_sha with a trailing newline must be rejected as TNG-BAD-COMMIT-SHA"
    )


def test_rs1_oci_digest_with_trailing_newline_rejected():
    """An OCI digest that matches the `sha256:<64 hex>` pattern but carries
    a trailing newline must be rejected — the old `re.match` with `$` would
    accept it because `$` matches before the final newline."""
    good_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    digest_with_newline = f"sha256:{good_hex}\n"
    with pytest.raises(TianguisError) as exc:
        parse_index(f"""\
package "foo" {{
    version "1.0.0" {{
        content_hash "sha256:abc"
        provenance {{
            kind "oci"
            registry "ghcr.io"
            repository "user/pkg"
            digest "{digest_with_newline}"
        }}
    }}
}}
""")
    assert exc.value.code == "TNG-BAD-OCI-DIGEST", (
        "an OCI digest with a trailing newline must be rejected as TNG-BAD-OCI-DIGEST"
    )
