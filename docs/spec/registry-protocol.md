# milpa registry protocol (S14)

Normative spec for how milpa **reads** the tianguis registry `index.kdl`
to resolve named deps. This is the **read contract only** — how a
`(name, constraint)` pair maps to candidate `(version, provenance)` records.
Index-deps resolution policy (the solver's strategy over those candidates) is
deferred to #98/#86 and is explicitly out of scope here.

Every parser that claims milpa conformance MUST implement the rules marked
`> NORMATIVE:`. Items marked `> NOTE:` describe the reference Python
implementation; conformant alternatives MAY differ in those details.

Related specs:

- `docs/spec/errors.md` — every `TNG-*` error code this protocol can produce
- `docs/spec/manifest-grammar.md` — P3 provenance-descriptor model (§4), which
  this spec cross-references normatively
- `docs/spec/lockfile-schema.md` (S5) — lockfile representation of provenance
- `docs/spec/resolver-semantics.md` (S6) — how candidate lists feed the solver
- `docs/spec/cli-contract.md` (S15) — environment variables including
  `MILPA_INDEX_URL`

---

## Normative surface

A conformant implementation of this spec MUST:

1. Parse `index.kdl` as a valid KDL 1.0 document.
2. Reject (`TNG-SCHEMA-UNKNOWN`) any document whose declared `schema_version`
   integer exceeds `TIANGUIS_INDEX_SCHEMA_VERSION` (currently `1`).
3. Treat provenance records inside index entries as **strict subsets of the
   manifest provenance-descriptor grammar** (§4 of `manifest-grammar.md`); MUST
   NOT define a second, parallel grammar.
4. Validate all security-critical fields at parse time, before any string flows
   into subprocess argv or the filesystem (§4 of this document).
5. Implement the named-dep lookup contract: name → candidate list, ordered
   descending by semver, constraint-filtered (§5).
6. Treat unknown version-node children (including `rekor`, `attestation`,
   `signed_by`, `published_at`, `upstream`, `namespace`) as forward-compat
   metadata: parse MUST succeed, fields MUST be ignored.
7. Treat unknown provenance `kind` values as forward-compat: skip the
   provenance record rather than failing, provided at least one known-kind
   provenance remains on the version.
8. Raise `TNG-NO-IDENTITY` for any index entry whose `content_hash` is absent
   or empty; MUST NOT attempt to fetch a version without a verifiable identity
   (§3.2).
9. Use `DEFAULT_INDEX_URL` when no override is configured; honor
   `MILPA_INDEX_URL` when set (§1).
10. Implement the four-state cache freshness model: fresh-serve / stale-refetch
    / offline-fallback / no-cache-error (§6).

---

## 1  Document structure

An `index.kdl` document is a flat sequence of top-level nodes. The parser
recognises two kinds of top-level node:

- `schema_version <int>` — optional schema-version declaration (§2).
- `package "<name>" { … }` — a named-package entry (§3).

All other top-level nodes MUST be silently skipped (forward-compat).

> NORMATIVE: The default index URL is
> `https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl`.
> This is the `DEFAULT_INDEX_URL` constant in the reference implementation.
> Conformant implementations MUST use this URL when no override is configured.

> NORMATIVE: The environment variable `MILPA_INDEX_URL`, when set to a
> non-empty string, MUST override the default index URL for all index-fetching
> operations in that invocation. This allows air-gapped, mirrored, or
> enterprise deployments to substitute a private index. See
> `docs/spec/cli-contract.md` (S15) §8 for the full environment variable
> table.

> NOTE: The live index is a flat KDL file of `package` nodes with no nesting
> beyond the package/version/provenance hierarchy.

---

## 2  Schema-version negotiation

> NORMATIVE: The `index.kdl` document MAY carry a top-level
> `schema_version <int>` node. When absent the document is treated as version
> 1 (legacy/minimal indexes predate the field).

> NORMATIVE: A conformant implementation MUST define a constant
> `TIANGUIS_INDEX_SCHEMA_VERSION` (spec v1.0 value: `1`). When the document
> declares a `schema_version` integer **strictly greater than** this constant,
> the implementation MUST raise `TNG-SCHEMA-UNKNOWN` and MUST NOT attempt to
> parse the rest of the document. The error message MUST name both the declared
> version and the maximum understood version and MUST direct the user to upgrade
> milpa.

> NORMATIVE: When the declared `schema_version` is **less than or equal to**
> `TIANGUIS_INDEX_SCHEMA_VERSION`, the document MUST be parsed
> forward-compatibly — unknown nodes and fields are silently skipped; no error
> is raised for unrecognised top-level nodes.

> NOTE: The `schema_version` value is parsed as an integer. The reference
> implementation (`_scalar_int`) handles the KDL-library quirk of emitting bare
> integers as float: a whole-number float is coerced to `int`; a fractional
> float returns `None` (treated as absent). A boolean is explicitly rejected
> (bool is an int subclass in Python).

---

## 3  Package entry structure

A package entry has the KDL form:

```kdl
package "<name>" {
    namespace "<org-or-user>"
    upstream (url)"<canonical-URL>"
    version "<semver>" {
        content_hash "<algorithm>:<hex>"
        provenance {
            kind "<git|oci|…>"
            // kind-specific fields (§3.2)
        }
        [provenance { … }]           // additional provenances, preference-ordered
        attestation "<label>"        // e.g. "author-signed" or "milpa-vendored"
        signed_by "<identity>"
        published_at "<ISO-8601>"
        rekor {                      // durable Rekor reference; optional
            uuid "<hex>"
            log_index "<decimal-string>"
            integrated_time "<decimal-string>"
        }
    }
    [version "…" { … }]             // additional versions
}
```

### 3.1  Package-level fields

**`name`** (positional arg on the `package` node, required) — the bare package
name, as a KDL string.

> NORMATIVE: A `package` node whose first positional argument is not a string
> MUST emit a `UserWarning` and be silently skipped. It MUST NOT raise a hard
> error — forward-compat (a malformed double entry does not block others).

> NORMATIVE: A `package` name that contains path-traversal characters (`..`,
> `/`, `\`, or that is an absolute path) MUST raise `TNG-UNSAFE-NAME` at parse
> time. This check applies before the entry is stored or any fetch attempted,
> because names flow directly into `_deps/<name>/` on the filesystem.

**`namespace`** (child node, optional) — the registry namespace (typically a
GitHub org or user). Together with `name` it forms the unique `(namespace,
name)` identity key.

> NOTE: Two packages MAY share a bare `name` under different namespaces (e.g.
> a library that has been forked). The internal store is keyed on
> `(namespace, name)`; a bare-name lookup that matches multiple namespaces
> returns `AmbiguousName` rather than silently picking one.

**`upstream`** (child node, optional) — the canonical source URL for the
package. Accepted in plain-string and `(url)`-annotated form. Informational;
not used during fetch.

### 3.2  Version entry structure

Each `version "<semver>" { … }` child of a `package` node records one
published version.

> NORMATIVE: A `version` node whose first positional argument is not a string
> MUST be silently skipped.

> NORMATIVE: If a `package` node declares the same version string more than
> once, the first occurrence MUST be kept and subsequent duplicates MUST emit a
> `UserWarning` and be skipped. Duplicate versions MUST NOT raise a hard error.

**`content_hash`** (child node, string, **required and non-empty**) — the
sha256 identity of the source tree, in `sha256:<64-hex>` form. This is the
value milpa recomputes after fetching to enforce Invariant 1 (identity gate).
See `docs/spec/identity.md` (S12) for the canonical byte algorithm.

> NORMATIVE: An index entry whose `content_hash` is absent or empty string
> MUST raise `TNG-NO-IDENTITY` on the resolution read path. Identity is
> non-negotiable in milpa: a fetch without a content_hash to verify against
> provides no supply-chain integrity guarantee. The resolver MUST NOT
> attempt to fetch a version whose `content_hash` is absent or empty.

> NOTE: Legacy index entries from before the identity mandate may carry an
> empty `content_hash`. The reference implementation stores it as `""` after
> parsing but raises `TNG-NO-IDENTITY` before any fetch is attempted
> (`_resolve_named_version` in `tianguis_client.py`). There is no "identity
> not recorded" permissive path on the resolution read path.

**`provenance`** (child node, zero or more) — a provenance descriptor (§3.3)
describing how to fetch this version's source tree. Multiple `provenance` nodes
on the same version are **preference-ordered** by index-document order: the
first is canonical, the rest are mirrors. A fetcher MUST attempt them in order.

> NORMATIVE: Provenance records inside an index entry are a **strict subset of
> the manifest provenance-descriptor grammar** defined in
> `docs/spec/manifest-grammar.md` §4. The meta-grammar, kind-set, and field
> shapes are the same. Index entries add only index-specific metadata
> (`content_hash`, attestation fields, Rekor block) alongside the provenance;
> they do not introduce a new or parallel provenance grammar. Implementations
> MUST NOT write a second provenance parser for the index — one parser, shared.

**`attestation`** (child node, string, optional) — a label indicating the trust
path: `"author-signed"` (package author signed the OCI artifact via cosign) or
`"milpa-vendored"` (tianguis vendor-en-absentia bot signed on the author's
behalf). MAY be absent on legacy entries.

> NOTE: milpa's reader treats `attestation` as forward-compat metadata: it is
> parsed and then ignored. The trust value is displayed by tianguis.dev; milpa
> does not enforce it during resolution.

**`signed_by`** (child node, string, optional) — the identity (GitHub Actions
workflow URL or bot identifier) that produced the attestation. Informational;
not enforced by milpa.

**`published_at`** (child node, string, optional) — ISO 8601 timestamp of when
the version was published. Informational.

**`rekor`** (child node, optional block) — a durable Rekor transparency-log
reference captured at publish time. Fields:

| Child | Type | Meaning |
|---|---|---|
| `uuid` | string | Rekor entry UUID (80-char hex in the reference index) |
| `log_index` | string | Rekor log index, as a decimal string |
| `integrated_time` | string | Unix timestamp (seconds) when the entry was integrated, as a decimal string |

> NORMATIVE: A conformant milpa reader MUST tolerate a `rekor` block on a
> version node. The block MUST NOT cause a parse error. milpa does not
> validate or enforce Rekor entries during resolution; the block is
> forward-compat metadata for the tianguis.dev site and auditing tooling.
> `IndexVersion` carries no `rekor` field; Rekor data is inert to the
> resolver.

> NOTE: The test fixture `REKOR_INDEX` in `tests/test_tianguis_client.py`
> (test `test_rekor_block_is_tolerated_and_ignored`) is the regression pin
> for this forward-compat requirement. It verifies that `IndexVersion` has no
> `rekor` attribute after parsing.

### 3.3  Provenance record shapes (index form)

Index provenance records use the same kind-set and field shapes as the manifest
grammar's §4.2, with the additional acceptance of `(url)`-annotated URL values
(the milpa KDL url convention — see `manifest-grammar.md` §2).

#### `git` provenance

```kdl
provenance {
    kind "git"
    url (url)"<https-or-http-or-ssh-or-git URL>"
    ref "<git-ref>"
    commit_sha "<40-hex>"    // optional — immutable pin
}
```

Fields: `url` (required), `ref` (required), `commit_sha` (optional).

> NORMATIVE: `url` MUST be accepted in both plain-string and `(url)`-annotated
> form (the live tianguis index uses `(url)` annotation). The value is
> normalized to a plain URL string before use.

> NORMATIVE: When `commit_sha` is present it MUST be a 40-character lowercase
> hexadecimal string (`[0-9a-f]{40}`). A non-conforming value MUST raise
> `TNG-BAD-COMMIT-SHA` at parse time. When absent, the fetcher falls back to
> the tip of `ref`.

> NORMATIVE: `url` MUST NOT begin with `-`. A leading dash MUST raise
> `TNG-UNSAFE-URL` at parse time (flag-injection prevention).

> NORMATIVE: `ref` MUST NOT begin with `-`. A leading dash MUST raise
> `TNG-UNSAFE-REF` at parse time (flag-injection prevention).

#### `oci` provenance

```kdl
provenance {
    kind "oci"
    registry "<hostname>"
    repository "<org/name>"
    digest "sha256:<64-hex>"
}
```

Fields: `registry` (required), `repository` (required), `digest` (required).

> NORMATIVE: `digest` MUST be in `sha256:<64 lowercase hex>` form. Any other
> format MUST raise `TNG-BAD-OCI-DIGEST` at parse time.

> NORMATIVE: `registry` and `repository` MUST NOT begin with `-`. A leading
> dash on either field MUST raise `TNG-UNSAFE-OCI-FIELD` at parse time
> (flag-injection prevention; these values flow into `oras` argv).

#### Unknown kinds

> NORMATIVE: A `provenance` node whose `kind` value is not `"git"` or `"oci"` MUST
> be silently skipped (forward-compat: a future transport the index records but this
> milpa cannot fetch is non-fatal provided other provenances on the same version
> remain fetchable).

---

## 4  Security validators

All validators are applied **at parse time**, at the trust boundary, before any
index-supplied string can reach subprocess argv or the filesystem. This is the
single source of truth for these checks; the rest of the system may trust that
strings passing these validators are safe.

| Code | What it checks | Rejects |
|---|---|---|
| `TNG-UNSAFE-NAME` | Package `name` (positional arg on `package` node) | Names containing `..`, `/`, `\`, or that are absolute paths — these would escape `_deps/<name>/` |
| `TNG-BAD-COMMIT-SHA` | `commit_sha` in a `git` provenance | Any value not matching `^[0-9a-f]{40}$` — removes flag-injection vector and abbreviated-SHA ambiguity |
| `TNG-UNSAFE-URL` | `url` in a `git` provenance | Any value beginning with `-` — prevents flag injection into git subprocess argv |
| `TNG-UNSAFE-REF` | `ref` in a `git` provenance | Any value beginning with `-` — prevents flag injection into git subprocess argv |
| `TNG-BAD-OCI-DIGEST` | `digest` in an `oci` provenance | Any value not matching `^sha256:[0-9a-f]{64}$` — enforces OCI digest format, prevents malformed reference string in oras argv |
| `TNG-UNSAFE-OCI-FIELD` | `registry` and `repository` in an `oci` provenance | Any value beginning with `-` — prevents flag injection into oras subprocess argv |
| `TNG-SCHEMA-UNKNOWN` | Top-level `schema_version` integer | Any value strictly greater than `TIANGUIS_INDEX_SCHEMA_VERSION` |

> NORMATIVE: All six field-level validators (`TNG-UNSAFE-NAME`,
> `TNG-BAD-COMMIT-SHA`, `TNG-UNSAFE-URL`, `TNG-UNSAFE-REF`,
> `TNG-BAD-OCI-DIGEST`, `TNG-UNSAFE-OCI-FIELD`) MUST be applied during
> `parse_index`, not deferred to fetch time. An index entry that fails
> validation MUST raise the corresponding error immediately.

> NOTE: The `is_safe_name` predicate is also used by the resolver's
> URL-derived name check (`_name_from_url`) — one predicate, two call sites.
> This is the single source of truth for the safe-name rule.

---

## 5  Named-dep resolution read-contract

This section specifies the contract by which a `(name, constraint)` pair maps
to a candidate list via the index. This is the **index read contract** only;
how the solver selects among candidates is specified in
`docs/spec/resolver-semantics.md` (S6).

### 5.1  Bare-name lookup

The index stores packages keyed on `(namespace, name)`. The resolution
entry point uses a bare-name lookup (no namespace qualifier) via
`Index.lookup_bare`.

> NORMATIVE: A bare-name lookup that matches **no** package MUST raise
> `TNG-NOT-FOUND`.

> NORMATIVE: A bare-name lookup that matches packages under **more than one**
> namespace MUST raise `TNG-AMBIGUOUS-NAME`. The error message MUST list all
> matching namespaces.

> NOTE: The `AmbiguousName` result type is distinct from the raised error: the
> registry primitive `Index.lookup_bare` returns `AmbiguousName` (a typed
> value, not an exception) so that a future multi-version provider
> (P3.2/#100) can enumerate all candidates during backtracking without a hard
> stop. The policy layer (`resolve_named`, `resolve_named_all`) converts
> `AmbiguousName` to `TNG-AMBIGUOUS-NAME`.

### 5.2  Constraint filtering and ordering

Once a package is found, its versions are filtered by the constraint.

> NORMATIVE: Versions are ordered **descending by semver** (newest first)
> before constraint filtering. Parseable semver versions precede unparseable
> ones (in stable input order). This ordering MUST be applied at parse time
> (`parse_index`), not at lookup time.

> NORMATIVE: Versions whose version string is not a parseable semver triple
> (`X.Y.Z`) MUST be silently skipped during constraint filtering. They are
> stored in the index (in stable input order, after parseable versions) but
> are not candidates for constraint-based resolution.

> NORMATIVE: Given a constraint string, a conformant implementation MUST
> apply `VersionSet.from_constraint(constraint).contains(version)` to each
> candidate. Versions that do not satisfy the constraint MUST be excluded. A
> `None` constraint means "any version" — all parseable versions are
> candidates.

> NOTE: `VersionSet.from_constraint` is defined in `milpa/solver.py` and is
> the single source of truth for constraint matching. `registry-protocol.md`
> does not define constraint syntax; cross-reference
> `docs/spec/resolver-semantics.md` (S6) for the constraint grammar.

### 5.3  Provenance-less version handling

> NORMATIVE: A version entry with no `provenance` child nodes (or whose only
> `provenance` nodes have unknown kinds and were skipped) MUST be excluded from
> the satisfying candidate list with a `UserWarning`. It MUST NOT raise an
> immediate error — older valid versions on the same package should still be
> reachable.

> NORMATIVE: If every satisfying version was excluded for lack of provenance,
> the implementation MUST raise `TNG-NO-PROVENANCE` (not
> `TNG-NO-SATISFYING-VERSION`). The error message MUST list the excluded
> version strings.

### 5.4  No-satisfying-version

> NORMATIVE: If no version satisfies the constraint (and no provenance-less
> exclusions occurred), the implementation MUST raise
> `TNG-NO-SATISFYING-VERSION`. The error message MUST list all available
> version strings.

### 5.5  Result: `resolve_named_all` vs `resolve_named`

Two resolution entry points are specified:

**`resolve_named_all(index, name, constraint) → list[IndexVersion]`** — returns
ALL satisfying `IndexVersion` records, ordered descending by semver. This is
the Phase-A enumerate step for P3.2's two-phase model: the caller registers the
full candidate set into the solver provider so the solver can choose and
backtrack.

**`resolve_named(index, name, constraint) → IndexVersion`** — returns the
single highest-semver satisfying `IndexVersion`. Equivalent to
`resolve_named_all(…)[0]`.

> NORMATIVE: Both entry points MUST apply the same structural error policy:
> `TNG-NOT-FOUND`, `TNG-AMBIGUOUS-NAME`, `TNG-NO-SATISFYING-VERSION`,
> `TNG-NO-PROVENANCE` (in that precedence order).

---

## 6  Index caching

> NORMATIVE: A conformant implementation MUST cache the fetched `index.kdl`
> under a stable per-URL cache location. The **cache key** MUST be a
> deterministic function of the index URL (the reference uses the first 16 hex
> characters of `sha256(url.encode("utf-8"))`). Using a deterministic cache key
> is normative so that two concurrent invocations share the same cache entry
> and air-gapped deployments that substitute `MILPA_INDEX_URL` cache the
> substitute correctly.

> NORMATIVE: Cache freshness model — a conformant implementation MUST implement
> the following four-state behavior:
>
> 1. **Fresh cache** (cache present and age < TTL) → serve cached bytes without
>    any network access.
> 2. **Stale cache** (cache present and age ≥ TTL) → attempt re-fetch; on
>    success overwrite the cache and serve fresh bytes.
> 3. **Network failure with stale-but-present cache** → serve the stale cache
>    as an offline fallback and emit a warning to stderr indicating the index
>    may be out of date. MUST NOT raise an error in this case.
> 4. **Network failure with no cache** → propagate the error; MUST NOT proceed
>    without an index.

> NORMATIVE: Cache writes MUST be atomic. The implementation MUST write to a
> sibling temporary file and rename it into place (`os.replace` / `rename(2)`)
> to prevent a concurrent reader from observing a partial write.

> NORMATIVE: The index cache lives outside the project directory. `milpa clean`
> MUST NOT remove the index cache. Multiple concurrent `milpa` invocations MAY
> share the same cache file safely because cache writes are atomic.

> NOTE: The reference implementation caches under
> `$XDG_CACHE_HOME/milpa/index/` (default `~/.cache/milpa/index/`). The
> default TTL is 24 hours — generous enough to avoid hammering tianguis on
> every invocation, short enough that the vendor-en-absentia daily pass is
> visible within the same cycle. Conformant implementations MAY use a different
> default TTL; the four-state behavior model above is normative, the 24h value
> is not.

---

## Appendix A  Error-code summary (TNG-* domain)

All tianguis-domain errors use stable slug codes. Consumers (CI scripts, IDE
integrations, alternate implementations) MAY rely on slugs; MUST NOT rely on
message wording.

| Code | When raised |
|---|---|
| `TNG-SCHEMA-UNKNOWN` | Declared `schema_version` > `TIANGUIS_INDEX_SCHEMA_VERSION` |
| `TNG-UNSAFE-NAME` | Package name contains path-traversal characters |
| `TNG-BAD-COMMIT-SHA` | `commit_sha` not exactly 40 lowercase hex chars |
| `TNG-UNSAFE-URL` | Git `url` begins with `-` |
| `TNG-UNSAFE-REF` | Git `ref` begins with `-` |
| `TNG-BAD-OCI-DIGEST` | OCI `digest` not in `sha256:<64 hex>` form |
| `TNG-UNSAFE-OCI-FIELD` | OCI `registry` or `repository` begins with `-` |
| `TNG-NOT-FOUND` | Bare-name lookup matches no package |
| `TNG-AMBIGUOUS-NAME` | Bare-name lookup matches multiple namespaces |
| `TNG-NO-SATISFYING-VERSION` | No version satisfies the constraint |
| `TNG-NO-PROVENANCE` | All satisfying versions lack provenance |
| `TNG-NO-IDENTITY` | Index entry's `content_hash` is absent or empty string; raised before any fetch is attempted |

---

## Appendix B  Minimal `index.kdl` example

```kdl
schema_version 1

package "nimkdl" {
    namespace "coreyleavitt"
    upstream (url)"https://github.com/coreyleavitt/nimkdl"
    version "0.1.4" {
        content_hash "sha256:1aaf2a95f53681c86f6dcd4c1267144401ba923f31afa42da3c5ae783dc7ab61"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "coreyleavitt/nimkdl"
            digest "sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24"
        }
        attestation "author-signed"
        signed_by "https://github.com/coreyleavitt/tianguis/.github/workflows/publish.yaml"
        published_at "2026-05-26T04:49:44Z"
        rekor {
            uuid "108e9186e8c5677abce5a62d285437741218f878474a02d9a4dac01dc12e39b979336e712890d636"
            log_index "1753541583"
            integrated_time "1780881469"
        }
    }
}

package "chronos" {
    namespace "status-im"
    upstream (url)"https://github.com/status-im/nim-chronos"
    version "4.0.3" {
        content_hash "sha256:abc123…"
        provenance {
            kind "git"
            url (url)"https://github.com/status-im/nim-chronos"
            ref "HEAD"
            commit_sha "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        }
        attestation "milpa-vendored"
    }
}
```
