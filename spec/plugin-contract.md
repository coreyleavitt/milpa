# milpa fetcher protocol (S10)

Normative spec of the **Fetcher protocol** — the language-agnostic contract
a transport plugin must satisfy. Any implementation that claims milpa conformance
MUST implement the rules marked `> NORMATIVE:`. Items marked `> NOTE:` describe
the reference Python implementation; conformant alternatives MAY differ in those
details.

This document covers **Layer 2 backend-binding obligations** only.

- **Layer 1 — Provenance-descriptor grammar** (closed meta-grammar, kind
  registry, parse-always / verify-always / fetch-fails-precisely): see
  `spec/manifest-grammar.md` §4 (S4). Do not duplicate the provenance
  shape enumeration here.
- **Layer 3 — Discovery** (`milpa.fetchers` entry-point convention, factory
  signature): Python-specific mechanism implemented in the reference
  implementation's `milpa/fetchers/__init__.py` (`_build_default_registry`,
  `importlib.metadata` entry-point scan). Not normative for non-Python porters;
  non-Python implementations define their own equivalent discovery mechanism.

Related specs:

- `spec/errors.md` — `FETCH-*` error codes
- `spec/identity.md` (S12) — identity algorithm; CAS admission;
  `cas_admissible` CAS-level contract
- `spec/manifest-grammar.md` (S4) — provenance shapes (Layer 1); closed
  meta-grammar; kind registry

---

## Normative surface

A conformant fetcher implementation MUST:

1. Implement the three obligations — Claim, Materialize, Receipt — as defined
   in §1.
2. Signal materialization failure by raising `FetchError` (Python) / returning
   `Err(FetchError)` (Rust); leave `dest` cleanup to the registry (§2).
3. NOT compute or assert identity in any receipt field; the registry computes
   identity post-fetch (§3).
4. Declare `cas_admissible` on every `Provenance` subclass; editable sources
   MUST declare `False` (§4).
5. Return `True` from `can_handle` for exactly the provenance kind(s) the
   fetcher declares; MUST NOT return `True` for any other kind (§5).

A conformant registry implementation MUST:

6. Enforce unique-match dispatch: raise an ambiguity error if two or more
   registered fetchers claim `can_handle` for one descriptor; raise a no-handler
   error if none do (§5).
7. Compute identity from the materialized tree after every successful fetch,
   never delegating identity computation to the fetcher (§3).
8. Read `cas_admissible` before calling `admit()` and skip CAS admission for
   non-admissible provenances (§4).

---

## 1  Three obligations

Every fetcher satisfies exactly three obligations.

### 1.1  Claim

> NORMATIVE: A fetcher MUST implement `can_handle(provenance) -> bool`. The
> method MUST return `True` for every provenance kind the fetcher declares
> support for and MUST return `False` for every other kind. A fetcher MUST NOT
> return `True` for a provenance kind it cannot fully materialize.

The return value is the fetcher's sole dispatch signal. The registry calls
`can_handle` on every registered fetcher and enforces unique-match (§5).

### 1.2  Materialize

> NORMATIVE: A fetcher MUST implement `fetch(name, provenance, *, dest) ->
> ProvenanceReceipt`. On success, the materialized source tree MUST be
> accessible at `dest` when the method returns. Two forms are conformant:
>
> - **CAS-admissible fetchers** (git, tarball, oci): MUST materialize the tree
>   as a real directory at `dest/`. The registry then admits the directory into
>   the CAS and replaces `dest` with a relative CAS symlink (§3.5).
>
> - **Non-admissible (editable) fetchers** (local, member): MUST create a
>   **symlink** at `dest` pointing to the source directory. MUST NOT copy,
>   move, or snapshot the tree. The symlink gives the user edit-in-place
>   semantics: changes to the source are immediately visible through `dest`
>   without a re-fetch. The registry does NOT create a CAS entry for this dep.

> NORMATIVE: The fetcher MUST NOT compute, hash, or assert identity — it must
> not call the milpa identity algorithm (`compute_content_hash` or equivalent)
> anywhere in its `fetch` implementation. Identity is computed by the registry
> post-fetch (§3).

> NORMATIVE: `dest` is provided by the registry. For admissible fetchers, the
> fetcher MUST write the tree into the directory at `dest/`. For non-admissible
> fetchers, the fetcher MUST create a symlink at `dest` (not a parallel path or
> a renamed location).

### 1.3  Receipt

> NORMATIVE: `fetch` MUST return a `ProvenanceReceipt` subclass instance that
> records transport-pinning fields (§3.2). The receipt MUST NOT contain any
> field whose value is a function of the materialized tree bytes (§3.1).

---

## 2  Failure

> NORMATIVE: When materialization cannot complete, the fetcher MUST signal
> failure by raising `FetchError` (Python) / returning `Err(FetchError)` (Rust)
> with an appropriate `FETCH-*` code from `spec/errors.md`.

> NORMATIVE: The contents of `dest` after a failure are **undefined**. The
> fetcher MUST NOT attempt to clean up `dest` itself; cleanup is the
> **registry's responsibility**. The registry calls `clear_dest(dest)` before
> retrying or propagating the error.

> NOTE: In the reference Python implementation, `FetcherRegistry.fetch` wraps
> the fetcher call in a `try/except BaseException` block and removes the scratch
> directory on failure (see `types.py`, the CAS path branch). Callers of
> `fetch_any` similarly call `clear_dest(dest)` between candidates. The fetcher
> is not involved.

The `FETCH-ALL-FAILED` code is raised by `fetch_any` when every candidate
provenance fails; individual fetcher failures use transport-specific codes
(`FETCH-GIT-FAILED`, `FETCH-DOWNLOAD-FAILED`, `FETCH-OCI-PULL-FAILED`, etc.).
See `spec/errors.md` §FETCH for the full list.

> NORMATIVE: A tarball fetcher MUST wrap all archive extraction operations with
> the sandboxed extractor. Extraction failures (zip-slip, symlink-escape, size
> limits, file-count limits) MUST be surfaced as `FETCH-*` errors; `EXTRACT-*`
> codes are defined in `spec/errors.md` §EXTRACT. The tarball fetcher
> signals extraction failure by raising `FetchError` with the appropriate
> `EXTRACT-*` code as the cause; the cleanup obligation above applies.

---

## 2.1  Tarball extraction limits

> NORMATIVE: A conformant tarball fetcher MUST apply the following extraction
> limits **before or during** extraction, before any bytes are written to
> `dest/`. Limits are enforced by the sandboxed extractor
> (`safe_extract.extract_tar` in the reference implementation). The defaults
> are normative; a conformant implementation MAY allow callers to tighten them
> but MUST NOT exceed them without explicit user configuration.
>
> | Limit | Default | Error code |
> |---|---|---|
> | Total uncompressed size across all entries | 1 GiB (2³⁰ bytes) | `EXTRACT-SIZE-LIMIT` |
> | Per-file uncompressed size | 256 MiB (2²⁸ bytes) | `EXTRACT-SIZE-LIMIT` |
> | Total file count (regular files + symlinks) | 100 000 | `EXTRACT-SIZE-LIMIT` |
>
> Additionally, the extractor MUST reject:
>
> | Attack class | Error code |
> |---|---|
> | Zip-slip (entry resolves outside `dest/`) | `EXTRACT-ZIP-SLIP` |
> | Symlink-escape (symlink target resolves outside `dest/`) | `EXTRACT-SYMLINK-ESCAPE` |
>
> All five checks MUST be applied to every extraction. The size checks run
> during extraction (streaming); the path-escape checks run
> per-entry before any write. A failure MUST abort the extraction immediately
> and raise `FetchError` with the matching code.

> NOTE: The reference implementation's defaults are declared as keyword
> arguments on `extract_tar` in `milpa/fetchers/safe_extract.py`:
> `max_total_size=1<<30`, `max_file_size=1<<28`, `max_file_count=100_000`.
> Device nodes, FIFOs, and other non-regular, non-symlink, non-directory entry
> types are silently skipped (never legitimate in a source archive).

---

## 2.2  Hardlink target geometry

> NORMATIVE: A tar **hardlink** entry (typeflag `1`) encodes the link target in
> `linkname`, which is an **archive-absolute path** — not a relative symlink
> target. A conformant extractor MUST apply `strip_components` to `linkname`
> using the same POSIX-`/` split as to the entry name, then resolve the stripped
> target against `dest_root` (not relative to the entry's parent directory).
> The resolved target MUST be checked for escape: if it does not start with
> `dest_root` the extractor MUST raise `EXTRACT-ZIP-SLIP` (the same slug as a
> regular path-traversal escape — no new slug).

> NORMATIVE: A conformant extractor MUST materialize a hardlink entry as a
> **file copy** of the target's bytes, not as a filesystem hard link or a
> symlink. A content-addressed store represents identical content as a copy;
> this preserves hash-stability — two archives encoding the same logical tree
> with a hardlink vs a plain duplicate file produce the same `content_hash`.

> NORMATIVE: Extraction MUST be performed in two passes:
>
> 1. **First pass** — process every entry that is NOT a hardlink (regular files,
>    directories, symlinks), in archive order.
> 2. **Second pass** — process every hardlink entry, in archive order.
>
> The two-pass ordering is required because a hardlink entry MAY
> forward-reference a target not yet written (tar ordering is arbitrary). The
> copy-bytes strategy requires the source file to exist when the hardlink is
> materialized; two-pass extraction guarantees this without imposing any
> ordering constraint on archive creators.

> NORMATIVE: `linkname` is split on POSIX `/` explicitly — not via the host
> operating system's path separator. This is a no-op on spec-v1 Linux but
> ensures geometry remains correct if future spec versions extend platform
> support to Windows.

> NOTE: `EXTRACT-HARDLINK-UNSUPPORTED` was mentioned in an earlier draft of
> `rfc-pluggable-fetchers.md` but was never added to `spec/errors.md` (the slug
> is absent). H2 of `rfc-fetch-extraction-hardening.md` supersedes the
> reject-with-new-slug approach with copy-bytes materialization; no new slug is
> needed and none may be added for this case.

---

## 2.3  The `materialize-git-tree` primitive

VCS fetchers (git, and future Hg/Fossil fetchers) MUST produce their
materialized tree via the impl's `materialize-git-tree` equivalent. This
function is the single chokepoint for blob writing, LFS detection, symlink
containment, and submodule recursion; these properties are structural (there
is exactly one place blobs are written), not achieved by per-caller discipline.

The normative contract for `materialize-git-tree`:

### 2.3.1  Subprocess discipline

> NORMATIVE: Blob enumeration MUST use `git ls-tree -r <commit>`, which
> emits one `(mode, type, sha, path)` record per blob and gitlink. Blob
> bytes MUST be streamed from the object store via a **single**
> `git cat-file --batch` subprocess invocation (all SHAs on stdin, headers
> and raw bytes on stdout). A per-blob `cat-file` subprocess call is NOT
> conformant: a dep with 10 000 files would spawn 10 000 processes and may
> exhaust OS `ulimit` ceilings in constrained CI environments.

> NORMATIVE: The backing clone MUST be `--no-checkout` (or bare). A
> default `git clone` creates a working tree and runs smudge filters at
> checkout time, defeating the object-store mechanism. See
> `spec/identity.md §1.7.1`.

### 2.3.2  LFS pointer detection

> NORMATIVE: Before writing any blob to the output tree, the implementation
> MUST test whether the blob is a Git-LFS pointer. A blob is a Git-LFS
> pointer if and only if its **first line** is exactly:
>
> ```
> version https://git-lfs.github.com/spec/v1
> ```
>
> The test MUST be applied to the first line only (the bytes up to and
> including the first `\n`, or the entire blob if shorter than one line).
> A large blob that contains that string elsewhere is NOT a pointer —
> first-line exact-match eliminates documentation false-positives.
>
> On detection, the implementation MUST raise `FETCH-GIT-LFS-POINTER`
> carrying `path=<relpath>` identifying the pointer file. milpa reads the
> git object store directly and cannot fetch LFS blobs; the tree would be
> incomplete (violating the *Complete* admission predicate). The error
> message MUST be actionable: it MUST indicate that the dep uses Git LFS
> and that the user should vendor a plain-git mirror or use a `local=`
> path.
>
> (`FETCH-GIT-LFS-POINTER` has its `spec/errors.md` catalog entry and a raise
> site in every conforming impl.)

### 2.3.3  Per-symlink lexical-containment check

> NORMATIVE: A mode-120000 blob in `ls-tree` output is a symlink; its blob
> bytes are the link-target string. The object-store path does NOT route
> through `SafeExtractor`, so `materialize-git-tree` MUST itself apply the
> same lexical-containment check that `SafeExtractor` uses for archive
> symlinks:
>
> 1. Decode the blob bytes as UTF-8 to obtain the link-target string `T`.
>    (A non-UTF-8 target MUST be treated as `ID-NON-UTF8-SYMLINK-TARGET`
>    per `spec/identity.md §1.5`.)
> 2. Compute the normalized absolute path `P = normalize(dest_root /
>    entry_dir / T)` where `normalize` resolves all `.` and `..` components
>    lexically without following filesystem symlinks.
> 3. If `P` does not start with `dest_root` the symlink escapes the dep
>    root and the implementation MUST raise `EXTRACT-SYMLINK-ESCAPE`
>    (the existing slug — no new slug). This is the same escape class
>    `SafeExtractor` guards against on the tarball path.
>
> This check MUST be applied to every mode-120000 entry before the symlink
> is written to disk.

### 2.3.4  On-disk mode

> NORMATIVE: Materialized blobs MUST be written with the fixed on-disk
> modes specified in `spec/identity.md §1.7.4`. This ensures that
> `milpa verify` re-hashing on a different host produces byte-identical
> results regardless of the host `umask`.

### 2.3.5  Submodule recursion

> NORMATIVE: A mode-160000 entry in `ls-tree` output is a gitlink (submodule
> reference). `materialize-git-tree` MUST recurse into every gitlink by
> applying the same primitive to the submodule's object store with the
> gitlink's pinned commit SHA. Recursion is always-on per
> `spec/identity.md §1.7.5`.
>
> The detailed mechanics — reading `.gitmodules` from the superproject
> object store, resolving relative `url =` values against the superproject's
> recorded provenance URL (`GitProvenance.url`), fetching submodule objects,
> and recording `path → SHA` pairs in `GitReceipt.submodule_shas` — are
> specified in `spec/lockfile-schema.md §4.1`.
>
> NORMATIVE (recursion bound): submodule recursion MUST be bounded. A
> conforming impl MUST reject recursion deeper than `MAX_SUBMODULE_DEPTH`
> (16) and MUST reject a `(resolved-url, commit-sha)` pair that recurs on
> the current recursion path (a cycle), in both cases raising
> `FETCH-GIT-SUBMODULE-FAILED` with `submodule_path=`/`submodule_url=`
> context. The depth bound is the load-bearing guard: an alternating
> superproject↔submodule chain presents a distinct commit SHA at each level,
> so the cycle set alone does not terminate it. The constant is normative so
> that a pathologically nested input is admitted-or-rejected identically on
> every implementation.

### 2.3.6  Output-tree cleanliness

> NORMATIVE: The output tree written to `dest/` MUST NOT contain a `.git`
> directory. The function writes only the blobs and symlinks enumerated by
> `ls-tree -r` into a clean output directory. Empty directories MUST NOT be
> synthesized (see `spec/identity.md §1.7.3`).

### 2.3.7  Entry-path containment

> NORMATIVE: `ls-tree` reports the path of each tree entry verbatim from the
> tree object. A hostile repository can encode an entry path that escapes the
> dep root — an absolute path or one containing `..` components — because git's
> own fsck does not run on objects produced by `git hash-object -t tree
> --literally` / `git mktree` and `clone` transfers them faithfully. The
> §2.3.3 containment check guards only the *target* of a mode-120000 symlink;
> it does NOT guard the *placement* of a regular blob (modes 100644/100755)
> or a mode-160000 gitlink sub-destination.
>
> Therefore, before writing any blob or creating any gitlink sub-destination,
> `materialize-git-tree` MUST compute the normalized absolute path
> `P = normalize(dest_root / entry_path)` (resolving `.`/`..` lexically,
> without following filesystem symlinks) and MUST require that `P` equals
> `dest_root` or lies strictly beneath it. An absolute `entry_path` or any
> escape MUST raise `EXTRACT-ZIP-SLIP` (the existing slug — no new slug; this
> is the same traversal class `SafeExtractor` guards on the archive path).
>
> NORMATIVE (path bytes): `ls-tree` MUST be invoked with `-z` (NUL-delimited)
> so that exotic entry names are not C-quoted; the containment check and the
> on-disk write operate on the true path bytes, never a C-quoted rendering. A
> tree-entry path that is not valid UTF-8 MUST be rejected with
> `ID-NON-UTF8-RELPATH` (the same slug `compute_content_hash` raises for a
> non-UTF-8 relpath — see `spec/identity.md §1.3`); implementations MUST NOT
> silently transcode it (e.g. latin-1 or `U+FFFD`-lossy decoding), because two
> implementations choosing different transcodings would write different
> on-disk names and diverge on `content_hash`. Non-UTF-8 source filenames are
> never legitimate in a conforming package; rejecting uniformly is the only
> cross-impl-deterministic behavior.

---

## 2.4  Structural enforcement of the admission invariants

The four admission predicates (Complete, Deterministic, Normalized, Bounded)
described in the RFC are enforced structurally — by the architecture of the
admission path — not by per-fetcher prose MUSTs. This subsection documents
the locus of each.

### 2.4.1  Normalized, Complete, and Deterministic (VCS path)

For VCS fetchers, all three predicates are structural properties of
`materialize-git-tree` (§2.3):

- **Normalized** — no checkout runs, so smudge filters (`eol=`, `filter=`,
  `ident`, `working-tree-encoding=`) cannot apply. The output is identically
  the object-store bytes on every conforming implementation.
- **Complete** — submodule recursion is always-on (§2.3.5); the output tree
  contains every blob reachable from the pinned commit.
- **Deterministic** — object-store blobs are SHA-addressed: the same pinned
  commit SHA always yields the same bytes, on every host and git version.

These three predicates are consequences of there being exactly one place
blobs are written (the `materialize-git-tree` function), not of per-fetcher
discipline. A VCS fetcher that bypasses this function and performs a
working-tree checkout instead violates all three predicates simultaneously.

> NORMATIVE: VCS fetchers MUST produce their materialized output tree
> exclusively via the impl's `materialize-git-tree` equivalent. No working-tree
> checkout path MAY be used to produce bytes that enter the CAS.

### 2.4.2  Bounded (admission chokepoint)

> NORMATIVE: The registry / `CasAdmittingFetcher` MUST stat the staged tree
> before hashing and MUST raise `FETCH-DOWNLOAD-SIZE-EXCEEDED` if the total
> uncompressed size exceeds the configured cap. This check is applied at the
> one point every fetcher passes through, so no fetcher can bypass it.

> NORMATIVE: HTTP-backed fetchers (tarball, OCI artifact download) MUST
> additionally enforce a compressed-byte cap at the streaming boundary, before
> the response body is fully buffered. This bounds peak memory consumption — the
> post-admission stat bounds disk usage, but a 4 GiB buffered response already
> exhausts memory before the stat runs.

> NORMATIVE: `OciFetcher`'s blob fetch routes through milpa's native HTTP
> transport (§2.4.5) exactly like the tarball fetcher, and MUST enforce the
> same **fixed** compressed-byte streaming cap this section defines —
> `MAX_COMPRESSED_BYTES`, applied at the streaming boundary before the
> response body is fully buffered. There is no OCI-specific exemption from
> this cap: an oversized-blob DoS is exactly what the streaming cap closes
> for tarball, and a native OCI blob GET is not structurally different from
> a tarball GET. The token and manifest requests preceding the blob fetch
> (§2.4.5's redirect-stripping clause covers all three) are additionally
> bounded under a small, fixed cap of their own — these are always small
> JSON documents, never an unbounded stream. The full token → manifest →
> blob phase decomposition and the per-phase cap values are normatively
> specified in `spec/registry-protocol.md` §7, not restated here; this
> clause states only that OCI is not exempt from the cap this section
> defines. (Historical note: an earlier draft of this section exempted
> `OciFetcher` on the premise that it shelled out to `oras pull`, bypassing
> milpa's HTTP layer entirely. That premise no longer holds — §2.4.5 records
> the native-transport decision — and the exemption is struck accordingly.)

### 2.4.3  Archive-extracting fetchers

> NORMATIVE: Every archive-extracting fetcher (tarball and any future
> zip/jar/whl fetcher) MUST route ALL archive content through the impl's
> `extract_tar` / `SafeExtractor` equivalent with **default-or-stricter**
> limits. By routing through this path the fetcher inherits, without
> re-implementation:
>
> - zip-slip / path-traversal guard → `EXTRACT-ZIP-SLIP`
> - symlink-escape guard → `EXTRACT-SYMLINK-ESCAPE`
> - total-size, per-file-size, and file-count limits → `EXTRACT-SIZE-LIMIT`
> - hardlink copy-bytes geometry (§2.2)
> - decompression-bomb guard (bz2/xz/gzip stream cap)
>
> A fetcher that extracts archives through any other path does NOT inherit
> these guards and is NOT conformant.

### 2.4.4  Decompression stream cap

> NORMATIVE: The decompression-bomb guard caps the *decompressed* byte stream
> before the per-entry size checks run, so that a small archive declaring tiny
> member sizes but carrying a large compressed payload cannot be expanded into
> memory. The cap is `decomp_cap = max_total_size + 512` (the 512-byte slack
> admits a legitimately maximal tree plus one tar trailer block). The boundary
> is normative for cross-impl convergence: a stream that decompresses to
> **exactly** `decomp_cap` bytes MUST be admitted; a stream exceeding
> `decomp_cap` MUST raise `EXTRACT-SIZE-LIMIT`. (Equivalently: read
> `decomp_cap + 1` bytes and reject iff more than `decomp_cap` were produced.)
>
> NORMATIVE: the guard MUST recognize and cap every compression format the
> extractor will subsequently decompress. gzip (`1f 8b`), bzip2 (`42 5a 68`),
> and xz (`fd 37 7a 58 5a 00`) are dispatched by their reliable leading magic.
> **lzma-alone / `FORMAT_ALONE`** (`.tar.lzma`) has NO reliable magic — its
> leading byte is a variable LZMA1 *properties* byte, not a fixed signature, so
> a fixed two-byte test (e.g. `5d 00`) matches only the default encoder and
> lets other valid property bytes slip through uncapped. A conforming impl
> MUST therefore detect lzma-alone by *attempting* a `FORMAT_ALONE` decode
> under the `decomp_cap` bound when no reliable magic matched: if the stream
> decodes it is lzma-alone (and is thereby capped); if the decode errors it is
> treated as already-decompressed plain tar. An unrecognized stream MUST NOT be
> handed to an autodetecting tar reader that would decompress it outside the
> cap — in particular a `.tar.lzma` stream MUST NOT reach such a reader.

### 2.4.5  Transport backend (native, no consumer-side shell-out)

> NOTE: milpa's consumer-side network fetches — the tianguis index, index
> bundles, dep-decl and entry-bundle metadata, tarball artifacts, and OCI
> artifacts — are served by **one native in-process HTTP transport** per impl.
> A conformant consumer MUST NOT shell out to an external process (`curl`,
> `oras`, …) to perform these fetches; the transport is the same coupling milpa
> otherwise refuses (nimscript evaluation, `config.nims` emission). Publish/push
> tooling that runs in a controlled CI environment MAY still use `oras`
> (non-consumer, out of scope for this contract). Decided in RFC
> `docs/rfc-native-oci-fetch.md` F1 (broad). The reference impls back this with
> Rust `ureq` + `rustls` and Python stdlib `urllib` (F2); the library is an impl
> choice, the in-process property is the contract.

> NOTE: the native transport MUST reach **parity** with the shell-outs it
> replaces, not silently regress (RFC §0.1). It MUST honor the standard proxy
> environment variables (`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`), trust the
> host OS certificate store (so enterprise / MITM-proxy roots and OS cert updates
> keep working), and apply conservative connect/read timeouts (an in-process call
> with no timeout blocks a resolver worker forever — strictly worse than an
> interruptible subprocess). There is no dual-transport rollback shim
> (no-legacy-support pre-v1): once the shell-outs are removed the native path is
> the only path.

> NORMATIVE: On an HTTP redirect, an HTTP-backed fetcher's transport MUST strip
> the `Authorization` header unless the redirect target's **origin — `(scheme,
> host, port)`** — exactly matches the original request's origin. A host-only
> check is insufficient: it would forward a bearer token across a same-host
> scheme downgrade (`https` → `http`) in cleartext, or across a port change.
> This protects the OCI bearer token, which ghcr 307-redirects a blob GET to a
> CDN host that authenticates via a self-contained presigned URL and does not
> need the token.

> NOTE: the token/manifest/blob transport state machine is **not exercisable
> through a black-box conformance fixture** — under `MILPA_MOCKED_FETCHES` the
> OCI fetcher is replaced wholesale, so the corpus and the differential harness
> cannot observe transport phases. This is a known, accepted limitation (RFC
> §3.7). Cross-impl parity for the transport is provided at the **unit tier** by
> a shared canned-transport contract at `conformance/oci-transport/` (a sibling
> of, and deliberately outside, `conformance/spec-v<N>/`) that both impls'
> OCI-client unit tests replay through their injected transport.

---

## 3  Identity contract

### 3.1  Identity is forbidden in the receipt — field-level line

> NORMATIVE: A `ProvenanceReceipt` subclass MUST NOT define any field whose
> value is computed from, or is a function of, the materialized source tree bytes.
> Specifically, fields named or equivalent to `content_hash`, `identity`,
> `tree_sha256`, or any other tree-level digest are **forbidden** in receipt
> types.

**Why:** identity (`sha256` of the source tree) is milpa's trust anchor,
computed by the **registry** in every conformant implementation after the
fetcher returns. If a fetcher populated an `expected_hash` or `tree_sha256`
field in the receipt, a buggy or hostile fetcher could supply a wrong value
that a careless registry accepted instead of recomputing — a trust bypass.
The forbidden-field rule enforces the invariant **structurally**, not by
procedure: there is no "identity field the registry should ignore" because
such a field cannot exist.

> NORMATIVE: Fields recording the **transport artifact's own identifier** are
> **permitted and expected** in receipt types. Examples:
>
> - `GitReceipt.commit_sha` — identifies the git object, not the source tree
> - `OciReceipt.layer_digest` — identifies the compressed OCI blob
> - `TarballReceipt.archive_sha256` — identifies the downloaded archive before
>   extraction
> - `LocalReceipt.resolved_path` — records the filesystem path used
>
> None of these is the source-tree hash milpa keys on. A porter writing a
> receipt field for "what the transport delivered" is explicitly permitted.

**The precise permitted/forbidden boundary:** a receipt field is permitted iff
its value can be computed without access to the materialized tree at `dest/`.
A receipt field is forbidden iff producing its value requires hashing or reading
the materialized tree bytes.

### 3.2  Receipt must be non-empty — structural enforcement

> NORMATIVE: Every concrete `ProvenanceReceipt` subclass MUST declare at least
> one transport-pinning field. A receipt that records no transport-specific
> information provides no provenance evidence and MUST be rejected at admission
> time.

> NOTE: The reference Python implementation (`milpa/fetchers/types.py`) defines
> `ProvenanceReceipt` as an abstract base class with an `@abstractmethod
> transport_fields() -> dict[str, str]` that every concrete subclass must
> implement. The reference registry enforces the non-empty obligation at
> admission time via `FETCH-RECEIPT-EMPTY`. Built-in receipts (`GitReceipt`,
> `TarballReceipt`, `OciReceipt`, `LocalReceipt`) each declare ≥1
> transport-pinning field and implement `transport_fields()`. Third-party
> fetchers MUST satisfy the same obligation; the registry enforces it at
> admission time.

### 3.3  Registry computes identity

> NORMATIVE: The registry MUST call the milpa identity algorithm
> (`compute_content_hash` or its equivalent per `spec/identity.md` §1) on
> the materialized tree at `dest/` after every successful `fetch` call, before
> returning a `FetchResult`. The `identity` field of `FetchResult` MUST be set
> by the registry, never by the fetcher.

> NORMATIVE: No fetcher — built-in or third-party — may influence the
> `FetchResult.identity` value. The registry walks the tree itself.

> NOTE: This is sharpened from the RFC's sketched signature (which had
> `FetchResult` returned by the fetcher). The tightened types enforce the
> invariant structurally — `fetch` returns only `ProvenanceReceipt`; `FetchResult`
> is assembled by the registry.

---

## 4  `cas_admissible` declaration

> NORMATIVE: Every `Provenance` subclass MUST declare a `cas_admissible` class
> attribute (not an instance field) of type `bool`. The registry reads this
> attribute before calling `admit()` on the CAS.

> NORMATIVE: Editable sources — local-path provenances and workspace-member
> provenances — MUST declare `cas_admissible = False`. Admitting an editable
> source would silently freeze user edits: the CAS entry would be immutable while
> the user's source tree continues to change, and subsequent resolution would
> serve the frozen content.

> NORMATIVE: Immutable sources — **all git provenances** (regardless of whether
> `commit_sha` is set or the ref is a branch/tag/HEAD) and tarball provenances
> — MUST declare `cas_admissible = True`. The registry admits these into the
> CAS after the first fetch and serves subsequent resolution from the store.

**Why all git provenances are admissible:** CAS-admission safety does not come
from the provenance kind but from the post-fetch identity gate. After any git
fetch, the registry computes `content_hash` over the materialized tree and
checks it against the expected value in the lockfile. If the fetched content
differs from what was locked (including a moving-ref that advanced), the
identity mismatch is detected at that gate — the CAS entry is never stored with
the wrong hash. A mutable-ref git provenance on a first fetch (before any lock)
produces a correct CAS entry because the CAS is keyed on the content hash; on a
subsequent `--frozen` run the CAS entry is served unconditionally. The safety
invariant is the identity gate, not a restriction on which git provenances may
be admitted.

> NOTE: In the reference Python implementation, `Provenance` (the base dataclass
> in `types.py`) declares `cas_admissible: ClassVar[bool] = True`, making
> immutability the default. `LocalProvenance` overrides with `cas_admissible =
> False`. Subclasses MUST override the default explicitly if they represent an
> editable source.

> NOTE: Workspace **members** are a special case. The reference impls do **not**
> model a member as a transport `Provenance` subclass/variant at all — members
> are resolved inline by the resolver (against the workspace member table), not
> fetched through the `FetcherRegistry`. The `cas_admissible = False` requirement
> above is therefore conceptual for `member`: a member is structurally never
> passed to `admit()` because it never enters the fetcher protocol. Note also
> that `member` — unlike `local` — **is identity-bearing**: its content is hashed
> and drift-detected even though it is not CAS-admissible. See
> `spec/identity.md §4.1` for the two orthogonal axes (identity-bearing vs
> CAS-admissible) and why they diverge on `member`.

**Why this is part of the protocol:** `cas_admissible` is a contract
declaration, not an implementation detail. The registry in any conformant
implementation must read it before deciding whether to admit. A third-party
fetcher for a new mutable source (e.g. an SSH-backed live checkout) must
declare `False`; if it did not, the registry would silently freeze content the
user expects to be live. The fetcher is the only party with the knowledge to
make this declaration correctly.

See `spec/identity.md` (S12) §3 for the CAS-level `admit()` contract.

---

## 5  Exclusive dispatch

> NORMATIVE: The registry MUST enforce **unique-match dispatch**. For a given
> provenance descriptor, exactly one registered fetcher MUST claim it via
> `can_handle`. If two or more registered fetchers return `True` for the same
> descriptor, the registry MUST raise an ambiguity error and MUST NOT proceed
> with materialization. If no registered fetcher returns `True`, the registry
> MUST raise a no-handler error.

> NORMATIVE: The dispatch rule is stated without reference to any
> language-specific mechanism. A plugin's `can_handle` MUST return `True` for
> exactly the provenance kinds it declares; the registry enforces unique-match at
> dispatch and raises an ambiguity error if two registered fetchers both claim one
> descriptor.

**Registration order is for readability, not priority.** The exclusive-dispatch
rule means a plugin cannot shadow a built-in fetcher by registration order —
claiming the same kind as a built-in triggers the ambiguity error, not a silent
override. This is a stronger safety property than "built-ins win": it fails
loudly rather than permitting any silent substitution.

> NOTE: In the reference Python implementation, `FetcherRegistry._select`
> (`types.py`) collects all fetchers whose `can_handle` returns `True` in a list
> comprehension, then inspects `len(matches)`. If `> 1`, it raises `FetchError`
> naming the conflicting fetchers. If `== 0`, it raises `FetchError` naming the
> unhandled provenance kind. Only `matches[0]` is used — but the single result is
> the output of a uniqueness check, not a priority tie-break. The `default_registry`
> pre-registers four built-in fetchers: Git, Local, Tarball, OCI.

The built-in kind set (git, local, tarball, oci) is defined by the spec and
owned by the spec version. A third-party fetcher claiming one of these kinds
will trigger the ambiguity error. A fetcher for a **new kind** (not in the
built-in set) is possible only with a spec amendment that adds the kind to the
kind registry; see `spec/manifest-grammar.md` §4 (Layer 1 / P3).

### 5.1  Dispatch errors are uncoded programmer-invariants (catalog exemption)

> NORMATIVE: The ambiguity error and the no-handler error — together with the
> `fetch_any` "no candidates provided" guard — are **programmer-invariants**:
> they signal a registration bug or a call-site bug, never a condition reachable
> from user input (manifest, lockfile, index, or fetched bytes). They therefore
> carry **no error-catalog slug** and are **exempt from the error-catalog
> bijection lint** (`spec/errors.md`). An implementation MUST NOT mint
> user-facing codes such as `FETCH-AMBIGUOUS-DISPATCH` or `FETCH-NO-HANDLER` for
> them; it raises its transport-error type without a code (reference: bare
> `FetchError` with `code=None`).

> NORMATIVE: Every implementation's catalog-bijection lint MUST share this
> exemption list — exactly these three invariants, identified by their condition
> (ambiguous dispatch, no handler, no candidates), not by message text. The
> Python reference encodes it as `FETCH_UNCODED_INVARIANTS` in
> `tests/test_error_catalog.py`; the Rust catalog lint mirrors the same set.
> Adding a genuinely user-reachable `FETCH-*` condition is the only path to a new
> coded fetch error — these three never become coded.

---

## 6  Layer-2 backend binding and content-addressing override safety

**A key property of the Layer-2 backend contract:** two different backends for
the same provenance kind (e.g. a libgit2-based git fetcher vs. the reference
subprocess-git fetcher) produce byte-identical source trees for the same pinned
source — and therefore byte-identical identity hashes. This means backend
substitution is **safe by construction** for immutable references, not a footgun
that must be forbidden.

> NORMATIVE: **Byte-equivalence across backends holds for pinned identities
> only** — commit SHAs, tags that resolve to a fixed commit, tarball
> content-hashes. For a mutable reference (`ref=main`, a branch, a moving tag),
> two backends (or one backend at two times) may clone different commits, produce
> different trees, and therefore produce different identity hashes. This is not a
> hole in the safety argument.

> NORMATIVE: For a **locked** dep (identity pinned in the lockfile), a backend
> that delivers content with a different identity hash MUST be detected by the
> registry's identity check and treated as a failure — the mismatch is raised as
> an identity error, not silently accepted. `fetch_any` enforces this: a candidate
> whose materialized bytes produce a hash different from `expected_identity` is
> dropped and the next candidate is tried (with a warning). The trust boundary is
> the content hash, not the transport.

**Implication for the frozen fast-path:** mutable-ref resolution is not part of
the frozen fast-path because the identity is not yet pinned. Once a resolution
cycle pins the identity into the lockfile, subsequent `--frozen` runs bypass the
fetcher entirely (serving from CAS) and the identity check is structural.

> NOTE: The Layer-2 backend-override configuration surface (declaring "use
> backend B for kind K") is not implemented in spec v1.0. Filing it as a
> follow-up is an explicit design decision ([[feedback_defer_file_now]]); it is
> non-breaking because the exclusive-dispatch + content-hash model already makes
> override semantically safe.

---

## 7  `FetcherConfig` — normative definition

Every plugin factory receives a `FetcherConfig` instance. The factory signature
is:

```
(config: FetcherConfig) -> Fetcher
```

> NORMATIVE: The factory MUST accept exactly one positional argument of type
> `FetcherConfig`. A zero-argument factory is not conformant; a two-or-more-
> argument factory is not conformant. The reserved-slot discipline (§7.1) is why.

### 7.1  v1 shape

> NORMATIVE: `FetcherConfig` in spec v1.0 is a struct with **no required
> fields**. It reserves exactly one optional forward hook:
>
> ```
> FetcherConfig {
>   mirror_urls: list[str]  # optional; default []; not required to be honored in v1
> }
> ```
>
> No other fields exist in v1. An implementation MUST NOT define additional
> fields on `FetcherConfig` without a spec amendment.

> NORMATIVE: A v1 fetcher MAY ignore `mirror_urls`. The field is reserved so
> that a future spec version can pass mirror candidates without a breaking
> signature change. A fetcher that reads and uses `mirror_urls` in v1 is doing
> so as a forward-compatible optimization, not a conformance obligation.

> NOTE: In the reference Python implementation, `FetcherConfig` is a frozen
> dataclass in `milpa/fetchers/types.py`. A Rust porter MUST define the
> equivalent struct before writing the discovery harness; the v1 shape (one
> optional `mirror_urls` field, no required fields) is normative here.

**Why a slot at all:** a zero-argument factory forecloses ever passing a plugin a
mirror URL, a timeout, or a credential token without a breaking signature change.
Reserving the one-argument slot now (with an empty struct) costs nothing and
satisfies [[feedback_minimal_over_completeness]] — the slot is built, the config
system is not. This is the exact failure the gate exists to prevent: if the
factory signature is undefined, the Rust impl invents a different shape and the
two impls diverge at the discovery boundary.

---

## 8  Cancellation and credentials — stated non-contracts

### 8.1  Cancellation

> NORMATIVE: Cancellation and timeout propagation into the fetcher are **not
> guaranteed in spec v1.0**. A fetcher is not required to handle cancellation
> signals. A registry is not required to propagate timeouts to the fetcher's
> `fetch` call.

This is stated explicitly so no conformant implementation invents propagation
semantics that become a de facto cross-impl expectation. A future spec amendment
may add cancellation obligations; until then, implementations that handle
cancellation do so as an incidental quality-of-implementation choice.

### 8.2  Credentials and authentication

> NORMATIVE: Credential passing to fetchers is **explicitly deferred** and is a
> known spec hole in v1.0. No conformant implementation SHOULD define a
> credential-passing convention through `FetcherConfig` or any other mechanism
> without a spec amendment, as doing so risks cross-impl divergence in the
> credential model.

> NOTE: The reference Python implementation handles credentials informally
> (git credential helpers via the subprocess environment; no explicit credential
> API). This is incidental and not normative. Per `docs/rfc-pluggable-fetchers.md`,
> credential federation is deferred work; the `FetcherConfig` slot is designed to
> carry it when the spec amendment lands.
