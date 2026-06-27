# RFC: Fetch & extraction hardening

Status: **designed (architect rounds 1–2, 2026-06-23 / 2026-06-26)** — was a triage
stub from the 2026-06-21 issue audit; now designed and twice-reviewed. No design forks:
the two apparent forks (.gitattributes policy, submodule default) dissolved under milpa's
non-negotiables into one root-cause mechanism change — **hash git deps from the object
store, not the working-tree checkout** (see **Root-cause: object-store materialization**).
Scope greenlit by Corey 2026-06-26 (object-store rewrite over the weaker flag patch).
Round 2 hardened the design: closed a **new symlink-escape surface** the object-store
pivot opened, corrected the hash-churn analysis (the conformance corpus does **not**
churn — only the real-network fresco fixture does), introduced the `materialize_git_tree`
primitive as the single enforcement chokepoint, reordered H4 before H3, and split H3 into
sub-slices. Umbrella: #170. Milestone: *v0.x / v1 — robustness*.
Standalone (decided — see **Standalone vs fold-in**); closes the correctness residuals
of `rfc-pluggable-fetchers.md` (F1–F3 Stage-4 review) and coordinates with
`rfc-conformance-parity.md` (corpus fixtures pin the converged behavior).

## Problem

A cluster of real correctness and security bugs on the fetch → extract → hash path,
all surfaced by the pluggable-fetchers (F1–F3) Stage-4 code review. Each lands
incomplete, non-deterministic, or unsafe bytes in the CAS — the worst failure mode
for a content-addressed dep manager: the identity hash is computed over wrong/partial
content, so the lockfile records a hash that doesn't mean what it should.

## The admission invariant (the unifying contract)

Every issue here is a violation of one predicate of a single contract. Bytes admitted
to the CAS — and thus fed to `compute_content_hash` — must be:

1. **Complete** — all files the build references are present. *(#140 submodules)*
2. **Deterministic** — the same declared provenance produces byte-identical trees
   across hosts, OSes, git versions, and re-fetches, on every conforming impl.
   *(#143 `.gitattributes`, #145 shallow-clone divergence)*
3. **Normalized** — host-config-dependent transformations (EOL, smudge filters,
   encoding, ident expansion) are suppressed before hashing. *(#143)*
4. **Bounded** — download size and archive expansion are capped *before* bytes hit
   memory or the filesystem. *(#149 download DoS; the bz2/xz bomb-guard parity gap)*

"Deterministic" is the predicate the stub omitted; it is the one most of these bugs
actually violate (same pin, different bytes), and it is the testable spec predicate:
`fetch(pin, host_A) == fetch(pin, host_B)` for all valid pins and host configurations,
for every impl. The structural goal of this RFC is to make these four properties
**properties of the admission path**, not per-fetcher discipline (see
**Structural enforcement** below).

## Issues unified

Organized by the predicate each one violates.

### Complete
- **#140 — recurse git submodules.** Deps that vendor sources via a submodule (e.g.
  `bearssl-nim` vendoring C sources) land **incomplete** in the CAS; cold builds then
  fail on missing files. Labeled `bug`. Cross-impl: Rust `GitFetcher` also omits
  recursion. **No fork:** submodule *source bytes* are content (the build needs them)
  → part of `content_hash`; submodule *URLs + pinned SHAs* are provenance. Recursion is
  always-on, not opt-in — an opt-in flag would make the hash cover the full source
  closure *sometimes* and a subset *other times*, i.e. a hash whose meaning depends on
  a flag, which defeats content-addressing (full reasoning under **Root-cause**).
  Under object-store materialization this is the *same* mechanism: recurse the
  gitlink (mode-160000 `ls-tree` entry) into the submodule's object store.

### Deterministic + Normalized
- **#143 — in-tree `.gitattributes` defeats `core.autocrlf=false`.** `_GIT_TRANSPORT_FLAGS`
  injects `-c core.autocrlf=false -c core.filemode=false`, but a repo's own
  `.gitattributes` is applied at *checkout* and overrides the config for EOL on a
  per-path basis. The surface is broader than EOL: `eol=`, `filter=` (e.g. git-LFS
  substitutes pointer text for real blobs — silently wrong content), `ident` ($Id$
  expansion injects the commit SHA *into file content* — a provenance/content leak),
  and `working-tree-encoding=` (UTF-16 transcode) all mutate materialized bytes.
  `-c core.autocrlf=false` suppresses none of these. **This is not a fork; it is a
  symptom.** The autocrlf flag was patch #1, `.gitattributes` is the same bug
  resurfacing, and the list above is its unenumerated tail — every checkout-time
  transformation is another flag to chase. The root cause is that milpa hashes the
  *smudge output* (the working-tree checkout) instead of the *canonical committed
  bytes* (the object store). The fix is mechanism change, not another flag — see
  **Root-cause**.
- **#145 — git fetcher shallow-clone divergence.** Python `_ensure_commit_present`
  has a 4-step fetch/unshallow/re-check chain; Rust `commit_present` is a single
  `cat-file -e` with no fetch fallback (confirmed: Rust does not implement the retry
  chain at all). A pin to a commit not at a branch tip — the common locked-dep case —
  succeeds on Python, raises `FETCH-GIT-COMMIT-ABSENT` on Rust. Fix: port the 4-step
  strategy to Rust (clear-best; see H4). Two precision points resolved below.

### Bounded
- **#149 — download-size DoS.** The compressed-byte cap is enforced *post-buffer*
  (`len(raw_bytes) > cap` fires only after the full response is in memory).
  **Premise needs empirical verification** (see **Verification gate** below): the
  claim that `curl --max-filesize` is bypassed by chunked / no-`Content-Length`
  responses is contested — modern curl applies `--max-filesize` to received transfer
  size, not just the announced header. Regardless of that, the buffered-`output()`
  path is a real OOM vector for injected transports and any case curl does not catch;
  the fix is a streaming bounded read. Distinct error slug proposed
  (`FETCH-DOWNLOAD-SIZE-EXCEEDED`) so a security rejection is not conflated with a
  network failure.
- **#175 — pure-garbage archive silently succeeds (Rust).** Rust `TarEntries` returns
  zero entries (→ empty dir, exit 0) for a non-zero buffer < 512 bytes with no valid
  tar header; Python raises `FETCH-EXTRACT-FAILED`. **Likely already closed:**
  `fixture-291-fetch-all-failed-corrupt-tar` exists and exercises the S4a raw-bytes
  path. H0 is to verify Rust passes it; if so, close #175. (Was named only in the
  stub's title; now first-class.)

### Hardening — escape geometry
- **#144 — hardlink extraction maps hardlinks to symlinks + mishandles
  `strip_components`.** `safe_extract.py:194` branches `member.issym() or
  member.islnk()` and writes `linkname` as a symlink target; Rust does the same. A
  hardlink's `linkname` is an **archive-absolute path**, not a relative symlink
  target, and it is *not* run through `strip_components` like the entry name is — so
  after `strip_components=N` the link dangles, and the escape check uses symlink
  geometry (`parent / linkname`) on a path that needs hardlink geometry
  (`dest_root / strip(linkname)`). Fix is clear-best; the materialization choice
  (copy bytes vs reject) is resolved below.

## Out of scope / covered elsewhere

Stated explicitly so these are not re-opened as gaps:

- **Zip-slip, symlink-escape, absolute-path and `..` traversal, device/FIFO/special
  files** — already handled and fixtured by `SafeExtractor`
  (`EXTRACT-ZIP-SLIP`, `EXTRACT-SYMLINK-ESCAPE`, `EXTRACT-SIZE-LIMIT`). Not in scope.
- **Case-collision on case-insensitive filesystems** (`Foo.nim` vs `foo.nim`) — a
  deterministic-across-*platforms* concern; deferred to the v2/platform checklist per
  `rfc-conformance-parity.md §2` (spec v1 is Linux/POSIX). Cross-referenced, not fixed.
- **TOCTOU on the extraction dest dir** (dest swapped for a symlink between `mkdir`
  and extract) — out of scope for v1: milpa is a single-user dev tool and `_deps/` is
  project-local and not world-writable. Revisit if scope extends to shared CI agents.
- **`.zip` archive format** — `TarballFetcher` is `.tar.*` only. A `.zip` URL today
  fails with a poor message. Minimal in-scope ask: magic-byte detection →
  `FETCH-EXTRACT-FAILED` with an unsupported-format note (folded into H0). Full zip
  support (its own slip/symlink/bomb path) is a separate future fetcher, not this RFC.

## New threats surfaced by review (tracked, mostly deferred)

- **bz2/xz decompression-bomb parity (Rust).** Rust wraps only the gzip decoder in
  `.take(decomp_cap)`; bz2/xz are unguarded. This is the `rfc-pluggable-fetchers.md`
  round-2 item 2b, previously untracked here. Folded in as **H1b** (bounded). Also
  note the Python-vs-Rust mechanism difference: Python trusts the tar header `size`
  (pre-extract cap), Rust streams `.take()` (caps the real stream) — not equivalent
  when a crafted header lies. Defense-in-depth: Python should also cap the actual
  decompressed stream, not only the header. Tracked under H1b.
- **Non-UTF-8 archive entry names.** A tar name field can hold arbitrary bytes;
  Python `tarfile` falls back to latin-1 (silent mojibake into the hash), Rust may
  differ — a cross-impl identity divergence. `spec/identity.md` already requires valid
  UTF-8 relpaths (`ID-NON-UTF8-RELPATH`). Propose extending rejection to archive entry
  names via a new `EXTRACT-NON-UTF8-ENTRY-NAME` slug. **File as a follow-up issue**;
  not in the H0–H5 critical path.

## Root-cause: object-store materialization (resolves #143 and #140)

The stub posed two questions as forks. Both dissolve under milpa's non-negotiables
(identity recomputable from bytes alone; host-independent; identity ≠ provenance;
content_hash covers the build's source closure). What looked like two policy choices is
one mechanism defect with one structural fix.

**The defect.** milpa materializes a git dep with `git clone` + `git checkout`, then
hashes the **working-tree checkout**. The checkout is the *smudge output*: git applies
`core.autocrlf`, then per-path `.gitattributes` (`eol=`, `filter=`, `ident`,
`working-tree-encoding=`) at checkout time. §1.7 fights this with `-c` flags, one per
smudge source discovered. #143 is the next flag in a queue with no end, and several
smudge sources (LFS `filter`, `ident`) are host-dependent or fuse provenance into
content — so the checkout is **not** a host-independent function of the pin. There is
also **no single git switch** that reliably disables all in-tree `.gitattributes` +
`info/attributes` across versions, so the flag approach can never *guarantee* the
invariant content-addressing requires. It can only chase it.

**The fix.** Materialize git deps from the **object store**, not a checkout:
`git ls-tree -r <commit>` enumerates `(mode, type, sha, path)`; `git cat-file --batch`
streams the exact stored bytes for every blob in **one** subprocess; milpa writes those
bytes to a clean output tree itself. Object-store blobs are the canonical *clean* side —
pre-smudge by construction. autocrlf, `.gitattributes` eol/filter/ident/encoding **cannot
apply because no checkout runs.** This:

- dissolves #143 *and its entire unenumerated tail* in one move;
- makes §1.7's `-c core.autocrlf=false` redundant — **delete it**; the hole it patches
  ceases to exist. (`core.filemode` is moot too — not because `ls-tree` carries the mode,
  but because **there is no working tree** for it to govern; identity continues to ignore
  the exec bit per `spec/identity.md §1.2`.)
- is the **only** mechanism that *guarantees* determinism rather than approximating it;
- gives #140 a clean recursion point: submodules are mode-160000 gitlink entries in
  `ls-tree`; recurse into the submodule's object store with the same primitive. No
  `--recurse-submodules` checkout dance, no separate code path.
- maps cleanly across impls (both Python and Rust shell `ls-tree`/`cat-file`).

**Materialization mechanics** (the round-2 precision the bare "ls-tree + cat-file"
sketch omitted):

- **No implicit checkout.** A plain `git clone` *does* create a working tree (and thus
  runs smudge filters). The clone that backs object-store reading **MUST** be
  `--no-checkout` (or bare). The whole point — no checkout — is defeated by the default
  clone behavior; this is the one easy way to reintroduce the bug.
- **Two scratch directories.** The *clone scratch* contains `.git` (the object store we
  read from); the *output tree* is what `cat-file` writes and what is admitted to the
  CAS — it **MUST NOT** contain `.git`. They are distinct directories. The clone scratch
  is cleaned up after the `cat-file` pass regardless of whether CAS admission succeeds.
- **Bulk reads.** Use `git cat-file --batch` (SHAs in on stdin, headers+bytes out), not a
  `cat-file` subprocess per blob — a 10k-file dep would otherwise spawn 10k processes and
  can hit ulimit ceilings in constrained CI. Normative in `plugin-contract.md`.
- **Empty directories.** `ls-tree -r` emits only blobs and gitlinks; git does not track
  empty directories, so the output tree has none. This is *consistent* with identity
  (`§1.2`: empty dirs contribute no bytes) and is made **normative**: VCS materialization
  MUST NOT synthesize empty directories. (No observed Nim dep requires one; if that ever
  changes it is a spec decision, not a silent behavior.)
- **On-disk mode.** Identity ignores the exec bit, so the on-disk mode does not affect the
  hash — but to keep `milpa verify` re-hashing byte-identically across hosts, H3 writes a
  fixed mode: `0o644` for regular blobs, `0o755` for `ls-tree` mode `100755`, `0o755`
  dirs. Stated so both impls converge.
- **`.nimble` / `milpa.kdl` are regular blobs**, enumerated by `ls-tree` and written like
  any other file, so transitive-dep parsing (`_collect_transitive_deps`) reads them from
  the output tree unchanged — no separate code path. **`strip_components` is moot** for
  the git path: `ls-tree -r` paths are already repo-root-relative (no leading archive
  dir). Noted for future F4/F5 (Hg/Fossil via `hg archive`) authors who *will* need it.

**Symlinks** (mode 120000): blob bytes = the link target string. **This is a new escape
surface the object-store pivot opens and round 1 missed.** A committed symlink blob whose
content is `../../../../etc/passwd` (or an absolute path) would, written naively via
`symlink_to(blob_bytes)`, escape the dep root — exactly the zip-slip/symlink-escape class
`SafeExtractor` exists to stop, but the object-store path **does not go through
`SafeExtractor`**. The "Out of scope" symlink-escape clause covers only the tarball path.
H3 **MUST** apply the same lexical-containment check `SafeExtractor` uses
(`_normalize_lexical(parent / target)` must stay under `dest_root`) per reconstructed
symlink, raising **`EXTRACT-SYMLINK-ESCAPE`** on violation. Specced in
`plugin-contract.md` for the VCS path.

**LFS** is the one residual, and it is *resolved, not open*: object-store reading hashes
the **pointer text** (deterministic, but the real content lives in the LFS store, so the
tree is *incomplete*). Detection is specified precisely so both impls agree: a blob is an
LFS pointer iff its **first line** is exactly `version https://git-lfs.github.com/spec/v1`
(a 10 MB blob that merely *contains* that string elsewhere is not a pointer — first-line
exact match eliminates documentation false-positives). On detection raise
**`FETCH-GIT-LFS-POINTER`** carrying `path=<relpath>` so the user knows which file
triggered it, with an actionable message ("dep uses Git LFS; milpa reads the git object
store directly and cannot fetch LFS blobs — vendor a plain-git mirror or a `local=` path").
Forced by the *complete* predicate; transparently resolving LFS is a separate future
`LfsFetcher` (host-tool dependence) and is explicitly out of scope.

### Why neither was an opinion fork

- **#143 "suppress vs accept-canonical":** accept-canonical fails the bar outright —
  smudge filters are host-dependent (LFS installed or not; libiconv version) and
  `ident` injects the commit SHA into content, both direct violations of
  "recomputable from bytes alone" and identity≠provenance. It was never viable; the
  only question was *how* to suppress, and "read the clean blobs" is the guaranteeing
  answer where "-c flags" is the chasing one.
- **#140 "always vs opt-in":** an opt-in flag makes `content_hash` cover the full
  source closure sometimes and a subset other times — a hash whose meaning varies by
  flag, defeating content-addressing. Recursion is a precondition of the hash being
  meaningful, not a feature. Bandwidth (huge-submodule case) justifies a future
  opt-*out* optimization, never an opt-*in* default; and per
  [[feedback_minimal_over_completeness]] we don't add even the opt-out knob until a
  real need appears. Record each submodule `path → commit SHA` as provenance
  (`GitReceipt.submodule_shas`) so resolution stays reproducible; add
  **`FETCH-GIT-SUBMODULE-FAILED`** so a failing submodule names itself.

  **Round-2 correction — relative submodule URLs are *not* "absorbed by SHA-addressing."**
  Round 1 claimed object-store reading settles submodule-URL determinism. It does not: a
  mode-160000 gitlink gives the submodule *commit SHA* (what to materialize) but the
  *URL* (where to fetch the objects) lives in the superproject's `.gitmodules` blob, and
  may be **relative** (e.g. `url = ../sibling`). H5 therefore: (a) reads `.gitmodules`
  from the superproject object store (it is a regular blob — already available), (b)
  parses the gitconfig-format `submodule.<name>.{path,url}` entries, (c) resolves a
  relative URL against the **superproject's recorded provenance URL**
  (`GitProvenance.url`) — git's own deterministic rule, so this stays host-independent
  and is the correct (not merely convenient) resolution; absolute URLs pass through
  unchanged. A `.gitmodules` entry that fails to resolve or fetch raises
  `FETCH-GIT-SUBMODULE-FAILED` (carrying `submodule_path=` and `submodule_url=`). Nested
  submodules recurse the same way against *their* superproject's resolved URL.

  **`submodule_shas` lockfile shape:** flat `path → sha`, where `path` is the full path
  from the *outermost* superproject root (so a nested submodule is `outer/inner` — the
  full key disambiguates without a tree structure), emitted in path-sorted order for
  deterministic diffs. KDL encoding: one `submodule "<path>" sha="<40hex>"` child node per
  entry under the dep's git record (not a nested map — flat nodes parse and round-trip
  cleanly). This is provenance, sharing the git record's provenance block with
  `commit-sha`. Schema fragment lands in `spec/lockfile-schema.md` with H5.

### The one thing genuinely for Corey — scope appetite, not design

Object-store materialization is the correct mechanism, but it is a **rewrite of git
tree-materialization** with real blast radius:

1. it lets us *delete* §1.7's transport flags and rewrite §1.6/§1.7 around
   "hash the committed blobs" instead of "hash the smudge-suppressed checkout";
2. it **re-hashes every git dep** where checkout ≠ blob (any repo with autocrlf- or
   filter-affected content), a one-time `content_hash` churn. **Round-2 correction on
   blast radius:** this churn does **not** touch the conformance corpus. `MockedGitFetcher`
   stages `content/` verbatim with **no git invocation** (confirmed in `mocked.py`), so
   every corpus git-dep `content_hash` is the hash of pre-baked bytes and is *unchanged*
   by H3 — the corpus stays green across the rewrite. The churn lands on exactly one
   place: the **real-network fresco integration fixture** (`MILPA_INTEGRATION_TESTS=1`),
   which runs the real `GitFetcher`. Its lockfile fails `milpa verify` /
   `FETCH-PROVENANCE-DIVERGENCE` until re-locked. Trivial pre-1.0 (no external consumers,
   per [[spec_versioning_deferred]]); the broken pre-fix hashes were never correct anyway.
   Re-lock via normal `milpa update`. **H3 acceptance criterion:** re-lock fresco's
   committed fixture in the same change so the integration suite does not silently regress.
   (The flip side, surfaced in round 2: because the corpus never runs real git, H3's core
   invariant gets **zero corpus coverage** — only the H-infra integration test exercises
   it. See **Testing strategy**.)

The knowingly-weaker alternative — keep checkout, add `GIT_ATTR_SOURCE` + `core.eol=lf`
+ LFS detection — is *strictly* weaker (cannot guarantee, leaves the treadmill, still
host-dependent on git-version attribute handling) and is recorded only as the fallback
if Corey rejects the rewrite's scope. **Recommend the rewrite.** Sub-questions it
absorbs (relative-submodule-URL determinism, recursive depth, submodule commit
reachability) are settled by object-store reading: blobs are addressed by SHA, so URL
resolution and reachability fallbacks (#145) apply to *fetching* the objects, not to
the deterministic materialization.

## Clear-best resolutions (baked in — not forks)

- **#144 materialization: copy bytes, don't reject.** A hardlink in a source archive
  is just dedup of identical content; a content-addressed store should materialize it
  as a file copy (the canonical, hash-stable form), not a dangling symlink and not an
  `EXTRACT-HARDLINK-UNSUPPORTED` rejection of otherwise-valid archives. Apply
  `strip_components` to `linkname` exactly as to the entry name; resolve the stripped
  target against `dest_root`; if it still escapes, raise `EXTRACT-ZIP-SLIP` (same slug
  as a regular escape — no new slug). Hash-stability bonus: two archives encoding the
  same logical tree as copy-vs-hardlink now hash identically.
  **Ordering invariant (round 2):** a hardlink entry may *forward-reference* a target not
  yet written (tar ordering is arbitrary). Copy-bytes therefore requires the source to
  exist when the hardlink is materialized; specify a **two-pass** extraction — all regular
  files first, hardlinks resolved second — so Python and Rust cannot diverge on
  forward-referencing archives. (`linkname` is split on POSIX `/` explicitly, not via the
  host `Path` separator — a no-op on spec-v1 Linux, but it keeps the geometry correct if
  the v2 platform work lands Windows.) A pinned corpus fixture exercises the
  forward-reference case.
- **`EXTRACT-HARDLINK-UNSUPPORTED` (superseded):** `rfc-pluggable-fetchers.md` round 2
  claimed it added this slug to `spec/errors.md`, but the slug is absent (never landed).
  H2's copy-bytes resolution supersedes the reject-with-new-slug approach: no new slug,
  hardlink escape reuses `EXTRACT-ZIP-SLIP`. H2 updates `rfc-pluggable-fetchers.md` to
  record the supersession so the bijection lint stays clean.
- **#145 precision:** (a) `git fetch --unshallow` on an already-complete clone must
  fail *softly* but only for the specific "already complete / not shallow" error — do
  not blanket-swallow arbitrary fetch failures (Python currently swallows too much);
  (b) complement the fallback by never *creating* a shallow clone (full-depth clone),
  so the fallback is only needed for the genuine force-pushed-away-commit case.
- **#149 error slug:** add `FETCH-DOWNLOAD-SIZE-EXCEEDED`, distinct from
  `FETCH-DOWNLOAD-FAILED`.
- **Standalone vs fold-in:** **standalone.** `rfc-pluggable-fetchers.md` is marked
  *Implemented*; folding open correctness bugs into a done doc buries them. Keep this
  RFC separate and cross-link: its round-2 residual items 2b/3/4 are closed *into*
  H1b/H2/H4 here.

## Structural enforcement (make the four predicates inherited, not re-implemented)

A new fetcher author (F4 Hg, F5 Fossil, …) must not be able to silently omit these
properties. Round 1 framed this as "shared primitives + a normative MUST clause." Round 2
sharpened it: **a prose MUST is documentation, not enforcement** — it is exactly what
`core.autocrlf=false` was, and the RFC opens by explaining why that failed. The deep-module
move is to make each predicate a *structural* property of the one code path every fetcher
already funnels through, so omission is impossible, not merely discouraged. We still do
**not** introduce a forced cross-language pipeline base class (Python/Rust streaming models
differ); the enforcement is per-impl factored functions plus the existing admission
chokepoint.

The locus already exists: `FetcherRegistry.fetch()` computes identity itself — a fetcher
*cannot* skip it. Three of the four predicates fold into that same shape:

- **Normalized** → *structural after H3.* Object-store materialization produces no
  checkout, so smudge output is unreachable by construction. Not a clause — a property of
  the materialization function.
- **Complete** → *structural after H3/H5.* Reduces to a single testable question — does
  the materializer recurse mode-160000 gitlinks? — answered in one function, not
  re-verified per fetcher.
- **Bounded** → *enforce at the admission chokepoint.* The registry/`CasAdmittingFetcher`
  stats the staged tree before hashing and raises `FETCH-DOWNLOAD-SIZE-EXCEEDED` over cap —
  one place every fetcher passes through, so the cap cannot be forgotten. (HTTP fetchers
  *additionally* cap at the streaming boundary to bound *memory*, since the post-hoc stat
  bounds *disk* but a 4 GiB buffered download already OOM'd — H1.)
- **Deterministic** → *structural after H3.* Object blobs are SHA-addressed: same pin →
  same bytes, by construction.

**`materialize_git_tree` — the named primitive.** Factor object-store materialization into
one function per impl rather than inlining the `ls-tree`/`cat-file` loop in
`GitFetcher.fetch`:

```python
def materialize_git_tree(
    repo: Path,            # clone scratch holding the object store (.git)
    commit: str,           # SHA to materialize
    dest: Path,            # clean output tree (no .git)
    *,
    submodule_fetch: Callable[[str, str], Path],   # (resolved_url, sha) -> clone scratch
) -> dict[str, str]:        # full-path -> sha for every gitlink recursed
```

It is the single chokepoint for: `cat-file --batch` blob writing, fixed on-disk mode,
LFS-pointer detection, **symlink-escape containment**, and submodule recursion (H5 just
re-enters the same function via `submodule_fetch`, accumulating the returned
`path → sha` map → `GitReceipt.submodule_shas`). `submodule_fetch` is also the test seam:
H-infra stubs it to point at local bare-repo fixtures. The spec names this primitive and
its contract in `spec/plugin-contract.md`; the MUST clause becomes "VCS fetchers MUST
produce their tree via the impl's `materialize-git-tree` equivalent" — enforceable because
there is exactly one place blobs are written.

The residual prose clauses (genuinely contractual, no structural locus):

- Archive-extracting fetchers **MUST** route content through `extract_tar` /
  `SafeExtractor` with default-or-stricter `Limits` (inherits zip-slip, escape, size-cap,
  hardlink, bomb guards).
- **OCI carve-out (round 2):** `OciFetcher` downloads via `oras pull`, *not* milpa's HTTP
  layer, so H1's streaming compressed-cap does not apply to it. Its bounded guarantee comes
  from (a) digest-pinning at the registry (the registry verifies the digest before serving)
  and (b) the admission-chokepoint stat + `extract_tar` `EXTRACT-SIZE-LIMIT` on the pulled
  artifact. Stated explicitly so OCI is not left in ambiguous partial coverage; adding a
  size flag to `oras pull` is deferred unless a real over-size OCI artifact appears.

This is the deep-module move: three predicates become architectural invariants of the
admission path + `materialize_git_tree`, one stays a narrowly-scoped contract — correctness
is structural, not per-fetcher vigilance.

## Spec cascade

This RFC touches the spec, not just the impls. **Bijection discipline:** each new error
slug lands in `spec/errors.md` *in the same slice that creates its raise site*, never in an
upfront batch — adding a slug before its raise site exists violates the `errors.md`
slug↔raise-site bijection lint.

- `spec/identity.md §1.6/§1.7` — **rewrite** around committed-blob hashing (H3a): identity
  is the hash of the object-store tree (`ls-tree` + `cat-file --batch`), not the
  working-tree checkout; clone is `--no-checkout`; **delete** the
  `-c core.autocrlf=false -c core.filemode=false` normalization (no working tree to
  govern); empty dirs not synthesized (§1.2-consistent); fixed on-disk mode; submodule
  content in hash + submodule provenance recording; migration note scoped to the
  integration fixture (corpus unaffected).
- `spec/plugin-contract.md` — (a) the `materialize-git-tree` primitive + its contract
  (`ls-tree` + `cat-file --batch`; `--no-checkout` clone; LFS first-line detection;
  **per-symlink lexical-containment check** → `EXTRACT-SYMLINK-ESCAPE`; recursion into
  mode-160000 gitlinks); (b) the **structural-enforcement** subsection — archive fetchers
  route through `SafeExtractor`; bounded enforced at the admission chokepoint; OCI
  carve-out; (c) hardlink target geometry (linkname is strip-subject; two-pass ordering;
  escape → `EXTRACT-ZIP-SLIP`). *This file was missing from round 1's cascade list for
  the structural clauses — added.*
- `spec/lockfile-schema.md` — `submodule_shas` provenance on `GitReceipt`: flat
  `submodule "<full-path>" sha="<40hex>"` child nodes, path-sorted (H5).
- `spec/errors.md` — new slugs, each with its slice: `FETCH-DOWNLOAD-SIZE-EXCEEDED` (H1),
  `FETCH-GIT-LFS-POINTER` (H3b/c), `FETCH-GIT-SUBMODULE-FAILED` (H5),
  `EXTRACT-NON-UTF8-ENTRY-NAME` (deferred follow-up). `EXTRACT-SYMLINK-ESCAPE` already
  exists — the H3 VCS-path symlink check *reuses* it (no new slug).
- No `spec/manifest-schema.md` change — recursion is always-on, no `submodules` flag.

## Testing strategy — corpus vs integration

A key constraint the slicing must respect: **`MockedGitFetcher` bypasses real git**
(it stages `content/` verbatim), so git-protocol behaviors **cannot** be pinned in the
static conformance corpus without new infrastructure. Therefore:

- **Archive-path slices (H0, H1, H2)** → static conformance fixtures via the S4a
  `archive` raw-bytes mode (no network, both impls converge in-corpus). This is the
  normal `rfc-conformance-parity.md §5` "every fix lands a pinned fixture" discipline.
- **Git-protocol slices (H3 object-store materialization, H4 shallow-clone, H5
  submodules)** → cannot be corpus fixtures today, and because `MockedGitFetcher` bypasses
  git entirely, **H3's central invariant (object-store bytes ≠ smudge bytes) has zero
  static-corpus coverage** — the corpus passes identically before and after H3 regardless
  of correctness. The only test of that invariant is an integration test against a real
  `GitFetcher`. This makes **H-infra load-bearing**, not optional polish.

  **H-infra is a full slice, not a thin adapter** (round-2 correction — it was
  under-scoped ~2–3×). It is a new test *tier*, distinct from both the static corpus and
  the `MILPA_INTEGRATION_TESTS=1` network tier: real `GitFetcher` against `file://` **bare
  repos generated at test time**. Generated, not committed — a bare repo is binary pack
  files that differ by git version and would be a git-in-git mess; it cannot live in
  `conformance/` as static bytes. Scope:
  1. **Creation mechanism:** scripted-at-test-time via `git fast-import` (deterministic
     stream) or shell `git init --bare`+commits, anchored to the existing prior art —
     Python `_make_local_repo()` in `test_git_fetcher.py`, Rust `make_crlf_repo()` in
     `fetchers_tests.rs` — so we extend one of those rather than inventing a fourth path.
  2. **Runner integration:** a new code path in *both* `test_conformance.py` and the Rust
     `milpa-conformance` runner that, for a fixture flagged as git-protocol, generates the
     bare repo(s), injects the `file://` URL (reuse the mocked-fetch env seam), runs the
     real fetcher, tears down.
  3. **Fixture content matrix** the three consumers need: `.gitattributes * eol=crlf` (H3
     determinism), a non-tip pinned commit + shallow clone (H4), a superproject+submodule
     bare-repo pair with a relative `.gitmodules` URL (H5), and an LFS-pointer blob (H3 —
     no LFS tooling required, just commit the pointer text).
  - Interim fallback if H-infra slips: `MILPA_INTEGRATION_TESTS=1`-gated tests carry H3/H5
    coverage until the tier lands. But H-infra is the discipline-conformant home and is
    sequenced as a prerequisite (see slices).
- **Cross-transport byte-identity** (pluggable-fetchers Remaining-Work item 5, previously
  un-absorbed): a fixture asserting that the *same* logical tree fetched via git
  (object-store path) and via tarball produces the **same `content_hash`**. H3 changes the
  git mechanism, so this invariant matters more, not less — folded into H3's H-infra tests.

## Slices (ordered by dependency, not severity)

The stub's "highest-severity first" ordering is wrong for sequencing — #140/#143 are
the deepest and most blocked. Cheapest-and-unblocked first; within the git-protocol
cluster, **H-infra → H4 → H3(a–d) → H5** (round-2 reorder: H4's object-reachability
guarantee is a prerequisite for H3's object-store reads, not a follow-up to them):

- **H0 — verify #175 / corrupt-archive parity (closes #175).** Confirm Rust passes
  `fixture-291`; if it fails, fix the Rust tarball path to raise `FETCH-EXTRACT-FAILED`
  (not Ok-empty) for a sub-512-byte non-zero buffer with no valid header. Fold in the
  `.zip` magic-byte → unsupported-format guard. Gate: `./dev-rust test -p
  milpa-conformance` + `uv run pytest`. No design questions. **First.**
- **H1 — #149 streaming download cap.** Replace buffered `output()` with a streaming
  read aborting at the compressed cap; add `FETCH-DOWNLOAD-SIZE-EXCEEDED`. Unit-test
  via injected transport + tiny cap (no 4 GiB needed). See **Verification gate**.
- **H1b — bz2/xz bomb-guard parity (Rust) + Python stream cap.** Wrap bz2/xz decoders
  in `.take(decomp_cap)` like gzip; add a Python decompressed-stream cap as
  defense-in-depth against lying headers. Corpus fixture via `archive` mode.
- **H2 — #144 hardlink/strip geometry (both impls).** Copy-bytes materialization +
  strip-applied linkname + `dest_root` escape check. Spec the geometry in
  `plugin-contract.md` first. Crafted-tar corpus fixture via `archive` mode. Land both
  impls atomically.
- **H-infra — local-bare-repo fixture tier** *(prerequisite for H4/H3/H5; full slice, not
  a thin adapter — see **Testing strategy**).* Build the generated-bare-repo test tier +
  runner integration in both impls. Gate: a git-protocol fixture runs the real `GitFetcher`
  against a `file://` bare repo and appears in the parity diff.
- **H4 — #145 shallow-clone convergence (Rust).** *Moved before H3 (round-2 dependency
  fix).* Port Python's 4-step fetch/unshallow/re-check chain to Rust with the two precision
  fixes. **This must precede H3 in Rust:** H3's `ls-tree`/`cat-file` require the pinned
  commit's objects present locally, and the common locked-dep case is a non-tip commit —
  Python already has the chain, Rust does not, so Rust H3 is untestable for the primary use
  case without H4. Test via H-infra (non-tip commit; shallow clone).
- **H3 — object-store materialization.** *Split into sub-slices (round 2 — one `/tdd`
  slice was too wide).* Subsumes #143 (no checkout → no smudge); no separate flag-patch
  slice. Causes the one-time hash churn on the **integration fixture only** (corpus
  unaffected) — re-lock fresco's fixture within H3b/c.
  - **H3a — spec first.** Rewrite `spec/identity.md §1.6/§1.7` + add the
    `materialize-git-tree` contract and structural-enforcement subsection to
    `spec/plugin-contract.md`. Normative contract precedes code.
  - **H3b — Python impl.** Factor `materialize_git_tree` (`--no-checkout` clone,
    `cat-file --batch`, fixed mode, **per-symlink escape check** → `EXTRACT-SYMLINK-ESCAPE`,
    LFS first-line detection → `FETCH-GIT-LFS-POINTER`); make it the only path
    `GitFetcher.fetch` produces a tree by; delete `_GIT_TRANSPORT_FLAGS` checkout reliance.
  - **H3c — Rust impl** ✓ **DONE (2026-06-26).** `materialize_git_tree` landed in
    `impls/rust/crates/milpa-core/src/fetchers.rs`; checkout path deleted; `GIT_TRANSPORT_FLAGS`
    emptied (structural: no working tree → no smudge); `FETCH-GIT-LFS-POINTER` moved from
    `DEFERRED` to a real raise site; bijection lint green. Behaviors a–e tested in
    `fetchers_tests.rs` (H3c-a through H3c-e + cross-impl convergence).
    **Integration fixture re-lock: DEFERRED to Corey.** The fresco real-network fixture
    requires `MILPA_INTEGRATION_TESTS=1` which cannot run in the sandbox. Exact command:
    ```
    cd impls/python
    MILPA_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py -v
    ```
    If that generates / updates the committed lockfile fixture, commit it. If the
    integration test suite is not yet wired (test_integration.py absent), run
    `milpa update` against fresco's `milpa.kdl` with the real fetcher and re-pin the
    fixture. The content_hash values for git deps will change (object-store bytes
    differ from checkout bytes where any smudge was previously applied).
  - **H3d — H-infra invariant tests.** ✓ **DONE (2026-06-26).** Seven shared conformance
    fixtures landed in `conformance/spec-v1/fixture-296` through `fixture-302`. All run
    the REAL fetcher on both Python and Rust; both pass (Python: `uv run pytest` 2197 pass;
    Rust: `./dev-rust test --workspace` all pass, conformance 265/299 pass 0 regressions).
    **Generator schema growth:** added `symlinks` map support to both Python
    `_make_git_protocol_repo` (test_conformance.py) and Rust `make_git_protocol_repo`
    (runner.rs) — `{link_path: target}` committed as mode-120000 blobs. Both runners
    extended to handle error-class git-protocol fixtures (expected/error path); Rust
    `run_git_protocol_fixture` now returns the raw slug as `Err(slug)` (no wrapping prefix)
    so `run_fixture`'s `(Expected::Error(slug), Err(code))` arm matches cleanly.
    Fixture inventory:
    - `fixture-296-git-protocol-eol-crlf-with-attr` — LF bytes + `* eol=crlf` → hash
      `sha256:cd92fb78...` (proves no smudge; tree includes `.gitattributes`)
    - `fixture-297-git-protocol-eol-crlf-no-attr` — same `data.txt` LF bytes, no attr →
      hash `sha256:985b34e3...` (different tree, different hash; pair proves `data.txt`
      bytes identical in both repos via per-impl comparison)
    - `fixture-298-git-protocol-symlink-escape` — committed symlink `../../../../etc/passwd`
      → `EXTRACT-SYMLINK-ESCAPE` (error fixture; uses `symlinks` generator extension)
    - `fixture-299-git-protocol-safe-symlink` — committed in-tree symlink `link.txt→target.txt`
      → hash `sha256:c97c9e72...` (success fixture; symlink materialized, included in hash)
    - `fixture-300-git-protocol-lfs-pointer` — blob with exact LFS first-line →
      `FETCH-GIT-LFS-POINTER` (error fixture)
    - `fixture-301-cross-transport-git` — git path for `data.txt+stub.nimble` →
      hash `sha256:985b34e3...` (same hash as 302)
    - `fixture-302-cross-transport-tarball` — tarball path for same `data.txt+stub.nimble`
      → hash `sha256:985b34e3...` (same hash as 301; proves git+tarball converge)
- **H5 — #140 submodule recursion.** ✓ **DONE (2026-06-26).** Built on H3's
  `materialize_git_tree`: read+parse `.gitmodules` from the object store (pure text, no
  eval), resolve relative URLs against superproject provenance (git's `${remote%/*}` rule),
  recurse each mode-160000 gitlink via the same primitive; record full-path → SHA in
  `GitReceipt.submodule_shas` (flat KDL nodes, path-sorted in lockfile); add
  `FETCH-GIT-SUBMODULE-FAILED` (carrying `submodule_path`/`submodule_url`). Both Python
  and Rust impls complete; bijection lint green. Lockfile round-trip for `submodule_shas`
  tested in `test_lockfile.py`. `ProvenanceRecord::Git` in `milpa-types` extended with
  `submodule_shas: Vec<(String, String)>`; all construction sites updated. Both impl gates
  pass: Python 2218/30 skipped, Rust all `ok. N passed; 0 failed`.
  **Integration fixture re-lock: DEFERRED to Corey** (same as H3c — needs
  `MILPA_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py -v` against fresco's
  real dep tree).

## Verification gate (resolve before H1 ships)

Round 2 narrowed this: the streaming rewrite is warranted **regardless of curl's
behavior**, because the Python `make_http_get` uses `subprocess.run(..., capture_output
=True)`, which buffers the entire response into memory before returning — `--max-filesize`
aborting mid-stream doesn't help, the partial-but-large bytes curl already read are still
fully buffered, and the Rust path captures `Vec<u8>` the same way. So H1 is *definitively*
a streaming-bounded-read rewrite; the cap moves to the streaming boundary and a distinct
`FETCH-DOWNLOAD-SIZE-EXCEEDED` slug replaces the post-buffer `FETCH-DOWNLOAD-FAILED` raise.
The only thing left to *measure* (not decide) is how much curl already mitigates on the
real-network path — run the chunked / no-`Content-Length` `http.server` experiment to set
the issue's risk note, but it does not change H1's scope.

## Sequencing vs rfc-conformance-parity

`rfc-conformance-parity.md` S4/S4a (raw-bytes mocked mode, `fixture-291`) is **done**
and is exactly what H0/H1/H1b/H2 build on — H0 is essentially confirming S4 crossed the
line for Rust. No new parity-side work; just verify Rust green. If H1 exposes a
fixture-level cap override (e.g. `MILPA_TARBALL_MAX_BYTES`), coordinate with the
conformance-parity env-injection runner. H3–H5 (git-protocol) do not touch the corpus
machinery and have no overlap.
