# milpa identity algorithm and CAS layout (S12)

Normative spec of milpa's **content-hash identity algorithm** and
**content-addressed store (CAS) layout**. Any implementation that claims
milpa conformance MUST produce byte-identical hashes and MUST follow the
CAS admission rules marked `> NORMATIVE:`. Items marked `> NOTE:` describe
the reference Python implementation; conformant alternatives MAY differ in
those details.

This document covers identity computation and the CAS layout only. Related
specs:

- `spec/errors.md` — `ID-*` and `CAS-*` error codes
- `spec/manifest-grammar.md` (S4) — manifest grammar; `cas { dir }` field
- `spec/lockfile-schema.md` (S5) — lockfile `identity` field;
  `nim.cfg --path:` dependence on the CAS symlink layout
- `spec/plugin-contract.md` (S10) — fetcher contract; registry computes
  identity, never the fetcher; `cas_admissible` declaration

---

## Normative surface

A conformant implementation of this spec MUST:

1. Compute `content_hash` using the canonical byte stream defined in §1:
   UTF-8-byte-order-sorted file entries, per-entry serialization with null-byte
   separators, sha256 digest.
2. Exclude any path component named `.git` at any depth from the hashed
   tree.
3. Hash symlinks by their target string (not by following them), using the
   symlink mode marker `0x80`.
4. NOT normalize line endings; raw bytes are fed to the hash as-is.
5. Encode the output as `sha256:<64-lowercase-hex-chars>`.
6. Validate identity strings via the `<algorithm>:<digest>` grammar (§2),
   rejecting unknown algorithms and wrong digest lengths.
7. Lay out the CAS as `<root>/<algorithm>/<hex-digest>/` (§3).
8. Admit trees atomically via `rename(2)`; treat duplicate admission as a
   no-op (§3.3).
9. Create `_deps/<name>` as a **relative** symlink into the CAS entry (§3.5).
10. NOT silently evict a CAS entry that a lockfile still references (§3.7).
11. Use a per-fetch unique scratch subdirectory under `<root>/_scratch/` and
    clean it up on both success and error paths (§3.4).
12. Raise a coded error for symlink targets that are not valid UTF-8 (§1.5).
13. Resolve the CAS root using the four-tier precedence:
    `MILPA_CACHE_DIR` > manifest `cas { dir }` > `$XDG_CACHE_HOME` >
    `~/.cache/milpa/cas` (§3.2).

---

## 1  Content-hash algorithm

### 1.1  Overview

The content hash of a source tree is the sha256 digest of a deterministic
byte stream derived from every file and symlink under the tree root.
The hash is:

- **Transport-independent**: the same source bytes always produce the same
  hash regardless of how they were fetched (git, tarball, OCI, local copy).
- **Provenance-independent**: the hash does not incorporate a git URL,
  commit SHA, ref name, or any other transport-level metadata.
- **Recomputable**: given the bytes on disk, any implementation can reproduce
  the hash without contacting any network service.

### 1.2  Canonical byte stream

> NORMATIVE: The input to sha256 is the concatenation of zero or more
> **entry records**, one per file or symlink under the tree, in ascending
> POSIX relpath order. Each record has exactly this byte layout:
>
> ```
> <relpath-bytes> 0x00 <mode-marker> 0x00 <content-bytes> 0x00
> ```
>
> where:
>
> - `<relpath-bytes>` is the relative path from the tree root to the entry,
>   encoded as UTF-8, with `/` as the path separator (POSIX form), and
>   without a leading `/` or `./`. Example: `src/foo.nim`.
> - `0x00` is a single null byte used as a field separator.
> - `<mode-marker>` is exactly one byte:
>   - `0x00` — regular file, non-executable (owner-execute bit not set)
>   - `0x01` — regular file, executable (owner-execute bit set,
>     `stat.S_IXUSR`)
>   - `0x80` — symbolic link
> - `<content-bytes>` is:
>   - For a regular file (`0x00` or `0x01`): the raw file contents, byte for
>     byte. Line endings are NOT normalized; CRLF and LF are distinct.
>   - For a symlink (`0x80`): the link-target string encoded as UTF-8.
>     The symlink is NOT followed; its target path is hashed as-is.
> - A trailing `0x00` byte closes each record.

> NORMATIVE: There are NO length prefixes, NO record-count headers, and NO
> other framing bytes beyond the three null-byte separators per record.

> NORMATIVE: Empty directories contribute no bytes to the hash. Only file
> and symlink entries generate records.

> NOTE: The reference implementation feeds entries into a single live
> `hashlib.sha256()` accumulator in one pass; there is no intermediate
> serialization buffer. `identity.py:compute_content_hash`, lines 119–128.

### 1.3  Sort order

> NORMATIVE: Entries MUST be sorted by their `<relpath-bytes>` value using
> raw UTF-8 byte-order comparison: compare byte-by-byte from the start of
> each relpath string; the first differing byte determines the order; shorter
> strings that are a prefix of a longer one sort first. This rule applies
> unconditionally regardless of filename character set. Implementations MUST
> NOT apply locale-sensitive collation, Unicode normalization, or any other
> transformation before comparing.

> NOTE: The reference implementation calls
> `entries.sort(key=lambda e: e.relpath)` on the list of `_Entry` objects
> after collecting them (`identity.py:178`). Python's default string sort is
> lexicographic on Unicode code points. For all path strings that encode
> as pure ASCII the Unicode point order is identical to the UTF-8 byte
> order. For paths containing non-ASCII characters the correct comparison
> is raw UTF-8 byte order; see the NORMATIVE clause above.

### 1.4  `.git/` exclusion

> NORMATIVE: Any entry whose path parts include a component named exactly
> `.git` MUST be excluded from the hash, at any depth in the tree. This
> applies to the `.git/` directory at the repository root as well as any
> nested `.git/` directory (e.g., `vendor/foo/.git/`). Git metadata is
> provenance, not content.

> NOTE: The reference implementation checks `".git" in p.parts` for every
> `Path` object returned by `root.rglob("*")` (`identity.py:155`). `p.parts`
> is the tuple of path components; the check excludes both `.git` itself and
> anything beneath it.

### 1.5  Symlink handling

> NORMATIVE: Symbolic links MUST be hashed as entries with mode marker
> `0x80`; their content bytes are the UTF-8 encoding of the link-target
> string as returned by `readlink(2)`, not the contents of the file the
> symlink points to. Symlinks MUST NOT be followed.

> NOTE: The reference implementation calls `os.readlink(p)` and encodes the
> result as UTF-8 (`identity.py:160–161`). On Linux, `os.readlink()` returns
> a Python `str` decoded with `surrogateescape` error handler; calling
> `.encode("utf-8")` on a string containing surrogate bytes raises
> `UnicodeEncodeError`. The reference implementation does not handle this case
> and will propagate the exception.

> NORMATIVE: A symlink whose target is not valid UTF-8 MUST be treated as an
> error. A conformant implementation MUST raise `ID-NON-UTF8-SYMLINK-TARGET`
> (or an equivalent coded error) rather than silently proceeding with a
> corrupted or lossy byte sequence. This preserves the hash-stability
> guarantee: two implementations must hash the same bytes.

### 1.6  No line-ending normalization

> NORMATIVE: File contents are fed to the hash raw. Implementations MUST NOT
> convert `\r\n` to `\n`, strip trailing whitespace, or apply any other
> normalization to file bytes before hashing.

> NOTE: The reference implementation reads files with `p.read_bytes()`
> (`identity.py:174`), which returns the exact bytes on disk.

### 1.7  Mode bit: executable

> NORMATIVE: A regular file's mode marker is `0x01` if and only if the
> owner-execute bit (`stat.S_IXUSR`, octal `0o100`) is set in the file's
> mode. All other permission bits are ignored. A file without the
> owner-execute bit set uses marker `0x00` regardless of group-execute or
> world-execute bits.

> NOTE: The reference implementation evaluates `mode & stat.S_IXUSR`
> (`identity.py:169`).

---

## 2  Identity string format (multihash encoding)

### 2.1  Canonical form

> NORMATIVE: The identity string produced by `compute_content_hash` and
> stored in lockfiles, CAS paths, and `FetchResult.identity` MUST be:
>
> ```
> sha256:<64-lowercase-hex-chars>
> ```
>
> The `sha256:` prefix is part of the canonical form. An identity string
> without the prefix is invalid.

> NORMATIVE: The hex digest MUST use lowercase letters `a`–`f`; uppercase
> is rejected.

> NOTE: The reference implementation returns `f"sha256:{h.hexdigest()}"`
> from `compute_content_hash` (`identity.py:128`). `hashlib.hexdigest()`
> always produces lowercase.

### 2.2  Validation grammar

> NORMATIVE: A conformant implementation MUST validate identity strings via
> `parse_identity` semantics:
>
> 1. The input MUST be a string (`ID-NOT-A-STRING` otherwise).
> 2. The string MUST contain a `:` separator (`ID-NO-ALGORITHM-PREFIX`
>    otherwise).
> 3. The algorithm prefix (the part before `:`) MUST be in the supported
>    algorithm set (`ID-UNSUPPORTED-ALGORITHM` otherwise). Currently the
>    only supported algorithm is `sha256`.
> 4. The digest (the part after `:`) MUST be exactly 64 characters for
>    `sha256` (`ID-WRONG-DIGEST-LENGTH` otherwise).
> 5. The digest MUST consist entirely of `0`–`9` and `a`–`f`
>    (`ID-NON-HEX-DIGEST` otherwise).

> NOTE: The reference implementation is `parse_identity` in `identity.py`,
> lines 65–107. It returns the input string unchanged when valid — the
> canonical form is the input itself.

### 2.3  Algorithm agility

> NOTE: The `sha256:` prefix anticipates future algorithm migration. Adding
> a new algorithm requires: (1) adding it to `SUPPORTED_ALGORITHMS`, (2)
> adding its digest-hex length to `_DIGEST_HEX_LEN`, and (3) updating
> `compute_content_hash`. During a migration window, lockfiles MAY carry
> both the old and new algorithm's identity per dep; both MUST be written,
> and only the new one is required to match for verification. This is
> **not yet implemented** in spec v1.0; a future spec amendment will define
> the migration protocol.

---

## 3  Content-addressed store (CAS) layout

### 3.1  Directory structure

> NORMATIVE: The CAS root is a directory under which all admitted trees
> are stored. Within the root, entries are addressed by algorithm and
> digest:
>
> ```
> <root>/
>   <algorithm>/           e.g. sha256/
>     <hex-digest>/        e.g. a3f9...c1d2/   (64 hex chars for sha256)
>       <tree contents>    the source tree, as-fetched
> ```
>
> The `<algorithm>` component is the same prefix used in the identity
> string. The `<hex-digest>` component is the 64-character lowercase hex
> digest. A conformant implementation MUST NOT use any other layout.

### 3.2  Default root and override

> NORMATIVE: The CAS root location is resolved in this precedence order
> (highest priority first):
>
> 1. `MILPA_CACHE_DIR` environment variable — explicit override (for tests
>    and sandboxes). When set, no other tier is consulted.
> 2. Manifest `cas { dir "..." }` override in `milpa.kdl` — a per-project
>    CAS root. Relative paths are resolved against the project root; absolute
>    paths are used verbatim. Only effective when `MILPA_CACHE_DIR` is unset.
> 3. `$XDG_CACHE_HOME/milpa/cas` — if `XDG_CACHE_HOME` is set.
> 4. `~/.cache/milpa/cas` — fallback default.
>
> The normative precedence list above is the single source of truth; see
> `cli-contract.md` §8.2 for the environment-variable normative rules that
> correspond to tiers 1 and 3–4.

> NOTE: `default_store()` in `cas.py` (lines 99–113) implements tiers 1, 3,
> and 4 only — it has no access to the manifest. Tier 2 is applied by
> `_fetcher_for_manifest()` in `cli.py` (lines ~237–258): when
> `manifest.cas_dir` is non-empty and `MILPA_CACHE_DIR` is unset, it
> constructs a fresh `FetcherRegistry` with a `CAStore` rooted at the
> resolved path. This override is per-invocation; it does not affect the
> process-global `default_store()` value.

### 3.3  Admission: `admit()`

> NORMATIVE: Admitting a source tree to the CAS MUST:
>
> 1. Compute the content hash of the tree to be admitted (via the algorithm
>    in §1).
> 2. Compare the computed hash against the caller-supplied `identity` string.
>    If they differ, raise `CAS-IDENTITY-MISMATCH` and leave the source tree
>    in place for the caller to inspect. The store MUST NOT be modified on a
>    mismatch.
> 3. Create the canonical path `<root>/<algorithm>/<hex-digest>/` if it does
>    not exist.
> 4. Move the source tree to the canonical path via `rename(2)`.
>    If the rename fails because the canonical path already exists (a
>    concurrent admit of the same identity), the source tree MUST be removed
>    and the existing canonical path returned. This is the **duplicate
>    admission = no-op** rule.
> 5. Return the canonical path.

> NORMATIVE: The rename MUST be to a path on the same filesystem as the
> source tree to guarantee atomicity. Implementations using a CAS that
> crosses filesystem boundaries MUST use an alternative atomic mechanism
> (e.g., copy-then-rename within the CAS, then delete the source).

> NOTE: The reference implementation fetches into a scratch directory under
> `<root>/_scratch/` for exactly this reason: the scratch dir and the CAS
> entries share the same filesystem mount, so `src.rename(canonical)`
> (`cas.py:68`) is a POSIX rename(2) and is atomic. The `FetcherRegistry`
> creates the scratch dir at `self._store.root / "_scratch"` (`types.py:161`).

> NOTE: The reference implementation's OSError catch (`cas.py:69–75`) handles
> the race where two processes admit the same identity concurrently: the
> loser's rename fails, it verifies the canonical dir exists, removes its
> scratch, and returns the canonical path. If the canonical dir is absent
> after the OSError (a different OS error), the exception is re-raised.

### 3.4  Scratch-area lifecycle and cleanup

> NORMATIVE: In-progress fetches MUST use a dedicated scratch area under
> `<root>/_scratch/` before being moved into the store via atomic rename.
> Each individual fetch occupies a unique subdirectory under `_scratch/`
> (the reference implementation uses a UUID hex name). The scratch entry
> MUST be removed — via `shutil.rmtree` or equivalent — in a `finally`-style
> cleanup after the fetch succeeds or fails, so that a clean failure leaves
> no orphaned scratch data.

> NORMATIVE: If a process is interrupted (SIGKILL, power loss, etc.) before
> the cleanup executes, orphaned `<root>/_scratch/<uuid>/` subdirectories
> MAY remain on disk. The spec v1.0 reference implementation provides no
> automatic GC for these entries.

> NOTE: The reference implementation uses `try: ... except BaseException:
> shutil.rmtree(scratch, ignore_errors=True); raise` (`fetchers/types.py:211–219`).
> `BaseException` catches both normal exceptions and `KeyboardInterrupt` /
> `SystemExit`, so all foreground-signal-safe termination paths clean up.
> Only `SIGKILL` (which terminates the process immediately, bypassing Python)
> can leave orphaned entries.

> NOTE: An automatic startup GC (scan and remove stale `_scratch/` entries
> older than a threshold) is the intended remedy for orphaned entries but is
> NOT implemented in spec v1.0. A future spec amendment MUST specify the GC
> policy (staleness threshold, locking protocol, safe-to-remove heuristic)
> before any implementation may remove entries from `_scratch/`.

### 3.5  The `_deps/<name>` symlink convention

> NORMATIVE: After a successful admit, `_deps/<name>` in the project
> directory MUST be a symlink pointing to the CAS entry for that dep's
> identity. The symlink target MUST be a **relative** path from the
> `_deps/<name>` symlink's parent directory to the CAS entry. Absolute
> symlinks are non-conformant.

> NORMATIVE: The `nim.cfg --path:` entries emitted by milpa (S5) reference
> `_deps/<name>/<src_dir>`. Conformant `nim.cfg` emission MUST assume the
> symlink convention: it uses the `_deps/<name>` path, not the CAS path
> directly.

> NOTE: The reference implementation uses `os.path.relpath(canonical,
> start=target.parent)` to compute the relative symlink target (`cas.py:95`).
> This keeps `_deps/<name>` symlinks valid when the project tree is
> bind-mounted at a different absolute path (e.g., host
> `/home/x/proj` mounted as `/work` in a container).

> NOTE: `link()` calls `clear_dest(target)` before creating the symlink
> (`cas.py:94`), making re-linking idempotent.

### 3.6  Identity verification on link

> NORMATIVE: `CAStore.link()` MUST raise `CAS-NOT-IN-STORE` if the
> requested identity has no entry under `<root>/<algorithm>/<hex-digest>/`.
> It MUST NOT create a dangling symlink.

### 3.7  CAS is append-only (no silent eviction)

> NORMATIVE: A conformant implementation MUST NOT silently evict a CAS
> entry that a lockfile still references. The CAS is append-only from the
> perspective of the spec: admission is the only write; deletion is out of
> scope for spec v1.0.

> NORMATIVE: A future GC / eviction mechanism MUST be specified in a spec
> amendment before any implementation may prune the CAS. Until such an
> amendment is ratified, conformant implementations MUST NOT remove entries
> from the CAS.

> NOTE: The v1.0 Python reference implementation has no eviction path. The
> normative statement above is prospective — it governs future implementations
> and spec amendments, not existing behaviour.

---

## 4  Identity vs provenance boundary

This section summarises the separation of concerns. Full conceptual
treatment is in `docs/identity-and-provenance.md`.

> NORMATIVE: `content_hash` / `identity` is the identity primitive.
> It is recomputable from the source-tree bytes alone, without knowledge of
> how the bytes were obtained.

> NORMATIVE: Git URL, git ref, commit SHA, OCI registry/repository/digest,
> tarball URL, and archive sha256 are **provenance** — metadata about how to
> obtain or verify the source. They are stored in the lockfile's provenance
> block, not in the identity field.

> NORMATIVE: Identity MUST be computed by the **fetcher registry** after the
> source tree is materialized on disk. Individual fetcher implementations
> MUST NOT compute or assert identity; they return a `ProvenanceReceipt`
> only. (Cross-reference S10 for the full fetcher contract.)

> NOTE: `FetcherRegistry.fetch()` calls `compute_content_hash(dest)` or
> `compute_content_hash(scratch)` after the fetcher returns
> (`types.py:152–153`, `types.py:167`). The fetcher's `fetch()` method
> returns `ProvenanceReceipt`, which is explicitly described as "descriptive,
> not identity-bearing" (`types.py:63–64`).

---

## 5  Error codes

All identity and CAS errors are defined in `spec/errors.md`. Summary:

| Code | When |
|---|---|
| `ID-NOT-A-STRING` | `parse_identity` receives a non-string |
| `ID-NO-ALGORITHM-PREFIX` | identity string has no `:` separator |
| `ID-UNSUPPORTED-ALGORITHM` | algorithm prefix not in supported set |
| `ID-WRONG-DIGEST-LENGTH` | digest length wrong for algorithm |
| `ID-NON-HEX-DIGEST` | digest contains non-lowercase-hex chars |
| `CAS-IDENTITY-MISMATCH` | `admit()` computed hash ≠ claimed identity |
| `CAS-NOT-IN-STORE` | `link()` called for an identity not in store |
