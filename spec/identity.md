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

1. Compute `content_hash` as the canonical content Merkle DAG of §1.8 (epoch 2,
   the epoch in force per §1.1.1): per-level leaf-name sort, four-valued
   mode-byte, bottom-up tree nodes, root `H_tree` as the digest. (The interim
   epoch-1 flat byte stream of §1.2 is retired and no longer emitted.)
2. Exclude any path component named `.git` at any depth from the hashed
   tree.
3. Hash symlinks by their target string (not by following them), using the
   symlink mode marker `0x80`.
4. NOT normalize line endings; raw bytes are fed to the hash as-is.
5. Encode the output as `dag-sha256:<64-lowercase-hex-chars>`.
6. Validate identity strings via the `<algorithm>:<digest>` grammar (§2),
   rejecting unknown algorithms and wrong digest lengths.
7. Lay out the CAS as `<root>/<algorithm>/<hex-digest>/` (§3).
8. Admit trees atomically via `rename(2)`; treat duplicate admission as a
   successful no-op returning the existing entry — the store is never
   overwritten (C-admit-idem, §3.3).
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

### 1.1.1  Two epochs (interim flat stream vs. canonical Merkle DAG)

> NORMATIVE: milpa identity has two epochs. The identity-string scheme prefix
> (`dag-sha256:`, §2) names the *full canonical computation*, and which epoch is
> in force is a property of the milpa release, not of the string:
>
> - **Epoch 1 (interim, RETIRED).** §1.2–§1.7 define a single **flat
>   null-separated byte stream** over the whole tree, digested with one sha256
>   pass. This is what the reference impls emitted in the interim; it is **no
>   longer emitted** (RFC `rfc-identity-conformance-authority`, B-cutover). Its
>   mode marker was two-valued (`0x00` regular, `0x80` symlink) and the executable
>   bit was excluded. §1.2–§1.7 are retained as the historical description and as
>   the home of the cross-cutting content rules §1.8 inherits.
> - **Epoch 2 (canonical Merkle DAG, the forever format — IN FORCE).** §1.8
>   defines a canonical content **Merkle DAG** of blob and tree nodes. It is the
>   normative target the multi-impl conformance corpus freezes (RFC
>   `rfc-identity-conformance-authority`). Epoch 2 includes the executable bit
>   (mode-byte `0x01`, §1.8.2) — a deliberate correction over epoch 1.

> NORMATIVE: Epoch 2 is the meaning of `dag-sha256:`. The B-cutover flipped
> emission from the §1.2 flat stream to the §1.8 Merkle DAG; the digest bytes
> changed (intended — there are no external consumers pre-v1, see §2.1). The
> cross-cutting content rules (`.git` exclusion §1.4, symlink-as-target §1.5,
> raw bytes / no line-ending normalization §1.6, non-UTF-8 relpath rejection)
> are **shared by both epochs**; §1.8 inherits them by reference.

### 1.2  Canonical byte stream (epoch 1 — interim)

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
>   - `0x00` — regular file
>   - `0x80` — symbolic link
> - `<content-bytes>` is:
>   - For a regular file (`0x00`): the raw file contents, byte for
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

### 1.7  Git-dep identity: object-store materialization

The identity of a git dep is the hash of the **object-store tree**, not the
working-tree checkout.

**Why object-store, not checkout.** A `git checkout` is the *smudge output*:
git applies `core.autocrlf`, then per-path `.gitattributes` directives
(`eol=`, `filter=`, `ident`, `working-tree-encoding=`) at checkout time.
These transformations are host-config-dependent (LFS installation, libiconv
version, git version), making the working-tree checkout a non-deterministic
function of the pin. Object-store blobs are the *clean* side — the exact
bytes committed, pre-smudge by construction. No checkout runs, so no smudge
filter can apply.

#### 1.7.1  Clone discipline

> NORMATIVE: The clone that backs object-store reading MUST be created with
> `--no-checkout` (or as a bare repository). A default `git clone` creates a
> working tree and runs smudge filters at checkout time; this defeats the
> object-store mechanism. Conformant implementations MUST NOT perform a
> working-tree checkout before or during the identity-computation pass.

> NORMATIVE: The output tree written to `dest/` MUST NOT contain a `.git`
> directory. The clone scratch (which holds the object store) and the output
> tree MUST be distinct directories. The clone scratch MUST be removed after
> the `cat-file` pass completes, regardless of whether CAS admission succeeds.

#### 1.7.2  Enumeration and bulk blob reading

> NORMATIVE: Blob enumeration MUST use `git ls-tree -r <commit>`, which
> produces one `(mode, type, sha, path)` record per blob and gitlink in the
> committed tree. Implementations MUST stream the stored bytes for every
> enumerated blob through a single `git cat-file --batch` subprocess invocation
> (SHAs supplied on stdin, headers and raw bytes returned on stdout). A
> per-blob `cat-file` subprocess invocation is NOT conformant: a 10 000-file
> dep would spawn 10 000 processes, exhausting OS process limits in constrained
> environments.

#### 1.7.3  Empty directories

> NORMATIVE: `git ls-tree -r` emits only blobs (regular files and symlinks)
> and gitlinks (submodule references); git does not track empty directories.
> VCS materialization MUST NOT synthesize empty directories. The absence of
> empty directories from the output tree is consistent with §1.2 (empty
> directories contribute no bytes to the hash), and is normative for the VCS
> path: the hash MUST be computed over exactly the blobs emitted by
> `ls-tree -r`, not over a filesystem walk that may include synthesized
> directories.

#### 1.7.4  On-disk mode for materialized blobs

Conformant implementations MUST write materialized blobs with the following
fixed on-disk modes:

- Under **epoch 2** (§1.8, in force) the executable bit is **part of identity**
  (mode-byte `0x01`, §1.8.2), so the on-disk mode is identity-bearing and MUST
  be preserved exactly as committed. This is what makes the B-cutover invariant
  hold: re-walking the materialized on-disk tree (`compute_content_hash`, which
  CAS `verify` uses) reproduces the same `dag-sha256:` as the object-store
  enumeration only because the exec bit and symlinks survive to disk.
- (Historical: under the retired interim epoch 1 the exec bit was excluded from
  the hash; the fixed modes were still required so `milpa verify` re-hashed
  byte-identically across hosts.)

> NORMATIVE:
>
> | `ls-tree` mode | On-disk permission |
> |---|---|
> | `100644` — regular blob | `0o644` |
> | `100755` — executable blob | `0o755` |
> | `120000` — symlink blob | (materialized as a symlink; mode is the OS default) |
> | Directory entries | `0o755` |
>
> Any `ls-tree` mode not listed above (e.g. `160000` gitlink — handled by
> §1.7.5) MUST be processed by the submodule recursion path, not written
> as a plain blob.

#### 1.7.5  Submodules: identity/provenance split and always-on recursion

> NORMATIVE: A mode-160000 gitlink entry in `ls-tree -r` output records a
> **submodule reference**. Submodule *source bytes* are content — the build
> needs them for a complete dependency closure — and therefore MUST be
> included in the `content_hash`. Submodule *URLs and pinned commit SHAs*
> are **provenance** and MUST be recorded separately (in the lockfile's
> provenance block for the dep, not in the identity field). These two kinds
> of information MUST NOT be conflated.

> NORMATIVE: Submodule recursion is **always-on**. Implementations MUST
> recurse into every mode-160000 gitlink entry via the same `materialize-git-tree`
> primitive (see `spec/plugin-contract.md §2.3`). An opt-in recursion flag
> would make `content_hash` cover the full source closure in some invocations
> and a strict subset in others — a hash whose meaning varies by flag, which
> violates the transport-independence and recomputability requirements of §1.1.
> The detailed mechanics of submodule URL resolution, `.gitmodules` parsing,
> and relative-URL handling are specified in `spec/plugin-contract.md §2.3`
> and land with H5.

---

## 1.8  Canonical content Merkle DAG (epoch 2 — the forever format)

This section is the **byte-level normative table** for milpa identity epoch 2.
It is the format the multi-impl conformance corpus freezes; a wrong byte or a
wrong child order is a permanent cross-impl divergence. Epoch 2 inherits the
shared content rules of §1.4 (`.git` exclusion), §1.5 (symlink-as-target), §1.6
(raw bytes, no line-ending normalization), and the non-UTF-8 relpath rejection
(`ID-NON-UTF8-RELPATH`).

Identity is the digest of a **canonical content Merkle DAG**: leaves are content
**blob nodes**, interior nodes are **tree nodes** (one per directory), and the
identity is the digest of the **root tree node**. This aligns milpa with
git/OCI/IPFS (all Merkle-addressed) while remaining transport-independent: the
DAG derives from content, not from how the content was fetched.

> NORMATIVE: `dag-sha256:<hex>` is a milpa scheme string, **not an IPFS CID**
> (RFC §3.6); it MUST NOT be passed to CID/multihash-parsing libraries. The
> digest is the raw 32-byte/64-hex sha256, with no multicodec/varint prefix.

### 1.8.1  Blob node

> NORMATIVE: A **blob node** is a single regular file or symlink. Its digest is:
>
> ```
> H_blob = sha256(content-bytes)
> ```
>
> This is **transport-neutral**: it is the sha256 of the raw content bytes
> directly, **NOT** git's `blob <len>\0<content>` object hash, and **NOT**
> wrapped in any framing. For a **regular file**, `content-bytes` is the exact
> bytes on disk / in the object store — no line-ending normalization (§1.6). For
> a **symlink**, `content-bytes` is the UTF-8 encoding of the link-target string
> (§1.5); the symlink is not followed. A non-UTF-8 symlink target raises
> `ID-NON-UTF8-SYMLINK-TARGET`; a non-UTF-8 relpath raises `ID-NON-UTF8-RELPATH`.

### 1.8.2  Tree node and the per-entry encoding

A **tree node** is the canonical encoding of one directory's immediate children.
Each child — whether a blob (file/symlink) or a subtree (subdirectory) — is one
**entry**.

> NORMATIVE: Each entry is serialized as exactly these four fields, concatenated
> with no separators or padding:
>
> ```
> <uint32-be name-length> <name-bytes> <mode-byte> <child-digest-raw>
> ```
>
> where:
>
> - `<uint32-be name-length>` is the byte length of `<name-bytes>`, encoded as a
>   4-byte big-endian unsigned integer.
> - `<name-bytes>` is the UTF-8 encoding of the child's **leaf name** — a single
>   path component (e.g. `b.txt`), **NOT** the full relpath. It MUST NOT contain
>   `/`. Length-prefixing removes any separator-byte ambiguity: a name may
>   contain any byte except those excluded by the OS, and no in-band delimiter is
>   used.
> - `<mode-byte>` is exactly one byte (§1.8.2.1).
> - `<child-digest-raw>` is the **raw 32-byte** sha256 digest of the child node —
>   `H_blob` for a blob child, `H_tree` for a subtree child. It is the raw bytes,
>   **never** the ASCII `dag-sha256:<hex>` string (the self-describing string
>   lives only in lockfiles/CAS paths, never inside a node).
>
> The tree-node digest is:
>
> ```
> H_tree = sha256(concat(entries-in-canonical-order))   // §1.8.3
> ```

> NORMATIVE: Leaf names are unique within a tree node (a filesystem/`git tree`
> invariant: a directory cannot hold two children of the same name). An
> implementation MUST NOT emit two entries with the same `<name-bytes>` in one
> tree node.

#### 1.8.2.1  Mode-byte (four-valued)

> NORMATIVE: The mode-byte takes exactly four values:
>
> | Byte   | Meaning                          | Child digest is |
> |--------|----------------------------------|-----------------|
> | `0x00` | regular file                     | `H_blob`        |
> | `0x01` | executable regular file          | `H_blob`        |
> | `0x80` | symbolic link                    | `H_blob`        |
> | `0x40` | tree (subdirectory / submodule)  | `H_tree`        |
>
> No other value is valid. A directory entry (including a spliced submodule,
> §1.8.7) is always `0x40` regardless of the directory's own permission bits —
> directory permissions are not content.

> NORMATIVE: The mode-byte is a **type tag** that domain-separates `H_blob` from
> `H_tree` within a parent. Because blob and subtree children both carry a raw
> 32-byte digest in the same position, the mode-byte (together with the
> length-prefixed name) is what makes the entry stream unambiguously decodable
> and prevents a blob from forging a subtree, or vice versa (the
> Certificate-Transparency leaf/node-prefix discipline). The `0x40` value is
> therefore load-bearing — without it the encoding could neither represent
> subdirectories nor separate the two digest spaces.

> NORMATIVE: `0x01` (the executable bit) places the POSIX `+x` bit into identity
> for the first time. This is a deliberate **epoch-2 correction**: epoch 1
> dropped it, so two trees differing only in a script's executable bit hashed
> identically (a correctness hole). git tracks it (`100644`/`100755`); the
> materializers already carry it. A `100755` `ls-tree` blob → `0x01`; a `100644`
> blob → `0x00`; a `120000` blob → `0x80`.

### 1.8.3  Canonical child order — leaf-name byte sort (top divergence risk)

> NORMATIVE: Within a tree node, entries — **both blob and subtree children** —
> MUST be concatenated in **ascending UTF-8 byte order of the leaf name**
> (`<name-bytes>`), compared byte-by-byte; the first differing byte determines
> the order; a shorter name that is a byte-prefix of a longer one sorts first.
> No locale collation, no Unicode normalization.

> NORMATIVE: The sort key is the **leaf name (single path component)**, **not**
> the full relpath. This differs from epoch 1's full-relpath sort (§1.3) and is
> **the single highest cross-impl-divergence risk in epoch 2.** A materializer's
> natural stream order (`git ls-tree -r`, or a flat directory walk) is
> *full-relpath* order, which can differ from per-level leaf-name order. The DAG
> builder MUST re-sort the immediate children of **every** tree node by leaf name
> independently, and MUST NOT rely on the materializer's stream order.
>
> Worked example (the corpus pins this as `fixture-330-dag-oracle-nested-leafsort`):
> a root containing a subdirectory `a/` and a file `a.txt`. In full-relpath byte
> order, `a.txt` precedes `a/b.txt` because `.` (`0x2e`) < `/` (`0x2f`) — i.e.
> the file would come *before* the directory. But by leaf name, `"a"` is a
> byte-prefix of `"a.txt"`, so the **subdirectory `a` sorts first**. A builder
> that re-uses stream order produces a different (wrong) root `H_tree`.

### 1.8.4  DAG construction (buffered, bottom-up)

> NORMATIVE: A per-transport **materializer** yields a **flat, fully-buffered**
> sequence of `(relpath, mode, content-bytes)` triples for the whole tree (e.g.
> `git ls-tree -r` over the committed tree, or a directory walk). This is **not**
> a streaming hash feed: the builder MUST collect the whole sequence before
> hashing (peak memory is bounded to "the entry set + one blob at a time"). The
> builder then groups entries by directory prefix and constructs tree nodes
> **bottom-up** (deepest directories first), each `H_tree` becoming a parent
> entry with mode `0x40`. The **root tree node's `H_tree` is the identity.**

> NOTE: Reference pseudocode (a conformant impl MAY differ internally so long as
> the resulting bytes match):
>
> ```
> def dag_identity(entries):                  # entries: list of (relpath, mode, bytes)
>     entries = [e for e in entries           # §1.4: drop any path with a `.git` component
>                if ".git" not in e.relpath.split("/")]
>     root = build_nested_tree(entries)        # group by directory prefix
>     digest, _ = h_tree(root)
>     return "dag-sha256:" + hex(digest)
>
> def h_tree(node):                            # returns (digest, is_empty)
>     items = []
>     for leaf, (mode, content) in node.files:
>         items.append((leaf, blob_mode_byte(mode), sha256(content)))   # H_blob
>     for leaf, sub in node.subdirs:
>         sub_digest, sub_empty = h_tree(sub)
>         if sub_empty:                        # §1.8.5: omit empty subdir
>             continue
>         items.append((leaf, 0x40, sub_digest))                        # H_tree
>     items.sort(key=lambda i: utf8(i.leaf))   # §1.8.3: leaf-name byte order
>     blob = b"".join(u32be(len(utf8(name))) + utf8(name) + bytes([m]) + dig
>                     for (name, m, dig) in items)
>     return sha256(blob), (len(items) == 0)
> ```

### 1.8.5  Empty directories and the empty root

> NORMATIVE: A tree node with **zero entries** contributes **no entry** to its
> parent. This rule is applied recursively: an intermediate directory that
> becomes empty after omitting its empty children is itself omitted. This keeps
> git (which records no empty directories) byte-identical with the tarball/local
> materializers (which may carry empty directories on disk).

> NORMATIVE: The **empty source tree** is the zero-entry root tree node. Its
> identity is the digest of the empty entry concatenation:
>
> ```
> dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
> ```
>
> (= `dag-sha256:` + `sha256(b"")`). Pinned as `fixture-329-dag-oracle-empty-root`.

> NORMATIVE: The zero-entry-tree digest (`sha256` of the empty string) is the
> identity **only** when the whole tree is empty. It is **never** used as a
> `<child-digest-raw>`, because empty subdirectories are omitted from their
> parents (above) before the parent is encoded.

### 1.8.6  `.git/` exclusion

> NORMATIVE: Inherited from §1.4: any path whose components include one named
> exactly `.git` is excluded **before** DAG construction, at any depth.

### 1.8.7  Submodules

> NORMATIVE: A `160000` gitlink occupies a **directory position**. Its source
> bytes are content (§1.7.5): the submodule is fetched and materialized, its
> **root `H_tree`** is computed, and that `H_tree` is spliced in as the
> `<child-digest-raw>` of a tree entry at the gitlink's path, with mode `0x40`
> (a subtree child). The submodule's URL and pinned commit SHA are provenance
> and are recorded separately (§1.7.5) — never inside a node. A submodule whose
> materialized tree is empty is an empty subdirectory and is omitted (§1.8.5).

### 1.8.8  Name-byte ceiling

> NORMATIVE: A leaf name's `<name-bytes>` length MUST NOT exceed **4096 bytes**.
> A longer name raises `ID-NAME-TOO-LONG`. (Common filesystems cap a single path
> component at 255 bytes; the 4096-byte ceiling is a generous, transport-neutral
> bound that also caps the `<uint32-be name-length>` field far below its range,
> foreclosing any length-field abuse.)

### 1.8.9  Soundness

> NOTE: The encoding is injective up to sha256: each tree node's byte string
> decodes uniquely (read 4-byte length, then that many name bytes, then 1 mode
> byte, then 32 digest bytes, repeat), the canonical leaf-name sort makes the
> order deterministic, and the mode-byte domain-separates the blob and tree
> digest spaces. Distinct trees therefore produce distinct encodings (and hence
> distinct digests, absent a sha256 collision). Shared subtrees share an
> `H_tree` — the basis for the subtree-dedup CAS work split out of this RFC.

### 1.8.10  Materializer faithfulness and lossy archives

> NORMATIVE: Identity is transport-independent (§1.1): the git, tarball, and
> local-path materializers MUST all yield the same `(relpath, mode, content)`
> sequence — and therefore the same `dag-sha256:` — for a tree whose source bytes
> and POSIX modes are identical. The executable bit (`0x01`, §1.8.2.1) is part of
> identity, so a materializer MUST set it from the bytes its transport actually
> delivers:
>
> - **git**: from the `ls-tree` mode (`100755` → `0x01`, `100644` → `0x00`,
>   `120000` → `0x80`), per §1.8.2.1.
> - **tarball**: from the tar entry mode — any POSIX execute bit (`mode & 0o111`)
>   → `0x01`, else `0x00`; a tar symlink entry → `0x80` with the `linkname` string
>   as content.
> - **local path**: from the on-disk `st_mode` (`st_mode & 0o111` → `0x01`); a
>   symlink → `0x80` with the `readlink` target string as content.

> NORMATIVE: A **lossy archive format** — one that does not record POSIX execute
> bits (e.g. a `.zip`) — materializes a **genuinely different tree**: every file
> is `0x00` because the `+x` bit was never delivered. Its `dag-sha256:` therefore
> **differs** from the git/`.tar` digest of the same logical source, and this is
> **correct behaviour, not a bug**: identity hashes the bytes-plus-modes that were
> actually delivered, and a delivery that dropped the exec bit is not the same
> tree. A conformant implementation MUST NOT silently re-impute exec bits a lossy
> archive failed to carry, and MUST NOT admit a lossy archive format through an
> exec-bit-faithful materializer path. (The reference `TarballFetcher` rejects
> `.zip` upstream; only the exec-bit-faithful tar family — `.tar` / `.tar.gz` /
> `.tar.bz2` / `.tar.xz` — feeds the tarball materializer.)

---

## 2  Identity string format (multihash encoding)

### 2.1  Canonical form

> NORMATIVE: The identity string produced by `compute_content_hash` and
> stored in lockfiles, CAS paths, and `FetchResult.identity` MUST be:
>
> ```
> dag-sha256:<64-lowercase-hex-chars>
> ```
>
> The `dag-sha256:` prefix is part of the canonical form. An identity string
> without this prefix is invalid. The algorithm name `dag-sha256` names the
> canonical content **Merkle DAG** encoding of §1.8.

> NORMATIVE: The hex digest MUST use lowercase letters `a`–`f`; uppercase
> is rejected.

> NOTE: The reference implementation returns `f"dag-sha256:{digest.hex()}"`
> from `compute_content_hash` (`identity.py`), where the digest is the root
> `H_tree` of the canonical Merkle DAG of §1.8. Lowercase hex is produced.

> NOTE: The interim epoch-1 flat byte stream is **retired** (RFC
> `rfc-identity-conformance-authority`, B-cutover). `dag-sha256:<hex>` now means
> the actual §1.8 canonical content Merkle DAG — the digest is the root `H_tree`,
> not the flat SHA256 of §1.2. §1.2–§1.7 are retained only as the historical
> description of the interim stream and as the source of the cross-cutting content
> rules (`.git` exclusion, symlink-as-target, raw bytes, non-UTF-8 rejection) that
> §1.8 inherits; the executable bit, **excluded** under epoch 1, is **part of**
> epoch-2 identity (§1.8.2). A stale `sha256:` identity is rejected at parse as
> `ID-UNSUPPORTED-ALGORITHM` — re-lock with `milpa fetch`.

### 2.2  Validation grammar

> NORMATIVE: A conformant implementation MUST validate identity strings via
> `parse_identity` semantics:
>
> 1. The input MUST be a string (`ID-NOT-A-STRING` otherwise).
> 2. The string MUST contain a `:` separator (`ID-NO-ALGORITHM-PREFIX`
>    otherwise).
> 3. The algorithm prefix (the part before `:`) MUST be in the supported
>    algorithm set (`ID-UNSUPPORTED-ALGORITHM` otherwise). The only supported
>    algorithm in the A1 epoch is `dag-sha256`. Stale `sha256:` identities
>    (epoch-0) are explicitly NOT accepted; they raise `ID-UNSUPPORTED-ALGORITHM`.
> 4. The digest (the part after `:`) MUST be exactly 64 characters for
>    `dag-sha256` (`ID-WRONG-DIGEST-LENGTH` otherwise).
> 5. The digest MUST consist entirely of `0`–`9` and `a`–`f`
>    (`ID-NON-HEX-DIGEST` otherwise).

> NOTE: The reference implementation is `parse_identity` in `identity.py`,
> lines 65–107. It returns the input string unchanged when valid — the
> canonical form is the input itself.

---

## 3  Content-addressed store (CAS) layout

### 3.1  Directory structure

> NORMATIVE: The CAS root is a directory under which all admitted trees
> are stored. Within the root, entries are addressed by algorithm and
> digest:
>
> ```
> <root>/
>   <algorithm>/           e.g. dag-sha256/
>     <hex-digest>/        e.g. a3f9...c1d2/   (64 hex chars for dag-sha256)
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
> 3. **Idempotency (C-admit-idem)**: if the canonical path
>    `<root>/<algorithm>/<hex-digest>/` already exists, the source tree MUST
>    be removed and the existing canonical path returned immediately. This is a
>    successful no-op — the store already holds the content under this identity.
>    The store MUST NOT be overwritten. A conformant implementation MUST NOT
>    attempt a rename(2) in this case. Implementations SHOULD check for the
>    canonical path's existence before attempting the rename to make CAS hits
>    O(1).
>    Rationale: content-addressing guarantees byte-identity — same identity
>    implies same bytes by construction. No byte comparison is needed on a hit.
>    This is the foundation for cross-project dedup (two projects fetching the
>    same content share one store entry) and makes repeated fetches safe.
> 4. Create the canonical path `<root>/<algorithm>/<hex-digest>/` if it does
>    not exist.
> 5. Move the source tree to the canonical path via `rename(2)`.
>    **TOCTOU race guard**: if the rename fails because the canonical path
>    appeared between step 3 and step 5 (a concurrent admit of the same
>    identity), the source tree MUST be removed and the existing canonical path
>    returned. This is the same no-op as step 3 — content-addressing guarantees
>    the bytes are identical, so no corruption can occur.
> 6. Return the canonical path.

> NORMATIVE: The rename MUST be to a path on the same filesystem as the
> source tree to guarantee atomicity. Implementations using a CAS that
> crosses filesystem boundaries MUST use an alternative atomic mechanism
> (e.g., copy-then-rename within the CAS, then delete the source).

> NOTE: The reference implementation fetches into a scratch directory under
> `<root>/_scratch/` for exactly this reason: the scratch dir and the CAS
> entries share the same filesystem mount, so `src.rename(canonical)`
> (`cas.py`) is a POSIX rename(2) and is atomic. `CAStore.scratch()`
> (Python `cas.py`; Rust `store.rs`) allocates a unique subdir under
> `<root>/_scratch/` and is the sole owner of this transient staging area.

> NOTE: The reference implementation's OSError catch (`cas.py`) handles
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

> NOTE: The Python reference implementation uses `CAStore.scratch()` as a
> context manager (`cas.py`) that runs `shutil.rmtree` in its `except
> BaseException` branch, catching both normal exceptions and
> `KeyboardInterrupt` / `SystemExit`, so all foreground-signal-safe
> termination paths clean up. The Rust implementation cleans up the
> `ScratchDir` path explicitly on both success and failure paths in
> `CasAdmittingFetcher::fetch` (`fetchers.rs`). Only `SIGKILL` (which
> terminates the process immediately, bypassing cleanup handlers) can leave
> orphaned entries.

> NOTE: An automatic startup GC (scan and remove stale `_scratch/` entries
> older than a threshold) is the intended remedy for orphaned entries but is
> NOT implemented in spec v1.0. The GC design — liveness predicate
> (`projects.kdl` watched-project registry), sentinel-before-admit
> concurrency protocol, and the `_scratch/` staleness age T — is settled in
> `docs/rfc-store-gc.md`. A spec amendment adding the `STORE-GC-ENTRY-IN-USE`
> error code and the `milpa store gc` command lands with the implementation
> (tracked in issue #141). No implementation may remove entries from
> `_scratch/` or `dag-sha256/` (or any future algorithm dir) before that amendment is applied.

### 3.5  The `_deps/<name>` symlink convention

> NORMATIVE: After a successful fetch, `_deps/<name>` in the project
> directory MUST be a symlink. Two distinct cases:
>
> - **CAS-admissible deps** (`cas_admissible = True`: git, tarball, oci):
>   `_deps/<name>` MUST be a symlink pointing to the CAS entry for that dep's
>   identity. The symlink target MUST be a **relative** path from the
>   `_deps/<name>` symlink's parent directory to the CAS entry. Absolute
>   symlinks are non-conformant.
>
> - **Non-admissible (editable) deps** (`cas_admissible = False`: local,
>   member): `_deps/<name>` MUST be a symlink pointing **directly to the source
>   directory** (the `local=` path, or the workspace member directory). The
>   target is an **absolute** path to the source tree. There is no CAS entry.
>   The user can edit the source in-place and changes are immediately visible
>   through `_deps/<name>` without a re-fetch.
>
> Implementations MUST NOT copy or move the tree for non-admissible deps.
> The `milpa verify` command distinguishes the two cases by provenance kind.

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

### 4.1  Identity-bearing vs. CAS-admissible — two orthogonal axes (normative SSOT)

milpa has **two distinct per-provenance predicates** that are easily conflated
but are NOT the same. This subsection is the single normative source of truth
for both; every layer that needs either predicate MUST derive it from here, and
MUST select the axis that matches its concern — it MUST NOT use one axis as a
proxy for the other.

- **identity-bearing** — the dep carries a recorded `content_hash` / `identity`
  that is hash-compared during `verify` and frozen reconstruction. Governs
  lockfile `identity` emission and verify dispatch.
- **CAS-admissible** (`cas_admissible`) — the materialized tree is admitted into
  the content-addressed store and `_deps/<name>` points at the CAS entry, rather
  than being a direct symlink to an editable source (see §3.5). Governs CAS
  admission, content-dedup, and the deps-view stale-entry sweep.

> NORMATIVE: The canonical enumeration. The two axes coincide for `git` /
> `tarball` / `oci` and for `local`, but **diverge for `member`**: a workspace
> member is identity-bearing (its content is hashed and drift-detected) yet not
> CAS-admissible (it is symlinked to the editable member directory, never copied
> into the CAS).
>
> | Kind      | identity-bearing? | `cas_admissible`? | Notes                                                           |
> |-----------|-------------------|-------------------|-----------------------------------------------------------------|
> | `git`     | YES               | YES               | Immutable once pinned to commit SHA; admitted to CAS            |
> | `tarball` | YES               | YES               | Immutable; pinned by archive sha256; admitted to CAS           |
> | `oci`     | YES               | YES               | Immutable; pinned by OCI digest; admitted to CAS               |
> | `member`  | YES               | NO                | Workspace member: content hashed + drift-detected, but symlinked to the editable member dir (not copied into CAS) |
> | `local`   | NO                | NO                | Editable external source: no stable identity; liveness-only    |
>
> A named / registry dep resolves to one of the concrete transports above and
> inherits that transport's status on both axes. Any future provenance kind MUST
> declare both predicates explicitly (`cas_admissible` is a fetcher-protocol
> contract — see `spec/plugin-contract.md §4` and `spec/manifest-grammar.md §4.3`);
> the reference default is identity-bearing **and** CAS-admissible
> (immutable-by-default).

### 4.1a  Declared version is not an identity input (normative SSOT)

> NORMATIVE: A dep's **declared version** — the package's own `milpa.kdl`
> `version` field, its `.nimble` `version` field, a git-tag-derived version, or
> an explicit `version=` annotation on the dep declaration (`spec/resolver-
> semantics.md` Axis A: manifest-agnostic declared-version precedence) — is a
> **constraint-satisfaction label**, orthogonal to `content_hash` / `identity`.
> It MUST NOT be read as an input to, mixed into, or otherwise influence the
> content-hash computation of §1. Two provenances that produce the same
> `content_hash` are the same identity regardless of what version label each
> one carries (including differing labels, or one carrying a label the other
> lacks); two provenances with different `content_hash` values are different
> identities even when they happen to carry the identical declared version
> string. This is the same identity ⊥ provenance discipline (§4) extended to
> a third orthogonal fact: identity is content, provenance is transport, and
> declared version is a solver-facing label — none of the three is derivable
> from, or substitutable for, either of the other two.

> NORMATIVE: A dep whose declared version cannot be established from any of
> the sources above (**version-unknown**, `spec/resolver-semantics.md` Axis A
> (c)) is not a degraded or partial identity: its `content_hash` is computed
> and recorded exactly as for any other dep (§1). "Version-unknown" describes
> only the absence of a constraint-satisfaction label — never an absence or
> weakening of identity. See `spec/lockfile-schema.md` §3.2/§3.2a for the
> lockfile-boundary encoding of the version-unknown case.

The downstream consequences, each keyed to the axis it actually depends on:

> NORMATIVE: **(a) Lockfile emission — IDENTITY-BEARING axis.** The `identity`
> field in a `dep` block MUST be emitted if and only if the dep is
> identity-bearing. It is therefore present for `git` / `tarball` / `oci` /
> `member` and absent **only** for `local`. A conformant parser MUST treat a
> present `identity` field on a non-identity-bearing dep (`local`) as an error
> (`LOCK-DEP-IDENTITY-INVALID`).

> NORMATIVE: **(b) Verify dispatch — IDENTITY-BEARING axis.** `milpa verify`
> MUST apply liveness-only checking (no content-hash comparison) for every
> non-identity-bearing dep (`local` only). It MUST apply the four-state
> structural check plus identity hash-compare for every identity-bearing dep
> (`git` / `tarball` / `oci` / `member`). The dispatch criterion is
> identity-bearing status, not a per-kind enumeration in the verify code. See
> `spec/lockfile-schema.md §6.2` for the normative verify procedure.

> NORMATIVE: **(c) CAS admission and content-dedup — CAS-ADMISSIBLE axis.**
> Non-CAS-admissible deps (`local` **and** `member`) MUST NOT be passed to
> `CASStore.admit()` and MUST NOT be included in any content-dedup pass (e.g.,
> alias detection in Phase B). They are editable sources symlinked in place;
> admitting them would silently freeze user edits.

> NORMATIVE: **(d) Deps-view rebuild (stale-entry sweep) — CAS-ADMISSIBLE axis.**
> When rebuilding the `_deps/` symlink view (e.g., `milpa fetch` or
> `milpa clean`), the stale-entry sweep MUST NOT evict symlinks for
> non-CAS-admissible deps (`local` **and** `member`) based on a missing CAS
> entry — their symlinks point directly to the live source tree and are valid
> regardless of CAS state.

### 4.1b  Source-id vs. identity — origin vs. content (normative SSOT)

> NORMATIVE: **Vocabulary discipline.** The bare word "identity" is reserved,
> everywhere in this spec, for `content_hash` (§1). A **source-id**
> (`SourceId` — `rfc-origin-as-identity.md` §3.1/§4.1) is an **origin**: a
> version-independent description of *where a dep comes from* (a registry
> coordinate, a normalized git/tarball URL, an OCI coordinate, a local path,
> or a workspace-member name), used as the PubGrub solver variable
> (`spec/resolver-semantics.md` §6b) and as the lockfile's grouping key
> (`spec/lockfile-schema.md` §3.10). A source-id is never called an
> "identity," and `content_hash` is never called an "origin" — the two
> concepts are deliberately named apart because they answer unrelated
> questions and hold unrelated invariants:
>
> | | `SourceId` (origin) | `content_hash` (identity) |
> |---|---|---|
> | Answers | "where do these bytes come from?" | "are these the bytes that were expected?" |
> | Computed | pre-fetch, from the manifest/index alone | post-fetch, from the materialized tree (§1) |
> | Varies with | the dep's declared source (URL, path, coordinate) | the dep's actual byte content |
> | Ref/tag/digest | excluded — those select a *version* within one origin, never part of the origin itself | irrelevant — identity is computed from bytes on disk, independent of how they were obtained |
> | Two dep declarations can | be genuinely different origins yet still resolve to the identical `content_hash` (byte-identical trees) | be the identical `content_hash` regardless of how many distinct origins produced it |

> NORMATIVE: These two facts compose, never substitute for each other. A
> `SourceId` never participates in the content-hash computation of §1 (no
> origin field is hashed — only tree bytes are), mirroring exactly the
> declared-version boundary §4.1a already draws. Conversely, `content_hash`
> is never used to decide which origin a reference binds to
> (`spec/resolver-semantics.md` §10.0/§10.1) — origin binding is a pre-fetch
> decision, and `content_hash` does not exist until after a tree is fetched.
> The one place the two facts meet is a **post-fetch, proof-based**
> unification: two *distinct* source-ids whose fetched trees hash identically
> MAY be collapsed to one solver variable (`spec/resolver-semantics.md`
> §10.6) — a merge justified by content-identity, never by inspecting or
> guessing at origin equivalence. This is milpa's structural edge over a
> pure name+origin identity model (Cargo): identity can prove two
> differently-sourced dependency declarations are the same tree even though
> their origins remain, correctly, distinct facts.

> NORMATIVE: **`canonical(source_id)` is a stable wire format once shipped.**
> Like `content_hash`'s own algorithm (§1.1.1's epoch discipline), a change to
> a `SourceId` normalization rule post-stabilization (e.g., additionally
> stripping a `www.` host prefix) is a **lockfile-migration event**, not a
> silent fix — it changes what string a fetched dep's solver variable and
> on-disk grouping key canonicalize to. Pre-v1.0 stabilization, normalization
> rules MAY change freely with a one-shot lockfile regen
> (`spec/resolver-semantics.md` §8 migration discipline); this commitment
> applies from spec v1.0 onward, the same way the content-hash epoch
> boundary (§1.1.1) does.

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
| `ID-NAME-TOO-LONG` | an epoch-2 leaf name exceeds the 4096-byte ceiling (§1.8.8) |
| `ID-NON-UTF8-RELPATH` | a source-tree relative path is not valid UTF-8 (§1.3) |
| `ID-NON-UTF8-SYMLINK-TARGET` | a symlink target string is not valid UTF-8 (§1.5) |
| `CAS-IDENTITY-MISMATCH` | `admit()` computed hash ≠ claimed identity |
| `CAS-NOT-IN-STORE` | `link()` called for an identity not in store |
| `CAS-STORE-IO-ERROR` | a CAS store filesystem operation failed with an I/O error |
| `STORE-AMBIGUOUS-PREFIX` | a short content-hash prefix matches more than one stored object |
