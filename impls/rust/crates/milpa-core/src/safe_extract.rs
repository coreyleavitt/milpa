//! Safe tar extraction (RFC §6 S14; `milpa/fetchers/safe_extract.py`).
//!
//! Extract a (decompressed) tar archive into a destination tree, defending
//! against the archive attack classes:
//!   - **zip-slip** (`EXTRACT-ZIP-SLIP`): an entry whose path escapes `dest` via
//!     `..` or an absolute path;
//!   - **symlink-escape** (`EXTRACT-SYMLINK-ESCAPE`): a symlink whose target
//!     resolves outside `dest`;
//!   - **size-limit** (`EXTRACT-SIZE-LIMIT`): per-file / total-bytes / file-count
//!     caps (decompression-bomb defense).
//!
//! `strip_components` drops the first N path components of each entry (like
//! `tar --strip-components=N`); entries with fewer components are skipped. The
//! identity hash is computed by the caller *after* extraction over the stripped
//! tree (strip-before-hash).
//!
//! The USTAR reader is hand-rolled (no `tar` crate dependency — pure + offline,
//! same ethos as the `.nimble` line parser). Gzip/xz decompression is the
//! tarball *fetcher*'s job (S14c): it decompresses, then calls [`extract_tar`].
//! Path-escape checks are **lexical** (the target doesn't exist yet, so
//! `canonicalize` can't be used) — `..` is resolved by popping, then a prefix
//! check against the canonicalized `dest`.
//!
//! [`extract_tar`] reads its archive from a generic `R: Read` (#202,
//! `docs/rfc-native-oci-fetch.md` §3.3) rather than a fully-materialized
//! `&[u8]`: the fetcher call sites (`fetchers::fetch_tarball_with_decomp_cap`,
//! `fetchers::pull_and_extract_oci`) feed a decompressing reader straight off
//! the downloaded scratch file, so the whole (de)compressed archive is never
//! held in memory at once — peak memory is bounded by the largest tar member,
//! not the archive size. The USTAR reader ([`TarEntries`]) pulls one 512-byte
//! header block at a time and materializes only the CURRENT entry's data
//! (pre-checked against a per-entry byte cap before allocating, so a
//! maliciously/corruptly huge declared size can't itself trigger an
//! allocation-DoS); non-data-bearing entries (dirs/symlinks/hardlinks) are
//! skipped via a fixed-size scratch buffer, never allocated at all. Callers
//! that already hold the whole archive as `&[u8]` (e.g.
//! [`tar_materialize_entries`], which needs every entry simultaneously to
//! build the epoch-2 DAG) simply wrap it in a [`std::io::Cursor`] — one reader
//! implementation, not two parallel parsers.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::error::MilpaError;
use crate::fetch::FetchError;

/// Overhead added to `max_total_size` to compute the decompression-bomb cap —
/// one tar header block (512 B) to leave room for tar framing around file data.
///
/// **Single definition** (R2-06): this is the canonical source; `fetchers.rs`
/// imports `crate::safe_extract::DECOMP_CAP_OVERHEAD` so both modules always
/// agree.  The old `const DECOMP_CAP_OVERHEAD: u64 = 512` in `fetchers.rs` was
/// a duplicate of the inline `const OVERHEAD: u64 = 512` previously in
/// `Limits::decomp_cap()` — that inline copy is now removed.
pub(crate) const DECOMP_CAP_OVERHEAD: u64 = 512;

/// Decompression-bomb caps (mirror `safe_extract.py` defaults).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_total_size: u64,
    pub max_file_size: u64,
    pub max_file_count: u64,
}

impl Limits {
    /// Default `max_total_size` (1 GiB) — exposed as a named constant so
    /// `fetchers.rs` can derive `MAX_COMPRESSED_BYTES` without constructing a
    /// `Limits` value at const evaluation time.
    pub const DEFAULT_MAX_TOTAL_SIZE: u64 = 1 << 30; // 1 GiB

    /// R1-12 / R2-06: single source of truth for the decompression-bomb cap formula.
    /// Cap = max_total_size + DECOMP_CAP_OVERHEAD (one tar header block = 512 B).
    /// Both `fetch_tarball` (gzip/bz2/xz/lzma-alone) and `fetch_oci` (gzip) use this.
    /// Mirrors Python's `Limits.decomp_cap` field.
    ///
    /// `DECOMP_CAP_OVERHEAD` is now defined once (above) and re-exported so
    /// `fetchers.rs` can reference it directly — eliminating the former duplicate.
    pub fn decomp_cap(&self) -> u64 {
        self.max_total_size + DECOMP_CAP_OVERHEAD
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_total_size: Self::DEFAULT_MAX_TOTAL_SIZE,
            max_file_size: 1 << 28,  // 256 MiB
            max_file_count: 100_000,
        }
    }
}

/// What an extraction produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionResult {
    pub file_count: u64,
    pub total_bytes: u64,
}

fn extract_err(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Fetch(FetchError::Extract(code, message.into()))
}

/// Marker wrapped in an `io::Error` by a streaming decompressor's cap-
/// enforcing `Read` wrapper (`fetchers::CappedReader`, the SA-1 decompression-
/// bomb guard's pull-based sibling to `fetchers::LimitedWriter`) once the
/// decompression-bomb cap is exceeded mid-stream. `TarEntries`'s read helpers
/// (below) recognize this via [`is_decomp_cap_exceeded`] and raise
/// `EXTRACT-SIZE-LIMIT` — a deliberate cap trip is "the archive is bigger than
/// policy allows", not "the archive is corrupt" (`FETCH-EXTRACT-FAILED`), and
/// the two must stay distinguishable even though decompression and extraction
/// are now interleaved in a single streaming pass (#202) instead of two
/// separate phases with their own independent error returns.
#[derive(Debug)]
pub(crate) struct DecompCapExceeded;

impl std::fmt::Display for DecompCapExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decompression cap exceeded")
    }
}

impl std::error::Error for DecompCapExceeded {}

/// `true` if `e` was raised by a `CappedReader` hitting its decompression-bomb
/// cap (as opposed to a genuine I/O failure or archive corruption).
fn is_decomp_cap_exceeded(e: &std::io::Error) -> bool {
    e.get_ref()
        .map(|inner| inner.is::<DecompCapExceeded>())
        .unwrap_or(false)
}

/// Classify a genuine stream-read error into the two-way split shared by
/// every raw `Read` call site in this module: a `CappedReader`
/// decompression-bomb trip is `EXTRACT-SIZE-LIMIT` (a deliberate policy cap,
/// not corruption); anything else is a real I/O failure → `FETCH-EXTRACT-
/// FAILED`. `read_entry_data`'s `read_exact` additionally distinguishes a
/// true short-read (`UnexpectedEof`, a declared-size entry running past the
/// end of the archive) with its own message — that one extra case lives at
/// its call site, but its final "genuine I/O error" arm, plus `read_header`'s
/// and `skip_exact`'s, and the post-loop trailing-data drain (below), all
/// share this single two-way classification rather than repeating the same
/// `if is_decomp_cap_exceeded(&e) { .. } else { .. }` match a fourth/fifth
/// time.
fn classify_stream_read_error(e: std::io::Error, context: impl std::fmt::Display) -> MilpaError {
    if is_decomp_cap_exceeded(&e) {
        extract_err(
            "EXTRACT-SIZE-LIMIT",
            "decompressed archive exceeds cap; possible decompression bomb",
        )
    } else {
        extract_err("FETCH-EXTRACT-FAILED", format!("{context}: {e}"))
    }
}

/// Drain `reader` to EOF, discarding bytes.
///
/// Security fix (decompression-bomb cap bypass via trailing data after the
/// tar terminator, `docs/rfc-native-oci-fetch.md` §3.3): `TarEntries::next()`
/// returns `None` the instant `read_header` sees a clean end-of-archive —
/// either the all-zero marker block or a short final read — and nothing
/// afterward reads any further from the underlying stream. When that stream
/// is a `CappedReader`-wrapped decompressor (`fetchers::open_streaming_tar` /
/// `pull_and_extract_oci`), any compressed data appended AFTER a well-formed
/// tar is therefore never read, hence never decompressed, hence never
/// counted by the decompression-bomb cap — silently narrowing the cap's
/// guarantee to "the bytes inside tar entries" instead of "the whole
/// decompressed stream".
///
/// Called by `extract_tar` immediately after its entry-reading loop finishes
/// normally, so every caller (streaming OCI/tarball pulls AND the buffered
/// `Cursor`-backed callers, for which this is simply reading the rest of an
/// already-in-memory buffer) gets the same "cap covers everything" guarantee
/// uniformly, in the one place the archive is read. Reads through a
/// fixed-size scratch buffer — never an allocation proportional to the
/// trailing data's size — so a legitimate archive's ordinary end-of-archive
/// padding (a few hundred bytes) drains cheaply, while a hostile trailer
/// decompresses (and is counted) only up to the cap before `CappedReader`
/// trips it.
fn drain_to_eof<R: Read>(mut reader: R) -> Result<(), MilpaError> {
    let mut scratch = [0u8; 8192];
    loop {
        match reader.read(&mut scratch) {
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            Err(e) => return Err(classify_stream_read_error(e, "draining trailing archive data")),
        }
    }
}

/// Extract a (decompressed) tar stream `tar` into `dest`. See the module docs
/// for the guards. Partial extraction state on error is the caller's to clean
/// up (typically: remove `dest`).
///
/// `tar` is a generic `R: Read` (#202) rather than `&[u8]` — callers that
/// already have the whole archive buffered can pass `&buf[..]` (or wrap it in
/// [`std::io::Cursor`]); streaming callers feed a decompressing reader
/// directly so the archive is never fully materialized in memory (see the
/// module docs).
pub fn extract_tar<R: Read>(
    tar: R,
    dest: &Path,
    strip_components: u32,
    limits: Limits,
) -> Result<ExtractionResult, MilpaError> {
    std::fs::create_dir_all(dest).map_err(|e| {
        extract_err(
            "EXTRACT-IO-ERROR",
            format!("cannot create dest {}: {e}", dest.display()),
        )
    })?;
    let dest_root = std::fs::canonicalize(dest).unwrap_or_else(|_| normalize_lexical(dest));

    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    let strip = strip_components as usize;

    // H2 — two-pass extraction (spec/plugin-contract.md §2.2).
    // Hardlink entries carry an archive-absolute linkname that may
    // forward-reference a target not yet written (tar ordering is arbitrary).
    // All regular files, dirs, and symlinks are written in pass 1; hardlinks
    // are resolved in pass 2 when every target is guaranteed to exist.
    // Collect (name, linkname, target_path) for pass 2.
    struct PendingHardlink {
        name: String,
        linkname: String,
        target: PathBuf,
    }
    let mut hardlinks: Vec<PendingHardlink> = Vec::new();

    // Helper: strip_components applied via POSIX '/' split (not host separator).
    let strip_name = |raw: &str| -> Option<String> {
        let parts: Vec<&str> = raw
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        if parts.len() <= strip {
            None
        } else {
            Some(parts[strip..].join("/"))
        }
    };

    // Pass 1: dirs, regular files, symlinks — everything except hardlinks.
    // Bound to a local so the underlying reader (`tar_entries.src`) is still
    // reachable after the loop, to drain any trailing data past the tar
    // terminator (see `drain_to_eof`'s doc comment) — `&mut tar_entries`
    // borrows for iteration instead of `TarEntries::new(..)` being consumed
    // as a bare temporary that drops (taking the reader with it) the moment
    // the loop ends.
    let mut tar_entries = TarEntries::new(tar, limits.max_file_size);
    for entry in &mut tar_entries {
        let entry = entry?;

        let stripped = match strip_name(&entry.name) {
            Some(s) => s,
            None => continue,
        };

        // zip-slip: the entry's lexical target must stay under dest_root.
        let target = normalize_lexical(&dest_root.join(&stripped));
        if !target.starts_with(&dest_root) {
            return Err(extract_err(
                "EXTRACT-ZIP-SLIP",
                format!(
                    "archive entry {:?} resolves outside destination: {} not under {}",
                    entry.name,
                    target.display(),
                    dest_root.display()
                ),
            ));
        }

        match entry.kind {
            EntryKind::HardLink => {
                // Defer to pass 2 for forward-reference safety.
                hardlinks.push(PendingHardlink {
                    name: entry.name.clone(),
                    linkname: entry.linkname.clone(),
                    target,
                });
            }
            EntryKind::Symlink => {
                // Symlink geometry: target is relative to the link's parent dir.
                let parent = target.parent().unwrap_or(&dest_root);
                let link_target = normalize_lexical(&parent.join(&entry.linkname));
                if !link_target.starts_with(&dest_root) {
                    return Err(extract_err(
                        "EXTRACT-SYMLINK-ESCAPE",
                        format!(
                            "symlink {:?} → {:?} resolves outside destination: {} not under {}",
                            entry.name,
                            entry.linkname,
                            link_target.display(),
                            dest_root.display()
                        ),
                    ));
                }
                if let Some(p) = target.parent() {
                    std::fs::create_dir_all(p).map_err(io_err(&entry.name))?;
                }
                let _ = std::fs::remove_file(&target);
                std::os::unix::fs::symlink(&entry.linkname, &target)
                    .map_err(io_err(&entry.name))?;
                file_count += 1;
                if file_count > limits.max_file_count {
                    return Err(extract_err(
                        "EXTRACT-SIZE-LIMIT",
                        format!(
                            "archive file count exceeds cap ({file_count} > {})",
                            limits.max_file_count
                        ),
                    ));
                }
            }
            EntryKind::Dir => {
                std::fs::create_dir_all(&target).map_err(io_err(&entry.name))?;
            }
            EntryKind::File => {
                if entry.size > limits.max_file_size {
                    return Err(extract_err(
                        "EXTRACT-SIZE-LIMIT",
                        format!(
                            "entry {:?} exceeds per-file cap ({} > {})",
                            entry.name, entry.size, limits.max_file_size
                        ),
                    ));
                }
                total_bytes += entry.size;
                if total_bytes > limits.max_total_size {
                    return Err(extract_err(
                        "EXTRACT-SIZE-LIMIT",
                        format!(
                            "archive total size exceeds cap ({total_bytes} > {})",
                            limits.max_total_size
                        ),
                    ));
                }
                file_count += 1;
                if file_count > limits.max_file_count {
                    return Err(extract_err(
                        "EXTRACT-SIZE-LIMIT",
                        format!(
                            "archive file count exceeds cap ({file_count} > {})",
                            limits.max_file_count
                        ),
                    ));
                }
                if let Some(p) = target.parent() {
                    std::fs::create_dir_all(p).map_err(io_err(&entry.name))?;
                }
                std::fs::write(&target, entry.data).map_err(io_err(&entry.name))?;
            }
            EntryKind::Other => {} // char/block/fifo — never legitimate in source.
        }
    }

    // Security fix (decompression-bomb cap bypass via trailing data after
    // the tar terminator): `TarEntries::next()` above stopped reading `tar`
    // the instant it saw the end-of-archive marker. Drain whatever remains
    // so a `CappedReader`-wrapped decompressor (the streaming OCI/tarball
    // callers) decompresses — and counts against the cap — the ENTIRE
    // stream, not just the bytes inside tar entries. See `drain_to_eof`'s
    // doc comment. For buffered `Cursor`/`&[u8]` callers (no cap, e.g. the
    // unit tests and `tar_materialize_entries`'s own independent reader) this
    // is just reading the remaining in-memory bytes to EOF — cheap and
    // side-effect-free.
    drain_to_eof(tar_entries.src)?;

    // Pass 2: hardlinks — copy bytes from now-guaranteed-existing targets.
    // (spec/plugin-contract.md §2.2: copy-bytes materialisation; linkname is
    //  archive-absolute, strip_components applied via POSIX '/' split,
    //  resolved against dest_root — NOT relative to the link's parent dir.)
    for hl in hardlinks {
        // Apply strip_components to the linkname (POSIX '/' split).
        let stripped_link = match strip_name(&hl.linkname) {
            Some(s) => s,
            None => {
                // Linkname stripped away entirely → treat as escape.
                return Err(extract_err(
                    "EXTRACT-ZIP-SLIP",
                    format!(
                        "hardlink {:?} → {:?}: linkname has fewer than {} component(s); cannot strip",
                        hl.name, hl.linkname, strip + 1
                    ),
                ));
            }
        };
        // Resolve against dest_root (hardlink geometry).
        let resolved_link = normalize_lexical(&dest_root.join(&stripped_link));
        if !resolved_link.starts_with(&dest_root) {
            return Err(extract_err(
                "EXTRACT-ZIP-SLIP",
                format!(
                    "hardlink {:?} → {:?} resolves outside destination: {} not under {}",
                    hl.name,
                    hl.linkname,
                    resolved_link.display(),
                    dest_root.display()
                ),
            ));
        }
        // Copy the target's bytes.
        let source_bytes = std::fs::read(&resolved_link).map_err(|e| {
            extract_err(
                "EXTRACT-IO-ERROR",
                format!(
                    "hardlink {:?} → {:?}: target {} cannot be read: {e}",
                    hl.name,
                    hl.linkname,
                    resolved_link.display()
                ),
            )
        })?;
        // Size caps: treat the copy as if it were a regular file.
        let copy_size = source_bytes.len() as u64;
        if copy_size > limits.max_file_size {
            return Err(extract_err(
                "EXTRACT-SIZE-LIMIT",
                format!(
                    "hardlink {:?} target exceeds per-file cap ({copy_size} > {})",
                    hl.name, limits.max_file_size
                ),
            ));
        }
        total_bytes += copy_size;
        if total_bytes > limits.max_total_size {
            return Err(extract_err(
                "EXTRACT-SIZE-LIMIT",
                format!(
                    "archive total size exceeds cap ({total_bytes} > {})",
                    limits.max_total_size
                ),
            ));
        }
        file_count += 1;
        if file_count > limits.max_file_count {
            return Err(extract_err(
                "EXTRACT-SIZE-LIMIT",
                format!(
                    "archive file count exceeds cap ({file_count} > {})",
                    limits.max_file_count
                ),
            ));
        }
        if let Some(p) = hl.target.parent() {
            std::fs::create_dir_all(p).map_err(io_err(&hl.name))?;
        }
        std::fs::write(&hl.target, &source_bytes).map_err(io_err(&hl.name))?;
    }

    Ok(ExtractionResult {
        file_count,
        total_bytes,
    })
}

/// Map a genuine I/O error during extraction (write/mkdir/symlink) to
/// `EXTRACT-IO-ERROR`.  This is distinct from `EXTRACT-ZIP-SLIP` (which is
/// reserved for security-escape failures) — callers that have already passed
/// the containment / path-escape checks use this helper.
fn io_err(name: &str) -> impl Fn(std::io::Error) -> MilpaError + '_ {
    move |e| extract_err("EXTRACT-IO-ERROR", format!("writing {name:?}: {e}"))
}

/// Lexically normalize a path: resolve `.` (drop) and `..` (pop the previous
/// `Normal` component, never above the root). No filesystem access.
///
/// `pub(crate)` so `fetchers.rs`'s `materialize_git_tree` can reuse this for
/// the per-symlink containment check (plugin-contract.md §2.3.3) without
/// reimplementing lexical normalization. Single source of truth.
pub(crate) fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// USTAR reader (POSIX prefix + GNU LongLink + PAX path support)
// ---------------------------------------------------------------------------
//
// SA-2 fix: the original reader read entry names from bytes[0..100] only,
// ignoring the POSIX `prefix` field (bytes[345..500]) and GNU @LongLink
// entries (typeflag b'L' / b'K') and PAX extended headers (b'x' / b'X').
// Archives with path components > 100 chars (common in GitHub tarballs)
// produced wrong or truncated paths, causing cross-impl identity divergence
// vs Python's stdlib tarfile which handles all these formats.
//
// Fix: implement all four long-path mechanisms in priority order:
//   1. PAX extended headers (typeflag x/X) — highest priority, supersede
//      all other name sources.
//   2. GNU @LongLink (typeflag L/K) — next entry data = full name/linkname.
//   3. POSIX prefix field (bytes 345..500) — concatenate prefix + "/" + name.
//   4. Plain USTAR name (bytes 0..100) — fallback.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    File,
    Dir,
    Symlink,
    HardLink,
    Other,
}

struct TarEntry {
    name: String,
    linkname: String,
    size: u64,
    kind: EntryKind,
    /// POSIX mode bits (header bytes 100..108, octal). Only the execute bits
    /// (`& 0o111`) are load-bearing for epoch-2 identity (§1.8.2.1).
    mode: u32,
    /// Populated for `File` entries and the GNU-LongLink/PAX control types
    /// (`L`/`K`/`x`/`X`, whose payload is a filename, consumed internally by
    /// `TarEntries` and never surfaced as a real entry); empty for
    /// `Dir`/`Symlink`/`HardLink`/`Other`, whose content (if any — normally
    /// `size == 0`) is skipped rather than buffered (#202).
    data: Vec<u8>,
}

/// Iterate the entries of an uncompressed tar stream, reading from a generic
/// `R: Read` one 512-byte header block at a time (#202 — no longer requires
/// the whole archive materialized as `&[u8]`; see the module docs). Yields a
/// coded `EXTRACT-*` error on a truncated/garbled header.
struct TarEntries<R: Read> {
    src: R,
    /// Per-entry byte cap enforced BEFORE allocating a buffer for an entry's
    /// data (`read_entry_data`) — guards against a maliciously/corruptly huge
    /// declared `size` field triggering an allocation-DoS via
    /// `Vec::with_capacity`/`vec![0u8; n]` before the read even starts.
    /// `extract_tar` passes `limits.max_file_size` (a single entry can never
    /// legitimately exceed the whole-archive per-file cap);
    /// `tar_materialize_entries` passes the length of its already-in-memory
    /// input buffer (a single entry can never legitimately exceed the buffer
    /// it's sliced from).
    max_entry_bytes: u64,
    /// Pending GNU LongLink name override (next real entry uses this as name).
    pending_name: Option<String>,
    /// Pending GNU LongLink linkname override.
    pending_linkname: Option<String>,
    /// Pending PAX path override (from `path` key in extended header).
    pending_pax_name: Option<String>,
    /// Pending PAX linkpath override (from `linkpath` key in extended header).
    pending_pax_linkname: Option<String>,
}

impl<R: Read> TarEntries<R> {
    fn new(src: R, max_entry_bytes: u64) -> Self {
        TarEntries {
            src,
            max_entry_bytes,
            pending_name: None,
            pending_linkname: None,
            pending_pax_name: None,
            pending_pax_linkname: None,
        }
    }

    /// Read the next 512-byte header block. `Ok(Some(_))` on a full block
    /// that isn't the all-zero end-of-archive marker; `Ok(None)` on a clean
    /// end — EITHER an all-zero block OR fewer than 512 bytes available
    /// before EOF (a truncated trailer with no proper end marker), matching
    /// the original slice-based reader's lenient "insufficient bytes remain"
    /// semantics: real-world tar writers vary on trailer padding, so a short
    /// final read is treated as "no more entries", not an error.
    fn read_header(&mut self) -> Result<Option<[u8; 512]>, MilpaError> {
        let mut header = [0u8; 512];
        let mut filled = 0usize;
        while filled < 512 {
            match self.src.read(&mut header[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => return Err(classify_stream_read_error(e, "reading tar header")),
            }
        }
        if filled < 512 {
            return Ok(None);
        }
        if header.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        Ok(Some(header))
    }

    /// Read exactly `n` bytes of an entry's data into an owned buffer,
    /// pre-checking `n` against `max_entry_bytes` BEFORE allocating (see the
    /// field doc on `max_entry_bytes`). `raw_name` is the raw USTAR name
    /// field, used only for error messages (matching the original reader's
    /// convention of naming the entry from the not-yet-long-path-resolved
    /// header field at this point in parsing).
    fn read_entry_data(&mut self, n: u64, raw_name: &str) -> Result<Vec<u8>, MilpaError> {
        if n > self.max_entry_bytes {
            return Err(extract_err(
                "EXTRACT-SIZE-LIMIT",
                format!(
                    "tar entry {raw_name:?} declared size ({n} bytes) exceeds the per-entry \
                     cap ({} bytes); rejected before buffering",
                    self.max_entry_bytes
                ),
            ));
        }
        // R1-19: checked convert so a 32-bit target (or an `n` that slipped
        // past the cap check above because `max_entry_bytes` itself is huge)
        // does not silently truncate.
        let n_usize: usize = match n.try_into() {
            Ok(v) => v,
            Err(_) => {
                return Err(extract_err(
                    "EXTRACT-SIZE-LIMIT",
                    format!(
                        "tar entry {raw_name:?} size {n} overflows platform usize \
                         (archive is malformed or targets a larger address space)"
                    ),
                ));
            }
        };
        let mut buf = vec![0u8; n_usize];
        self.src.read_exact(&mut buf).map_err(|e| {
            if !is_decomp_cap_exceeded(&e) && e.kind() == std::io::ErrorKind::UnexpectedEof {
                // `read_exact` reports a true short-read (the underlying
                // reader hit clean EOF before filling the buffer) as
                // `UnexpectedEof` — matches `skip_exact`'s `Ok(0)` case: the
                // archive is simply truncated, not corrupt mid-stream. This
                // is the one case `classify_stream_read_error`'s generic
                // two-way split doesn't cover, so it stays inline here.
                extract_err(
                    "EXTRACT-SIZE-LIMIT",
                    format!("tar entry {raw_name:?} data ({n} bytes) runs past end of archive: {e}"),
                )
            } else {
                classify_stream_read_error(e, format!("reading tar entry {raw_name:?} data ({n} bytes)"))
            }
        })?;
        Ok(buf)
    }

    /// Discard `n` bytes from the stream without materializing them — used
    /// for the tar padding after every entry, and for the full data segment
    /// of non-data-bearing kinds (Dir/Symlink/HardLink/Other), whose content
    /// (if any) the extractor never reads. Memory-safe regardless of `n`'s
    /// magnitude: a fixed-size scratch buffer, never an allocation
    /// proportional to `n`.
    fn skip_exact(&mut self, mut n: u64, raw_name: &str) -> Result<(), MilpaError> {
        let mut scratch = [0u8; 8192];
        while n > 0 {
            let chunk = if n >= scratch.len() as u64 { scratch.len() } else { n as usize };
            match self.src.read(&mut scratch[..chunk]) {
                Ok(0) => {
                    return Err(extract_err(
                        "EXTRACT-SIZE-LIMIT",
                        format!("tar entry {raw_name:?} data runs past end of archive"),
                    ));
                }
                Ok(read) => n -= read as u64,
                Err(e) => {
                    return Err(classify_stream_read_error(
                        e,
                        format!("skipping tar entry {raw_name:?} data"),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Validate the USTAR header checksum (bytes 148-155).
///
/// The checksum is the unsigned sum of all 512 header bytes with bytes 148-155
/// treated as 8 ASCII spaces (0x20).  POSIX also allows the signed-byte variant
/// (subtract 256 for each byte > 127) — both are accepted here, as both are in
/// the wild (GNU tar writes unsigned; some older tools write signed).
///
/// Returns `true` if the stored checksum matches either unsigned or signed sum,
/// `false` on mismatch.
fn header_checksum_valid(header: &[u8]) -> bool {
    debug_assert_eq!(header.len(), 512);

    // Parse the stored checksum from bytes 148-155 (octal, NUL/space-padded).
    let stored = match octal(&header[148..156]) {
        Some(v) => v,
        None => return false, // unparseable field → reject
    };

    // Compute unsigned sum (bytes 148-155 treated as 0x20).
    let unsigned_sum: u64 = header.iter().enumerate().map(|(i, &b)| {
        if i >= 148 && i < 156 { b' ' as u64 } else { b as u64 }
    }).sum();

    if stored == unsigned_sum {
        return true;
    }

    // Compute signed-byte variant: same but each byte is treated as i8, then
    // summed as i64 (with the checksum field still as 8 spaces each = +32).
    let signed_sum: i64 = header.iter().enumerate().map(|(i, &b)| {
        if i >= 148 && i < 156 { b' ' as i64 } else { b as i8 as i64 }
    }).sum();

    stored == signed_sum.unsigned_abs()
}

impl<R: Read> Iterator for TarEntries<R> {
    type Item = Result<TarEntry, MilpaError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let header = match self.read_header() {
                Ok(Some(h)) => h,
                Ok(None) => return None,
                Err(e) => return Some(Err(e)),
            };

            // R6: validate USTAR header checksum BEFORE trusting any other field.
            // A corrupt-but-structurally-plausible header with a wrong checksum
            // must be rejected here rather than interpreted as file data and written
            // to disk.  Python's stdlib tarfile validates the checksum and raises
            // TarError → FETCH-EXTRACT-FAILED; this makes Rust match that behavior.
            if !header_checksum_valid(&header) {
                let name = cstr(&header[0..100]).unwrap_or_default();
                return Some(Err(extract_err(
                    "FETCH-EXTRACT-FAILED",
                    format!(
                        "tar header for entry {name:?} has an invalid checksum; \
                         archive may be corrupt"
                    ),
                )));
            }

            let size = match octal(&header[124..136]) {
                Some(s) => s,
                None => {
                    let name = cstr(&header[0..100]).unwrap_or_default();
                    return Some(Err(extract_err(
                        "EXTRACT-SIZE-LIMIT",
                        format!("tar entry {name:?} has an unparseable size field"),
                    )));
                }
            };
            let typeflag = header[156];
            let raw_name = cstr(&header[0..100]).unwrap_or_default();

            // Padding to the next 512-byte boundary, per POSIX tar framing.
            let padded = size.div_ceil(512) * 512;
            let padding = padded - size;

            // --- GNU @LongLink (typeflag b'L' = long name, b'K' = long linkname) ---
            // The entry DATA is the NUL-terminated long name/linkname string.
            // Store it and loop to read the following header entry which is the
            // actual content entry (its own name field may be truncated; we override).
            if typeflag == b'L' {
                let data = match self.read_entry_data(size, &raw_name) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                if let Err(e) = self.skip_exact(padding, &raw_name) {
                    return Some(Err(e));
                }
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                if let Ok(s) = std::str::from_utf8(&data[..end]) {
                    self.pending_name = Some(s.to_string());
                }
                continue; // skip — consume the real next entry
            }
            if typeflag == b'K' {
                let data = match self.read_entry_data(size, &raw_name) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                if let Err(e) = self.skip_exact(padding, &raw_name) {
                    return Some(Err(e));
                }
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                if let Ok(s) = std::str::from_utf8(&data[..end]) {
                    self.pending_linkname = Some(s.to_string());
                }
                continue;
            }

            // --- PAX extended headers (typeflag b'x' local, b'X' global) ---
            // Format: NUL-terminated records of "<len> <key>=<value>\n".
            // We extract `path` and `linkpath` keys.
            if typeflag == b'x' || typeflag == b'X' {
                let data = match self.read_entry_data(size, &raw_name) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                if let Err(e) = self.skip_exact(padding, &raw_name) {
                    return Some(Err(e));
                }
                parse_pax_headers(&data, &mut self.pending_pax_name, &mut self.pending_pax_linkname);
                continue;
            }

            // --- Resolve the entry name ---
            // Priority: PAX path > GNU LongLink > POSIX prefix + USTAR name > USTAR name alone.
            let name = if let Some(pax_name) = self.pending_pax_name.take() {
                self.pending_name = None; // PAX supersedes GNU LongLink
                pax_name
            } else if let Some(gnu_name) = self.pending_name.take() {
                gnu_name
            } else {
                // POSIX prefix field: bytes 345..500. If non-empty, prepend "prefix/" to name.
                let ustar_name = match cstr(&header[0..100]) {
                    Some(n) if !n.is_empty() => n,
                    _ => {
                        return Some(Err(extract_err(
                            "EXTRACT-ZIP-SLIP",
                            "tar header with empty/invalid name",
                        )));
                    }
                };
                let prefix = cstr(&header[345..500]).unwrap_or_default();
                if prefix.is_empty() {
                    ustar_name
                } else {
                    format!("{}/{}", prefix, ustar_name)
                }
            };

            // --- Resolve the linkname ---
            let linkname = if let Some(pax_link) = self.pending_pax_linkname.take() {
                self.pending_linkname = None; // PAX supersedes
                pax_link
            } else if let Some(gnu_link) = self.pending_linkname.take() {
                gnu_link
            } else {
                cstr(&header[157..257]).unwrap_or_default()
            };

            let kind = match typeflag {
                b'0' | 0 => EntryKind::File,
                b'5' => EntryKind::Dir,
                b'2' => EntryKind::Symlink,
                b'1' => EntryKind::HardLink,
                _ => EntryKind::Other,
            };

            // POSIX mode bits (bytes 100..108, octal). Used only for the epoch-2
            // execute bit (§1.8.2.1); an unparseable field defaults to 0 (regular).
            let mode = octal(&header[100..108]).unwrap_or(0) as u32;

            // Only File entries' content is needed downstream (written to disk
            // by `extract_tar`, or hashed into `MaterializedEntry` by
            // `tar_materialize_entries`) — buffer it (cap-checked). Every other
            // kind's data segment (normally `size == 0`; symlink/hardlink
            // targets live in the header `linkname` field, not here) is
            // discarded via a fixed-size scratch buffer, never allocated
            // proportional to `size` (#202).
            let data = if kind == EntryKind::File {
                match self.read_entry_data(size, &raw_name) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                }
            } else {
                if let Err(e) = self.skip_exact(size, &raw_name) {
                    return Some(Err(e));
                }
                Vec::new()
            };
            if let Err(e) = self.skip_exact(padding, &raw_name) {
                return Some(Err(e));
            }

            return Some(Ok(TarEntry {
                name,
                linkname,
                size,
                kind,
                mode,
                data,
            }));
        }
    }
}

/// Parse PAX extended header records and extract `path` and `linkpath` overrides.
///
/// PAX record format: `"<decimal-length> <key>=<value>\n"` where `length` is the
/// total byte length of the record including the length field, space, key, `=`,
/// value, and `\n`.
fn parse_pax_headers(
    data: &[u8],
    out_name: &mut Option<String>,
    out_linkname: &mut Option<String>,
) {
    let mut pos = 0;
    while pos < data.len() {
        // Find the space that separates the length from the key=value.
        let space = match data[pos..].iter().position(|&b| b == b' ') {
            Some(i) => pos + i,
            None => break,
        };
        let len_str = match std::str::from_utf8(&data[pos..space]) {
            Ok(s) => s,
            Err(_) => break,
        };
        let record_len: usize = match len_str.parse() {
            Ok(n) => n,
            Err(_) => break,
        };
        if record_len == 0 || pos + record_len > data.len() {
            break;
        }
        // The record is data[pos .. pos+record_len]; strip the trailing '\n'.
        let record = &data[pos..pos + record_len];
        // record = "<len> <key>=<value>\n"
        // `space` is an ABSOLUTE offset into data[]; convert to relative so it
        // indexes correctly into `record` (which starts at `pos`, not 0).
        let kv_start = (space - pos) + 1;
        let kv_end = if record.last() == Some(&b'\n') {
            record.len() - 1
        } else {
            record.len()
        };
        if kv_start >= kv_end {
            pos += record_len;
            continue;
        }
        let kv = &record[kv_start..kv_end];
        if let Some(eq) = kv.iter().position(|&b| b == b'=') {
            let key = &kv[..eq];
            let val = &kv[eq + 1..];
            if key == b"path" {
                if let Ok(s) = std::str::from_utf8(val) {
                    *out_name = Some(s.to_string());
                }
            } else if key == b"linkpath" {
                if let Ok(s) = std::str::from_utf8(val) {
                    *out_linkname = Some(s.to_string());
                }
            }
        }
        pos += record_len;
    }
}

/// A NUL-terminated (or full-field) ASCII string from a header field.
fn cstr(field: &[u8]) -> Option<String> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).ok().map(str::to_string)
}

/// Parse a tar octal numeric field (space/NUL-padded).
fn octal(field: &[u8]) -> Option<u64> {
    let s: String = field
        .iter()
        .map(|&b| b as char)
        .filter(|c| !matches!(c, ' ' | '\0'))
        .collect();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(&s, 8).ok()
}

/// Materialize a (decompressed) tar byte stream into the epoch-2 seam sequence
/// (`Vec<MaterializedEntry>`, spec §1.8.4) — the tar-format half of the tarball
/// materialize seam (RFC slice B2-tarball).
///
/// This reuses the hand-rolled [`TarEntries`] USTAR reader (the tar-format SSOT
/// shared with [`extract_tar`]) so the same long-path / PAX / GNU-LongLink
/// handling applies. Decompression is the caller's concern (see
/// `fetchers::enumerate_tarball_entries`), exactly as for [`extract_tar`].
///
/// Mode mapping (spec §1.8.2.1): a regular file with any POSIX execute bit
/// (`mode & 0o111`) → `0x01`, else `0x00`; a symlink entry → `0x80` with the
/// `linkname` string bytes as content; a hardlink → resolved to the target's
/// content bytes (copy-bytes, mirroring `extract_tar` pass 2) with the link's own
/// mode. Directories and device/FIFO entries contribute no leaf (subtrees are
/// synthesised by the DAG builder).
pub fn tar_materialize_entries(
    tar: &[u8],
    strip_components: u32,
) -> Result<Vec<crate::dag_identity::MaterializedEntry>, MilpaError> {
    use std::collections::HashMap;

    use crate::dag_identity::{
        MaterializedEntry, MODE_EXECUTABLE, MODE_REGULAR, MODE_SYMLINK,
    };

    let strip = strip_components as usize;
    let strip_name = |raw: &str| -> Option<String> {
        let parts: Vec<&str> = raw
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        if parts.len() <= strip {
            None
        } else {
            Some(parts[strip..].join("/"))
        }
    };
    let mode_byte = |mode: u32| if mode & 0o111 != 0 { MODE_EXECUTABLE } else { MODE_REGULAR };

    let mut entries: Vec<MaterializedEntry> = Vec::new();
    let mut file_index: HashMap<String, usize> = HashMap::new();
    // (relpath, stripped_linkname, mode_byte) — resolved in pass 2 once all files
    // are collected (hardlink may forward-reference its target).
    let mut hardlinks: Vec<(String, String, u8)> = Vec::new();

    // The whole archive is already in memory (`tar: &[u8]`, every entry is
    // needed simultaneously to build the DAG) — wrap it in a `Cursor` so
    // `TarEntries` (generic over `Read`, #202) is the ONE USTAR-parsing
    // implementation shared with the streaming `extract_tar`, not a second
    // parallel parser. `tar.len()` is a correct, already-available per-entry
    // cap: no single entry can legitimately exceed the buffer it's sliced
    // from, so this never rejects a previously-valid archive — it only stops
    // a corrupt/malicious declared size from driving an allocation before the
    // (cheap, bounded) read itself would fail anyway.
    for entry in TarEntries::new(std::io::Cursor::new(tar), tar.len() as u64) {
        let entry = entry?;
        let relpath = match strip_name(&entry.name) {
            Some(s) => s,
            None => continue,
        };
        match entry.kind {
            EntryKind::Dir | EntryKind::Other => {}
            EntryKind::Symlink => {
                entries.push(MaterializedEntry {
                    relpath,
                    mode_byte: MODE_SYMLINK,
                    content: entry.linkname.into_bytes(),
                });
            }
            EntryKind::File => {
                file_index.insert(relpath.clone(), entries.len());
                entries.push(MaterializedEntry {
                    relpath,
                    mode_byte: mode_byte(entry.mode),
                    content: entry.data,
                });
            }
            EntryKind::HardLink => {
                if let Some(link) = strip_name(&entry.linkname) {
                    hardlinks.push((relpath, link, mode_byte(entry.mode)));
                }
            }
        }
    }

    for (relpath, link, mb) in hardlinks {
        if let Some(&idx) = file_index.get(&link) {
            let content = entries[idx].content.clone();
            entries.push(MaterializedEntry { relpath, mode_byte: mb, content });
        }
    }

    Ok(entries)
}

#[cfg(test)]
#[path = "safe_extract_tests.rs"]
mod safe_extract_tests;
