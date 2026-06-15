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

use std::path::{Component, Path, PathBuf};

use crate::error::MilpaError;
use crate::fetch::FetchError;

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

/// Extract the (already-decompressed) tar bytes `tar` into `dest`. See the module
/// docs for the guards. Partial extraction state on error is the caller's to
/// clean up (typically: remove `dest`).
pub fn extract_tar(
    tar: &[u8],
    dest: &Path,
    strip_components: u32,
    limits: Limits,
) -> Result<ExtractionResult, MilpaError> {
    std::fs::create_dir_all(dest).map_err(|e| {
        extract_err(
            "EXTRACT-ZIP-SLIP",
            format!("cannot create dest {}: {e}", dest.display()),
        )
    })?;
    let dest_root = std::fs::canonicalize(dest).unwrap_or_else(|_| normalize_lexical(dest));

    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    let strip = strip_components as usize;

    for entry in TarEntries::new(tar) {
        let entry = entry?;

        // strip_components: split, drop empty/".", skip if too shallow.
        let parts: Vec<&str> = entry
            .name
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        if parts.len() <= strip {
            continue;
        }
        let stripped = parts[strip..].join("/");

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
            EntryKind::Symlink | EntryKind::HardLink => {
                // The link target is evaluated relative to the link's parent.
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
                    std::fs::create_dir_all(p).map_err(io_zip(&entry.name))?;
                }
                let _ = std::fs::remove_file(&target);
                std::os::unix::fs::symlink(&entry.linkname, &target)
                    .map_err(io_zip(&entry.name))?;
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
                std::fs::create_dir_all(&target).map_err(io_zip(&entry.name))?;
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
                    std::fs::create_dir_all(p).map_err(io_zip(&entry.name))?;
                }
                std::fs::write(&target, entry.data).map_err(io_zip(&entry.name))?;
            }
            EntryKind::Other => {} // char/block/fifo — never legitimate in source.
        }
    }

    Ok(ExtractionResult {
        file_count,
        total_bytes,
    })
}

fn io_zip(name: &str) -> impl Fn(std::io::Error) -> MilpaError + '_ {
    move |e| extract_err("EXTRACT-ZIP-SLIP", format!("writing {name:?}: {e}"))
}

/// Lexically normalize a path: resolve `.` (drop) and `..` (pop the previous
/// `Normal` component, never above the root). No filesystem access.
fn normalize_lexical(path: &Path) -> PathBuf {
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

struct TarEntry<'a> {
    name: String,
    linkname: String,
    size: u64,
    kind: EntryKind,
    data: &'a [u8],
}

/// Iterate the entries of an uncompressed tar byte stream. Yields a coded
/// `EXTRACT-*` error on a truncated/garbled header.
struct TarEntries<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Pending GNU LongLink name override (next real entry uses this as name).
    pending_name: Option<String>,
    /// Pending GNU LongLink linkname override.
    pending_linkname: Option<String>,
    /// Pending PAX path override (from `path` key in extended header).
    pending_pax_name: Option<String>,
    /// Pending PAX linkpath override (from `linkpath` key in extended header).
    pending_pax_linkname: Option<String>,
}

impl<'a> TarEntries<'a> {
    fn new(buf: &'a [u8]) -> Self {
        TarEntries {
            buf,
            pos: 0,
            pending_name: None,
            pending_linkname: None,
            pending_pax_name: None,
            pending_pax_linkname: None,
        }
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

impl<'a> Iterator for TarEntries<'a> {
    type Item = Result<TarEntry<'a>, MilpaError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Need a full 512-byte header block.
            if self.pos + 512 > self.buf.len() {
                return None;
            }
            let header = &self.buf[self.pos..self.pos + 512];
            // Two consecutive zero blocks (or one, leniently) end the archive.
            if header.iter().all(|&b| b == 0) {
                return None;
            }

            // R6: validate USTAR header checksum BEFORE trusting any other field.
            // A corrupt-but-structurally-plausible header with a wrong checksum
            // must be rejected here rather than interpreted as file data and written
            // to disk.  Python's stdlib tarfile validates the checksum and raises
            // TarError → FETCH-EXTRACT-FAILED; this makes Rust match that behavior.
            let header_arr: &[u8; 512] = header.try_into().unwrap();
            if !header_checksum_valid(header_arr) {
                let name = cstr(&header[0..100]).unwrap_or_default();
                self.pos += 512; // consume the bad header block so we don't spin
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

            let data_start = self.pos + 512;
            let data_end = data_start + size as usize;
            if data_end > self.buf.len() {
                let name = cstr(&header[0..100]).unwrap_or_default();
                return Some(Err(extract_err(
                    "EXTRACT-SIZE-LIMIT",
                    format!("tar entry {name:?} data ({size} bytes) runs past end of archive"),
                )));
            }
            let data = &self.buf[data_start..data_end];
            // Advance past the data, padded up to the next 512 boundary.
            let padded = size.div_ceil(512) * 512;
            self.pos = data_start + padded as usize;

            // --- GNU @LongLink (typeflag b'L' = long name, b'K' = long linkname) ---
            // The entry DATA is the NUL-terminated long name/linkname string.
            // Store it and loop to read the following header entry which is the
            // actual content entry (its own name field may be truncated; we override).
            if typeflag == b'L' {
                // data bytes are the long name (NUL-terminated).
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                if let Ok(s) = std::str::from_utf8(&data[..end]) {
                    self.pending_name = Some(s.to_string());
                }
                continue; // skip — consume the real next entry
            }
            if typeflag == b'K' {
                // data bytes are the long linkname (NUL-terminated).
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
                parse_pax_headers(data, &mut self.pending_pax_name, &mut self.pending_pax_linkname);
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

            return Some(Ok(TarEntry {
                name,
                linkname,
                size,
                kind,
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

#[cfg(test)]
#[path = "safe_extract_tests.rs"]
mod safe_extract_tests;
