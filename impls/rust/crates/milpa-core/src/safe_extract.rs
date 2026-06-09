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

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_total_size: 1 << 30, // 1 GiB
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
// Minimal USTAR reader
// ---------------------------------------------------------------------------

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
}

impl<'a> TarEntries<'a> {
    fn new(buf: &'a [u8]) -> Self {
        TarEntries { buf, pos: 0 }
    }
}

impl<'a> Iterator for TarEntries<'a> {
    type Item = Result<TarEntry<'a>, MilpaError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Need a full 512-byte header block.
        if self.pos + 512 > self.buf.len() {
            return None;
        }
        let header = &self.buf[self.pos..self.pos + 512];
        // Two consecutive zero blocks (or one, leniently) end the archive.
        if header.iter().all(|&b| b == 0) {
            return None;
        }

        let name = match cstr(&header[0..100]) {
            Some(n) if !n.is_empty() => n,
            _ => {
                return Some(Err(extract_err(
                    "EXTRACT-ZIP-SLIP",
                    "tar header with empty/invalid name",
                )))
            }
        };
        let size = match octal(&header[124..136]) {
            Some(s) => s,
            None => {
                return Some(Err(extract_err(
                    "EXTRACT-SIZE-LIMIT",
                    format!("tar entry {name:?} has an unparseable size field"),
                )))
            }
        };
        let typeflag = header[156];
        let linkname = cstr(&header[157..257]).unwrap_or_default();
        let kind = match typeflag {
            b'0' | 0 => EntryKind::File,
            b'5' => EntryKind::Dir,
            b'2' => EntryKind::Symlink,
            b'1' => EntryKind::HardLink,
            _ => EntryKind::Other,
        };

        let data_start = self.pos + 512;
        let data_end = data_start + size as usize;
        if data_end > self.buf.len() {
            return Some(Err(extract_err(
                "EXTRACT-SIZE-LIMIT",
                format!("tar entry {name:?} data ({size} bytes) runs past end of archive"),
            )));
        }
        let data = &self.buf[data_start..data_end];
        // Advance past the data, padded up to the next 512 boundary.
        let padded = size.div_ceil(512) * 512;
        self.pos = data_start + padded as usize;

        Some(Ok(TarEntry {
            name,
            linkname,
            size,
            kind,
            data,
        }))
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
