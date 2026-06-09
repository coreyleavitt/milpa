//! Unit tests for safe tar extraction (S14b). EXTRACT-* codes are not
//! fixture-expressible (the corpus uses the FakeFetcher, no real archives), so
//! they are covered here with hand-built USTAR archives.

use super::*;

/// Build a single 512-byte USTAR header + padded data for one entry.
fn entry(name: &str, typeflag: u8, linkname: &str, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
    // size (octal, field 124..136) — 11 octal digits + NUL.
    let size_oct = format!("{:011o}\0", data.len());
    h[124..136].copy_from_slice(size_oct.as_bytes());
    h[156] = typeflag;
    let lb = linkname.as_bytes();
    h[157..157 + lb.len().min(100)].copy_from_slice(&lb[..lb.len().min(100)]);
    // mode/uid/gid/mtime left zero (octal "" → 0, accepted).
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Two trailing zero blocks = end of archive.
fn finish(mut tar: Vec<u8>) -> Vec<u8> {
    tar.extend(std::iter::repeat_n(0u8, 1024));
    tar
}

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn extracts_files_and_dirs() {
    let mut tar = Vec::new();
    tar.extend(entry("pkg/", b'5', "", b""));
    tar.extend(entry("pkg/foo.nim", b'0', "", b"echo 1"));
    let tar = finish(tar);

    let d = tmp();
    let res = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert_eq!(res.file_count, 1);
    assert_eq!(
        std::fs::read(d.path().join("pkg/foo.nim")).unwrap(),
        b"echo 1"
    );
}

#[test]
fn strip_components_drops_the_leading_dir() {
    let mut tar = Vec::new();
    tar.extend(entry("pkg-1.0/", b'5', "", b""));
    tar.extend(entry("pkg-1.0/src/x.nim", b'0', "", b"x"));
    let tar = finish(tar);

    let d = tmp();
    extract_tar(&tar, d.path(), 1, Limits::default()).unwrap();
    // The "pkg-1.0/" prefix is stripped → src/x.nim lands at the dest root.
    assert!(d.path().join("src/x.nim").is_file());
    assert!(!d.path().join("pkg-1.0").exists());
}

#[test]
fn zip_slip_via_parent_dir_is_rejected() {
    let tar = finish(entry("../escape.txt", b'0', "", b"pwned"));
    let d = tmp();
    let err = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap_err();
    assert_eq!(err.code(), "EXTRACT-ZIP-SLIP");
}

#[test]
fn symlink_escape_is_rejected() {
    // A symlink whose target climbs out of dest.
    let tar = finish(entry("link", b'2', "../../etc/passwd", b""));
    let d = tmp();
    let err = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap_err();
    assert_eq!(err.code(), "EXTRACT-SYMLINK-ESCAPE");
}

#[test]
fn in_tree_symlink_is_allowed() {
    let mut tar = Vec::new();
    tar.extend(entry("a.nim", b'0', "", b"a"));
    tar.extend(entry("link", b'2', "a.nim", b""));
    let tar = finish(tar);
    let d = tmp();
    let res = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert_eq!(res.file_count, 2);
    assert!(std::fs::symlink_metadata(d.path().join("link"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn per_file_size_cap_trips() {
    let tar = finish(entry("big.bin", b'0', "", &[0u8; 600]));
    let d = tmp();
    let limits = Limits {
        max_file_size: 100,
        ..Limits::default()
    };
    assert_eq!(
        extract_tar(&tar, d.path(), 0, limits).unwrap_err().code(),
        "EXTRACT-SIZE-LIMIT"
    );
}

#[test]
fn total_size_cap_trips() {
    let mut tar = Vec::new();
    tar.extend(entry("a", b'0', "", &[0u8; 400]));
    tar.extend(entry("b", b'0', "", &[0u8; 400]));
    let tar = finish(tar);
    let d = tmp();
    let limits = Limits {
        max_total_size: 500,
        max_file_size: 1000,
        ..Limits::default()
    };
    assert_eq!(
        extract_tar(&tar, d.path(), 0, limits).unwrap_err().code(),
        "EXTRACT-SIZE-LIMIT"
    );
}

#[test]
fn file_count_cap_trips() {
    let mut tar = Vec::new();
    for i in 0..3 {
        tar.extend(entry(&format!("f{i}"), b'0', "", b"x"));
    }
    let tar = finish(tar);
    let d = tmp();
    let limits = Limits {
        max_file_count: 2,
        ..Limits::default()
    };
    assert_eq!(
        extract_tar(&tar, d.path(), 0, limits).unwrap_err().code(),
        "EXTRACT-SIZE-LIMIT"
    );
}
