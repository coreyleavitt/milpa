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
    write_checksum(&mut h);
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Compute the USTAR header checksum (bytes 148-155 treated as spaces).
/// Returns the unsigned sum of all 512 header bytes with the checksum field
/// treated as 8 ASCII spaces.
fn header_checksum(h: &[u8; 512]) -> u32 {
    let mut sum: u32 = 0;
    for (i, &b) in h.iter().enumerate() {
        // Checksum field occupies bytes 148-155; treat those as 0x20 (space).
        if i >= 148 && i < 156 {
            sum += b' ' as u32;
        } else {
            sum += b as u32;
        }
    }
    sum
}

/// Write the USTAR checksum into header bytes 148-155 (6-octal-digit NUL space).
fn write_checksum(h: &mut [u8; 512]) {
    let sum = header_checksum(h);
    // POSIX format: 6 octal digits, NUL, space.
    let s = format!("{:06o}\0 ", sum);
    h[148..156].copy_from_slice(s.as_bytes());
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

// ---------------------------------------------------------------------------
// SA-2: POSIX prefix field + GNU LongLink + PAX long-path handling
// ---------------------------------------------------------------------------

/// Build a USTAR header with the POSIX prefix field set (bytes 345..500).
/// `name` goes in bytes 0..100; `prefix` goes in bytes 345..500.
fn entry_with_prefix(prefix: &str, name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
    let size_oct = format!("{:011o}\0", data.len());
    h[124..136].copy_from_slice(size_oct.as_bytes());
    h[156] = typeflag;
    let pb = prefix.as_bytes();
    h[345..345 + pb.len().min(155)].copy_from_slice(&pb[..pb.len().min(155)]);
    // USTAR magic so tools recognize it.
    h[257..263].copy_from_slice(b"ustar ");
    write_checksum(&mut h);
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Build a GNU @LongLink header: typeflag b'L', data = the long name bytes.
fn gnu_longlink_name(long_name: &str) -> Vec<u8> {
    let name_bytes = long_name.as_bytes();
    // The @LongLink entry header.
    let mut h = [0u8; 512];
    // GNU uses "././@LongLink" as the name of the LongLink entry itself.
    let sentinel = b"././@LongLink";
    h[..sentinel.len()].copy_from_slice(sentinel);
    let size_oct = format!("{:011o}\0", name_bytes.len() + 1);
    h[124..136].copy_from_slice(size_oct.as_bytes());
    h[156] = b'L';
    write_checksum(&mut h);
    let mut out = h.to_vec();
    out.extend_from_slice(name_bytes);
    out.push(0); // NUL terminator
    let total_data = name_bytes.len() + 1;
    let pad = (512 - total_data % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[test]
fn posix_prefix_field_combined_with_name() {
    // SA-2 REGRESSION: an archive entry whose path > 100 chars uses the POSIX
    // prefix field (bytes 345..500) to carry the directory portion.  The reader
    // must concatenate prefix + "/" + name to form the full path.
    let prefix = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"; // 34 chars; fits in name too but let's use prefix
    let name = "deep_file.nim";
    let expected_path = format!("{prefix}/{name}");
    let mut tar = Vec::new();
    tar.extend(entry_with_prefix(prefix, name, b'0', b"content"));
    let tar = finish(tar);

    let d = tmp();
    extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert!(
        d.path().join(&expected_path).is_file(),
        "POSIX prefix+name must produce {expected_path}"
    );
    assert_eq!(
        std::fs::read(d.path().join(&expected_path)).unwrap(),
        b"content"
    );
}

#[test]
fn posix_prefix_creates_correct_tree_for_long_path() {
    // SA-2 cross-impl parity: a path whose total length > 100 chars split
    // across prefix (≤155) + name (≤100) must produce the same tree as Python's
    // stdlib tarfile (which handles prefix natively).
    //
    // We use a 120-char path: 80-char directory prefix + 40-char filename.
    let dir_prefix: String = "a".repeat(60) + "/" + &"b".repeat(18); // 79 chars total
    let file_name: String = "c".repeat(39) + ".nim";                  // 43 chars
    // Total = 79 + 1 + 43 = 123 chars (> 100, requires prefix field).
    let expected_path = format!("{dir_prefix}/{file_name}");
    let mut tar = Vec::new();
    tar.extend(entry_with_prefix(&dir_prefix, &file_name, b'0', b"long-path-content"));
    let tar = finish(tar);

    let d = tmp();
    extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert!(
        d.path().join(&expected_path).is_file(),
        "long POSIX prefix path must be extracted correctly: {expected_path}"
    );
    assert_eq!(
        std::fs::read(d.path().join(&expected_path)).unwrap(),
        b"long-path-content"
    );
}

#[test]
fn gnu_longlink_name_overrides_short_header_name() {
    // SA-2 REGRESSION: a GNU @LongLink (typeflag L) entry preceding a file
    // entry overrides the file entry's (truncated) name.  Without this fix the
    // reader sees only bytes[0..100] of the actual entry header, which is
    // truncated to 100 chars.
    //
    // We use a 120-char path which exceeds the 100-char USTAR name field.
    let long_name: String = "pkg/".to_string() + &"x".repeat(110) + ".nim"; // 115 chars
    let mut tar = Vec::new();
    // 1. The @LongLink entry (typeflag L, data = full name).
    tar.extend(gnu_longlink_name(&long_name));
    // 2. The actual file entry (name field will be truncated to 100 chars).
    tar.extend(entry(&long_name[..long_name.len().min(100)], b'0', "", b"gnu-long"));
    let tar = finish(tar);

    let d = tmp();
    extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    // The file MUST be at the FULL long_name path (not the truncated 100-char path).
    assert!(
        d.path().join(&long_name).is_file(),
        "GNU @LongLink must produce full path: {long_name}"
    );
    assert_eq!(
        std::fs::read(d.path().join(&long_name)).unwrap(),
        b"gnu-long"
    );
}

#[test]
fn pax_path_header_overrides_name() {
    // SA-2: a PAX extended header (typeflag x) carrying a `path` record
    // overrides the following entry's name field.  PAX headers allow arbitrary-
    // length paths and are the highest-priority name source.
    //
    // PAX record format: "<len> path=<value>\n"
    let long_name = "src/".to_string() + &"y".repeat(200) + ".nim"; // 204+4 = 208 chars
    // Build the PAX record.
    // record = "<len> path=<long_name>\n"
    // len = len(record) as decimal.
    let kv = format!("path={long_name}\n");
    // We need to compute len including the "NNN " prefix and the kv bytes.
    // Start with len=1 digit and iterate until stable.
    let mut len_digits = 1usize;
    loop {
        let _candidate = format!("{}{} {}", len_digits, " ".repeat(0), kv);
        // Total len: digits_len + 1 (space) + kv.len()
        let total = len_digits + 1 + kv.len();
        if total.to_string().len() == len_digits {
            break;
        }
        len_digits = total.to_string().len();
    }
    let record = format!("{} {}", len_digits + 1 + kv.len(), kv);
    // Truncate to actual byte count (PAX record length must be exact).
    let record_bytes = record.into_bytes();

    // Build the PAX header entry (typeflag x, data = PAX records).
    let mut pax_h = [0u8; 512];
    pax_h[..b"paxheader".len()].copy_from_slice(b"paxheader");
    let size_oct = format!("{:011o}\0", record_bytes.len());
    pax_h[124..136].copy_from_slice(size_oct.as_bytes());
    pax_h[156] = b'x';
    write_checksum(&mut pax_h);
    let mut tar = pax_h.to_vec();
    tar.extend_from_slice(&record_bytes);
    let pad = (512 - record_bytes.len() % 512) % 512;
    tar.extend(std::iter::repeat_n(0u8, pad));

    // The actual entry (name field truncated to 100 chars).
    let truncated = &long_name[..long_name.len().min(100)];
    tar.extend(entry(truncated, b'0', "", b"pax-content"));
    let tar = finish(tar);

    let d = tmp();
    extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert!(
        d.path().join(&long_name).is_file(),
        "PAX path= must produce full path: {long_name}"
    );
    assert_eq!(
        std::fs::read(d.path().join(&long_name)).unwrap(),
        b"pax-content"
    );
}

/// Build a raw PAX extended-header entry (typeflag x) from a slice of
/// (key, value) pairs.  Each pair becomes one PAX record:
/// `"<len> <key>=<value>\n"` where `<len>` is the total byte length of the
/// record (length field + space + key + '=' + value + '\n').
fn pax_header_entry(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut records: Vec<u8> = Vec::new();
    for (key, val) in pairs {
        // Compute the record length iteratively (length field is variable-width).
        let kv = format!("{key}={val}\n");
        let mut digits = 1usize;
        loop {
            let total = digits + 1 + kv.len(); // "<digits> <kv>"
            if total.to_string().len() == digits {
                break;
            }
            digits = total.to_string().len();
        }
        let total = digits + 1 + kv.len();
        let record = format!("{total} {kv}");
        records.extend_from_slice(record.as_bytes());
    }

    // Build the 512-byte PAX header block.
    let mut h = [0u8; 512];
    h[..b"paxheader".len()].copy_from_slice(b"paxheader");
    let size_oct = format!("{:011o}\0", records.len());
    h[124..136].copy_from_slice(size_oct.as_bytes());
    h[156] = b'x';
    write_checksum(&mut h);

    let mut out = h.to_vec();
    out.extend_from_slice(&records);
    let pad = (512 - records.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[test]
fn pax_path_as_second_record_is_not_silently_dropped() {
    // REGRESSION: parse_pax_headers computed kv_start as an ABSOLUTE offset
    // into data[] but then indexed into `record` (a sub-slice starting at pos).
    // For pos==0 (first record) the offsets coincide → worked.
    // For pos>0 (any subsequent record) kv_start is too large → guard fires,
    // record is silently skipped → PAX path= is ignored → extraction uses
    // truncated 100-char USTAR name → CROSS-IMPL DIVERGENCE with Python tarfile.
    //
    // This test puts `comment=` first (so pos>0 when `path=` is parsed) and
    // asserts the file lands at the FULL PAX path, not the truncated name.
    let long_name = "src/".to_string() + &"z".repeat(200) + ".nim"; // 208 chars

    let mut tar = Vec::new();
    // PAX extended header: comment= first, then path=.
    tar.extend(pax_header_entry(&[
        ("comment", "this record comes first"),
        ("path", &long_name),
    ]));
    // Actual file entry (name truncated to 100 chars — PAX must override it).
    let truncated = &long_name[..100];
    tar.extend(entry(truncated, b'0', "", b"second-record-pax"));
    let tar = finish(tar);

    let d = tmp();
    extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert!(
        d.path().join(&long_name).is_file(),
        "PAX path= record at non-zero pos must be applied (not silently dropped): {long_name}"
    );
    assert_eq!(
        std::fs::read(d.path().join(&long_name)).unwrap(),
        b"second-record-pax"
    );
}

#[test]
fn pax_path_as_third_record_is_not_silently_dropped() {
    // Variant: path= is the THIRD record (pos is even larger). Belt-and-suspenders.
    let long_name = "lib/".to_string() + &"w".repeat(196) + ".nim"; // 204 chars

    let mut tar = Vec::new();
    tar.extend(pax_header_entry(&[
        ("mtime", "1718000000.0"),
        ("comment", "another leading record"),
        ("path", &long_name),
    ]));
    let truncated = &long_name[..100];
    tar.extend(entry(truncated, b'0', "", b"third-record-pax"));
    let tar = finish(tar);

    let d = tmp();
    extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert!(
        d.path().join(&long_name).is_file(),
        "PAX path= as third record must be applied: {long_name}"
    );
    assert_eq!(
        std::fs::read(d.path().join(&long_name)).unwrap(),
        b"third-record-pax"
    );
}

#[test]
fn existing_short_path_entries_still_extract_correctly() {
    // SA-2 regression guard: ordinary entries (path ≤ 100 chars) must still
    // extract correctly after the long-path changes.
    let mut tar = Vec::new();
    tar.extend(entry("src/foo.nim", b'0', "", b"foo"));
    tar.extend(entry("src/bar.nim", b'0', "", b"bar"));
    let tar = finish(tar);

    let d = tmp();
    let res = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert_eq!(res.file_count, 2);
    assert_eq!(std::fs::read(d.path().join("src/foo.nim")).unwrap(), b"foo");
    assert_eq!(std::fs::read(d.path().join("src/bar.nim")).unwrap(), b"bar");
}

// ---------------------------------------------------------------------------
// R6: USTAR header checksum validation
// ---------------------------------------------------------------------------

/// Build an entry with a deliberately WRONG checksum in bytes 148-155.
/// The caller supplies a fully-populated header (with a VALID checksum already
/// written by `write_checksum`), then this function overwrites bytes 148-155
/// with zeros — guaranteed to be wrong for any non-trivial header.
fn entry_corrupt_checksum(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
    let size_oct = format!("{:011o}\0", data.len());
    h[124..136].copy_from_slice(size_oct.as_bytes());
    h[156] = typeflag;
    // Write a VALID checksum first so the rest of the header is coherent …
    write_checksum(&mut h);
    // … then CORRUPT it by writing zeros into the checksum field.
    // The correct checksum for any non-trivial header is >0, so zeros always mismatch.
    h[148..156].copy_from_slice(&[0u8; 8]);
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[test]
fn corrupt_checksum_is_rejected_does_not_write_garbage() {
    // R6 REGRESSION: a structurally plausible tar header whose checksum field
    // does not match the computed checksum MUST be rejected with an extraction
    // error (FETCH-EXTRACT-FAILED), NOT silently written to disk.
    //
    // Before this fix the hand-rolled USTAR reader did not validate the checksum
    // at all.  Python's stdlib tarfile validates and raises on corruption →
    // cross-impl divergence.  This test drives the FAILING side: it must be RED
    // (passes without writing any file) until checksum validation is added.
    let tar = finish(entry_corrupt_checksum("garbage.nim", b'0', b"pwned-content"));
    let d = tmp();
    let result = extract_tar(&tar, d.path(), 0, Limits::default());

    // Must return an error — FETCH-EXTRACT-FAILED or any EXTRACT-* code.
    match &result {
        Err(e) => {
            // The error must carry FETCH-EXTRACT-FAILED (the slug Python returns
            // on corrupt archive, and the slug the fetcher wrap maps to).
            assert_eq!(
                e.code(),
                "FETCH-EXTRACT-FAILED",
                "corrupt checksum must produce FETCH-EXTRACT-FAILED, got: {e:?}"
            );
        }
        Ok(_) => {
            panic!("corrupt checksum must not succeed (cross-impl divergence: Python raises, Rust must too)");
        }
    }

    // Must NOT have written any file.
    assert!(
        !d.path().join("garbage.nim").exists(),
        "corrupt-checksum entry must not be extracted to disk"
    );
}

#[test]
fn valid_checksum_entries_still_extract() {
    // Sanity guard: after adding checksum validation, entries with correct
    // checksums (produced by write_checksum) must still be accepted.
    let mut tar = Vec::new();
    tar.extend(entry("valid.nim", b'0', "", b"valid-content"));
    let tar = finish(tar);
    let d = tmp();
    let res = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    assert_eq!(res.file_count, 1);
    assert_eq!(
        std::fs::read(d.path().join("valid.nim")).unwrap(),
        b"valid-content"
    );
}

// ---------------------------------------------------------------------------
// R21: symlink/hardlink file_count cap (cross-impl parity with Python)
// ---------------------------------------------------------------------------

#[test]
fn symlink_count_cap_trips() {
    // R21 REGRESSION: the file_count cap (max_file_count) was checked after
    // incrementing in the File arm but NOT in the Symlink/HardLink arm.
    // Python's safe_extract.py checks the cap after every file_count increment
    // (files, symlinks, hardlinks alike).  An archive with >max_file_count
    // symlinks must raise EXTRACT-SIZE-LIMIT, matching Python.
    let mut tar = Vec::new();
    // First entry: a real file so the symlinks have a valid target.
    tar.extend(entry("target.nim", b'0', "", b"x"));
    // Add 3 symlinks; with max_file_count=2 the third must trip the cap.
    for i in 0..3 {
        tar.extend(entry(&format!("link{i}"), b'2', "target.nim", b""));
    }
    let tar = finish(tar);
    let d = tmp();
    let limits = Limits {
        max_file_count: 2,
        ..Limits::default()
    };
    let err = extract_tar(&tar, d.path(), 0, limits).unwrap_err();
    assert_eq!(
        err.code(),
        "EXTRACT-SIZE-LIMIT",
        "symlink count over max_file_count must raise EXTRACT-SIZE-LIMIT; got: {err:?}"
    );
}

#[test]
fn hardlink_count_cap_trips() {
    // Variant: same cap applies to hardlinks (EntryKind::HardLink, typeflag b'1').
    let mut tar = Vec::new();
    tar.extend(entry("real.nim", b'0', "", b"y"));
    for i in 0..3 {
        tar.extend(entry(&format!("hard{i}"), b'1', "real.nim", b""));
    }
    let tar = finish(tar);
    let d = tmp();
    let limits = Limits {
        max_file_count: 2,
        ..Limits::default()
    };
    let err = extract_tar(&tar, d.path(), 0, limits).unwrap_err();
    assert_eq!(
        err.code(),
        "EXTRACT-SIZE-LIMIT",
        "hardlink count over max_file_count must raise EXTRACT-SIZE-LIMIT; got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// H2 — hardlink geometry (spec/plugin-contract.md §2.2)
// ---------------------------------------------------------------------------

#[test]
fn hardlink_materialised_as_file_copy() {
    // H2a: hardlink entry is extracted as a real file (not a symlink or filesystem hardlink).
    let mut tar = Vec::new();
    tar.extend(entry("a/foo.txt", b'0', "", b"hello hardlink"));
    tar.extend(entry("a/bar.txt", b'1', "a/foo.txt", b""));
    let tar = finish(tar);
    let d = tmp();
    let res = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    // bar.txt must be a real regular file with identical bytes
    let bar = d.path().join("a/bar.txt");
    assert!(bar.is_file(), "bar.txt must be a regular file");
    assert!(
        !std::fs::symlink_metadata(&bar).unwrap().file_type().is_symlink(),
        "bar.txt must NOT be a symlink"
    );
    assert_eq!(std::fs::read(&bar).unwrap(), b"hello hardlink");
    assert_eq!(res.file_count, 2, "foo.txt + bar.txt (hardlink) = 2 files");
}

#[test]
fn hardlink_strip_components_applied_to_linkname() {
    // H2b: strip_components is applied to linkname (POSIX '/' split), not just the entry name.
    // Archive: a/foo.txt (regular) + a/bar.txt → a/foo.txt (hardlink).
    // With strip_components=1 the leading "a/" is stripped from BOTH names.
    let mut tar = Vec::new();
    tar.extend(entry("a/foo.txt", b'0', "", b"stripped link"));
    tar.extend(entry("a/bar.txt", b'1', "a/foo.txt", b""));
    let tar = finish(tar);
    let d = tmp();
    extract_tar(&tar, d.path(), 1, Limits::default()).unwrap();
    let foo = d.path().join("foo.txt");
    let bar = d.path().join("bar.txt");
    assert!(foo.is_file(), "foo.txt must exist after strip");
    assert!(bar.is_file(), "bar.txt must exist after strip (hardlink target also stripped)");
    assert_eq!(std::fs::read(&bar).unwrap(), b"stripped link");
    assert!(
        !std::fs::symlink_metadata(&bar).unwrap().file_type().is_symlink(),
        "bar.txt must be a real file, not a symlink"
    );
}

#[test]
fn hardlink_forward_reference_two_pass() {
    // H2c: hardlink BEFORE its target in archive order must still resolve (two-pass).
    // Archive order: hardlink first, regular file second.
    let mut tar = Vec::new();
    tar.extend(entry("a/bar.txt", b'1', "a/foo.txt", b"")); // hardlink FIRST
    tar.extend(entry("a/foo.txt", b'0', "", b"forward ref")); // file SECOND
    let tar = finish(tar);
    let d = tmp();
    let res = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap();
    let bar = d.path().join("a/bar.txt");
    assert!(bar.is_file(), "bar.txt must exist even though hardlink was listed first");
    assert_eq!(std::fs::read(&bar).unwrap(), b"forward ref");
    assert_eq!(res.file_count, 2);
}

#[test]
fn hardlink_escape_raises_zip_slip() {
    // H2d: hardlink whose linkname (after strip) escapes dest_root → EXTRACT-ZIP-SLIP.
    // No new slug — same code as a regular path-traversal escape.
    let tar = finish(entry("a/evil.txt", b'1', "../../etc/passwd", b""));
    let d = tmp();
    let err = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap_err();
    assert_eq!(
        err.code(),
        "EXTRACT-ZIP-SLIP",
        "hardlink escape must raise EXTRACT-ZIP-SLIP, not a new slug; got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// R1-18: EXTRACT-IO-ERROR — genuine I/O failures after path-validation
// ---------------------------------------------------------------------------

#[test]
fn write_failure_after_validation_raises_io_error() {
    // R1-18: a genuine filesystem I/O error (not a path-escape) during extraction
    // must raise EXTRACT-IO-ERROR, not EXTRACT-ZIP-SLIP.
    //
    // We induce the failure by making the destination directory read-only so that
    // fs::write (which is called AFTER all containment checks pass) returns EPERM.
    // This proves that io_err (not io_zip) is used for post-validation I/O.
    let mut tar = Vec::new();
    tar.extend(entry("ok.nim", b'0', "", b"content"));
    let tar = finish(tar);

    let d = tmp();
    // Make dest read-only: create_dir_all succeeds (dest exists), but any file
    // write inside it will fail with EACCES/EPERM.
    std::fs::set_permissions(d.path(), std::os::unix::fs::PermissionsExt::from_mode(0o555)).unwrap();

    // Probe whether we are actually restricted: try writing a probe file.
    // Running as root (or in some CI setups) ignores permissions — skip if so.
    let probe = d.path().join(".probe");
    let is_restricted = std::fs::write(&probe, b"x").is_err();
    if !is_restricted {
        std::fs::set_permissions(d.path(), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        return; // running as root or in a permissionless FS — can't induce failure
    }

    let result = extract_tar(&tar, d.path(), 0, Limits::default());
    std::fs::set_permissions(d.path(), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "EXTRACT-IO-ERROR",
        "write failure after path validation must raise EXTRACT-IO-ERROR; got: {err:?}"
    );
}

#[test]
fn zip_slip_via_parent_dir_still_raises_zip_slip_not_io_error() {
    // R1-18 regression guard: path-escape detection must keep EXTRACT-ZIP-SLIP.
    // This is the same check as the existing `zip_slip_via_parent_dir_is_rejected`
    // test but re-stated explicitly as the EXTRACT-IO-ERROR counterpart.
    let tar = finish(entry("../escape.txt", b'0', "", b"pwned"));
    let d = tmp();
    let err = extract_tar(&tar, d.path(), 0, Limits::default()).unwrap_err();
    assert_eq!(
        err.code(),
        "EXTRACT-ZIP-SLIP",
        "path escape must still raise EXTRACT-ZIP-SLIP after R1-18; got: {err:?}"
    );
}
