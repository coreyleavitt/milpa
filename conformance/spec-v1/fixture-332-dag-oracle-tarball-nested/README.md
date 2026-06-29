# fixture-332 — epoch-2 Merkle-DAG oracle: tarball transport, nested tree

**Status: LIVE (epoch-2 tarball materializer, RFC slice B2-tarball).** This fixture
is a **cross-transport gate**: a real `.tar.gz` archive (built at test time from
`tarball-protocol.json`, preserving the executable bit and the symlink) is
enumerated through milpa's production tarball seam (`enumerate_tarball_entries`)
and must reproduce the SAME pinned `dag-sha256:` digest that the staged-seam
fixture (`fixture-330-dag-oracle-nested-leafsort`) and the git-transport fixture
(`fixture-331-dag-oracle-git-nested`) compute.

## The tree this fixture encodes

The same logical tree as fixtures 330/331, packed into a `.tar.gz`:

```
.
├── a.txt            regular     "alpha\n"              (tar mode 0644 → 0x00)
├── a/
│   ├── b.txt        regular     "beta\n"               (tar mode 0644 → 0x00)
│   └── run.sh       executable  "#!/bin/sh\necho hi\n"  (tar mode 0755 → 0x01)
└── link  -> a/b.txt symlink     (tar symlink entry; linkname = "a/b.txt") → 0x80
```

## Why this is the cross-transport gate (git ≡ tarball)

Identity is **transport-independent** (spec §1.1): the same source bytes (plus
POSIX modes) hash to the same digest regardless of how they were delivered. The
exec bit on `run.sh` is part of epoch-2 identity (spec §1.8.2.1), and a `.tar`
records POSIX modes faithfully, so the tarball reproduces the git digest exactly.

## The lossy-archive rule (spec §1.8.10, RFC §3.4)

A `.zip` (or any archive format that **drops** POSIX exec bits) would materialize a
*genuinely different* tree — every file `0x00` — and hash differently. That is
**correct** behaviour, not a bug: milpa hashes the bytes-plus-modes actually
delivered. `.zip` is rejected upstream by `TarballFetcher`; only exec-bit-faithful
tar formats (`.tar` / `.tar.gz` / `.tar.bz2` / `.tar.xz`) feed this seam.

## Pinned identity (frozen epoch-2 oracle — shared with fixtures 330/331)

```
dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f
```

Identical to fixtures 330/331. The standalone reference oracle
(`conformance/spec-v1/_oracle/dag_sha256_reference.py`) does NOT import milpa, so
each impl's builder reproducing the pin IS the differential check.
