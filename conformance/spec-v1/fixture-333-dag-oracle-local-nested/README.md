# fixture-333 — epoch-2 Merkle-DAG oracle: local transport, nested tree

**Status: LIVE (epoch-2 local materializer, RFC slice B2-local).** This fixture is a
**cross-transport gate**: a real directory tree (laid out on disk at test time from
`local-protocol.json`, preserving the executable bit and the symlink) is walked
through milpa's production local seam (`enumerate_local_entries`) and must
reproduce the SAME pinned `dag-sha256:` digest that the staged-seam fixture
(`fixture-330-dag-oracle-nested-leafsort`), the git-transport fixture
(`fixture-331-dag-oracle-git-nested`), and the tarball-transport fixture
(`fixture-332-dag-oracle-tarball-nested`) compute.

## The tree this fixture encodes

The same logical tree as fixtures 330/331/332, on a live filesystem:

```
.
├── a.txt            regular     "alpha\n"              (st_mode 0644 → 0x00)
├── a/
│   ├── b.txt        regular     "beta\n"               (st_mode 0644 → 0x00)
│   └── run.sh       executable  "#!/bin/sh\necho hi\n"  (st_mode 0755 → 0x01)
└── link  -> a/b.txt symlink     (readlink = "a/b.txt") → 0x80
```

## Why the local seam is distinct from the staged seam

The staged `dag-oracle.json` path (fixture-330) feeds pre-built `MaterializedEntry`
objects straight to the DAG builder — it exercises **no** filesystem walk. The
local materializer (`enumerate_local_entries`) is the only thing that turns real
on-disk bytes + POSIX mode bits (exec via `st_mode & 0o111`, symlink via
`readlink`) into the seam, so this fixture is a genuine proof of the local
transport, not a duplicate of fixture-330.

## Pinned identity (frozen epoch-2 oracle — shared with fixtures 330/331/332)

```
dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f
```

Identity is transport-independent (spec §1.1): git, tarball, and a local directory
walk of the same source bytes hash identically. The standalone reference oracle
(`conformance/spec-v1/_oracle/dag_sha256_reference.py`) does NOT import milpa.
