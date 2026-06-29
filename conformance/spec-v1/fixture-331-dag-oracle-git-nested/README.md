# fixture-331 — epoch-2 Merkle-DAG oracle: git transport, nested tree

**Status: LIVE (epoch-2 git materializer, RFC slice B2-git).** This fixture is
the **cross-transport proof**: a real git repository, cloned `--no-checkout` and
enumerated through milpa's production git seam
(`enumerate_git_entries`), must reproduce the SAME pinned `dag-sha256:` digest
that the staged-seam fixture (`fixture-330-dag-oracle-nested-leafsort`) and the
standalone reference oracle compute.

## The tree this fixture encodes

The same logical tree as fixture-330, committed to git so it materializes from
the object store (`git-protocol.json` builds it at test time):

```
.
├── a.txt            regular     "alpha\n"             (git mode 100644 → 0x00)
├── a/
│   ├── b.txt        regular     "beta\n"              (git mode 100644 → 0x00)
│   └── run.sh       executable  "#!/bin/sh\necho hi\n" (git mode 100755 → 0x01)
└── link  -> a/b.txt symlink     (git mode 120000; blob bytes = "a/b.txt")
```

It proves the git-specific materialization details land exactly on the spec:
- the **executable bit** survives as git mode `100755` → mode-byte `0x01`;
- the **symlink** is a mode-`120000` blob whose bytes are the target string
  `a/b.txt` (no trailing newline, not followed) → mode-byte `0x80`;
- the builder re-sorts each level's children by **leaf name**, so the
  subdirectory `a` sorts before the file `a.txt` (leaf-name order ≠
  `git ls-tree -r` stream order).

## Pinned identity (frozen epoch-2 oracle — shared with fixture-330)

```
dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f
```

Identical to fixture-330: identity is **transport-independent** (spec
§1.1) — the same source bytes hash the same regardless of how they were fetched.
This fixture proves the git transport agrees with the staged seam and the frozen
reference (`conformance/spec-v1/_oracle/dag_sha256_reference.py`), which does NOT
import milpa.
