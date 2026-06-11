"""Pin-candidate emission for the differential conformance harness (slice 3d).

`pin_candidate(spec, divergence_record, dest_dir)` serializes a (shrunk)
FixtureSpec to a candidate directory containing:
  - The serialized fixture inputs (via harness.spec.serialize)
  - divergence.json — the §2e divergence record

It does NOT write expected/ — per RFC §2c, computing expected/ requires human
verification: a reviewer reads the spec, inspects the winning impl's output, and
blesses the bytes. The candidate dir is a ready-to-review artifact awaiting
human-blessed expected/ before promotion to conformance/spec-v1/.

Stdlib only; no 3rd-party dependencies, no import milpa.
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.spec import FixtureSpec, serialize


def pin_candidate(
    spec: FixtureSpec,
    divergence_record: dict,
    dest_dir: Path,
) -> None:
    """Serialize a shrunk FixtureSpec as a pin candidate directory.

    Writes to `dest_dir` (created if it does not exist):
      - All fixture inputs via serialize(spec, dest_dir):
          cmd, milpa.kdl, mocked-fetches/<key>/..., index.kdl (if named deps)
      - divergence.json — the §2e divergence record (passed in as a dict)

    Does NOT write expected/ — human verification is required before promotion.

    Parameters
    ----------
    spec              — the (shrunk) FixtureSpec to serialize
    divergence_record — the §2e JSON record dict, typically from Divergence.to_json()
                        parsed back to a dict, or built directly; must be
                        JSON-serializable
    dest_dir          — destination directory (will be created if needed)
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Write all fixture inputs (cmd, milpa.kdl, mocked-fetches/, index.kdl)
    serialize(spec, dest_dir)

    # Write the divergence record as divergence.json
    (dest_dir / "divergence.json").write_text(
        json.dumps(divergence_record, indent=2) + "\n",
        encoding="utf-8",
    )

    # Explicitly assert expected/ was NOT written (invariant documentation)
    expected_dir = dest_dir / "expected"
    assert not expected_dir.exists(), (
        f"pin_candidate must not write expected/; found {expected_dir}"
    )
