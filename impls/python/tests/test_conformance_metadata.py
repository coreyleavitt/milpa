"""Conformance metadata declaration (rfc-conformance-parity §3.5 / spec §1.4).

Each impl that claims spec conformance must declare its epoch + corpus in its
own project metadata, so the new-impl onboarding protocol and the multi-epoch
filter have a single machine-readable source per impl. The Rust impl declares
this in ``crates/milpa-conformance/Cargo.toml`` under
``[package.metadata.milpa]``; the Python impl declares the equivalent here.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_PY_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _tool_milpa() -> dict:
    data = tomllib.loads((_PY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["tool"]["milpa"]


def test_conformance_declaration_present() -> None:
    """§1.4 NORMATIVE: the Python impl declares spec-version + corpus."""
    milpa = _tool_milpa()
    assert milpa["spec-version"] == "1.0"
    assert milpa["corpus"] == "spec-v1"


def test_declared_corpus_exists() -> None:
    """The declared corpus directory must exist at the repo root."""
    milpa = _tool_milpa()
    assert (_REPO_ROOT / "conformance" / milpa["corpus"]).is_dir()


def test_epoch_matches_rust_declaration() -> None:
    """Both reference impls must declare the same v1 epoch + corpus.

    A drift here means one impl silently claims a different conformance epoch
    than the other — exactly the multi-epoch hazard §3.4 guards against.
    """
    rust_cargo = (
        _REPO_ROOT / "impls" / "rust" / "crates" / "milpa-conformance" / "Cargo.toml"
    )
    rust = tomllib.loads(rust_cargo.read_text(encoding="utf-8"))
    rust_meta = rust["package"]["metadata"]["milpa"]
    py_meta = _tool_milpa()
    assert py_meta["spec-version"] == rust_meta["spec-version"]
    assert py_meta["corpus"] == rust_meta["corpus"]
