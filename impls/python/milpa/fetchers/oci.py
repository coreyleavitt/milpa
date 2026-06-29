"""OciFetcher — OCI registry pull transport (slice 7d-5).

Pulls an OCI artifact identified by ``registry/repository@digest`` and
safe-extracts the single ``*.tar.gz`` layer into ``dest/``.

At v1 the **mandatory** deliverable is the ``TNG-*`` parse-path: every
digest and reference field is validated at parse-time (trust-boundary) by
``validate_oci_digest``, ``validate_oci_field``.  The live pull is driven by
an injected ``OciPull`` transport (production: ``oras pull``; tests inject a
closure).

Public surface:
  - ``OciProvenance``   — ``Provenance`` subclass for OCI deps.
  - ``OciReceipt``      — ``ProvenanceReceipt`` carrying ``layer_digest``.
  - ``OciFetcher``      — ``Fetcher`` ABC implementation.
  - ``validate_oci_digest``  — ``TNG-BAD-OCI-DIGEST`` gate.
  - ``validate_oci_field``   — ``TNG-UNSAFE-OCI-FIELD`` gate.
  - ``make_oras_pull``  — production seam: ``oras pull`` transport.

TNG-* parse-path (registry-protocol.md §4 NORMATIVE):
  ``validate_oci_digest`` and ``validate_oci_field`` are called from the
  manifest/index parse boundary.  ``OciFetcher.fetch`` calls them again at
  fetch time for defense-in-depth (any path that constructs an
  ``OciProvenance`` at runtime).

Digest format (registry-protocol.md §4):
    ``sha256:<64 lowercase hex>`` — bare or prefixed; ``TNG-BAD-OCI-DIGEST``
    for any other format.

Registry/repository safety (registry-protocol.md §4):
    Any value beginning with ``-`` raises ``TNG-UNSAFE-OCI-FIELD``
    (flag-injection prevention; values flow into ``oras`` argv).
"""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from milpa.errors import (
    FETCH_EXTRACT_FAILED,
    FETCH_OCI_AMBIGUOUS_TARBALL,
    FETCH_OCI_NO_TARBALL,
    FETCH_OCI_PULL_FAILED,
    TNG_BAD_OCI_DIGEST,
    TNG_UNSAFE_OCI_FIELD,
    MilpaError,
)
from milpa.fetchers.safe_extract import _DEFAULT_LIMITS, Limits, extract_tar
from milpa.fetchers.types import (
    Fetcher,
    Provenance,
    ProvenanceReceipt,
)
from milpa.registry import _RE_SHA256_DIGEST

# ---------------------------------------------------------------------------
# Validators — TNG-* parse-path (registry-protocol.md §4 NORMATIVE)
# ---------------------------------------------------------------------------


def validate_oci_digest(digest: str) -> None:
    """Raise ``MilpaError(TNG_BAD_OCI_DIGEST)`` unless ``digest`` is ``sha256:<64-hex>``.

    Registry-protocol.md §4 NORMATIVE: any ``digest`` field on an ``oci``
    provenance that does not match ``^sha256:[0-9a-f]{64}$`` MUST raise this
    error at parse time (trust boundary).

    Uses ``_RE_SHA256_DIGEST`` from ``milpa.registry`` — the single source of
    truth for the ``sha256:<64 lowercase hex>`` pointer format (shared with
    ``_validate_dep_decl_pointer``; only the error code differs).
    """
    if not _RE_SHA256_DIGEST.fullmatch(digest):
        raise MilpaError(
            TNG_BAD_OCI_DIGEST,
            f"OCI digest must be in sha256:<64 lowercase hex> form; got {digest!r}",
            digest=digest,
        )


def validate_oci_field(field_name: str, value: str) -> None:
    """Raise ``MilpaError(TNG_UNSAFE_OCI_FIELD)`` if ``value`` begins with ``-``.

    Registry-protocol.md §4 NORMATIVE: ``registry`` and ``repository`` MUST NOT
    begin with ``-`` (flag-injection prevention; values flow into ``oras`` argv).
    """
    if value.startswith("-"):
        raise MilpaError(
            TNG_UNSAFE_OCI_FIELD,
            f"OCI field {field_name!r} must not begin with '-'; got {value!r}",
            field=field_name,
            value=value,
        )


# ---------------------------------------------------------------------------
# OciProvenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OciProvenance(Provenance):
    """Provenance descriptor for an OCI-registry dep.

    Fields are validated at construction time (defense-in-depth; canonical
    validation is at the manifest/index parse boundary).

    Fields
    ------
    registry:
        OCI registry hostname (e.g. ``"ghcr.io"``).  MUST NOT start with ``-``.
    repository:
        OCI repository path (e.g. ``"org/pkg"``).  MUST NOT start with ``-``.
    digest:
        OCI content digest in ``sha256:<64-hex>`` form.
    """

    cas_admissible: ClassVar[bool] = True

    registry: str
    repository: str
    digest: str

    def __post_init__(self) -> None:
        validate_oci_digest(self.digest)
        validate_oci_field("registry", self.registry)
        validate_oci_field("repository", self.repository)

    @property
    def reference(self) -> str:
        """Full OCI reference: ``registry/repository@digest``."""
        return f"{self.registry}/{self.repository}@{self.digest}"


# ---------------------------------------------------------------------------
# OciReceipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OciReceipt(ProvenanceReceipt):
    """Receipt produced by a successful OCI pull.

    ``layer_digest`` is the OCI content digest from the provenance —
    it identifies the pulled blob uniquely within the registry.
    """

    layer_digest: str  # the ``sha256:…`` digest from OciProvenance

    def transport_fields(self) -> dict[str, str]:
        return {"layer_digest": self.layer_digest}


# ---------------------------------------------------------------------------
# OciPull seam type
# ---------------------------------------------------------------------------

#: Injected OCI pull transport: given a full OCI reference string and an output
#: directory path (as ``str``), produces a list of files (as ``Path``) placed in
#: that directory, or raises ``MilpaError(FETCH_OCI_PULL_FAILED, …)``.
OciPull = Callable[[str, Path], list[Path]]


def make_oras_pull() -> OciPull:
    """Return a production ``OciPull`` backed by ``oras pull``."""

    def _pull(reference: str, output_dir: Path) -> list[Path]:
        result = subprocess.run(
            ["oras", "pull", reference, "--output", str(output_dir)],
            capture_output=True,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"oras pull failed for {reference!r}: {detail}",
                reference=reference,
            )
        return sorted(output_dir.iterdir())

    return _pull


# ---------------------------------------------------------------------------
# enumerate_oci_entries — the OCI materialize seam (RFC slice B2-oci: STUB)
# ---------------------------------------------------------------------------


def enumerate_oci_entries(*_args: object, **_kwargs: object) -> list:
    """The OCI **materialize seam** — a coded not-implemented STUB (RFC slice B2-oci).

    Every other transport (git / tarball / local) has a real epoch-2 materializer
    feeding ``compute_dag_identity``. OCI does **not**: there is no epoch-2 OCI
    fetcher path yet (the OCI dag-oracle conformance tier stays SKIPPED), so asking
    for the OCI seam is a clear coded not-implemented condition rather than a silent
    empty/incorrect result.

    NOTE (slug): there is no ``FETCH-*-NOT-IMPLEMENTED`` slug in ``spec/errors.md``,
    and the error-catalog discipline forbids minting one carelessly. This stub
    raises the language-level not-implemented marker (``NotImplementedError``); if
    the OCI epoch-2 materializer is ever built (B2-oci proper), a catalog slug is a
    deliberate spec decision made then, not now.

    Raises:
        NotImplementedError: always — the OCI epoch-2 materializer is not built.
    """
    raise NotImplementedError(
        "OCI epoch-2 materialize seam is not implemented (RFC identity-conformance "
        "B2-oci is a stub; there is no epoch-2 OCI fetcher path yet)"
    )


# ---------------------------------------------------------------------------
# OciFetcher
# ---------------------------------------------------------------------------


class OciFetcher(Fetcher):
    """Pull + safe-extract fetcher for OCI-registry deps (slice 7d-5).

    The pull transport is injected via ``oci_pull`` so tests need no real
    registry.  The production transport is ``make_oras_pull()``.

    Protocol (plugin-contract.md §1):
        1. ``can_handle`` → True for ``OciProvenance``.
        2. ``fetch``      → validate fields, pull the OCI artifact (which must
                            contain exactly one ``*.tar.gz``), safe-extract to
                            ``dest/``, return ``OciReceipt``.
        3. Receipt carries ``layer_digest`` (transport-pinning field).

    Failure codes:
        ``TNG-BAD-OCI-DIGEST``          — malformed digest at fetch time.
        ``TNG-UNSAFE-OCI-FIELD``        — leading-dash in registry/repo.
        ``FETCH-OCI-PULL-FAILED``       — oras/transport error.
        ``FETCH-OCI-NO-TARBALL``        — artifact had 0 ``*.tar.gz`` files.
        ``FETCH-OCI-AMBIGUOUS-TARBALL`` — artifact had >1 ``*.tar.gz`` files.
        ``FETCH-EXTRACT-FAILED``        — safe_extract raised.
    """

    def __init__(
        self,
        oci_pull: OciPull | None = None,
        limits: Limits = _DEFAULT_LIMITS,
    ) -> None:
        self._oci_pull: OciPull = oci_pull if oci_pull is not None else make_oras_pull()
        self._limits = limits

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, OciProvenance)

    def fetch(
        self,
        name: str,
        p: Provenance,
        *,
        dest: Path,
    ) -> ProvenanceReceipt:
        if not isinstance(p, OciProvenance):
            raise TypeError(f"OciFetcher.fetch called with {type(p).__name__!r}")

        # Defense-in-depth validation (canonical check is at parse boundary).
        validate_oci_digest(p.digest)
        validate_oci_field("registry", p.registry)
        validate_oci_field("repository", p.repository)

        reference = p.reference

        # Pull into a scratch directory so we can inspect the artifact
        # before touching dest.
        with tempfile.TemporaryDirectory(prefix=f".milpa-oci-{name}.") as _tmp:
            scratch = Path(_tmp)
            try:
                pulled_files = self._oci_pull(reference, scratch)
            except MilpaError:
                raise
            except Exception as exc:
                raise MilpaError(
                    FETCH_OCI_PULL_FAILED,
                    f"fetching {name!r} ({reference!r}): {exc}",
                    dep=name,
                    reference=reference,
                ) from exc

            # Artifact MUST contain exactly one *.tar.gz.
            tarballs = sorted(
                f for f in pulled_files
                if f.name.endswith(".tar.gz") or f.name.endswith(".tgz")
            )

            if len(tarballs) == 0:
                raise MilpaError(
                    FETCH_OCI_NO_TARBALL,
                    f"OCI artifact {reference!r} for {name!r} contained no *.tar.gz",
                    dep=name,
                    reference=reference,
                )
            if len(tarballs) > 1:
                names = [t.name for t in tarballs]
                raise MilpaError(
                    FETCH_OCI_AMBIGUOUS_TARBALL,
                    f"OCI artifact {reference!r} for {name!r} has "
                    f"{len(tarballs)} *.tar.gz files; ambiguous: {names!r}",
                    dep=name,
                    reference=reference,
                    tarballs=names,
                )

            tarball_path = tarballs[0]

            # Extract.
            dest.mkdir(parents=True, exist_ok=True)
            try:
                extract_tar(
                    tarball_path,
                    dest,
                    strip_components=0,
                    limits=self._limits,
                )
            except MilpaError as exc:
                raise MilpaError(
                    FETCH_EXTRACT_FAILED,
                    f"fetching {name!r}: safe extraction failed ({exc.slug}): {exc.message}",
                    dep=name,
                    reference=reference,
                    inner_slug=exc.slug,
                ) from exc
            except Exception as exc:
                raise MilpaError(
                    FETCH_EXTRACT_FAILED,
                    f"fetching {name!r}: extraction error: {exc}",
                    dep=name,
                    reference=reference,
                ) from exc

        return OciReceipt(layer_digest=p.digest)
