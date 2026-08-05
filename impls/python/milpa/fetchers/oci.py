"""OciFetcher — OCI registry pull transport (slice 7d-5; native client S6).

Pulls an OCI artifact identified by ``registry/repository@digest`` and
safe-extracts the single milpa source-tarball layer into ``dest/``.

At v1 the **mandatory** deliverable is the ``TNG-*`` parse-path: every
digest and reference field is validated at parse-time (trust-boundary) by
``validate_oci_digest``, ``validate_oci_field``.  The live pull is driven by
the native ``OciRegistryClient`` (``milpa.fetchers.oci_client``): token →
manifest → blob, composed directly in ``OciFetcher.fetch`` (RFC
docs/rfc-native-oci-fetch.md §3.2). The single "exactly one milpa
source-tarball layer" gate lives in ``select_source_layer`` — there is no
second copy of that predicate here.

Public surface:
  - ``OciProvenance``   — ``Provenance`` subclass for OCI deps.
  - ``OciReceipt``      — ``ProvenanceReceipt`` carrying ``layer_digest``.
  - ``OciFetcher``      — ``Fetcher`` ABC implementation.
  - ``validate_oci_digest``  — ``TNG-BAD-OCI-DIGEST`` gate.
  - ``validate_oci_field``   — ``TNG-UNSAFE-OCI-FIELD`` gate.

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
    (flag-injection prevention; historically these values flowed into
    ``oras`` argv — the native client has no subprocess/argv surface, but
    the gate is retained as defense-in-depth on untrusted manifest/index
    input).
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from milpa import bounded_http
from milpa.errors import (
    FETCH_EXTRACT_FAILED,
    TNG_BAD_OCI_DIGEST,
    TNG_UNSAFE_OCI_FIELD,
    MilpaError,
)
from milpa.fetchers.oci_client import OciRegistryClient, TokenCache, select_source_layer
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
    begin with ``-`` (defense-in-depth on untrusted manifest/index input; the
    native client builds these directly into request URLs, not subprocess argv,
    but the gate is retained regardless — see the module docstring).
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
    """Pull + safe-extract fetcher for OCI-registry deps (slice 7d-5; S6 native client).

    Composes the native ``OciRegistryClient`` (token → manifest → blob) and
    the pure ``select_source_layer`` policy directly — no intermediate
    whole-pull closure (RFC docs/rfc-native-oci-fetch.md §3.2). The client
    is injectable for tests; production defaults to ``bounded_http.request``
    over a fresh ``TokenCache``.

    RustF1 (doc-accuracy note, cross-impl): unlike the Rust twin's
    ``fetchers.rs::fetch_oci`` (which mints a new ``OciRegistryClient`` /
    ``TokenCache`` on every individual dep fetch), this ``OciFetcher`` — and
    therefore its one ``TokenCache`` — genuinely IS constructed once per
    resolve: ``build_registry()`` builds one ``OciFetcher`` in
    ``_build_env()`` (``cli.py``), and that single instance is reused for
    every OCI dep fetched by the ``ThreadPoolExecutor`` workers. Cross-dep
    token reuse within one resolve is therefore already live in Python. The
    Rust side does not have this yet (tracked by #203).

    Protocol (plugin-contract.md §1):
        1. ``can_handle`` → True for ``OciProvenance``.
        2. ``fetch``      → validate fields, acquire a token, fetch + verify
                            the manifest, select the single milpa
                            source-tarball layer, fetch + verify the blob,
                            safe-extract to ``dest/``, return ``OciReceipt``.
        3. Receipt carries ``layer_digest`` (transport-pinning field).

    Failure codes:
        ``TNG-BAD-OCI-DIGEST``          — malformed digest at fetch time.
        ``TNG-UNSAFE-OCI-FIELD``        — leading-dash in registry/repo.
        ``FETCH-OCI-PULL-FAILED``       — token/manifest/blob transport error.
        ``FETCH-OCI-DIGEST-MISMATCH``   — manifest or blob digest mismatch.
        ``FETCH-OCI-NO-TARBALL``        — artifact had 0 source-tarball layers.
        ``FETCH-OCI-AMBIGUOUS-TARBALL`` — artifact had >1 source-tarball layers.
        ``FETCH-EXTRACT-FAILED``        — safe_extract raised.
    """

    def __init__(
        self,
        client: OciRegistryClient | None = None,
        limits: Limits = _DEFAULT_LIMITS,
    ) -> None:
        self._client = client if client is not None else OciRegistryClient(
            bounded_http.request, TokenCache()
        )
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

        # Pull into a scratch directory so the raw tarball never lands
        # inside `dest` alongside the extracted tree — `dest`'s content_hash
        # is computed over the source tree alone (identity vs provenance).
        with tempfile.TemporaryDirectory(prefix=f".milpa-oci-{name}.") as _tmp:
            blob_path = Path(_tmp) / "source.tar.gz"

            token = self._client.token(p.registry, p.repository)
            manifest = self._client.manifest(p.registry, p.repository, p.digest, token)
            layer = select_source_layer(manifest)
            self._client.blob(
                p.registry, p.repository, layer.digest, layer.size, token, dest=blob_path
            )

            dest.mkdir(parents=True, exist_ok=True)
            try:
                extract_tar(
                    blob_path,
                    dest,
                    strip_components=0,
                    limits=self._limits,
                )
            except MilpaError as exc:
                raise MilpaError(
                    FETCH_EXTRACT_FAILED,
                    f"fetching {name!r}: safe extraction failed ({exc.slug}): {exc.message}",
                    dep=name,
                    reference=p.reference,
                    inner_slug=exc.slug,
                ) from exc
            except Exception as exc:
                raise MilpaError(
                    FETCH_EXTRACT_FAILED,
                    f"fetching {name!r}: extraction error: {exc}",
                    dep=name,
                    reference=p.reference,
                ) from exc

        return OciReceipt(layer_digest=p.digest)
