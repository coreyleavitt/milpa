"""``FakeOciClient`` — a coarse, in-memory ``OciRegistryClient`` test double.

Not a canned-transport replay (that's ``_oci_transport_replay.py``, which
drives the REAL client's token/manifest/blob state machine — auth, digest
verification, redirect handling — against recorded HTTP transcripts under
``conformance/oci-transport/``). This fake is deliberately coarser: it
satisfies the same duck-typed shape ``OciFetcher`` depends on
(``token``/``manifest``/``blob``) and just stages canned tar bytes, for
end-to-end tests (resolver / override-target wiring) that only need to prove
the right ``(registry, repository, digest)`` triple was reached and the
right bytes got extracted — not re-exercise the client's own transport
correctness, which ``test_oci_client.py`` already covers exhaustively.

Not collected as a test module (leading underscore; no ``test_`` prefix).
"""

from __future__ import annotations

from pathlib import Path

from milpa.fetchers.oci_client import Layer, Manifest, SOURCE_LAYER_MEDIA_TYPE

_DEFAULT_LAYER_DIGEST = "sha256:" + "0" * 64


class FakeOciClient:
    """Records each ``manifest()`` call and stages ``tar_bytes`` on ``blob()``.

    ``calls`` accumulates ``"<registry>/<repository>@<digest>"`` strings, one
    per ``manifest()`` invocation — mirroring the old whole-pull fake's
    ``pull_calls`` shape so migrated call sites keep the same assertion
    format.
    """

    def __init__(self, tar_bytes: bytes, *, layer_digest: str = _DEFAULT_LAYER_DIGEST) -> None:
        self._tar_bytes = tar_bytes
        self._layer_digest = layer_digest
        self.calls: list[str] = []

    def token(self, registry: str, repository: str) -> str:
        return "fake-token"

    def manifest(self, registry: str, repository: str, digest: str, token: str) -> Manifest:
        self.calls.append(f"{registry}/{repository}@{digest}")
        return Manifest(
            media_type="application/vnd.oci.image.manifest.v1+json",
            artifact_type=None,
            layers=(
                Layer(
                    media_type=SOURCE_LAYER_MEDIA_TYPE,
                    digest=self._layer_digest,
                    size=len(self._tar_bytes),
                ),
            ),
            config_media_type=None,
        )

    def blob(
        self,
        registry: str,
        repository: str,
        digest: str,
        size: int | None,
        token: str,
        *,
        dest: Path,
    ) -> None:
        dest.write_bytes(self._tar_bytes)
