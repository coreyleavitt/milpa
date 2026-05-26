"""`milpa publish` — author-side publish pipeline.

Packs a Nim source tree into a deterministic tarball, pushes it as an
OCI artifact, cosign-signs the artifact, and POSTs to a tianguis
dispatch endpoint.

See milpa #95 for the design rationale (why publish lives in milpa, not
in the tianguis CLI). Pipeline shape:

    pack_source(dir)  -> bytes (deterministic tar.gz)
    push_oci(...)     -> oci_ref (registry+digest)
    cosign_sign(...)  -> Rekor entry (side effect; uses ambient cosign)
    post_dispatch(...) -> dispatch response

Each step is a separately-testable pure function (or a thin orchestrator
over an injectable subprocess runner / HTTP client).
"""

from __future__ import annotations

import gzip
import io
import re
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any


# Runner protocol: (argv, **kw) -> (exit_code, stdout, stderr).
# Injected by callers; default is _real_runner which actually subprocesses.
Runner = Callable[..., tuple[int, str, str]]


def _real_runner(argv: list[str], *, input: bytes | None = None, **kw: Any) -> tuple[int, str, str]:
    proc = subprocess.run(argv, input=input, capture_output=True, **kw)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}|sha256:[0-9a-f]{6,}")


def pack_source(source_dir: Path) -> bytes:
    """Pack `source_dir` into a gzip-compressed tar archive.

    Byte-deterministic: same file tree contents always produce the same
    output bytes, regardless of filesystem mtime / uid / gid. The OCI
    artifact digest the caller will produce from these bytes is therefore
    stable, and matches what `milpa fetch` will later compute when it
    pulls the artifact back down.

    Determinism strategy:
      - canonical entry order (sorted by arcname)
      - mtime zeroed on every tar entry
      - uid/gid/uname/gname zeroed (no filesystem ownership leak)
      - mode normalized (preserves executable bit only)
      - gzip mtime header set to 0 (otherwise gzip stamps current time)
    """
    # Build the inner tar first (no gzip), then gzip it ourselves so we
    # control the gzip mtime header (which tarfile's "w:gz" mode does NOT
    # let us set to 0).
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for path in sorted(source_dir.rglob("*"), key=lambda p: p.relative_to(source_dir).as_posix()):
            # Mirror identity._enumerate_entries: exclude anything under
            # .git/ at any depth. Without this, the OCI artifact's
            # unpacked content_hash diverges from what identity.py would
            # compute on the same source tree, breaking the trust chain.
            if ".git" in path.relative_to(source_dir).parts:
                continue
            arcname = path.relative_to(source_dir).as_posix()
            info = tf.gettarinfo(str(path), arcname=arcname)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            # Preserve only the executable bit on files; directories get 0o755.
            if info.isfile():
                info.mode = 0o755 if info.mode & 0o111 else 0o644
            elif info.isdir():
                info.mode = 0o755
            if info.isfile():
                with open(path, "rb") as f:
                    tf.addfile(info, f)
            else:
                tf.addfile(info)

    return gzip.compress(tar_buf.getvalue(), mtime=0)


def push_oci(
    *,
    blob: bytes,
    registry_ref: str,
    runner: Runner = _real_runner,
) -> str:
    """Push `blob` as an OCI artifact to `registry_ref` (e.g.
    ghcr.io/owner/repo:v1.2.3) and return the canonical
    `<registry>/<repo>@sha256:<digest>` form.

    The caller is responsible for authenticating the runner's environment
    to the registry (e.g. setting GHCR creds via the GH Actions OIDC
    permission); this function just orchestrates oras.
    """
    with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmp:
        tmp.write(blob)
        tmp.flush()
        argv = [
            "oras", "push",
            # oras rejects absolute paths in artifact specifications by
            # default; ours is a NamedTemporaryFile which always lives
            # under /tmp, so opt out of the check.
            "--disable-path-validation",
            registry_ref,
            f"{tmp.name}:application/vnd.tianguis.source.v1.tar+gzip",
        ]
        code, out, err = runner(argv)
    if code != 0:
        raise RuntimeError(f"oras push failed (exit {code}): {err.strip() or out.strip()}")

    m = _DIGEST_RE.search(out)
    if not m:
        raise RuntimeError(f"oras push succeeded but no digest in output: {out!r}")
    digest = m.group(0)

    # Convert tag form `registry/repo:tag` → canonical `registry/repo@digest`.
    head = registry_ref.rsplit(":", 1)[0] if ":" in registry_ref.split("/", 1)[1] else registry_ref
    return f"{head}@{digest}"


def cosign_sign(*, oci_ref: str, runner: Runner = _real_runner) -> None:
    """Cosign keyless-sign the OCI artifact at `oci_ref`.

    Cosign uses the runner environment's ambient OIDC token to fetch a
    Fulcio certificate, signs the artifact's manifest digest, and uploads
    the inclusion proof to Rekor. All the crypto belongs to cosign; this
    is pure orchestration. The caller must ensure cosign is on PATH and
    that the CI has minted an OIDC token (e.g. `id-token: write` on GH).
    """
    code, out, err = runner(["cosign", "sign", "--yes", oci_ref])
    if code != 0:
        raise RuntimeError(f"cosign sign failed (exit {code}): {err.strip() or out.strip()}")


HttpPost = Callable[..., tuple[int, dict[str, Any]]]


def _real_http_post(url: str, *, headers: dict[str, str], json: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    # Standard-library urllib — keep stdlib-only to avoid adding deps for
    # one POST. requests/httpx would be overkill.
    import json as _json
    import urllib.request
    body = _json.dumps(json).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return (resp.status, _json.loads(resp.read().decode("utf-8") or "{}"))
    except urllib.error.HTTPError as e:
        return (e.code, _json.loads(e.read().decode("utf-8") or "{}"))


def post_dispatch(
    *,
    dispatch_url: str,
    oidc_token: str,
    payload: dict[str, Any],
    http_post: HttpPost = _real_http_post,
) -> dict[str, Any]:
    """POST `payload` to `<dispatch_url>/v1/publish` with the OIDC bearer.

    Returns the dispatch response JSON on 2xx. Raises RuntimeError on
    any non-2xx, including the dispatch-side error code in the message
    so authors see what went wrong (identity_mismatch, invalid_token, etc.).
    """
    url = dispatch_url.rstrip("/") + "/v1/publish"
    headers = {
        "Authorization": f"Bearer {oidc_token}",
        "Content-Type": "application/json",
    }
    code, body = http_post(url, headers=headers, json=payload)
    if not (200 <= code < 300):
        err_code = body.get("error", "unknown") if isinstance(body, dict) else "unknown"
        raise RuntimeError(f"dispatch rejected publish ({code} {err_code}): {body}")
    return body


def publish(
    *,
    source_dir: Path,
    name: str,
    version: str,
    registry_ref: str,
    provider: str,
    repo_url: str,
    signed_by: str,
    oidc_token: str,
    dispatch_url: str,
    dry_run: bool = False,
    runner: Runner = _real_runner,
    http_post: HttpPost = _real_http_post,
) -> dict[str, Any] | None:
    """End-to-end publish: pack → push → sign → POST dispatch.

    Returns the dispatch response, or None when `dry_run=True` (in which
    case the OCI artifact is still pushed and signed — only the dispatch
    POST is skipped).
    """
    blob = pack_source(source_dir)
    oci_ref = push_oci(blob=blob, registry_ref=registry_ref, runner=runner)
    cosign_sign(oci_ref=oci_ref, runner=runner)

    payload = {
        "name":      name,
        "version":   version,
        "oci_ref":   oci_ref,
        "provider":  provider,
        "repo_url":  repo_url,
        "signed_by": signed_by,
    }
    if dry_run:
        # Local-dev path: no OIDC token to authenticate the dispatch
        # POST, so skip it entirely. Author inspects the OCI artifact +
        # Rekor entry directly.
        if not oidc_token:
            return None
        # CI-side path: full chain runs end-to-end — dispatch sees
        # dry_run=true and skips the commit workflow only. This proves
        # OIDC + identity wiring is correct before going live.
        payload["dry_run"] = True
    return post_dispatch(
        dispatch_url=dispatch_url,
        oidc_token=oidc_token,
        payload=payload,
        http_post=http_post,
    )
