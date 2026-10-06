"""Fetch the bundled runtime assets (public embedder + gated model artifacts).

This is a **developer-checkout** helper. End users never run it: the published
package carries no model, and the CLI downloads the model itself on the first
`ails check` (see ``src/reporails_cli/core/mapper/model_fetch.py``).

What it does today: pre-populates the in-tree ``src/reporails_cli/bundled/models/``
folder of a checkout (run ``uv run poe fetch_bundled_model``) so local work can
use the model from the working tree. No CI workflow and no package build runs it.
Idempotent: skips work if the expected files are already present.

Two sources, two trust levels:

- **Public embedder** — the open-weights embedder under
  ``src/reporails_cli/bundled/models/`` (~87 MB), downloaded without credentials.
- **Gated artifacts** — the remaining ``*.onnx`` files plus their contract
  under the same folder. These are pulled from a configurable URL over
  authenticated HTTP (see ``_gated`` below). When that URL is not configured
  the fetch fails with a clear message rather than fabricating a source.

Credentials come from the environment only
(``AILS_MODEL_BUCKET_URL`` + ``AILS_MODEL_AUTH_TOKEN``) and are never stored in
this file.

The target directory is ``.gitignore``d so no artifact is committed. The
published wheel is lean and carries no model; this helper pre-populates the
in-tree ``bundled/models/`` copy so a dev checkout runs offline without a
runtime fetch. The runtime fetch path (for end users) lives separately in
``src/reporails_cli/core/mapper/model_fetch.py`` and shares this manifest.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# The manifest — which files make up the model set — has one source of truth:
# the runtime fetch module. This dev/CI helper imports it so the dev tree and the
# runtime cache stay in lockstep.
from reporails_cli.core.mapper import model_fetch

_MODELS_BUNDLE_RELPATH = Path("src/reporails_cli/bundled/models")

# ─── ONNX embedder (public, ungated) ──────────────────────────────────

_ONNX_ALLOW_PATTERNS: list[str] = list(model_fetch.EMBEDDER_FILES)
_ONNX_BUNDLE_RELPATH = _MODELS_BUNDLE_RELPATH / model_fetch.EMBEDDER_SUBDIR
_ONNX_HF_REPO_ID = "Xenova/all-MiniLM-L6-v2"

# ─── Gated model artifacts (authenticated download) ───────────────────

# Relative paths of the gated artifacts, resolved against the bundle root
# ``src/reporails_cli/bundled/models/``.
_GATED_RELPATHS: list[str] = list(model_fetch.GATED_FILES)

# License files that must travel with the weights — a weight file pulled from a
# user's cache carries these next to it, since the repo copies do not travel
# with a separately-fetched artifact. The repo-root files are the ONLY
# source: this script stages them into the working tree, and the runtime fetch
# manifest pulls them from the host, so the copies can never diverge.
_BUNDLE_LICENSE_NAMES: tuple[str, ...] = model_fetch.LICENSE_FILES


def _repo_root() -> Path:
    """Return the repository root, assuming this script lives in ``scripts/``."""
    return Path(__file__).resolve().parent.parent


def _onnx_target() -> Path:
    return _repo_root() / _ONNX_BUNDLE_RELPATH


def _models_root() -> Path:
    return _repo_root() / _MODELS_BUNDLE_RELPATH


def _onnx_already_present(target: Path) -> bool:
    return model_fetch.models_present(target, model_fetch.EMBEDDER_FILES)


def _fetch_onnx() -> int:
    target = _onnx_target()
    if _onnx_already_present(target):
        size_mb = sum((target / r).stat().st_size for r in _ONNX_ALLOW_PATTERNS) / 1e6
        print(f"✓ ONNX model already present at {target} ({size_mb:.1f} MB)")
        return 0

    print(f"downloading {_ONNX_HF_REPO_ID} to {target} ...")

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print(
            "ERROR: huggingface_hub is required for the dev fetch script.\n"
            "Install with: uv add --dev huggingface_hub",
            file=sys.stderr,
        )
        return 1

    target.mkdir(parents=True, exist_ok=True)
    snapshot_download(
        repo_id=_ONNX_HF_REPO_ID,
        allow_patterns=_ONNX_ALLOW_PATTERNS,
        local_dir=str(target),
    )

    if not _onnx_already_present(target):
        missing = [r for r in _ONNX_ALLOW_PATTERNS if not (target / r).exists()]
        print(f"ERROR: ONNX download completed but missing files: {missing}", file=sys.stderr)
        return 1

    size_mb = sum((target / r).stat().st_size for r in _ONNX_ALLOW_PATTERNS) / 1e6
    print(f"✓ fetched ONNX ({size_mb:.1f} MB) to {target}")
    return 0


# ─── Gated fetch client ───────────────────────────────────────────────


class BucketNotProvisioned(RuntimeError):
    """Raised when no gated-download URL or auth token is configured."""


class GatedFetchError(RuntimeError):
    """Raised when an authenticated fetch fails (auth, network, or missing key)."""


def _bucket_url() -> str:
    """Configured gated-download base URL. Environment only — never a file default."""
    return os.environ.get("AILS_MODEL_BUCKET_URL", "").strip()


def _auth_token() -> str:
    """Configured download token. Environment only — never a file default."""
    return os.environ.get("AILS_MODEL_AUTH_TOKEN", "").strip()


def _refresh_token(stale: str) -> str | None:
    """Obtain a replacement download token after a 401.

    Rotation path so a token can be revoked and replaced mid-run without
    restarting the build: POST the stale token to ``AILS_MODEL_REFRESH_URL``
    (expects ``{"token": "..."}``) when configured; otherwise re-read
    ``AILS_MODEL_AUTH_TOKEN`` in case the operator re-exported a fresh value.
    Returns the new token, or ``None`` when no rotation source yields one.
    """
    refresh_url = os.environ.get("AILS_MODEL_REFRESH_URL", "").strip()
    if refresh_url:
        try:
            import httpx

            resp = httpx.post(
                refresh_url,
                headers={"Authorization": f"Bearer {stale}"},
                timeout=30.0,
            )
            if resp.status_code == 200:
                token = str(resp.json().get("token", "")).strip()
                if token and token != stale:
                    return token
        except Exception as exc:  # noqa: BLE001 — refresh is best-effort; fall through to env fallback
            print(f"  token refresh failed: {exc}", file=sys.stderr)

    # Env fallback runs whether the refresh URL was unset OR its POST raised —
    # a freshly re-exported token should still rescue the fetch.
    fresh = os.environ.get("AILS_MODEL_AUTH_TOKEN", "").strip()
    return fresh if fresh and fresh != stale else None


def _gated_all_present() -> bool:
    return model_fetch.models_present(_models_root(), model_fetch.GATED_FILES)


def _download_one(client, base_url: str, rel: str, token: str, target: Path) -> str:
    """Fetch one gated artifact with bearer auth; refresh + retry once on 401.

    Returns the token that succeeded (possibly refreshed). Raises
    ``GatedFetchError`` on any non-recoverable failure.
    """
    url = f"{base_url.rstrip('/')}/{rel}"

    def _get(tok: str):
        return client.get(url, headers={"Authorization": f"Bearer {tok}"})

    resp = _get(token)
    if resp.status_code == 401:
        print(f"  401 on {rel} — attempting token refresh ...")
        rotated = _refresh_token(token)
        if not rotated:
            raise GatedFetchError(
                f"authentication refused for {rel} (401) and no refreshed token available"
            )
        token = rotated
        resp = _get(token)

    if resp.status_code != 200:
        raise GatedFetchError(f"fetch of {rel} failed: HTTP {resp.status_code}")

    data = resp.content
    # The runtime fetch's guard: an empty body or an HTML page (an auth/redirect
    # interstitial) is never written as a model artifact.
    try:
        model_fetch.check_response_head(rel, url, resp.headers.get("content-type", ""), data)
    except model_fetch.ModelFetchError as exc:
        raise GatedFetchError(str(exc)) from exc

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return token


def _fetch_gated() -> int:
    """Pull the gated model artifacts from the configured URL.

    Idempotent skip when every artifact is already present. When artifacts are
    missing and no URL/token is configured, fail with a clear
    "model bucket not provisioned" message instead of fabricating a source.
    """
    root = _models_root()

    if _gated_all_present():
        size_mb = sum((root / r).stat().st_size for r in _GATED_RELPATHS) / 1e6
        print(f"✓ gated model artifacts already present at {root} ({size_mb:.1f} MB)")
        _ensure_bundle_license()
        return 0

    base_url = _bucket_url()
    token = _auth_token()
    if not base_url or not token:
        missing = [r for r in _GATED_RELPATHS if not (root / r).is_file()]
        print(
            "ERROR: model bucket not provisioned — cannot fetch gated artifacts.\n"
            "  Export AILS_MODEL_BUCKET_URL and AILS_MODEL_AUTH_TOKEN to authorize the\n"
            "  download. They are read from the environment only — never store a value\n"
            "  in this file: this script is source, and source is public.\n"
            f"  Missing: {missing}",
            file=sys.stderr,
        )
        return 1

    try:
        import httpx
    except ImportError:
        print("ERROR: httpx is required for the gated fetch.", file=sys.stderr)
        return 1

    print(f"downloading {len(_GATED_RELPATHS)} gated artifact(s) from the model bucket ...")
    try:
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            for rel in _GATED_RELPATHS:
                target = root / rel
                if target.is_file() and target.stat().st_size > 0:
                    continue
                print(f"  fetching {rel} ...")
                token = _download_one(client, base_url, rel, token, target)
    except GatedFetchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not _gated_all_present():
        missing = [r for r in _GATED_RELPATHS if not (root / r).is_file()]
        print(f"ERROR: gated fetch completed but missing files: {missing}", file=sys.stderr)
        return 1

    size_mb = sum((root / r).stat().st_size for r in _GATED_RELPATHS) / 1e6
    print(f"✓ fetched {len(_GATED_RELPATHS)} gated artifact(s) ({size_mb:.1f} MB) to {root}")
    _ensure_bundle_license()
    return 0


def _ensure_bundle_license() -> None:
    """Stage the license files next to the weights in the working tree.

    Dev-tree convenience only. The shipped copies are the wheel's license
    metadata files taken straight from the repo root, so the two shipped
    copies are the same bytes by construction.
    """
    for name in _BUNDLE_LICENSE_NAMES:
        src = _repo_root() / name
        if not src.is_file():
            continue
        dest = _models_root() / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.is_file() or dest.read_bytes() != src.read_bytes():
            dest.write_bytes(src.read_bytes())
            print(f"✓ staged {name} into bundle at {dest}")


def main() -> int:
    rc = _fetch_onnx()
    if rc != 0:
        return rc
    return _fetch_gated()


if __name__ == "__main__":
    sys.exit(main())
