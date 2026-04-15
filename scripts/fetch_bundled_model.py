"""Fetch the bundled ONNX embedding model from Hugging Face Hub.

This is a **dev-only** helper. End users never run it — they install the
pre-built wheel which already contains the ONNX files.

Runs at clone time (via ``uv run poe fetch_bundled_model``) and in CI
before ``hatch build``. Idempotent: skips the download if all expected
files are already present.

Source: ``Xenova/all-MiniLM-L6-v2`` — a pre-exported ONNX build of
``sentence-transformers/all-MiniLM-L6-v2``. fp32 is bit-identical to
the PyTorch reference. Total download: ~87 MB.

Target: ``src/reporails_cli/bundled/models/minilm-l6-v2/``

The target directory is ``.gitignore``d so the binaries are never
committed. The wheel builder picks them up via ``artifacts`` in
``pyproject.toml``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Files we need from the Xenova repo
_ALLOW_PATTERNS: list[str] = [
    "onnx/model.onnx",
    "tokenizer.json",
    "config.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
]

# Required files (checked by the idempotency guard)
_REQUIRED: list[str] = _ALLOW_PATTERNS[:]

# Repo-relative bundle target
_BUNDLE_RELPATH = Path("src/reporails_cli/bundled/models/minilm-l6-v2")
_HF_REPO_ID = "Xenova/all-MiniLM-L6-v2"


def _repo_root() -> Path:
    """Return the repository root, assuming this script lives in ``scripts/``."""
    return Path(__file__).resolve().parent.parent


def _target_dir() -> Path:
    return _repo_root() / _BUNDLE_RELPATH


def _already_present(target: Path) -> bool:
    """True when every required file exists and is non-empty."""
    for rel in _REQUIRED:
        f = target / rel
        if not f.exists() or f.stat().st_size == 0:
            return False
    return True


def main() -> int:
    target = _target_dir()
    if _already_present(target):
        size_mb = sum((target / r).stat().st_size for r in _REQUIRED) / 1e6
        print(f"✓ bundled model already present at {target} ({size_mb:.1f} MB)")
        return 0

    print(f"downloading {_HF_REPO_ID} to {target} ...")

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
        repo_id=_HF_REPO_ID,
        allow_patterns=_ALLOW_PATTERNS,
        local_dir=str(target),
    )

    if not _already_present(target):
        missing = [r for r in _REQUIRED if not (target / r).exists()]
        print(f"ERROR: download completed but missing files: {missing}", file=sys.stderr)
        return 1

    size_mb = sum((target / r).stat().st_size for r in _REQUIRED) / 1e6
    print(f"✓ fetched {len(_REQUIRED)} files to {target} ({size_mb:.1f} MB)")
    print("  contents:")
    for rel in _REQUIRED:
        f = target / rel
        print(f"    {rel}  {f.stat().st_size / 1e6:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
