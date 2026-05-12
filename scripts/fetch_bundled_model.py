"""Fetch the bundled ML assets (ONNX embedder + spaCy en_core_web_sm).

This is a **dev-only** helper. End users never run it — they install the
pre-built wheel which already contains both assets.

Runs at clone time (via ``uv run poe fetch_bundled_model``) and in CI
before ``hatch build``. Idempotent: skips work if all expected files
are already present.

Targets:
- ``src/reporails_cli/bundled/models/minilm-l6-v2/`` — ONNX embedder
  (~87 MB) from ``Xenova/all-MiniLM-L6-v2`` on Hugging Face.
- ``src/reporails_cli/bundled/spacy/en_core_web_sm/`` — spaCy English
  pipeline (~15 MB) from spaCy's GitHub Releases. The model wheel is
  not on PyPI, so it cannot be declared as a normal runtime dep; we
  ship the model files inside our wheel instead.

Both target directories are ``.gitignore``d so the binaries are never
committed. ``hatch_build.py`` picks them up via ``force_include`` at
build time.
"""

from __future__ import annotations

import io
import sys
import urllib.request
import zipfile
from pathlib import Path

# ─── ONNX embedder ────────────────────────────────────────────────────

_ONNX_ALLOW_PATTERNS: list[str] = [
    "onnx/model.onnx",
    "tokenizer.json",
    "config.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
]
_ONNX_BUNDLE_RELPATH = Path("src/reporails_cli/bundled/models/minilm-l6-v2")
_ONNX_HF_REPO_ID = "Xenova/all-MiniLM-L6-v2"

# ─── spaCy en_core_web_sm ─────────────────────────────────────────────

_SPACY_BUNDLE_RELPATH = Path("src/reporails_cli/bundled/spacy/en_core_web_sm")
_SPACY_WHEEL_URL = (
    "https://github.com/explosion/spacy-models/releases/download/"
    "en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
)
# Inside the wheel, the model files sit under this prefix.
_SPACY_WHEEL_MODEL_PREFIX = "en_core_web_sm/en_core_web_sm-3.8.0/"
# A small set of files we expect after extraction (idempotency guard).
_SPACY_REQUIRED_FILES: list[str] = [
    "meta.json",
    "config.cfg",
    "tokenizer",
    "vocab/strings.json",
    "tagger/model",
    "parser/model",
]


def _repo_root() -> Path:
    """Return the repository root, assuming this script lives in ``scripts/``."""
    return Path(__file__).resolve().parent.parent


def _onnx_target() -> Path:
    return _repo_root() / _ONNX_BUNDLE_RELPATH


def _spacy_target() -> Path:
    return _repo_root() / _SPACY_BUNDLE_RELPATH


def _onnx_already_present(target: Path) -> bool:
    for rel in _ONNX_ALLOW_PATTERNS:
        f = target / rel
        if not f.exists() or f.stat().st_size == 0:
            return False
    return True


def _spacy_already_present(target: Path) -> bool:
    for rel in _SPACY_REQUIRED_FILES:
        f = target / rel
        if not f.exists() or f.stat().st_size == 0:
            return False
    return True


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


def _fetch_spacy() -> int:
    target = _spacy_target()
    if _spacy_already_present(target):
        total = sum(p.stat().st_size for p in target.rglob("*") if p.is_file())
        print(f"✓ spaCy model already present at {target} ({total / 1e6:.1f} MB)")
        return 0

    print("downloading en_core_web_sm wheel from spaCy releases ...")
    with urllib.request.urlopen(_SPACY_WHEEL_URL) as resp:
        wheel_bytes = resp.read()

    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir(parents=True, exist_ok=True)

    extracted = 0
    with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
        for name in zf.namelist():
            if not name.startswith(_SPACY_WHEEL_MODEL_PREFIX):
                continue
            rel = name[len(_SPACY_WHEEL_MODEL_PREFIX):]
            if not rel:
                continue
            dest = target / rel
            if name.endswith("/"):
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(name) as src, open(dest, "wb") as out:
                out.write(src.read())
            extracted += 1

    if not _spacy_already_present(target):
        missing = [r for r in _SPACY_REQUIRED_FILES if not (target / r).exists()]
        print(f"ERROR: spaCy extraction missing files: {missing}", file=sys.stderr)
        return 1

    total = sum(p.stat().st_size for p in target.rglob("*") if p.is_file())
    print(f"✓ extracted {extracted} spaCy files ({total / 1e6:.1f} MB) to {target}")
    return 0


def main() -> int:
    rc = _fetch_onnx()
    if rc != 0:
        return rc
    return _fetch_spacy()


if __name__ == "__main__":
    sys.exit(main())
