"""Bundled configuration files for reporails CLI.

This package contains CLI-owned configuration:
- project-types.yml: Project type detection data for backbone discovery
- models/: Bundled ONNX embedding model (populated by
  scripts/fetch_bundled_model.py, not committed to git)
"""

from __future__ import annotations

from pathlib import Path


def get_bundled_path() -> Path:
    """Get path to bundled configuration directory."""
    return Path(__file__).parent


def get_project_types_path() -> Path:
    """Get path to bundled project-types.yml."""
    return get_bundled_path() / "project-types.yml"


def get_models_path() -> Path:
    """Get path to bundled ML models directory.

    The directory is populated at build time by
    ``scripts/fetch_bundled_model.py`` and shipped inside the wheel.
    See ``core/mapper/onnx_embedder.py`` for the consumer.
    """
    return get_bundled_path() / "models"
