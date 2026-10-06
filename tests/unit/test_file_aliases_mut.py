"""Mutation-closing test for `core/discovery/file_aliases.py`."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.discovery.file_aliases import _dedupe_with_aliases


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_broken_symlinks_to_same_target_collapse(tmp_path: Path) -> None:
    """Two broken symlinks pointing at the same missing target must collapse
    to one canonical entry.

    Kills the `resolve(strict=False) -> strict=True` mutant: with `strict=True`
    a broken symlink raises FileNotFoundError, so each falls back to its own
    unresolved path and the two never group together.
    """
    target = tmp_path / "missing_target.md"  # deliberately never created
    link_a = tmp_path / "a.md"
    link_b = tmp_path / "b.md"
    os.symlink(target, link_a)
    os.symlink(target, link_b)

    representatives, aliases = _dedupe_with_aliases([link_a, link_b])

    assert representatives == [link_a]
    assert aliases == {link_a: [link_b]}
