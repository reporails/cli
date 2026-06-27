"""Regression tests for `_narrow_to_path_targets` symlink handling.

A directory target must keep an in-tree symlinked instruction file (e.g. a
hub-symlinked rule). The earlier `f.resolve()`-only membership test dropped it,
because resolution follows the symlink out of the target directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.interfaces.cli.main import _narrow_to_path_targets, _resolved_within_target


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_symlinked_file_under_dir_target_is_preserved(tmp_path: Path) -> None:
    """A symlink inside a directory target survives narrowing even though it
    resolves to a file outside the target."""
    target = tmp_path / "rules"
    target.mkdir()
    external = tmp_path / "external" / "real.md"
    external.parent.mkdir()
    external.write_text("rule body")
    link = target / "link.md"
    try:
        link.symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/filesystem")

    kept = _narrow_to_path_targets([link], {target.resolve()})

    assert kept == [link]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_unrelated_file_is_dropped(tmp_path: Path) -> None:
    """A real file outside every target is still excluded."""
    target = tmp_path / "rules"
    target.mkdir()
    outside = tmp_path / "other" / "note.md"
    outside.parent.mkdir()
    outside.write_text("x")

    kept = _narrow_to_path_targets([outside], {target.resolve()})

    assert kept == []


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_resolved_within_target_excludes_escaping_symlink(tmp_path: Path) -> None:
    """A symlink under the target whose real file escapes the target is NOT a heal-write
    candidate — heal writes through to the real file, which sits outside the named scope."""
    target = tmp_path / "rules"
    target.mkdir()
    external = tmp_path / "external" / "real.md"
    external.parent.mkdir()
    external.write_text("rule body")
    link = target / "link.md"
    try:
        link.symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/filesystem")

    # In-scope by logical path (kept for scanning) but excluded from the heal write set.
    assert _narrow_to_path_targets([link], {target.resolve()}) == [link]
    assert _resolved_within_target(link, target) is False

    real = target / "real_in_scope.md"
    real.write_text("x")
    assert _resolved_within_target(real, target) is True
