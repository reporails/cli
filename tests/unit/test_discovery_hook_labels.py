"""Hook file labels: a file resolving outside the project and home keeps the path as written."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.features import _hook_file_label


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_symlink_in_project_pointing_outside_keeps_written_path(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    outside = tmp_path / "out" / "settings.json"
    outside.parent.mkdir()
    outside.write_text("{}")
    link = proj / "linked.json"
    link.symlink_to(outside)
    assert _hook_file_label(link, proj) == link.as_posix()


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_outside_symlink_keeps_written_path(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    real = tmp_path / "out" / "settings.json"
    real.parent.mkdir()
    real.write_text("{}")
    link = tmp_path / "out" / "lnk.json"
    link.symlink_to(real)
    assert _hook_file_label(link, proj) == link.as_posix()


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_project_file_is_project_relative(tmp_path: Path) -> None:
    f = tmp_path / "proj" / ".claude" / "settings.json"
    f.parent.mkdir(parents=True)
    f.write_text("{}")
    assert _hook_file_label(f, tmp_path / "proj") == ".claude/settings.json"
