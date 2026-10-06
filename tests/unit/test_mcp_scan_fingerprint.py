"""The change fingerprint `validate` compares between calls sees what can change its reply."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.interfaces.mcp.scan_fingerprint import scan_inputs_fingerprint


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))  # Path.home() reads USERPROFILE on Windows
    monkeypatch.delenv("AILS_SERVER_URL", raising=False)
    root = tmp_path / "project"
    root.mkdir()
    (root / "CLAUDE.md").write_text(
        "# Project\n\nRun tests before committing.\n\nNever push to main.  \n", encoding="utf-8"
    )
    return root


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_edit_that_keeps_size_and_modification_time_changes_the_fingerprint(project: Path) -> None:
    """Rewriting a file with text of the same length and restoring its modification time still
    changes the fingerprint, so the next `validate` checks the file again."""
    target = project / "CLAUDE.md"
    before = scan_inputs_fingerprint(project)
    stat = target.stat()
    target.write_text("# Project\n\nRun tests before committing.\n\n*Never push to main.*\n", encoding="utf-8")
    os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert target.stat().st_size == stat.st_size
    assert target.stat().st_mtime_ns == stat.st_mtime_ns
    assert scan_inputs_fingerprint(project) != before


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_changed_server_address_changes_the_fingerprint(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pointing `AILS_SERVER_URL` at another server during a session changes the fingerprint,
    so the next `validate` asks that server instead of replaying the earlier reply."""
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    first = scan_inputs_fingerprint(project)
    assert scan_inputs_fingerprint(project) == first
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:8001")
    assert scan_inputs_fingerprint(project) != first


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_edit_to_a_skills_supporting_file_changes_the_fingerprint(project: Path) -> None:
    """A skill's supporting markdown file is part of the scan, so editing only that file
    makes the next `validate` check again instead of replaying the earlier reply."""
    skill = project / ".claude" / "skills" / "api"
    (skill / "references").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: api\ndescription: Use for the API\n---\n\n# API\n", encoding="utf-8")
    notes = skill / "references" / "notes.md"
    notes.write_text("# Notes\n\n- Prefer pagination\n", encoding="utf-8")
    before = scan_inputs_fingerprint(project)
    notes.write_text("# Notes\n\n- Prefer cursors\n", encoding="utf-8")
    assert scan_inputs_fingerprint(project) != before
