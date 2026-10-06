"""A circular symlink named like an instruction file is skipped by every stage of a check."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import get_all_instruction_files, get_all_scannable_files
from reporails_cli.core.discovery.walk import (
    has_symlink_loop,
    is_symlink_loop_error,
    is_under,
    safe_resolve,
)


def _project_with_loop(root: Path) -> Path:
    (root / "CLAUDE.md").write_text("# Project\n\nRun the tests before every commit.\n", encoding="utf-8")
    loop = root / "loop"
    loop.mkdir()
    (loop / "CLAUDE.md").symlink_to("x")
    (loop / "x").symlink_to("CLAUDE.md")
    return loop / "CLAUDE.md"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_guard_reports_a_loop_and_resolves_it_to_itself(tmp_path: Path) -> None:
    looping = _project_with_loop(tmp_path)
    assert has_symlink_loop(looping) is True
    assert has_symlink_loop(tmp_path / "CLAUDE.md") is False
    assert safe_resolve(looping) == looping
    assert is_under(looping, tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_mechanical_check_location_test_survives_a_loop(tmp_path: Path) -> None:
    from reporails_cli.core.lint.mechanical.runner import _is_under_root

    looping = _project_with_loop(tmp_path)
    assert _is_under_root(looping, tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_discovery_leaves_out_a_looping_link_and_keeps_the_real_file(tmp_path: Path) -> None:
    looping = _project_with_loop(tmp_path)
    for files in (get_all_instruction_files(tmp_path), get_all_scannable_files(tmp_path)):
        assert looping not in files
        assert any(f.name == "CLAUDE.md" and f.parent == tmp_path for f in files)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_loop_error_is_recognised_in_both_python_forms() -> None:
    """3.12 raises RuntimeError, 3.13 raises OSError(ELOOP); a missing file is no loop."""
    import errno

    from reporails_cli.core.discovery.walk import is_symlink_loop_error

    assert is_symlink_loop_error(RuntimeError("Symlink loop"))
    assert is_symlink_loop_error(OSError(errno.ELOOP, "loop"))
    assert not is_symlink_loop_error(FileNotFoundError(errno.ENOENT, "missing"))


def _resolve_raising(monkeypatch: pytest.MonkeyPatch, winerror: int) -> None:
    def fake_resolve(self: Path, strict: bool = False) -> Path:
        exc = OSError(22, "windows resolve failure")
        exc.winerror = winerror  # type: ignore[attr-defined]
        raise exc

    monkeypatch.setattr(Path, "resolve", fake_resolve)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("winerror", [1920, 1921])
def test_a_windows_unfollowable_symlink_error_is_a_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, winerror: int
) -> None:
    _resolve_raising(monkeypatch, winerror)
    exc = OSError(22, "x")
    exc.winerror = winerror  # type: ignore[attr-defined]
    assert is_symlink_loop_error(exc) is True
    assert has_symlink_loop(tmp_path / "CLAUDE.md") is True
    assert is_under(tmp_path / "CLAUDE.md", tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("winerror", [2, 3])
def test_a_windows_missing_file_error_is_not_a_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, winerror: int
) -> None:
    _resolve_raising(monkeypatch, winerror)
    exc = OSError(2, "x")
    exc.winerror = winerror  # type: ignore[attr-defined]
    assert is_symlink_loop_error(exc) is False
    assert has_symlink_loop(tmp_path / "CLAUDE.md") is False
