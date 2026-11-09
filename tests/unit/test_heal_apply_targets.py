"""`heal_apply` with `targets`: resolved once, refused when unresolvable, a capability target stays whole."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.heal.apply import heal_scope_files
from reporails_cli.core.platform.dto.heal import NamedTargets
from reporails_cli.interfaces.mcp import server, validate_targets

pytestmark = [pytest.mark.unit, pytest.mark.subsys_heal]


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = (tmp_path / "proj").resolve()
    (root / ".git").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\n\nRun the tests with pytest.\n", encoding="utf-8")
    skill = root / ".claude" / "skills" / "foo"
    (skill / "references").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: foo\ndescription: Does foo.\n---\n\n# foo\n", "utf-8")
    (skill / "references" / "x.md").write_text("# x\n", "utf-8")
    return root


def _kept(root: Path, token: str) -> list[Path]:
    selection = validate_targets.resolve_validate_targets((token,), root)
    assert isinstance(selection, tuple)
    named = NamedTargets(frozenset(selection[0]), frozenset(selection[1]))
    files = [root / "CLAUDE.md", root / ".claude/skills/foo/SKILL.md", root / ".claude/skills/foo/references/x.md"]
    return heal_scope_files(files, root, root, named)


def test_capability_target_keeps_the_whole_skill_folder(project: Path) -> None:
    assert _kept(project, "skills:foo") == [
        project / ".claude/skills/foo/SKILL.md",
        project / ".claude/skills/foo/references/x.md",
    ]


def test_plain_file_target_keeps_only_that_file(project: Path) -> None:
    assert _kept(project, "CLAUDE.md") == [project / "CLAUDE.md"]


def _run(project: Path, monkeypatch: pytest.MonkeyPatch, targets: list[str]) -> tuple[str, dict[str, int]]:
    calls = {"resolve": 0, "write": 0}
    real = validate_targets.resolve_validate_targets

    def counting(*a: Any, **k: Any) -> Any:
        calls["resolve"] += 1
        return real(*a, **k)

    def write(*_a: Any, **_k: Any) -> str:
        calls["write"] += 1
        return "wrote"

    payload: dict[str, Any] = {"tier": "pro", "files": {}, "workflow": {"summary": "", "locations": []}}
    server.validate_states.clear()
    monkeypatch.setattr(server, "model_not_ready_error", lambda: None)
    monkeypatch.setattr(server, "resolve_validate_targets", counting)
    monkeypatch.setattr(server, "heal_apply_write", write)
    monkeypatch.setattr(
        server, "run_pipeline_for_path", lambda p, full=False, named=frozenset(), **_k: (payload, object(), None)
    )
    result = asyncio.run(server.server.call_tool("heal_apply", {"path": str(project), "targets": targets}))
    return result.content[0].text, calls  # type: ignore[no-any-return,union-attr]


def test_targets_are_resolved_once(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, calls = _run(project, monkeypatch, ["skills:foo"])
    assert text == "wrote"
    assert calls == {"resolve": 1, "write": 1}


def test_unresolvable_target_refuses_and_writes_nothing(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text, calls = _run(project, monkeypatch, ["skills:nope"])
    assert text.startswith("heal_apply:") and "nope" in text
    assert calls["write"] == 0


def test_targets_that_name_nothing_write_nothing(project: Path) -> None:
    files = [project / "CLAUDE.md", project / ".claude/skills/foo/SKILL.md"]
    assert heal_scope_files(files, project, project, NamedTargets(frozenset(), frozenset())) == []
    assert heal_scope_files(files, project, project, None) == files
