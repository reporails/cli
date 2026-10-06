"""Antigravity loads files from the locations its docs name (antigravity.google/docs).

Each row builds the file under a tmp project (or a tmp HOME for `~/` paths) and asserts the
type `classify_files` gives it. Sources: /docs/rules, /docs/skills, /docs/subagents,
/docs/plugins, /docs/settings?tab=cli, /docs/hooks/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types

PROJECT_CASES = [
    (".agents/rules/style.md", "rules"),
    ("pkg/.agents/rules/style.md", "rules"),
    (".agents/skills/fmt/SKILL.md", "skills"),
    (".agents/agents/reviewer.md", "agents"),
    (".agents/agents/reviewer/agent.md", "agents"),
    (".agents/plugins/demo/plugin.json", "extensions"),
    (".agents/plugins/demo/hooks.json", "hooks"),
    (".agents/hooks.json", "hooks"),
]

USER_CASES = [
    (".gemini/AGENTS.md", "main"),
    (".gemini/GEMINI.md", "main"),
    (".gemini/config/AGENTS.md", "main"),
    (".gemini/config/GEMINI.md", "main"),
    (".gemini/config/rules/style.md", "rules"),
    (".gemini/config/skills/fmt/SKILL.md", "skills"),
    (".gemini/config/skills/fmt/notes.md", "skills"),
    (".gemini/config/agents/reviewer.md", "agents"),
    (".gemini/config/agents/reviewer/agent.md", "agents"),
    (".gemini/config/plugins/demo/plugin.json", "extensions"),
    (".gemini/antigravity-cli/settings.json", "config"),
    (".gemini/antigravity-cli/keybindings.json", "keybindings"),
]


def _write(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _classify(project: Path, files: list[Path]) -> dict[Path, str]:
    classified = classify_files(project, files, load_file_types("antigravity"))
    return {c.path: c.file_type for c in classified}


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(("rel", "expected"), PROJECT_CASES)
def test_project_location(tmp_path: Path, rel: str, expected: str) -> None:
    project = tmp_path / "proj"
    files = [_write(project / rel)]
    if rel.endswith("hooks.json") and "plugins" in rel:
        files.append(_write(project / ".agents/plugins/demo/plugin.json", "{}"))
    assert _classify(project, files)[files[0]] == expected


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(("rel", "expected"), USER_CASES)
def test_user_location(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rel: str, expected: str) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Path.home() reads USERPROFILE on Windows
    project = tmp_path / "proj"
    project.mkdir()
    f = _write(home / rel)
    assert _classify(project, [f])[f] == expected


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_only_immediate_children_of_rules_dir_are_rules(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    nested = _write(project / ".agents/rules/sub/x.md")
    assert _classify(project, [nested]).get(nested) != "rules"
