"""Unit tests for focus_expansion — subagent→skill preload resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.focus_expansion import UnresolvedSkill, expand_focus


def _make_agent_file(root: Path, name: str, skills: list[str] | None = None) -> Path:
    agents_dir = root / ".claude" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    agent_file = agents_dir / f"{name}.md"
    fm_lines = [
        "---",
        f"name: {name}",
        "description: Test agent",
    ]
    if skills is not None:
        fm_lines.append(f"skills: {skills}")
    fm_lines.append("---")
    fm_lines.append("")
    fm_lines.append("# Body")
    agent_file.write_text("\n".join(fm_lines), encoding="utf-8")
    return agent_file


def _make_skill(root: Path, name: str) -> Path:
    skill_dir = root / ".claude" / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text(f"# {name}\n\nA skill.\n", encoding="utf-8")
    return skill_file


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_expand_focus_includes_declared_skills(tmp_path: Path) -> None:
    agent = _make_agent_file(tmp_path, "rule-writer", skills=["write-rule", "refine-rule"])
    write_rule = _make_skill(tmp_path, "write-rule")
    refine_rule = _make_skill(tmp_path, "refine-rule")
    expanded, unresolved = expand_focus({agent}, "claude", tmp_path)
    assert agent in expanded
    assert write_rule in expanded
    assert refine_rule in expanded
    assert unresolved == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_expand_focus_passes_through_when_no_skills_declared(tmp_path: Path) -> None:
    agent = _make_agent_file(tmp_path, "simple")
    expanded, unresolved = expand_focus({agent}, "claude", tmp_path)
    assert expanded == {agent}
    assert unresolved == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_expand_focus_reports_unresolved_skill_names(tmp_path: Path) -> None:
    agent = _make_agent_file(tmp_path, "agent", skills=["does-not-exist"])
    expanded, unresolved = expand_focus({agent}, "claude", tmp_path)
    assert expanded == {agent}
    assert unresolved == [UnresolvedSkill(declared_in=agent, skill_name="does-not-exist", agent="claude")]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_expand_focus_mixed_resolved_and_unresolved(tmp_path: Path) -> None:
    agent = _make_agent_file(tmp_path, "lead", skills=["orient", "self-check"])
    orient = _make_skill(tmp_path, "orient")
    expanded, unresolved = expand_focus({agent}, "claude", tmp_path)
    assert agent in expanded
    assert orient in expanded
    assert [u.skill_name for u in unresolved] == ["self-check"]
    assert unresolved[0].declared_in == agent
    assert unresolved[0].agent == "claude"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_expand_focus_handles_no_frontmatter(tmp_path: Path) -> None:
    agents_dir = tmp_path / ".claude" / "agents"
    agents_dir.mkdir(parents=True)
    agent = agents_dir / "no-fm.md"
    agent.write_text("# Just a body\n\nNo frontmatter here.\n", encoding="utf-8")
    expanded, unresolved = expand_focus({agent}, "claude", tmp_path)
    assert expanded == {agent}
    assert unresolved == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_expand_focus_handles_string_skills_field(tmp_path: Path) -> None:
    agents_dir = tmp_path / ".claude" / "agents"
    agents_dir.mkdir(parents=True)
    agent = agents_dir / "agent.md"
    agent.write_text(
        "---\nname: agent\nskills: write-rule, refine-rule\n---\n\nbody",
        encoding="utf-8",
    )
    _make_skill(tmp_path, "write-rule")
    _make_skill(tmp_path, "refine-rule")
    expanded, unresolved = expand_focus({agent}, "claude", tmp_path)
    names = {p.parent.name for p in expanded if p.name == "SKILL.md"}
    assert names == {"write-rule", "refine-rule"}
    assert unresolved == []
