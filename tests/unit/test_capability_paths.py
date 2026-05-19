"""Unit tests for capability_paths — per-capability targeting plumbing."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.capability_paths import (
    available_capabilities,
    canonicalize_capability,
    is_capability_keyword,
    list_capability_targets,
    resolve_capability,
)


def _make_skill(root: Path, name: str) -> Path:
    skill_dir = root / ".claude" / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text(f"# {name}\n\nA skill.\n", encoding="utf-8")
    return skill_file


def _make_rule(root: Path, name: str) -> Path:
    rules_dir = root / ".claude" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / f"{name}.md"
    rule_file.write_text(f"# {name}\n\nA rule.\n", encoding="utf-8")
    return rule_file


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_available_capabilities_for_claude_contains_expected_keys() -> None:
    caps = available_capabilities("claude")
    assert "main" in caps
    assert "skills" in caps
    assert "rules" in caps
    assert "agents" in caps


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_canonicalize_singular_to_plural() -> None:
    assert canonicalize_capability("skill", "claude") == "skills"
    assert canonicalize_capability("rule", "claude") == "rules"
    assert canonicalize_capability("agent", "claude") == "agents"
    assert canonicalize_capability("skills", "claude") == "skills"  # already canonical


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_canonicalize_unknown_capability_returns_none() -> None:
    assert canonicalize_capability("nonsense", "claude") is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_canonicalize_unknown_agent_returns_none() -> None:
    assert canonicalize_capability("skill", "nonexistent-agent") is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_is_capability_keyword_rejects_paths() -> None:
    assert not is_capability_keyword(".", "claude")
    assert not is_capability_keyword("./src/", "claude")
    assert not is_capability_keyword("src/foo.md", "claude")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_is_capability_keyword_accepts_known_capability() -> None:
    assert is_capability_keyword("skill", "claude")
    assert is_capability_keyword("skills", "claude")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_list_capability_targets_globs_skills(tmp_path: Path) -> None:
    _make_skill(tmp_path, "alpha")
    _make_skill(tmp_path, "beta")
    targets = list_capability_targets("claude", "skills", tmp_path)
    names = sorted(p.parent.name for p in targets)
    assert names == ["alpha", "beta"]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_list_capability_targets_globs_rules(tmp_path: Path) -> None:
    _make_rule(tmp_path, "git")
    _make_rule(tmp_path, "testing")
    targets = list_capability_targets("claude", "rules", tmp_path)
    stems = sorted(p.stem for p in targets)
    assert stems == ["git", "testing"]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_resolve_capability_skill_by_parent_dir_name(tmp_path: Path) -> None:
    expected = _make_skill(tmp_path, "alpha")
    resolved = resolve_capability("claude", "skills", "alpha", tmp_path)
    assert resolved is not None
    assert resolved.parent.name == expected.parent.name


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_resolve_capability_rule_by_stem(tmp_path: Path) -> None:
    expected = _make_rule(tmp_path, "git")
    resolved = resolve_capability("claude", "rules", "git", tmp_path)
    assert resolved is not None
    assert resolved.stem == expected.stem


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_resolve_capability_missing_returns_none(tmp_path: Path) -> None:
    _make_skill(tmp_path, "alpha")
    assert resolve_capability("claude", "skills", "nonexistent", tmp_path) is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_list_capability_targets_unknown_capability_returns_empty(tmp_path: Path) -> None:
    assert list_capability_targets("claude", "no-such-cap", tmp_path) == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_canonicalize_handles_empty_string() -> None:
    assert canonicalize_capability("", "claude") is None


# ── Virtual capability: `referenced` ──────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_canonicalize_referenced_singular_and_plural() -> None:
    """`referenced` and `references` both canonicalize to `referenced`, agent-agnostic."""
    for keyword in ("referenced", "references"):
        for agent in ("claude", "gemini", "codex"):
            assert canonicalize_capability(keyword, agent) == "referenced"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_is_capability_keyword_recognizes_referenced() -> None:
    """`referenced` and `references` are accepted as capability keywords by every agent."""
    for keyword in ("referenced", "references"):
        for agent in ("claude", "gemini"):
            assert is_capability_keyword(keyword, agent) is True


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_list_referenced_enumerates_link_reached_files(tmp_path: Path) -> None:
    """`ails check referenced` returns files reached only via `[text](path)` markdown links."""
    # Project root with a CLAUDE.md linking to arch.md
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nSee [arch](arch.md) for design.\n", encoding="utf-8")
    (tmp_path / "arch.md").write_text("# Arch\n", encoding="utf-8")
    # Opt-in to generic scanning so the link-walker runs
    (tmp_path / ".ails").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")

    targets = list_capability_targets("claude", "referenced", tmp_path)
    names = {p.name for p in targets}
    # arch.md was reached via markdown link → classified `referenced` → listed
    assert "arch.md" in names
    # CLAUDE.md is the source (file_type: main) — not referenced
    assert "CLAUDE.md" not in names


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_list_referenced_empty_when_no_links(tmp_path: Path) -> None:
    """No markdown links → no referenced targets, even with generic_scanning on."""
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nNo links here.\n", encoding="utf-8")
    (tmp_path / ".ails").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")

    assert list_capability_targets("claude", "referenced", tmp_path) == []
