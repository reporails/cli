"""Per-agent capability-level detection.

`detect_features_filesystem` used to gate L3-L6 on Claude's own paths
(`.claude/rules`, `.claude/skills`, `.claude/agents`, `.mcp.json`,
`.claude/settings.json`) no matter which agent a project used. A Copilot,
Codex or Antigravity project capped at L2 and a Cursor project capped at L5
even with the matching capability on disk, because the gate never looked at
that agent's own declared file types. These tests pin Claude's own level
(regression) and prove each other agent's own surfaces now drive its level.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import detect_agents, detect_single_agent
from reporails_cli.core.discovery.features import (
    _agent_has_hooks,
    _agent_has_surface,
    detect_features_filesystem,
)
from reporails_cli.core.platform.dto.models import Level
from reporails_cli.core.platform.policy.levels import determine_level_from_gates

SKILL = """---
name: deploy
description: Deploy the service to staging. Use when the user asks to deploy.
---

Run `make deploy-staging`.
"""

AGENT_MD = """---
name: reviewer
description: Reviews pull requests.
---

Review diffs and report defects.
"""


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _level(project: Path) -> Level:
    agents = detect_agents(project)
    features = detect_features_filesystem(project, agents=agents)
    return determine_level_from_gates(features)


class TestClaudeLevelPinned:
    """Claude's own level must not change — the fix drives gates from config.yml,
    it does not change what Claude itself reaches."""

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_bare_main_file_is_l1(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        assert _level(tmp_path) == Level.L1

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_richest_claude_layout_is_l6(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".claude/rules/testing.md", '---\npaths: ["tests/**/*.py"]\n---\n\nUse pytest.\n')
        _write(tmp_path, ".claude/skills/deploy/SKILL.md", SKILL)
        _write(tmp_path, ".claude/agents/reviewer.md", AGENT_MD)
        _write(
            tmp_path,
            ".claude/settings.json",
            '{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "./guard.sh"}]}]}}',
        )
        assert _level(tmp_path) == Level.L6

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_settings_json_without_hooks_key_grants_no_governance(self, tmp_path: Path) -> None:
        """A `.claude/settings.json` with no `hooks` key must not itself grant
        governance — only its existence changed, not the file's content."""
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".claude/settings.json", '{"permissions": {"deny": ["Read(./.env)"]}}')
        agents = detect_agents(tmp_path)
        features = detect_features_filesystem(tmp_path, agents=agents)
        assert features.has_hooks is False


class TestLevelCreditsHighestPresent:
    """A project reaches the level its richest surface supports even when a
    lower rung is missing — the ladder credits the highest capability present,
    not the highest contiguous run. Regression: a Claude project with skills,
    sub-agents and memory but an empty `.claude/rules/` was collapsing to L2
    because the L3 gate failed and the walk required every lower rung."""

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_skills_and_agents_without_rules_reach_l5(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".claude/skills/deploy/SKILL.md", SKILL)
        _write(tmp_path, ".claude/agents/reviewer.md", AGENT_MD)
        assert _level(tmp_path) == Level.L5

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_mcp_config_alone_does_not_reach_l6(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".mcp.json", '{"mcpServers": {"db": {"command": "db-mcp"}}}')
        assert _level(tmp_path) == Level.L1

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_hooks_alone_reach_l6(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(
            tmp_path,
            ".claude/settings.json",
            '{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "./guard.sh"}]}]}}',
        )
        assert _level(tmp_path) == Level.L6

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_one_skill_alone_reaches_l4(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".claude/skills/deploy/SKILL.md", SKILL)
        assert _level(tmp_path) == Level.L4

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_memory_above_a_gap_reaches_l7(self, tmp_path: Path) -> None:
        """Skills (L4) + sub-agents (L5) + memory (L7) with no path-scoped rules
        (L3) and no governance (L6) still reaches L7 — the real shape of a
        project that keeps rule-governance out of `.claude/rules/`."""
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".claude/skills/deploy/SKILL.md", SKILL)
        _write(tmp_path, ".claude/agents/reviewer.md", AGENT_MD)
        _write(tmp_path, ".claude/agent-memory/reviewer/MEMORY.md", "# Note\n\nRemembered fact.\n")
        assert _level(tmp_path) == Level.L7


class TestCopilotReachesL6:
    """Red-first: a Copilot fixture with applyTo, skills, agents and hooks reaches
    at least L6 — previously capped at L2 (CORE gate read only Claude paths)."""

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_richest_copilot_layout_reaches_l6(self, tmp_path: Path) -> None:
        _write(tmp_path, ".github/copilot-instructions.md", "# Project\n")
        _write(
            tmp_path,
            ".github/instructions/python.instructions.md",
            '---\napplyTo: "**/*.py"\n---\n\nUse type hints.\n',
        )
        _write(tmp_path, ".github/skills/deploy/SKILL.md", SKILL)
        _write(tmp_path, ".github/agents/reviewer.agent.md", AGENT_MD)
        _write(
            tmp_path,
            ".github/hooks/pre.json",
            '{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./guard.sh"}]}}',
        )
        level = _level(tmp_path)
        assert level in (Level.L6, Level.L7), f"expected at least L6, got {level.value}"


class TestCodexAndAntigravityNestedScoping:
    """Codex and Antigravity: neither declares a `scope:
    path_scoped` file type (only Claude, Cursor, Copilot do); both scope
    instructions per directory through a nested on-demand instruction type
    instead (`nested_context`). L3 credit for those two now comes from a real
    nested instruction file below root, not a path-scoped rule file."""

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_codex_root_only_stays_l1(self, tmp_path: Path) -> None:
        """A Codex project with only a root AGENTS.md — no nested file, no
        skills, no hooks — stays at L1: the nested-instruction fallback must
        not fire on the root file itself."""
        _write(tmp_path, "AGENTS.md", "# Project\n\nAlways run tests before committing.\n")
        assert _level(tmp_path) == Level.L1

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_codex_nested_agents_md_grants_l3(self, tmp_path: Path) -> None:
        """A real `pkg/AGENTS.md` below root is Codex's own equivalent of a
        path-scoped rule — it must grant L3 on its own, before skills/agents/
        hooks enter the picture."""
        _write(tmp_path, "AGENTS.md", "# Project\n")
        _write(tmp_path, "pkg/AGENTS.md", "# Pkg\n\nUse pnpm in this package.\n")
        features = detect_features_filesystem(tmp_path, agents=detect_agents(tmp_path))
        assert features.has_path_scoped_rules is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_richest_codex_layout_reaches_l6(self, tmp_path: Path) -> None:
        """The richest layout Codex documents — root + nested AGENTS.md,
        skills, its own `.codex/agents/*.toml` sub-agents, and hooks — reaches
        L6, the same ceiling Claude/Copilot/Cursor reach on their own richest
        layouts."""
        _write(tmp_path, "AGENTS.md", "# Project\n\nAlways run tests before committing.\n")
        _write(tmp_path, "pkg/AGENTS.md", "# Pkg\n\nUse pnpm in this package.\n")
        _write(tmp_path, ".agents/skills/release/SKILL.md", SKILL)
        _write(tmp_path, ".codex/agents/reviewer.toml", 'name = "reviewer"\ndescription = "Reviews pull requests"\n')
        _write(tmp_path, ".codex/hooks.json", '{"hooks": {"PostToolUse": [{"matcher": "Bash"}]}}')
        _write(tmp_path, ".codex/config.toml", '[mcp_servers.docs]\ncommand = "npx"\n')
        level = _level(tmp_path)
        assert level == Level.L6, f"expected L6, got {level.value}"

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_antigravity_full_layout_reaches_its_full_level(self, tmp_path: Path) -> None:
        """An Antigravity fixture with a nested GEMINI.md, skills, agents and
        hooks reaches L6 — previously capped at L2 with none of this credited."""
        _write(tmp_path, "GEMINI.md", "# Project\n\nAlways run tests before committing.\n")
        _write(tmp_path, "pkg/GEMINI.md", "# Pkg\n\nUse pnpm in this package.\n")
        _write(tmp_path, ".agents/skills/release/SKILL.md", SKILL)
        _write(tmp_path, ".agents/agents/reviewer.md", AGENT_MD)
        _write(tmp_path, ".agents/hooks.json", '{"hooks": {"BeforeTool": [{"matcher": "run_shell_command"}]}}')
        level = _level(tmp_path)
        assert level == Level.L6, f"expected L6, got {level.value}"

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_cursor_nested_file_alone_grants_no_l3_credit(self, tmp_path: Path) -> None:
        """Cursor declares its own `scope: path_scoped` rules type, so it must
        keep exactly today's L3 gate — a nested AGENTS.md with no `.cursor/
        rules/*.mdc` must NOT fall back to the Codex/Antigravity nested-credit
        path. Isolated to Cursor alone via `detect_single_agent` — a bare
        `AGENTS.md` fixture also matches Codex's and Antigravity's own `main`
        pattern, and asserting through `detect_agents` would pick up their
        (correct) nested-fallback credit instead of testing Cursor's own gate."""
        _write(tmp_path, "AGENTS.md", "# Project\n")
        _write(tmp_path, "pkg/AGENTS.md", "# Pkg\n")
        cursor_only = [detect_single_agent(tmp_path, "cursor")]
        features = detect_features_filesystem(tmp_path, agents=cursor_only)
        assert features.has_path_scoped_rules is False

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_copilot_nested_file_alone_grants_no_l3_credit(self, tmp_path: Path) -> None:
        """Copilot also declares its own `scope: path_scoped` rules type
        (`applyTo`), so a cross-agent nested AGENTS.md with no `.github/
        instructions/*.instructions.md` must not grant L3 either."""
        _write(tmp_path, ".github/copilot-instructions.md", "# Project\n")
        _write(tmp_path, "pkg/AGENTS.md", "# Pkg\n")
        copilot_only = [detect_single_agent(tmp_path, "copilot")]
        features = detect_features_filesystem(tmp_path, agents=copilot_only)
        assert features.has_path_scoped_rules is False


class TestPerAgentSurfaceHelpers:
    """The surface helpers read each agent's own config.yml — not a Claude path."""

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_cursor_mcp_json_detected(self, tmp_path: Path) -> None:
        _write(tmp_path, ".cursor/mcp.json", '{"mcpServers": {"db": {"command": "db-mcp"}}}')
        assert _agent_has_surface(tmp_path, "cursor", "mcp") is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_codex_dedicated_hooks_file_detected(self, tmp_path: Path) -> None:
        """Codex's hooks live in their own `.codex/hooks.json` — never read by the
        old Claude-only `.claude/hooks` / `.githooks` / settings.json check."""
        _write(tmp_path, ".codex/hooks.json", '{"hooks": {"PreToolUse": [{"matcher": "Bash"}]}}')
        assert _agent_has_hooks(tmp_path, "codex") is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_antigravity_dedicated_hooks_file_detected(self, tmp_path: Path) -> None:
        """Antigravity's hooks live at `.agents/hooks.json` — a different file from
        its own `.gemini/settings.json` config, and from Claude's hooks path."""
        _write(tmp_path, ".agents/hooks.json", '{"hooks": {"BeforeTool": [{"matcher": "run_shell_command"}]}}')
        assert _agent_has_hooks(tmp_path, "antigravity") is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_copilot_skills_dir_detected(self, tmp_path: Path) -> None:
        _write(tmp_path, ".github/skills/deploy/SKILL.md", SKILL)
        assert _agent_has_surface(tmp_path, "copilot", "skills") is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_agent_with_no_hooks_surface_declared_is_false(self, tmp_path: Path) -> None:
        assert _agent_has_hooks(tmp_path, "not-a-real-agent") is False


class TestLevelFollowsTheCheckedAgent:
    """One agent's hooks or memory never raise the level of a check for another."""

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_git_hooks_folder_adds_no_level(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
        assert _level(tmp_path) == Level.L1

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_claude_hooks_folder_does_not_govern_a_codex_project(self, tmp_path: Path) -> None:
        _write(tmp_path, "AGENTS.md", "# Project\n")
        _write(tmp_path, ".claude/hooks/x.sh", "#!/bin/sh\nexit 0\n")
        codex_only = [detect_single_agent(tmp_path, "codex")]
        features = detect_features_filesystem(tmp_path, agents=codex_only)
        assert features.has_hooks is False
        assert determine_level_from_gates(features) != Level.L6

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_claude_auto_memory_counts_for_claude_only(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.core.discovery.features import claude_project_folder_name

        project = tmp_path / "proj"
        project.mkdir()
        home = tmp_path / "home"
        _write(home, f".claude/projects/{claude_project_folder_name(project)}/memory/MEMORY.md", "# Memory\n")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))  # Path.home() reads USERPROFILE on Windows
        monkeypatch.setattr(Path, "home", lambda: home)
        _write(project, "CLAUDE.md", "# Project\n")
        _write(project, "AGENTS.md", "# Project\n")
        claude = detect_features_filesystem(project, agents=[detect_single_agent(project, "claude")])
        codex = detect_features_filesystem(project, agents=[detect_single_agent(project, "codex")])
        assert determine_level_from_gates(claude) == Level.L7
        assert determine_level_from_gates(codex) != Level.L7

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_repo_agent_memory_folder_reaches_l7(self, tmp_path: Path) -> None:
        _write(tmp_path, "CLAUDE.md", "# Project\n")
        _write(tmp_path, ".claude/agent-memory/reviewer/MEMORY.md", "# Memory\n")
        assert _level(tmp_path) == Level.L7
