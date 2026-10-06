"""One glob matcher: `**` spans zero or more directories, anchored or trailing-segment matching."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.utils.utils import glob_matches


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("path", "pattern", "anchored", "expected"),
    [
        (".claude/agents/a/b/c.md", ".claude/agents/**/*.md", True, True),
        (".claude/agents/c.md", ".claude/agents/**/*.md", True, True),
        (".claude/agents/c.txt", ".claude/agents/**/*.md", True, False),
        ("pkg/.claude/agents/c.md", ".claude/agents/**/*.md", True, False),
        ("pkg/.claude/CLAUDE.md", ".claude/CLAUDE.md", True, False),
        (".claude/CLAUDE.md", ".claude/CLAUDE.md", True, True),
        ("pkg/AGENTS.md", "AGENTS.md", False, True),
        ("AGENTS.md", "**/AGENTS.md", False, True),
        ("a/b/AGENTS.md", "**/AGENTS.md", False, True),
        ("AGENTS.md.bak", "AGENTS.md", False, False),
        (".gemini/extensions", ".gemini/extensions/**", True, False),
        (".gemini/extensions/x/y.json", ".gemini/extensions/**", True, True),
        ("/etc/codex/skills/a/SKILL.md", "/etc/codex/skills/**/*.md", True, True),
        ("/home/me/.claude/CLAUDE.md", "/home/me/.claude/CLAUDE.md", False, True),
        ("x/CLAUDE.md", "/home/me/.claude/CLAUDE.md", False, False),
        ("a.md", "", False, False),
    ],
)
def test_glob_matches(path: str, pattern: str, anchored: bool, expected: bool) -> None:
    assert glob_matches(path, pattern, anchored=anchored) is expected


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("src/a/b.tsx", "src/**/*.{ts,tsx}", True),
        ("src/a/b.ts", "src/**/*.{ts,tsx}", True),
        ("src/a/b.js", "src/**/*.{ts,tsx}", False),
        ("src/x.md", "src/{x}.md", False),
        ("src/{x}.md", "src/{x}.md", True),
        ("src/{{x}}.md", "src/{{x}}.md", True),
    ],
)
def test_glob_matches_expands_a_brace_group_with_a_comma(path: str, pattern: str, expected: bool) -> None:
    assert glob_matches(path, pattern) is expected


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_brace_alternatives_expand_only_a_comma_group() -> None:
    from reporails_cli.core.platform.utils.utils import brace_alternatives

    assert brace_alternatives("*.{ts,tsx}") == ("*.ts", "*.tsx")
    assert brace_alternatives("{a,b}/{c,d}") == ("a/c", "a/d", "b/c", "b/d")
    assert brace_alternatives("{x}") == ("{x}",)
    assert brace_alternatives("{{x}}") == ("{{x}}",)
