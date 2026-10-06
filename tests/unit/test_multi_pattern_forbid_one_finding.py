"""A rule that forbids something behind a gate reports the forbidden thing once, on its own line."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.regex import run_checks

_RULES = Path(__file__).resolve().parents[2] / "framework" / "rules"

_HOOKS = [
    ("claude/hook-valid-event-types", "CLAUDE:S:0005", ".claude/settings.json", "PostToolUze", "PostToolUse"),
    ("cursor/hook-valid-event-types", "CURSOR:S:0002", ".cursor/hooks.json", "postToolUze", "postToolUse"),
    ("codex/hook-valid-event-types", "CODEX:S:0003", ".codex/hooks.json", "PostToolUze", "PostToolUse"),
    ("copilot/hook-valid-event-types", "COPILOT:S:0003", ".github/hooks/hooks.json", "PostToolUze", "PostToolUse"),
]


def _lines(rule_dir: str, rule: str, root: Path, rel: str) -> list[int]:
    findings = run_checks([_RULES / rule_dir / "checks.yml"], root, instruction_files=[root / rel])
    return sorted(f.line for f in findings if f.rule == rule)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _config(events: list[str]) -> str:
    body = ",\n".join(f'    "{e}": [{{"command": "x"}}]' for e in events)
    return '{\n  "version": 1,\n  "hooks": {\n' + body + "\n  }\n}\n"


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("rule_dir", "rule", "rel", "typo", "good"), _HOOKS)
def test_misspelt_hook_event_is_reported_once_on_its_line(
    tmp_path: Path, rule_dir: str, rule: str, rel: str, typo: str, good: str
) -> None:
    _write(tmp_path, rel, _config([good, typo]))
    assert _lines(rule_dir, rule, tmp_path, rel) == [5]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("rule_dir", "rule", "rel", "typo", "good"), _HOOKS)
def test_two_misspelt_hook_events_are_two_findings(
    tmp_path: Path, rule_dir: str, rule: str, rel: str, typo: str, good: str
) -> None:
    _write(tmp_path, rel, _config([typo, good, typo + "x"]))
    assert _lines(rule_dir, rule, tmp_path, rel) == [4, 6]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("rule_dir", "rule", "rel", "typo", "good"), _HOOKS)
def test_misspelt_hook_event_on_one_line_is_one_finding(
    tmp_path: Path, rule_dir: str, rule: str, rel: str, typo: str, good: str
) -> None:
    _write(tmp_path, rel, f'{{"hooks": {{"{good}": [{{"command": "x"}}], "{typo}": [{{"command": "x"}}]}}}}\n')
    assert _lines(rule_dir, rule, tmp_path, rel) == [1]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_skill_with_both_gates_closed_is_one_finding(tmp_path: Path) -> None:
    rel = ".claude/skills/s/SKILL.md"
    _write(tmp_path, rel, "---\nname: s\ndisable-model-invocation: true\nuser-invocable: false\n---\nBody\n")
    assert len(_lines("core/skill-invocation-reachable", "CORE:C:0057", tmp_path, rel)) == 1
