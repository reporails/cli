"""Unit tests for the hook handler check: a parsed config, judged handler by handler."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from reporails_cli.core.lint.mechanical.checks import MECHANICAL_CHECKS
from reporails_cli.core.platform.dto.models import ClassifiedFile

# The shapes the shipped rules describe, as `args`.
GROUPED = {"block": "hooks", "handlers": "grouped"}
DIRECT = {"block": "hooks", "handlers": "direct", "default_type": "command"}
NAMED = {"named_hooks": True, "handlers": "grouped", "default_type": "command"}

NEEDS_COMMAND = {"select": {"type": ["command"]}, "require": {"non_empty": ["command"]}, "message": "no command"}
NEEDS_TYPE = {
    "select": {"has": ["type", "command", "url", "prompt", "server", "tool"]},
    "require": {"type": ["command", "http", "mcp_tool", "prompt", "agent"]},
    "message": "no valid type",
}


def _run(tmp_path: Path, name: str, body: str, args: dict[str, Any]) -> list[tuple[str, str]]:
    """Write one config file, run the check on it, return its (location, message) findings."""
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    result = MECHANICAL_CHECKS["hook_handlers"](tmp_path, args, [ClassifiedFile(path=target, file_type="hooks")])
    assert result.passed is not bool(result.occurrences)
    return list(result.occurrences or [])


def _lines(findings: list[tuple[str, str]]) -> list[int]:
    return [int(location.rsplit(":", 1)[1]) for location, _ in findings]


class TestOnlyHandlersAreJudged:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_empty_object_file_draws_no_finding(self, tmp_path: Path) -> None:
        """A hooks file that is just `{}` declares no handler, so nothing is reported."""
        assert _run(tmp_path, ".agents/hooks.json", "{}", {**NAMED, **NEEDS_COMMAND}) == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unrelated_array_of_objects_is_not_read_as_handlers(self, tmp_path: Path) -> None:
        """Objects in a top-level array beside the hook block are not command handlers."""
        body = json.dumps(
            {"version": 1, "hooks": {"stop": [{"command": "./a.sh"}]}, "extra": [{"name": "n"}, {"name": "m"}]}
        )
        assert _run(tmp_path, ".cursor/hooks.json", body, {**DIRECT, **NEEDS_COMMAND}) == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unrelated_objects_with_a_command_key_are_not_untyped_handlers(self, tmp_path: Path) -> None:
        """An array outside the hook block whose objects hold `command` draws no type finding."""
        body = json.dumps(
            {
                "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "./a.sh"}]}]},
                "x": [{"command": "y"}, {"command": "z"}],
            }
        )
        assert _run(tmp_path, ".claude/settings.json", body, {**GROUPED, **NEEDS_TYPE}) == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_command_handler_holding_a_nested_object_and_no_command_is_reported(self, tmp_path: Path) -> None:
        """A nested object inside the handler does not hide its missing command."""
        body = (
            '{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [\n'
            '  {"type": "command", "command": "./ok.sh"},\n'
            '  {"type": "command", "env": {"A": "1"}}\n'
            "]}]}}\n"
        )
        findings = _run(tmp_path, ".claude/settings.json", body, {**GROUPED, **NEEDS_COMMAND})
        assert findings == [(".claude/settings.json:3", "no command")]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_key_inside_a_nested_object_does_not_count_as_the_handlers_own(self, tmp_path: Path) -> None:
        """`command` inside a handler's `env` is not that handler's command."""
        body = json.dumps({"hooks": {"sessionStart": [{"type": "command", "env": {"command": "x", "bash": "y"}}]}})
        args = {**DIRECT, **NEEDS_COMMAND, "require": {"non_empty": ["bash", "powershell", "command", "exec"]}}
        assert _lines(_run(tmp_path, ".github/hooks/hooks.json", body, args)) == [1]


class TestHandlerPlacement:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_grouped_reads_handlers_inside_a_matcher_group(self, tmp_path: Path) -> None:
        """The group object is not a handler; the objects in its `hooks` list are."""
        body = '{"hooks": {"PreToolUse": [\n  {"matcher": "Bash", "hooks": [\n    {"type": "command"}\n  ]}\n]}}\n'
        assert _lines(_run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND})) == [3]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_grouped_reads_an_entry_without_a_hooks_list_as_a_handler(self, tmp_path: Path) -> None:
        """A handler listed directly under an event is judged like one inside a group."""
        body = '{"hooks": {"PreToolUse": [\n  {"type": "command", "matcher": "Edit"}\n]}}\n'
        assert _lines(_run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND})) == [2]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_direct_reads_every_listed_object_as_a_handler(self, tmp_path: Path) -> None:
        """With handlers listed directly, an object holding a `hooks` list is still one handler."""
        body = '{"hooks": {"stop": [\n  {"matcher": "Bash", "hooks": [{"type": "command", "command": "./a.sh"}]}\n]}}\n'
        assert _lines(_run(tmp_path, "hooks.json", body, {**DIRECT, **NEEDS_COMMAND})) == [2]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_named_hooks_reads_events_one_level_down(self, tmp_path: Path) -> None:
        """A file mapping hook names to their events is walked through each named hook."""
        body = (
            "{\n"
            '  "lint": {"PostToolUse": [{"matcher": "run_command", "hooks": [\n'
            '    {"type": "command"}\n'
            "  ]}]},\n"
            '  "reminder": {"PreInvocation": [\n'
            '    {"timeout": 10}\n'
            "  ]}\n"
            "}\n"
        )
        assert _lines(_run(tmp_path, ".agents/hooks.json", body, {**NAMED, **NEEDS_COMMAND})) == [3, 6]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_two_broken_handlers_give_two_findings_on_their_own_lines(self, tmp_path: Path) -> None:
        body = (
            "{\n"
            '  "hooks": {\n'
            '    "PreToolUse": [\n'
            '      {"matcher": "Bash", "hooks": [\n'
            '        {"type": "command", "timeout": 5},\n'
            '        {"type": "command", "command": "./ok.sh"}\n'
            "      ]}\n"
            "    ],\n"
            '    "Stop": [\n'
            '      {"hooks": [\n'
            "        {\n"
            '          "type": "command"\n'
            "        }\n"
            "      ]}\n"
            "    ]\n"
            "  }\n"
            "}\n"
        )
        assert _lines(_run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND})) == [5, 11]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_braces_and_quotes_inside_strings_do_not_shift_the_line(self, tmp_path: Path) -> None:
        body = (
            '{"note": "a } brace, a { brace and an escaped \\" quote",\n'
            ' "hooks": {"Stop": [{"hooks": [\n'
            '   {"type": "command", "command": "echo \\"{}\\""},\n'
            '   {"type": "command"}\n'
            " ]}]}}\n"
        )
        assert _lines(_run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND})) == [4]


class TestFilesThisCheckLeavesAlone:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        ("name", "body"),
        [
            pytest.param("settings.json", '{"hooks": {"Stop": [{"type": "command"}', id="invalid-json"),
            pytest.param("settings.json", "# not json at all", id="not-json"),
            pytest.param("config.toml", '[[hooks.Stop]\ntype = "command"\n', id="invalid-toml"),
            pytest.param("settings.json", '{"permissions": {"deny": ["Bash"]}}', id="no-hook-block"),
            pytest.param("settings.json", '{"hooks": {}}', id="empty-hook-block"),
            pytest.param("settings.json", '{"hooks": {"Stop": []}}', id="event-without-handlers"),
            pytest.param("settings.json", '{"hooks": {"Stop": {"type": "command"}}}', id="event-is-not-a-list"),
            pytest.param("settings.json", '{"hooks": ["Stop"]}', id="hook-block-is-not-an-object"),
            pytest.param("settings.json", '[{"type": "command"}]', id="file-is-an-array"),
            pytest.param("config.toml", 'approval_policy = "never"\n', id="toml-without-hooks"),
        ],
    )
    def test_no_finding(self, tmp_path: Path, name: str, body: str) -> None:
        """An unparseable file, or one with no hook block or no handlers, belongs to other rules."""
        assert _run(tmp_path, name, body, {**GROUPED, **NEEDS_COMMAND}) == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_missing_file_draws_no_finding(self, tmp_path: Path) -> None:
        gone = [ClassifiedFile(path=tmp_path / "settings.json", file_type="config")]
        result = MECHANICAL_CHECKS["hook_handlers"](tmp_path, {**GROUPED, **NEEDS_COMMAND}, gone)
        assert result.passed is True


class TestTomlHooks:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_toml_command_handler_without_command_is_reported_on_its_table_line(self, tmp_path: Path) -> None:
        body = (
            'approval_policy = "on-request"\n'
            "\n"
            "[[hooks.PreToolUse]]\n"
            'matcher = "^Bash$"\n'
            "\n"
            "[[hooks.PreToolUse.hooks]]\n"
            'type = "command"\n'
            'command = "./scripts/guard.sh"\n'
            "\n"
            "[[hooks.PreToolUse.hooks]]\n"
            'type = "command"\n'
            "timeout = 30\n"
        )
        findings = _run(tmp_path, ".codex/config.toml", body, {**GROUPED, **NEEDS_COMMAND})
        assert findings == [(".codex/config.toml:10", "no command")]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_toml_handlers_in_later_groups_keep_their_own_lines(self, tmp_path: Path) -> None:
        body = (
            "[[hooks.PreToolUse]]\n"
            'matcher = "Bash"\n'
            "[[hooks.PreToolUse.hooks]]\n"
            'type = "command"\n'
            'notes = """\n'
            "[[hooks.PreToolUse.hooks]]\n"
            '"""\n'
            "[[hooks.PreToolUse]]\n"
            'matcher = "Edit"\n'
            "[[hooks.PreToolUse.hooks]]\n"
            'type = "command"\n'
            "[[hooks.Stop]]\n"
            'hooks = [{ type = "command", command = "./done.sh" }, { type = "command" }]\n'
        )
        assert _lines(_run(tmp_path, "config.toml", body, {**GROUPED, **NEEDS_COMMAND})) == [3, 10, 13]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_toml_with_valid_hooks_draws_no_finding(self, tmp_path: Path) -> None:
        body = '[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = "command"\ncommand = "./done.sh"\n'
        assert _run(tmp_path, "config.toml", body, {**GROUPED, **NEEDS_COMMAND}) == []


class TestTypeRequirement:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_untyped_handler_is_reported_when_a_type_is_required(self, tmp_path: Path) -> None:
        body = (
            '{"hooks": {"Stop": [{"hooks": [\n'
            ' {"type": "command", "command": "a"},\n'
            ' {"command": "b"},\n'
            ' {"type": "shell", "command": "c"}\n'
            "]}]}}"
        )
        assert _lines(_run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_TYPE})) == [3, 4]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_untyped_handler_is_valid_where_it_runs_as_the_default_type(self, tmp_path: Path) -> None:
        body = (
            '{"hooks": {"stop": [\n'
            ' {"command": "a"},\n'
            ' {"type": "prompt", "prompt": "p"},\n'
            ' {"type": "shell", "command": "c"}\n'
            "]}}"
        )
        args = {**DIRECT, "require": {"type": ["command", "prompt"]}, "message": "bad type"}
        assert _lines(_run(tmp_path, "hooks.json", body, args)) == [4]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_type_that_is_not_a_string_is_reported(self, tmp_path: Path) -> None:
        body = '{"hooks": {"stop": [{"type": 3, "command": "a"}]}}'
        args = {**DIRECT, "require": {"type": ["command", "prompt"]}, "message": "bad type"}
        assert _lines(_run(tmp_path, "hooks.json", body, args)) == [1]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_select_has_leaves_out_objects_carrying_none_of_the_keys(self, tmp_path: Path) -> None:
        """An object with no handler field at all is not judged by a rule that selects on those fields."""
        body = '{"hooks": {"Stop": [{"matcher": "Bash"}, {"hooks": [{"timeout": 5}]}]}}'
        assert _run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_TYPE}) == []


class TestFieldRequirement:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("command", ['""', '"   "', "null", "3", '["npm", "test"]'])
    def test_blank_or_non_string_value_does_not_satisfy_non_empty(self, tmp_path: Path, command: str) -> None:
        body = f'{{"hooks": {{"Stop": [{{"type": "command", "command": {command}}}]}}}}'
        assert _lines(_run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND})) == [1]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_any_listed_key_satisfies_non_empty(self, tmp_path: Path) -> None:
        body = (
            '{"hooks": {"preToolUse": [\n'
            ' {"bash": "./a.sh"},\n'
            ' {"type": "command", "powershell": "./a.ps1"},\n'
            ' {"type": "command", "cwd": "scripts"}\n'
            "]}}"
        )
        args = {**DIRECT, **NEEDS_COMMAND, "require": {"non_empty": ["bash", "powershell", "command", "exec"]}}
        assert _lines(_run(tmp_path, "hooks.json", body, args)) == [4]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_handlers_of_other_types_are_not_selected(self, tmp_path: Path) -> None:
        body = '{"hooks": {"Stop": [{"hooks": [{"type": "prompt", "prompt": "check"}, {"type": "http", "url": "u"}]}]}}'
        assert _run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND}) == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_untyped_handler_is_not_a_command_handler_without_a_default_type(self, tmp_path: Path) -> None:
        body = '{"hooks": {"Stop": [{"hooks": [{"timeout": 5}]}]}}'
        assert _run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND}) == []
        assert _lines(
            _run(tmp_path, "settings.json", body, {**GROUPED, **NEEDS_COMMAND, "default_type": "command"})
        ) == [1]


class TestPatternRequirement:
    HARDCODED: ClassVar[dict[str, Any]] = {
        "select": {"type": ["command"]},
        "require": {"not_matches": {"command": r'^"?/(?:home|Users|tmp|var|etc|opt)/'}},
        "message": "hardcoded path",
    }
    USES_VARIABLE: ClassVar[dict[str, Any]] = {
        "select": {"type": ["command"]},
        "require": {"matches": {"command": r"\$CLAUDE_PROJECT_DIR|\$\{CLAUDE_PROJECT_DIR\}"}},
        "any_handler": True,
        "message": "no project dir",
    }

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_not_matches_reports_each_handler_whose_value_matches(self, tmp_path: Path) -> None:
        body = (
            '{"hooks": {"afterFileEdit": [\n'
            ' {"command": ".cursor/hooks/format.sh"},\n'
            ' {"command": "/home/user/project/audit.sh"},\n'
            ' {"command": "\\"/Users/me/project/audit.sh\\" --fast"},\n'
            ' {"type": "prompt", "prompt": "/home/ is fine here"},\n'
            ' {"timeout": 30}\n'
            "]}}"
        )
        assert _lines(_run(tmp_path, "hooks.json", body, {**DIRECT, **self.HARDCODED})) == [3, 4]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_any_handler_passes_when_one_judged_handler_matches(self, tmp_path: Path) -> None:
        body = (
            '{"hooks": {"Stop": [{"hooks": ['
            '{"type": "command", "command": "/home/u/a.sh"}, '
            '{"type": "command", "command": "\\"$CLAUDE_PROJECT_DIR\\"/b.sh"}'
            "]}]}}"
        )
        assert _run(tmp_path, "settings.json", body, {**GROUPED, **self.USES_VARIABLE}) == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_any_handler_gives_one_finding_on_the_first_judged_handler(self, tmp_path: Path) -> None:
        body = (
            '{"hooks": {"Stop": [{"hooks": [\n'
            ' {"type": "prompt", "prompt": "check"},\n'
            ' {"type": "command", "command": "/home/u/a.sh"},\n'
            ' {"type": "command", "command": "./b.sh"}\n'
            ']}]},\n "statusLine": {"type": "command", "command": "$CLAUDE_PROJECT_DIR/status.sh"}}'
        )
        findings = _run(tmp_path, "settings.json", body, {**GROUPED, **self.USES_VARIABLE})
        assert findings == [("settings.json:3", "no project dir")]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_any_handler_is_silent_when_no_handler_is_judged(self, tmp_path: Path) -> None:
        """Handlers with no command to judge leave a pattern rule with nothing to report."""
        body = '{"hooks": {"Stop": [{"hooks": [{"type": "prompt", "prompt": "check"}, {"type": "command"}]}]}}'
        assert _run(tmp_path, "settings.json", body, {**GROUPED, **self.USES_VARIABLE}) == []


class TestCheckContract:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        ("args", "problem"),
        [
            pytest.param({**GROUPED, **NEEDS_COMMAND, "message": ""}, "no message", id="no-message"),
            pytest.param({**NEEDS_COMMAND, "handlers": "nested"}, "handlers must be", id="unknown-placement"),
            pytest.param({**GROUPED, "message": "m"}, "require must hold", id="no-require"),
            pytest.param(
                {**GROUPED, "message": "m", "require": {"type": ["command"], "non_empty": ["command"]}},
                "require must hold",
                id="two-require-forms",
            ),
            pytest.param(
                {**GROUPED, "message": "m", "require": {"matches": {"command": "("}}},
                "invalid pattern",
                id="bad-pattern",
            ),
            pytest.param(
                {**GROUPED, "message": "m", "require": {"matches": "command"}}, "one key to one pattern", id="bad-form"
            ),
        ],
    )
    def test_unusable_args_fail_with_a_named_problem(self, tmp_path: Path, args: dict[str, Any], problem: str) -> None:
        result = MECHANICAL_CHECKS["hook_handlers"](tmp_path, args, [])
        assert result.passed is False
        assert result.message.startswith("hook_handlers: ")
        assert problem in result.message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_single_value_is_read_like_a_one_item_list(self, tmp_path: Path) -> None:
        """`type: command` means the same as `type: [command]`; it is never matched as part of a longer word."""
        body = '{"hooks": {"Stop": [{"hooks": [\n {"type": "comm"},\n {"type": "command"}\n]}]}}'
        args = {**GROUPED, "select": {"type": "command"}, "require": {"non_empty": "command"}, "message": "m"}
        assert _lines(_run(tmp_path, "settings.json", body, args)) == [3]
        typed = {**GROUPED, "select": {"has": "type"}, "require": {"type": "command"}, "message": "m"}
        assert _lines(_run(tmp_path, "settings.json", body, typed)) == [2]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_file_outside_the_project_is_reported_by_its_full_path(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        outside = tmp_path / "home" / "settings.json"
        outside.parent.mkdir()
        outside.write_text('{"hooks": {"Stop": [{"type": "command"}]}}', encoding="utf-8")
        result = MECHANICAL_CHECKS["hook_handlers"](
            project, {**GROUPED, **NEEDS_COMMAND}, [ClassifiedFile(path=outside, file_type="config")]
        )
        assert result.occurrences == [(f"{outside}:1", "no command")]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_every_target_file_is_checked(self, tmp_path: Path) -> None:
        for name in ("a.json", "b.json"):
            (tmp_path / name).write_text('{"hooks": {"Stop": [{"type": "command"}]}}', encoding="utf-8")
        files = [ClassifiedFile(path=tmp_path / name, file_type="hooks") for name in ("a.json", "b.json")]
        result = MECHANICAL_CHECKS["hook_handlers"](tmp_path, {**GROUPED, **NEEDS_COMMAND}, files)
        assert [location for location, _ in result.occurrences or []] == ["a.json:1", "b.json:1"]


class TestTomlLineBreaks:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_other_separator_characters_inside_a_value_do_not_shift_the_line(self, tmp_path: Path) -> None:
        """Only a newline starts a new line: a form feed or line-separator character in a string does not."""
        body = 'note = "a\\fb\u2028c"\n[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = "command"\n'
        assert _lines(_run(tmp_path, "config.toml", body, {**GROUPED, **NEEDS_COMMAND})) == [3]
