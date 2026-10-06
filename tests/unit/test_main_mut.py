"""Mutation-killing tests for interfaces.cli.main.

Each test reddens when a specific injected operator bug returns (verified by
scripts/mutation_probe.py). See test_heal_scope_safety.py for the heal-guard suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import reporails_cli.interfaces.cli.main as main_mod
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


def _write_long_rule(root: Path, rid: str, body: str) -> None:
    """Write a minimal rule.md under root/core/<slug>/ with the given long body."""
    slug = rid.lower().replace(":", "-")
    d = root / "core" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "rule.md").write_text(
        "---\n"
        f'id: "{rid}"\n'
        f'title: "Rule {rid}"\n'
        "category: structure\n"
        "type: deterministic\n"
        f"slug: {slug}\n"
        "match:\n"
        "  type: main\n"
        "---\n"
        f"{body}\n",
        encoding="utf-8",
    )


# ── check() option defaults (L77-L80) ────────────────────────────────


class TestCheckOptionDefaults:
    """The boolean flags default to False; flipping a default to True changes
    behavior for every invocation that omits the flag."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_boolean_flags_default_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Kills L77-L80 `False -> True`: the captured CheckInputs carries each
        # default straight through, so a flipped default shows up here.
        captured: dict[str, object] = {}
        monkeypatch.setattr(main_mod, "run_check_flow", lambda state: captured.setdefault("state", state))

        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0

        inputs = captured["state"].inputs  # type: ignore[attr-defined]
        assert inputs.ascii_mode is False  # kills L77
        assert inputs.strict is False  # kills L78
        assert inputs.verbose is False  # kills L79
        assert inputs.heal is False  # kills L80


# ── Hidden sub-apps (L180, L181) ─────────────────────────────────────


class TestHiddenSubApps:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_daemon_and_stopwords_are_hidden_from_help(self) -> None:
        # Kills L180/L181 `hidden=True -> False`: an un-hidden sub-app would
        # list its command name in the top-level help.
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "daemon" not in result.stdout
        assert "stopwords" not in result.stdout


# ── explain() severity (rule-level + per-check) ─────────────────


class TestExplainSeverity:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_rule_level_severity_is_shown(self) -> None:
        """`ails explain` must print the rule's own severity line, not silently drop it."""
        result = runner.invoke(app, ["explain", "CORE:S:0002"])  # rule.md severity: medium
        assert result.exit_code == 0
        assert "Severity: medium" in result.stdout

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_check_severity_inherits_the_rule_not_a_hardcoded_medium(self) -> None:
        """A check with no severity override in checks.yml must report the rule's own
        severity, never a hard-coded 'medium' regardless of what the rule really is."""
        result = runner.invoke(app, ["explain", "CORE:S:0003"])  # rule.md severity: high
        assert result.exit_code == 0
        assert "Severity: medium" not in result.stdout
        assert result.stdout.count("Severity: high") >= 2  # rule line + every check line


# ── explain() frontmatter split + markup (L148, L160) ────────────────


class TestExplainDescription:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_description_body_is_rendered(self) -> None:
        # A real rule.md is `---\n<frontmatter>\n---\n<body>` → split("---", 2)
        # yields exactly 3 parts, so the description is only extracted when the
        # length test is `>= 3`.
        # Kills L148 `>= -> >`: 3 > 3 is False, dropping the description body.
        result = runner.invoke(app, ["explain", "CORE:S:0024"])
        assert result.exit_code == 0
        assert "Import references in instruction files must resolve" in result.stdout

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_check_annotations_printed_literally(self) -> None:
        # The rule body / examples carry literal square brackets (e.g. the
        # `[mechanical]` check-type annotation) that Rich would consume as tags.
        # Kills L160 `markup=False -> True`: markup parsing eats the literal
        # `[mechanical]` (or raises), so it no longer appears verbatim.
        result = runner.invoke(app, ["explain", "CORE:S:0024"])
        assert result.exit_code == 0
        assert "[mechanical]" in result.stdout

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_long_description_is_shown_whole(self, tmp_path: Path) -> None:
        """A rule body past 500 characters is shown whole: every bundled rule body is longer
        than that, and a cut there dropped the antipatterns an agent reads the rule for (the
        `CORE:E:0004` "split into fragments" one among them)."""
        body = " ".join(f"word{i}" for i in range(120)) + " FINALTOKEN"  # ~800 chars
        _write_long_rule(tmp_path, "CORE:S:0900", body)

        result = runner.invoke(app, ["explain", "CORE:S:0900", "--rules", str(tmp_path)])

        assert result.exit_code == 0
        assert "FINALTOKEN" in result.stdout
        assert "…" not in result.stdout

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_pass_fail_section_is_not_repeated_in_the_description(self, tmp_path: Path) -> None:
        """The Pass / Fail examples render in their own block, so the description stops before
        them instead of printing them twice."""
        body = (
            "Intro line.\n\n## Antipatterns\n\n- **Bad**: shown in the description.\n\n"
            "## Pass / Fail\n\n### Pass\n\n~~~~markdown\nUse `ruff`.\n~~~~\n\n"
            "### Fail\n\n~~~~markdown\nLint.\n~~~~\n\n## Limitations\n\nMeasures words only.\n"
        )
        _write_long_rule(tmp_path, "CORE:S:0901", body)

        result = runner.invoke(app, ["explain", "CORE:S:0901", "--rules", str(tmp_path)])

        assert result.exit_code == 0
        assert "shown in the description" in result.stdout
        assert "Measures words only" in result.stdout
        assert result.stdout.count("Use `ruff`.") == 1
