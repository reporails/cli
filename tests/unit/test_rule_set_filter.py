"""The rule set a run resolves filters every producer's findings once, where they merge.

A disabled rule and a rule an agent excludes are never reported, whichever producer found
them, nor are its remediation rows, hints, cross-file rows and cross-file counts; a rule one
agent of a multi-agent run leaves out stays when another agent keeps it; a token that names
no rule on disk is kept.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from reporails_cli.core.lint.client_checks import FORMATTING_RULE
from reporails_cli.core.lint.suppression import rule_aliases
from reporails_cli.core.pipeline.assemble import (
    AssembleInputs,
    assemble_result,
    lint_request_local,
    reported_local_findings,
)
from reporails_cli.core.platform.dto.diagnostics import (
    CrossFileCoordinate,
    CrossFileFinding,
    Diagnostic,
    FileAnalysis,
    Hint,
    ListedFinding,
    LocationFinding,
    LocationRelation,
    RemediationWorkflow,
    RulesetReport,
    WorkflowLocation,
)
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.dto.results import AgentConfig

_DISABLED = "CORE:E:0003"
_OTHER = "CORE:C:0042"


def _inputs(root, **overrides: object) -> AssembleInputs:
    base: dict[str, object] = {
        "m_findings": [],
        "content_findings": [],
        "client_findings": [],
        "ruleset_map": None,
        "scan_root": root,
        "filter_agents": None,
        "effective_agent": "claude",
        "lint_result": None,
    }
    base.update(overrides)
    return AssembleInputs(**base)  # type: ignore[arg-type]


def _project(tmp_path, disabled: tuple[str, ...] = (_DISABLED,)):
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nUse Alpine.js here.\n", encoding="utf-8")
    ails = tmp_path / ".ails"
    ails.mkdir()
    if disabled:
        (ails / "config.yml").write_text(f"disabled_rules: [{', '.join(disabled)}]\n", encoding="utf-8")
    return tmp_path


def _finding(rule: str, source: str = "client_check", check_id: str = "c") -> LocalFinding:
    return LocalFinding("CLAUDE.md", 3, "warning", rule, "m", source=source, check_id=check_id)


def _rules(result) -> list[str]:
    return [f.rule for f in result.findings]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_disabled_rule_drops_an_m_probe_finding(tmp_path):
    root = _project(tmp_path)
    inp = _inputs(root, m_findings=[_finding(_DISABLED, "m_probe"), _finding(_OTHER, "m_probe")])

    result = assemble_result(inp)

    assert _rules(result) == [_OTHER]
    assert result.stats.m_probe_count == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_disabled_rule_drops_a_content_check_finding(tmp_path):
    root = _project(tmp_path)
    inp = _inputs(root, content_findings=[_finding(_DISABLED), _finding(_OTHER)])

    assert _rules(assemble_result(inp)) == [_OTHER]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("check", ["format", "bold"])
def test_a_disabled_rule_drops_the_formatting_client_checks(tmp_path, check):
    root = _project(tmp_path)
    inp = _inputs(root, client_findings=[_finding(FORMATTING_RULE, check_id=check)])

    assert assemble_result(inp).findings == ()
    assert lint_request_local(inp)[0] == []
    assert reported_local_findings(inp) == ()


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_formatting_client_check_is_reported_when_its_rule_is_on(tmp_path):
    root = _project(tmp_path, disabled=())
    inp = _inputs(root, client_findings=[_finding(FORMATTING_RULE, check_id="bold")])

    result = assemble_result(inp)

    assert [(f.rule, f.check_id) for f in result.findings] == [(FORMATTING_RULE, "bold")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_agent_exclude_drops_a_client_check_finding(tmp_path, monkeypatch):
    root = _project(tmp_path, disabled=())
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.registry.get_agent_config",
        lambda _agent: AgentConfig(excludes=[FORMATTING_RULE]),
    )
    inp = _inputs(root, client_findings=[_finding(FORMATTING_RULE, check_id="format"), _finding(_OTHER)])

    assert _rules(assemble_result(inp)) == [_OTHER]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_token_that_names_no_rule_is_kept(tmp_path):
    root = _project(tmp_path)
    inp = _inputs(root, client_findings=[_finding("ambiguous_charge"), _finding("memory_frontmatter")])

    assert _rules(assemble_result(inp)) == ["ambiguous_charge", "memory_frontmatter"]


def _served(root):
    workflow = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=1,
                element="CLAUDE.md",
                kind="main",
                loading="session_start",
                files=("CLAUDE.md",),
                findings=(
                    LocationFinding(rule=_DISABLED, file="CLAUDE.md", line=3, pi=None),
                    LocationFinding(rule=_OTHER, file="CLAUDE.md", line=5, pi=None),
                ),
            ),
        ),
        listed=(ListedFinding(rule=_DISABLED, reason="r", count=1), ListedFinding(rule=_OTHER, reason="r", count=1)),
    )
    report = RulesetReport(
        per_file=(
            FileAnalysis(
                file="CLAUDE.md",
                diagnostics=(
                    Diagnostic(file="CLAUDE.md", line=3, severity="warning", rule=_DISABLED, message="m"),
                    Diagnostic(file="CLAUDE.md", line=5, severity="warning", rule=_OTHER, message="m"),
                ),
            ),
        )
    )
    return SimpleNamespace(report=report, hints=(), cross_file_coordinates=(), tier="pro", workflow=workflow)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_disabled_rule_drops_a_server_diagnostic_and_its_workflow_rows(tmp_path):
    root = _project(tmp_path)
    (root / "CLAUDE.md").write_text("# Project\n\nOne.\n\nTwo.\n\nThree.\n", encoding="utf-8")

    result = assemble_result(_inputs(root, lint_result=_served(root)))

    assert _rules(result) == [_OTHER]
    rows = [f.rule for loc in result.reply.workflow.locations for f in loc.findings]
    assert rows == [_OTHER]
    assert [entry.rule for entry in result.reply.workflow.listed] == [_OTHER]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_reported_local_findings_agree_with_the_assembled_result(tmp_path):
    root = _project(tmp_path)
    inp = _inputs(
        root,
        m_findings=[_finding(_DISABLED, "m_probe"), _finding(_OTHER, "m_probe")],
        client_findings=[_finding(FORMATTING_RULE, check_id="bold"), _finding("ambiguous_charge")],
    )

    assert [(f.rule, f.line) for f in reported_local_findings(inp)] == [
        (f.rule, f.line) for f in assemble_result(inp).findings
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("name", "silences"), [("CORE:E:0003", True), ("formatting-regime", True), ("bold", False)])
def test_a_directive_names_the_rule_id_or_its_slug(tmp_path, name, silences):
    root = _project(tmp_path, disabled=())
    (root / "CLAUDE.md").write_text(f"# Project\n\nUse Alpine.js here. <!-- ails-disable-line {name} -->\n")
    inp = _inputs(
        root, client_findings=[LocalFinding("CLAUDE.md", 3, "warning", FORMATTING_RULE, "m", check_id="bold")]
    )

    assert (assemble_result(inp).findings == ()) is silences


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_aliases_are_the_id_the_slug_and_the_short_token():
    assert {"CORE:S:0039", "heading_instruction", "heading-as-instruction"} <= rule_aliases("CORE:S:0039")
    assert rule_aliases("ambiguous_charge") == {"ambiguous_charge"}


def _exclude_per_agent(monkeypatch, excludes: dict[str, list[str]]) -> None:
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.registry.get_agent_config",
        lambda agent: AgentConfig(excludes=excludes.get(agent, [])),
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_rule_one_agent_excludes_stays_when_another_agent_of_the_run_keeps_it(tmp_path, monkeypatch):
    root = _project(tmp_path, disabled=())
    _exclude_per_agent(monkeypatch, {"claude": [FORMATTING_RULE]})
    inp = _inputs(
        root,
        rule_agents=("claude", "codex"),
        client_findings=[_finding(FORMATTING_RULE, check_id="format"), _finding(_OTHER)],
    )

    assert sorted(_rules(assemble_result(inp))) == sorted([FORMATTING_RULE, _OTHER])


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_rule_every_agent_of_the_run_excludes_is_dropped(tmp_path, monkeypatch):
    root = _project(tmp_path, disabled=())
    _exclude_per_agent(monkeypatch, {"claude": [FORMATTING_RULE], "codex": [FORMATTING_RULE]})
    inp = _inputs(
        root,
        rule_agents=("claude", "codex"),
        client_findings=[_finding(FORMATTING_RULE, check_id="format"), _finding(_OTHER)],
    )

    assert _rules(assemble_result(inp)) == [_OTHER]


_REPEAT = "CORE:C:0040"
_OVERLAP = "CORE:C:0044"


def _cross_file_served(report_rows):
    workflow = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=1,
                element="CLAUDE.md",
                kind="main",
                loading="session_start",
                files=("CLAUDE.md",),
                relations=(
                    LocationRelation(rule=_OVERLAP, file="CLAUDE.md", line=3, partner_file="a.md", partner_line=1),
                    LocationRelation(rule=_REPEAT, file="CLAUDE.md", line=5, partner_file="a.md", partner_line=2),
                ),
            ),
        ),
    )
    return SimpleNamespace(
        report=RulesetReport(cross_file=report_rows),
        hints=(
            Hint(file="CLAUDE.md", diagnostic_type=_OVERLAP, count=2),
            Hint(file="CLAUDE.md", diagnostic_type=_REPEAT, count=1),
        ),
        cross_file_coordinates=(
            CrossFileCoordinate("CLAUDE.md", "a.md", "overlap", 2),
            CrossFileCoordinate("CLAUDE.md", "a.md", "repetition", 1),
        ),
        tier="free",
        workflow=workflow,
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_disabled_rule_drops_its_workflow_relations(tmp_path):
    root = _project(tmp_path, disabled=(_OVERLAP,))
    served = _cross_file_served(())

    result = assemble_result(_inputs(root, lint_result=served))

    assert [r.rule for loc in result.reply.workflow.locations for r in loc.relations] == [_REPEAT]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_disabled_rule_drops_its_hints_cross_file_rows_and_coordinates(tmp_path):
    root = _project(tmp_path, disabled=(_OVERLAP,))
    rows = (
        CrossFileFinding("CLAUDE.md", "a.md", 3, 1, "overlap"),
        CrossFileFinding("CLAUDE.md", "a.md", 5, 2, "repetition"),
    )

    result = assemble_result(_inputs(root, lint_result=_cross_file_served(rows)))

    assert [h.diagnostic_type for h in result.hints] == [_REPEAT]
    assert [r.finding_type for r in result.cross_file] == ["repetition"]
    assert [c.finding_type for c in result.cross_file_coordinates] == ["repetition"]
    assert result.stats.cross_file_overlaps == 0
    assert result.stats.cross_file_repetitions == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_cross_file_data_stays_when_its_rules_are_on(tmp_path):
    root = _project(tmp_path, disabled=())
    rows = (CrossFileFinding("CLAUDE.md", "a.md", 3, 1, "overlap"),)

    result = assemble_result(_inputs(root, lint_result=_cross_file_served(rows)))

    assert len(result.hints) == 2
    assert len(result.cross_file) == 1
    assert len(result.cross_file_coordinates) == 2
    assert result.stats.cross_file_overlaps == 1
