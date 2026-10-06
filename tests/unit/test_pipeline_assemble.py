"""Red-first tests for the surface-agnostic assemble core shared by CLI and MCP.

`core/pipeline/assemble.py` is the shared post-lint spine both the CLI check flow
and the MCP `validate` surface consume, so memory validation and
capability-level determination run by construction on both. These
tests pin:

- a broken memory link on a file in the ruleset map surfaces as a finding.
- the computed level is threaded onto the merged result (not left at the
  ``merge_results`` default of ``Level.L0``).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from reporails_cli.core.pipeline.assemble import AssembleInputs, assemble_result
from reporails_cli.core.platform.dto.models import Level


def _inputs(**overrides: object) -> AssembleInputs:
    base: dict[str, object] = {
        "m_findings": [],
        "content_findings": [],
        "client_findings": [],
        "ruleset_map": None,
        "scan_root": None,
        "filter_agents": None,
        "effective_agent": "",
        "lint_result": None,
        "alias_fn": lambda _rule: set(),
    }
    base.update(overrides)
    return AssembleInputs(**base)  # type: ignore[arg-type]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_assemble_folds_memory_validation(tmp_path):
    """Surface 1: a broken memory link on a ruleset-map file surfaces in the merged findings."""
    memory_file = tmp_path / "MEMORY.md"
    memory_file.write_text("# Memory\n\n- [broken](does-not-exist.md)\n", encoding="utf-8")
    ruleset_map = SimpleNamespace(files=[SimpleNamespace(path=str(memory_file), type="memory")])

    result = assemble_result(_inputs(ruleset_map=ruleset_map, scan_root=tmp_path))

    assert any("Broken memory link" in f.message for f in result.findings), (
        "memory-validation must run in the shared assemble core"
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_assemble_threads_computed_level(tmp_path, monkeypatch):
    """Surface 3: the computed capability level is set on the result, not the merge default."""
    monkeypatch.setattr(
        "reporails_cli.core.pipeline.assemble.determine_level_from_gates",
        lambda _features: Level.L3,
    )

    result = assemble_result(_inputs(scan_root=tmp_path))

    assert result.level == Level.L3, "the assemble core must thread the computed level onto the result"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_assemble_unpacks_lint_result_and_attaches_workflow(tmp_path):
    """`AssembleInputs.lint_result` is unpacked once here: report/hints/
    cross_file_coordinates/tier feed the merge, and a non-None `workflow` is attached onto
    the result -- both shells stop hand-unpacking and re-attaching it themselves."""
    from reporails_cli.core.platform.dto.diagnostics import RemediationWorkflow

    sentinel_workflow = RemediationWorkflow(summary="do the thing")
    lint_result = SimpleNamespace(
        report=None,
        hints=(),
        cross_file_coordinates=(),
        tier="pro",
        workflow=sentinel_workflow,
    )

    result = assemble_result(_inputs(scan_root=tmp_path, lint_result=lint_result))

    assert result.tier == "pro"
    assert result.workflow is sentinel_workflow


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_assemble_leaves_workflow_none_when_lint_result_absent(tmp_path):
    """No lint result (offline) → no workflow attached, no crash on the `None` unpack."""
    result = assemble_result(_inputs(scan_root=tmp_path, lint_result=None))

    assert result.workflow is None


def _subagent_credential_findings() -> list[object]:
    """One credential line in a subagent file, flagged by the generic and the subagent rule."""
    from reporails_cli.core.platform.dto.models import LocalFinding

    secret = 'api_key = "sk-live-abc123"'
    return [
        LocalFinding(".claude/agents/helper.md", 3, "warning", "CORE:G:0002", "Credential detected", signature=secret),
        LocalFinding(".claude/agents/helper.md", 3, "error", "CORE:G:0009", "Credential in subagent", signature=secret),
    ]


def _write_subagent(tmp_path, credential_line: str) -> None:
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "helper.md").write_text(f"# Helper\n\n{credential_line}\n", encoding="utf-8")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_assemble_reports_one_credential_finding_per_secret(tmp_path):
    """The generic and the subagent credential rule on one secret report it once."""
    _write_subagent(tmp_path, 'api_key = "sk-live-abc123"')

    result = assemble_result(
        _inputs(m_findings=_subagent_credential_findings(), scan_root=tmp_path, alias_fn=lambda rule: {rule})
    )

    assert [f.rule for f in result.findings] == ["CORE:G:0009"]
    assert result.stats.total_findings == 1
    assert result.stats.errors == 1
    assert result.stats.m_probe_count == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("ignored", "reported", "errors", "warnings"),
    [("CORE:G:0009", "CORE:G:0002", 0, 1), ("CORE:G:0002", "CORE:G:0009", 1, 0)],
)
def test_assemble_ignoring_one_credential_rule_keeps_the_other(tmp_path, ignored, reported, errors, warnings):
    """An inline ignore of either credential rule must not hide the credential: the
    other rule's finding on the same secret is still reported."""
    _write_subagent(tmp_path, f'api_key = "sk-live-abc123"  <!-- ails-disable-line {ignored} -->')

    result = assemble_result(
        _inputs(m_findings=_subagent_credential_findings(), scan_root=tmp_path, alias_fn=lambda rule: {rule})
    )

    assert [f.rule for f in result.findings] == [reported]
    assert result.stats.total_findings == 1
    assert (result.stats.errors, result.stats.warnings) == (errors, warnings)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_assemble_keeps_two_other_rules_that_matched_the_same_text(tmp_path):
    """Only the generic + subagent credential pair shares a pattern. Any other two rules
    that matched the same text on one line are separate problems and both stay reported."""
    from reporails_cli.core.platform.dto.models import LocalFinding

    findings = [
        LocalFinding("CLAUDE.md", 5, "warning", "CORE:C:0049", "First", signature="TODO"),
        LocalFinding("CLAUDE.md", 5, "error", "CORE:C:0050", "Second", signature="TODO"),
    ]

    result = assemble_result(_inputs(m_findings=findings, scan_root=tmp_path, alias_fn=lambda rule: {rule}))

    assert sorted(f.rule for f in result.findings) == ["CORE:C:0049", "CORE:C:0050"]
    assert result.stats.total_findings == 2


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_finding_takes_the_grade_of_the_reply_row_at_its_coordinates(tmp_path):
    """A client-reported finding is graded by the reply row at its file, rule and line; the other stays ungraded."""
    from reporails_cli.core.platform.dto.diagnostics import LocalTier, RulesetReport
    from reporails_cli.core.platform.dto.models import LocalFinding

    (tmp_path / "CLAUDE.md").write_text("# Project\n\nFirst line.\n\nSecond line.\n", encoding="utf-8")
    findings = [
        LocalFinding("CLAUDE.md", 3, "error", "CORE:C:0011", "m", check_id="c"),
        LocalFinding("CLAUDE.md", 5, "error", "CORE:C:0011", "m", check_id="c"),
    ]
    report = RulesetReport(
        local_tiers=(LocalTier(file="CLAUDE.md", rule="CORE:C:0011", line=5, impact_tier="conditional"),)
    )
    lint_result = SimpleNamespace(report=report, hints=(), cross_file_coordinates=(), tier="pro", workflow=None)

    result = assemble_result(
        _inputs(scan_root=tmp_path, m_findings=findings, lint_result=lint_result, alias_fn=lambda rule: {rule})
    )

    assert [(f.line, f.impact_tier) for f in result.findings if f.rule == "CORE:C:0011"] == [
        (3, ""),
        (5, "conditional"),
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_offline_run_grades_no_finding(tmp_path):
    """With no reply there are no rows, so no finding carries a grade."""
    from reporails_cli.core.platform.dto.models import LocalFinding

    (tmp_path / "CLAUDE.md").write_text("# Project\n\nFirst line.\n", encoding="utf-8")
    findings = [LocalFinding("CLAUDE.md", 3, "error", "CORE:C:0011", "m", check_id="c")]

    result = assemble_result(
        _inputs(scan_root=tmp_path, m_findings=findings, lint_result=None, alias_fn=lambda rule: {rule})
    )

    assert {f.impact_tier for f in result.findings} == {""}


def _dependent_pair_project(tmp_path, ignored: str = ""):
    """A CLAUDE.md holding one line that two findings point at, and those two findings."""
    from reporails_cli.core.platform.dto.models import LocalFinding

    suffix = f" <!-- ails-disable-line {ignored} -->" if ignored else ""
    (tmp_path / "CLAUDE.md").write_text(f"# Project\n\nRun the tests.{suffix}\n", encoding="utf-8")
    return [
        LocalFinding("CLAUDE.md", 3, "warning", "CORE:S:0016", "layers", check_id="c"),
        LocalFinding("CLAUDE.md", 3, "warning", "CORE:S:0002", "headings", check_id="c"),
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_finding_whose_dependency_reports_on_its_file_is_neither_shown_nor_sent(tmp_path):
    """CORE:S:0016 depends on CORE:S:0002: with both on one file only CORE:S:0002 is reported and sent."""
    from reporails_cli.core.pipeline.assemble import lint_request_local

    inputs = _inputs(
        m_findings=_dependent_pair_project(tmp_path),
        scan_root=tmp_path,
        effective_agent="claude",
        alias_fn=lambda rule: {rule},
    )

    result = assemble_result(inputs)
    entries, _total = lint_request_local(inputs)

    assert [f.rule for f in result.findings] == ["CORE:S:0002"]
    assert result.stats.total_findings == 1
    assert result.stats.m_probe_count == 1
    assert [e.rule for e in entries] == ["CORE:S:0002"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_silencing_a_dependency_inline_does_not_bring_back_the_finding_that_depends_on_it(tmp_path):
    """The dependency was detected, so what depends on it stays dropped after the ignore."""
    from reporails_cli.core.pipeline.assemble import lint_request_local

    inputs = _inputs(
        m_findings=_dependent_pair_project(tmp_path, ignored="CORE:S:0002"),
        scan_root=tmp_path,
        effective_agent="claude",
        alias_fn=lambda rule: {rule},
    )

    result = assemble_result(inputs)
    entries, _total = lint_request_local(inputs)

    assert result.findings == ()
    assert entries == []


def _served(tmp_path, *rows):
    """A workflow with one location holding `rows` as (rule, line, impact_tier, members) findings."""
    from reporails_cli.core.platform.dto.diagnostics import LocationFinding, RemediationWorkflow, WorkflowLocation

    path = str(tmp_path / "AGENTS.md")
    findings = tuple(
        LocationFinding(
            rule=rule, file=path, line=line, pi=None, message="", remedy="", impact_tier=tier, members=members
        )
        for rule, line, tier, members in rows
    )
    location = WorkflowLocation(order=1, element=path, kind="main", loading="", files=(path,), findings=findings)
    return RemediationWorkflow(locations=(location,))


def _tiers(tmp_path, findings, workflow, local_tiers=()):
    from reporails_cli.core.platform.dto.diagnostics import RulesetReport

    report = RulesetReport(local_tiers=tuple(local_tiers))
    lint_result = SimpleNamespace(report=report, hints=(), cross_file_coordinates=(), tier="pro", workflow=workflow)
    result = assemble_result(
        _inputs(scan_root=tmp_path, m_findings=findings, lint_result=lint_result, effective_agent="codex")
    )
    return {f.rule: f.impact_tier for f in result.findings}


def _codex_size_finding():
    from reporails_cli.core.platform.dto.models import LocalFinding

    return LocalFinding(file="AGENTS.md", line=1, severity="error", rule="CODEX:E:0001", message="big", check_id="c")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_local_finding_the_workflow_serves_reads_the_served_tier(tmp_path, dev_rules_dir):
    """A whole-file row (line 0) sets the tier of the same file's finding, over the reply's own row."""
    from reporails_cli.core.platform.dto.diagnostics import LocalTier

    row = LocalTier(file="AGENTS.md", rule="CODEX:E:0001", line=1, impact_tier="cosmetic")
    workflow = _served(tmp_path, ("CODEX:E:0001", 0, "gate_mover", ()))

    assert _tiers(tmp_path, [_codex_size_finding()], None, [row])["CODEX:E:0001"] == "cosmetic"
    assert _tiers(tmp_path, [_codex_size_finding()], workflow, [row])["CODEX:E:0001"] == "gate_mover"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_listed_config_file_finding_keeps_the_tier_its_row_carried(tmp_path, dev_rules_dir):
    """A finding in a config file is graded by its workflow row before heal lists that file."""
    from reporails_cli.core.platform.dto.diagnostics import LocationFinding, RemediationWorkflow, WorkflowLocation
    from reporails_cli.core.platform.dto.models import LocalFinding

    config = str(tmp_path / ".claude" / "settings.json")
    main = str(tmp_path / "AGENTS.md")

    def row(rule, file, tier):
        return LocationFinding(rule=rule, file=file, line=1, pi=None, message="", remedy="", impact_tier=tier)

    config_row = row("CODEX:E:0002", config, "gate_mover")
    locations = (
        WorkflowLocation(order=1, element=config, kind="main", loading="", files=(config,), findings=(config_row,)),
        WorkflowLocation(
            order=2, element=main, kind="main", loading="", files=(main,), findings=(row("CODEX:E:0001", main, ""),)
        ),
    )
    finding = LocalFinding(
        file=".claude/settings.json", line=1, severity="error", rule="CODEX:E:0002", message="m", check_id="c"
    )
    lint_result = SimpleNamespace(
        report=None, hints=(), cross_file_coordinates=(), tier="pro", workflow=RemediationWorkflow(locations=locations)
    )

    result = assemble_result(
        _inputs(scan_root=tmp_path, m_findings=[finding], lint_result=lint_result, effective_agent="codex")
    )

    assert [f.impact_tier for f in result.findings if f.rule == "CODEX:E:0002"] == ["gate_mover"]
    assert [loc.element for loc in result.workflow.locations] == [main]
    assert [(e.rule, e.reason) for e in result.workflow.listed] == [("CODEX:E:0002", "config-file")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_served_member_tier_stays_on_its_own_rule(tmp_path, dev_rules_dir):
    from reporails_cli.core.platform.dto.diagnostics import LocationFinding
    from reporails_cli.core.platform.dto.models import LocalFinding

    path = str(tmp_path / "AGENTS.md")
    member = LocationFinding(
        rule="CORE:C:0042", file=path, line=7, pi=None, message="", remedy="", impact_tier="gate_mover"
    )
    workflow = _served(tmp_path, ("CORE:C:0058", 7, "conditional", (member,)))
    local = [
        LocalFinding("AGENTS.md", 7, "warning", "CORE:C:0058", "packed", check_id="c"),
        LocalFinding("AGENTS.md", 7, "warning", "CORE:E:0004", "brief", check_id="c"),
    ]

    tiers = _tiers(tmp_path, local, workflow)

    assert tiers["CORE:C:0058"] == "conditional"
    assert tiers["CORE:E:0004"] == ""


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_finding_the_workflow_does_not_serve_keeps_the_grade_of_its_reply_row(tmp_path, dev_rules_dir):
    from reporails_cli.core.platform.dto.diagnostics import LocalTier

    row = LocalTier(file="AGENTS.md", rule="CODEX:E:0001", line=1, impact_tier="conditional")
    workflow = _served(tmp_path, ("CORE:C:0058", 7, "gate_mover", ()))
    assert _tiers(tmp_path, [_codex_size_finding()], workflow, [row])["CODEX:E:0001"] == "conditional"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_stamping_served_tiers_without_a_workflow_returns_the_same_result():
    from reporails_cli.core.platform.runtime.merger import CombinedResult, stamp_served_tiers

    result = CombinedResult()
    assert stamp_served_tiers(result) is result


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_assemble_records_the_agents_whose_rules_ran(tmp_path):
    """The summary names the agent even when no ruleset map exists (no model on disk)."""
    assert assemble_result(_inputs(scan_root=tmp_path, effective_agent="claude")).stats.agents == ("claude",)
    assert assemble_result(_inputs(scan_root=tmp_path, rule_agents=("claude", "cursor"))).stats.agents == (
        "claude",
        "cursor",
    )
