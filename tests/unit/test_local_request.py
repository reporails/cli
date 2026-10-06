"""The diagnostics request carries each reported local finding on its own line.

A broken link is one entry located on the line that holds it; a finding the author suppressed is
not sent; an entry names its file by index into the mapped files, then into the extra files the
request lists.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.pipeline import assemble as assemble_module
from reporails_cli.core.pipeline.assemble import AssembleInputs, lint_request_local
from reporails_cli.core.platform.adapters.payload import project_local
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap
from reporails_cli.formatters.text.display_constants import rule_aliases

_MAIN = (
    "# Project\n\nRun `pytest tests/` before committing a parser change.\n\n"
    "## Notes\n\nSee [parser notes]({target}).{tail}\n"
)


def _inputs(root: Path) -> AssembleInputs:
    from reporails_cli.core.discovery.agents import get_all_instruction_files
    from reporails_cli.core.lint.rule_runner import run_m_probes

    files = get_all_instruction_files(root)
    return AssembleInputs(
        m_findings=run_m_probes(root, files, agent="claude"),
        content_findings=[],
        client_findings=[],
        ruleset_map=None,
        scan_root=root,
        filter_agents=None,
        effective_agent="claude",
        lint_result=None,
        alias_fn=rule_aliases,
    )


def _link_entries(root: Path) -> list[tuple[str, str, int]]:
    entries, _required = lint_request_local(_inputs(root))
    return [(e.rule, e.file, e.line) for e in entries if e.rule == "CORE:S:0056"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_broken_link_is_sent_on_its_line(tmp_path: Path, dev_rules_dir: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(_MAIN.format(target="gone.md", tail=""))
    assert _link_entries(tmp_path) == [("CORE:S:0056", (tmp_path / "CLAUDE.md").as_posix(), 7)]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_each_entry_carries_its_file_s_config_type(tmp_path: Path, dev_rules_dir: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(_MAIN.format(target="gone.md", tail=""))
    entries, _required = lint_request_local(_inputs(tmp_path))
    assert {e.type for e in entries if e.rule == "CORE:S:0056"} == {"main"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_suppressed_finding_is_not_sent(tmp_path: Path, dev_rules_dir: Path) -> None:
    tail = "  <!-- ails-disable-line CORE:S:0056 -->"
    (tmp_path / "CLAUDE.md").write_text(_MAIN.format(target="gone.md", tail=tail))
    assert _link_entries(tmp_path) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_locally_reported_skill_supporting_file_takes_the_skill_s_type(
    tmp_path: Path, dev_rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local finding on an unmapped file typed `skills` inside a recorded skill folder keeps
    the `skills` type."""
    skill_dir = tmp_path / ".claude" / "skills" / "digest"
    skill_dir.mkdir(parents=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text("---\nname: digest\ndescription: d\n---\n")
    supporting = skill_dir / "intake-flow.md"
    supporting.write_text("# Intake\n")

    ruleset_map = RulesetMap(
        schema_version="1",
        embedding_model="m",
        generated_at="2026-01-01T00:00:00Z",
        files=(
            FileRecord(path=skill_md.as_posix(), content_hash="sha256:x", type="skills", skill=skill_dir.as_posix()),
        ),
        atoms=(),
    )
    finding = SimpleNamespace(rule="CORE:S:0056", file=str(supporting), line=1, severity="error")
    monkeypatch.setattr(assemble_module, "reported_local_findings", lambda inp: (finding,))

    inp = AssembleInputs(
        m_findings=[],
        content_findings=[],
        client_findings=[],
        ruleset_map=ruleset_map,
        scan_root=tmp_path,
        filter_agents=None,
        effective_agent="claude",
        lint_result=None,
        alias_fn=rule_aliases,
    )

    entries, _required = lint_request_local(inp)

    assert entries[0].type == "skills"


@pytest.mark.unit
@pytest.mark.subsys_api
def test_entries_index_the_mapped_files_then_the_extra_files() -> None:
    # `mapped` rides root-relative (as `_project_files` sends it); each `LocalEntry.file`
    # stays the absolute local path — `project_local` maps the two together via the same
    # root-relative form, by exact match, never by a path-suffix guess.
    root = Path("/p")
    local = [
        LocalEntry(rule="CORE:S:0056", file="/p/CLAUDE.md", line=7, severity="error"),
        LocalEntry(rule="CLAUDE:S:0005", file="/p/.claude/settings.json", line=0, severity="error"),
        LocalEntry(rule="CORE:G:0006", file="/p/.claude/settings.json", line=0, severity="warning"),
    ]
    local[1:] = [
        LocalEntry(rule=e.rule, file=e.file, line=e.line, severity=e.severity, type="config") for e in local[1:]
    ]
    fields = project_local(local, [".claude/rules/x.md", "CLAUDE.md"], root)
    # Extra files ride relative too — never the absolute local path.
    assert fields["local_files"] == [".claude/settings.json"]
    assert fields["local_types"] == ["config"]
    assert [(e["r"], e["f"], e["l"]) for e in fields["local"]] == [
        ("CORE:S:0056", 1, 7),
        ("CLAUDE:S:0005", 2, 0),
        ("CORE:G:0006", 2, 0),
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_main_file_without_headings_is_sent_as_a_warning(tmp_path: Path, dev_rules_dir: Path) -> None:
    from reporails_cli.core.lint.rule_runner import run_content_quality_checks
    from reporails_cli.core.platform.dto.ruleset import RulesetSummary

    main = tmp_path / "CLAUDE.md"
    main.write_text("Run `pytest tests/` before committing a parser change.\n")
    ruleset_map = RulesetMap(
        schema_version="1",
        embedding_model="none",
        generated_at="t",
        files=(FileRecord(path=main.as_posix(), content_hash="sha256:a"),),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
    )
    inputs = replace(
        _inputs(tmp_path),
        content_findings=run_content_quality_checks(ruleset_map, tmp_path, [main], agent="claude"),
    )

    entries, _required = lint_request_local(inputs)

    assert [e.severity for e in entries if e.rule == "CORE:S:0002"] == ["warning"]
