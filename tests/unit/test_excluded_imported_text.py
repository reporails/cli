"""Text imported from a file the run left out still counts; the Excluded line, JSON and MCP view say so."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.core.discovery.features import detect_features_filesystem
from reporails_cli.core.pipeline.assemble import AssembleInputs, _imports_left_out
from reporails_cli.core.platform.runtime.merger import CombinedResult, Omissions
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import mcp_view
from reporails_cli.formatters.text.display_constants import excluded_phrase

CLAUSE = "imported text in checked files still counts"


def _inputs(root: Path, imported_from: str | None) -> AssembleInputs:
    atom = SimpleNamespace(file_path=str(root / "CLAUDE.md"), imported_from=imported_from)
    return AssembleInputs(
        m_findings=[],
        content_findings=[],
        client_findings=[],
        ruleset_map=SimpleNamespace(atoms=[atom]),
        scan_root=root,
        filter_agents=None,
        effective_agent="claude",
        lint_result=None,
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("config", ["", "generic_scanning: true\n"], ids=["scanning-off", "scanning-on"])
def test_import_into_a_left_out_folder_sets_the_flag(tmp_path: Path, config: str) -> None:
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.yml").write_text(config or "{}\n", encoding="utf-8")
    left_out = load_run_exclusions(tmp_path, ["ext"], None)
    assert _imports_left_out(_inputs(tmp_path, "ext/notes.md"), left_out)
    assert not _imports_left_out(_inputs(tmp_path, "docs/notes.md"), left_out)
    assert not _imports_left_out(_inputs(tmp_path, None), left_out)
    assert not _imports_left_out(_inputs(tmp_path, "ext/notes.md"), None)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_text_line_ends_with_the_clause_only_when_an_import_crosses() -> None:
    assert excluded_phrase(["ext"], [], imported_counted=True).endswith(f"; {CLAUSE}")
    assert "the score covers the rest; imported" in excluded_phrase(["ext"], [], imported_counted=True)
    assert CLAUSE not in excluded_phrase(["ext"], [])
    assert excluded_phrase([], [], imported_counted=True) == ""


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_json_excluded_object_carries_the_flag() -> None:
    on = json_formatter.format_combined_result(
        CombinedResult(omissions=Omissions(excluded_dirs=("ext",), excluded_imported=True))
    )
    off = json_formatter.format_combined_result(CombinedResult(omissions=Omissions(excluded_dirs=("ext",))))
    assert on["excluded"] == {"dirs": ["ext"], "files": [], "imported_text_counted": True}
    assert off["excluded"]["imported_text_counted"] is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mcp_view_says_imported_text_counts() -> None:
    on = {"excluded": {"dirs": ["ext"], "files": [], "imported_text_counted": True}, "quality": 7.0}
    off = {"excluded": {"dirs": ["ext"], "files": []}, "quality": 7.0}
    assert any(CLAUSE in line for line in mcp_view._excluded_lines(on))
    assert not any(CLAUSE in line for line in mcp_view._excluded_lines(off))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_feature_detection_ignores_a_flag_excluded_skills_folder(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# P\n\nAlways test.\n", encoding="utf-8")
    skill = tmp_path / ".claude" / "skills" / "s"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\n\nDo it.\n", encoding="utf-8")
    assert detect_features_filesystem(tmp_path).has_skills_dir
    left_out = load_run_exclusions(tmp_path, ["skills"], None)
    assert not detect_features_filesystem(tmp_path, exclusions=left_out).has_skills_dir


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_import_with_parent_hop_is_judged_by_where_it_lands(tmp_path: Path) -> None:
    left_out = load_run_exclusions(tmp_path, ["sub"], None)
    atom = SimpleNamespace(file_path=str(tmp_path / "sub" / "CLAUDE.md"), imported_from="../shared/x.md")
    inp = replace(_inputs(tmp_path, None), ruleset_map=SimpleNamespace(atoms=[atom]))
    assert not _imports_left_out(inp, left_out)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_flag_needs_something_listed() -> None:
    from reporails_cli.core.pipeline.assemble import with_exclusions

    flagged = CombinedResult(omissions=Omissions(excluded_imported=True))
    assert not with_exclusions(flagged, ((), ())).omissions.excluded_imported
    assert with_exclusions(flagged, (("ext",), ())).omissions.excluded_imported
    assert with_exclusions(flagged, ((), ("a/*.md",))).omissions.excluded_imported


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_capability_left_out_by_file_glob_is_not_counted(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "CLAUDE.md").write_text("# P\n\nRun pytest.\n", encoding="utf-8")
    skill = tmp_path / ".claude" / "skills" / "foo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: foo\ndescription: d\n---\nBody.\n", encoding="utf-8")
    assert detect_features_filesystem(tmp_path).has_skills_dir
    left_out = load_run_exclusions(tmp_path, None, [".claude/skills/*/SKILL.md"])
    assert not detect_features_filesystem(tmp_path, exclusions=left_out).has_skills_dir
    assert detect_features_filesystem(tmp_path, exclusions=left_out.with_named([skill])).has_skills_dir


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_file_named_inside_a_left_out_folder_still_counts_toward_the_level(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "CLAUDE.md").write_text("# P\n\nRun pytest.\n", encoding="utf-8")
    skill = tmp_path / ".claude" / "skills" / "foo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: foo\ndescription: d\n---\nBody.\n", encoding="utf-8")
    left_out = load_run_exclusions(tmp_path, ["skills"], None)
    assert not detect_features_filesystem(tmp_path, exclusions=left_out).has_skills_dir
    assert detect_features_filesystem(tmp_path, exclusions=left_out.with_named([skill])).has_skills_dir


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_import_that_was_itself_named_is_not_a_left_out_import(tmp_path: Path) -> None:
    left_out = load_run_exclusions(tmp_path, ["docs", "other"], None)
    atom = SimpleNamespace(file_path=str(tmp_path / "CLAUDE.md"), imported_from="docs/x.md")
    inp = replace(_inputs(tmp_path, None), ruleset_map=SimpleNamespace(atoms=[atom]))
    assert _imports_left_out(inp, left_out)
    assert not _imports_left_out(inp, left_out.with_named([tmp_path / "docs" / "x.md"]))
