"""Whole-project checks run once over every in-scope file, not once per owning agent."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.rule_runner import run_m_probes_over_pairs


def _two_agent_project(root: Path) -> list[tuple[str, list[Path]]]:
    claude = root / "CLAUDE.md"
    codex = root / "AGENTS.md"
    claude.write_text("# Proj\n\nUse uv.\n", encoding="utf-8")
    codex.write_text("# Proj\n\nUse uv.\n", encoding="utf-8")
    return [("claude", [claude]), ("codex", [codex])]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_modular_file_count_judges_the_whole_project(dev_rules_dir: Path, tmp_path: Path) -> None:
    """Two files across two agents satisfy the two-file minimum, so the rule does not fire."""
    pairs = _two_agent_project(tmp_path)
    hits = [f.rule for f in run_m_probes_over_pairs(tmp_path, pairs, scoped=False)]
    assert hits.count("CORE:S:0010") == 0


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_single_file_project_reports_modular_once(dev_rules_dir: Path, tmp_path: Path) -> None:
    """Across two agent passes a one-file project reports the file-count finding once."""
    only = tmp_path / "CLAUDE.md"
    only.write_text("# Proj\n\nUse uv.\n", encoding="utf-8")
    pairs = [("claude", [only]), ("codex", [])]
    hits = [f.rule for f in run_m_probes_over_pairs(tmp_path, pairs, scoped=False)]
    assert hits.count("CORE:S:0010") == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_total_size_limit_sums_every_agents_files(dev_rules_dir: Path, tmp_path: Path) -> None:
    """Files that are each under the limit but together over it still trigger the total-size rule."""
    (tmp_path / ".github").mkdir()
    pairs = []
    for agent, name in (("claude", "CLAUDE.md"), ("copilot", ".github/copilot-instructions.md")):
        path = tmp_path / name
        path.write_text("# Proj\n\n" + "x" * 60_000 + "\n", encoding="utf-8")
        pairs.append((agent, [path]))
    hits = [f.rule for f in run_m_probes_over_pairs(tmp_path, pairs, scoped=False)]
    assert hits.count("CORE:E:0001") == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_identical_local_findings_are_reported_once() -> None:
    """The same finding handed in twice reaches the output once."""
    from reporails_cli.core.platform.dto.models import LocalFinding
    from reporails_cli.core.platform.runtime.merger import _merge_local_findings

    finding = LocalFinding(file="a.md", line=1, severity="warning", rule="CORE:S:0010", message="m", check_id="c")
    items, count = _merge_local_findings([finding, finding], set(), "local", lambda p: p)
    assert count == 1
    assert len(items) == 1


def _big(path: Path, size: int) -> Path:
    path.write_text("# Proj\n\n" + "".join(f"- Run `make step-{i}` before the release.\n" for i in range(size // 40)))
    return path


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_size_finding_an_agent_s_rule_replaces_is_reported_once(dev_rules_dir: Path, tmp_path: Path) -> None:
    """Codex's own size rule judges its files; the core size rule does not report them again."""
    (tmp_path / ".codex").mkdir()
    agents = _big(tmp_path / "AGENTS.md", 117_000)
    other = tmp_path / "notes.md"
    other.write_text("# Notes\n\n- Keep the changelog current.\n", encoding="utf-8")
    pairs = [("codex", [agents]), ("", [other])]
    hits = [(f.rule, Path(f.file).name) for f in run_m_probes_over_pairs(tmp_path, pairs, scoped=False)]
    assert ("CODEX:E:0001", "AGENTS.md") in hits
    assert [h for h in hits if h[0] == "CORE:E:0001"] == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_core_size_finding_still_covers_files_no_agent_rule_replaces(dev_rules_dir: Path, tmp_path: Path) -> None:
    """Only the Claude files exceed the core ceiling: the core size finding is still reported."""
    claude = _big(tmp_path / "CLAUDE.md", 117_000)
    codex = tmp_path / "AGENTS.md"
    codex.write_text("# Proj\n\n- Use uv.\n", encoding="utf-8")
    pairs = [("claude", [claude]), ("codex", [codex])]
    hits = [(f.rule, Path(f.file).name) for f in run_m_probes_over_pairs(tmp_path, pairs, scoped=False)]
    assert [h for h in hits if h[0] == "CORE:E:0001"] == [("CORE:E:0001", "CLAUDE.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("scoped", [False, True])
def test_not_a_git_repository_is_reported_once_across_agents(dev_rules_dir: Path, tmp_path: Path, scoped: bool) -> None:
    """A project that is not a git repository gets one finding, whatever the number of agents, targeted or not."""
    pairs = _two_agent_project(tmp_path)
    hits = [f.rule for f in run_m_probes_over_pairs(tmp_path, pairs, scoped=scoped)]
    assert hits.count("CORE:G:0001") == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_not_a_git_repository_is_kept_on_a_targeted_single_agent_run(dev_rules_dir: Path, tmp_path: Path) -> None:
    """A targeted run does not skip the git finding (it is a project fact, not a project aggregate)."""
    only = tmp_path / "CLAUDE.md"
    only.write_text("# Proj\n\nUse uv.\n", encoding="utf-8")
    hits = [f.rule for f in run_m_probes_over_pairs(tmp_path, [("claude", [only])], scoped=True)]
    assert hits.count("CORE:G:0001") == 1
    assert hits.count("CORE:S:0010") == 0
