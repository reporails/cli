"""A skill's whole folder is one item in the reports: its files group, count and score together."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.mapper.skills import record_skills
from reporails_cli.core.platform.dto.diagnostics import FileAnalysis, QualityResult
from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem
from reporails_cli.formatters.text import display, item_scorecard, scorecard, triage_view
from reporails_cli.formatters.text.display_constants import file_type_summary, skill_lookup
from reporails_cli.formatters.text.item_scorecard import _display_name_for_path, compute_item_scores
from reporails_cli.formatters.text.scorecard import _surface_key, compute_surface_scores


def _rec(root: Path, rel: str, type_: str = "skills", agent: str = "claude") -> FileRecord:
    return FileRecord(path=(root / rel).as_posix(), content_hash=f"sha256:{rel}", type=type_, agent=agent)


def _raw_map(*records: FileRecord) -> RulesetMap:
    return RulesetMap(
        schema_version="1", embedding_model="", generated_at="2026-01-01T00:00:00Z", files=records, atoms=()
    )


def _map(root: Path, *records: FileRecord, agents: tuple[str, ...] | None = None) -> RulesetMap:
    """A map with membership recorded for the run's agents (default: the records' own agents)."""
    rmap = _raw_map(*records)
    record_skills(rmap, agents if agents is not None else {r.agent for r in records}, root)
    return rmap


def _skill(root: Path, base: str, *others: str, agent: str = "claude") -> list[FileRecord]:
    return [_rec(root, f"{base}/SKILL.md", agent=agent), *(_rec(root, f"{base}/{o}", agent=agent) for o in others)]


def _finding(rel: str) -> FindingItem:
    return FindingItem(file=rel, line=1, severity="warning", rule="CORE:S:0010", message="m")


def _state(rmap: RulesetMap, root: Path) -> dict[str, tuple[str, str]]:
    """Relative path -> (type, skill folder relative to root, "" for none)."""
    return {
        Path(r.path).relative_to(root).as_posix(): (
            r.type,
            Path(r.skill).relative_to(root).as_posix() if r.skill else "",
        )
        for r in rmap.files
    }


class TestRecordSkills:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_skill_md_and_supporting_file_belong_to_their_skill(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/ails", "workflows/heal.md"))
        assert _state(rmap, tmp_path) == {
            ".claude/skills/ails/SKILL.md": ("skills", ".claude/skills/ails"),
            ".claude/skills/ails/workflows/heal.md": ("skills", ".claude/skills/ails"),
        }

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_outsiders_and_other_types_belong_to_no_skill(self, tmp_path: Path) -> None:
        rmap = _map(
            tmp_path,
            *_skill(tmp_path, ".claude/skills/ails"),
            _rec(tmp_path, "docs/skills/guide/intro.md", "generic"),
            _rec(tmp_path, ".claude/skills/ails/agents/helper.md", "agents"),
        )
        state = _state(rmap, tmp_path)
        assert state["docs/skills/guide/intro.md"] == ("generic", "")
        assert state[".claude/skills/ails/agents/helper.md"] == ("agents", "")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_symlinked_skill_md_keeps_the_folder_it_was_found_in(self, tmp_path: Path) -> None:
        skill = tmp_path / ".claude/skills/foo"
        skill.mkdir(parents=True)
        (tmp_path / "elsewhere").mkdir()
        (tmp_path / "elsewhere/real.md").write_text("# Foo\n")
        os.symlink(tmp_path / "elsewhere/real.md", skill / "SKILL.md")
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "ref.md"))
        assert _state(rmap, tmp_path)[".claude/skills/foo/ref.md"] == ("skills", ".claude/skills/foo")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_cursor_skills_root_skill_md_is_no_skill_and_siblings_are_two(self, tmp_path: Path) -> None:
        recs = [
            _rec(tmp_path, ".cursor/skills/SKILL.md", agent="cursor"),
            *_skill(tmp_path, ".cursor/skills/a", agent="cursor"),
            *_skill(tmp_path, ".cursor/skills/b", agent="cursor"),
        ]
        state = _state(_map(tmp_path, *recs), tmp_path)
        assert state[".cursor/skills/SKILL.md"] == ("generic", "")
        assert state[".cursor/skills/a/SKILL.md"] == ("skills", ".cursor/skills/a")
        assert state[".cursor/skills/b/SKILL.md"] == ("skills", ".cursor/skills/b")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_skill_md_one_level_too_deep_is_a_skill_only_when_cursor_runs(self, tmp_path: Path) -> None:
        rel = ".claude/skills/group/x/SKILL.md"
        claude_only = _state(_map(tmp_path, _rec(tmp_path, rel), agents=("claude",)), tmp_path)
        assert claude_only[rel] == ("generic", "")
        with_cursor = _state(_map(tmp_path, _rec(tmp_path, rel), agents=("claude", "cursor")), tmp_path)
        assert with_cursor[rel] == ("skills", ".claude/skills/group/x")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_generic_agent_record_is_a_skill_when_a_run_agent_reads_it(self, tmp_path: Path) -> None:
        rel = ".agents/skills/group/x/SKILL.md"
        rec = _rec(tmp_path, rel, agent="generic")
        assert _state(_map(tmp_path, rec, agents=("cursor",)), tmp_path)[rel] == ("skills", ".agents/skills/group/x")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_nested_skill_md_belongs_to_the_outermost_skill(self, tmp_path: Path) -> None:
        recs = _skill(tmp_path, ".claude/skills/a", "b/SKILL.md", "b/y.md")
        assert {v[1] for v in _state(_map(tmp_path, *recs), tmp_path).values()} == {".claude/skills/a"}

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_generic_file_in_a_skill_takes_over_the_entrys_loading(self, tmp_path: Path) -> None:
        entry = FileRecord(
            path=(tmp_path / ".claude/skills/a/SKILL.md").as_posix(),
            content_hash="h1",
            type="skills",
            agent="claude",
            loading="on_invocation",
            scope="task_scoped",
            globs=("src/**",),
        )
        ref = FileRecord(path=(tmp_path / ".claude/skills/a/ref.md").as_posix(), content_hash="h2", type="generic")
        record_skills(_raw_map(entry, ref), ["claude"], tmp_path)
        assert (ref.type, ref.loading, ref.scope, ref.globs, ref.agent) == (
            "skills",
            "on_invocation",
            "task_scoped",
            ("src/**",),
            "claude",
        )

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_recording_twice_changes_nothing(self, tmp_path: Path) -> None:
        recs = [
            *_skill(tmp_path, ".claude/skills/a", "ref.md", "b/SKILL.md"),
            _rec(tmp_path, ".claude/skills/group/x/SKILL.md"),
            _rec(tmp_path, ".claude/skills/a/extra.md", "generic"),
            _rec(tmp_path, "docs/note.md", "skills"),
        ]
        rmap = _raw_map(*recs)
        record_skills(rmap, ["claude"], tmp_path)
        once = [r.model_dump() for r in rmap.files]
        record_skills(rmap, ["claude"], tmp_path)
        assert [r.model_dump() for r in rmap.files] == once

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_skills_file_an_older_build_retyped_outside_every_skill_becomes_generic(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, _rec(tmp_path, "docs/note.md", "skills"))
        assert _state(rmap, tmp_path)["docs/note.md"] == ("generic", "")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_skill_folder_that_is_also_a_plugin_keeps_its_agent_an_agent(self, tmp_path: Path) -> None:
        manifest = tmp_path / ".claude/skills/tool/.claude-plugin/plugin.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}")
        recs = [
            *_skill(tmp_path, ".claude/skills/tool"),
            _rec(tmp_path, ".claude/skills/tool/agents/reviewer.md", "agents"),
        ]
        rmap = _map(tmp_path, *recs)
        assert skill_lookup(rmap, tmp_path) == {".claude/skills/tool/SKILL.md": ".claude/skills/tool"}
        surfaces = compute_surface_scores(
            CombinedResult(quality=QualityResult()), ruleset_map=rmap, project_root=tmp_path
        )
        assert {s.name: s.file_count for s in surfaces} == {"Skills": 1, "Agents": 1}

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_plugin_skill_is_an_entry_only_one_level_below_the_plugin_skills_folder(self, tmp_path: Path) -> None:
        manifest = tmp_path / "plug/.claude-plugin/plugin.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}")
        recs = [*_skill(tmp_path, "plug/skills/tool"), *_skill(tmp_path, "plug/skills/group/child")]
        state = _state(_map(tmp_path, *recs, agents=("claude",)), tmp_path)
        assert state["plug/skills/tool/SKILL.md"] == ("skills", "plug/skills/tool")
        assert state["plug/skills/group/child/SKILL.md"] == ("generic", "")


class TestSkillFolderCounting:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_one_skill_of_three_files_and_an_agent(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rmap = _map(
            tmp_path,
            *_skill(tmp_path, ".claude/skills/foo", "a.md", "b.md"),
            _rec(tmp_path, ".claude/agents/x.md", "agents"),
        )
        surfaces = compute_surface_scores(
            CombinedResult(quality=QualityResult()), ruleset_map=rmap, project_root=tmp_path
        )
        skills = next(s for s in surfaces if s.name == "Skills")
        assert (skills.item_count, skills.file_count) == (1, 3)
        scorecard._render_surface_health(surfaces)
        out = capsys.readouterr().out
        assert "Skills (1):" in out and "Skills (3)" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_supporting_file_findings_count_under_skills_surface(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "ref.md"))
        result = CombinedResult(findings=(_finding(".claude/skills/foo/ref.md"),), quality=QualityResult())
        surfaces = compute_surface_scores(result, ruleset_map=rmap, project_root=tmp_path)
        assert [(s.name, s.finding_count) for s in surfaces] == [("Skills", 1)]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_skill_with_an_inner_skill_md_scores_as_one_item_named_after_the_folder(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/tool", "inner/SKILL.md", "inner/ref.md"))
        analyses = tuple(
            FileAnalysis(file=r.path, display_score=sc, stats={"atoms": 1})
            for r, sc in zip(rmap.files, (8.0, 4.0, 6.0), strict=True)
        )
        result = CombinedResult(per_file_analysis=analyses, quality=QualityResult())
        (item,) = compute_item_scores(result, ruleset_map=rmap, project_root=tmp_path)
        assert (item.name, item.file_count, item.score) == ("tool", 3, 6.0)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_file_listed_twice_counts_once_in_its_item(self, tmp_path: Path) -> None:
        recs = _skill(tmp_path, ".claude/skills/foo", "ref.md")
        (item,) = compute_item_scores(CombinedResult(quality=QualityResult()), _map(tmp_path, *recs, recs[1]), tmp_path)
        assert item.file_count == 2

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_same_name_skills_in_different_agent_dirs_are_two_items_named_by_folder(self, tmp_path: Path) -> None:
        rmap = _map(
            tmp_path, *_skill(tmp_path, ".claude/skills/foo"), *_skill(tmp_path, ".agents/skills/foo", agent="codex")
        )
        surfaces = compute_surface_scores(
            CombinedResult(quality=QualityResult()), ruleset_map=rmap, project_root=tmp_path
        )
        assert surfaces[0].item_count == 2
        items = compute_item_scores(CombinedResult(quality=QualityResult()), rmap, tmp_path)
        assert sorted(it.name for it in items) == [".agents/skills/foo", ".claude/skills/foo"]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_skill_md_the_agent_does_not_read_is_a_plain_file_not_a_skill(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/group/child", "ref.md"))
        skill_of = skill_lookup(rmap, tmp_path)
        rel = ".claude/skills/group/child/SKILL.md"
        assert skill_of == {}
        assert _surface_key(rel, {}, skill_of) != "skills"
        assert display._group_key(rel, {}, tmp_path, skill_of) != "skills"
        assert "skill" not in file_type_summary({rel}, skill_of)
        assert _display_name_for_path(rel, skill_of) == rel
        surfaces = compute_surface_scores(
            CombinedResult(quality=QualityResult()), ruleset_map=rmap, project_root=tmp_path
        )
        assert all(s.name != "Skills" for s in surfaces)
        with triage_view.console.capture() as cap:
            triage_view.print_file_card(rel, [], {}, False, project_root=tmp_path, skill_of=skill_of)
        assert rel in cap.get().splitlines()[0]  # named by its project-relative path, as a skill would be by "child"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_without_a_map_the_path_tag_decides(self, tmp_path: Path) -> None:
        rel = ".claude/skills/foo/SKILL.md"
        assert skill_lookup(None, tmp_path) is None
        assert _surface_key(rel, {}, None) == "skills"
        assert display._group_key(rel, {}, tmp_path, None) == "skills"
        assert file_type_summary({rel}, None) == "1 skill"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_docs_folder_skill_md_typed_generic_is_not_on_skills(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, _rec(tmp_path, "docs/skills/guide/SKILL.md", "generic", "generic"))
        skill_of = skill_lookup(rmap, tmp_path)
        rel = "docs/skills/guide/SKILL.md"
        result = CombinedResult(findings=(_finding(rel),), quality=QualityResult())
        assert skill_of == {}
        assert all(s.name != "Skills" for s in compute_surface_scores(result, ruleset_map=rmap, project_root=tmp_path))
        assert list(display._build_file_groups(result, {}, tmp_path, skill_of)) != ["skills"]
        assert "skill" not in file_type_summary({rel}, skill_of)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_symlink_inside_a_skill_folder_stays_in_the_skill(self, tmp_path: Path) -> None:
        skill = tmp_path / ".claude/skills/foo"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("# Foo\n")
        (tmp_path / "outside.md").write_text("# Outside\n")
        os.symlink(tmp_path / "outside.md", skill / "link.md")
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "link.md"))
        assert skill_lookup(rmap, tmp_path) == {
            ".claude/skills/foo/SKILL.md": ".claude/skills/foo",
            ".claude/skills/foo/link.md": ".claude/skills/foo",
        }

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    @pytest.mark.parametrize("file_type", ["referenced", "generic"])
    def test_a_supporting_file_also_linked_or_imported_stays_in_its_skill(self, tmp_path: Path, file_type: str) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "ref.md"))
        skill_of = skill_lookup(rmap, tmp_path)
        rel = ".claude/skills/foo/ref.md"
        ft = {rel: file_type}
        result = CombinedResult(findings=(_finding(rel),), quality=QualityResult())
        assert list(display._build_file_groups(result, ft, tmp_path, skill_of)) == ["skills"]
        surfaces = compute_surface_scores(result, ruleset_map=rmap, project_root=tmp_path, file_type_by_path=ft)
        assert [(s.name, s.item_count, s.finding_count) for s in surfaces] == [("Skills", 1, 1)]
        assert file_type_summary({rel, ".claude/skills/foo/SKILL.md"}, skill_of) == "1 skill"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_markdown_under_skills_dir_without_skill_md_is_not_a_skill(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, _rec(tmp_path, "docs/skills/guide/intro.md", "generic"))
        surfaces = compute_surface_scores(
            CombinedResult(quality=QualityResult()), ruleset_map=rmap, project_root=tmp_path
        )
        assert all(s.name != "Skills" for s in surfaces)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_group_header_counts_a_skill_once(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "a.md", "b.md"))
        skill_of = skill_lookup(rmap, tmp_path)
        group = [((tmp_path / p).as_posix(), []) for p in skill_of]  # raw, absolute finding paths
        with display.console.capture() as cap:
            display._render_group_header("skills", group, rmap, tmp_path, skill_of=skill_of)
        assert "(1)" in cap.get() and "(3)" not in cap.get()

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_findings_in_supporting_files_group_under_skills(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "ref.md"))
        groups = display._build_file_groups(
            CombinedResult(findings=(_finding(".claude/skills/foo/ref.md"),), quality=QualityResult()),
            {},
            tmp_path,
            skill_lookup(rmap, tmp_path),
        )
        assert list(groups) == ["skills"]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_card_names_supporting_file_by_path_inside_skill(self, tmp_path: Path) -> None:
        manifest = tmp_path / "plugins/reporails/.claude-plugin/plugin.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}")
        rmap = _map(tmp_path, *_skill(tmp_path, "plugins/reporails/skills/ails", "workflows/heal.md"))
        skill_of = skill_lookup(rmap, tmp_path)
        assert skill_of
        for rel, expected in (
            ("plugins/reporails/skills/ails/workflows/heal.md", "ails/workflows/heal.md"),
            ("plugins/reporails/skills/ails/SKILL.md", "ails"),
        ):
            with triage_view.console.capture() as cap:
                triage_view.print_file_card(rel, [], {}, False, project_root=tmp_path, skill_of=skill_of)
            assert expected in cap.get().splitlines()[0]
            assert "ails/ails" not in cap.get()
        with triage_view.console.capture() as cap:  # a raw, absolute finding path names the file the same way
            absolute = (tmp_path / "plugins/reporails/skills/ails/workflows/heal.md").as_posix()
            triage_view.print_file_card(absolute, [], {}, False, project_root=tmp_path, skill_of=skill_of)
        assert "ails/workflows/heal.md" in cap.get().splitlines()[0]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_path_equal_to_its_skill_folder_is_named_like_the_skill(self) -> None:
        from reporails_cli.formatters.text.display_constants import friendly_name

        assert friendly_name(".claude/skills/broken", "skills:broken", ".claude/skills/broken") == "broken"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_skill_md_inside_a_skill_folder_is_named_by_its_path_not_as_the_skill(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/tool"), *_skill(tmp_path, ".claude/skills/tool/inner"))
        skill_of = skill_lookup(rmap, tmp_path)
        heads = {}
        for rel in (".claude/skills/tool/SKILL.md", ".claude/skills/tool/inner/SKILL.md"):
            with triage_view.console.capture() as cap:
                triage_view.print_file_card(rel, [], {}, False, project_root=tmp_path, skill_of=skill_of)
            heads[rel] = cap.get().splitlines()[0]
        assert "tool/inner/SKILL.md" in heads[".claude/skills/tool/inner/SKILL.md"]
        assert "tool/" not in heads[".claude/skills/tool/SKILL.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_file_type_summary_counts_a_skill_once(self, tmp_path: Path) -> None:
        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "a.md", "b.md"))
        skill_of = skill_lookup(rmap, tmp_path)
        assert file_type_summary(set(skill_of), skill_of) == "1 skill"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_item_bars_hidden_for_one_skill_shown_for_two(self, tmp_path: Path) -> None:
        for bases, shown in ((("foo",), False), (("foo", "bar"), True)):
            recs = [r for b in bases for r in _skill(tmp_path, f".claude/skills/{b}", "ref.md")]
            rmap = _map(tmp_path, *recs)
            analyses = tuple(FileAnalysis(file=r.path, display_score=7.0, stats={"atoms": 1}) for r in recs)
            result = CombinedResult(per_file_analysis=analyses, quality=QualityResult(display_score=7.0))
            with item_scorecard.console.capture() as cap:
                display._render_findings_and_scorecard(
                    result, rmap, True, False, scorecard.ScopeInfo(), "free", 0, tmp_path, {}
                )
            assert ("foo:" in cap.get()) is shown


class TestSkillRecordConsumers:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_skill_lookup_reads_the_recorded_skill_and_decides_nothing(self, tmp_path: Path) -> None:
        rec = _rec(tmp_path, ".claude/skills/foo/SKILL.md")
        assert skill_lookup(_raw_map(rec), tmp_path) == {}  # nothing recorded: no skill
        rec.skill = (tmp_path / ".claude/skills/foo").as_posix()
        assert skill_lookup(_raw_map(rec), tmp_path) == {".claude/skills/foo/SKILL.md": ".claude/skills/foo"}

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_skill_md_in_no_skill_is_named_by_its_path_in_the_item_rows(self, tmp_path: Path) -> None:
        rel = ".cursor/skills/SKILL.md"
        rmap = _map(
            tmp_path, _rec(tmp_path, rel, agent="cursor"), *_skill(tmp_path, ".cursor/skills/a", agent="cursor")
        )
        names = {it.name for it in compute_item_scores(CombinedResult(quality=QualityResult()), rmap, tmp_path)}
        assert names == {rel, "a"}

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_payload_carries_a_relative_skill_only_for_a_file_in_one(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.payload import project_payload

        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo", "ref.md"), _rec(tmp_path, "docs/n.md", "generic"))
        files = {f["path"]: f for f in project_payload(rmap, tmp_path)["files"]}
        assert files[".claude/skills/foo/ref.md"]["skill"] == ".claude/skills/foo"
        assert "skill" not in files["docs/n.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_local_type_resolver_keeps_mapped_types_and_gates_unmapped_skills(self, tmp_path: Path) -> None:
        from reporails_cli.core.mapper.inspect import _load_registry
        from reporails_cli.core.pipeline.assemble import AssembleInputs, _local_finding_type_resolver

        rmap = _map(tmp_path, *_skill(tmp_path, ".claude/skills/foo"), _rec(tmp_path, ".claude/skills/bar/SKILL.md"))
        inp = AssembleInputs(
            m_findings=[], content_findings=[], client_findings=[], ruleset_map=rmap, scan_root=tmp_path,
            filter_agents=None, effective_agent="claude", lint_result=None, alias_fn=lambda _r: set(),
        )  # fmt: skip
        typed = _local_finding_type_resolver(inp, _load_registry())
        root = tmp_path.as_posix()
        assert typed(f"{root}/.claude/skills/foo/SKILL.md") == "skills"  # mapped: the record's type
        assert typed(f"{root}/.claude/skills/foo/new.md") == "skills"  # unmapped, in a recorded skill folder
        assert typed(f"{root}/.claude/skills/other/SKILL.md") == "generic"  # unmapped, in no recorded skill


class TestSkillFolderFromDisk:
    @staticmethod
    def _disk(root: Path, *rels: str) -> None:
        for rel in rels:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("# x\n")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_supporting_file_mapped_alone_stays_in_its_skill(self, tmp_path: Path) -> None:
        self._disk(tmp_path, ".claude/skills/foo/SKILL.md", ".claude/skills/foo/ref.md")
        rmap = _map(tmp_path, _rec(tmp_path, ".claude/skills/foo/ref.md", "generic"), agents=("claude",))
        assert _state(rmap, tmp_path) == {".claude/skills/foo/ref.md": ("skills", ".claude/skills/foo")}

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_single_deep_skill_md_stays_generic_for_claude_only(self, tmp_path: Path) -> None:
        rel = ".claude/skills/group/x/SKILL.md"
        self._disk(tmp_path, rel)
        rmap = _map(tmp_path, _rec(tmp_path, rel), agents=("claude",))
        assert _state(rmap, tmp_path)[rel] == ("generic", "")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_cursor_category_file_mapped_alone_is_in_its_skill(self, tmp_path: Path) -> None:
        self._disk(tmp_path, ".cursor/skills/cat/a/SKILL.md", ".cursor/skills/cat/a/ref.md")
        rmap = _map(tmp_path, _rec(tmp_path, ".cursor/skills/cat/a/ref.md", "generic", "cursor"), agents=("cursor",))
        assert _state(rmap, tmp_path)[".cursor/skills/cat/a/ref.md"] == ("skills", ".cursor/skills/cat/a")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_symlinked_skill_md_on_disk_still_owns_its_folder(self, tmp_path: Path) -> None:
        self._disk(tmp_path, "elsewhere/real.md", ".claude/skills/foo/ref.md")
        os.symlink(tmp_path / "elsewhere/real.md", tmp_path / ".claude/skills/foo/SKILL.md")
        rmap = _map(tmp_path, _rec(tmp_path, ".claude/skills/foo/ref.md", "generic"), agents=("claude",))
        assert _state(rmap, tmp_path)[".claude/skills/foo/ref.md"] == ("skills", ".claude/skills/foo")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_no_skill_md_on_disk_means_no_skill(self, tmp_path: Path) -> None:
        self._disk(tmp_path, ".claude/skills/foo/ref.md")
        rmap = _map(tmp_path, _rec(tmp_path, ".claude/skills/foo/ref.md", "skills"), agents=("claude",))
        assert _state(rmap, tmp_path)[".claude/skills/foo/ref.md"] == ("generic", "")


class TestEntryOnlyRegexCheck:
    """`CORE:S:0018` (skill name in kebab-case) reads a skill's entry `SKILL.md` only."""

    _YML = Path(__file__).resolve().parents[2] / "framework/rules/core/skill-directory-kebab-case/checks.yml"

    def _run(self, root: Path, files: dict[str, str], *, recorded: bool) -> set[str]:
        from reporails_cli.core.lint.regex import run_checks
        from reporails_cli.core.mapper.skills import skill_entry_paths
        from reporails_cli.core.platform.dto.models import ClassifiedFile

        classified = []
        for rel, name in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"---\nname: {name}\n---\n# Body\n")
            props: dict[str, str | list[str]] = {"skill": str(root / ".claude/skills/a")} if recorded else {}
            classified.append(ClassifiedFile(path=path, file_type="skills", properties=props))
        findings = run_checks(
            [self._YML],
            root,
            instruction_files=[cf.path for cf in classified],
            skill_entries=skill_entry_paths(classified),
        )
        return {f.file for f in findings if f.rule == "CORE:S:0018"}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_supporting_skill_md_inside_a_recorded_skill_is_not_reported(self, tmp_path: Path) -> None:
        files = {".claude/skills/a/SKILL.md": "good-name", ".claude/skills/a/b/SKILL.md": "Bad_Name"}
        assert self._run(tmp_path, files, recorded=True) == set()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_an_entry_skill_md_with_a_bad_name_is_still_reported(self, tmp_path: Path) -> None:
        files = {".claude/skills/a/SKILL.md": "Bad_Name", ".claude/skills/a/b/SKILL.md": "Bad_Name"}
        assert self._run(tmp_path, files, recorded=True) == {".claude/skills/a/SKILL.md"}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_without_recorded_skills_every_skill_md_is_checked(self, tmp_path: Path) -> None:
        files = {".claude/skills/a/SKILL.md": "Bad_Name", ".claude/skills/a/b/SKILL.md": "Bad_Name"}
        assert self._run(tmp_path, files, recorded=False) == set(files)


class TestSkillSlotFolders:
    """A direct subfolder of a one-level skills root is a slot a skill should fill."""

    @staticmethod
    def _tree(root: Path) -> RulesetMap:
        (root / ".claude/skills/good").mkdir(parents=True)
        (root / ".claude/skills/broken").mkdir()
        (root / ".claude/skills/.hidden").mkdir()
        (root / ".claude/skills/good/SKILL.md").write_text("x")
        (root / ".claude/skills/broken/notes.md").write_text("x")
        return _map(root, *_skill(root, ".claude/skills/good"), _rec(root, ".claude/skills/broken/notes.md"))

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_slot_folder_names_itself_in_membership(self, tmp_path: Path) -> None:
        from reporails_cli.core.mapper.skills import skill_membership, skill_slot_folders

        rmap = self._tree(tmp_path)
        broken = tmp_path / ".claude/skills/broken"
        assert skill_slot_folders(rmap, tmp_path) == {broken}
        members = skill_membership(rmap, tmp_path) or {}
        assert members[broken.as_posix()] == broken.as_posix()
        assert (broken / "notes.md").as_posix() not in members
        assert str(broken) not in (skill_membership(rmap) or {})

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_slot_folder_is_typed_skills_while_its_file_stays_generic(self, tmp_path: Path) -> None:
        from reporails_cli.core.mapper.skills import skill_membership, skill_type

        rmap = self._tree(tmp_path)
        folders = {Path(f) for f in (skill_membership(rmap, tmp_path) or {}).values()}
        assert skill_type("generic", tmp_path / ".claude/skills/broken", folders) == "skills"
        assert _state(rmap, tmp_path)[".claude/skills/broken/notes.md"] == ("generic", "")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_slot_folder_reaches_the_skills_surface(self, tmp_path: Path) -> None:
        rmap = self._tree(tmp_path)
        skill_of = skill_lookup(rmap, tmp_path)
        assert skill_of is not None
        assert _surface_key(".claude/skills/broken", {}, skill_of) == "skills"
        assert _surface_key(".claude/skills/broken/notes.md", {}, skill_of) != "skills"

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_no_slots_without_a_one_level_skills_root(self, tmp_path: Path) -> None:
        from reporails_cli.core.mapper.skills import skill_slot_folders

        (tmp_path / "docs/other").mkdir(parents=True)
        rmap = _map(tmp_path, _rec(tmp_path, "docs/other/a.md", type_="generic"))
        assert skill_slot_folders(rmap, tmp_path) == set()
