"""Tests for core/lint/suppression.py — inline per-line finding suppression."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.suppression import (
    apply_suppressions,
    apply_surface_mutations,
    build_index,
    finding_surface,
    parse_directives,
)
from reporails_cli.core.platform.adapters.registry import load_rules
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.runtime.merger import merge_results
from reporails_cli.formatters.text.rule_meta import rule_aliases


class TestParseDirectives:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("separator", ["\u2028", "\x0c", "\x85", "\x1e"])
    def test_lines_are_counted_at_newlines_only(self, separator: str) -> None:
        text = f"Intro{separator}still line one.\nDo the thing.  <!-- ails-disable-line CORE:C:0049 -->\n"
        assert parse_directives(text) == {2: {"CORE:C:0049"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_same_line_html_comment(self) -> None:
        text = "Do the thing.  <!-- ails-disable-line CORE:C:0049 -->\n"
        assert parse_directives(text) == {1: {"CORE:C:0049"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_multiple_rules_space_and_comma(self) -> None:
        text = "x\ny  <!-- ails-disable-line CORE:C:0049, CORE:C:0046 -->\n"
        assert parse_directives(text) == {2: {"CORE:C:0049", "CORE:C:0046"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_slug_token_accepted(self) -> None:
        text = "y  <!-- ails-disable-line italic-constraints -->\n"
        assert parse_directives(text) == {1: {"italic-constraints"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_bare_directive_names_nothing(self) -> None:
        # No rule named → targeted-only contract: suppress nothing.
        assert parse_directives("y  <!-- ails-disable-line -->\n") == {}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_directive(self) -> None:
        assert parse_directives("just prose\nmore prose\n") == {}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    # Line 2: directive for CORE:C:0049. Line 4: same rule, no directive.
    (tmp_path / "CLAUDE.md").write_text(
        "# Title\nDescribe behavior.  <!-- ails-disable-line CORE:C:0049 -->\nspacer\nAnother ambiguous instruction.\n",
        encoding="utf-8",
    )
    return tmp_path


def _result(project: Path):
    findings = [
        LocalFinding("CLAUDE.md", 2, "warning", "CORE:C:0049", "ambiguous", source="client_check"),
        LocalFinding("CLAUDE.md", 4, "warning", "CORE:C:0049", "ambiguous", source="client_check"),
    ]
    return merge_results([], findings, None, project_root=project)


class TestApplySuppressions:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_suppressed_line_silent_sibling_still_fires(self, project: Path) -> None:
        result = _result(project)
        assert len(result.findings) == 2

        out = apply_suppressions(result, project_root=project, alias_fn=rule_aliases)

        # Both directions: the annotated line is gone, the un-annotated sibling stays.
        lines = sorted(f.line for f in out.findings)
        assert lines == [4]
        assert out.stats.total_findings == 1
        assert out.stats.warnings == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unnamed_rule_on_line_does_not_suppress(self, project: Path) -> None:
        # Directive names CORE:C:0049 only; a different rule on the same line still fires.
        findings = [
            LocalFinding("CLAUDE.md", 2, "warning", "CORE:C:0046", "conflict", source="client_check"),
        ]
        result = merge_results([], findings, None, project_root=project)
        out = apply_suppressions(result, project_root=project, alias_fn=rule_aliases)
        assert len(out.findings) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_canonical_id_directive_matches_client_token(self, tmp_path: Path) -> None:
        # Author copies the displayed canonical ID; finding carries the raw client token.
        (tmp_path / "CLAUDE.md").write_text(
            "constraint first  <!-- ails-disable-line CORE:E:0003 -->\n", encoding="utf-8"
        )
        findings = [LocalFinding("CLAUDE.md", 1, "warning", "bold", "bold on term", source="client_check")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)
        assert out.findings == ()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("token", ["heading_instruction", "CORE:S:0039", "heading-as-instruction"])
    def test_heading_finding_is_silenced_by_its_token_id_or_slug(self, tmp_path: Path, token: str) -> None:
        (tmp_path / "CLAUDE.md").write_text(
            f"## Never commit secrets  <!-- ails-disable-line {token} -->\n", encoding="utf-8"
        )
        findings = [LocalFinding("CLAUDE.md", 1, "warning", "CORE:S:0039", "heading", source="content_query")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)
        assert out.findings == ()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_directive_file_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("plain prose\n", encoding="utf-8")
        findings = [LocalFinding("CLAUDE.md", 1, "warning", "CORE:C:0049", "x", source="client_check")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)
        assert out is result

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_default_alias_is_exact_rule_token(self, project: Path) -> None:
        # Without an alias_fn only the exact raw token matches.
        result = _result(project)
        out = apply_suppressions(result, project_root=project)
        assert sorted(f.line for f in out.findings) == [4]


class TestBuildIndex:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_missing_file_skipped(self, tmp_path: Path) -> None:
        assert build_index(["does-not-exist.md"], tmp_path) == {}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_directive_in_non_utf8_file_is_indexed(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_bytes(b"caf\xe9 here <!-- ails-disable-line CORE:C:0049 -->\n")
        assert build_index(["CLAUDE.md"], tmp_path) == {("CLAUDE.md", 1): {"CORE:C:0049"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_directive_line_tracks_import_expansion(self, tmp_path: Path) -> None:
        """Regression: build_index used to key a directive at its import-EXPANDED
        line, but atom/finding line numbers are SOURCE lines (`pipeline.py`
        translates `atom.line` back to source coordinates after tokenizing expanded
        content). With an `@import` above a directive, the expanded
        and source lines diverge, and keying on the expanded line silently missed
        the suppression. The index must key the directive at its own SOURCE line."""
        (tmp_path / "frag.md").write_text("imported line one\nimported line two\n", encoding="utf-8")
        main = tmp_path / "CLAUDE.md"
        # Directive is written on source line 2; @frag.md expands to 2 lines, pushing
        # the same text to expanded line 3 — the index must use the SOURCE line (2).
        main.write_text("@frag.md\nDo the thing.  <!-- ails-disable-line CORE:C:0049 -->\n", encoding="utf-8")

        from reporails_cli.core.mapper.imports import expand_imports

        expanded = expand_imports(main.read_text(encoding="utf-8"), main)
        expanded_line = next(i for i, line in enumerate(expanded.splitlines(), start=1) if "ails-disable-line" in line)
        assert expanded_line != 2, "import expansion did not move the directive off its source line"

        index = build_index(["CLAUDE.md"], tmp_path)

        assert ("CLAUDE.md", 2) in index, f"directive not keyed at its own source line: {index}"
        assert index[("CLAUDE.md", 2)] == {"CORE:C:0049"}
        assert ("CLAUDE.md", expanded_line) not in index, "directive keyed at the expanded line, not the source line"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_directive_after_import_suppresses_finding_end_to_end(self, tmp_path: Path) -> None:
        """End-to-end through the real suppression filter: a finding at the SOURCE
        line (what pipeline.py now always reports) must still be suppressed when an
        `@import` precedes the directive's line."""
        (tmp_path / "frag.md").write_text("imported line one\nimported line two\n", encoding="utf-8")
        main = tmp_path / "CLAUDE.md"
        main.write_text("@frag.md\nDo the thing.  <!-- ails-disable-line CORE:C:0049 -->\n", encoding="utf-8")

        findings = [LocalFinding("CLAUDE.md", 2, "warning", "CORE:C:0049", "ambiguous", source="client_check")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)
        assert out.findings == ()


class TestSurfaceMutations:
    """SEAM tests for surface-scoped mutation — a rule's `surface_mutations` drops its findings
    on the declared surface while the rule stays armed everywhere else. Reddens if the filter
    stops dropping memory-surface findings, over-drops off-surface findings, or loses alias
    resolution."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_finding_surface_resolves_memory(self) -> None:
        assert finding_surface("memory/MEMORY.md") == "memory"
        assert finding_surface("x/memory/feedback_a.md") == "memory"
        # Subagent-memory scopes (agent-memory/ user+project, agent-memory-local/ local)
        # resolve to the same `memory` surface as the auto-memory index.
        assert finding_surface(".claude/agent-memory/foo/MEMORY.md") == "memory"
        assert finding_surface("~/.claude/agent-memory/foo/MEMORY.md") == "memory"
        assert finding_surface(".claude/agent-memory-local/bar/MEMORY.md") == "memory"
        # Non-memory paths resolve to their own tag, not "memory".
        assert finding_surface("CLAUDE.md") == "main"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_every_config_memory_scope_resolves_to_memory_surface(self) -> None:
        # SEAM driven from live config: for EVERY memory / subagent_memory
        # scope pattern the bundled config declares, a MEMORY.md under that directory must
        # resolve to the `memory` surface. Reddens if the fix is reverted OR if config grows a
        # new memory scope `classify_file` does not cover — asserting behavior (finding_surface
        # output), not re-deriving the internal dir-name set.
        import yaml

        from reporails_cli.core.classify.file_tags import _MEMORY_SURFACE_FILE_TYPES
        from reporails_cli.core.platform.config.bundled import get_bundled_rules_path

        rules_dir = get_bundled_rules_path()
        assert rules_dir is not None, "bundled rules must resolve in-repo"

        checked = 0
        for config_path in rules_dir.glob("*/config.yml"):
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            for ft_name, ft in (data.get("file_types") or {}).items():
                if ft_name not in _MEMORY_SURFACE_FILE_TYPES or not isinstance(ft, dict):
                    continue
                for scope in (ft.get("scopes") or {}).values():
                    for pattern in (scope or {}).get("patterns", []) or []:
                        p = str(pattern)
                        if not p.endswith("/"):
                            continue
                        sample = f"{p}x/MEMORY.md" if p.endswith("*/") else f"{p}MEMORY.md"
                        assert finding_surface(sample) == "memory", f"{ft_name} scope {p!r} not covered"
                        checked += 1
        assert checked, "config must declare at least one memory-surface directory scope"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_schema_validated_surfaces_that_are_not_json_or_toml_resolve_to_config(self) -> None:
        # The shipped machine-config surfaces a suffix guess cannot see. `surface_mutations:
        # {config: {applies: false}}` only suppresses prose findings on a file the classifier
        # calls `config`; these three were tagged `file`, so prose-quality rules fired on
        # machine config.
        assert finding_surface(".codex/rules/style.rules") == "config"
        assert finding_surface("packages/api/.agents/skills/foo/agents/openai.yaml") == "config"
        assert finding_surface(".gemini/extensions/acme/manifest.md") == "config"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_every_config_schema_validated_scope_resolves_to_config_surface(self) -> None:
        # SEAM driven from live config, the same shape as the memory drift-guard above: for
        # EVERY repo-relative `format: schema_validated` scope pattern the bundled configs
        # declare, a file matching it resolves to the `config` surface. Reddens if the
        # derivation regresses to a suffix guess OR if config grows a schema-validated surface
        # the classifier does not cover.
        import yaml

        from reporails_cli.core.classify.file_tags import _SCHEMA_VALIDATED
        from reporails_cli.core.platform.config.bundled import get_bundled_rules_path

        rules_dir = get_bundled_rules_path()
        assert rules_dir is not None, "bundled rules must resolve in-repo"

        checked = 0
        for config_path in rules_dir.glob("*/config.yml"):
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            for ft in (data.get("file_types") or {}).values():
                if not isinstance(ft, dict) or ft.get("format") != _SCHEMA_VALIDATED:
                    continue
                for scope in (ft.get("scopes") or {}).values():
                    for pattern in (scope or {}).get("patterns", []) or []:
                        p = str(pattern)
                        if p.startswith(("~", "/")) or ":" in p.split("/", 1)[0]:
                            continue  # user-scope / managed absolute: not a repo path
                        segs = [seg for seg in p.split("/") if seg]
                        if segs[-1] == "**":
                            segs = [*segs[:-1], "acme", "manifest.md"]
                        else:
                            segs = ["dir" if seg == "**" else seg.replace("*", "x") for seg in segs]
                        sample = "/".join(segs)
                        assert finding_surface(sample) == "config", f"{p!r} -> {sample!r} not config"
                        checked += 1
        assert checked, "config must declare at least one repo-relative schema_validated scope"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_structural_file_under_memory_dir_not_memory(self) -> None:
        # A skill / agent / rule markdown file that lives under a
        # directory literally named `memory/` must NOT resolve to the memory surface, or its
        # real content-quality findings get silently suppressed. classify_file's structural-
        # directory precedence decides these first; finding_surface must honor it.
        assert finding_surface("skills/memory/SKILL.md") == "skills"
        assert finding_surface("agents/memory.md") == "agents"
        assert finding_surface(".claude/rules/memory.md") == "rules"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_skill_under_memory_dir_finding_not_suppressed(self, tmp_path: Path) -> None:
        # The end-to-end consequence of the precedence fix: a surface-mutated rule's finding on
        # a skill file under `memory/` survives (it is a skill surface, not memory).
        rules = load_rules()
        findings = [LocalFinding("skills/memory/SKILL.md", 1, "warning", "CORE:D:0003", "order", source="server")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_surface_mutations(result, rules, alias_fn=rule_aliases)
        assert len(out.findings) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_memory_finding_dropped_offsurface_kept(self, tmp_path: Path) -> None:
        # CORE:D:0003 (instruction-ordering) carries surface_mutations {memory: applies false}.
        rules = load_rules()
        findings = [
            LocalFinding("memory/MEMORY.md", 1, "warning", "CORE:D:0003", "order", source="server"),
            LocalFinding("CLAUDE.md", 1, "warning", "CORE:D:0003", "order", source="server"),
        ]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_surface_mutations(result, rules, alias_fn=rule_aliases)
        surviving = {f.file for f in out.findings}
        assert not any(finding_surface(f.file) == "memory" for f in out.findings)
        assert "CLAUDE.md" in surviving  # off-surface finding for the same rule stays armed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_client_token_aliases_to_mutated_rule(self, tmp_path: Path) -> None:
        # The client-side "bold" token aliases to CORE:E:0003; the mutation must reach it.
        rules = load_rules()
        findings = [LocalFinding("memory/MEMORY.md", 1, "warning", "bold", "bold on term", source="client_check")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_surface_mutations(result, rules, alias_fn=rule_aliases)
        assert out.findings == ()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unmutated_rule_still_fires_on_memory(self, tmp_path: Path) -> None:
        # "memory_frontmatter" (a client-check theory label, no shipped rule covers it)
        # declares no surface_mutations — it must stay armed on the memory surface, so the
        # filter cannot blanket-suppress the memory index.
        rules = load_rules()
        findings = [LocalFinding("memory/MEMORY.md", 1, "warning", "memory_frontmatter", "fm", source="client_check")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_surface_mutations(result, rules, alias_fn=rule_aliases)
        assert len(out.findings) == 1
