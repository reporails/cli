"""Unit tests for formatters/text/triage_view.py — collapse-the-tail rendering."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.runtime.merger import FindingItem
from reporails_cli.formatters.text import triage_view
from reporails_cli.formatters.text.display_constants import element_namer
from reporails_cli.formatters.triage import classify_regime

# The grade a paid reply carries for these rules in the fixtures below; any other rule is ungraded.
_REPLY_GRADES = {
    "CORE:C:0042": "gate_mover",
    "CORE:C:0037": "cosmetic",
    "CORE:C:0058": "conditional",
    "CORE:C:0060": "conditional",
    "CORE:E:0004": "conditional",
    "format": "cosmetic",
}


def _finding(
    rule: str,
    severity: str,
    message: str,
    line: int = 5,
    fix: str = "",
    pi: int | None = None,
    impact_tier: str | None = None,
) -> FindingItem:
    tier = _REPLY_GRADES.get(rule, "") if impact_tier is None else impact_tier
    return FindingItem(
        file="CLAUDE.md", line=line, severity=severity, rule=rule, message=message, fix=fix, pi=pi, impact_tier=tier
    )


def _render(monkeypatch: pytest.MonkeyPatch, findings: list[FindingItem], regime, verbose: bool = False) -> str:
    lines: list[str] = []
    monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
    sev_icons = {"error": "X", "warning": "!", "info": "i"}
    triage_view.print_file_card("CLAUDE.md", findings, sev_icons, verbose, regime)
    return "\n".join(lines)


class TestCollapseTail:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_over_capacity_collapses_ungraded_and_cosmetic_tail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Graded findings stay; cosmetic and ungraded warnings collapse to one row."""
        regime = classify_regime({"triage_tier": "partial"})
        findings = [
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
            _finding("CORE:C:0042", "warning", "Vague instruction"),
            _finding("CORE:C:0060", "warning", "Broad scope"),
            _finding("CORE:C:0037", "warning", "Static before dynamic"),
            _finding("CORE:S:0010", "warning", "File count outside bounds"),
            *[_finding("format", "warning", "unformatted", line=i) for i in range(10, 22)],
        ]
        out = _render(monkeypatch, findings, regime)
        assert "Unresolved imports: main" in out
        assert "Vague instruction" in out
        assert "Broad scope" in out
        assert "Static before dynamic" not in out
        assert "File count outside bounds" not in out
        assert "+14 more" in out
        assert "-v to list" in out
        assert "unformatted" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_ungraded_warning_is_never_promoted_but_ungraded_error_shows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "open"})
        findings = [
            _finding("CORE:C:0042", "warning", "Vague instruction"),
            _finding("CORE:S:0010", "warning", "File count outside bounds"),
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
        ]
        out = _render(monkeypatch, findings, regime)
        assert "Unresolved imports: main" in out
        assert "File count outside bounds" not in out
        assert "+1 more" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize("token", ["partial", "open"])
    def test_file_without_a_graded_finding_renders_the_neutral_body(
        self, monkeypatch: pytest.MonkeyPatch, token: str
    ) -> None:
        regime = classify_regime({"triage_tier": token})
        findings = [
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
            _finding("CORE:S:0010", "warning", "File count outside bounds"),
        ]
        out = _render(monkeypatch, findings, regime)
        assert "Unresolved imports: main" in out
        assert "File count outside bounds" in out
        assert "more · -v to list" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_restores_full_per_line_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        findings = [
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
            *[_finding("format", "warning", "unformatted", line=i) for i in range(10, 22)],
        ]
        out = _render(monkeypatch, findings, regime, verbose=True)
        assert "+12 more" not in out
        assert "unformatted" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_low_confidence_regime_falls_back_to_neutral_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A marginal regime degrades to today's neutral view — no collapse row asserted."""
        regime = classify_regime({"triage_tier": "neutral"})
        assert regime is not None and regime.confident is False
        findings = [
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
            *[_finding("format", "warning", "unformatted", line=i) for i in range(10, 22)],
        ]
        out = _render(monkeypatch, findings, regime)
        assert "more · -v to list" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_offline_no_regime_renders_neutral_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        findings = [_finding("CORE:S:0024", "error", "Unresolved imports: main")]
        out = _render(monkeypatch, findings, None)
        assert "Unresolved imports: main" in out
        assert "more · -v to list" not in out


class TestNoRemedyInTerminal:
    """The terminal lists findings, never their fix text — remedies reach the coding agent through MCP."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_shown_finding_renders_without_its_fix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        findings = [_finding("CORE:C:0042", "warning", "Vague instruction", fix="FIX-TEXT-MUST-NOT-RENDER")]
        out = _render(monkeypatch, findings, regime)
        assert "Vague instruction" in out
        assert "FIX-TEXT-MUST-NOT-RENDER" not in out
        assert "→" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_neutral_path_renders_without_its_fix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # regime=None → neutral/structural path.
        findings = [_finding("CORE:S:0024", "error", "Unresolved imports: main", fix="FIX-TEXT-MUST-NOT-RENDER")]
        out = _render(monkeypatch, findings, None)
        assert "Unresolved imports: main" in out
        assert "FIX-TEXT-MUST-NOT-RENDER" not in out
        assert "→" not in out


class TestClientCheckRuleIds:
    """Client-check labels render their canonical rule ID, consistent with server findings."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_display_rule_id_maps_client_labels(self) -> None:
        from reporails_cli.formatters.text.display_constants import display_rule_id

        assert display_rule_id("format") == "CORE:E:0003"
        assert display_rule_id("bold") == "CORE:E:0003"
        assert display_rule_id("heading_instruction") == "CORE:S:0039"
        # Server IDs and unmapped client diagnostics pass through unchanged.
        assert display_rule_id("CORE:C:0042") == "CORE:C:0042"
        assert display_rule_id("ambiguous_charge") == "ambiguous_charge"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_triaged_render_shows_canonical_id_not_label(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        findings = [_finding("CORE:C:0060", "warning", "Broad scope")]
        out = _render(monkeypatch, findings, regime)
        assert "CORE:C:0060" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_rule_docs_url_maps_agent_and_slug(self) -> None:
        from reporails_cli.formatters.text.display_constants import rule_docs_url

        assert rule_docs_url("CORE:E:0003") == "https://reporails.com/rules/core/formatting-regime"
        assert rule_docs_url("CODEX:E:0001") == "https://reporails.com/rules/codex/agents-md-within-size-limit"
        # Bare labels / non-canonical tokens do not resolve to a docs page.
        assert rule_docs_url("general") is None

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_triaged_render_hyperlinks_the_rule_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        out = _render(monkeypatch, [_finding("CORE:C:0042", "warning", "Vague instruction")], regime)
        assert "[link=https://reporails.com/rules/core/specificity-gap]CORE:C:0042[/link]" in out


class TestGeneralizedRowDropsInstanceCounts:
    """A grouped row stands for several lines, so one line's word count must not label it."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_word_count_is_stripped(self) -> None:
        msg = "Too brief (6 words) — not enough detail for the model to act on."
        assert triage_view._generalize_message(msg, "CORE:E:0004") == "Too brief"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_singular_word_count_is_stripped(self) -> None:
        assert triage_view._generalize_message("Too brief (1 word) — x", "CORE:E:0004") == "Too brief"


class TestHeadingCount:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_heading_findings_count_as_one_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Each heading carrying an instruction is a finding; the card shows one
        # "heading as instruction" count, not one row per heading.
        findings = [
            _finding("CORE:S:0039", "warning", 'Instruction in heading: "A"', line=3),
            _finding("CORE:S:0039", "warning", 'Instruction in heading: "B"', line=9),
            _finding("CORE:S:0039", "warning", 'Instruction in heading: "C"', line=12),
        ]
        out = _render(monkeypatch, findings, None)
        assert out.count("heading as instruction") == 1
        assert "3 heading as instruction" in out


class TestPackedSentenceRow:
    PACKED = "CORE:C:0058"

    def _findings(self) -> list[FindingItem]:
        return [
            _finding(self.PACKED, "warning", "This sentence holds 3 instructions", line=7),
            _finding("CORE:E:0004", "warning", "Soft wording", line=7, pi=1),
            _finding("CORE:C:0042", "warning", "Vague instruction", line=7, pi=2),
            _finding("CORE:C:0037", "warning", "Static before dynamic", line=9),
        ]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_triaged_view_nests_a_packed_line_s_findings_under_its_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        out = _render(monkeypatch, self._findings(), regime).splitlines()
        head = next(i for i, ln in enumerate(out) if self.PACKED in ln)
        assert "L7 " in out[head] and "This sentence holds 3 instructions" in out[head]
        nested = out[head + 1 : head + 3]
        assert {"CORE:E:0004", "CORE:C:0042"} == {r for ln in nested for r in ("CORE:E:0004", "CORE:C:0042") if r in ln}
        indent = out[head].index("!")
        assert all(ln.index("!") > indent for ln in nested)
        assert not any("CORE:C:0037" in ln for ln in out)
        assert any("+1 more" in ln for ln in out)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_view_nests_a_packed_line_s_findings_under_its_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        out = _render(monkeypatch, self._findings(), regime, verbose=True).splitlines()
        head = next(i for i, ln in enumerate(out) if self.PACKED in ln)
        nested = out[head + 1 : head + 3]
        assert {"CORE:E:0004", "CORE:C:0042"} == {r for ln in nested for r in ("CORE:E:0004", "CORE:C:0042") if r in ln}
        assert all(ln.index("!") > out[head].index("L7") for ln in nested)
        assert sum("CORE:" in ln for ln in out) == 4
        assert sum(self.PACKED in ln for ln in out) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_line_without_a_packed_finding_renders_flat(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        findings = [f for f in self._findings() if f.rule != self.PACKED]
        out = _render(monkeypatch, findings, regime).splitlines()
        marks = {ln.index("!") for ln in out if "CORE:" in ln}
        assert len(marks) == 1 and len([ln for ln in out if "CORE:" in ln]) == 2

    def _two_packed(self) -> list[FindingItem]:
        return [
            _finding(self.PACKED, "warning", "First packed sentence", line=7, pi=1),
            _finding(self.PACKED, "warning", "Second packed sentence", line=7, pi=2),
            _finding("CORE:E:0004", "warning", "Soft wording", line=7, pi=1),
            _finding("CORE:C:0042", "warning", "Vague instruction", line=7, pi=2),
        ]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize("verbose", [False, True])
    def test_two_packed_sentences_on_a_line_print_each_finding_once_under_the_first(
        self, monkeypatch: pytest.MonkeyPatch, verbose: bool
    ) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        out = _render(monkeypatch, self._two_packed(), regime, verbose=verbose).splitlines()
        assert sum("CORE:E:0004" in ln for ln in out) == 1
        assert sum("CORE:C:0042" in ln for ln in out) == 1
        first = next(i for i, ln in enumerate(out) if "First packed sentence" in ln)
        second = next(i for i, ln in enumerate(out) if "Second packed sentence" in ln)
        assert first < second
        between = out[first + 1 : second]
        assert len(between) == 2 and all("CORE:" in ln for ln in between)
        assert not any("CORE:" in ln for ln in out[second + 1 :])
        assert "L7 " in out[second]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize("verbose", [False, True])
    def test_a_finding_not_about_an_instruction_stays_out_of_the_packed_row(
        self, monkeypatch: pytest.MonkeyPatch, verbose: bool
    ) -> None:
        regime = classify_regime({"triage_tier": "partial"})
        findings = [
            *self._findings()[:3],
            _finding("CORE:S:0056", "error", "Broken link - docs/missing.md does not exist.", line=7),
        ]
        out = _render(monkeypatch, findings, regime, verbose=verbose).splitlines()
        head = next(i for i, ln in enumerate(out) if self.PACKED in ln)
        link = next(i for i, ln in enumerate(out) if "CORE:S:0056" in ln)
        nested = next(ln for ln in out[head + 1 :] if "CORE:E:0004" in ln)
        assert out[link].index("X") < nested.index("!")
        assert sum("CORE:S:0056" in ln for ln in out) == 1


class TestDocumentationConventions:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_conventions_collapse_to_one_counted_line(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Findings that only name a missing convention fold into one counted line under the card."""
        findings = [_finding("CORE:S:0024", "error", "Unresolved imports: main")] + [
            FindingItem(
                file="CLAUDE.md",
                line=1,
                severity="warning",
                rule=f"CORE:C:{i:04d}",
                message="Missing topic",
                convention=True,
            )
            for i in range(3)
        ]
        out = _render(monkeypatch, findings, None)
        assert "Unresolved imports: main" in out
        assert "Missing topic" not in out
        assert "3 documentation conventions not present · -v to list" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_lists_conventions_as_findings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        findings = [
            FindingItem(
                file="CLAUDE.md",
                line=1,
                severity="warning",
                rule="CORE:C:0005",
                message="Missing topic",
                convention=True,
            )
        ]
        out = _render(monkeypatch, findings, None, verbose=True)
        assert "Missing topic" in out
        assert "documentation convention" not in out


class TestFileLevelOverlap:
    _OVERLAP = (
        "62% of the instructions in this file and `AGENTS.md` cover the same topics \u2014 the copies can drift apart."
    )

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_file_pair_overlap_renders_at_file_level_not_under_its_line(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        findings = [
            _finding("CORE:C:0044", "warning", self._OVERLAP, line=11),
            _finding("CORE:C:0042", "warning", "Vague instruction", line=11),
        ]
        out = _render(monkeypatch, findings, classify_regime({}), verbose=True)
        overlap_row = next(r for r in out.splitlines() if "topic overlap with AGENTS.md" in r)
        vague_row = next(r for r in out.splitlines() if "Vague instruction" in r)
        assert "L11" not in overlap_row
        assert "CORE:C:0044" in overlap_row
        assert "L11" in vague_row
        # right under the file header: before the line-anchored finding
        assert out.index("topic overlap with AGENTS.md") < out.index("Vague instruction")

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_other_overlap_findings_keep_their_line(self, monkeypatch: pytest.MonkeyPatch) -> None:
        findings = [_finding("CORE:C:0044", "warning", "Overlaps another instruction", line=11)]
        out = _render(monkeypatch, findings, classify_regime({}), verbose=True)
        row = next(r for r in out.splitlines() if "Overlaps another instruction" in r)
        assert "L11" in row

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_overlap_rows_name_the_partner_element_and_order_by_percentage(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from dataclasses import dataclass

        @dataclass
        class Rec:
            path: str
            type: str = "skills"
            skill: str = ""
            agent: str = "claude"

        @dataclass
        class Map:
            files: tuple = ()
            atoms: tuple = ()

        rmap = Map((Rec(str(tmp_path / ".claude/skills/x/SKILL.md"), "skills", str(tmp_path / ".claude/skills/x")),))
        msg = "{}% of the instructions in this file and `{}` cover the same topics \u2014 the copies can drift apart."
        findings = [
            _finding("CORE:C:0044", "warning", msg.format(30, "AGENTS.md"), line=4),
            _finding("CORE:C:0044", "warning", msg.format(62, ".claude/skills/x/SKILL.md"), line=11),
        ]
        lines: list[str] = []
        monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
        triage_view.print_file_card(
            "CLAUDE.md",
            findings,
            {},
            True,
            classify_regime({}),
            project_root=tmp_path,
            element_of=element_namer(rmap, tmp_path),
        )
        rows = [r for r in lines if "topic overlap with" in r]
        assert "62% topic overlap with the `x` skill" in rows[0] and "CORE:C:0044" in rows[0]
        assert "30% topic overlap with AGENTS.md" in rows[1]
        assert not any("of the instructions in this file" in r for r in lines)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_one_row_per_partner_element_keeps_the_highest_percentage(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from dataclasses import dataclass

        @dataclass
        class Rec:
            path: str
            type: str = "skills"
            skill: str = ""
            agent: str = "claude"

        @dataclass
        class Map:
            files: tuple = ()
            atoms: tuple = ()

        folder = str(tmp_path / ".claude/skills/bootstrap")
        rmap = Map((Rec(folder + "/SKILL.md", "skills", folder), Rec(folder + "/ref.md", "skills", folder)))
        msg = "{}% of the instructions in this file and `{}` cover the same topics \u2014 the copies can drift apart."
        findings = [
            _finding("CORE:C:0044", "warning", msg.format(27, ".claude/skills/bootstrap/ref.md"), line=4),
            _finding("CORE:C:0044", "warning", msg.format(30, ".claude/skills/bootstrap/SKILL.md"), line=11),
        ]
        lines: list[str] = []
        monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
        triage_view.print_file_card(
            "CLAUDE.md",
            findings,
            {},
            True,
            classify_regime({}),
            project_root=tmp_path,
            element_of=element_namer(rmap, tmp_path),
        )
        rows = [r for r in lines if "topic overlap with" in r]
        assert len(rows) == 1
        assert "30% topic overlap with the `bootstrap` skill" in rows[0]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_same_named_partner_skills_are_disambiguated(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        from types import SimpleNamespace

        def rec(folder: str) -> SimpleNamespace:
            return SimpleNamespace(
                path=str(tmp_path / folder / "SKILL.md"), type="skills", skill=str(tmp_path / folder), agent="claude"
            )

        rmap = SimpleNamespace(files=(rec(".claude/skills/foo"), rec(".agents/skills/foo")), atoms=())
        msg = "{}% of the instructions in this file and `{}` cover the same topics \u2014 the copies can drift apart."
        findings = [
            _finding("CORE:C:0044", "warning", msg.format(40, ".claude/skills/foo/SKILL.md"), line=4),
            _finding("CORE:C:0044", "warning", msg.format(30, ".agents/skills/foo/SKILL.md"), line=5),
        ]
        lines: list[str] = []
        monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
        triage_view.print_file_card(
            "CLAUDE.md",
            findings,
            {},
            True,
            classify_regime({}),
            project_root=tmp_path,
            element_of=element_namer(rmap, tmp_path),
        )
        rows = [r for r in lines if "topic overlap with" in r]
        assert len(rows) == 2
        assert "40% topic overlap with the `foo` skill (.claude/skills/foo)" in rows[0]
        assert "30% topic overlap with the `foo` skill (.agents/skills/foo)" in rows[1]

    _MSG = "{}% of the instructions in this file and `{}` cover the same topics \u2014 the copies can drift apart."

    def _card(self, monkeypatch, findings, verbose, tmp_path, rmap=None, path="CLAUDE.md"):
        lines: list[str] = []
        monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
        triage_view.print_file_card(
            path,
            findings,
            {"warning": "!"},
            verbose,
            classify_regime({"triage_tier": "partial"}),
            project_root=tmp_path,
            element_of=element_namer(rmap, tmp_path) if rmap is not None else None,
        )
        return lines

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_default_view_renders_overlap_as_file_level_rows(self, monkeypatch, tmp_path) -> None:
        findings = [
            *[
                _finding("CORE:C:0044", "warning", self._MSG.format(62, "AGENTS.md"), line=i, impact_tier="gate_mover")
                for i in range(5)
            ],
            _finding("CORE:C:0042", "warning", "Vague instruction", line=9),
        ]
        lines = self._card(monkeypatch, findings, False, tmp_path)
        rows = [r for r in lines if "topic overlap with" in r]
        assert len(rows) == 1 and "62% topic overlap with AGENTS.md" in rows[0] and "CORE:C:0044" in rows[0]
        assert not any("of the instructions in this file" in r or "\u00d75" in r for r in lines)
        assert any("Vague instruction" in r for r in lines)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize("verbose", [False, True])
    def test_overlap_member_is_pulled_out_of_its_packed_sentence_owner(self, monkeypatch, tmp_path, verbose) -> None:
        findings = [
            _finding("CORE:C:0058", "warning", "This sentence holds 2 instructions", line=24),
            _finding(
                "CORE:C:0044", "warning", self._MSG.format(38, "AGENTS.md"), line=24, pi=3, impact_tier="gate_mover"
            ),
            _finding("CORE:E:0004", "warning", "Too brief", line=24, pi=4, impact_tier="conditional"),
        ]
        lines = self._card(monkeypatch, findings, verbose, tmp_path)
        overlap = [r for r in lines if "topic overlap with AGENTS.md" in r]
        assert len(overlap) == 1 and "L24" not in overlap[0]
        assert any("This sentence holds 2 instructions" in r for r in lines)
        assert any("Too brief" in r for r in lines)  # the owner keeps its other members

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_partner_inside_the_same_skill_is_named_by_its_path_in_the_skill(self, monkeypatch, tmp_path) -> None:
        from types import SimpleNamespace

        folder = str(tmp_path / ".claude/skills/bootstrap")
        rec = lambda rel: SimpleNamespace(path=f"{folder}/{rel}", type="skills", skill=folder, agent="claude")  # noqa: E731
        rmap = SimpleNamespace(files=(rec("SKILL.md"), rec("references/bootstrap-workflow.md")), atoms=())
        findings = [
            _finding("CORE:C:0044", "warning", self._MSG.format(62, ".claude/skills/bootstrap/SKILL.md"), line=3)
        ]
        lines = self._card(
            monkeypatch, findings, False, tmp_path, rmap, ".claude/skills/bootstrap/references/bootstrap-workflow.md"
        )
        rows = [r for r in lines if "topic overlap with" in r]
        assert "62% topic overlap with the `bootstrap` skill's SKILL.md" in rows[0]
