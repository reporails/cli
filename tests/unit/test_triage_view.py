"""Unit tests for formatters/text/triage_view.py — collapse-the-tail rendering."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.runtime.merger import FindingItem
from reporails_cli.formatters.text import triage_view
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
