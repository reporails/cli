"""Unit tests for formatters/text/triage_view.py — collapse-the-tail rendering."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.policy.leverage import classify_regime
from reporails_cli.core.platform.runtime.merger import FindingItem
from reporails_cli.formatters.text import triage_view


def _finding(rule: str, severity: str, message: str, line: int = 5, fix: str = "") -> FindingItem:
    return FindingItem(file="CLAUDE.md", line=line, severity=severity, rule=rule, message=message, fix=fix)


def _render(monkeypatch: pytest.MonkeyPatch, findings: list[FindingItem], regime, verbose: bool = False) -> str:
    lines: list[str] = []
    monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
    sev_icons = {"error": "X", "warning": "!", "info": "i"}
    triage_view.print_file_card("CLAUDE.md", findings, sev_icons, verbose, regime)
    return "\n".join(lines)


class TestCollapseTail:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_over_capacity_collapses_amplitude_tail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Abstract over-capacity file: gate-movers stay, amplitude tail collapses to one row."""
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": True, "confident": True}
        )
        findings = [
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
            _finding("CORE:C:0042", "warning", "Vague instruction"),
            _finding("CORE:C:0044", "warning", "Topic scatter"),
            *[_finding("format", "warning", "unformatted", line=i) for i in range(10, 22)],
        ]
        out = _render(monkeypatch, findings, regime)
        assert "Unresolved imports: main" in out
        assert "Topic scatter" in out
        assert "+12 lower-priority" in out
        assert "-v to list" in out
        # The 12 collapsed format findings are not individually rendered.
        assert "unformatted" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_same_rule_gate_movers_dedup_to_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Repeated same-rule gate-movers (buried-at-different-positions) collapse to one (xN) line."""
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": True, "confident": True}
        )
        findings = [
            _finding("CORE:C:0047", "warning", f"Buried instruction at position {p} of 79 — vague", line=p)
            for p in (12, 16, 27, 28, 29)
        ]
        out = _render(monkeypatch, findings, regime)
        assert "Buried instruction (\u00d75)" in out
        assert "position 16 of 79" not in out  # individual positions no longer spam lines

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_restores_full_per_line_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": True, "confident": True}
        )
        findings = [
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
            *[_finding("format", "warning", "unformatted", line=i) for i in range(10, 22)],
        ]
        out = _render(monkeypatch, findings, regime, verbose=True)
        assert "+12 lower-priority" not in out
        assert "unformatted" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_low_confidence_regime_falls_back_to_neutral_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A marginal regime degrades to today's neutral view — no collapse row asserted."""
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": False, "confident": False}
        )
        assert regime is not None and regime.confident is False
        findings = [
            _finding("CORE:S:0024", "error", "Unresolved imports: main"),
            *[_finding("format", "warning", "unformatted", line=i) for i in range(10, 22)],
        ]
        out = _render(monkeypatch, findings, regime)
        assert "lower-priority" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_offline_no_regime_renders_neutral_view(self, monkeypatch: pytest.MonkeyPatch) -> None:
        findings = [_finding("CORE:S:0024", "error", "Unresolved imports: main")]
        out = _render(monkeypatch, findings, None)
        assert "Unresolved imports: main" in out
        assert "lower-priority" not in out


class TestActionRender:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_action_line_shown_under_finding_with_fix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": True, "confident": True}
        )
        findings = [_finding("CORE:C:0044", "warning", "Topic scatter", fix="Name the specific `tool`.")]
        out = _render(monkeypatch, findings, regime)
        assert "→ Name the specific `tool`." in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_action_line_when_fix_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": True, "confident": True}
        )
        out = _render(monkeypatch, [_finding("CORE:C:0044", "warning", "Topic scatter", fix="")], regime)
        assert "→" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_collapsed_findings_get_no_action(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # over-capacity: the conditional `format` finding collapses; its fix must not render.
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": True, "confident": True}
        )
        out = _render(monkeypatch, [_finding("format", "warning", "x", fix="SHOULD-NOT-APPEAR")], regime)
        assert "SHOULD-NOT-APPEAR" not in out
        assert "lower-priority" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_action_collapses_whitespace_and_escapes_markup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime(
            {"within_capacity": False, "is_named": False, "weak_coupling": True, "confident": True}
        )
        out = _render(monkeypatch, [_finding("CORE:C:0044", "warning", "x", fix="line one\n  line two [x]")], regime)
        assert "→ line one line two \\[x]" in out

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_action_renders_in_neutral_offline_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # regime=None → neutral/structural path; the action must still surface.
        findings = [_finding("CORE:S:0024", "error", "Unresolved imports: main", fix="Add the import.")]
        out = _render(monkeypatch, findings, None)
        assert "→ Add the import." in out


class TestClientCheckRuleIds:
    """Client-check labels render their canonical rule ID, consistent with server findings."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_display_rule_id_maps_client_labels(self) -> None:
        from reporails_cli.formatters.text.display_constants import display_rule_id

        assert display_rule_id("format") == "CORE:E:0003"
        assert display_rule_id("bold") == "CORE:E:0003"
        assert display_rule_id("ordering") == "CORE:D:0003"
        assert display_rule_id("scope") == "CORE:C:0048"
        assert display_rule_id("heading_instruction") == "CORE:S:0039"
        assert display_rule_id("orphan") == "CORE:C:0053"
        # Server IDs and unmapped client diagnostics pass through unchanged.
        assert display_rule_id("CORE:C:0042") == "CORE:C:0042"
        assert display_rule_id("ambiguous_charge") == "ambiguous_charge"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_triaged_render_shows_canonical_id_not_label(self, monkeypatch: pytest.MonkeyPatch) -> None:
        regime = classify_regime({"within_capacity": True, "is_named": True, "weak_coupling": False, "confident": True})
        findings = [_finding("ordering", "warning", "Prohibition before directive")]
        out = _render(monkeypatch, findings, regime)
        assert "CORE:D:0003" in out
