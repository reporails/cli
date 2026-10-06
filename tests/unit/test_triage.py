"""Unit tests for formatters/triage.py — grade reading and the shown-or-collapsed split."""

from __future__ import annotations

from dataclasses import replace

import pytest

from reporails_cli.core.platform.runtime.merger import FindingItem
from reporails_cli.formatters.triage import (
    LeverageTier,
    Regime,
    TriageRegime,
    _display_severity,
    classify_regime,
    is_triaged,
    resolve_leverage,
    split_conventions,
    triage,
)


def _finding(rule: str, severity: str = "warning", line: int = 5, impact_tier: str = "") -> FindingItem:
    return FindingItem(file="a.md", line=line, severity=severity, rule=rule, message="msg", impact_tier=impact_tier)


def _regime(token: str) -> Regime | None:
    return classify_regime({"triage_tier": token})


class TestResolveLeverage:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize("tier", list(LeverageTier))
    def test_reads_each_grade_the_reply_carries(self, tier: LeverageTier) -> None:
        assert resolve_leverage(_finding("CORE:C:0042", impact_tier=tier.value)) is tier

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize("rule", ["CORE:C:0042", "bold", "CORE:S:0010", "format"])
    def test_finding_without_a_grade_has_none(self, rule: str) -> None:
        assert resolve_leverage(_finding(rule)) is None

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_unrecognized_grade_is_none(self) -> None:
        assert resolve_leverage(_finding("CORE:C:0042", impact_tier="bogus")) is None


class TestRegimeClassification:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_adopts_known_tier_tokens(self) -> None:
        for token, tier in (
            ("neutral", TriageRegime.NEUTRAL),
            ("partial", TriageRegime.PARTIAL),
            ("open", TriageRegime.OPEN),
        ):
            r = classify_regime({"triage_tier": token})
            assert r is not None and r.tier is tier, token

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_neutral_token_is_not_confident(self) -> None:
        assert Regime(tier=TriageRegime.NEUTRAL).confident is False
        assert Regime(tier=TriageRegime.PARTIAL).confident is True
        assert Regime(tier=TriageRegime.OPEN).confident is True

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_missing_or_unknown_token_returns_none(self) -> None:
        assert classify_regime({}) is None
        assert classify_regime({"atoms": 10, "named": 5}) is None
        assert classify_regime({"triage_tier": "bogus"}) is None
        assert classify_regime({"triage_tier": "strict"}) is None


class TestIsTriaged:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_needs_a_triage_token_and_a_graded_finding(self) -> None:
        graded = [_finding("CORE:C:0042", impact_tier="gate_mover")]
        ungraded = [_finding("CORE:C:0042")]
        assert is_triaged(graded, _regime("partial")) is True
        assert is_triaged(graded, _regime("open")) is True
        assert is_triaged(graded, _regime("neutral")) is False
        assert is_triaged(graded, None) is False
        assert is_triaged(ungraded, _regime("partial")) is False
        assert is_triaged([], _regime("open")) is False


class TestTriageBucketing:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_errors_and_graded_gate_movers_and_conditionals_shown(self) -> None:
        findings = [
            _finding("CORE:S:0024", severity="error"),
            _finding("CORE:C:0042", impact_tier="gate_mover"),
            _finding("CORE:C:0044", impact_tier="conditional"),
            _finding("bold", severity="info", impact_tier="cosmetic"),
            _finding("CORE:S:0010"),
        ]
        result = triage(findings)
        assert {tf.finding.rule for tf in result.shown} == {"CORE:S:0024", "CORE:C:0042", "CORE:C:0044"}
        assert {tf.finding.rule for tf in result.collapsed} == {"bold", "CORE:S:0010"}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_grade_in_the_reply_drives_collapse(self) -> None:
        findings = [
            _finding("CORE:C:0042", impact_tier="cosmetic"),
            _finding("bold", severity="info", impact_tier="gate_mover"),
        ]
        result = triage(findings)
        assert {tf.finding.rule for tf in result.shown} == {"bold"}
        assert {tf.finding.rule for tf in result.collapsed} == {"CORE:C:0042"}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_ungraded_finding_collapses_unless_it_is_an_error(self) -> None:
        result = triage([_finding("CORE:C:0042"), _finding("CORE:S:0024", severity="error")])
        assert [tf.finding.rule for tf in result.shown] == ["CORE:S:0024"]
        assert [tf.finding.rule for tf in result.collapsed] == ["CORE:C:0042"]
        assert result.collapsed[0].leverage is None

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_shows_everything(self) -> None:
        findings = [_finding("format"), _finding("bold", severity="info", impact_tier="cosmetic")]
        result = triage(findings, verbose=True)
        assert len(result.shown) == 2
        assert result.collapsed == ()


class TestSplitConventions:
    @staticmethod
    def _mixed() -> list[FindingItem]:
        return [
            _finding("CORE:C:0005"),
            _finding("CORE:C:0042", severity="error"),
            _finding("CORE:C:0007"),
        ]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_conventions_are_set_apart_from_the_listed_findings(self) -> None:
        findings = self._mixed()
        findings[0] = replace(findings[0], convention=True)
        findings[2] = replace(findings[2], convention=True)
        listed, folded = split_conventions(findings)
        assert [f.rule for f in listed] == ["CORE:C:0042"]
        assert [f.rule for f in folded] == ["CORE:C:0005", "CORE:C:0007"]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_output_folds_none(self) -> None:
        findings = [replace(f, convention=True) for f in self._mixed()]
        listed, folded = split_conventions(findings, verbose=True)
        assert len(listed) == 3
        assert folded == []


class TestDisplaySeverity:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_gate_mover_is_re_keyed_up_to_warning(self) -> None:
        assert _display_severity("info", LeverageTier.GATE_MOVER) == "warning"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_error_keeps_error_for_every_grade(self) -> None:
        for grade in (*LeverageTier, None):
            assert _display_severity("error", grade) == "error"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_cosmetic_and_ungraded_warning_is_info(self) -> None:
        assert _display_severity("warning", LeverageTier.COSMETIC) == "info"
        assert _display_severity("warning", None) == "info"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_conditional_keeps_its_own_severity(self) -> None:
        assert _display_severity("warning", LeverageTier.CONDITIONAL) == "warning"
        assert _display_severity("info", LeverageTier.CONDITIONAL) == "info"
