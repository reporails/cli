"""Unit tests for core/platform/policy/leverage.py — finding triage policy."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.policy.leverage import (
    LeverageTier,
    classify_leverage,
    classify_regime,
    resolve_leverage,
    triage,
)
from reporails_cli.core.platform.runtime.merger import FindingItem


def _finding(
    rule: str, severity: str = "warning", line: int = 5, message: str = "msg", impact_tier: str = ""
) -> FindingItem:
    return FindingItem(file="a.md", line=line, severity=severity, rule=rule, message=message, impact_tier=impact_tier)


class TestLeverageTable:
    """`LEVERAGE_TABLE` is the OFFLINE FALLBACK consulted only when the server
    sends no live tier — `resolve_leverage` is the source of truth at runtime."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_gate_movers_classify_as_gate_mover(self) -> None:
        for rule in ("CORE:C:0042", "CORE:C:0044", "CORE:C:0046", "CORE:C:0047", "CORE:C:0051", "ordering"):
            assert classify_leverage(rule) is LeverageTier.GATE_MOVER, rule

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_conditional_members_classify_as_conditional(self) -> None:
        for rule in ("format", "CORE:E:0003", "CORE:E:0004", "CORE:C:0043", "CORE:C:0041", "CORE:D:0002"):
            assert classify_leverage(rule) is LeverageTier.CONDITIONAL, rule

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_cosmetic_and_unknown_classify_as_cosmetic(self) -> None:
        assert classify_leverage("bold") is LeverageTier.COSMETIC
        assert classify_leverage("orphan") is LeverageTier.COSMETIC
        # Unknown mechanical / structural rules default to cosmetic.
        assert classify_leverage("CORE:S:0010") is LeverageTier.COSMETIC
        assert classify_leverage("general") is LeverageTier.COSMETIC


class TestResolveLeverage:
    """The live server tier wins; the table is the fallback for findings without one."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_live_tier_overrides_static_table(self) -> None:
        # CORE:C:0042 is gate_mover in the table, but the server tiered THIS finding
        # cosmetic for its file — the live value wins.
        f = _finding("CORE:C:0042", impact_tier="cosmetic")
        assert resolve_leverage(f) is LeverageTier.COSMETIC
        # And a table-cosmetic rule the server tiered up is honored too.
        assert resolve_leverage(_finding("bold", impact_tier="gate_mover")) is LeverageTier.GATE_MOVER

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_falls_back_to_table_without_live_tier(self) -> None:
        # No impact_tier (offline / local finding) → table lookup.
        assert resolve_leverage(_finding("CORE:C:0042")) is LeverageTier.GATE_MOVER
        assert resolve_leverage(_finding("CORE:S:0010")) is LeverageTier.COSMETIC

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_unknown_live_tier_string_falls_back(self) -> None:
        # A malformed wire value is ignored in favor of the table (tolerant).
        assert resolve_leverage(_finding("CORE:C:0044", impact_tier="bogus")) is LeverageTier.GATE_MOVER


def _regime_stats(
    *, within_capacity: bool = True, is_named: bool = True, weak_coupling: bool = False, confident: bool = True
) -> dict[str, bool]:
    """Server-shaped regime flags as they arrive in `FileAnalysis.stats`."""
    return {
        "within_capacity": within_capacity,
        "is_named": is_named,
        "weak_coupling": weak_coupling,
        "confident": confident,
    }


class TestRegimeClassification:
    """`classify_regime` now adopts server-computed flags; the raw-value math
    that derives them lives server-side (api `policy/regime.py`)."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_adopts_server_flags(self) -> None:
        r = classify_regime(_regime_stats(within_capacity=True, is_named=True, weak_coupling=False, confident=True))
        assert r is not None
        assert r.named is True
        assert r.within_capacity is True
        assert r.weak_coupling is False
        assert r.confident is True

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_adopts_over_capacity_flags(self) -> None:
        r = classify_regime(_regime_stats(within_capacity=False, is_named=False, weak_coupling=True, confident=True))
        assert r is not None
        assert r.named is False
        assert r.within_capacity is False
        assert r.weak_coupling is True

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_not_confident_flag_degrades_below_floor(self) -> None:
        assert classify_regime(_regime_stats(confident=False)).confident is False

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_missing_flags_returns_none(self) -> None:
        assert classify_regime({}) is None
        # Counts present but no regime flags (offline run) — fall back to neutral view.
        assert classify_regime({"atoms": 10, "named": 5}) is None


class TestTriageBucketing:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_gate_movers_and_errors_always_shown(self) -> None:
        regime = classify_regime(_regime_stats(within_capacity=False, is_named=False, weak_coupling=True))
        findings = [
            _finding("CORE:S:0024", severity="error"),  # structural error
            _finding("CORE:C:0044"),  # gate-mover
            _finding("format"),  # conditional, over-capacity -> collapse
            _finding("bold", severity="info"),  # cosmetic -> collapse
        ]
        result = triage(findings, regime)
        shown_rules = {tf.finding.rule for tf in result.shown}
        collapsed_rules = {tf.finding.rule for tf in result.collapsed}
        assert shown_rules == {"CORE:S:0024", "CORE:C:0044"}
        assert collapsed_rules == {"format", "bold"}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_over_capacity_collapses_all_conditional(self) -> None:
        regime = classify_regime(_regime_stats(within_capacity=False, is_named=False, weak_coupling=True))
        findings = [_finding("CORE:E:0004"), _finding("CORE:C:0041"), _finding("CORE:C:0043")]
        result = triage(findings, regime)
        assert result.shown == ()
        assert len(result.collapsed) == 3

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_named_regime_demotes_ceiling_bound_only(self) -> None:
        regime = classify_regime(_regime_stats(within_capacity=True, is_named=True, weak_coupling=False))
        findings = [
            _finding("format"),  # ceiling-bound -> collapse in named regime
            _finding("CORE:C:0043"),  # modality, ceiling-bound -> collapse
            _finding("CORE:E:0004"),  # brevity, still actionable -> shown
        ]
        result = triage(findings, regime)
        shown_rules = {tf.finding.rule for tf in result.shown}
        collapsed_rules = {tf.finding.rule for tf in result.collapsed}
        assert shown_rules == {"CORE:E:0004"}
        assert collapsed_rules == {"format", "CORE:C:0043"}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_live_server_tier_drives_collapse(self) -> None:
        # A file where the table would SHOW CORE:C:0042, but the server tiered it
        # cosmetic → it collapses; a server gate_mover stays shown regardless of
        # the table.
        regime = classify_regime(_regime_stats(within_capacity=True, is_named=True, weak_coupling=False))
        findings = [
            _finding("CORE:C:0042", impact_tier="cosmetic"),  # demoted by server -> collapse
            _finding("bold", severity="info", impact_tier="gate_mover"),  # promoted by server -> shown
        ]
        result = triage(findings, regime)
        assert {tf.finding.rule for tf in result.shown} == {"bold"}
        assert {tf.finding.rule for tf in result.collapsed} == {"CORE:C:0042"}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_verbose_shows_everything(self) -> None:
        regime = classify_regime(_regime_stats(within_capacity=False, is_named=False, weak_coupling=True))
        findings = [_finding("format"), _finding("bold", severity="info"), _finding("CORE:C:0044")]
        result = triage(findings, regime, verbose=True)
        assert len(result.shown) == 3
        assert result.collapsed == ()

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_display_severity_rekeys_by_leverage(self) -> None:
        regime = classify_regime(_regime_stats(within_capacity=False, is_named=False, weak_coupling=True))
        # An info-severity gate-mover is re-keyed up to warning (high leverage).
        result = triage([_finding("CORE:C:0044", severity="info")], regime)
        assert result.shown[0].display_severity == "warning"
        # A structural error keeps error severity.
        result_err = triage([_finding("CORE:S:0024", severity="error")], regime)
        assert result_err.shown[0].display_severity == "error"
