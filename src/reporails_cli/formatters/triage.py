"""Finding triage for the text view: which findings stay as lines and which collapse.

Pure presentation: a finding's grade and a file's triage token are read from the
reply and acted on; nothing here assigns a grade. A finding whose reply carries
no grade has none. No IO, no Rich — the text formatter renders the decision.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from reporails_cli.core.platform.contract.json_value import JsonObject, as_str
from reporails_cli.core.platform.dto.diagnostics import SEVERITY_RANK, FindingItem, FindingSeverity


class LeverageTier(str, Enum):
    """Grade a reply carries for a finding: how likely clearing it is to raise the score."""

    GATE_MOVER = "gate_mover"
    CONDITIONAL = "conditional"
    COSMETIC = "cosmetic"


class TriageRegime(str, Enum):
    """Per-file triage token carried by the reply."""

    NEUTRAL = "neutral"  # render the neutral findings view (no collapse)
    PARTIAL = "partial"  # triage the file's graded findings
    OPEN = "open"  # triage the file's graded findings


@dataclass(frozen=True)
class Regime:
    """Per-file triage read: a single token."""

    tier: TriageRegime

    @property
    def confident(self) -> bool:
        """True when the token asks for triage (not neutral)."""
        return self.tier is not TriageRegime.NEUTRAL


@dataclass(frozen=True)
class TriageFinding:
    """A finding with its grade (None when the reply gave none) and display severity."""

    finding: FindingItem
    leverage: LeverageTier | None
    display_severity: FindingSeverity


@dataclass(frozen=True)
class TriageResult:
    """Split of a file's findings into shown lines vs the collapsed tail."""

    shown: tuple[TriageFinding, ...]
    collapsed: tuple[TriageFinding, ...]


_TIER_FROM_WIRE: dict[str, LeverageTier] = {tier.value: tier for tier in LeverageTier}

_REGIME_FROM_WIRE: dict[str, TriageRegime] = {regime.value: regime for regime in TriageRegime}


def resolve_row_leverage(row: JsonObject) -> LeverageTier | None:
    """The grade a serialized finding row carries (`impact_tier`, or the per-file `leverage`)."""
    return _TIER_FROM_WIRE.get(as_str(row.get("impact_tier")) or as_str(row.get("leverage")))


def resolve_leverage(finding: FindingItem) -> LeverageTier | None:
    """The grade the reply carries for a finding, or None when it carries none."""
    return _TIER_FROM_WIRE.get(finding.impact_tier)


def classify_regime(file_stats: JsonObject) -> Regime | None:
    """Read the per-file triage token from `FileAnalysis.stats`.

    Returns None when the `triage_tier` token is absent (offline runs) or
    unrecognized, so the caller renders the neutral findings view.
    """
    if not file_stats:
        return None
    tier = _REGIME_FROM_WIRE.get(as_str(file_stats.get("triage_tier")))
    if tier is None:
        return None
    return Regime(tier=tier)


def is_triaged(findings: list[FindingItem], regime: Regime | None) -> bool:
    """True when the card collapses: the token asks for triage and a finding carries a grade."""
    if regime is None or not regime.confident:
        return False
    return any(resolve_leverage(f) is not None for f in findings)


def _display_severity(severity: FindingSeverity, leverage: LeverageTier | None) -> FindingSeverity:
    """Re-key a finding's severity by grade (independent of raw severity)."""
    if severity == "error":
        return "error"
    if leverage is LeverageTier.GATE_MOVER:
        return "warning"
    if leverage is LeverageTier.CONDITIONAL:
        return "warning" if severity == "warning" else "info"
    return "info"


def _is_shown(severity: FindingSeverity, leverage: LeverageTier | None) -> bool:
    """Decide whether a finding stays as a line or collapses into the tail."""
    if severity == "error":
        return True
    return leverage in (LeverageTier.GATE_MOVER, LeverageTier.CONDITIONAL)


def split_conventions(
    findings: Iterable[FindingItem], verbose: bool = False
) -> tuple[list[FindingItem], list[FindingItem]]:
    """Split findings into those listed and the documentation conventions folded into one counted line.

    A convention is a finding whose check only asks the file to document something (its `convention`
    mark). Verbose output folds none.
    """
    listed: list[FindingItem] = []
    folded: list[FindingItem] = []
    for f in findings:
        (folded if not verbose and f.convention else listed).append(f)
    return listed, folded


def triage(findings: list[FindingItem], verbose: bool = False) -> TriageResult:
    """Split findings into shown vs collapsed by grade.

    An ungraded finding collapses unless it is an error. In verbose mode
    everything returns as shown — the caller renders the full per-line view.
    """
    shown: list[TriageFinding] = []
    collapsed: list[TriageFinding] = []
    for f in findings:
        leverage = resolve_leverage(f)
        tf = TriageFinding(finding=f, leverage=leverage, display_severity=_display_severity(f.severity, leverage))
        if verbose or _is_shown(f.severity, leverage):
            shown.append(tf)
        else:
            collapsed.append(tf)
    return TriageResult(shown=tuple(shown), collapsed=tuple(collapsed))


@dataclass(slots=True)
class RuleTally:
    """The findings of one rule: count, worst severity, count per severity, first message."""

    rule: str
    severity: FindingSeverity
    message: str
    count: int = 0
    by_severity: dict[FindingSeverity, int] = field(default_factory=dict)


def tally_rules(findings: Iterable[FindingItem]) -> list[RuleTally]:
    """One tally per rule, most findings first (ties by rule id). Severity is the worst
    (error > warning > info) seen for the rule; the message is the first finding's."""
    tallies: dict[str, RuleTally] = {}
    for f in findings:
        tally = tallies.setdefault(f.rule, RuleTally(f.rule, f.severity, f.message))
        tally.count += 1
        tally.by_severity[f.severity] = tally.by_severity.get(f.severity, 0) + 1
        if SEVERITY_RANK.get(f.severity, 3) < SEVERITY_RANK.get(tally.severity, 3):
            tally.severity = f.severity
    return sorted(tallies.values(), key=lambda t: (-t.count, t.rule))
