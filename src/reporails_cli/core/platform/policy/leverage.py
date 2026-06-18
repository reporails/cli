"""Leverage classification and per-file read for finding triage.

Pure decision policy: maps each finding to a leverage tier, reads a per-file
summary from server `FileAnalysis.stats`, and splits findings into shown vs
collapsed. No IO, no Rich — the formatter renders the decision.

This is NOT the maturity ladder (`levels.py`). Leverage answers "how much is
fixing this finding likely to move the score?", a per-file read; `levels.py`
answers "what capabilities has the project set up?", a project-wide infra read.
The two axes are orthogonal and must not be conflated.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

# The per-file regime read (named / within_capacity / weak_coupling / confident)
# is computed server-side and arrives as booleans in `FileAnalysis.stats` — the
# raw c(N)/coupling floats it derives from never cross the wire. This floor maps
# the server's `confident` boolean back onto the Regime.confidence scale.
_CONFIDENCE_FLOOR = 0.5  # below this, degrade to the neutral findings view


class LeverageTier(str, Enum):
    """Leverage class of a finding — how much fixing it is likely to move the score."""

    GATE_MOVER = "gate_mover"
    CONDITIONAL = "conditional"
    COSMETIC = "cosmetic"


# Rule id / client-check label -> leverage tier. OFFLINE FALLBACK ONLY: when the
# server returns a per-finding tier, `resolve_leverage` uses that live value; this
# table is consulted only for offline runs and local-only findings. Seeded by
# hand — do not let it calcify into a second source of truth.
LEVERAGE_TABLE: dict[str, LeverageTier] = {
    # High-leverage — the findings that tend to move the score most. Always surfaced.
    "CORE:C:0042": LeverageTier.GATE_MOVER,
    "CORE:C:0044": LeverageTier.GATE_MOVER,
    "CORE:C:0046": LeverageTier.GATE_MOVER,
    "conflict": LeverageTier.GATE_MOVER,
    "ordering": LeverageTier.GATE_MOVER,
    "CORE:C:0047": LeverageTier.GATE_MOVER,
    "CORE:C:0051": LeverageTier.GATE_MOVER,
    # Conditional — move the score only when the file is specific enough AND not
    # over capacity; otherwise they sit at the ceiling.
    "CORE:E:0003": LeverageTier.CONDITIONAL,
    "format": LeverageTier.CONDITIONAL,
    "CORE:E:0004": LeverageTier.CONDITIONAL,
    "CORE:C:0043": LeverageTier.CONDITIONAL,
    "CORE:C:0041": LeverageTier.CONDITIONAL,
    "CORE:D:0002": LeverageTier.CONDITIONAL,
    "CORE:C:0050": LeverageTier.CONDITIONAL,
    # Cosmetic — informational.
    "bold": LeverageTier.COSMETIC,
    "orphan": LeverageTier.COSMETIC,
}

# Conditional members that sit at the ceiling once a file is already specific
# (formatting / position / inline-formatting). Demoted for a specific file.
_CEILING_BOUND = {"format", "CORE:E:0003", "CORE:C:0043", "CORE:D:0002", "CORE:C:0050"}


@dataclass(frozen=True)
class Regime:
    """Per-file summary derived from server `FileAnalysis.stats`."""

    named: bool
    within_capacity: bool
    weak_coupling: bool
    confidence: float

    @property
    def confident(self) -> bool:
        """True when the regime read is firm enough to drive collapse."""
        return self.confidence >= _CONFIDENCE_FLOOR


@dataclass(frozen=True)
class TriageFinding:
    """A finding tagged with its leverage tier and re-keyed display severity."""

    finding: Any  # FindingItem
    leverage: LeverageTier
    display_severity: str  # "error" | "warning" | "info"


@dataclass(frozen=True)
class TriageResult:
    """Split of a file's findings into shown lines vs the collapsed tail."""

    shown: tuple[TriageFinding, ...]
    collapsed: tuple[TriageFinding, ...]


def classify_leverage(rule: str) -> LeverageTier:
    """Return the leverage tier for a rule id or client-check label.

    Unknown rules (mechanical `CORE:S:*` doc-presence, `general`, `memory-*`)
    are cosmetic by default; error-severity ones still surface via triage.
    """
    return LEVERAGE_TABLE.get(rule, LeverageTier.COSMETIC)


_TIER_FROM_WIRE: dict[str, LeverageTier] = {
    "gate_mover": LeverageTier.GATE_MOVER,
    "conditional": LeverageTier.CONDITIONAL,
    "cosmetic": LeverageTier.COSMETIC,
}


def resolve_leverage(finding: Any) -> LeverageTier:
    """Resolve a finding's leverage tier — live server value first, table fallback.

    When the server provides a per-finding tier it is the source of truth; the
    static `LEVERAGE_TABLE` is consulted only when none is present (offline runs,
    local-only findings).
    """
    resolved = _TIER_FROM_WIRE.get(getattr(finding, "impact_tier", ""))
    if resolved is not None:
        return resolved
    return classify_leverage(finding.rule)


def classify_regime(file_stats: dict[str, Any]) -> Regime | None:
    """Read the per-file regime from server-computed flags in `FileAnalysis.stats`.

    The server projects the raw c(N)/coupling reads into booleans
    (`is_named` / `within_capacity` / `weak_coupling` / `confident`); this just
    adopts them. Returns None when the flags are absent (offline runs, no server
    diagnostics) so the caller falls back to the neutral view.
    """
    if not file_stats or "within_capacity" not in file_stats:
        return None
    return Regime(
        named=bool(file_stats.get("is_named", False)),
        within_capacity=bool(file_stats.get("within_capacity", False)),
        weak_coupling=bool(file_stats.get("weak_coupling", False)),
        confidence=1.0 if file_stats.get("confident", False) else 0.0,
    )


def _display_severity(severity: str, leverage: LeverageTier) -> str:
    """Re-key a finding's severity by leverage (independent of raw severity)."""
    if severity == "error":
        return "error"  # structural errors stay errors
    if leverage is LeverageTier.GATE_MOVER:
        return "warning"
    if leverage is LeverageTier.COSMETIC:
        return "info"
    return "warning" if severity == "warning" else "info"


def _is_shown(severity: str, rule: str, leverage: LeverageTier, regime: Regime) -> bool:
    """Decide whether a finding stays as a line or collapses into the tail."""
    if severity == "error":
        return True  # structural errors always surface
    if leverage is LeverageTier.GATE_MOVER:
        return True
    if leverage is LeverageTier.COSMETIC:
        return False
    # Conditional: gated by the per-file read.
    if not regime.within_capacity:
        return False  # over capacity: nothing moves until the file is split
    # specific file: formatting/position sit at the ceiling; everything else stays actionable.
    return not (regime.named and rule in _CEILING_BOUND)


def triage(findings: list[Any], regime: Regime, verbose: bool = False) -> TriageResult:
    """Split findings into shown vs collapsed by leverage and regime.

    In verbose mode everything returns as shown — the caller renders today's
    full per-line view.
    """
    shown: list[TriageFinding] = []
    collapsed: list[TriageFinding] = []
    for f in findings:
        leverage = resolve_leverage(f)
        tf = TriageFinding(finding=f, leverage=leverage, display_severity=_display_severity(f.severity, leverage))
        if verbose or _is_shown(f.severity, f.rule, leverage, regime):
            shown.append(tf)
        else:
            collapsed.append(tf)
    return TriageResult(shown=tuple(shown), collapsed=tuple(collapsed))
