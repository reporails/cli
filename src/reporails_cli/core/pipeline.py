"""Pipeline state — shared mutable state for per-rule ordered check execution.

Provides PipelineState (shared mutable context across rule checks), TargetMeta
(per-target metadata/annotations), and build_initial_state() factory.

Execution logic lives in pipeline_exec.py to stay within module size limits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reporails_cli.core.check_cache import CheckCache
from reporails_cli.core.models import RuleType, Violation

# Blocking checks — implementation-intrinsic, not schema-declared.
# A failed blocking check excludes the target for ALL remaining rules.
BLOCKING_CHECKS: frozenset[str] = frozenset({"file_exists", "directory_exists", "path_resolves"})

# Rule type ceiling: which check types are allowed per rule type.
CEILING: dict[RuleType, frozenset[str]] = {
    RuleType.MECHANICAL: frozenset({"mechanical"}),
    RuleType.DETERMINISTIC: frozenset({"mechanical", "deterministic"}),
    RuleType.SEMANTIC: frozenset({"mechanical", "deterministic", "semantic"}),
}


@dataclass
class TargetMeta:
    """Per-target metadata for pipeline state.

    Tracks exclusion (blocking checks) and annotations (D->M metadata).
    """

    path: Path
    annotations: dict[str, Any] = field(default_factory=dict)
    excluded: bool = False
    excluded_by: str | None = None


@dataclass
class PipelineState:
    """Shared mutable state across all rule checks within a single validation run.

    Attributes:
        targets: Map of path string -> TargetMeta for all instruction files.
        findings: Accumulated violations from all gates (mechanical, deterministic).
        candidates: Deterministic SARIF results available for semantic consumption.
        _sarif_by_rule: Pre-distributed SARIF results keyed by rule_id.
    """

    targets: dict[str, TargetMeta] = field(default_factory=dict)
    findings: list[Violation] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    _sarif_by_rule: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    check_cache: CheckCache = field(default_factory=CheckCache)

    def active_targets(self) -> list[TargetMeta]:
        """Return targets not excluded by blocking checks."""
        return [t for t in self.targets.values() if not t.excluded]

    def exclude_target(self, path_str: str, check_id: str) -> None:
        """Mark a target as excluded by a blocking check."""
        meta = self.targets.get(path_str)
        if meta and not meta.excluded:
            meta.excluded = True
            meta.excluded_by = check_id

    def annotate_target(self, path_str: str, key: str, value: Any) -> None:
        """Add an annotation to a target (D->M metadata)."""
        meta = self.targets.get(path_str)
        if meta:
            meta.annotations[key] = value

    def get_rule_sarif(self, rule_id: str) -> list[dict[str, Any]]:
        """Get pre-distributed SARIF results for a specific rule."""
        return self._sarif_by_rule.get(rule_id, [])


def build_initial_state(
    instruction_files: list[Path] | None,
    scan_root: Path,
) -> PipelineState:
    """Build initial pipeline state from discovered instruction files.

    Args:
        instruction_files: Pre-resolved instruction file paths, or None.
        scan_root: Project root for computing relative paths.

    Returns:
        PipelineState with targets populated from instruction files.
    """
    state = PipelineState()
    if instruction_files:
        for f in instruction_files:
            try:
                rel = str(f.relative_to(scan_root))
            except ValueError:
                rel = str(f)
            state.targets[rel] = TargetMeta(path=f)
    return state
