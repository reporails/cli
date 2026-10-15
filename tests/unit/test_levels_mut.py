"""Mutation-killing tests for core.platform.policy.levels.

Each test reddens when a specific injected operator bug returns (verified by
scripts/mutation_probe.py). Covers the capability gates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.results import DetectedFeatures, MemoryFeatures
from reporails_cli.core.platform.policy.levels import (
    _detect_capability,
    _level_has_capability,
)

# ── Governance / adaptive-memory OR detectors (L168, L170) ───────────


class TestOrDetectors:
    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_governance_fires_on_hooks_alone(self) -> None:
        features = DetectedFeatures(hook_files=(Path(".codex/hooks.json"),))
        assert _detect_capability(features, "governance") is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_governance_absent_without_hooks(self) -> None:
        features = DetectedFeatures(hook_files=())
        assert _detect_capability(features, "governance") is False

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_adaptive_memory_fires_on_auto_memory_alone(self) -> None:
        # Kills L170 `or -> and`: auto-memory present but no memory dir still
        # counts as adaptive under OR, but not under AND.
        features = DetectedFeatures(memory=MemoryFeatures(has_auto_memory=True, has_memory_dir=False))
        assert _detect_capability(features, "adaptive_memory") is True


# ── Empty-capability level (L199) ────────────────────────────────────


class TestLevelHasCapability:
    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_level_with_no_capabilities_passes_vacuously(self) -> None:
        # Kills L199 `return True -> False`: a level whose capability list is
        # empty (L0) passes vacuously.
        assert _level_has_capability(DetectedFeatures(), "L0") is True


# ── Detector dispatch (L206, L207) ───────────────────────────────────


class TestDetectCapability:
    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_known_detected_capability_returns_true(self) -> None:
        # Kills L206 `is -> is not`: a known capability has a non-None detector,
        # so the `is None` guard must be False and the detector must run.
        features = DetectedFeatures(has_instruction_file=True)
        assert _detect_capability(features, "instruction_file") is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_unknown_capability_returns_false(self) -> None:
        # Kills L207 `return False -> True`: an unrecognized capability id has
        # no detector and must report not-detected.
        assert _detect_capability(DetectedFeatures(has_instruction_file=True), "no_such_cap") is False
