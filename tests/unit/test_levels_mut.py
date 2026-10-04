"""Mutation-killing tests for core.platform.policy.levels.

Each test reddens when a specific injected operator bug returns (verified by
scripts/mutation_probe.py). Covers Mechanism 2 (capability gates) and the
list-valued property branch that test_gates.py does not exercise.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.dto.results import DetectedFeatures
from reporails_cli.core.platform.policy.levels import (
    _detect_capability,
    _level_has_capability,
    _property_depth,
)

# ── List-valued property divergence (L79) ────────────────────────────


class TestPropertyDepthListValued:
    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_list_of_only_nonbaseline_values_diverges(self) -> None:
        # Kills L79 `!= -> ==`: a list holding ONLY a non-baseline value
        # (`format: [frontmatter]`, baseline is `freeform`) diverges under
        # `any(v != base)` but not under `any(v == base)`.
        assert _property_depth({"format": ["frontmatter"]}) == 1


# ── Governance / adaptive-memory OR detectors (L168, L170) ───────────


class TestOrDetectors:
    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_governance_fires_on_hooks_alone(self) -> None:
        features = DetectedFeatures(has_hooks=True)
        assert _detect_capability(features, "governance") is True

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_governance_absent_without_hooks(self) -> None:
        features = DetectedFeatures(has_hooks=False)
        assert _detect_capability(features, "governance") is False

    @pytest.mark.unit
    @pytest.mark.subsys_gates
    def test_adaptive_memory_fires_on_auto_memory_alone(self) -> None:
        # Kills L170 `or -> and`: auto-memory present but no memory dir still
        # counts as adaptive under OR, but not under AND.
        features = DetectedFeatures(has_auto_memory=True, has_memory_dir=False)
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
