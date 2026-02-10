"""Unit tests for capability-based level detection.

Tests the capability detection, level determination, and orphan feature
logic in reporails_cli.core.levels.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from reporails_cli.core.levels import (
    _detect_capability,
    _level_has_capability,
    detect_orphan_features,
    determine_level_from_gates,
)
from reporails_cli.core.models import DetectedFeatures, Level

# Test data matching framework registry/levels.yml
_TEST_LEVEL_CAPS: dict[str, list[str]] = {
    "L0": [],
    "L1": ["instruction_file"],
    "L2": ["project_constraints", "size_controlled"],
    "L3": ["external_references", "multiple_files"],
    "L4": ["path_scoping"],
    "L5": ["structural_integrity", "org_policy", "navigation"],
    "L6": ["dynamic_context", "extensibility", "state_persistence"],
}


@pytest.fixture(autouse=True)
def _mock_level_caps() -> None:  # type: ignore[misc]
    """Ensure tests use known capability mapping regardless of framework state."""
    with patch(
        "reporails_cli.core.levels._load_level_capabilities",
        return_value=_TEST_LEVEL_CAPS,
    ):
        yield


class TestDetectCapability:
    """Test _detect_capability for individual capabilities."""

    def test_instruction_file_detected(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert _detect_capability(features, "instruction_file") is True

    def test_instruction_file_not_detected(self) -> None:
        features = DetectedFeatures()
        assert _detect_capability(features, "instruction_file") is False

    def test_project_constraints_detected(self) -> None:
        features = DetectedFeatures(has_explicit_constraints=True)
        assert _detect_capability(features, "project_constraints") is True

    def test_size_controlled_detected(self) -> None:
        features = DetectedFeatures(is_size_controlled=True)
        assert _detect_capability(features, "size_controlled") is True

    def test_external_references_detected(self) -> None:
        features = DetectedFeatures(has_imports=True)
        assert _detect_capability(features, "external_references") is True

    def test_multiple_files_detected(self) -> None:
        features = DetectedFeatures(has_multiple_instruction_files=True)
        assert _detect_capability(features, "multiple_files") is True

    def test_path_scoping_via_abstracted(self) -> None:
        features = DetectedFeatures(is_abstracted=True)
        assert _detect_capability(features, "path_scoping") is True

    def test_path_scoping_via_path_scoped_rules(self) -> None:
        features = DetectedFeatures(has_path_scoped_rules=True)
        assert _detect_capability(features, "path_scoping") is True

    def test_navigation_via_backbone(self) -> None:
        features = DetectedFeatures(has_backbone=True)
        assert _detect_capability(features, "navigation") is True

    def test_navigation_via_component_count(self) -> None:
        features = DetectedFeatures(component_count=3)
        assert _detect_capability(features, "navigation") is True

    def test_navigation_below_threshold(self) -> None:
        features = DetectedFeatures(component_count=2)
        assert _detect_capability(features, "navigation") is False

    def test_org_policy_detected(self) -> None:
        features = DetectedFeatures(has_shared_files=True)
        assert _detect_capability(features, "org_policy") is True

    def test_dynamic_context_detected(self) -> None:
        features = DetectedFeatures(has_skills_dir=True)
        assert _detect_capability(features, "dynamic_context") is True

    def test_extensibility_detected(self) -> None:
        features = DetectedFeatures(has_mcp_config=True)
        assert _detect_capability(features, "extensibility") is True

    def test_structural_integrity_not_detectable(self) -> None:
        """structural_integrity is not filesystem-detectable — always False."""
        features = DetectedFeatures()
        assert _detect_capability(features, "structural_integrity") is False

    def test_unknown_capability_returns_false(self) -> None:
        features = DetectedFeatures()
        assert _detect_capability(features, "nonexistent") is False

    def test_skip_content_treats_content_capability_as_detected(self) -> None:
        features = DetectedFeatures()  # project_constraints not set
        assert _detect_capability(features, "project_constraints", skip_content=True) is True

    def test_skip_content_does_not_affect_non_content_capability(self) -> None:
        features = DetectedFeatures()
        assert _detect_capability(features, "instruction_file", skip_content=True) is False


class TestLevelHasCapability:
    """Test _level_has_capability — OR within level."""

    def test_l1_with_instruction_file(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert _level_has_capability(features, "L1", _TEST_LEVEL_CAPS) is True

    def test_l2_with_only_size_controlled(self) -> None:
        """L2 passes with just size_controlled (OR semantics)."""
        features = DetectedFeatures(is_size_controlled=True)
        assert _level_has_capability(features, "L2", _TEST_LEVEL_CAPS) is True

    def test_l2_with_only_project_constraints(self) -> None:
        """L2 passes with just project_constraints (OR semantics)."""
        features = DetectedFeatures(has_explicit_constraints=True)
        assert _level_has_capability(features, "L2", _TEST_LEVEL_CAPS) is True

    def test_l2_with_neither_capability(self) -> None:
        features = DetectedFeatures()
        assert _level_has_capability(features, "L2", _TEST_LEVEL_CAPS) is False

    def test_l5_with_one_of_three(self) -> None:
        """L5 passes with just navigation (backbone)."""
        features = DetectedFeatures(has_backbone=True)
        assert _level_has_capability(features, "L5", _TEST_LEVEL_CAPS) is True

    def test_l6_with_none(self) -> None:
        features = DetectedFeatures()
        assert _level_has_capability(features, "L6", _TEST_LEVEL_CAPS) is False

    def test_empty_level_treated_as_passing(self) -> None:
        features = DetectedFeatures()
        assert _level_has_capability(features, "L0", _TEST_LEVEL_CAPS) is True


class TestDetermineLevelFromGates:
    """Test determine_level_from_gates — full cumulative walk."""

    def test_l0_no_features(self) -> None:
        features = DetectedFeatures()
        assert determine_level_from_gates(features) == Level.L0

    def test_l1_has_instruction_file(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert determine_level_from_gates(features) == Level.L1

    def test_l2_with_constraints(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
        )
        assert determine_level_from_gates(features) == Level.L2

    def test_l2_with_size_controlled(self) -> None:
        """L2 reachable via size_controlled alone (OR semantics)."""
        features = DetectedFeatures(
            has_instruction_file=True,
            is_size_controlled=True,
        )
        assert determine_level_from_gates(features) == Level.L2

    def test_l3_with_imports(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            is_size_controlled=True,
            has_imports=True,
        )
        assert determine_level_from_gates(features) == Level.L3

    def test_l3_via_multiple_files(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_multiple_instruction_files=True,
        )
        assert determine_level_from_gates(features) == Level.L3

    def test_l4_with_path_scoping(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            is_size_controlled=True,
            has_imports=True,
            is_abstracted=True,
        )
        assert determine_level_from_gates(features) == Level.L4

    def test_l6_full_project(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_imports=True,
            is_abstracted=True,
            has_backbone=True,  # L5: navigation
            has_skills_dir=True,  # L6: dynamic_context
        )
        assert determine_level_from_gates(features) == Level.L6

    def test_gap_caps_at_lower_level(self) -> None:
        """Has L4 + L6 features but missing L5 → caps at L4."""
        features = DetectedFeatures(
            has_instruction_file=True,
            is_size_controlled=True,
            has_imports=True,
            is_abstracted=True,
            # L5: no shared_files, no backbone, no structural_integrity
            has_skills_dir=True,  # L6 feature
        )
        assert determine_level_from_gates(features) == Level.L4

    def test_skip_content_optimistic(self) -> None:
        """With skip_content, content capabilities treated as detected."""
        features = DetectedFeatures(
            has_instruction_file=True,
            # no explicit_constraints, no size_controlled
            # but skip_content → project_constraints treated as True → L2 passes
            has_imports=True,
            is_abstracted=True,
            # skip_content → path_scoping treated as True → L4 passes
        )
        assert determine_level_from_gates(features, skip_content=True) == Level.L4


class TestDetectOrphanFeatures:
    """Test detect_orphan_features — capabilities above base level."""

    def test_l2_with_backbone_is_orphan(self) -> None:
        """Backbone = navigation (L5) → orphan above L2."""
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_backbone=True,
        )
        assert detect_orphan_features(features, Level.L2) is True

    def test_l1_with_abstracted_is_orphan(self) -> None:
        """Abstracted → path_scoping (L4) → orphan above L1."""
        features = DetectedFeatures(
            has_instruction_file=True,
            is_abstracted=True,
        )
        assert detect_orphan_features(features, Level.L1) is True

    def test_l6_project_no_orphan(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_imports=True,
            is_abstracted=True,
            has_backbone=True,
            has_skills_dir=True,
        )
        assert detect_orphan_features(features, Level.L6) is False

    def test_l1_no_higher_features_no_orphan(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert detect_orphan_features(features, Level.L1) is False
