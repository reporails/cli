"""Unit tests for gate-based capability detection.

Tests the gate resolution, evaluation, and level determination logic
in reporails_cli.core.levels.
"""

from __future__ import annotations

from reporails_cli.core.levels import (
    _evaluate_gate_item,
    _resolve_gate,
    detect_orphan_features,
    determine_level_from_gates,
)
from reporails_cli.core.models import DetectedFeatures, Level


class TestResolveGate:
    """Test _resolve_gate with direct and derived gates."""

    def test_direct_gate_true(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert _resolve_gate(features, "has_instruction_file") is True

    def test_direct_gate_false(self) -> None:
        features = DetectedFeatures()
        assert _resolve_gate(features, "has_instruction_file") is False

    def test_derived_gate_component_count_passes(self) -> None:
        features = DetectedFeatures(component_count=3)
        assert _resolve_gate(features, "component_count_3plus") is True

    def test_derived_gate_component_count_fails(self) -> None:
        features = DetectedFeatures(component_count=2)
        assert _resolve_gate(features, "component_count_3plus") is False

    def test_unknown_gate_returns_false(self) -> None:
        features = DetectedFeatures()
        assert _resolve_gate(features, "nonexistent_gate") is False


class TestEvaluateGateItem:
    """Test _evaluate_gate_item with AND, OR, and skip_content."""

    def test_string_gate_passes(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert _evaluate_gate_item(features, "has_instruction_file") is True

    def test_string_gate_fails(self) -> None:
        features = DetectedFeatures()
        assert _evaluate_gate_item(features, "has_instruction_file") is False

    def test_or_group_first_passes(self) -> None:
        features = DetectedFeatures(has_imports=True)
        assert _evaluate_gate_item(features, ["has_imports", "has_multiple_instruction_files"]) is True

    def test_or_group_second_passes(self) -> None:
        features = DetectedFeatures(has_multiple_instruction_files=True)
        assert _evaluate_gate_item(features, ["has_imports", "has_multiple_instruction_files"]) is True

    def test_or_group_none_passes(self) -> None:
        features = DetectedFeatures()
        assert _evaluate_gate_item(features, ["has_imports", "has_multiple_instruction_files"]) is False

    def test_skip_content_treats_content_gate_as_passing(self) -> None:
        features = DetectedFeatures()  # has_sections=False
        assert _evaluate_gate_item(features, "has_sections", skip_content=True) is True

    def test_skip_content_does_not_affect_non_content_gate(self) -> None:
        features = DetectedFeatures()  # is_abstracted=False
        assert _evaluate_gate_item(features, "is_abstracted", skip_content=True) is False

    def test_skip_content_in_or_group(self) -> None:
        features = DetectedFeatures()  # nothing set
        # OR group with a content gate — skip_content makes it pass
        assert _evaluate_gate_item(features, ["has_sections", "has_imports"], skip_content=True) is True


class TestDetermineLevelFromGates:
    """Test determine_level_from_gates — full walk."""

    def test_l0_no_features(self) -> None:
        features = DetectedFeatures()
        assert determine_level_from_gates(features) == Level.L0

    def test_l1_has_instruction_file(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert determine_level_from_gates(features) == Level.L1

    def test_l2_has_constraints(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
        )
        assert determine_level_from_gates(features) == Level.L2

    def test_l3_needs_sections_and_or_group(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_imports=True,
        )
        assert determine_level_from_gates(features) == Level.L3

    def test_l3_or_group_via_multiple_files(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_multiple_instruction_files=True,
        )
        assert determine_level_from_gates(features) == Level.L3

    def test_l4_project(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_imports=True,
            is_abstracted=True,
        )
        assert determine_level_from_gates(features) == Level.L4

    def test_l6_full_project(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_imports=True,
            is_abstracted=True,
            component_count=3,
            has_shared_files=True,
            has_backbone=True,
        )
        assert determine_level_from_gates(features) == Level.L6

    def test_gap_caps_at_lower_level(self) -> None:
        """Has L4 + L6 features but missing L5 gates → caps at L4."""
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_imports=True,
            is_abstracted=True,
            # L5 gates missing: component_count < 3 and no shared_files
            has_backbone=True,  # L6 gate
        )
        assert determine_level_from_gates(features) == Level.L4

    def test_skip_content_optimistic(self) -> None:
        """With skip_content, content gates treated as passing."""
        features = DetectedFeatures(
            has_instruction_file=True,
            # has_explicit_constraints=False (content gate, skipped)
            # has_sections=False (content gate, skipped)
            has_imports=True,  # not a content gate
            is_abstracted=True,
        )
        assert determine_level_from_gates(features, skip_content=True) == Level.L4


class TestDetectOrphanFeatures:
    """Test detect_orphan_features — data-driven from config."""

    def test_l2_with_backbone_is_orphan(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_backbone=True,
        )
        assert detect_orphan_features(features, Level.L2) is True

    def test_l1_with_abstracted_is_orphan(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            is_abstracted=True,
        )
        assert detect_orphan_features(features, Level.L1) is True

    def test_l6_project_no_orphan(self) -> None:
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_imports=True,
            is_abstracted=True,
            component_count=3,
            has_shared_files=True,
            has_backbone=True,
        )
        assert detect_orphan_features(features, Level.L6) is False

    def test_l1_no_higher_features_no_orphan(self) -> None:
        features = DetectedFeatures(has_instruction_file=True)
        assert detect_orphan_features(features, Level.L1) is False
