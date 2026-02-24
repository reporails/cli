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

    @pytest.mark.parametrize(
        "feature_kwargs, capability, expected",
        [
            ({"has_instruction_file": True}, "instruction_file", True),
            ({}, "instruction_file", False),
            ({"has_explicit_constraints": True}, "project_constraints", True),
            ({"is_size_controlled": True}, "size_controlled", True),
            ({"has_imports": True}, "external_references", True),
            ({"has_multiple_instruction_files": True}, "multiple_files", True),
            ({"is_abstracted": True}, "path_scoping", True),
            ({"has_path_scoped_rules": True}, "path_scoping", True),
            ({"has_backbone": True}, "navigation", True),
            ({"component_count": 3}, "navigation", True),
            ({"has_shared_files": True}, "org_policy", True),
            ({"has_skills_dir": True}, "dynamic_context", True),
            ({"has_mcp_config": True}, "extensibility", True),
        ],
        ids=lambda x: str(x) if not isinstance(x, dict) else next(iter(x.keys()), "empty"),
    )
    def test_capability_detected(self, feature_kwargs: dict, capability: str, expected: bool) -> None:
        features = DetectedFeatures(**feature_kwargs)
        assert _detect_capability(features, capability) is expected

    def test_navigation_below_threshold(self) -> None:
        features = DetectedFeatures(component_count=2)
        assert _detect_capability(features, "navigation") is False

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

    @pytest.mark.parametrize(
        "feature_kwargs, level, expected",
        [
            ({"has_instruction_file": True}, "L1", True),
            ({"is_size_controlled": True}, "L2", True),  # OR: just one of two
            ({"has_explicit_constraints": True}, "L2", True),  # OR: the other one
            ({}, "L2", False),  # neither L2 capability
            ({"has_backbone": True}, "L5", True),  # 1 of 3 suffices
            ({}, "L6", False),  # no L6 capabilities
            ({}, "L0", True),  # empty level always passes
        ],
        ids=["L1-pass", "L2-size", "L2-constraints", "L2-neither", "L5-backbone", "L6-none", "L0-empty"],
    )
    def test_level_capability_check(self, feature_kwargs: dict, level: str, expected: bool) -> None:
        features = DetectedFeatures(**feature_kwargs)
        assert _level_has_capability(features, level, _TEST_LEVEL_CAPS) is expected


class TestDetermineLevelFromGates:
    """Test determine_level_from_gates — full cumulative walk."""

    @pytest.mark.parametrize(
        "feature_kwargs, expected_level",
        [
            ({}, Level.L0),
            ({"has_instruction_file": True}, Level.L1),
            ({"has_instruction_file": True, "has_explicit_constraints": True}, Level.L2),
            ({"has_instruction_file": True, "is_size_controlled": True}, Level.L2),  # OR path
            ({"has_instruction_file": True, "is_size_controlled": True, "has_imports": True}, Level.L3),
            (
                {
                    "has_instruction_file": True,
                    "has_explicit_constraints": True,
                    "has_multiple_instruction_files": True,
                },
                Level.L3,
            ),  # L3 via multiple_files
            (
                {"has_instruction_file": True, "is_size_controlled": True, "has_imports": True, "is_abstracted": True},
                Level.L4,
            ),
            (
                {
                    "has_instruction_file": True,
                    "has_explicit_constraints": True,
                    "has_imports": True,
                    "is_abstracted": True,
                    "has_backbone": True,
                    "has_skills_dir": True,
                },
                Level.L6,
            ),
        ],
        ids=["L0", "L1", "L2-constraints", "L2-size", "L3-imports", "L3-multi", "L4", "L6-full"],
    )
    def test_cumulative_walk(self, feature_kwargs: dict, expected_level: Level) -> None:
        features = DetectedFeatures(**feature_kwargs)
        assert determine_level_from_gates(features) == expected_level

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


class TestCapabilityInteraction:
    """Test cross-level capability interactions and edge cases."""

    def test_l5_requires_l4_features(self) -> None:
        """L5 features without L4 path_scoping should cap at L3 or lower.

        Has L1-L3 + L5 (backbone) but missing L4 (no path_scoped_rules,
        no is_abstracted) → cumulative gate blocks at L4 gap → caps at L3.
        """
        features = DetectedFeatures(
            has_instruction_file=True,  # L1
            has_explicit_constraints=True,  # L2
            has_imports=True,  # L3
            # L4: is_abstracted=False, has_path_scoped_rules=False → gap
            is_abstracted=False,
            has_path_scoped_rules=False,
            has_backbone=True,  # L5: navigation
        )
        level = determine_level_from_gates(features)
        assert level.value <= Level.L3.value, f"Missing L4 path_scoping should cap level at L3 or below, got {level}"

    def test_state_persistence_detection(self) -> None:
        """state_persistence is L6 — verify it returns False for default features."""
        features = DetectedFeatures()
        assert _detect_capability(features, "state_persistence") is False

        # With has_memory_dir set, it should be detected
        features_with_memory = DetectedFeatures(has_memory_dir=True)
        assert _detect_capability(features_with_memory, "state_persistence") is True
