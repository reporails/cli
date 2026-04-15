"""Feature summary generation for display purposes."""

from __future__ import annotations

from reporails_cli.core.results import DetectedFeatures


def get_feature_summary(features: DetectedFeatures) -> str:
    """Generate human-readable summary of detected features.

    Args:
        features: Detected project features

    Returns:
        Summary string for display
    """
    parts = []

    file_count = features.instruction_file_count
    if file_count == 0:
        parts.append("No instruction files")
    elif file_count == 1:
        parts.append("1 instruction file")
    else:
        parts.append(f"{file_count} instruction files")

    feature_list = []
    if features.is_abstracted:
        feature_list.append("abstracted")
    if features.has_backbone:
        feature_list.append("backbone.yml")
    if features.has_shared_files:
        feature_list.append("shared files")
    if features.has_hierarchical_structure:
        feature_list.append("hierarchical")

    if feature_list:
        parts.append(" + ".join(feature_list))

    return ", ".join(parts) if parts else "No features detected"
