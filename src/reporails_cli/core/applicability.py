"""Feature detection and rule applicability.

Determines which rules apply based on detected project features.
Rules are additive - baseline rules always apply, additional rules
added based on features present.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class DetectedFeatures:
    """Features detected in a project."""

    has_claude_md: bool = False
    has_rules_dir: bool = False  # .claude/rules/
    has_backbone: bool = False  # .reporails/backbone.yml
    has_shared_files: bool = False  # shared instruction files
    has_imports: bool = False  # uses @imports in content
    has_multiple_instruction_files: bool = False
    has_hierarchical_structure: bool = False  # nested CLAUDE.md files
    instruction_file_count: int = 0
    component_count: int = 0


# Rule applicability by feature
# Baseline rules (L2) - always checked
BASELINE_RULES: set[str] = {
    "S1",  # Size limits
    "C1",  # Core sections
    "C2",  # Explicit over implicit
    "C4",  # Anti-pattern documentation
    "C7",  # Emphasis discipline
    "C8",  # Instructions over philosophy
    "C9",  # Has project description
    "C10",  # Has NEVER statements
    "C12",  # Has version/date
    "M5",  # Auto-generated content review
}

# Rules for structured content (has @imports, no embedded code)
STRUCTURED_RULES: set[str] = {
    "S2",  # Progressive disclosure
    "S3",  # No embedded code snippets
    "S7",  # Clear markdown structure
    "C3",  # Context-specific content
    "C6",  # Single source of truth
    "C11",  # Links are valid
    "E6",  # Code block line limit
    "E7",  # Import count
    "M1",  # Version control
    "M2",  # Review process
}

# Rules for modular setup (has .claude/rules/)
MODULAR_RULES: set[str] = {
    "S4",  # Hierarchical memory
    "S5",  # Path-scoped rules
    "E1",  # Deterministic tools for style
    "E3",  # Purpose-based file reading
    "E4",  # Memory reference
    "E5",  # Grep efficiency
    "E8",  # Context window awareness
    "M7",  # Rule snippet length enforcement
}

# Rules for governed setup (org policies, PR-based)
GOVERNED_RULES: set[str] = {
    "G1",  # Organization-level policies
    "G2",  # Team governance structure
    "G3",  # Security rules ownership
    "G4",  # Ownership assignment
    "G8",  # Metrics and CI/CD checks
    "M3",  # Change management
    "M4",  # No conflicting rules
}

# Rules for adaptive setup (backbone, contracts)
ADAPTIVE_RULES: set[str] = {
    "S6",  # YAML backbone
    "C5",  # MUST/MUST NOT with context
    "E2",  # Session start ritual
    "G5",  # Contract registry
    "G6",  # Component-contract binding
    "G7",  # Architecture tests
    "M6",  # Map staleness prevention
}


def detect_features(target: Path) -> DetectedFeatures:
    """
    Detect project features from file structure.

    Args:
        target: Project root path

    Returns:
        DetectedFeatures with all detected indicators
    """
    features = DetectedFeatures()

    # Check for CLAUDE.md at root
    root_claude = target / "CLAUDE.md"
    features.has_claude_md = root_claude.exists()

    # Check for .claude/rules/
    rules_dir = target / ".claude" / "rules"
    features.has_rules_dir = rules_dir.exists() and any(rules_dir.glob("*.md"))

    # Check for backbone.yml
    backbone_path = target / ".reporails" / "backbone.yml"
    features.has_backbone = backbone_path.exists()

    # Count instruction files
    claude_files = list(target.rglob("CLAUDE.md"))
    features.instruction_file_count = len(claude_files)
    features.has_multiple_instruction_files = len(claude_files) > 1

    # Check for hierarchical structure (nested CLAUDE.md)
    for cf in claude_files:
        if cf.parent != target:
            features.has_hierarchical_structure = True
            break

    # Check for @imports in content
    if features.has_claude_md:
        content = root_claude.read_text(encoding="utf-8")
        features.has_imports = "@" in content and ("@import" in content.lower() or "@" in content)

    # Check for shared files
    shared_patterns = [".shared/", "shared/", ".ai/shared/"]
    for pattern in shared_patterns:
        if (target / pattern.rstrip("/")).exists():
            features.has_shared_files = True
            break

    # Count components from backbone if present
    if features.has_backbone:
        try:
            import yaml

            backbone_content = backbone_path.read_text(encoding="utf-8")
            backbone_data = yaml.safe_load(backbone_content)
            features.component_count = len(backbone_data.get("components", {}))
        except Exception:
            pass

    return features


def get_applicable_rules(features: DetectedFeatures) -> set[str]:
    """
    Determine which rules apply based on detected features.

    Rules are additive - start with baseline, add rules for each
    feature present.

    Args:
        features: Detected project features

    Returns:
        Set of rule IDs that should be checked
    """
    applicable = set(BASELINE_RULES)

    # Add structured rules if has imports or multiple files
    if features.has_imports or features.has_multiple_instruction_files:
        applicable.update(STRUCTURED_RULES)

    # Add modular rules if has .claude/rules/
    if features.has_rules_dir:
        applicable.update(MODULAR_RULES)

    # Add adaptive rules if has backbone
    if features.has_backbone:
        applicable.update(ADAPTIVE_RULES)

    # Add governed rules if has multiple components or shared files
    # (indicators of team/org scale)
    if features.component_count >= 3 or features.has_shared_files:
        applicable.update(GOVERNED_RULES)

    return applicable


def get_feature_summary(features: DetectedFeatures) -> str:
    """
    Generate human-readable summary of detected features.

    Args:
        features: Detected project features

    Returns:
        Summary string for display
    """
    parts = []

    # File count
    if features.instruction_file_count == 0:
        parts.append("No instruction files")
    elif features.instruction_file_count == 1:
        parts.append("1 instruction file")
    else:
        parts.append(f"{features.instruction_file_count} instruction files")

    # Features present
    feature_list = []
    if features.has_rules_dir:
        feature_list.append(".claude/rules/")
    if features.has_backbone:
        feature_list.append("backbone.yml")
    if features.has_shared_files:
        feature_list.append("shared files")
    if features.has_hierarchical_structure:
        feature_list.append("hierarchical")

    if feature_list:
        parts.append(" + ".join(feature_list))

    return ", ".join(parts) if parts else "No features detected"
