"""Feature detection (filesystem) and rule applicability.

Filesystem detection populates DetectedFeatures for capability-gate
level detection and symlink resolution. Rule applicability is determined
by target file type existence, not level comparison.
"""

from __future__ import annotations

import errno
import logging
import re
from pathlib import Path

from reporails_cli.core.agents import DetectedAgent, get_all_instruction_files
from reporails_cli.core.models import DetectedFeatures, Rule

logger = logging.getLogger(__name__)


def resolve_symlinked_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Find instruction files that are symlinks pointing outside the scan directory."""
    resolved: list[Path] = []
    try:
        real_target = target.resolve()
    except OSError:
        return resolved

    for path in get_all_instruction_files(target, agents=agents):
        if not path.is_symlink():
            continue
        try:
            real_path = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            if isinstance(exc, RuntimeError) or getattr(exc, "errno", None) == errno.ELOOP:
                logger.warning(
                    "Circular symlink detected: %s — file will be skipped",
                    path,
                )
            continue
        # Only include if resolved path is outside the scan directory
        try:
            real_path.relative_to(real_target)
        except ValueError:
            # Outside the scan directory — regex engine scans as extra target
            resolved.append(real_path)

    return resolved


_CONSTRAINT_RE = re.compile(r"\b(MUST|NEVER|ALWAYS)\b")
_SIZE_THRESHOLD = 500  # lines


def _has_hierarchy(target: Path, agents: list[DetectedAgent] | None) -> bool:
    """Check if any agent has both root-level and nested instruction files."""
    if agents is None:
        return False
    for detected in agents:
        names_at_root: set[str] = set()
        has_nested = False
        for f in detected.instruction_files:
            if f.parent == target:
                names_at_root.add(f.name)
            else:
                has_nested = True
        if names_at_root and has_nested:
            return True
    return False


def detect_features_filesystem(target: Path, agents: list[DetectedAgent] | None = None) -> DetectedFeatures:
    """Detect project features from file structure and content.

    Populates DetectedFeatures for capability-gate level detection,
    display summaries, and symlink resolution.

    Args:
        target: Project root path
        agents: Pre-detected agents (avoids redundant filesystem scan)

    Returns:
        DetectedFeatures with all capability fields populated
    """
    features = DetectedFeatures()

    # Check for CLAUDE.md at root
    root_claude = target / "CLAUDE.md"
    features.has_claude_md = root_claude.exists()
    features.has_instruction_file = features.has_claude_md

    # Check for abstracted structure (rules, skills, agents directories)
    abstracted_dirs = [
        ".claude/rules",
        ".claude/skills",
        ".claude/agents",
        ".cursor/rules",
        ".ai/rules",
    ]
    for dirname in abstracted_dirs:
        d = target / dirname
        if d.exists() and any(d.iterdir()):
            features.is_abstracted = True
            break

    # Check for backbone.yml
    backbone_path = target / ".ails" / "backbone.yml"
    features.has_backbone = backbone_path.exists()
    if features.has_backbone:
        features.component_count = _count_components(backbone_path)

    # Count instruction files (all agents, not just CLAUDE.md)
    all_instruction_files = get_all_instruction_files(target, agents=agents)
    features.instruction_file_count = len(all_instruction_files)
    features.has_multiple_instruction_files = len(all_instruction_files) > 1

    if features.instruction_file_count > 0:
        features.has_instruction_file = True

    # Check for hierarchical structure
    features.has_hierarchical_structure = _has_hierarchy(target, agents)

    # Check for shared files
    shared_patterns = [".shared", "shared", ".ai/shared"]
    for pattern in shared_patterns:
        if (target / pattern).exists():
            features.has_shared_files = True
            break

    # L2 capabilities — content analysis on root instruction file
    root_file = _find_root_instruction(target, all_instruction_files)
    if root_file is not None:
        _detect_content_features(root_file, features)

    # L4 capabilities — path-scoped rules
    features.has_path_scoped_rules = features.is_abstracted

    # L6 capabilities — skills, MCP, memory
    features.has_skills_dir = _dir_has_content(target, [".claude/skills", ".cursor/skills", ".agents/skills"])
    features.has_mcp_config = (target / ".mcp.json").exists() or (target / ".claude" / "mcp.json").exists()
    features.has_memory_dir = _dir_has_content(target, [".claude/memory", ".claude/projects"])

    # Resolve symlinked instruction files (for regex engine extra targets)
    features.resolved_symlinks = resolve_symlinked_files(target, agents=agents)

    return features


def _find_root_instruction(target: Path, instruction_files: list[Path]) -> Path | None:
    """Find the root-level instruction file for content analysis."""
    for f in instruction_files:
        if f.parent == target:
            return f
    return None


def _detect_content_features(root_file: Path, features: DetectedFeatures) -> None:
    """Detect content-based features from the root instruction file."""
    try:
        content = root_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    line_count = content.count("\n")
    features.is_size_controlled = line_count < _SIZE_THRESHOLD
    features.has_explicit_constraints = bool(_CONSTRAINT_RE.search(content))
    features.has_imports = "@import" in content or "@ " in content


def _dir_has_content(target: Path, dirs: list[str]) -> bool:
    """Check if any of the directories exist and have content."""
    for dirname in dirs:
        d = target / dirname
        if d.exists():
            try:
                if any(d.iterdir()):
                    return True
            except OSError:
                pass
    return False


def _count_components(backbone_path: Path) -> int:
    """Count components declared in backbone.yml."""
    try:
        from reporails_cli.core.utils import load_yaml_file

        data = load_yaml_file(backbone_path)
        if not data:
            return 0
        components = data.get("components", {})
        return len(components) if isinstance(components, dict) else 0
    except Exception:  # YAML parsing; yaml imported in try scope
        return 0


def get_applicable_rules(
    rules: dict[str, Rule],
    present_types: set[str],
) -> dict[str, Rule]:
    """Filter rules to those whose target file type exists.

    A rule fires when:
    - rule.match.type is in present_types, OR
    - rule.match is None / rule.match.type is None (wildcard — fires if any type present)

    If rule A supersedes rule B, and both are applicable, drop B.

    Args:
        rules: Dict of all rules
        present_types: Set of file type names present in the project

    Returns:
        Dict of applicable rules
    """
    if not present_types:
        return {}

    applicable: dict[str, Rule] = {}
    for rule_id, rule in rules.items():
        if rule.match is None or rule.match.type is None:
            # Wildcard — fires if any type present
            applicable[rule_id] = rule
        elif isinstance(rule.match.type, list):
            if any(t in present_types for t in rule.match.type):
                applicable[rule_id] = rule
        elif rule.match.type in present_types:
            applicable[rule_id] = rule

    # Handle supersession within applicable set.
    # NOTE: load_rules() already handles supersession at load time, but this
    # covers cases where rules are constructed without load_rules() (e.g., tests)
    # and the edge case where a superseding rule's target type is absent.
    superseded_ids: set[str] = set()
    for rule_id, rule in list(applicable.items()):
        if rule.supersedes and rule.supersedes in applicable:
            superseded_ids.add(rule.supersedes)
            parent = applicable[rule.supersedes]
            # Inherit parent checks that aren't replaced by the agent rule
            replaced_ids = {c.replaces for c in rule.checks if c.replaces}
            inherited = [c for c in parent.checks if c.id not in replaced_ids]
            applicable[rule_id] = rule.model_copy(update={"checks": inherited + list(rule.checks)})

    if superseded_ids:
        applicable = {k: v for k, v in applicable.items() if k not in superseded_ids}

    return applicable
