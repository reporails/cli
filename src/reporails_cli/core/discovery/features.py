"""Filesystem feature detection for capability gates and symlink resolution.

Populates DetectedFeatures by inspecting the project layout: instruction
files, abstracted-rules directories, backbone manifest, shared files, and
content-level signals on the root instruction file. Also resolves
instruction-file symlinks that point outside the scan directory so the
regex engine can scan them as extra targets.
"""

from __future__ import annotations

import errno
import logging
import re
from pathlib import Path

from reporails_cli.core.discovery.agents import DetectedAgent, get_all_instruction_files
from reporails_cli.core.platform.dto.models import DetectedFeatures

logger = logging.getLogger(__name__)


_CONSTRAINT_RE = re.compile(r"\b(MUST|NEVER|ALWAYS)\b")
_SIZE_THRESHOLD = 500  # lines


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

    # Count instruction files (all agents, not just CLAUDE.md).
    # Scope the count to files under `target` — user-level memories like
    # `~/.claude/CLAUDE.md` get pulled in by claude's user-scope patterns,
    # but they are not part of the project's instruction-file inventory and
    # would inflate L-level capability gating (`has_multiple_instruction_files`
    # drives the `multiple_files` / `external_references` capability flags
    # in `policy/levels.py`).
    all_instruction_files = get_all_instruction_files(target, agents=agents)
    target_resolved = target.resolve()
    project_instruction_files = [f for f in all_instruction_files if _is_under(f, target_resolved)]
    features.instruction_file_count = len(project_instruction_files)
    features.has_multiple_instruction_files = len(project_instruction_files) > 1

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

    # L3 capabilities — path-scoped rules
    features.has_path_scoped_rules = features.is_abstracted

    # L4 capabilities — skills
    features.has_skills_dir = _dir_has_content(target, [".claude/skills", ".cursor/skills", ".agents/skills"])

    # L5 capabilities — sub-agents
    features.has_subagents = _dir_has_content(target, [".claude/agents", ".cursor/agents", ".agents/agents"])

    # L6 capabilities — governance (hooks, MCP, managed policies)
    features.has_mcp_config = (target / ".mcp.json").exists() or (target / ".claude" / "mcp.json").exists()
    features.has_hooks = (
        _dir_has_content(target, [".claude/hooks", ".githooks"])
        or _has_hooks_setting(target / ".claude" / "settings.json")
        or _has_hooks_setting(target / ".claude" / "settings.local.json")
    )

    # L7 capabilities — adaptive: project-level memory dir + user-scope auto-memory
    features.has_memory_dir = _dir_has_content(target, [".claude/memory", ".claude/projects"])
    features.has_auto_memory = _detect_auto_memory(target)

    # Resolve symlinked instruction files (for regex engine extra targets)
    features.resolved_symlinks = resolve_symlinked_files(target, agents=agents)

    return features


def _has_hooks_setting(settings_path: Path) -> bool:
    """True when `settings.json` declares a `hooks` block."""
    if not settings_path.exists():
        return False
    try:
        import json

        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and bool(data.get("hooks"))


def _detect_auto_memory(target: Path) -> bool:
    """True when the user-scope auto-memory dir for this project exists."""
    try:
        slug = "-" + str(target.resolve()).lstrip("/").replace("/", "-")
    except OSError:
        return False
    auto_memory_root = Path.home() / ".claude" / "projects" / slug / "memory"
    if not auto_memory_root.exists():
        return False
    try:
        return any(auto_memory_root.iterdir())
    except OSError:
        return False


def _is_under(path: Path, root_resolved: Path) -> bool:
    """True when `path` resolves to a location under `root_resolved`."""
    try:
        return path.resolve().is_relative_to(root_resolved)
    except (OSError, ValueError):
        return False


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
        from reporails_cli.core.platform.utils.utils import load_yaml_file

        data = load_yaml_file(backbone_path)
        if not data:
            return 0
        components = data.get("components", {})
        return len(components) if isinstance(components, dict) else 0
    except Exception:  # YAML parsing; yaml imported in try scope
        return 0
