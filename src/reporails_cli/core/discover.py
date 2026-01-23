"""Discovery engine - analyze instruction files and generate backbone.

Deterministic discovery of:
- Component structure (from directory hierarchy)
- File references (from markdown content)
- Dependencies (imports between instruction files)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.agents import DetectedAgent, detect_agents, get_all_instruction_files


@dataclass
class FileReference:
    """A reference to another file found in instruction content."""

    path: str
    line_number: int
    context: str  # The line containing the reference


@dataclass
class Component:
    """A discovered component (directory with instruction files)."""

    id: str  # Dot-separated path: "langgraph.app.agents"
    root: Path
    instruction_files: list[Path] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)  # Referenced files
    children: list[str] = field(default_factory=list)  # Child component IDs
    parent: str | None = None
    content_hash: str | None = None


@dataclass
class DiscoveryResult:
    """Result of discovery operation."""

    target: Path
    discovered_at: str
    agents: list[DetectedAgent]
    components: dict[str, Component]
    shared_files: list[str]
    total_instruction_files: int
    total_references: int


# Patterns for extracting file references from markdown
REFERENCE_PATTERNS = [
    # Backtick paths: `path/to/file.ext` or `./path/to/file`
    re.compile(r"`([./][\w\-./]+\.\w+)`"),
    re.compile(r"`(\.?\.?/[\w\-./]+)`"),
    # Markdown links: [text](path/to/file)
    re.compile(r"\[.*?\]\(([./][\w\-./]+\.?\w*)\)"),
    # Read/See commands: Read `file` or See "file"
    re.compile(r"(?:Read|See|Check|Load)\s+[`'\"]([^`'\"]+)[`'\"]", re.IGNORECASE),
    # Numbered lists with paths: 1. Read `.shared/sys.yml`
    re.compile(r"^\s*\d+\.\s+.*?[`'\"]([./][\w\-./]+)[`'\"]", re.MULTILINE),
]


def extract_references(content: str) -> list[FileReference]:
    """
    Extract file references from instruction file content.

    Deterministic: uses regex patterns to find explicit path references.

    Args:
        content: Markdown content to analyze

    Returns:
        List of file references found
    """
    references: list[FileReference] = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pattern in REFERENCE_PATTERNS:
            for match in pattern.finditer(line):
                path = match.group(1)
                # Filter out obvious non-paths
                if _is_valid_path_reference(path):
                    references.append(
                        FileReference(
                            path=path,
                            line_number=line_num,
                            context=line.strip()[:100],
                        )
                    )

    return references


def _is_valid_path_reference(path: str) -> bool:
    """Check if a string looks like a valid file path reference."""
    # Must have at least one slash or dot
    if "/" not in path and "." not in path:
        return False
    # Filter out URLs
    if path.startswith("http://") or path.startswith("https://"):
        return False
    # Filter out common false positives
    false_positives = {"e.g.", "i.e.", "etc.", "vs.", "v1", "v2"}
    return path.lower() not in false_positives


def compute_content_hash(file_path: Path) -> str:
    """Compute SHA256 hash of file content."""
    content = file_path.read_bytes()
    return f"sha256:{hashlib.sha256(content).hexdigest()[:16]}"


def discover_components(target: Path, instruction_files: list[Path]) -> dict[str, Component]:
    """
    Discover components from instruction file locations.

    Component = directory containing instruction file(s).
    Hierarchy derived from directory structure.

    Args:
        target: Project root
        instruction_files: All discovered instruction files

    Returns:
        Dict mapping component ID to Component
    """
    components: dict[str, Component] = {}

    for file_path in instruction_files:
        # Get directory containing the instruction file
        component_dir = file_path.parent
        relative_dir = component_dir.relative_to(target)

        # Create component ID from path
        if relative_dir == Path("."):
            component_id = "root"
        else:
            component_id = str(relative_dir).replace("/", ".").replace("\\", ".")

        # Create or update component
        if component_id not in components:
            components[component_id] = Component(
                id=component_id,
                root=component_dir,
            )

        component = components[component_id]
        component.instruction_files.append(file_path)

        # Extract references from file content
        content = file_path.read_text(encoding="utf-8")
        refs = extract_references(content)
        component.imports.extend([r.path for r in refs])

        # Compute content hash
        if component.content_hash is None:
            component.content_hash = compute_content_hash(file_path)

    # Deduplicate imports
    for component in components.values():
        component.imports = sorted(set(component.imports))

    # Build parent-child relationships
    _build_hierarchy(components)

    return components


def _build_hierarchy(components: dict[str, Component]) -> None:
    """Build parent-child relationships between components."""
    component_ids = sorted(components.keys())

    for comp_id in component_ids:
        component = components[comp_id]

        # Find parent (longest matching prefix)
        parts = comp_id.split(".")
        if len(parts) > 1:
            parent_id = ".".join(parts[:-1])
            if parent_id in components:
                component.parent = parent_id
                components[parent_id].children.append(comp_id)


def find_shared_files(components: dict[str, Component], target: Path) -> list[str]:
    """
    Identify shared files (referenced by multiple components).

    Args:
        components: Discovered components
        target: Project root

    Returns:
        List of shared file paths
    """
    # Count references to each file
    ref_counts: dict[str, int] = {}
    for component in components.values():
        for ref in component.imports:
            ref_counts[ref] = ref_counts.get(ref, 0) + 1

    # Files referenced by 2+ components are shared
    shared = [path for path, count in ref_counts.items() if count >= 2]

    # Also include common shared directories
    for pattern in [".shared/**/*", ".ai/shared/**/*", "shared/**/*"]:
        for path in target.glob(pattern):
            if path.is_file():
                rel_path = str(path.relative_to(target))
                if rel_path not in shared:
                    shared.append(rel_path)

    return sorted(set(shared))


def run_discovery(target: Path) -> DiscoveryResult:
    """
    Run full discovery on target directory.

    Deterministic analysis:
    1. Detect which coding agents are configured
    2. Find all instruction files
    3. Extract references from content
    4. Build component hierarchy
    5. Identify shared files

    Args:
        target: Project root to analyze

    Returns:
        DiscoveryResult with full analysis
    """
    # Detect agents
    agents = detect_agents(target)

    # Get all instruction files
    instruction_files = get_all_instruction_files(target)

    # Discover components
    components = discover_components(target, instruction_files)

    # Find shared files
    shared_files = find_shared_files(components, target)

    # Count total references
    total_refs = sum(len(c.imports) for c in components.values())

    return DiscoveryResult(
        target=target,
        discovered_at=datetime.now(UTC).isoformat(),
        agents=agents,
        components=components,
        shared_files=shared_files,
        total_instruction_files=len(instruction_files),
        total_references=total_refs,
    )


def generate_backbone_yaml(result: DiscoveryResult) -> str:
    """
    Generate backbone.yml content from discovery result.

    Args:
        result: Discovery result

    Returns:
        YAML string for backbone file
    """
    data: dict[str, Any] = {
        "version": 1,
        "generated_at": result.discovered_at,
        "generator": "ails discover",
        "target": str(result.target),
        "agents": {},
        "components": {},
        "shared": result.shared_files,
        "stats": {
            "total_instruction_files": result.total_instruction_files,
            "total_components": len(result.components),
            "total_references": result.total_references,
        },
    }

    # Add detected agents
    for agent in result.agents:
        data["agents"][agent.agent_type.id] = {
            "name": agent.agent_type.name,
            "instruction_files": [
                str(f.relative_to(result.target)) for f in agent.instruction_files
            ],
            "config_files": [str(f.relative_to(result.target)) for f in agent.config_files],
            "rule_files": [str(f.relative_to(result.target)) for f in agent.rule_files],
        }

    # Add components
    for comp_id, component in sorted(result.components.items()):
        comp_data: dict[str, Any] = {
            "root": str(component.root.relative_to(result.target)),
            "instruction_files": [
                str(f.relative_to(result.target)) for f in component.instruction_files
            ],
            "content_hash": component.content_hash,
        }
        if component.imports:
            comp_data["imports"] = component.imports
        if component.parent:
            comp_data["parent"] = component.parent
        if component.children:
            comp_data["children"] = component.children

        data["components"][comp_id] = comp_data

    yaml_output: str = yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return yaml_output


def save_backbone(target: Path, content: str) -> Path:
    """
    Save backbone.yml to target's .reporails directory.

    Args:
        target: Project root
        content: YAML content

    Returns:
        Path to saved file
    """
    backbone_dir = target / ".reporails"
    backbone_dir.mkdir(parents=True, exist_ok=True)

    backbone_path = backbone_dir / "backbone.yml"
    backbone_path.write_text(content, encoding="utf-8")

    return backbone_path
