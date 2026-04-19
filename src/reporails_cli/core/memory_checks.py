"""Memory index validation — broken links and missing frontmatter.

Client-side memory validation. Reads the local filesystem to validate
MEMORY.md index entries. Runs client-side (not in the API).
"""

from __future__ import annotations

import re
from pathlib import Path

from reporails_cli.core.models import LocalFinding

_MEMORY_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)]+\.md)\)(?:\s*[—\-]\s*(.+))?")
_FRONTMATTER_REQUIRED = {"name", "description", "type"}

_RULE_BROKEN_LINK = "CORE:E:0010"
_RULE_MISSING_FM = "CORE:E:0011"


def _validate_link_target(
    file_path: str,
    line_num: int,
    link_target: str,
    target_path: Path,
) -> list[LocalFinding]:
    """Validate a single memory link — check existence and frontmatter."""
    if not target_path.exists():
        return [
            LocalFinding(
                file=file_path,
                line=line_num,
                severity="error",
                rule=_RULE_BROKEN_LINK,
                message=f"Broken memory link — `{link_target}` does not exist.",
                fix="Remove the entry or create the missing memory file.",
                source="client_check",
            )
        ]

    try:
        target_content = target_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    return _check_frontmatter(file_path, line_num, link_target, target_content)


def _check_frontmatter(
    file_path: str,
    line_num: int,
    link_target: str,
    content: str,
) -> list[LocalFinding]:
    """Validate frontmatter presence and required fields in a memory file."""
    if not content.startswith("---"):
        return [
            LocalFinding(
                file=file_path,
                line=line_num,
                severity="warning",
                rule=_RULE_MISSING_FM,
                message=f"`{link_target}` has no frontmatter — memories need name, description, type.",
                fix="Add YAML frontmatter with name, description, and type fields.",
                source="client_check",
            )
        ]

    end = content.find("\n---", 3)
    if end <= 0:
        return [
            LocalFinding(
                file=file_path,
                line=line_num,
                severity="warning",
                rule=_RULE_MISSING_FM,
                message=f"`{link_target}` has unclosed frontmatter block.",
                fix="Close the YAML frontmatter with `---` on its own line.",
                source="client_check",
            )
        ]

    try:
        import yaml

        fm = yaml.safe_load(content[3:end])
        if isinstance(fm, dict):
            missing = _FRONTMATTER_REQUIRED - set(fm.keys())
            if missing:
                return [
                    LocalFinding(
                        file=file_path,
                        line=line_num,
                        severity="warning",
                        rule=_RULE_MISSING_FM,
                        message=f"`{link_target}` missing frontmatter: {', '.join(sorted(missing))}.",
                        fix="Add the missing fields to the memory file's YAML frontmatter.",
                        source="client_check",
                    )
                ]
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        pass

    return []


def validate_memory_files(
    file_paths: list[str],
) -> list[LocalFinding]:
    """Validate memory index files — check links and frontmatter.

    Args:
        file_paths: All instruction file paths from the ruleset map.

    Returns:
        List of LocalFinding for memory index issues.
    """
    findings: list[LocalFinding] = []

    for file_path in file_paths:
        if "memory" not in file_path.lower() and "MEMORY" not in file_path:
            continue

        fp = Path(file_path)
        if not fp.is_absolute():
            fp = Path.cwd() / fp

        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        memory_dir = fp.parent

        for line_num, line in enumerate(raw.splitlines(), 1):
            m = _MEMORY_LINK_RE.search(line)
            if not m:
                continue

            link_target = m.group(2)
            target_path = memory_dir / link_target
            findings.extend(_validate_link_target(file_path, line_num, link_target, target_path))

    return findings
