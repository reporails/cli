"""Memory index validation — broken links and missing frontmatter.

Client-side memory validation. Reads the local filesystem to validate
MEMORY.md index entries. Runs client-side (not in the API).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import MEMORY_SURFACES
from reporails_cli.core.mapper.structure import link_targets
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.dto.ruleset import FileRecord
from reporails_cli.core.platform.utils.utils import NOT_A_MAPPING, read_frontmatter

_FRONTMATTER_REQUIRED = {"name", "description", "type"}

# `CORE:S:0056` (Markdown Link Targets Resolve) — its `match` is unrestricted on
# `type`, so it already covers a memory file's links; this check re-implements it
# for memory files the mechanical scanner never reaches (auto-memory lives outside
# the scanned project tree).
_RULE_BROKEN_LINK = "CORE:S:0056"
# No shipped rule requires frontmatter on a memory-typed file — the two rules that
# require frontmatter identity (`CORE:S:0006`, `CORE:S:0005`) are matched to
# `type: rules` only. A missing/unclosed/incomplete frontmatter finding is reported
# under this local label instead of a `CORE:*` rule id, since no shipped rule covers it.
_RULE_MISSING_FM = "memory_frontmatter"


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
    read = read_frontmatter(content)
    if read.block is None and read.problem is None:
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

    if read.block is None:
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

    if read.problem is not None and read.problem.message == NOT_A_MAPPING:
        return [
            LocalFinding(
                file=file_path,
                line=line_num,
                severity="warning",
                rule=_RULE_MISSING_FM,
                message=f"`{link_target}` has frontmatter that is not a mapping of name, description, type.",
                fix="Write the frontmatter as `name:`, `description:` and `type:` lines.",
                source="client_check",
            )
        ]

    if read.problem is not None:
        return [
            LocalFinding(
                file=file_path,
                line=line_num,
                severity="warning",
                rule=_RULE_MISSING_FM,
                message=f"`{link_target}` has frontmatter that is not valid YAML.",
                fix="Fix the YAML frontmatter so it parses (quote values that contain `:` or `[`).",
                source="client_check",
            )
        ]

    missing = _FRONTMATTER_REQUIRED - set(read.data or {})
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
    return []


def validate_memory_files(
    files: Iterable[FileRecord],
) -> list[LocalFinding]:
    """Validate memory index files — check links and frontmatter.

    Args:
        files: The ruleset map's file records; those typed as a memory surface are validated.

    Returns:
        List of LocalFinding for memory index issues.
    """
    findings: list[LocalFinding] = []

    for record in files:
        if record.type not in MEMORY_SURFACES:
            continue
        file_path = record.path

        fp = Path(file_path)
        if not fp.is_absolute():
            fp = Path.cwd() / fp

        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        memory_dir = fp.parent

        first_per_line: dict[int, str] = {}
        for line_num, target in link_targets(raw):
            if target.endswith(".md"):
                first_per_line.setdefault(line_num, target)
        for line_num, link_target in first_per_line.items():
            target_path = memory_dir / link_target
            findings.extend(_validate_link_target(file_path, line_num, link_target, target_path))

    return findings
