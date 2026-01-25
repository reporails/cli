"""OpenGrep binary execution - runs OpenGrep and returns SARIF output.

Isolated I/O module for OpenGrep interactions.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any

from reporails_cli.bundled import get_capability_patterns_path, get_semgrepignore_path
from reporails_cli.core.bootstrap import get_opengrep_bin
from reporails_cli.core.models import Rule

logger = logging.getLogger(__name__)

# Module-level debug flag (set by CLI)
_debug_timing = False


def set_debug_timing(enabled: bool) -> None:
    """Enable/disable timing output to stderr."""
    global _debug_timing
    _debug_timing = enabled


def _log_timing(label: str, elapsed_ms: float) -> None:
    """Log timing info to stderr if debug enabled."""
    if _debug_timing:
        print(f"[perf] {label}: {elapsed_ms:.0f}ms", file=sys.stderr)

# Template placeholder pattern
TEMPLATE_PATTERN = re.compile(r"\{\{(\w+)\}\}")


def _ensure_semgrepignore(target: Path) -> Path | None:
    """Ensure .semgrepignore exists in target directory.

    If no .semgrepignore exists, copies the bundled default.
    Returns path to temp file if created, None if already exists.

    Args:
        target: Target directory to scan

    Returns:
        Path to temp .semgrepignore if created, None otherwise
    """
    target_dir = target if target.is_dir() else target.parent
    existing = target_dir / ".semgrepignore"
    if existing.exists():
        return None

    # Copy bundled .semgrepignore to target directory
    bundled = get_semgrepignore_path()
    if bundled.exists():
        try:
            shutil.copy(bundled, existing)
            return existing  # Return so caller can clean up
        except OSError:
            pass
    return None


def _glob_to_regex(glob_pattern: str, for_yaml: bool = True) -> str:
    """Convert a glob pattern to a regex pattern.

    Handles common glob syntax:
    - ** → .* (match any path)
    - * → [^/]* (match any chars except /)
    - . → \\. (escape literal dot)
    - Other special regex chars are escaped

    Args:
        glob_pattern: Glob pattern like "**/CLAUDE.md"
        for_yaml: If True, double-escape backslashes for YAML double-quoted strings

    Returns:
        Regex pattern like ".*CLAUDE\\.md"
    """
    # Remove leading **/ (matches any directory prefix)
    pattern = glob_pattern
    if pattern.startswith("**/"):
        pattern = pattern[3:]

    # Escape regex special chars except * and ?
    # We handle * specially below
    result = ""
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                # ** matches anything including /
                result += ".*"
                i += 2
                # Skip trailing / after **
                if i < len(pattern) and pattern[i] == "/":
                    i += 1
            else:
                # * matches anything except /
                result += "[^/]*"
                i += 1
        elif c == "?":
            result += "."
            i += 1
        elif c in ".^$+{}[]|()":
            # Escape for regex, double-escape for YAML if needed
            escape = "\\\\" if for_yaml else "\\"
            result += escape + c
            i += 1
        else:
            result += c
            i += 1

    return result


def resolve_yml_templates(yml_path: Path, context: dict[str, str | list[str]]) -> str:
    """Resolve template placeholders in yml content.

    Replaces {{placeholder}} with values from context.
    Context-aware resolution:
    - In array context (paths.include), expands list to multiple items
    - In pattern-regex context, converts globs to regex and joins with |
    - For string values, does simple substitution

    Args:
        yml_path: Path to yml file
        context: Dict mapping placeholder names to string or list values

    Returns:
        Resolved yml content
    """
    content = yml_path.read_text(encoding="utf-8")

    for key, value in context.items():
        placeholder = "{{" + key + "}}"
        if placeholder not in content:
            continue

        if isinstance(value, list):
            # Find the line with the placeholder and its indentation
            lines = content.split("\n")
            new_lines = []
            for line in lines:
                if placeholder in line:
                    stripped = line.lstrip()
                    indent = len(line) - len(stripped)
                    indent_str = " " * indent

                    # Check context: array (starts with -) or pattern-regex
                    if stripped.startswith("- "):
                        # Array context: expand to multiple list items
                        for item in value:
                            new_lines.append(f'{indent_str}- "{item}"')
                    elif "pattern-regex:" in line or "pattern-not-regex:" in line:
                        # Regex context: convert globs to regex, join with |
                        regex_patterns = [_glob_to_regex(g) for g in value]
                        combined = "(" + "|".join(regex_patterns) + ")"
                        new_lines.append(line.replace(placeholder, combined))
                    else:
                        # Other scalar context: use first item
                        first_item = value[0] if value else ""
                        new_lines.append(line.replace(placeholder, first_item))
                else:
                    new_lines.append(line)
            content = "\n".join(new_lines)
        else:
            # Simple string substitution
            content = content.replace(placeholder, str(value))

    return content


def has_templates(yml_path: Path) -> bool:
    """Check if yml file contains template placeholders.

    Args:
        yml_path: Path to yml file

    Returns:
        True if templates found
    """
    try:
        content = yml_path.read_text(encoding="utf-8")
        return bool(TEMPLATE_PATTERN.search(content))
    except OSError:
        return False


async def run_opengrep(
    yml_paths: list[Path],
    target: Path,
    opengrep_path: Path | None = None,
    template_context: dict[str, str | list[str]] | None = None,
) -> dict[str, Any]:
    """Execute OpenGrep with specified rule configs.

    Shells out to OpenGrep, returns parsed SARIF.

    Args:
        yml_paths: List of .yml rule config files (must exist)
        target: Directory to scan
        opengrep_path: Path to OpenGrep binary (optional, auto-detects)
        template_context: Optional dict for resolving {{placeholder}} in yml files

    Returns:
        Parsed SARIF JSON output
    """
    start_time = time.perf_counter()

    # Filter to only existing yml files - don't call OpenGrep with nothing to run
    valid_paths = [p for p in yml_paths if p and p.exists()]
    if not valid_paths:
        return {"runs": []}

    if opengrep_path is None:
        opengrep_path = get_opengrep_bin()

    if not opengrep_path.exists():
        logger.warning("OpenGrep binary not found: %s", opengrep_path)
        return {"runs": []}

    # Create temp file for SARIF output
    with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        sarif_path = Path(f.name)

    # Use temp directory for resolved yml files if context provided
    temp_dir = TemporaryDirectory() if template_context else None

    # Ensure .semgrepignore exists for performance
    created_semgrepignore = _ensure_semgrepignore(target)

    try:
        # Resolve templates if context provided
        if template_context and temp_dir:
            resolved_paths: list[Path] = []
            for yml_path in valid_paths:
                if has_templates(yml_path):
                    # Resolve and write to temp file
                    resolved_content = resolve_yml_templates(yml_path, template_context)
                    temp_yml = Path(temp_dir.name) / yml_path.name
                    temp_yml.write_text(resolved_content, encoding="utf-8")
                    resolved_paths.append(temp_yml)
                else:
                    # No templates, use original
                    resolved_paths.append(yml_path)
            config_paths = resolved_paths
        else:
            config_paths = valid_paths

        # Build command
        cmd = [
            str(opengrep_path),
            "scan",
            "--sarif",
            f"--output={sarif_path}",
        ]

        # Add rule files
        for yml_path in config_paths:
            cmd.extend(["--config", str(yml_path)])

        # Add target
        cmd.append(str(target))

        # Run OpenGrep
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        _log_timing(f"opengrep ({len(config_paths)} rules)", elapsed_ms)

        # Check for OpenGrep errors (0 = no findings, 1 = findings found)
        if process.returncode not in (0, 1):
            logger.warning(
                "OpenGrep failed with code %d: %s",
                process.returncode,
                stderr.decode("utf-8", errors="replace")[:500],
            )
            return {"runs": []}

        # Parse SARIF output
        if sarif_path.exists():
            try:
                result: dict[str, Any] = json.loads(sarif_path.read_text(encoding="utf-8"))
                return result
            except json.JSONDecodeError as e:
                logger.warning("Invalid SARIF output from OpenGrep: %s", e)
                return {"runs": []}
        return {"runs": []}

    finally:
        # Clean up
        if sarif_path.exists():
            sarif_path.unlink()
        if temp_dir:
            temp_dir.cleanup()
        # Clean up created .semgrepignore
        if created_semgrepignore and created_semgrepignore.exists():
            try:
                created_semgrepignore.unlink()
            except OSError:
                pass


def run_opengrep_sync(
    yml_paths: list[Path],
    target: Path,
    opengrep_path: Path | None = None,
    template_context: dict[str, str | list[str]] | None = None,
) -> dict[str, Any]:
    """Synchronous version of run_opengrep.

    Args:
        yml_paths: List of .yml rule config files (must exist)
        target: Directory to scan
        opengrep_path: Path to OpenGrep binary (optional, auto-detects)
        template_context: Optional dict for resolving {{placeholder}} in yml files

    Returns:
        Parsed SARIF JSON output
    """
    start_time = time.perf_counter()

    # Filter to only existing yml files - don't call OpenGrep with nothing to run
    valid_paths = [p for p in yml_paths if p and p.exists()]
    if not valid_paths:
        return {"runs": []}

    if opengrep_path is None:
        opengrep_path = get_opengrep_bin()

    if not opengrep_path.exists():
        logger.warning("OpenGrep binary not found: %s", opengrep_path)
        return {"runs": []}

    # Create temp file for SARIF output
    with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        sarif_path = Path(f.name)

    # Use temp directory for resolved yml files if context provided
    temp_dir = TemporaryDirectory() if template_context else None

    # Ensure .semgrepignore exists for performance
    created_semgrepignore = _ensure_semgrepignore(target)

    try:
        # Resolve templates if context provided
        if template_context and temp_dir:
            resolved_paths: list[Path] = []
            for yml_path in valid_paths:
                if has_templates(yml_path):
                    # Resolve and write to temp file
                    resolved_content = resolve_yml_templates(yml_path, template_context)
                    temp_yml = Path(temp_dir.name) / yml_path.name
                    temp_yml.write_text(resolved_content, encoding="utf-8")
                    resolved_paths.append(temp_yml)
                else:
                    # No templates, use original
                    resolved_paths.append(yml_path)
            config_paths = resolved_paths
        else:
            config_paths = valid_paths

        # Build command
        cmd = [
            str(opengrep_path),
            "scan",
            "--sarif",
            f"--output={sarif_path}",
        ]

        # Add rule files
        for yml_path in config_paths:
            cmd.extend(["--config", str(yml_path)])

        # Add target
        cmd.append(str(target))

        # Run OpenGrep
        proc = subprocess.run(cmd, capture_output=True, check=False)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        _log_timing(f"opengrep ({len(config_paths)} rules)", elapsed_ms)

        # Check for errors (0 = no findings, 1 = findings found)
        if proc.returncode not in (0, 1):
            logger.warning(
                "OpenGrep failed with code %d: %s",
                proc.returncode,
                proc.stderr.decode("utf-8", errors="replace")[:500],
            )
            return {"runs": []}

        # Parse SARIF output
        if sarif_path.exists():
            try:
                result: dict[str, Any] = json.loads(sarif_path.read_text(encoding="utf-8"))
                return result
            except json.JSONDecodeError as e:
                logger.warning("Invalid SARIF output from OpenGrep: %s", e)
                return {"runs": []}
        return {"runs": []}

    finally:
        if sarif_path.exists():
            sarif_path.unlink()
        if temp_dir:
            temp_dir.cleanup()
        # Clean up created .semgrepignore
        if created_semgrepignore and created_semgrepignore.exists():
            try:
                created_semgrepignore.unlink()
            except OSError:
                pass


async def run_capability_detection(target: Path) -> dict[str, Any]:
    """Run capability detection using bundled patterns.

    Uses bundled capability-patterns.yml for content analysis.

    Args:
        target: Directory to scan

    Returns:
        Parsed SARIF JSON output
    """
    patterns_path = get_capability_patterns_path()
    if not patterns_path.exists():
        logger.warning("Capability patterns not found: %s", patterns_path)
        return {"runs": []}

    return await run_opengrep([patterns_path], target)


def run_capability_detection_sync(target: Path) -> dict[str, Any]:
    """Synchronous version of run_capability_detection.

    Args:
        target: Directory to scan

    Returns:
        Parsed SARIF JSON output
    """
    patterns_path = get_capability_patterns_path()
    if not patterns_path.exists():
        logger.warning("Capability patterns not found: %s", patterns_path)
        return {"runs": []}

    return run_opengrep_sync([patterns_path], target)


async def run_rule_validation(rules: dict[str, Rule], target: Path) -> dict[str, Any]:
    """Run rule validation using rule .yml files.

    Args:
        rules: Dict of rules with yml_path set
        target: Directory to scan

    Returns:
        Parsed SARIF JSON output
    """
    # Filter to yml files that actually exist
    yml_paths = [
        r.yml_path for r in rules.values()
        if r.yml_path is not None and r.yml_path.exists()
    ]
    if not yml_paths:
        # No patterns to run — this is normal, not an error
        return {"runs": []}

    return await run_opengrep(yml_paths, target)


def run_rule_validation_sync(rules: dict[str, Rule], target: Path) -> dict[str, Any]:
    """Synchronous version of run_rule_validation.

    Args:
        rules: Dict of rules with yml_path set
        target: Directory to scan

    Returns:
        Parsed SARIF JSON output
    """
    # Filter to yml files that actually exist
    yml_paths = [
        r.yml_path for r in rules.values()
        if r.yml_path is not None and r.yml_path.exists()
    ]
    if not yml_paths:
        # No patterns to run — this is normal, not an error
        return {"runs": []}

    return run_opengrep_sync(yml_paths, target)


def get_rule_yml_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get list of .yml paths for rules that have them and exist.

    Args:
        rules: Dict of rules

    Returns:
        List of paths to existing .yml files
    """
    return [
        r.yml_path for r in rules.values()
        if r.yml_path is not None and r.yml_path.exists()
    ]
