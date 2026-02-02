"""OpenGrep binary execution.

Runs OpenGrep and returns parsed SARIF output.
"""

from __future__ import annotations

import contextlib
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any

from reporails_cli.bundled import get_capability_patterns_path
from reporails_cli.core.bootstrap import get_opengrep_bin
from reporails_cli.core.models import Rule
from reporails_cli.core.opengrep.semgrepignore import ensure_semgrepignore
from reporails_cli.core.opengrep.templates import has_templates, resolve_templates

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


def run_opengrep(
    yml_paths: list[Path],
    target: Path,
    opengrep_path: Path | None = None,
    template_context: dict[str, str | list[str]] | None = None,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
) -> dict[str, Any]:
    """Execute OpenGrep with specified rule configs.

    Shells out to OpenGrep, returns parsed SARIF.

    Args:
        yml_paths: List of .yml rule config files (must exist)
        target: Directory to scan (used as fallback when instruction_files not provided)
        opengrep_path: Path to OpenGrep binary (optional, auto-detects)
        template_context: Optional dict for resolving {{placeholder}} in yml files
        extra_targets: Additional file paths to scan (e.g. resolved symlinks
            whose targets fall outside the scan directory)
        instruction_files: Explicit list of files to scan. When provided, these
            are passed directly to OpenGrep instead of the target directory,
            avoiding a full tree walk.

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

    # Build scan targets: explicit files or directory
    use_file_targets = bool(instruction_files)
    scan_targets: list[str] = []
    if use_file_targets:
        assert instruction_files is not None
        seen: set[Path] = set()
        for ifile in instruction_files:
            resolved = ifile.resolve()
            if resolved not in seen and resolved.exists():
                seen.add(resolved)
                scan_targets.append(str(resolved))
        if extra_targets:
            for extra in extra_targets:
                resolved = extra.resolve()
                if resolved not in seen and resolved.exists():
                    seen.add(resolved)
                    scan_targets.append(str(resolved))
        if not scan_targets:
            return {"runs": []}
    else:
        scan_targets.append(str(target))
        if extra_targets:
            for extra in extra_targets:
                scan_targets.append(str(extra))

    # Ensure .semgrepignore exists for performance (only needed for directory scans)
    created_semgrepignore = ensure_semgrepignore(target) if not use_file_targets else None

    try:
        # Resolve templates if context provided
        if template_context and temp_dir:
            resolved_paths: list[Path] = []
            for yml_path in valid_paths:
                if has_templates(yml_path):
                    # Resolve and write to temp file
                    resolved_content = resolve_templates(yml_path, template_context)
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

        # Add scan targets (explicit files or directory + extras)
        cmd.extend(scan_targets)

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
            with contextlib.suppress(OSError):
                created_semgrepignore.unlink()


def run_capability_detection(
    target: Path,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
) -> dict[str, Any]:
    """Run capability detection using bundled patterns.

    Uses bundled capability-patterns.yml for content analysis.

    Args:
        target: Directory to scan
        extra_targets: Additional file paths to scan (e.g. resolved symlinks)
        instruction_files: Explicit list of files to scan (avoids directory walk)

    Returns:
        Parsed SARIF JSON output
    """
    patterns_path = get_capability_patterns_path()
    if not patterns_path.exists():
        logger.warning("Capability patterns not found: %s", patterns_path)
        return {"runs": []}

    return run_opengrep(
        [patterns_path], target, extra_targets=extra_targets,
        instruction_files=instruction_files,
    )


def run_rule_validation(
    rules: dict[str, Rule],
    target: Path,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
) -> dict[str, Any]:
    """Run rule validation using rule .yml files.

    Args:
        rules: Dict of rules with yml_path set
        target: Directory to scan
        extra_targets: Additional file paths to scan (e.g. resolved symlinks)
        instruction_files: Explicit list of files to scan (avoids directory walk)

    Returns:
        Parsed SARIF JSON output
    """
    yml_paths = get_rule_yml_paths(rules)
    if not yml_paths:
        # No patterns to run - this is normal, not an error
        return {"runs": []}

    return run_opengrep(
        yml_paths, target, extra_targets=extra_targets,
        instruction_files=instruction_files,
    )


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
