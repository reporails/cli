"""Shared utility functions used across modules.

All functions are pure (no I/O) except where noted.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

# Use C YAML loader when available (~3-5x faster than pure Python SafeLoader)
try:
    from yaml import CSafeLoader as _YamlLoader
except ImportError:
    from yaml import SafeLoader as _YamlLoader  # type: ignore[assignment]


def fast_yaml_load(content: str) -> Any:
    """Load YAML content using fastest available loader."""
    return yaml.load(content, Loader=_YamlLoader)


def parse_frontmatter(content: str) -> dict[str, Any]:
    """Parse YAML frontmatter from markdown content.

    Pure function — no I/O.

    Args:
        content: Markdown file content

    Returns:
        Parsed frontmatter dict

    Raises:
        ValueError: If frontmatter missing or invalid
    """
    # Match YAML frontmatter between --- delimiters
    pattern = r"^---\s*\n(.*?)---\s*\n"
    match = re.match(pattern, content, re.DOTALL)

    if not match:
        msg = "No frontmatter found"
        raise ValueError(msg)

    yaml_content = match.group(1)
    try:
        return fast_yaml_load(yaml_content) or {}
    except yaml.YAMLError as e:
        msg = f"Invalid YAML in frontmatter: {e}"
        raise ValueError(msg) from e


def compute_content_hash(file_path: Path) -> str:
    """Compute SHA256 hash of file content.

    I/O function — reads file.

    Args:
        file_path: Path to file

    Returns:
        Hash string in format "sha256:{hash16}"
    """
    content = file_path.read_bytes()
    return f"sha256:{hashlib.sha256(content).hexdigest()[:16]}"


def is_valid_path_reference(path: str) -> bool:
    """Check if a string looks like a valid file path reference.

    Pure function.

    Args:
        path: Potential path string

    Returns:
        True if it looks like a valid path reference
    """
    # Must have at least one slash or dot
    if "/" not in path and "." not in path:
        return False

    # Filter out URLs
    if path.startswith("http://") or path.startswith("https://"):
        return False

    # Reject path traversal attempts (../../../etc)
    if path.count("..") > 2:
        return False

    # Reject absolute paths outside project
    if path.startswith("/") and not path.startswith("./"):
        return False

    # Filter out common false positives
    false_positives = {"e.g.", "i.e.", "etc.", "vs.", "v1", "v2"}
    return path.lower() not in false_positives


def relative_to_safe(path: Path, base: Path) -> str:
    """Get relative path safely, with fallback to absolute.

    Pure function.

    Args:
        path: Path to convert
        base: Base directory

    Returns:
        Relative path string, or absolute if not relative to base
    """
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def normalize_rule_id(rule_id: str) -> str:
    """Normalize rule ID to uppercase.

    Pure function.

    Args:
        rule_id: Raw rule ID

    Returns:
        Uppercase rule ID
    """
    return rule_id.upper()


def extract_body_content(markdown: str) -> str:
    """Extract content after frontmatter from markdown.

    Pure function.

    Args:
        markdown: Full markdown content

    Returns:
        Content after frontmatter (or full content if no frontmatter)
    """
    parts = markdown.split("---", 2)
    if len(parts) >= 3:
        return parts[2].strip()
    return markdown.strip()
