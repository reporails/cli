"""Template resolution for rule YAML files.

Handles {{placeholder}} substitution in .yml rule configs.
"""

from __future__ import annotations

import re
from pathlib import Path

# Template placeholder pattern
TEMPLATE_PATTERN = re.compile(r"\{\{(\w+)\}\}")


def _glob_to_regex(glob_pattern: str, for_yaml: bool = True) -> str:
    """Convert a glob pattern to a regex pattern.

    Handles common glob syntax:
    - ** -> .* (match any path)
    - * -> [^/]* (match any chars except /)
    - . -> \\. (escape literal dot)
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


def resolve_templates(yml_path: Path, context: dict[str, str | list[str]]) -> str:
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
            new_lines: list[str] = []
            for line in lines:
                if placeholder in line:
                    stripped = line.lstrip()
                    indent = len(line) - len(stripped)
                    indent_str = " " * indent

                    # Check context: array (starts with -) or pattern-regex
                    if stripped.startswith("- "):
                        # Array context: expand to multiple list items
                        new_lines.extend(f'{indent_str}- "{item}"' for item in value)
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
