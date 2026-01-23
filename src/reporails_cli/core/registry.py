"""Rule loading from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.models import Antipattern, Category, Rule, RuleType, Severity


def get_checks_dir() -> Path:
    """
    Get checks directory (~/.reporails/checks/).

    Returns:
        Path to checks directory
    """
    from reporails_cli.core.bootstrap import get_checks_path

    return get_checks_path()


def load_rules(checks_dir: Path | None = None) -> dict[str, Rule]:
    """
    Load all rules from checks directory.

    Scans checks/**/*.md, parses frontmatter, links to .yml files.

    Args:
        checks_dir: Path to checks directory (default: ~/.reporails/checks/)

    Returns:
        Dict mapping rule ID to Rule object
    """
    if checks_dir is None:
        checks_dir = get_checks_dir()

    if not checks_dir.exists():
        return {}

    rules: dict[str, Rule] = {}

    for md_path in checks_dir.rglob("*.md"):
        try:
            content = md_path.read_text(encoding="utf-8")
            frontmatter = parse_frontmatter(content)

            if not frontmatter:
                continue

            # Look for corresponding .yml file
            yml_path_candidate = md_path.with_suffix(".yml")
            yml_path: Path | None = yml_path_candidate if yml_path_candidate.exists() else None

            rule = build_rule(frontmatter, md_path, yml_path)
            rules[rule.id] = rule

        except (ValueError, KeyError):
            # Skip files without valid frontmatter
            continue

    return rules


def parse_frontmatter(content: str) -> dict[str, Any]:
    """
    Parse YAML frontmatter from markdown content.

    Pure function — no I/O.

    Args:
        content: Markdown file content

    Returns:
        Parsed frontmatter dict

    Raises:
        ValueError: If frontmatter missing or invalid
    """
    # Match YAML frontmatter between --- delimiters
    # Pattern allows for empty frontmatter (no content between delimiters)
    pattern = r"^---\s*\n(.*?)---\s*\n"
    match = re.match(pattern, content, re.DOTALL)

    if not match:
        msg = "No frontmatter found"
        raise ValueError(msg)

    yaml_content = match.group(1)
    try:
        return yaml.safe_load(yaml_content) or {}
    except yaml.YAMLError as e:
        msg = f"Invalid YAML in frontmatter: {e}"
        raise ValueError(msg) from e


def build_rule(frontmatter: dict[str, Any], md_path: Path, yml_path: Path | None) -> Rule:
    """
    Build Rule object from parsed frontmatter.

    Pure function — validates and constructs.

    Args:
        frontmatter: Parsed YAML dict
        md_path: Path to source .md file
        yml_path: Path to .yml file (optional)

    Returns:
        Rule object

    Raises:
        KeyError: If required fields missing
        ValueError: If field values invalid
    """
    # Parse antipatterns
    antipatterns = []
    for ap_data in frontmatter.get("antipatterns", []):
        antipattern = Antipattern(
            id=ap_data["id"],
            name=ap_data["name"],
            severity=Severity(ap_data.get("severity", "medium")),
            points=ap_data.get("points", -10),
        )
        antipatterns.append(antipattern)

    return Rule(
        id=frontmatter["id"],
        title=frontmatter["title"],
        category=Category(frontmatter["category"]),
        type=RuleType(frontmatter["type"]),
        level=frontmatter["level"],
        scoring=frontmatter.get("scoring", 0),
        detection=frontmatter.get("detection"),
        sources=frontmatter.get("sources", []),
        see_also=frontmatter.get("see_also", []),
        antipatterns=antipatterns,
        validation=frontmatter.get("validation"),
        md_path=md_path,
        yml_path=yml_path,
    )


def get_rules_by_type(rules: dict[str, Rule], rule_type: RuleType) -> dict[str, Rule]:
    """
    Filter rules by type.

    Pure function.

    Args:
        rules: Dict of rules
        rule_type: Type to filter by

    Returns:
        Filtered dict of rules
    """
    return {k: v for k, v in rules.items() if v.type == rule_type}


def get_rules_by_category(rules: dict[str, Rule], category: Category) -> dict[str, Rule]:
    """
    Filter rules by category.

    Pure function.

    Args:
        rules: Dict of rules
        category: Category to filter by

    Returns:
        Filtered dict of rules
    """
    return {k: v for k, v in rules.items() if v.category == category}


def get_rule_yml_paths(rules: dict[str, Rule]) -> list[Path]:
    """
    Get list of .yml paths for rules that have them.

    Pure function.

    Args:
        rules: Dict of rules

    Returns:
        List of paths to .yml files
    """
    return [r.yml_path for r in rules.values() if r.yml_path is not None]
