"""Rule loading from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.bootstrap import get_rules_path
from reporails_cli.core.models import Category, Check, Rule, RuleType, Severity
from reporails_cli.core.utils import parse_frontmatter


def get_rules_dir() -> Path:
    """Get rules directory (~/.reporails/rules/).

    Returns:
        Path to rules directory
    """
    return get_rules_path()


def load_rules(rules_dir: Path | None = None) -> dict[str, Rule]:
    """Load all rules from rules directory.

    Scans rules/**/*.md, parses frontmatter, links to .yml files.

    Args:
        rules_dir: Path to rules directory (default: ~/.reporails/rules/)

    Returns:
        Dict mapping rule ID to Rule object
    """
    if rules_dir is None:
        rules_dir = get_rules_dir()

    if not rules_dir.exists():
        return {}

    rules: dict[str, Rule] = {}

    for md_path in rules_dir.rglob("*.md"):
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


def build_rule(frontmatter: dict[str, Any], md_path: Path, yml_path: Path | None) -> Rule:
    """Build Rule object from parsed frontmatter.

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
    # Parse checks (formerly antipatterns)
    checks = []
    # Support both "checks" and legacy "antipatterns" field names
    check_data = frontmatter.get("checks", frontmatter.get("antipatterns", []))
    for item in check_data:
        check = Check(
            id=item.get("id", ""),
            name=item.get("name", ""),
            severity=Severity(item.get("severity", "medium")),
        )
        checks.append(check)

    return Rule(
        id=frontmatter["id"],
        title=frontmatter["title"],
        category=Category(frontmatter["category"]),
        type=RuleType(frontmatter["type"]),
        level=frontmatter.get("level", "L2"),  # Default to L2 (Basic) if not specified
        checks=checks,
        detection=frontmatter.get("detection"),
        sources=frontmatter.get("sources", []),
        see_also=frontmatter.get("see_also", []),
        scoring=frontmatter.get("scoring", 0),
        validation=frontmatter.get("validation"),
        question=frontmatter.get("question"),
        criteria=frontmatter.get("criteria"),
        choices=frontmatter.get("choices"),
        pass_value=frontmatter.get("pass_value"),
        examples=frontmatter.get("examples"),
        md_path=md_path,
        yml_path=yml_path,
    )


def get_rules_by_type(rules: dict[str, Rule], rule_type: RuleType) -> dict[str, Rule]:
    """Filter rules by type.

    Pure function.

    Args:
        rules: Dict of rules
        rule_type: Type to filter by

    Returns:
        Filtered dict of rules
    """
    return {k: v for k, v in rules.items() if v.type == rule_type}


def get_rules_by_category(rules: dict[str, Rule], category: Category) -> dict[str, Rule]:
    """Filter rules by category.

    Pure function.

    Args:
        rules: Dict of rules
        category: Category to filter by

    Returns:
        Filtered dict of rules
    """
    return {k: v for k, v in rules.items() if v.category == category}


def get_rule_yml_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get list of .yml paths for rules that have them.

    Pure function.

    Args:
        rules: Dict of rules

    Returns:
        List of paths to .yml files
    """
    return [r.yml_path for r in rules.values() if r.yml_path is not None]
