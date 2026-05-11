"""Init command — set up rules at `~/.reporails/rules/`."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.install.download import (
    RULES_VERSION,
    download_rules,
    write_version_file,
)


def run_init() -> dict[str, str | int | Path]:
    """Run global initialization.

    Setup rules at ~/.reporails/rules/ (from local framework or GitHub).

    Returns dict with status info.
    """
    results: dict[str, str | int | Path] = {}

    # Setup rules (check local framework_path first, then GitHub)
    rules_path, rule_count = download_rules()
    results["rules_path"] = rules_path
    results["rule_count"] = rule_count

    # Write version file
    write_version_file(RULES_VERSION)
    results["rules_version"] = RULES_VERSION

    return results
