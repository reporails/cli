"""Python regex engine module.

Built-in pattern matching runtime. Interprets OpenGrep-compatible YAML rule
files natively using Python's re module.
"""

from reporails_cli.core.regex.runner import (
    checks_per_file,
    get_rule_yml_paths,
    run_capability_detection,
    run_validation,
)

__all__ = [
    "checks_per_file",
    "get_rule_yml_paths",
    "run_capability_detection",
    "run_validation",
]
