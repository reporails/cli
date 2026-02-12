"""OpenGrep integration module.

Public API for running OpenGrep and processing results.
"""

from reporails_cli.core.opengrep.runner import (
    get_rule_yml_paths,
    run_capability_detection,
    run_opengrep,
    run_rule_validation,
    set_debug_timing,
)
from reporails_cli.core.opengrep.templates import (
    TEMPLATE_PATTERN,
    has_templates,
    resolve_templates,
)

# Backward-compatible alias
resolve_yml_templates = resolve_templates

__all__ = [
    "TEMPLATE_PATTERN",
    "get_rule_yml_paths",
    "has_templates",
    "resolve_templates",
    "resolve_yml_templates",
    "run_capability_detection",
    "run_opengrep",
    "run_rule_validation",
    "set_debug_timing",
]
