"""Mechanical check runner — executes Python-based structural checks.

Public API: run_mechanical_checks(), dispatch_single_check()
"""

from reporails_cli.core.mechanical.runner import (
    bind_instruction_files,
    dispatch_single_check,
    resolve_location,
    run_mechanical_checks,
)

__all__ = ["bind_instruction_files", "dispatch_single_check", "resolve_location", "run_mechanical_checks"]
