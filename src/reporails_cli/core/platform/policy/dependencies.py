"""Rule dependencies — a finding is dropped where a rule it depends on already reports.

Pure: takes the findings as detected and the resolved dependency map, no IO.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def drop_dependent_findings(
    findings: Iterable[Any],
    dependencies: Mapping[str, frozenset[str]],
    whole_run_checks: frozenset[str],
) -> list[Any]:
    """The findings that remain once those covered by a rule they depend on are dropped.

    A finding of rule R is covered when R depends on D and D has a finding on the same file.
    A finding that stands for the matched files as a whole (its check is in `whole_run_checks`)
    is covered when D has a finding anywhere in the run. Coverage is judged on every finding
    given, so a chain A -> B -> C drops A and B and keeps C. Order is preserved.
    """
    items = list(findings)
    if not dependencies:
        return items
    files_by_rule: dict[str, set[str]] = {}
    for f in items:
        files_by_rule.setdefault(f.rule, set()).add(f.file)

    def _covered(f: Any) -> bool:
        deps = dependencies.get(f.rule, frozenset()) - {f.rule}
        if getattr(f, "check_id", "") in whole_run_checks:
            return any(d in files_by_rule for d in deps)
        return any(f.file in files_by_rule.get(d, ()) for d in deps)

    return [f for f in items if not _covered(f)]
