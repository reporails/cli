"""Local findings as the request carries them."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from reporails_cli.core.platform.dto.diagnostics import CLIENT_CHECK_KINDS, FindingItem
from reporails_cli.core.platform.dto.models import LocalEntry, LocalFinding


def local_entries(
    findings: Iterable[FindingItem | LocalFinding],
    file_level_checks: frozenset[str],
    registry_ids: frozenset[str],
    resolve: Callable[[str], str],
    type_of: Callable[[str], str] = lambda _path: "generic",
) -> list[LocalEntry]:
    """One entry per reported local finding, in order — no message and no matched text.

    `findings` are the local findings as they will be reported (suppressions applied);
    `file_level_checks` are the check ids whose finding concerns the whole file, sent at line 0;
    `registry_ids` are the rule ids the registry defines: a finding under any other label stays
    in the user's output but is not sent, and so does a finding from a client check
    (`CLIENT_CHECK_KINDS`);
    `resolve` maps a reported path to its absolute path, and `type_of` an absolute path to its
    file type.
    """
    entries: list[LocalEntry] = []
    for f in findings:
        check = f.check_id
        if f.rule not in registry_ids or check in CLIENT_CHECK_KINDS:
            continue
        line = 0 if check in file_level_checks else max(f.line, 0)
        file = resolve(f.file)
        entries.append(
            LocalEntry(rule=f.rule, file=file, line=line, severity=f.severity, check=check, type=type_of(file))
        )
    return entries
