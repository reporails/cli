"""A scope's `patterns` is read as a single pattern or a list, as every other file-type reader does."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.exclusions import no_exclusions
from reporails_cli.core.discovery.memory_locator import _entries_from_directory_globs
from reporails_cli.core.platform.config.run_context import RunContext


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_scope_holding_one_pattern_as_text_enumerates_its_directory(tmp_path: Path) -> None:
    (tmp_path / "mem").mkdir()
    (tmp_path / "mem" / "note.md").write_text("# n\n", encoding="utf-8")
    spec = {"scopes": {"project": {"patterns": "mem/"}}}

    entries = _entries_from_directory_globs(
        RunContext(), "claude", "subagent_memory", spec, project_root=tmp_path, exclusions=no_exclusions(tmp_path)
    )

    assert [e.path.name for e in entries] == ["note.md"]
