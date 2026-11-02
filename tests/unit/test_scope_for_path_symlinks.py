"""A folder check keeps an instruction file that is a symlink into another folder."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.pipeline import check_one
from reporails_cli.core.platform.dto.pipeline import Scope

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


def test_scope_for_a_folder_keeps_a_symlinked_instruction_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "proj"
    agents = project / ".claude" / "agents"
    agents.mkdir(parents=True)
    outside = tmp_path / "shared" / "reviewer.md"
    outside.parent.mkdir()
    outside.write_text(
        "---\nname: reviewer\ndescription: Reviews a change.\n---\n\nReview the diff.\n", encoding="utf-8"
    )
    (agents / "reviewer.md").symlink_to(outside)
    (agents / "own.md").write_text("---\nname: own\ndescription: Own agent.\n---\n\nDo it.\n", encoding="utf-8")
    clear_agent_cache()
    monkeypatch.setattr(check_one, "is_initialized", lambda: True)
    monkeypatch.setattr(check_one, "model_refusal", lambda: None)

    scope = check_one.scope_for_path(str(agents), project)

    assert isinstance(scope, Scope)
    assert {f.name for f in scope.instruction_files} == {"reviewer.md", "own.md"}
