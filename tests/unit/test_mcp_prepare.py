"""The MCP `prepare` tool: it maps what `validate` would check and does nothing else."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from reporails_cli.core.pipeline import check_one
from reporails_cli.core.platform.dto.pipeline import Refusal
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.interfaces.mcp import server, tools
from reporails_cli.interfaces.mcp.prepare import prepare_for_path
from tests.fake_models import no_models

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


def _map(n_files: int = 0) -> RulesetMap:
    return RulesetMap.model_construct(
        schema_version="1", embedding_model="m", generated_at="t", files=tuple(range(n_files)), atoms=()
    )


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "CLAUDE.md").write_text("# Project\n\nAlways run the tests.\n", encoding="utf-8")
    monkeypatch.setattr(check_one, "is_initialized", lambda: True)
    monkeypatch.setattr(check_one, "model_refusal", lambda _fetch: None)
    return root


def test_prepare_answers_the_number_of_mapped_files(project, monkeypatch):
    monkeypatch.setattr(check_one, "map_instruction_files", lambda *_a, **_k: _map(3))
    assert prepare_for_path(str(project), None, project, no_models()) == {"files": 3}


def test_prepare_builds_no_api_client_and_leaves_the_validate_state_alone(project, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("prepare must not contact the server")

    monkeypatch.setattr("reporails_cli.core.platform.adapters.server_lint.AilsClient", refuse)
    monkeypatch.setattr(tools, "has_api_key", refuse)
    monkeypatch.setattr(check_one, "map_instruction_files", lambda *_a, **_k: _map(1))
    server.validate_states.clear()

    result = asyncio.run(server.prepare(None, str(project)))

    assert json.loads(result.content[0].text) == {"files": 1}
    assert result.structured_content == {"files": 1}
    assert server.validate_states == {}


def test_prepare_passes_model_downloading_through_without_mapping(project, monkeypatch):
    reply = {"error": "model_downloading", "message": tools._MODEL_DOWNLOADING}
    monkeypatch.setattr(check_one, "model_refusal", lambda _fetch: Refusal("model_downloading", "downloading"))

    def refuse(*_a, **_k):
        raise AssertionError("no map while the model downloads")

    monkeypatch.setattr(check_one, "map_instruction_files", refuse)
    assert prepare_for_path(str(project), None, project, no_models()) == reply


def test_prepare_answers_target_not_found_as_validate_does(project, monkeypatch):
    monkeypatch.setattr(check_one, "map_instruction_files", lambda *_a, **_k: _map(1))
    reply = prepare_for_path(str(project), ["nope/missing.md"], project, no_models())
    assert reply["error"] == "target_not_found"


def test_prepare_answers_config_unreadable_as_validate_does(project):
    (project / ".ails").mkdir()
    (project / ".ails" / "config.yml").write_text("disabled_rules: [CORE:E:0003\n", encoding="utf-8")
    reply = json.loads(asyncio.run(server.prepare(None, str(project))).content[0].text)
    assert reply["error"] == "config_unreadable"
    assert str(project / ".ails" / "config.yml") in reply["message"]


def test_prepare_on_a_project_with_nothing_to_map_answers_zero(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(check_one, "is_initialized", lambda: True)
    monkeypatch.setattr(check_one, "model_refusal", lambda _fetch: None)
    assert prepare_for_path(str(empty), None, empty, no_models()) == {"files": 0}


def test_prepare_names_a_missing_path(project):
    assert prepare_for_path(str(project / "gone"), None, project, no_models())["error"].startswith("Path not found")


def test_prepare_answers_mapper_unavailable_when_no_map_comes_back(project, monkeypatch):
    def broken(*_a, **_k):
        raise RuntimeError("no model")

    monkeypatch.setattr(check_one, "map_instruction_files", broken)
    assert prepare_for_path(str(project), None, project, no_models()) == {
        "error": "mapper_unavailable",
        "mapper_error": "RuntimeError: no model",
    }


def test_prepare_maps_a_file_added_since_the_last_call(project, monkeypatch):
    mapped: list[list[str]] = []

    def record(_target, files, **_k):
        mapped.append(sorted(Path(f).name for f in files))
        return _map(len(files))

    monkeypatch.setattr(check_one, "map_instruction_files", record)
    prepare_for_path(str(project), None, project, no_models())
    rules = project / ".claude" / "rules"
    rules.mkdir(parents=True)
    (rules / "style.md").write_text("# Style\n\nUse snake_case for functions.\n", encoding="utf-8")
    prepare_for_path(str(project), None, project, no_models())
    assert "style.md" not in mapped[0]
    assert "style.md" in mapped[1]
