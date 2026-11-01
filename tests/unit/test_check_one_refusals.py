"""A refusal `check_one` builds always carries a sentence for the user; MCP formatter errors surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.mapper import model_fetch
from reporails_cli.core.pipeline import check_one
from reporails_cli.core.pipeline.check_one import check_path
from reporails_cli.core.platform.dto.pipeline import Refusal
from reporails_cli.interfaces.mcp import tools

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    (root / ".ails").mkdir(parents=True)
    clear_agent_cache()
    monkeypatch.setattr(check_one, "is_initialized", lambda: True)
    monkeypatch.setattr(check_one, "model_refusal", lambda: None)
    return root


def _refused(path: Path) -> Refusal:
    refusal = check_path(str(path))
    assert isinstance(refusal, Refusal)
    return refusal


def test_unknown_agent_refusal_names_the_agent(project: Path) -> None:
    (project / ".ails" / "config.yml").write_text("default_agent: codx\n", encoding="utf-8")
    refusal = _refused(project)
    assert refusal.kind == "unknown_agent"
    assert refusal.text == "Unknown agent: codx"
    assert tools.refusal_payload(refusal)["error"] == "Unknown agent: codx"


def test_empty_project_refusal_names_the_folder(project: Path) -> None:
    refusal = _refused(project)
    assert refusal.kind == "empty_project"
    assert refusal.text == f"No instruction files found in {project.resolve()}"


def test_path_not_found_and_rules_missing_carry_a_sentence(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _refused(project / "nope").text.startswith("Path not found: ")
    monkeypatch.setattr(check_one, "is_initialized", lambda: False)
    missing = _refused(project)
    assert missing.kind == "rules_missing"
    assert "reinstall reporails-cli" in missing.text
    assert tools.refusal_payload(missing) == {"needs_install": True, "message": missing.text}


def test_model_not_ready_refusals_carry_a_sentence_and_mcp_keeps_its_own_wording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.undo()
    monkeypatch.setattr(check_one, "models_present", lambda _p: False)
    monkeypatch.setattr(model_fetch, "download_in_progress", lambda: True)
    downloading = check_one.model_refusal()
    assert downloading is not None and downloading.kind == "model_downloading"
    assert downloading.text and "validate" not in downloading.text
    assert "Call validate again" in str(tools.refusal_payload(downloading)["message"])


def test_failed_refusal_is_never_empty(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_scope: object) -> None:
        raise ValueError

    monkeypatch.setattr(check_one, "check_scope", boom)
    (project / "CLAUDE.md").write_text("# P\n\nRun tests.\n", encoding="utf-8")
    assert _refused(project).text


def test_mcp_does_not_swallow_a_formatter_error(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (project / "CLAUDE.md").write_text("# P\n\nRun tests.\n", encoding="utf-8")
    monkeypatch.setattr(tools, "check_path", lambda *_a, **_k: object())

    def bad(_run: object, full: bool = False) -> None:
        raise ValueError("formatter bug")

    monkeypatch.setattr(tools, "format_run", bad)
    with pytest.raises(ValueError, match="formatter bug"):
        tools.run_pipeline_for_path(str(project))
