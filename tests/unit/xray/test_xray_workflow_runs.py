"""The workflow runs of a session as the view lists them: their phases, their agents and their status."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.xray import XrayView
from reporails_cli.core.platform.dto.xray_workflows import XrayWorkflow
from reporails_cli.core.xray.session import XraySession
from tests.unit.xray.test_xray_session import _project, _session, _view

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

WORKFLOW = "2.1.311-workflow"
FIRST, SECOND = "awf0000000000001", "awf0000000000002"


def _setup(tmp_path: Path) -> tuple[XraySession, Path]:
    session = _session(tmp_path, WORKFLOW, _project(tmp_path))
    return session, tmp_path / WORKFLOW / "session" / "workflows" / "wf_test01.json"


def _edited(record: Path, **changes: object) -> None:
    record.write_text(json.dumps(json.loads(record.read_text()) | changes))


def _run(view: XrayView) -> XrayWorkflow:
    (run,) = view.workflows
    return run


def test_a_run_finishing_raises_the_version_so_the_page_draws_it_again(tmp_path: Path) -> None:
    session, record = _setup(tmp_path)
    finished = record.read_text()
    _edited(record, status="running", totalTokens=100)
    running = _view(session)
    assert _view(session).version == running.version
    record.write_text(finished)
    done = _view(session)
    assert done.version > running.version
    assert (_run(done).status, _run(done).total_tokens) == ("completed", 4200)
    record.unlink()
    assert _view(session).version > done.version


def test_two_phases_with_one_title_list_each_agent_under_its_own_phase_once(tmp_path: Path) -> None:
    session, record = _setup(tmp_path)
    data = json.loads(record.read_text())
    progress = [{**e, "phaseTitle": "Build"} if "agentId" in e else e for e in data["workflowProgress"]]
    _edited(record, phases=[{"title": "Build"}, {"title": "Build"}], workflowProgress=progress)
    run = _run(_view(session))
    assert [(p.title, p.agents) for p in run.phases] == [("Build", (FIRST,)), ("Build", (SECOND,))]
    assert (run.unphased, run.agent_count) == ((), 2)


def test_an_agent_whose_phase_the_run_does_not_hold_is_listed_apart_and_counted(tmp_path: Path) -> None:
    session, record = _setup(tmp_path)
    progress = [
        {**e, "phaseIndex": 7} if e.get("agentId") == SECOND else e
        for e in json.loads(record.read_text())["workflowProgress"]
    ]
    _edited(record, workflowProgress=progress)
    run = _run(_view(session))
    assert [(p.title, p.agents) for p in run.phases] == [("Build", (FIRST,)), ("Verify", ())]
    assert (run.unphased, run.agent_count) == ((SECOND,), 2)


def test_a_record_file_that_is_not_json_shows_the_run_as_not_readable_not_as_running(tmp_path: Path) -> None:
    session, record = _setup(tmp_path)
    record.write_text('{"runId": "wf_test01", "status": "comp')
    run = _run(_view(session))
    assert (run.status, run.status_text) == ("unreadable", "not readable")
    assert run.refusal is not None and "wf_test01.json" in run.refusal
    assert run.agent_count == 2
