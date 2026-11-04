"""An agent type's source shows what its launches were sent with: the system prompt size of the first launch that
recorded a request and each tool with the launches that had it."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.xray_sources import AgentLaunch, XraySource
from reporails_cli.core.xray.session import XraySession
from tests.unit.xray.test_xray_composition import _files
from tests.unit.xray.test_xray_graph import _graph, launch
from tests.unit.xray.test_xray_measured import _request, _size

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


def _type_source(root: Path, records: list[EventRecord]) -> XraySource:
    (source,) = [item for item in _graph(root, records, _files(root)).sources if item.agent_type == "general-purpose"]
    return source


def _shaped(sub: str, seconds: float, system: int, tools: tuple[str, ...]) -> EventRecord:
    return _request(seconds, replace(_size(f"req-{sub}", system_chars=system), tool_names=tools), sub)


def test_a_type_lists_its_tools_with_the_launches_that_had_each(tmp_path: Path) -> None:
    records = [
        launch(1, "A", None, "tuA"),
        _shaped("A", 1.5, 4000, ("Read", "Grep", "Bash")),
        launch(2, "B", None, "tuB"),
        _shaped("B", 2.5, 800, ("Read", "Glob")),
    ]
    source = _type_source(tmp_path, records)
    assert source.launch is not None and source.launch.tools == (("Read", 2), ("Bash", 1), ("Glob", 1), ("Grep", 1))
    assert source.tools == ()
    # the size is the first launch's own: 4000 characters is 1000 tokens
    assert source.launch.system_tokens_est == 1000 and source.launches == 2


def test_a_second_request_of_a_launch_does_not_count_its_tools_again(tmp_path: Path) -> None:
    records = [
        launch(1, "A", None, "tuA"),
        _shaped("A", 1.5, 400, ("Read",)),
        _shaped("A", 1.6, 400, ("Read", "Edit")),
    ]
    assert (_type_source(tmp_path, records).launch or AgentLaunch(0, ())).tools == (("Read", 1),)


def test_a_type_with_no_recorded_request_keeps_today_s_state(tmp_path: Path) -> None:
    source = _type_source(tmp_path, [launch(1, "A", None, "tuA")])
    assert source.launch is None and source.builtin is True


def test_the_serialized_source_holds_sizes_and_names_only(tmp_path: Path) -> None:
    source = _type_source(tmp_path, [launch(1, "A", None, "tuA"), _shaped("A", 1.5, 400, ("Read",))])
    body = source.to_json()
    assert body["launch_tools"] == [["Read", 1]] and body["tools"] == [] and body["system_tokens_est"] == 100
    assert "text" not in json.dumps(body)


def test_the_system_prompt_comes_from_the_launch_the_size_was_taken_from(tmp_path: Path) -> None:
    """The first launch that recorded a request has no shape in its file; the later launch's prompt is not offered
    in its place."""
    root = tmp_path / "proj"
    root.mkdir()
    session_file = tmp_path / "s" / "s.jsonl"
    folder = session_file.with_suffix("") / "subagents"
    folder.mkdir(parents=True)
    request = {"type": "api-request", "id": "r", "shapeHash": "sh", "keep": 0, "tail": []}
    shape = {
        "type": "api-request-shape",
        "shapeHash": "sh",
        "shape": {"system": [{"type": "text", "text": "B"}], "tools": []},
    }
    (folder / "agent-A.jsonl").write_text(json.dumps(request) + "\n", encoding="utf-8")
    (folder / "agent-B.jsonl").write_text(json.dumps(shape) + "\n" + json.dumps(request) + "\n", encoding="utf-8")
    session = XraySession(root, session_file)
    session._transcript = [
        launch(1, "A", None, "tuA"),
        _shaped("A", 1.5, 400, ()),
        launch(2, "B", None, "tuB"),
        _shaped("B", 2.5, 400, ()),
    ]
    assert session.system_prompt("general-purpose") is None


def test_launch_settings_group_values_that_differ_and_say_agreement_once() -> None:
    from reporails_cli.core.platform.dto.events import MessageSize, RequestConfig, RequestSize, SubagentMeta
    from reporails_cli.core.xray.graph.shapes import launched_with

    def meta(model: str | None, background: bool, defaults: bool | None = None) -> SubagentMeta:
        return SubagentMeta(None, None, None, 1, None, False, background, model, defaults)

    def request(model: str) -> RequestSize:
        return RequestSize("r", 4, 4, 1, MessageSize(), 0, ("Read",), None, RequestConfig(model, 100, None, "low"))

    metas = {"a": meta("sonnet", True, True), "b": meta(None, True), "c": meta(None, True)}
    first = {key: request("claude-x") for key in metas}
    launch = launched_with(["a", "b", "c"], first, metas)
    assert launch is not None
    assert dict(launch.settings) == {
        "Model asked for": "default · 2 launches; sonnet · 1 launch",
        "Model in requests": "claude-x",
        "Launched with defaults": "not recorded · 2 launches; yes · 1 launch",
        "Background": "yes",
        "Effort": "low",
        "Max tokens": "100",
    }
