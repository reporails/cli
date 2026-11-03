"""An agent type's source shows what its launches were sent with: the system prompt size of the first launch that
recorded a request and each tool with the launches that had it."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.xray_sources import XraySource
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
    assert source.tools == (("Read", 2), ("Bash", 1), ("Glob", 1), ("Grep", 1))
    # the size is the first launch's own: 4000 characters is 1000 tokens
    assert source.system_tokens_est == 1000 and source.launches == 2


def test_a_second_request_of_a_launch_does_not_count_its_tools_again(tmp_path: Path) -> None:
    records = [
        launch(1, "A", None, "tuA"),
        _shaped("A", 1.5, 400, ("Read",)),
        _shaped("A", 1.6, 400, ("Read", "Edit")),
    ]
    assert _type_source(tmp_path, records).tools == (("Read", 1),)


def test_a_type_with_no_recorded_request_keeps_today_s_state(tmp_path: Path) -> None:
    source = _type_source(tmp_path, [launch(1, "A", None, "tuA")])
    assert source.tools == () and source.system_tokens_est is None and source.builtin is True


def test_the_serialized_source_holds_sizes_and_names_only(tmp_path: Path) -> None:
    source = _type_source(tmp_path, [launch(1, "A", None, "tuA"), _shaped("A", 1.5, 400, ("Read",))])
    body = source.to_json()
    assert body["tools"] == [["Read", 1]] and body["system_tokens_est"] == 100
    assert "text" not in json.dumps(body)
