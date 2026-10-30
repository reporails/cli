"""The event bus core: real Claude Code payloads become records, nothing else is stored."""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from reporails_cli.core.eventbus import port, store
from reporails_cli.core.eventbus.dispatcher import record_payload
from reporails_cli.core.eventbus.query import read_events
from reporails_cli.core.pipeline import expected_loads
from reporails_cli.core.platform.config.bootstrap import get_xray_log_dir
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.events import EventRecord, ToolUse

pytestmark = [pytest.mark.unit, pytest.mark.subsys_eventbus]

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "claude_payloads.jsonl"
SESSION = "0eaf5219-a81f-478c-b211-a82b56ea93d9"
SUB = "abc6bd7ba7ca09f1e"
ROWS = FIXTURE.read_text().splitlines()

# (kind, tool_name, tool_use_id, paths, subagent_id, source) per fixture row, written out by hand.
EXPECTED = [
    ("session_start", None, None, (), None, "startup"),
    ("prompt_submit", None, None, (), None, None),
    ("pre_tool", "Read", "toolu_01Ajfwx36fLRkEBrR3KJgGL2", ("/work/proj/notes.md",), None, None),
    ("post_tool", "Read", "toolu_01Ajfwx36fLRkEBrR3KJgGL2", ("/work/proj/notes.md",), None, None),
    ("pre_tool", "Edit", "toolu_01TzEAKCWAsxLzF66Wy1Hbmf", ("/work/proj/notes.md",), None, None),
    ("post_tool", "Edit", "toolu_01TzEAKCWAsxLzF66Wy1Hbmf", ("/work/proj/notes.md",), None, None),
    ("pre_tool", "Write", "toolu_01XoTXN9Jdxsc7itwFNFSSL1", ("/work/proj/new.md",), None, None),
    ("post_tool", "Write", "toolu_01XoTXN9Jdxsc7itwFNFSSL1", ("/work/proj/new.md",), None, None),
    ("pre_tool", "Read", "toolu_01UKMHA2iscQyqzKaCyeBFdN", ("/work/proj/sub/x.txt",), SUB, None),
    ("post_tool", "Read", "toolu_01UKMHA2iscQyqzKaCyeBFdN", ("/work/proj/sub/x.txt",), SUB, None),
    ("stop", None, None, (), None, None),
    ("subagent_stop", None, None, (), SUB, None),
    ("pre_compact", None, None, (), None, "manual"),
    ("post_compact", None, None, (), None, "manual"),
    ("session_end", None, None, (), None, None),
]


def _lines(session: str = SESSION) -> list[JsonObject]:
    return [json.loads(line) for line in store.events_path(session).read_text().splitlines()]


@pytest.mark.parametrize(("row", "expected"), list(zip(ROWS, EXPECTED, strict=True)))
def test_each_row_resolves_correctly(row: str, expected: tuple[object, ...]) -> None:
    record_payload("claude", row)
    (record,), _ = read_events(SESSION, 0)
    kind, tool, use_id, paths, sub, source = expected
    used = record.tool or ToolUse()
    got_paths = (used.path,) if used.path else ()
    assert (record.event, used.name, used.use_id, got_paths, record.subagent_id, record.source) == (
        kind,
        tool,
        use_id,
        paths,
        sub,
        source,
    )
    assert record.agent == "claude"
    assert record.session_id == SESSION
    assert record.cwd == "/work/proj"
    assert record.refusal is None


def test_the_whole_session_reads_back_in_order_and_resumes_from_an_offset() -> None:
    for row in ROWS:
        record_payload("claude", row)
    records, nxt = read_events(SESSION, 0)
    assert [r.event for r in records] == [e[0] for e in EXPECTED]
    size = store.events_path(SESSION).stat().st_size
    assert nxt == size
    thirteenth = sum(len(line) + 1 for line in store.events_path(SESSION).read_bytes().split(b"\n")[:13])
    tail, nxt2 = read_events(SESSION, thirteenth)
    assert [r.event for r in tail] == ["post_compact", "session_end"]
    assert nxt2 == size
    assert read_events(SESSION, size) == ([], size)


def store_record() -> JsonObject:
    return EventRecord(agent="claude", event="stop", session_id=SESSION, time="t").to_json()


def test_a_torn_last_line_is_skipped() -> None:
    for row in ROWS[:3]:
        record_payload("claude", row)
    with store.events_path(SESSION).open("ab") as fh:
        fh.write(json.dumps(store_record()).encode())
    records, nxt = read_events(SESSION, 0)
    assert len(records) == 3
    assert nxt == store.events_path(SESSION).read_bytes().rfind(b"\n") + 1
    with store.events_path(SESSION).open("ab") as fh:
        fh.write(b"\n")
    assert len(read_events(SESSION, nxt)[0]) == 1


def test_no_content_leaks_into_the_log() -> None:
    for row in ROWS:
        record_payload("claude", row)
    stored = store.events_path(SESSION).read_text()
    payloads = [json.loads(r) for r in ROWS]
    secrets = [
        payloads[1]["prompt"],
        "line one",
        "line two",
        "hello",
        "sub file",
        "# probe",
        payloads[13]["compact_summary"],
        payloads[10]["last_assistant_message"] + '"',
    ]
    for secret in secrets:
        assert secret not in stored, secret
    assert "transcript_path" not in stored and "tool_input" not in stored and "tool_response" not in stored


def test_a_non_path_tool_gets_no_path() -> None:
    payload = {
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "tool_name": "NotebookEdit",
        "tool_input": {"file_path": "/x/y.ipynb", "notebook_path": "/x/y.ipynb"},
        "tool_use_id": "toolu_1",
    }
    record_payload("claude", json.dumps(payload))
    (record,), _ = read_events(SESSION, 0)
    assert record.tool == ToolUse("NotebookEdit", "toolu_1", None)


@pytest.mark.parametrize(
    ("agent", "raw", "session", "reason"),
    [
        ("claude", json.dumps({"session_id": "s1", "hook_event_name": "Elicitation"}), "s1", "unknown event"),
        ("claude", json.dumps({"hook_event_name": "Stop"}), "unknown", "no session_id"),
        ("nosuch", ROWS[0], SESSION, "unknown agent: nosuch"),
        ("claude", b"\xff\x00 not json {", "unknown", "not JSON"),
        ("claude", "[1, 2]", "unknown", "unknown event"),
    ],
)
def test_refusals_are_recorded_never_raised(agent: str, raw: bytes | str, session: str, reason: str) -> None:
    record_payload(agent, raw)
    (record,), _ = read_events(session, 0)
    assert record.event == "refusal" and record.agent == agent
    assert record.refusal is not None and reason in record.refusal
    assert record.tool is None


def test_an_unwritable_store_never_raises() -> None:
    folder = get_xray_log_dir()
    folder.parent.mkdir(parents=True, exist_ok=True)
    folder.write_text("a file where the folder should be")
    record_payload("claude", ROWS[0])
    record_payload("claude", b"garbage")
    assert folder.read_text() == "a file where the folder should be"


class _OtherAdapter:
    agent = "other"

    def resolve(self, payload: JsonObject) -> list[EventRecord]:
        return [
            EventRecord(agent="other", event="pre_tool", session_id=str(payload["sid"]), time="t", tool=ToolUse("X"))
        ]


def test_a_second_adapter_needs_no_dispatcher_change(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(port, "ADAPTERS", dict(port.ADAPTERS))
    port.register(_OtherAdapter())
    record_payload("claude", ROWS[0])
    record_payload("other", json.dumps({"sid": SESSION}))
    records, _ = read_events(SESSION, 0)
    assert [(r.agent, r.event) for r in records] == [("claude", "session_start"), ("other", "pre_tool")]
    assert len(_lines()) == 2


@pytest.fixture
def subscribers() -> Iterator[list[port.EventSubscriber]]:
    saved = list(port.SUBSCRIBERS)
    yield port.SUBSCRIBERS
    port.SUBSCRIBERS[:] = saved


@pytest.mark.usefixtures("subscribers")
def test_a_subscriber_receives_the_records_the_store_wrote_in_order() -> None:
    seen: list[EventRecord] = []
    port.subscribe(seen.append)
    for row in ROWS[:4]:
        record_payload("claude", row)
    record_payload("nosuch", ROWS[0])
    stored, _ = read_events(SESSION, 0)
    assert seen[:4] == stored[:4] and len(stored) == 5
    assert seen[4].event == "refusal" and seen == stored


def test_a_raising_subscriber_does_not_stop_the_store_write(subscribers: list[port.EventSubscriber]) -> None:
    def boom(record: EventRecord) -> None:
        raise RuntimeError("subscriber failed")

    seen: list[EventRecord] = []
    subscribers.insert(0, boom)
    port.subscribe(seen.append)
    record_payload("claude", ROWS[1])
    assert [r.event for r in read_events(SESSION, 0)[0]] == ["prompt_submit"]
    assert len(seen) == 1


def test_session_ids_are_reduced_to_a_safe_file_name() -> None:
    path = store.events_path("../../etc/pass wd")
    assert path.parent == get_xray_log_dir()
    assert path.name == "etcpasswd.events.jsonl"


def test_the_folder_is_private_and_the_file_is_0600() -> None:
    record_payload("claude", ROWS[1])
    assert stat.S_IMODE(get_xray_log_dir().stat().st_mode) == 0o700
    assert stat.S_IMODE(store.events_path(SESSION).stat().st_mode) == 0o600


def test_prune_sweeps_both_log_kinds_by_session() -> None:
    folder = get_xray_log_dir()
    folder.mkdir(parents=True, mode=0o700)
    old = {"olds.events.jsonl", "olds.1700000000000.0.jsonl", "olds.1700000000000.1.jsonl"}
    new = {"news.events.jsonl", "news.1700000000000.0.jsonl", "notes.txt"}
    for name in old | new:
        (folder / name).write_text("{}\n")
    stale = time.time() - 40 * 86400
    for name in old:
        os.utime(folder / name, (stale, stale))
    store.prune(None)
    assert sorted(p.name for p in folder.iterdir()) == sorted(new)


def test_a_session_start_prunes_the_old_sessions() -> None:
    folder = get_xray_log_dir()
    folder.mkdir(parents=True, mode=0o700)
    victim = folder / "olds.events.jsonl"
    victim.write_text("{}\n")
    stale = time.time() - 40 * 86400
    os.utime(victim, (stale, stale))
    record_payload("claude", ROWS[0])
    assert not victim.exists()
    assert store.events_path(SESSION).exists()


def test_expected_loads_calls_the_store_prune_and_keeps_no_copy() -> None:
    assert expected_loads.prune is store.prune
    assert not hasattr(expected_loads, "_prune_event_logs")
