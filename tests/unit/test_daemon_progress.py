"""Daemon-path progress channel: the per-harness-element counter must also fire
when the map runs in the background daemon, not only on the in-process fallback.
The daemon streams `{"type":"progress"}` lines ahead of the result line; the
client forwards them to its callback."""

from __future__ import annotations

import json
import threading

import pytest

from reporails_cli.core.mapper import daemon as d
from reporails_cli.core.mapper import daemon_client as dc


class _FakeSock:
    """Feeds pre-canned bytes via recv(); records sends; tracks close()."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, _t: float) -> None:
        pass

    def sendall(self, b: bytes) -> None:
        self.sent.append(b)

    def recv(self, _n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


# --- client: _stream_map_response ---------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_forwards_progress_then_returns_result() -> None:
    stream = (
        json.dumps({"type": "progress", "msg": "Mapping main: 1/1"})
        + "\n"
        + json.dumps({"type": "progress", "msg": "Mapping agents: 1/2"})
        + "\n"
        + json.dumps({"ok": True, "ruleset_map": {"x": 1}})
        + "\n"
    ).encode()
    sock = _FakeSock([stream])
    seen: list[str] = []
    res = dc._stream_map_response(sock, {"cmd": "map_ruleset"}, seen.append, timeout=5.0)
    assert seen == ["Mapping main: 1/1", "Mapping agents: 1/2"]
    assert res == {"ok": True, "ruleset_map": {"x": 1}}
    assert sock.closed


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_reassembles_lines_split_across_recv_chunks() -> None:
    payload = (
        json.dumps({"type": "progress", "msg": "Mapping skills: 3/5"}) + "\n" + json.dumps({"ok": True}) + "\n"
    ).encode()
    sock = _FakeSock([payload[:12], payload[12:40], payload[40:]])
    seen: list[str] = []
    res = dc._stream_map_response(sock, {}, seen.append, timeout=5.0)
    assert seen == ["Mapping skills: 3/5"]
    assert res == {"ok": True}


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_closed_before_result_returns_none() -> None:
    sock = _FakeSock([json.dumps({"type": "progress", "msg": "x"}).encode() + b"\n"])
    seen: list[str] = []
    res = dc._stream_map_response(sock, {}, seen.append, timeout=5.0)
    assert res is None  # stream ended before a result line -> caller falls back
    assert seen == ["x"]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_none_callback_is_safe() -> None:
    payload = (json.dumps({"type": "progress", "msg": "m"}) + "\n" + json.dumps({"ok": True}) + "\n").encode()
    res = dc._stream_map_response(_FakeSock([payload]), {}, None, timeout=5.0)
    assert res == {"ok": True}


# --- daemon: dispatch + connection handler ------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_dispatch_threads_progress_into_map_handler(monkeypatch) -> None:
    seen: list[str] = []

    def fake_handle(_request, _models, progress=None):
        assert progress is not None
        progress("Mapping agents: 1/3")
        return {"ok": True, "ruleset_map": {}}

    monkeypatch.setattr(d, "_handle_map_ruleset", fake_handle)
    ev = threading.Event()
    ev.set()
    res = d._dispatch({"cmd": "map_ruleset"}, models=object(), warmup_done=ev, progress=seen.append)
    assert seen == ["Mapping agents: 1/3"]
    assert res["ok"]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_handle_connection_writes_progress_lines_then_result(monkeypatch) -> None:
    request = json.dumps({"cmd": "map_ruleset", "paths": [], "root": "/x"}).encode() + b"\n"

    class _Conn:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self._chunks = [request]

        def settimeout(self, _t: float) -> None:
            pass

        def recv(self, _n: int) -> bytes:
            return self._chunks.pop(0) if self._chunks else b""

        def sendall(self, b: bytes) -> None:
            self.sent.append(b)

        def close(self) -> None:
            pass

    def fake_dispatch(_request, _models, _warmup_done, progress=None):
        progress("Mapping main: 1/1")
        progress("Mapping agents: 1/1")
        return {"ok": True, "ruleset_map": {}}

    monkeypatch.setattr(d, "_dispatch", fake_dispatch)
    ev = threading.Event()
    ev.set()
    conn = _Conn()
    d._handle_connection(conn, models=object(), warmup_done=ev)

    lines = [json.loads(b.rstrip(b"\n")) for b in conn.sent]
    assert lines[0] == {"type": "progress", "msg": "Mapping main: 1/1"}
    assert lines[1] == {"type": "progress", "msg": "Mapping agents: 1/1"}
    assert lines[2]["ok"] is True  # result line last


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_send_progress_swallows_broken_pipe(monkeypatch) -> None:
    request = json.dumps({"cmd": "map_ruleset", "paths": [], "root": "/x"}).encode() + b"\n"

    class _BrokenConn:
        def __init__(self) -> None:
            self._chunks = [request]
            self.result_sent = False

        def settimeout(self, _t: float) -> None:
            pass

        def recv(self, _n: int) -> bytes:
            return self._chunks.pop(0) if self._chunks else b""

        def sendall(self, b: bytes) -> None:
            if b'"type":"progress"' in b:
                raise BrokenPipeError("client gone")
            self.result_sent = True

        def close(self) -> None:
            pass

    def fake_dispatch(_request, _models, _warmup_done, progress=None):
        progress("Mapping main: 1/1")  # raises inside sendall, must be swallowed
        return {"ok": True, "ruleset_map": {}}

    monkeypatch.setattr(d, "_dispatch", fake_dispatch)
    ev = threading.Event()
    ev.set()
    conn = _BrokenConn()
    d._handle_connection(conn, models=object(), warmup_done=ev)  # must not raise
    assert conn.result_sent  # result line still written after a dropped progress write


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_survives_a_raising_progress_callback() -> None:
    """A caller callback that raises (e.g. a spinner render error) must not abort
    the stream — progress is best-effort, the map result still returns."""
    stream = (
        json.dumps({"type": "progress", "msg": "Mapping main: 1/1"})
        + "\n"
        + json.dumps({"ok": True, "ruleset_map": {"x": 1}})
        + "\n"
    ).encode()

    def boom(_msg: str) -> None:
        raise RuntimeError("spinner blew up")

    sock = _FakeSock([stream])
    out = dc._stream_map_response(sock, {"cmd": "map_ruleset"}, boom, timeout=5.0)
    assert out == {"ok": True, "ruleset_map": {"x": 1}}
    assert sock.closed
