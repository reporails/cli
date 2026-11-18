"""Daemon-path progress channel: the per-harness-element counter must also fire
when the map runs in the background daemon, not only on the in-process fallback.
The daemon streams `{"type":"progress"}` lines ahead of the result line; the
client forwards them to its callback."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from reporails_cli.core.mapper import daemon_client as dc
from reporails_cli.core.mapper import daemon_server as d
from reporails_cli.core.platform.adapters import daemon_socket as ds
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from tests.fake_daemon import FakeDaemonTransport


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


# --- adapter: reading the streamed frames ---------------------------------------------


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
    res = ds._read_reply(sock, lambda frame: seen.append(str(frame["msg"])))
    assert seen == ["Mapping main: 1/1", "Mapping agents: 1/2"]
    assert res == {"ok": True, "ruleset_map": {"x": 1}}


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_reassembles_lines_split_across_recv_chunks() -> None:
    payload = (
        json.dumps({"type": "progress", "msg": "Mapping skills: 3/5"}) + "\n" + json.dumps({"ok": True}) + "\n"
    ).encode()
    sock = _FakeSock([payload[:12], payload[12:40], payload[40:]])
    seen: list[str] = []
    res = ds._read_reply(sock, lambda frame: seen.append(str(frame["msg"])))
    assert seen == ["Mapping skills: 3/5"]
    assert res == {"ok": True}


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_closed_before_result_is_unavailable() -> None:
    sock = _FakeSock([json.dumps({"type": "progress", "msg": "x"}).encode() + b"\n"])
    seen: list[str] = []
    with pytest.raises(PlatformUnavailableError):  # stream ended before a result line -> caller falls back
        ds._read_reply(sock, lambda frame: seen.append(str(frame["msg"])))
    assert seen == ["x"]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_stream_none_callback_is_safe() -> None:
    payload = (json.dumps({"type": "progress", "msg": "m"}) + "\n" + json.dumps({"ok": True}) + "\n").encode()
    res = ds._read_reply(_FakeSock([payload]), None)
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
def test_handle_connection_writes_progress_lines_then_result() -> None:
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

    def handle(_request, send):
        send({"type": "progress", "msg": "Mapping main: 1/1"})
        send({"type": "progress", "msg": "Mapping agents: 1/1"})
        return {"ok": True, "ruleset_map": {}}

    conn = _Conn()
    ds._answer(conn, handle)

    lines = [json.loads(b.rstrip(b"\n")) for b in conn.sent]
    assert lines[0] == {"type": "progress", "msg": "Mapping main: 1/1"}
    assert lines[1] == {"type": "progress", "msg": "Mapping agents: 1/1"}
    assert lines[2]["ok"] is True  # result line last


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_send_progress_swallows_broken_pipe() -> None:
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

    def handle(_request, send):
        send({"type": "progress", "msg": "Mapping main: 1/1"})  # raises inside sendall, must be swallowed
        return {"ok": True, "ruleset_map": {}}

    conn = _BrokenConn()
    ds._answer(conn, handle)  # must not raise
    assert conn.result_sent  # result line still written after a dropped progress write


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_map_via_daemon_survives_a_raising_progress_callback() -> None:
    """A caller callback that raises (e.g. a spinner render error) must not abort
    the stream — progress is best-effort, the map result still returns."""
    from reporails_cli.core.mapper.daemon import code_identity

    def boom(_msg: str) -> None:
        raise RuntimeError("spinner blew up")

    def answer(_request, on_message):
        on_message({"type": "progress", "msg": "Mapping main: 1/1"})
        return {"ok": True, "code": code_identity()}  # no map: the client answers None after the stream

    transport = FakeDaemonTransport(answer=answer)
    assert dc.map_ruleset_via_daemon(transport, [], Path("/x"), "legacy", progress=boom) is None
    assert len(transport.exchanges) == 1  # the callback raised mid-stream and the reply was still read


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_map_handler_maps_with_the_requested_segmentation(monkeypatch, tmp_path) -> None:
    """The daemon maps with the segmentation the request carries, never one it reads from a config itself."""
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.yml").write_text("mapper:\n  segmentation: legacy\n", encoding="utf-8")
    seen: dict[str, object] = {}

    def fake_map(_paths, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop")

    monkeypatch.setattr(d, "map_ruleset", fake_map)
    res = d._handle_map_ruleset(
        {"cmd": "map_ruleset", "paths": [], "root": str(tmp_path), "segmentation": "structure-aware"}, object()
    )
    assert seen["segmentation"] == "structure-aware"
    assert res["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_runtime
@pytest.mark.skipif(sys.platform == "win32", reason="the daemon socket needs Unix domain sockets")
def test_exchange_streams_progress_then_reply_over_a_real_socket() -> None:
    """The client's frames and the server's framing meet on one real Unix socket: a progress frame reaches the
    callback and the reply is returned; an address nobody listens on raises `PlatformUnavailableError`."""
    import socket as _socket

    address = Path(tempfile.mkdtemp(prefix="ails-")) / "d.sock"
    server = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    server.bind(str(address))
    server.listen(1)
    seen_requests: list[dict] = []

    def handle(request, send):
        seen_requests.append(request)
        send({"type": "progress", "msg": "Mapping main: 1/1"})
        return {"ok": True, "echo": request["cmd"]}

    def serve_one() -> None:
        conn, _ = server.accept()
        try:
            ds._answer(conn, handle)
        finally:
            conn.close()

    thread = threading.Thread(target=serve_one)
    thread.start()
    seen: list[str] = []
    reply = ds.UnixDaemonSocket().exchange(
        address, {"cmd": "map_ruleset"}, timeout=5.0, on_message=lambda f: seen.append(str(f["msg"]))
    )
    thread.join(5)
    server.close()

    assert reply == {"ok": True, "echo": "map_ruleset"}
    assert seen == ["Mapping main: 1/1"]
    assert seen_requests == [{"cmd": "map_ruleset"}]
    with pytest.raises(PlatformUnavailableError):
        ds.UnixDaemonSocket().exchange(address, {"cmd": "ping"}, timeout=1.0, on_message=None)
