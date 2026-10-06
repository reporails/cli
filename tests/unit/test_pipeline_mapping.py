"""SEAM tests for `core/pipeline/mapping.py` — the shared daemon-resolution + whole-map-cache head.

Pins two behaviours:

  - the whole-map cache lookup must short-circuit BEFORE any daemon resolution
    (a cache hit never touches `ensure_daemon`), and a caller that passes `spawn_daemon=False`
    (the MCP server, which must never fork from inside a multi-threaded asyncio process)
    must never call `ensure_daemon`/`start_daemon` -- it only attaches to an already-running
    daemon or maps in-process.
  - an in-process mapper failure logs its warning through the real logging
    handler chain and returns `None` -- no longer swallowed behind a swapped `sys.stderr`.

No shape-only tests -- every test drives a real branch of `map_instruction_files` /
`_resolve_daemon` / `_map_via_daemon_or_process` / `_map_in_process`.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.pipeline import mapping

pytestmark = [pytest.mark.unit, pytest.mark.subsys_map]


class _FakeFullMapCache:
    """Stand-in for `FullMapCache` -- records calls, returns a canned hit/miss."""

    def __init__(self, cache_dir: Path, *, hit: object = None) -> None:
        self.cache_dir = cache_dir
        self.hit = hit
        self.put_calls: list[tuple[str, object]] = []

    def get(self, key: str) -> object:
        return self.hit

    def put(self, key: str, value: object) -> None:
        self.put_calls.append((key, value))


def _patch_config_and_cache(monkeypatch, *, cache_hit: object = None) -> None:
    cfg = SimpleNamespace(mapper=SimpleNamespace(segmentation="legacy"))
    monkeypatch.setattr("reporails_cli.core.platform.config.config.get_project_config", lambda _t: cfg)
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_cache_dir", lambda: Path("/tmp/fake-cache")
    )
    monkeypatch.setattr(
        "reporails_cli.core.cache.full_map_cache.FullMapCache",
        lambda cache_dir: _FakeFullMapCache(cache_dir, hit=cache_hit),
    )
    monkeypatch.setattr("reporails_cli.core.cache.full_map_cache.compute_identity", lambda *_a, **_k: "IDENTITY")


def _boom(*_a: object, **_k: object) -> None:
    raise AssertionError("this daemon-spawning entrypoint must not be called on this path")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cache_hit_short_circuits_before_daemon_resolution(monkeypatch):
    """A whole-map cache hit returns straight off disk -- `ensure_daemon` is never called."""
    _patch_config_and_cache(monkeypatch, cache_hit="CACHED_MAP")
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ensure_daemon", _boom)

    result = mapping.map_instruction_files(Path("/proj"), [Path("/proj/CLAUDE.md")])

    assert result == "CACHED_MAP"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_mcp_path_never_spawns_a_daemon_when_none_is_running(monkeypatch):
    """`spawn_daemon=False` with no daemon running maps in-process, never calling
    `ensure_daemon`/`start_daemon` (the MCP server must not fork from its own process)."""
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: False)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ensure_daemon", _boom)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.start_daemon", _boom)
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping._map_in_process", lambda *_a, **_k: "IN_PROCESS_MAP")

    result = mapping.map_instruction_files(Path("/proj"), [Path("/proj/CLAUDE.md")], spawn_daemon=False)

    assert result == "IN_PROCESS_MAP"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_mcp_path_attaches_to_an_already_running_daemon(monkeypatch):
    """`spawn_daemon=False` with a live daemon attaches and maps via it -- no spawn call."""
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    from reporails_cli.core.mapper.daemon import code_identity

    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ping", lambda: {"ok": True, "code": code_identity()})
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ensure_daemon", _boom)
    monkeypatch.setattr(
        "reporails_cli.core.mapper.daemon_client.map_ruleset_via_daemon", lambda *_a, **_k: "DAEMON_MAP"
    )

    result = mapping.map_instruction_files(Path("/proj"), [Path("/proj/CLAUDE.md")], spawn_daemon=False)

    assert result == "DAEMON_MAP"


# A daemon left by an older version: one from before the reply carried its code, or a lower version.
_OLDER = [{"ok": True, "pid": 1, "warm": True}, {"ok": True, "pid": 7, "code": "0.0.1+map1"}]
_NEWER = {"ok": True, "code": "999.0.0+map999"}


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(("pong", "stopped"), [*((p, True) for p in _OLDER), (_NEWER, False)])
def test_mcp_path_maps_in_process_beside_a_daemon_running_other_code(monkeypatch, pong, stopped):
    """A daemon running other code maps with its own mapper, so its map is not this version's:
    map in-process instead. One left over from an older version is stopped so it does not
    linger; a newer version's is left to that version."""
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    stops: list[object] = []
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.retire_daemon", lambda pid: bool(stops.append(pid)))
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ping", lambda: pong)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.map_ruleset_via_daemon", _boom)
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping._map_in_process", lambda *_a, **_k: "IN_PROCESS_MAP")

    result = mapping.map_instruction_files(Path("/proj"), [Path("/proj/CLAUDE.md")], spawn_daemon=False)

    assert result == "IN_PROCESS_MAP"
    assert stops == ([pong.get("pid")] if stopped else [])


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("pong", _OLDER)
def test_cli_path_replaces_a_daemon_left_by_an_older_version(monkeypatch, pong):
    """After an upgrade the old daemon still holds the socket; the check stops it and starts
    this version's instead of mapping cold on every run while the old one stays up."""
    from reporails_cli.core.mapper import daemon_client
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    running = [True]
    calls: list[str] = []
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: running[-1])

    def _retire(pid: object) -> bool:
        calls.append(f"retire {pid}")
        running.append(False)
        return True

    def _start() -> int:
        calls.append("start")
        running.append(True)
        return 2

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.retire_daemon", _retire)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.start_daemon", _start)
    pongs = iter([pong])
    monkeypatch.setattr(daemon_client, "ping", lambda: next(pongs, {"ok": True}))

    assert daemon_client.ensure_daemon() == DaemonStatus.STARTED
    assert calls == [f"retire {pong.get('pid')}", "start"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cli_path_leaves_an_older_daemon_that_does_not_exit(monkeypatch):
    """A leftover daemon too busy to take the shutdown keeps running; the check maps in-process
    rather than starting a second daemon beside it."""
    from reporails_cli.core.mapper import daemon_client
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.retire_daemon", lambda _pid: False)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.daemon_pid", lambda: _OLDER[0]["pid"])
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.start_daemon", _boom)
    monkeypatch.setattr(daemon_client, "ping", lambda: _OLDER[0])

    assert daemon_client.ensure_daemon() == DaemonStatus.UNAVAILABLE


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cli_path_attaches_when_a_check_beside_it_already_replaced_the_older_daemon(monkeypatch):
    """Two checks right after an upgrade: the other one retired the old daemon and started this
    version's, so this one attaches to it instead of mapping cold."""
    from reporails_cli.core.mapper import daemon_client
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.retire_daemon", lambda _pid: False)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.daemon_pid", lambda: 999)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.start_daemon", lambda: 999)
    pongs = iter([_OLDER[0]])
    monkeypatch.setattr(daemon_client, "ping", lambda: next(pongs, {"ok": True}))

    assert daemon_client.ensure_daemon() == DaemonStatus.STARTED


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cli_path_leaves_a_newer_version_s_daemon_to_that_version(monkeypatch):
    from reporails_cli.core.mapper import daemon_client
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.retire_daemon", _boom)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.start_daemon", _boom)
    monkeypatch.setattr(daemon_client, "ping", lambda: _NEWER)

    assert daemon_client.ensure_daemon() == DaemonStatus.UNAVAILABLE


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cli_path_queues_on_a_daemon_too_busy_to_answer_the_ping(monkeypatch):
    """A daemon mapping a large project serves one connection at a time and misses the ping;
    the check waits for it rather than loading a second copy of the models."""
    from reporails_cli.core.mapper import daemon_client
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.start_daemon", _boom)
    monkeypatch.setattr(daemon_client, "ping", lambda: None)

    assert daemon_client.ensure_daemon() == DaemonStatus.ATTACHED


class _MapReplySocket:
    """A daemon socket that answers a map request with one result line."""

    def __init__(self, reply: dict) -> None:
        self._out = [json.dumps(reply).encode() + b"\n"]

    def settimeout(self, _t: float) -> None:
        pass

    def sendall(self, _b: bytes) -> None:
        pass

    def recv(self, _n: int) -> bytes:
        return self._out.pop(0) if self._out else b""

    def close(self) -> None:
        pass


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("code", [None, "0.0.1+map1"])
def test_a_map_from_a_daemon_running_other_code_is_refused(monkeypatch, code):
    """Attached while busy, a daemon left by another version still maps with its own code: its
    map is refused, and the caller maps in-process."""
    from reporails_cli.core.mapper import daemon_client

    reply = {"ok": True, "ruleset_map": {}} | ({"code": code} if code else {})
    monkeypatch.setattr(daemon_client, "connect", lambda: _MapReplySocket(reply))

    assert daemon_client.map_ruleset_via_daemon([Path("/proj/CLAUDE.md")], Path("/proj")) is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_daemon_ping_reports_the_code_it_maps_with() -> None:
    import threading

    from reporails_cli.core.mapper.daemon import _dispatch, code_identity

    pong = _dispatch({"cmd": "ping"}, None, threading.Event())
    assert pong["code"] == code_identity()
    assert code_identity().endswith(
        f"+map{__import__('reporails_cli.core.cache.map_cache', fromlist=['x'])._CACHE_VERSION}"
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_daemon_round_trip_failure_falls_back_to_in_process(monkeypatch):
    """A daemon that attaches but fails the round-trip (returns None) falls back in-process."""
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ensure_daemon", lambda **_k: DaemonStatus.ATTACHED)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.map_ruleset_via_daemon", lambda *_a, **_k: None)
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping._map_in_process", lambda *_a, **_k: "FALLBACK_MAP")

    result = mapping.map_instruction_files(Path("/proj"), [Path("/proj/CLAUDE.md")])

    assert result == "FALLBACK_MAP"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_daemon_starting_routes_to_daemon(monkeypatch):
    """A freshly-spawned daemon still warming (STARTING) is routed to, NOT mapped in-process:
    the daemon-side handler blocks on `warmup_done` then serves, so the models load once (in the
    daemon) instead of a redundant in-process load. Regression guard for the cold-path double-load."""
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ensure_daemon", lambda **_k: DaemonStatus.STARTING)
    monkeypatch.setattr(
        "reporails_cli.core.mapper.daemon_client.map_ruleset_via_daemon", lambda *_a, **_k: "DAEMON_MAP"
    )
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping._map_in_process", _boom)

    result = mapping.map_instruction_files(Path("/proj"), [Path("/proj/CLAUDE.md")])

    assert result == "DAEMON_MAP"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("status_name", ["UNAVAILABLE"])
def test_daemon_unavailable_maps_in_process(monkeypatch, status_name):
    """An absent daemon (UNAVAILABLE) maps in-process directly, without a round-trip against a
    non-attached daemon. (STARTING now routes to the daemon — see test_daemon_starting_routes_to_daemon.)"""
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    from reporails_cli.core.mapper.daemon_client import DaemonStatus

    status = getattr(DaemonStatus, status_name)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ensure_daemon", lambda **_k: status)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.map_ruleset_via_daemon", _boom)
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping._map_in_process", lambda *_a, **_k: "IN_PROCESS_MAP")

    result = mapping.map_instruction_files(Path("/proj"), [Path("/proj/CLAUDE.md")])

    assert result == "IN_PROCESS_MAP"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_in_process_mapper_raises_returns_none_and_warns(monkeypatch, caplog):
    """An in-process mapper failure (ImportError/RuntimeError) returns `None` and the warning
    reaches the real logging handler chain -- not swallowed behind a stderr swap."""
    import reporails_cli.core.mapper as mapper_pkg

    monkeypatch.setattr(mapper_pkg, "map_ruleset", _boom_runtime, raising=False)
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_cache_dir", lambda: Path("/tmp/fake-cache")
    )

    with caplog.at_level(logging.WARNING, logger="reporails_cli.core.pipeline.mapping"):
        result = mapping._map_in_process([Path("/proj/CLAUDE.md")], Path("/proj"), "legacy")

    assert result is None
    assert any("In-process mapper unavailable" in r.message for r in caplog.records)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_in_process_mapper_warning_never_repeats_exception_text(monkeypatch, caplog):
    """The WARNING-level line never repeats the raised exception's own text: the mapper's
    unavailability messages can name a maintainer-only script that does not ship in the
    wheel/sdist; the full exception still reaches DEBUG for a `-v`/log diagnosis."""
    import reporails_cli.core.mapper as mapper_pkg

    def _boom_leaky(*_a: object, **_k: object) -> None:
        raise RuntimeError("Run `uv run python scripts/fetch_bundled_model.py` to populate it.")

    monkeypatch.setattr(mapper_pkg, "map_ruleset", _boom_leaky, raising=False)
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_cache_dir", lambda: Path("/tmp/fake-cache")
    )

    with caplog.at_level(logging.DEBUG, logger="reporails_cli.core.pipeline.mapping"):
        result = mapping._map_in_process([Path("/proj/CLAUDE.md")], Path("/proj"), "legacy")

    assert result is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert warnings and all("fetch_bundled_model.py" not in r.message for r in warnings)
    assert any("fetch_bundled_model.py" in r.message for r in debugs)


def _boom_runtime(*_a: object, **_k: object) -> None:
    raise RuntimeError("boom")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_in_process_mapper_restores_logger_levels_after_success(monkeypatch):
    """A successful in-process map restores the quieted loggers' original levels afterward."""
    quieted_logger = logging.getLogger("sentence_transformers")
    quieted_logger.setLevel(logging.DEBUG)

    import reporails_cli.core.mapper as mapper_pkg

    monkeypatch.setattr(mapper_pkg, "map_ruleset", lambda *_a, **_k: "MAP", raising=False)
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_cache_dir", lambda: Path("/tmp/fake-cache")
    )

    result = mapping._map_in_process([Path("/proj/CLAUDE.md")], Path("/proj"), "legacy")

    assert result == "MAP"
    assert quieted_logger.level == logging.DEBUG


def _capture_in_process_map(monkeypatch, sink: dict) -> None:
    """Stand in for the real in-process `map_ruleset`, recording the kwargs it was handed."""
    import reporails_cli.core.mapper as mapper_pkg

    def _capture(paths: list[Path], **kwargs: object) -> str:
        sink["paths"] = list(paths)
        sink.update(kwargs)
        return "IN_PROCESS_MAP"

    monkeypatch.setattr(mapper_pkg, "map_ruleset", _capture, raising=False)
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_cache_dir", lambda: Path("/tmp/fake-cache")
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_in_process_fallback_maps_against_the_project_root(monkeypatch):
    """The in-process fallback must map against the PROJECT root, not `paths[0].parent`.

    `_detect_file_loading` derives every FileRecord's `loading` / `scope` / `globs` / `agent`
    from `path.relative_to(root)`. Drop `root` and `map_ruleset` defaults it to the first
    file's own parent, so a nested agent surface (`.cursor/rules/*.mdc`) no longer matches
    any registry pattern and degrades to `generic / session_start / global` -- on every MCP
    `validate` without a warm daemon and on every Windows run.
    """
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: False)
    seen: dict = {}
    _capture_in_process_map(monkeypatch, seen)

    target = Path("/proj")
    result = mapping.map_instruction_files(target, [target / ".cursor/rules/style.mdc"], spawn_daemon=False)

    assert result == "IN_PROCESS_MAP"
    assert seen["root"] == target


@pytest.mark.unit
@pytest.mark.subsys_map
def test_daemon_and_in_process_arms_receive_the_same_root(monkeypatch):
    """Both mapping entry points are handed the same project root for the same call.

    The daemon arm sends `root` on the wire (`map_ruleset_via_daemon(paths, root)`); the
    in-process arm must pass the identical value as `map_ruleset(root=...)`. Any divergence
    means the two surfaces classify the same project differently.
    """
    target = Path("/proj")
    files = [target / ".cursor/rules/style.mdc", target / "CLAUDE.md"]

    _patch_config_and_cache(monkeypatch, cache_hit=None)
    daemon_roots: list[Path] = []

    def _via_daemon(paths: list[Path], root: Path, progress=None) -> str:
        daemon_roots.append(root)
        return "DAEMON_MAP"

    from reporails_cli.core.mapper.daemon import code_identity

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ping", lambda: {"ok": True, "code": code_identity()})
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.map_ruleset_via_daemon", _via_daemon)
    assert mapping.map_instruction_files(target, files, spawn_daemon=False) == "DAEMON_MAP"

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: False)
    seen: dict = {}
    _capture_in_process_map(monkeypatch, seen)
    assert mapping.map_instruction_files(target, files, spawn_daemon=False) == "IN_PROCESS_MAP"

    assert daemon_roots == [target]
    assert seen["root"] == daemon_roots[0]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_retire_daemon_leaves_a_daemon_started_since_the_ping(monkeypatch, tmp_path):
    """The daemon that answered the ping has been replaced already: the one now holding the
    daemon files is not the one to stop."""
    from reporails_cli.core.mapper import daemon

    monkeypatch.setattr(daemon.sys, "platform", "linux")
    (tmp_path / "mapper.pid").write_text("200")
    monkeypatch.setattr(daemon, "_pid_path", lambda: tmp_path / "mapper.pid")
    monkeypatch.setattr(daemon.socket, "socket", _boom)

    assert daemon.retire_daemon(100) is False


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(sys.platform == "win32", reason="the mapper daemon socket is POSIX-only")
def test_retire_daemon_waits_for_the_answering_daemon_to_exit(monkeypatch, tmp_path):
    from reporails_cli.core.mapper import daemon

    sent: list[bytes] = []

    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def settimeout(self, _t):
            pass

        def connect(self, _p):
            pass

        def sendall(self, b):
            sent.append(b)

        def recv(self, _n):
            return b'{"ok": true}\n'

    alive = iter([None, None])

    def _kill(pid, sig):
        assert (pid, sig) == (100, 0)
        if next(alive, "gone") == "gone":
            raise ProcessLookupError

    monkeypatch.setattr(daemon.sys, "platform", "linux")
    (tmp_path / "mapper.pid").write_text("100")
    monkeypatch.setattr(daemon, "_pid_path", lambda: tmp_path / "mapper.pid")
    monkeypatch.setattr(daemon, "_socket_path", lambda: tmp_path / "mapper.sock")
    monkeypatch.setattr(daemon.socket, "socket", lambda *_a: _Sock())
    monkeypatch.setattr(daemon.os, "kill", _kill)
    monkeypatch.setattr(daemon.time, "sleep", lambda _s: None)

    assert daemon.retire_daemon(100) is True
    assert sent == [b'{"cmd": "shutdown"}\n']


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("pong", "retired", "says", "started"),
    [
        (None, False, "Daemon already running.", False),  # busy with a map
        (_OLDER[1], True, "Stopped the daemon left by an older version", True),
        (_NEWER, False, "A newer version's daemon is running", False),
    ],
)
def test_daemon_start_reports_whose_daemon_holds_the_socket(monkeypatch, pong, retired, says, started):
    """`ails daemon start` calls a daemon "already running" only when it runs this version's code."""
    from typer.testing import CliRunner

    from reporails_cli.interfaces.cli.daemon_cmd import daemon_app

    running = [True]
    starts: list[bool] = []
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: running[-1])
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ping", lambda: pong)
    monkeypatch.setattr(
        "reporails_cli.core.mapper.daemon.retire_daemon", lambda _pid: bool(running.append(False)) or retired
    )

    def _start() -> int:
        starts.append(True)
        running.append(True)
        return 3

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.start_daemon", _start)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert says in result.output
    assert bool(starts) is started


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("pong", "says"),
    [
        (_OLDER[0], "left by an older version of ails; the next check replaces it"),
        (_OLDER[1], "version 0.0.1, left by an older version of ails; the next check replaces it"),
        (_NEWER, "version 999.0.0, a newer version's daemon; this version checks without it"),
        (
            {"ok": True, "pid": 9, "code": "unknown+map5"},
            "an unrecognized version's daemon; this version checks without it",
        ),
    ],
)
def test_daemon_status_says_whose_daemon_is_running(monkeypatch, pong, says):
    """`ails daemon status` names the daemon's version and whether this version uses it."""
    from typer.testing import CliRunner

    from reporails_cli.interfaces.cli.daemon_cmd import daemon_app

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon_client.ping", lambda: pong)

    result = CliRunner().invoke(daemon_app, ["status"])

    assert says in " ".join(result.output.split())


# ── stamp_file_agents: attribute a cross-read file to its owner ──


def _ruleset_map_with_agent(path: str, agent: str) -> object:
    from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap

    return RulesetMap(
        schema_version="1",
        embedding_model="m",
        generated_at="now",
        files=(FileRecord(path=path, content_hash="sha256:a", agent=agent, type="main"),),
        atoms=(),
    )


def _detected(agent_id: str, instruction_files: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        agent_type=SimpleNamespace(id=agent_id),
        instruction_files=[Path(p) for p in instruction_files],
        rule_files=[],
        config_files=[],
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_stamp_file_agents_corrects_shared_marker_misattribution():
    """A shared marker (`AGENTS.md`) the mapper's own registry match ties-broke to the wrong
    agent (Antigravity, by registry declaration order) is corrected to discovery's real,
    resolved owner (Codex): a cross-read file is attributed to the agent that owns it."""
    ruleset_map = _ruleset_map_with_agent("/proj/AGENTS.md", "antigravity")
    codex = _detected("codex", ["/proj/AGENTS.md"])

    mapping.stamp_file_agents(ruleset_map, [codex], Path("/proj"))

    assert ruleset_map.files[0].agent == "codex"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_stamp_file_agents_noop_without_filtered_agents():
    """No `filtered_agents` -- nothing to stamp from -- leaves every record untouched."""
    ruleset_map = _ruleset_map_with_agent("/proj/AGENTS.md", "antigravity")

    mapping.stamp_file_agents(ruleset_map, None, Path("/proj"))

    assert ruleset_map.files[0].agent == "antigravity"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_stamp_file_agents_leaves_unclaimed_records_alone():
    """A record whose path no `filtered_agents` entry claims is left as the mapper found it --
    the stamp only ever narrows attribution to a file discovery actually assigned."""
    ruleset_map = _ruleset_map_with_agent("/proj/other.md", "antigravity")
    codex = _detected("codex", ["/proj/AGENTS.md"])

    mapping.stamp_file_agents(ruleset_map, [codex], Path("/proj"))

    assert ruleset_map.files[0].agent == "antigravity"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_resolve_agent_filters_keeps_generic_scope_when_nothing_distinctive_detected():
    """Regression: a plain project with no agent-specific marker at all
    (a root `AGENTS.md` and nothing else -- `detect_agents` returns only the `generic`
    entry) must still discover its own instruction files. The auto-detect branch's
    `[a for a in all_detected if a.agent_type.id != "generic"]` line drops `generic`
    unconditionally, so when `generic` is the ONLY detected entry, `filtered` came back
    empty and `get_all_instruction_files(target, agents=filtered)` found nothing --
    the whole-project scan silently scored zero files instead of running core rules on
    the one file it has: this must fall back to the detected set, not to an empty
    scope."""
    generic = _detected("generic", ["/proj/AGENTS.md"])

    effective, _assumed, mixed, filtered = mapping.resolve_agent_filters("", [generic], Path("/proj"), None, None)

    assert [d.agent_type.id for d in filtered] == ["generic"]
    assert effective == "generic"
    assert not mixed


@pytest.mark.unit
@pytest.mark.subsys_map
def test_resolve_agent_filters_keeps_generics_own_files_beside_a_named_agent():
    """A project with its own `CLAUDE.md` alongside a root `AGENTS.md` keeps `generic` in the
    discovery scope: `AGENTS.md` is the shared standard's own file, and no other detected agent
    need read it for it to be checked (it runs the core rule set)."""
    claude = _detected("claude", ["/proj/CLAUDE.md"])
    generic = _detected("generic", ["/proj/AGENTS.md"])

    _, _, _, filtered = mapping.resolve_agent_filters("", [claude, generic], Path("/proj"), None, None)

    assert [d.agent_type.id for d in filtered] == ["claude", "generic"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_daemon_status_of_this_version_s_daemon(monkeypatch):
    from typer.testing import CliRunner

    from reporails_cli.core.mapper.daemon import code_identity
    from reporails_cli.interfaces.cli.daemon_cmd import daemon_app

    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: True)
    monkeypatch.setattr(
        "reporails_cli.core.mapper.daemon_client.ping", lambda: {"ok": True, "pid": 5, "code": code_identity()}
    )

    result = CliRunner().invoke(daemon_app, ["status"])

    version = code_identity().rpartition("+map")[0]
    assert f"running (PID 5, version {version})" in " ".join(result.output.split())
    assert "older" not in result.output and "newer" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_daemon_status_help_carries_no_undocumented_path_argument() -> None:
    """`ails daemon status --help` used to show a bare `[PATH]` in its Usage line — the
    deprecated, always-ignored positional carried over from the old per-project daemon —
    with no Arguments section explaining it. The daemon is global now; the dead argument
    is gone, not just hidden."""
    from typer.testing import CliRunner

    from reporails_cli.interfaces.cli.daemon_cmd import daemon_app

    result = CliRunner().invoke(daemon_app, ["status", "--help"])

    assert result.exit_code == 0
    assert "[PATH]" not in result.output
    assert "[OPTIONS]" in result.output


@pytest.mark.unit
@pytest.mark.subsys_map
def test_the_cache_holds_the_map_as_mapped_before_membership_is_applied(monkeypatch, tmp_path):
    """The whole-map cache is written before skill membership is recorded, so a later run with
    other agents decides again from the map as mapped."""
    from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap

    rec = FileRecord(path=(tmp_path / ".claude/skills/group/x/SKILL.md").as_posix(), content_hash="h", type="skills")
    rmap = RulesetMap(schema_version="1", embedding_model="", generated_at="t", files=(rec,), atoms=())
    _patch_config_and_cache(monkeypatch, cache_hit=None)
    seen: list[tuple[str, str]] = []
    fake = _FakeFullMapCache(Path("/x"))
    fake.put = lambda _k, value: seen.append((value.files[0].type, value.files[0].skill))  # type: ignore[method-assign]
    monkeypatch.setattr("reporails_cli.core.cache.full_map_cache.FullMapCache", lambda _d: fake)
    monkeypatch.setattr("reporails_cli.core.mapper.daemon.is_daemon_running", lambda: False)
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping._map_in_process", lambda *_a, **_k: rmap)

    result = mapping.map_instruction_files(tmp_path, [Path(rec.path)], spawn_daemon=False)

    assert seen == [("skills", "")]  # cached as mapped
    assert (result.files[0].type, result.files[0].skill) == ("generic", "")  # then decided for this run
