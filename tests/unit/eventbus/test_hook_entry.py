"""The `ails hook` entry starts light and records without a network."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from reporails_cli.core.eventbus import store
from reporails_cli.core.eventbus.dispatcher import record_payload
from reporails_cli.core.eventbus.query import read_events

pytestmark = [pytest.mark.unit, pytest.mark.subsys_eventbus]

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "claude_payloads.jsonl"
ROWS = FIXTURE.read_text().splitlines()
SESSION = json.loads(ROWS[0])["session_id"]
HEAVY = (
    "typer",
    "click",
    "onnxruntime",
    "numpy",
    "torch",
    "tokenizers",
    "pydantic",
    "reporails_cli.core.mapper",
)

TRACER = """
import io, json, sys
from reporails_cli.interfaces.cli import entry
sys.argv = ["ails", "hook", "--agent", "claude"]
sys.stdin = io.TextIOWrapper(io.BytesIO({payload!r}))
try:
    entry.run()
except SystemExit as exit_:
    code = exit_.code
print(json.dumps({{"code": code, "modules": sorted(sys.modules)}}))
"""


def test_the_hook_path_loads_none_of_the_heavy_modules(tmp_path: Path) -> None:
    # A tool event is the per-call path.
    script = TRACER.format(payload=ROWS[2].encode())
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": ""},
        check=False,
    )
    assert done.returncode == 0, done.stderr
    out = json.loads(done.stdout.splitlines()[-1])
    assert out["code"] == 0
    loaded = set(out["modules"])
    present = [m for m in HEAVY if m in loaded or any(name.startswith(m + ".") for name in loaded)]
    assert present == [], present


def test_recording_and_reading_need_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("network blocked")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    record_payload("claude", ROWS[0])
    records, nxt = read_events(SESSION, 0)
    assert [r.event for r in records] == ["session_start"] and nxt == store.events_path(SESSION).stat().st_size


def test_stage_timing_names_each_recorded_event_on_stderr_and_stdout_stays_empty(tmp_path: Path) -> None:
    ails = Path(sys.executable).with_name("ails")
    done = subprocess.run(
        [str(ails), "hook", "--agent", "claude"],
        input=ROWS[2].encode(),
        capture_output=True,
        timeout=60,
        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "AILS_STAGE_TIMING": "1"},
        check=False,
    )
    assert done.returncode == 0 and done.stdout == b""
    err = done.stderr.decode()
    assert "event pre_tool" in err and "hook claude" in err
    quiet = subprocess.run(
        [str(ails), "hook", "--agent", "claude"],
        input=ROWS[2].encode(),
        capture_output=True,
        timeout=60,
        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)},
        check=False,
    )
    assert quiet.returncode == 0 and quiet.stdout == b"" and quiet.stderr == b""


def test_a_bare_hook_on_a_terminal_prints_usage_and_exits_0_without_reading(tmp_path: Path) -> None:
    ails = Path(sys.executable).with_name("ails")
    pty = pytest.importorskip("pty")
    import select

    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": os.environ.get("PATH", "")}
    pid, fd = pty.fork()
    if pid == 0:  # child: stdin, stdout and stderr are the terminal
        os.execve(str(ails), [str(ails), "hook"], env)
    out = b""
    deadline = time.monotonic() + 5
    status = None
    while time.monotonic() < deadline and status is None:
        if select.select([fd], [], [], 0.1)[0]:
            with contextlib.suppress(OSError):
                out += os.read(fd, 4096)
        done, raw = os.waitpid(pid, os.WNOHANG)
        if done:
            status = raw
    if status is None:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    os.close(fd)
    assert status is not None, "ails hook blocked on a terminal"
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert "usage: ails hook [--agent NAME] < payload.json" in out.decode(errors="replace")


def test_a_malformed_remote_settings_cache_leaves_the_hook_stderr_empty(tmp_path: Path) -> None:
    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    (claude_home / "remote-settings.json").write_text("{ not json", encoding="utf-8")
    ails = Path(sys.executable).with_name("ails")
    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    done = subprocess.run(
        [str(ails), "hook", "--agent", "claude"],
        input=ROWS[0].encode(),
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert done.returncode == 0 and done.stdout == b"" and done.stderr == b"", done.stderr


@pytest.mark.parametrize("row", [0, 2], ids=["session_start", "tool_event"])
def test_the_hook_path_does_not_import_the_xray_records_chain(tmp_path: Path, row: int) -> None:
    script = TRACER.format(payload=ROWS[row].encode())
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": ""},
        check=False,
    )
    assert done.returncode == 0, done.stderr
    loaded = set(json.loads(done.stdout.splitlines()[-1])["modules"])
    chain = {m for m in loaded if m.startswith("reporails_cli.core.platform.dto.xray_")}
    assert chain == set(), chain
