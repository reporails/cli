"""Mapper daemon serving loop: keeps the models loaded and answers map requests.

Serves map requests over the Unix domain socket named by `daemon.socket_path`. The embedding
model stays in memory between invocations, eliminating the 5-10s model load time on
subsequent runs. One daemon serves all projects on the machine.
Protocol: JSON-line over Unix domain socket (one JSON object per line).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reporails_cli.core.mapper.daemon import code_identity, pid_path, socket_path
from reporails_cli.core.mapper.models import get_models
from reporails_cli.core.mapper.pipeline import map_ruleset
from reporails_cli.core.mapper.serialize import save_ruleset_map
from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir, parse_idle_timeout_env
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.runtime import _torch_blocker

logger = logging.getLogger(__name__)

# Idle shutdown is on by default (30 min) so resident embedding models don't
# pin memory indefinitely on an idle machine. Override the window via the
# AILS_DAEMON_IDLE_S env var (seconds) — set low for CI (e.g. 5), set 0 to
# disable idle shutdown entirely (daemon runs until `ails daemon stop`/kill).
_DEFAULT_IDLE_TIMEOUT_S = 1800


def _parse_idle_timeout() -> int | None:
    return parse_idle_timeout_env("AILS_DAEMON_IDLE_S", _DEFAULT_IDLE_TIMEOUT_S)


_IDLE_TIMEOUT_S: int | None = _parse_idle_timeout()
_SOCKET_BACKLOG = 2
_MAX_REQUEST_BYTES = 10_000_000  # 10MB


def _init_daemon_process() -> None:
    """Initialize daemon process: torch blocker, PID file, ML noise suppression."""
    _torch_blocker.install()
    # Drop any wall-clock backstop inherited from the forking `ails check` parent:
    # fork() clears the interval timer but the SIGALRM disposition carries over.
    if sys.platform != "win32":  # no SIGALRM/setitimer on Windows
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
    pid_path().write_text(str(os.getpid()))

    os.environ["TOKENIZERS_PARALLELISM"] = "false"


def _start_model_warmup() -> tuple[Any, threading.Event]:
    """Start model warmup in a background thread. Returns (models, warmup_done)."""
    models = get_models()
    warmup_done = threading.Event()

    def _warmup() -> None:
        try:
            models.warmup()
        except Exception:  # pylint: disable=broad-exception-caught  # the background warmup thread must not crash
            logger.warning("daemon warmup failed", exc_info=True)
        finally:
            warmup_done.set()

    threading.Thread(target=_warmup, name="mapper-warmup", daemon=True).start()
    return models, warmup_done


def run_daemon() -> None:
    """Main daemon loop: bind socket, warm models in background, serve requests.

    Socket is bound BEFORE model warmup so the parent's ``start_daemon`` can
    return as soon as the socket exists (microseconds after fork) and
    proceed with file discovery + M probes in parallel with model loading.
    ``map_ruleset`` requests block on ``warmup_done`` before dispatching;
    ``ping`` and ``shutdown`` are answered immediately regardless.

    Lifecycle: runs until explicit shutdown command, SIGTERM/SIGINT, or the
    idle timeout (default 30 min, AILS_DAEMON_IDLE_S seconds; 0 disables). No
    parent-process tracking; the global daemon isn't a child of any specific
    CLI process.

    Unreachable on Windows: callers gate on sys.platform before invoking.
    """
    if sys.platform == "win32":
        return

    _init_daemon_process()

    _shutdown = False

    def _handle_signal(_signum: int, _frame: object) -> None:
        nonlocal _shutdown
        _shutdown = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    # SIGPIPE on a half-closed client connection must not kill the daemon —
    # Python's socket layer raises BrokenPipeError, caught by the per-request
    # `except Exception` in the accept loop. Default SIGPIPE handler terminates.
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    sock_path = socket_path()
    sock_path.unlink(missing_ok=True)
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(str(sock_path))
    server_sock.listen(_SOCKET_BACKLOG)
    server_sock.settimeout(1.0)

    models, warmup_done = _start_model_warmup()

    last_activity = time.monotonic()

    while not _shutdown:
        if _IDLE_TIMEOUT_S is not None and time.monotonic() - last_activity > _IDLE_TIMEOUT_S:
            break

        try:
            conn, _ = server_sock.accept()
        except TimeoutError:
            continue
        except OSError:
            break

        last_activity = time.monotonic()
        try:
            _handle_connection(conn, models, warmup_done)
        except Exception:  # pylint: disable=broad-exception-caught  # one failed request must not stop the daemon serving
            logger.warning("daemon request failed", exc_info=True)
        finally:
            conn.close()

    server_sock.close()
    sock_path.unlink(missing_ok=True)
    pid_path().unlink(missing_ok=True)
    models.unload()  # release resident models before the daemon process exits


def _handle_connection(
    conn: socket.socket,
    models: Any,
    warmup_done: threading.Event,
) -> None:
    """Handle a single client connection.

    ``map_ruleset`` requests block on ``warmup_done`` before dispatching —
    this lets the parent connect to the socket before models are loaded
    and get a fast response once they are. ``ping`` and ``shutdown`` never
    block so callers can reason about daemon liveness even mid-warmup.
    """
    conn.settimeout(300.0)  # enough for cold warmup + map
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return
        data += chunk
        if len(data) > _MAX_REQUEST_BYTES:
            conn.sendall(json.dumps({"ok": False, "error": "request too large"}).encode() + b"\n")
            return

    line = data.split(b"\n", 1)[0]
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        conn.sendall(json.dumps({"ok": False, "error": "invalid JSON"}).encode() + b"\n")
        return

    def _send_progress(msg: str) -> None:
        # Stream a per-element progress line to the client mid-map. A closed/
        # half-open client connection raises here; swallow it — a progress write
        # failure must never crash the daemon or abort the map.
        with contextlib.suppress(OSError):
            conn.sendall(json.dumps({"type": "progress", "msg": msg}, separators=(",", ":")).encode() + b"\n")

    response = _dispatch(request, models, warmup_done, _send_progress)
    conn.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")


def _dispatch(
    request: dict[str, Any],
    models: Any,
    warmup_done: threading.Event,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Dispatch a request to the appropriate handler.

    ``progress`` (map_ruleset only) streams per-element progress lines back to
    the client before the result line; ping/shutdown stay single-response.
    """
    cmd = request.get("cmd", "")

    if cmd == "ping":
        return {"ok": True, "pid": os.getpid(), "warm": warmup_done.is_set(), "code": code_identity()}

    if cmd == "shutdown":
        os.kill(os.getpid(), signal.SIGTERM)
        return {"ok": True}

    if cmd == "map_ruleset":
        warmup_done.wait(timeout=120)
        return _handle_map_ruleset(request, models, progress)

    return {"ok": False, "error": f"unknown command: {cmd}"}


def _resolve_segmentation(root: Path | None) -> str:
    """Read the project's segmentation mode from `.ails/config.yml` at `root`."""
    if root is None:
        return "legacy"
    return get_project_config(root).mapper.segmentation


def _ruleset_map_to_dict(ruleset_map: Any) -> dict[str, Any]:
    """Serialize a RulesetMap to a JSON-compatible dict via a temp round-trip."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        save_ruleset_map(ruleset_map, Path(f.name))
        tmp_path = f.name
    result_json = Path(tmp_path).read_text(encoding="utf-8")
    Path(tmp_path).unlink()
    data: dict[str, Any] = json.loads(result_json)
    return data


def _handle_map_ruleset(
    request: dict[str, Any], models: Any, progress: Callable[[str], None] | None = None
) -> dict[str, Any]:
    """Handle map_ruleset request — build RulesetMap from paths.

    ``progress`` streams per-element mapping messages back to the client, so the
    daemon path shows the same per-harness-element counter as the in-process path.
    """
    paths = [Path(p) for p in request.get("paths", [])]
    root = Path(request["root"]) if "root" in request else None

    try:
        ruleset_map = map_ruleset(
            paths,
            models=models,
            root=root,
            cache_dir=get_global_cache_dir(),
            segmentation=_resolve_segmentation(root),
            progress=progress,
        )
        return {"ok": True, "ruleset_map": _ruleset_map_to_dict(ruleset_map), "code": code_identity()}
    except Exception as e:  # pylint: disable=broad-exception-caught  # the daemon answers with an error dict, never crashes
        logger.warning("daemon map_ruleset failed", exc_info=True)
        return {"ok": False, "error": str(e)}
