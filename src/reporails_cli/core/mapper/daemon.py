"""Mapper daemon — single global background process keeping models loaded.

Serves map requests over a Unix domain socket. The sentence-transformers
model stays in memory between invocations, eliminating the 5-10s model
load time on subsequent runs. One daemon serves all projects on the machine.

Socket: ~/.reporails/daemon/mapper.sock
PID file: ~/.reporails/daemon/mapper.pid
Protocol: JSON-line over Unix domain socket (one JSON object per line).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Idle timeout defaults to 1 hour; override with AILS_DAEMON_IDLE_S env var
# (e.g. AILS_DAEMON_IDLE_S=5 for fast integration tests, or a large number
# for long dev loops).
_IDLE_TIMEOUT_S = int(os.environ.get("AILS_DAEMON_IDLE_S", "3600"))
_SOCKET_BACKLOG = 2
_MAX_REQUEST_BYTES = 10_000_000  # 10MB


def _daemon_dir() -> Path:
    from reporails_cli.core.bootstrap import get_daemon_dir

    return get_daemon_dir()


def _socket_path() -> Path:
    return _daemon_dir() / "mapper.sock"


def _pid_path() -> Path:
    return _daemon_dir() / "mapper.pid"


def _lock_path() -> Path:
    return _daemon_dir() / "mapper.lock"


def is_daemon_running() -> bool:
    """Check if the global daemon process is alive."""
    pid_file = _pid_path()
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)  # signal 0 = existence check
        return True
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        # Stale PID file — clean up
        pid_file.unlink(missing_ok=True)
        _socket_path().unlink(missing_ok=True)
        return False


def stop_daemon() -> bool:
    """Send shutdown command to daemon. Returns True if stopped."""
    if sys.platform == "win32":
        return False
    if not is_daemon_running():
        return False
    sock_path = _socket_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect(str(sock_path))
            sock.sendall(json.dumps({"cmd": "shutdown"}).encode() + b"\n")
            resp = sock.recv(4096)
            logger.debug("Daemon shutdown response: %s", resp.decode())
    except (OSError, TimeoutError):
        # Force kill
        pid_file = _pid_path()
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, signal.SIGTERM)
            except (ValueError, ProcessLookupError, OSError):
                pass
    # Clean up
    _pid_path().unlink(missing_ok=True)
    _socket_path().unlink(missing_ok=True)
    return True


def _become_daemon() -> None:
    """Detach from parent, close inherited FDs, redirect stdio, run daemon loop.

    Called in the forked child process. Never returns — calls os._exit(0).
    Unreachable on Windows: callers gate on sys.platform before forking.
    """
    if sys.platform == "win32":
        return
    try:
        os.setsid()

        # Close inherited FDs above stderr before redirecting.
        # Without this, the daemon child holds references to the parent's
        # pipes (e.g., npx's stdio: "inherit"), preventing EOF and causing
        # the parent to hang indefinitely waiting for pipe closure.
        import resource

        max_fd = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        import contextlib

        for fd in range(3, min(max_fd, 1024)):
            with contextlib.suppress(OSError):
                os.close(fd)

        # Redirect std streams to /dev/null
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)

        _daemon_main()
    except Exception:  # daemon child must not crash on transient errors
        pass
    finally:
        os._exit(0)  # daemon child must not return


def start_daemon() -> int:
    """Start global daemon in a forked subprocess. Returns child PID.

    Uses flock on mapper.lock to serialize concurrent starts.
    Requires Unix (fork/AF_UNIX) — raises OSError on Windows.
    """
    if sys.platform == "win32":
        raise OSError("Mapper daemon requires Unix (fork/AF_UNIX). Use 'ails check' directly on Windows.")

    import fcntl

    daemon_dir = _daemon_dir()
    daemon_dir.mkdir(parents=True, exist_ok=True)

    if is_daemon_running():
        pid = int(_pid_path().read_text().strip())
        logger.debug("Daemon already running (PID %d)", pid)
        return pid

    # Serialize concurrent starts
    lock_file = _lock_path()
    lock_fd = open(lock_file, "w")  # noqa: SIM115
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        # Another process is starting the daemon — wait for it
        for _ in range(20):
            time.sleep(0.1)
            if is_daemon_running():
                return int(_pid_path().read_text().strip())
        return 0

    try:
        # Re-check after acquiring lock (another starter may have finished)
        if is_daemon_running():
            return int(_pid_path().read_text().strip())

        # Clean stale socket
        _socket_path().unlink(missing_ok=True)

        pid = os.fork()
        if pid > 0:
            # Parent — wait briefly for daemon to be ready
            sock_path = _socket_path()
            for _ in range(20):
                time.sleep(0.1)
                if sock_path.exists():
                    break
            return pid

        _become_daemon()

        return 0  # unreachable
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def _init_daemon_process() -> None:
    """Initialize daemon process: torch blocker, PID file, ML noise suppression."""
    from reporails_cli.core import _torch_blocker

    _torch_blocker.install()
    _pid_path().write_text(str(os.getpid()))

    import logging as _logging

    os.environ["TRANSFORMERS_VERBOSITY"] = "error"
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
    for lib in ("sentence_transformers", "transformers", "huggingface_hub"):
        _logging.getLogger(lib).setLevel(_logging.ERROR)


def _start_model_warmup() -> tuple[Any, threading.Event]:
    """Start model warmup in a background thread. Returns (models, warmup_done)."""
    from reporails_cli.core.mapper.mapper import get_models

    models = get_models()
    warmup_done = threading.Event()

    def _warmup() -> None:
        try:
            models.warmup()
        except Exception:  # background warmup thread must not crash
            logger.debug("daemon warmup failed", exc_info=True)
        finally:
            warmup_done.set()

    threading.Thread(target=_warmup, name="mapper-warmup", daemon=True).start()
    return models, warmup_done


def _daemon_main() -> None:
    """Main daemon loop: bind socket, warm models in background, serve requests.

    Socket is bound BEFORE model warmup so the parent's ``start_daemon`` can
    return as soon as the socket exists (microseconds after fork) and
    proceed with file discovery + M probes in parallel with model loading.
    ``map_ruleset`` requests block on ``warmup_done`` before dispatching;
    ``ping`` and ``shutdown`` are answered immediately regardless.

    Lifecycle: idle timeout only — no parent-process tracking. The global
    daemon isn't a child of any specific CLI process.

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

    sock_path = _socket_path()
    sock_path.unlink(missing_ok=True)
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(str(sock_path))
    server_sock.listen(_SOCKET_BACKLOG)
    server_sock.settimeout(1.0)

    models, warmup_done = _start_model_warmup()

    last_activity = time.monotonic()

    while not _shutdown:
        if time.monotonic() - last_activity > _IDLE_TIMEOUT_S:
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
        except Exception:  # per-request isolation; return error to client
            pass
        finally:
            conn.close()

    server_sock.close()
    sock_path.unlink(missing_ok=True)
    _pid_path().unlink(missing_ok=True)


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

    response = _dispatch(request, models, warmup_done)
    conn.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")


def _dispatch(
    request: dict[str, Any],
    models: Any,
    warmup_done: threading.Event,
) -> dict[str, Any]:
    """Dispatch a request to the appropriate handler."""
    cmd = request.get("cmd", "")

    if cmd == "ping":
        return {"ok": True, "pid": os.getpid(), "warm": warmup_done.is_set()}

    if cmd == "shutdown":
        os.kill(os.getpid(), signal.SIGTERM)
        return {"ok": True}

    if cmd == "map_ruleset":
        warmup_done.wait(timeout=120)
        return _handle_map_ruleset(request, models)

    return {"ok": False, "error": f"unknown command: {cmd}"}


def _handle_map_ruleset(request: dict[str, Any], models: Any) -> dict[str, Any]:
    """Handle map_ruleset request — build RulesetMap from paths."""
    from reporails_cli.core.bootstrap import get_global_cache_dir
    from reporails_cli.core.mapper.mapper import map_ruleset

    paths_str = request.get("paths", [])
    paths = [Path(p) for p in paths_str]
    root = Path(request["root"]) if "root" in request else None
    cache_dir = get_global_cache_dir()

    try:
        ruleset_map = map_ruleset(paths, models=models, root=root, cache_dir=cache_dir)
        # Serialize to JSON-compatible dict
        import tempfile

        from reporails_cli.core.mapper.mapper import save_ruleset_map

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            save_ruleset_map(ruleset_map, Path(f.name))
            tmp_path = f.name

        result_json = Path(tmp_path).read_text()
        Path(tmp_path).unlink()

        return {"ok": True, "ruleset_map": json.loads(result_json)}
    except Exception as e:  # daemon returns error dict, must not crash
        return {"ok": False, "error": str(e)}
