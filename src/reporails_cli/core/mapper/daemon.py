"""Mapper daemon — persistent background process keeping models loaded.

Serves map requests over a Unix domain socket. The sentence-transformers
model stays in memory between invocations, eliminating the 5-10s model
load time on subsequent runs.

Socket: .ails/.cache/mapper.sock
PID file: .ails/.cache/mapper.pid
Protocol: JSON-line over Unix domain socket (one JSON object per line).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
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


def _socket_path(cache_dir: Path) -> Path:
    return cache_dir / "mapper.sock"


def _pid_path(cache_dir: Path) -> Path:
    return cache_dir / "mapper.pid"


def is_daemon_running(cache_dir: Path) -> bool:
    """Check if daemon process is alive."""
    pid_file = _pid_path(cache_dir)
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)  # signal 0 = existence check
        return True
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        # Stale PID file — clean up
        pid_file.unlink(missing_ok=True)
        _socket_path(cache_dir).unlink(missing_ok=True)
        return False


def stop_daemon(cache_dir: Path) -> bool:
    """Send shutdown command to daemon. Returns True if stopped."""
    if not is_daemon_running(cache_dir):
        return False
    sock_path = _socket_path(cache_dir)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect(str(sock_path))
            sock.sendall(json.dumps({"cmd": "shutdown"}).encode() + b"\n")
            resp = sock.recv(4096)
            logger.debug("Daemon shutdown response: %s", resp.decode())
    except (OSError, TimeoutError):
        # Force kill
        pid_file = _pid_path(cache_dir)
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, signal.SIGTERM)
            except (ValueError, ProcessLookupError, OSError):
                pass
    # Clean up
    _pid_path(cache_dir).unlink(missing_ok=True)
    _socket_path(cache_dir).unlink(missing_ok=True)
    return True


def start_daemon(cache_dir: Path) -> int:
    """Start daemon in a forked subprocess. Returns child PID."""
    if is_daemon_running(cache_dir):
        pid = int(_pid_path(cache_dir).read_text().strip())
        logger.debug("Daemon already running (PID %d)", pid)
        return pid

    # Clean stale socket
    _socket_path(cache_dir).unlink(missing_ok=True)

    cache_dir.mkdir(parents=True, exist_ok=True)

    pid = os.fork()
    if pid > 0:
        # Parent — wait briefly for daemon to be ready
        for _ in range(20):
            time.sleep(0.1)
            if _socket_path(cache_dir).exists():
                break
        return pid

    # Child — become daemon
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

        _daemon_main(cache_dir)
    except Exception:  # daemon child must not crash on transient errors
        pass
    finally:
        os._exit(0)  # daemon child must not return

    return 0  # unreachable


def _init_daemon_process(cache_dir: Path) -> None:
    """Initialize daemon process: torch blocker, PID file, ML noise suppression."""
    from reporails_cli.core import _torch_blocker

    _torch_blocker.install()
    _pid_path(cache_dir).write_text(str(os.getpid()))

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


def _is_orphaned(last_check: float, interval: float) -> tuple[bool, float]:
    """Check if parent died (PPID=1). Returns (orphaned, updated_last_check)."""
    now = time.monotonic()
    if now - last_check > interval:
        if os.getppid() == 1:
            logger.debug("Parent process died (PPID=1), shutting down daemon")
            return True, now
        return False, now
    return False, last_check


def _daemon_main(cache_dir: Path) -> None:
    """Main daemon loop: bind socket, warm models in background, serve requests.

    Socket is bound BEFORE model warmup so the parent's ``start_daemon`` can
    return as soon as the socket exists (microseconds after fork) and
    proceed with file discovery + M probes in parallel with model loading.
    ``map_ruleset`` requests block on ``warmup_done`` before dispatching;
    ``ping`` and ``shutdown`` are answered immediately regardless.
    """
    _init_daemon_process(cache_dir)

    _shutdown = False

    def _handle_signal(_signum: int, _frame: object) -> None:
        nonlocal _shutdown
        _shutdown = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    sock_path = _socket_path(cache_dir)
    sock_path.unlink(missing_ok=True)
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(str(sock_path))
    server_sock.listen(_SOCKET_BACKLOG)
    server_sock.settimeout(1.0)

    models, warmup_done = _start_model_warmup()

    last_activity = time.monotonic()
    orphan_check_interval = 30
    last_orphan_check = last_activity

    while not _shutdown:
        if time.monotonic() - last_activity > _IDLE_TIMEOUT_S:
            break

        orphaned, last_orphan_check = _is_orphaned(last_orphan_check, orphan_check_interval)
        if orphaned:
            break

        try:
            conn, _ = server_sock.accept()
        except TimeoutError:
            continue
        except OSError:
            break

        last_activity = time.monotonic()
        try:
            _handle_connection(conn, models, cache_dir, warmup_done)
        except Exception:  # per-request isolation; return error to client
            pass
        finally:
            conn.close()

    server_sock.close()
    sock_path.unlink(missing_ok=True)
    _pid_path(cache_dir).unlink(missing_ok=True)


def _handle_connection(
    conn: socket.socket,
    models: Any,
    cache_dir: Path,
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

    response = _dispatch(request, models, cache_dir, warmup_done)
    conn.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")


def _dispatch(
    request: dict[str, Any],
    models: Any,
    cache_dir: Path,
    warmup_done: threading.Event,
) -> dict[str, Any]:
    """Dispatch a request to the appropriate handler.

    ``map_ruleset`` does NOT block on ``warmup_done``. Models are loaded
    lazily on first access with a thread-safe lock inside the ``Models``
    singleton, so if a request arrives before the warmup thread finishes
    it will just wait on the lock inside ``map_ruleset`` when (and only
    when) it actually needs the model. For cache-hit requests where
    neither the spaCy nor the ST model is touched, warmup is skipped
    entirely — the request returns before warmup completes.
    """
    cmd = request.get("cmd", "")

    if cmd == "ping":
        return {"ok": True, "pid": os.getpid(), "warm": warmup_done.is_set()}

    if cmd == "shutdown":
        # Signal will be caught by the main loop
        os.kill(os.getpid(), signal.SIGTERM)
        return {"ok": True}

    if cmd == "map_ruleset":
        return _handle_map_ruleset(request, models, cache_dir)

    return {"ok": False, "error": f"unknown command: {cmd}"}


def _handle_map_ruleset(request: dict[str, Any], models: Any, cache_dir: Path) -> dict[str, Any]:
    """Handle map_ruleset request — build RulesetMap from paths."""
    from reporails_cli.core.mapper.mapper import map_ruleset

    paths_str = request.get("paths", [])
    paths = [Path(p) for p in paths_str]
    root = Path(request["root"]) if "root" in request else None

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
