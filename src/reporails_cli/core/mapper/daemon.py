"""Mapper daemon — single global background process keeping models loaded.

Process lifecycle of the global daemon: where its files live, whether it runs, how it
starts and stops. The serving loop that keeps the models loaded lives in `daemon_server`.

Socket: ~/.reporails/daemon/mapper.sock
PID file: ~/.reporails/daemon/mapper.pid
Protocol: JSON-line over Unix domain socket (one JSON object per line).
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import signal
import stat
import sys
import time
from pathlib import Path

from reporails_cli.core.mapper.map_cache import CACHE_VERSION
from reporails_cli.core.platform.config.bootstrap import get_daemon_dir
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.http_get import HttpGet
from reporails_cli.core.platform.dto.ports import DaemonTransport
from reporails_cli.core.platform.utils.version import installed_version

logger = logging.getLogger(__name__)


def _daemon_dir() -> Path:
    return get_daemon_dir()


def socket_path() -> Path:
    """The Unix socket the daemon listens on."""
    return _daemon_dir() / "mapper.sock"


def pid_path() -> Path:
    """The file naming the daemon's process id."""
    return _daemon_dir() / "mapper.pid"


def write_pid(pid: int) -> None:
    """Record `pid` as the daemon's process id."""
    pid_path().write_text(str(pid))


def remove_socket() -> None:
    """Remove the daemon's socket file, if any."""
    socket_path().unlink(missing_ok=True)


def remove_runtime_files() -> None:
    """Remove the daemon's socket file, then its process-id file."""
    remove_socket()
    pid_path().unlink(missing_ok=True)


def _lock_path() -> Path:
    return _daemon_dir() / "mapper.lock"


def is_daemon_running() -> bool:
    """Return True only when the recorded PID is alive AND the socket file exists."""
    pid_file = pid_path()
    sock_file = socket_path()
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)  # signal 0 = existence check
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        pid_file.unlink(missing_ok=True)
        sock_file.unlink(missing_ok=True)
        return False
    if not sock_file.exists():
        # PID alive but accept loop has shut down (or never bound).
        # Reap so the next start_daemon forks a fresh one.
        pid_file.unlink(missing_ok=True)
        return False
    return True


def stop_daemon(transport: DaemonTransport) -> bool:
    """Send shutdown command to daemon. Returns True if stopped."""
    if sys.platform == "win32":
        return False
    if not is_daemon_running():
        return False
    try:
        resp = transport.exchange(socket_path(), {"cmd": "shutdown"}, timeout=_SHUTDOWN_TIMEOUT_S, on_message=None)
    except PlatformUnavailableError:
        # Force kill
        pid = daemon_pid()
        if pid is not None:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.kill(pid, signal.SIGTERM)
    else:
        logger.debug("Daemon shutdown response: %s", resp)
    # Clean up
    pid_path().unlink(missing_ok=True)
    socket_path().unlink(missing_ok=True)
    return True


def daemon_pid() -> int | None:
    """The pid the daemon files name, or None when no daemon holds them."""
    try:
        return int(pid_path().read_text().strip())
    except (OSError, ValueError):
        return None


# Seconds a retired daemon is given to answer and to exit.
_RETIRE_TIMEOUT_S = 5.0
# Seconds a daemon being stopped is given to answer.
_SHUTDOWN_TIMEOUT_S = 5.0


def retire_daemon(transport: DaemonTransport, pid: object) -> bool:
    """Shut down the daemon running as `pid` and wait for it to exit. True once it is gone.

    Only a daemon that still owns the daemon files is asked, and it removes its own files
    as it exits, so a daemon started in the meantime is never touched. A daemon too busy to
    answer, or one that has not exited within `_RETIRE_TIMEOUT_S`, is not waited for: it stops once its
    current request is done.
    """
    if sys.platform == "win32" or not isinstance(pid, int):
        return False
    if daemon_pid() != pid:
        return False
    try:
        transport.exchange(socket_path(), {"cmd": "shutdown"}, timeout=_RETIRE_TIMEOUT_S, on_message=None)
    except PlatformUnavailableError:
        return False
    deadline = time.monotonic() + _RETIRE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        time.sleep(0.05)
    return False


def _become_daemon(transport: DaemonTransport, fetch: HttpGet) -> None:
    """Detach from parent, close inherited FDs, redirect stdio, run daemon loop.

    Called in the forked child process. Never returns — calls os._exit(0).
    Unreachable on Windows: callers gate on sys.platform before forking.
    """
    if sys.platform == "win32":
        return
    try:
        os.setsid()

        # Close inherited PIPE FDs above stderr (e.g. npx stdio: "inherit")
        # so the parent doesn't hang waiting for pipe closure. Limited to
        # pipes so pre-fork-imported C-extension FDs survive.
        import resource  # pylint: disable=import-outside-toplevel  # absent on Windows

        max_fd = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        for fd in range(3, min(max_fd, 1024)):
            try:
                if stat.S_ISFIFO(os.fstat(fd).st_mode):
                    with contextlib.suppress(OSError):
                        os.close(fd)
            except OSError:
                continue

        # Redirect std streams to /dev/null
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)

        from reporails_cli.core.mapper.daemon_server import (  # pylint: disable=import-outside-toplevel  # startup: the forked daemon child loads the ML runtime
            run_daemon,
        )

        run_daemon(transport, fetch)
    except Exception:  # pylint: disable=broad-exception-caught  # the daemon child must not crash on transient errors
        logger.warning("daemon process failed", exc_info=True)
    finally:
        os._exit(0)  # daemon child must not return


def start_daemon(transport: DaemonTransport, fetch: HttpGet) -> int:
    """Start global daemon in a forked subprocess. Returns child PID.

    Uses flock on mapper.lock to serialize concurrent starts.
    Requires Unix (fork/AF_UNIX) — raises OSError on Windows.
    """
    if sys.platform == "win32":
        raise OSError("Mapper daemon requires Unix (fork/AF_UNIX). Use 'ails check' directly on Windows.")

    daemon_dir = _daemon_dir()
    daemon_dir.mkdir(parents=True, exist_ok=True)

    if is_daemon_running():
        pid = int(pid_path().read_text(encoding="utf-8").strip())
        logger.debug("Daemon already running (PID %d)", pid)
        return pid

    import fcntl  # pylint: disable=import-outside-toplevel  # absent on Windows

    # Serialize concurrent starts
    with open(_lock_path(), "w", encoding="utf-8") as lock_fd:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass  # another process holds the lock: it is starting the daemon
        else:
            try:
                return _fork_daemon(transport, fetch)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
    # Another process is starting the daemon — wait for it
    for _ in range(20):
        time.sleep(0.1)
        if is_daemon_running():
            return int(pid_path().read_text(encoding="utf-8").strip())
    return 0


def _fork_daemon(transport: DaemonTransport, fetch: HttpGet) -> int:
    """Fork the daemon child while holding the start lock. Returns the child PID.

    Unreachable on Windows: callers gate on sys.platform before forking.
    """
    if sys.platform == "win32":
        return 0
    # Re-check after acquiring lock (another starter may have finished)
    if is_daemon_running():
        return int(pid_path().read_text(encoding="utf-8").strip())

    # Clean stale socket
    socket_path().unlink(missing_ok=True)

    pid = os.fork()
    if pid > 0:
        # Parent — wait for child's accept loop to bind the socket.
        # Cold model imports can take >2s; 4s headroom keeps the parent
        # from giving up before the child has bound.
        sock_path = socket_path()
        for _ in range(40):
            time.sleep(0.1)
            if sock_path.exists():
                break
        return pid

    _become_daemon(transport, fetch)

    return 0  # unreachable


@functools.cache
def code_identity() -> str:
    """The code this process maps with: the installed package version and the map-cache
    version, which changes whenever the mapper's output does."""
    return f"{installed_version()}+map{CACHE_VERSION}"
