"""Daemon client — talks to the global mapper daemon over Unix socket.

Falls back gracefully: if daemon is not running or unreachable,
returns None and caller uses in-process mapping.
"""

from __future__ import annotations

import json
import logging
import socket
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _socket_path() -> Path:
    from reporails_cli.core.bootstrap import get_daemon_dir

    return get_daemon_dir() / "mapper.sock"


def connect(timeout: float = 5.0) -> socket.socket | None:
    """Connect to global daemon socket. Returns None if unreachable."""
    if sys.platform == "win32":
        return None
    sock_path = _socket_path()
    if not sock_path.exists():
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(sock_path))
        return sock
    except (OSError, TimeoutError):
        return None


def send_request(sock: socket.socket, request: dict[str, Any], timeout: float = 120.0) -> dict[str, Any] | None:
    """Send JSON-line request, read JSON-line response."""
    try:
        sock.settimeout(timeout)
        sock.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                return None
            data += chunk

        line = data.split(b"\n", 1)[0]
        result: dict[str, Any] = json.loads(line)
        return result
    except (OSError, TimeoutError, json.JSONDecodeError):
        return None
    finally:
        sock.close()


def ping() -> dict[str, Any] | None:
    """Ping daemon. Returns response dict or None if unreachable."""
    sock = connect()
    if sock is None:
        return None
    return send_request(sock, {"cmd": "ping"}, timeout=5.0)


def map_ruleset_via_daemon(
    paths: list[Path],
    root: Path,
) -> Any:
    """Map ruleset via global daemon. Returns RulesetMap or None on failure.

    Caller should fall back to in-process mapping when this returns None.
    """
    sock = connect()
    if sock is None:
        return None

    request = {
        "cmd": "map_ruleset",
        "paths": [str(p) for p in paths],
        "root": str(root),
    }
    # 300s matches the daemon-side conn timeout. Covers cold ST import (~29s)
    # + spaCy load + first-encode, plus mapping work, with headroom.
    response = send_request(sock, request, timeout=300.0)
    if response is None or not response.get("ok"):
        logger.debug("Daemon map_ruleset failed: %s", response.get("error") if response else "no response")
        return None

    # Deserialize the RulesetMap from JSON
    map_data = response.get("ruleset_map")
    if map_data is None:
        return None

    try:
        import tempfile

        from reporails_cli.core.mapper.mapper import load_ruleset_map

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(map_data, f)
            tmp_path = Path(f.name)

        result = load_ruleset_map(tmp_path)
        tmp_path.unlink()
        return result
    except (OSError, TimeoutError, json.JSONDecodeError, RuntimeError):
        logger.debug("Failed to deserialize daemon response", exc_info=True)
        return None


def ensure_daemon() -> bool:
    """Ensure global daemon is running. Start it if not. Returns True if available."""
    from reporails_cli.core.mapper.daemon import is_daemon_running, start_daemon

    if is_daemon_running():
        return True

    try:
        start_daemon()
        return is_daemon_running()
    except OSError:
        return False
