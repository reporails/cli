"""Mapper daemon serving loop: keeps the models loaded and answers map requests.

Serves map requests on the socket named by `daemon.socket_path`. The embedding model stays in
memory between invocations, eliminating the 5-10s model load time on subsequent runs.
One daemon serves all projects on the machine.
Protocol: JSON-line over Unix domain socket (one JSON object per line).
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from collections.abc import Callable
from pathlib import Path

from reporails_cli.core.mapper.daemon import code_identity, remove_runtime_files, remove_socket, socket_path, write_pid
from reporails_cli.core.mapper.models import Models
from reporails_cli.core.mapper.pipeline import map_ruleset
from reporails_cli.core.mapper.serialize import ruleset_map_json
from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir, parse_idle_timeout_env
from reporails_cli.core.platform.contract.http_get import HttpGet
from reporails_cli.core.platform.contract.json_value import JsonObject, as_str, str_list
from reporails_cli.core.platform.dto.ports import DaemonTransport
from reporails_cli.core.platform.observability.log_levels import configure_logging
from reporails_cli.core.platform.observability.stage_timer import get_stage_timer

logger = logging.getLogger(__name__)

# Idle shutdown is on by default (30 min) so resident embedding models don't
# pin memory indefinitely on an idle machine. Override the window via the
# AILS_DAEMON_IDLE_S env var (seconds) — set low for CI (e.g. 5), set 0 to
# disable idle shutdown entirely (daemon runs until `ails daemon stop`/kill).
_DEFAULT_IDLE_TIMEOUT_S = 1800


def _parse_idle_timeout() -> int | None:
    return parse_idle_timeout_env("AILS_DAEMON_IDLE_S", _DEFAULT_IDLE_TIMEOUT_S)


_IDLE_TIMEOUT_S: int | None = _parse_idle_timeout()


def _init_daemon_process() -> None:
    """Initialize daemon process: logging, PID file, ML noise suppression."""
    configure_logging()
    # Drop any wall-clock backstop inherited from the forking `ails check` parent:
    # fork() clears the interval timer but the SIGALRM disposition carries over.
    if sys.platform != "win32":  # no SIGALRM/setitimer on Windows
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
    write_pid(os.getpid())

    os.environ["TOKENIZERS_PARALLELISM"] = "false"


def _start_model_warmup(fetch: HttpGet) -> tuple[Models, threading.Event]:
    """Start model warmup in a background thread. Returns (models, warmup_done)."""
    models = Models(fetch)
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


def run_daemon(transport: DaemonTransport, fetch: HttpGet) -> None:
    """Main daemon loop: warm models in the background, serve requests on `transport`.

    The socket is bound as soon as the warmup thread has started, so requests are accepted
    while the models are still loading.
    ``map_ruleset`` requests block on ``warmup_done`` before dispatching;
    ``ping`` and ``shutdown`` are answered immediately regardless.

    Lifecycle: runs until explicit shutdown command, SIGTERM/SIGINT, or the
    idle timeout (default 30 min, AILS_DAEMON_IDLE_S seconds; 0 disables).
    Returns at once on Windows.
    """
    if sys.platform == "win32":
        return

    _init_daemon_process()
    models, warmup_done = _start_model_warmup(fetch)

    def _handle(request: JsonObject, send: Callable[[JsonObject], None]) -> JsonObject:
        # Stream a per-element progress frame to the client mid-map.
        def _send_progress(msg: str) -> None:
            send({"type": "progress", "msg": msg})

        with get_stage_timer().run(f"daemon {as_str(request.get('cmd', ''))}"):
            return _dispatch(request, models, warmup_done, _send_progress)

    remove_socket()
    try:
        transport.serve(socket_path(), _handle, idle_timeout=_IDLE_TIMEOUT_S)
    finally:
        remove_runtime_files()
        models.unload()  # release resident models before the daemon process exits


def _dispatch(
    request: JsonObject,
    models: Models,
    warmup_done: threading.Event,
    progress: Callable[[str], None] | None = None,
) -> JsonObject:
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


def _handle_map_ruleset(
    request: JsonObject, models: Models, progress: Callable[[str], None] | None = None
) -> JsonObject:
    """Handle map_ruleset request — build RulesetMap from paths.

    ``progress`` streams per-element mapping messages back to the client, so the
    daemon path shows the same per-harness-element counter as the in-process path.
    """
    paths = [Path(p) for p in str_list(request.get("paths"))]
    root = Path(as_str(request["root"])) if "root" in request else None
    segmentation = as_str(request["segmentation"])

    try:
        ruleset_map = map_ruleset(
            paths,
            models=models,
            root=root,
            cache_dir=get_global_cache_dir(),
            segmentation=segmentation,
            progress=progress,
        )
        return {"ok": True, "ruleset_map": ruleset_map_json(ruleset_map), "code": code_identity()}
    except Exception as e:  # pylint: disable=broad-exception-caught  # the daemon answers with an error dict, never crashes
        logger.warning("daemon map_ruleset failed", exc_info=True)
        return {"ok": False, "error": str(e)}
