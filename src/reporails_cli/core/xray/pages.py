"""The x-ray page a project has running: its record, whether it still answers, and starting one."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

import httpx

from reporails_cli.core.cache.hashing import content_hash
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.adapters.programs import launch_detached
from reporails_cli.core.platform.config.bootstrap import get_xray_pages_dir
from reporails_cli.core.platform.contract.errors import XrayPageError
from reporails_cli.core.platform.contract.json_value import JsonValue, as_object, as_str, opt_int
from reporails_cli.core.platform.dto.xray import SessionPick, XrayPage
from reporails_cli.core.platform.utils.utils import write_json_atomic
from reporails_cli.core.platform.utils.version import installed_code_stamp

HOST = "127.0.0.1"
# Seconds a started page has to answer, and the age after which a start lock is taken to be stale.
PAGE_START_S = 30.0
_PROBE_TIMEOUT_S = 1.0
_POLL_S = 0.1
# Seconds a look at the installed code stays the answer to whether it changed.
_CODE_CHECK_S = 3.0


def _record_path(root: Path) -> Path:
    """The record file of the project's page, named by a digest of its resolved root."""
    digest = content_hash(safe_resolve(root).as_posix()).removeprefix("sha256:")[:32]
    return get_xray_pages_dir() / f"{digest}.json"


def _lock_path(root: Path) -> Path:
    return _record_path(root).with_suffix(".lock")


def _read_record(root: Path) -> XrayPage | None:
    """The page the project's record names; None when there is no record or it is not the pinned shape."""
    try:
        data = as_object(json.loads(_record_path(root).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None
    pid, port, launch = opt_int(data.get("pid")), opt_int(data.get("port")), as_str(data.get("launch"))
    return None if pid is None or port is None or not launch else XrayPage(pid, port, launch)


def register_page(root: Path, port: int, launch: str) -> None:
    """Record this process as the one serving the project's page on `port` under `launch`. Raises `OSError`."""
    record: JsonValue = {"pid": os.getpid(), "port": port, "launch": launch}
    path = _record_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_json_atomic(path, record, mode=0o600)


def forget_page(root: Path, launch: str) -> None:
    """Remove the project's record while it still names `launch`."""
    page = _read_record(root)
    if page is not None and page.launch == launch:
        with contextlib.suppress(OSError):
            _record_path(root).unlink()


def _answers(page: XrayPage) -> bool:
    """Whether the process on the page's port reports the page's own launch id and the installed code it started
    with."""
    try:
        reply = httpx.get(f"http://{HOST}:{page.port}/launch", timeout=_PROBE_TIMEOUT_S)
        body = as_object(reply.json())
        return as_str(body.get("launch")) == page.launch and body.get("changed") is False
    except (httpx.HTTPError, ValueError):
        return False


def running_page(root: Path) -> XrayPage | None:
    """The page running for the project, or None; a record whose page does not answer is removed."""
    page = _read_record(root)
    if page is None:
        return None
    if _answers(page):
        return page
    with contextlib.suppress(OSError):
        _record_path(root).unlink()
    return None


def _take_lock(root: Path) -> bool:
    """Create the start lock; False while another start holds it. A lock older than `PAGE_START_S` is stale and
    is replaced."""
    lock = _lock_path(root)
    lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for _ in range(2):
        try:
            os.close(os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            return True
        except FileExistsError:
            with contextlib.suppress(OSError):
                if time.time() - lock.stat().st_mtime > PAGE_START_S:
                    lock.unlink()
                    continue
            return False
    return False


def _wait_for_page(root: Path, pid: int | None) -> XrayPage:
    """The page that answers for the project, the one process `pid` registered when given; raises `XrayPageError`
    when none answers within `PAGE_START_S`."""
    deadline = time.monotonic() + PAGE_START_S
    while time.monotonic() < deadline:
        page = running_page(root)
        if page is not None and (pid is None or page.pid == pid):
            return page
        time.sleep(_POLL_S)
    raise XrayPageError(f"the x-ray page did not answer within {PAGE_START_S:.0f} seconds")


def _unwritable(exc: OSError) -> XrayPageError:
    """The error for a page that could not start; it names the folder the page's record lives in."""
    return XrayPageError(f"the x-ray page could not start; its folder is {get_xray_pages_dir()}: {exc}")


def start_page(root: Path, session_id: str) -> tuple[XrayPage, bool]:
    """The project's page and whether it was already running; with none running, start one on `session_id`,
    detached, and wait for it to answer.

    While another start of the project's page is in progress, wait for the page it registers. Raises
    `XrayPageError` when the page cannot be started or when none answers in time."""
    page = running_page(root)
    if page is not None:
        return page, True
    try:
        locked = _take_lock(root)
    except OSError as exc:
        raise _unwritable(exc) from exc
    if not locked:
        return _wait_for_page(root, None), True
    try:
        page = running_page(root)
        if page is not None:
            return page, True
        command = [sys.executable, "-I", "-m", "reporails_cli", "xray", "--no-open", "--session", session_id]
        try:
            pid = launch_detached(command, cwd=root)
        except OSError as exc:
            raise _unwritable(exc) from exc
        return _wait_for_page(root, pid), False
    finally:
        with contextlib.suppress(OSError):
            _lock_path(root).unlink()


def page_url(page: XrayPage, session_id: str, picked: SessionPick) -> str:
    """The address of `session_id` on the running page; a session the agent did not name carries a mark the
    page says so by."""
    return f"http://{HOST}:{page.port}/?session={session_id}&pick={picked}"


def code_change_watch() -> Callable[[], bool]:
    """A check, started now, of whether the installed code differs from the code at this moment; once it does,
    it stays so. The installed files are looked at once every few seconds."""
    started = installed_code_stamp()
    checked = time.monotonic()
    changed = False

    def check() -> bool:
        nonlocal checked, changed
        if not changed and time.monotonic() - checked >= _CODE_CHECK_S:
            checked = time.monotonic()
            changed = installed_code_stamp() != started
        return changed

    return check
