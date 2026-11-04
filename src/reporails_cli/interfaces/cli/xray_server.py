"""The local x-ray page server: serves the bundled page and translates its requests into core calls.

Binds `127.0.0.1` only. Every request is refused before any core call unless its `Host`, `Origin` (a POST),
launch token and file path pass; the routes only translate between HTTP and the core.
"""

from __future__ import annotations

import logging
import mimetypes
import secrets
import shlex
import socket
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import get_args

import typer
import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from reporails_cli.bundled import get_xray_path
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.eventbus.transcript import known_session
from reporails_cli.core.heal.apply import heal_one, resolved_within
from reporails_cli.core.pipeline.check_one import check_path, file_findings
from reporails_cli.core.platform.adapters.programs import open_in_browser
from reporails_cli.core.platform.adapters.registry import file_level_check_ids
from reporails_cli.core.platform.adapters.rules_query import rule_category, rule_title
from reporails_cli.core.platform.config.bootstrap import parse_idle_timeout_env
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import FindingItem
from reporails_cli.core.platform.dto.pipeline import Refusal
from reporails_cli.core.platform.dto.xray import SessionPick, XrayCheck
from reporails_cli.core.platform.dto.xray_sources import FindingTally, XrayPeek
from reporails_cli.core.xray.pages import HOST, code_change_watch, forget_page, register_page
from reporails_cli.core.xray.session import XraySession
from reporails_cli.core.xray.sessions import session_entries
from reporails_cli.core.xray.tally import tallies_by_file, tally_of
from reporails_cli.formatters.mcp_view import render_heal_apply
from reporails_cli.formatters.text.rule_meta import rule_docs_url
from reporails_cli.interfaces.cli.xray_line import xray_line

TOKEN_HEADER = "x-xray-token"
TOKEN_PLACEHOLDER = "__XRAY_TOKEN__"
PAGE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    ),
    "Cache-Control": "no-store",
}
NO_STORE = {"Cache-Control": "no-store"}
CHANGED_MESSAGE = "ails changed since this page started; run `ails xray` again to open a current page"
# Seconds with no request after which a page stops: an open tab asks at least once a minute, a closed one never.
_DEFAULT_IDLE_S = 1800
_PICKS: tuple[SessionPick, ...] = get_args(SessionPick)

logger = logging.getLogger(__name__)

# Browsers refuse a module script served under another type, and some platforms map `.js` to one.
mimetypes.add_type("text/javascript", ".js")


def _refused(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


class XrayServer:
    """One launch: the session it opened on and how it was chosen, the sessions read since, the launch token and id,
    and the one-at-a-time lock on slow core calls."""

    def __init__(
        self, root: Path, session_file: Path, *, picked: SessionPick, token: str, launch: str, port: int
    ) -> None:
        self._root = root
        self._launch_file = session_file
        self._launch_pick = picked
        self._sessions: dict[str, XraySession] = {}
        self._token = token
        self._launch_id = launch
        self._origin = f"http://{HOST}:{port}"
        self._findings: dict[str, FindingTally] = {}
        self._launch = XrayCheck("running", None)
        self._view_lock = threading.Lock()
        self._work_lock = threading.Lock()
        self._code_changed = code_change_watch()

    def _wrong_token(self, request: Request) -> bool:
        sent = request.headers.get(TOKEN_HEADER, "")
        return not secrets.compare_digest(sent.encode(), self._token.encode())

    async def _guard(self, request: Request) -> JSONResponse | None:
        """The refusal for a request that carries no valid token (or, for a POST, a foreign `Origin`) or that reaches
        a page whose installed code changed since it started, else None."""
        if request.method == "POST" and request.headers.get("origin") != self._origin:
            return _refused(403, "foreign origin")
        if self._wrong_token(request):
            return _refused(403, "missing or wrong token")
        if await run_in_threadpool(self._code_changed):
            return JSONResponse({"error": CHANGED_MESSAGE, "changed": True}, status_code=409, headers=NO_STORE)
        return None

    async def _target(self, request: Request) -> Path | JSONResponse:
        """The checked file of a POST body `{"path": ...}`, or the refusal."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        try:
            body = await request.json()
        except ValueError:
            return _refused(400, "the body is not JSON")
        if not isinstance(body, dict) or set(body) != {"path"} or not isinstance(body["path"], str):
            return _refused(400, 'the body is {"path": "<file>"}')
        if not await run_in_threadpool(self._lists, body["path"]):
            return _refused(400, "not a file this page lists")
        target = safe_resolve(self._root / body["path"])
        if not resolved_within(target, self._root) or not target.is_file():
            return _refused(400, "the path is not a file inside the project")
        return target

    def _lists(self, path: str) -> bool:
        """Whether a session this page has read lists `path`."""
        self._session_for(self._launch_file.stem)
        with self._view_lock:
            return any(session.acts_on(path) for session in self._sessions.values())

    async def page(self, _request: Request) -> Response:
        """The bundled page with the launch token in it."""
        html = (get_xray_path() / "index.html").read_text(encoding="utf-8").replace(TOKEN_PLACEHOLDER, self._token)
        return Response(html, media_type="text/html", headers=PAGE_HEADERS)

    async def view(self, request: Request) -> Response:
        """The session view, `304` when its version is the one the page holds."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        chosen = await self._session_of(request)
        if isinstance(chosen, JSONResponse):
            return chosen
        session_id, session, picked = chosen
        payload, version = await run_in_threadpool(self._build_view, session, picked)
        etag = f'"{session_id}:{version}"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(payload, headers={"ETag": etag, **NO_STORE})

    def _build_view(self, session: XraySession, picked: SessionPick) -> tuple[JsonObject, int]:
        with self._view_lock:
            session.refresh()
            view = session.view(self._findings, self._launch, picked)
            return view.to_json(), view.version

    async def _session_of(self, request: Request) -> tuple[str, XraySession, SessionPick] | JSONResponse:
        """The session a request names with `?session=` (the launch session without it), and how it was chosen:
        `?pick=` when sent, else the launch pick for a request naming no session and `named` for one that does."""
        named_session = request.query_params.get("session")
        session_id = named_session or self._launch_file.stem
        picked: SessionPick = "named" if named_session else self._launch_pick
        sent = request.query_params.get("pick")
        if sent is not None:
            named = next((member for member in _PICKS if member == sent), None)
            if named is None:
                return _refused(400, f"pick is one of {', '.join(_PICKS)}")
            picked = named
        session = await run_in_threadpool(self._session_for, session_id)
        if session is None:
            return _refused(400, "not a session of this project")
        return session_id, session, picked

    def _session_for(self, session_id: str) -> XraySession | None:
        """The session `session_id`, read on first use; None when it is not a session of the project."""
        with self._view_lock:
            held = self._sessions.get(session_id)
            if held is not None:
                return held
            if session_id == self._launch_file.stem:
                transcript: Path | None = self._launch_file
            else:
                transcript = known_session(self._root, session_id)
            if transcript is None:
                return None
            self._sessions[session_id] = XraySession(self._root, transcript)
            return self._sessions[session_id]

    async def sessions(self, request: Request) -> Response:
        """The project's recent sessions with the facts the switcher lists, and the session this request is on."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        chosen = await self._session_of(request)
        if isinstance(chosen, JSONResponse):
            return chosen
        entries = await run_in_threadpool(session_entries, self._root)
        return JSONResponse(
            {"session": chosen[0], "sessions": [entry.to_json() for entry in entries]}, headers=NO_STORE
        )

    async def launch(self, _request: Request) -> Response:
        """The id of this launch, so a caller can tell a live page from a record left behind, and whether the
        installed code changed since it started."""
        changed = await run_in_threadpool(self._code_changed)
        return JSONResponse({"launch": self._launch_id, "changed": changed}, headers=NO_STORE)

    async def peek(self, request: Request) -> Response:
        """The text of one listed file."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        path = request.query_params.get("path")
        if path is None:
            return _refused(400, "the query is ?path=<file>")
        chosen = await self._session_of(request)
        if isinstance(chosen, JSONResponse):
            return chosen
        found = await run_in_threadpool(self._peek, chosen[1], path)
        if found is None:
            return _refused(400, "not a file this page lists")
        return JSONResponse(
            {
                "path": path,
                "text": found.text,
                "truncated": found.truncated,
                "frontmatter": found.frontmatter,
                "body": found.body,
            },
            headers=NO_STORE,
        )

    def _peek(self, session: XraySession, path: str) -> XrayPeek | None:
        with self._view_lock:
            return session.peek(path)

    async def _text_route(self, request: Request, route: _TextRoute) -> Response:
        """Guard the request, read `?<query>=` and reply `{"id", ...}` with the fields the route's lookup finds in the
        session the request is on."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        chosen = await self._session_of(request)
        if isinstance(chosen, JSONResponse):
            return chosen
        key = request.query_params.get(route.query)
        if key is None:
            return _refused(400, route.hint)
        try:
            fields = await run_in_threadpool(self._locked, route.lookup, chosen[1], key)
        except PayloadRefused as err:
            return _refused(400, err.reason)
        if fields is None:
            return _refused(400, route.unknown)
        return JSONResponse({"id": key, **fields}, headers=NO_STORE)

    def _locked(
        self, lookup: Callable[[XraySession, str], JsonObject | None], session: XraySession, key: str
    ) -> JsonObject | None:
        with self._view_lock:
            return lookup(session, key)

    async def brief(self, request: Request) -> Response:
        """The brief one listed subagent was given."""
        return await self._text_route(
            request,
            _TextRoute(
                "subagent",
                "the query is ?subagent=<id>",
                _text_fields(XraySession.brief),
                "not a subagent this page lists",
            ),
        )

    async def system(self, request: Request) -> Response:
        """The system prompt one launched agent type was sent with."""
        return await self._text_route(
            request,
            _TextRoute(
                "type",
                "the query is ?type=<agent type>",
                _text_fields(XraySession.system_prompt),
                "not an agent type this session launched with a recorded request",
            ),
        )

    async def prompt(self, request: Request) -> Response:
        """The text of one typed prompt of the session."""
        return await self._text_route(
            request,
            _TextRoute(
                "id", "the query is ?id=<prompt id>", _text_fields(XraySession.prompt), "not a prompt this page lists"
            ),
        )

    async def call(self, request: Request) -> Response:
        """One call of the session: its tool, command, input and result excerpt."""
        return await self._text_route(
            request, _TextRoute("id", "the query is ?id=<call id>", _call_fields, "not a call this page lists")
        )

    async def first_prompt(self, request: Request) -> Response:
        """The text of the first typed prompt of a session, read when asked for and never kept."""
        return await self._text_route(
            request,
            _TextRoute(
                "session",
                "the query is ?session=<id>",
                _text_fields(lambda session, _key: session.first_prompt()),
                "the session has no typed prompt",
            ),
        )

    async def check(self, request: Request) -> Response:
        """Check one file and reply with its findings."""
        target = await self._target(request)
        if isinstance(target, JSONResponse):
            return target
        return await run_in_threadpool(self._check, target)

    def _check(self, target: Path) -> JSONResponse:
        with self._work_lock:
            run = check_path(str(target), self._root)
            if isinstance(run, Refusal):
                return _refused(400, run.text)
            found = file_findings(run, target)
            key = self._key(target)
            with self._view_lock:
                self._findings[key] = tally_of(found)
            return JSONResponse(
                {
                    "path": str(target),
                    "findings": len(found),
                    "lines": [_line(f) for f in found],
                    "fix_command": f"ails check {shlex.quote(key)} --heal",
                }
            )

    def launch_check(self) -> None:
        """Check the whole project once and hold the tally of every file it covers; any failure lands as refused."""
        with self._work_lock:
            outcome, tallies = self._launch_outcome()
            with self._view_lock:
                self._findings.update(tallies)
                self._launch = outcome

    def _launch_outcome(self) -> tuple[XrayCheck, dict[str, FindingTally]]:
        """The launch check's state and the tally of every file it covers; a failed check is refused with its text."""
        try:
            run = check_path(str(self._root), self._root)
            if isinstance(run, Refusal):
                return XrayCheck("refused", run.text), {}
            return XrayCheck("done", None), tallies_by_file(run)
        except Exception as err:  # pylint: disable=broad-exception-caught  # thread boundary: any failure lands as refused
            logger.warning("the launch check failed: %s", err)
            return XrayCheck("refused", str(err)), {}

    async def heal(self, request: Request) -> Response:
        """Heal one file and reply with the receipt."""
        target = await self._target(request)
        if isinstance(target, JSONResponse):
            return target
        return await run_in_threadpool(self._heal, target)

    def _heal(self, target: Path) -> JSONResponse:
        with self._work_lock:
            outcome = heal_one(str(target), self._root)
            with self._view_lock:
                self._findings.pop(self._key(target), None)
            if outcome.written is None:
                receipt = [outcome.withheld]
            else:
                written = outcome.written
                text = render_heal_apply(written.fixes, written.decisions, written.put_back, outcome.scan_root)
                receipt = text.split("\n")
            return JSONResponse({"path": str(target), "receipt": receipt})

    def _key(self, target: Path) -> str:
        return target.relative_to(safe_resolve(self._root)).as_posix()


@dataclass(frozen=True)
class _TextRoute:
    """A route that replies with a text found by id: the query key it reads, the refusal for a missing key, what finds
    the text and the refusal for an id it does not know."""

    query: str
    hint: str
    lookup: Callable[[XraySession, str], JsonObject | None]
    unknown: str


def _text_fields(lookup: Callable[[XraySession, str], str | None]) -> Callable[[XraySession, str], JsonObject | None]:
    """A lookup that finds a text, as one that finds the reply's `text` field."""

    def fields(session: XraySession, key: str) -> JsonObject | None:
        text = lookup(session, key)
        return None if text is None else {"text": text}

    return fields


def _call_fields(session: XraySession, key: str) -> JsonObject | None:
    """The reply fields of a call the session names: its tool, command, input and result excerpt."""
    detail = session.call(key)
    if detail is None:
        return None
    return {
        "tool": detail.tool,
        "text": detail.text,
        "input": detail.input,
        "result": detail.result,
        "truncated": detail.truncated,
    }


def _line(finding: FindingItem) -> JsonObject:
    """One finding as the page shows it."""
    return {
        "line": finding.line,
        "rule": finding.rule,
        "message": finding.message,
        "severity": finding.severity,
        "title": rule_title(finding.rule),
        "category": rule_category(finding.rule),
        "file_level": finding.check_id in file_level_check_ids() or finding.line == 0,
        "docs_url": rule_docs_url(finding.rule),
    }


class RequestClock:
    """When the page last received a request."""

    def __init__(self) -> None:
        self._last = time.monotonic()

    def mark(self) -> None:
        """Record a request now."""
        self._last = time.monotonic()

    def quiet_s(self) -> float:
        """Seconds since the last request."""
        return time.monotonic() - self._last


def _mark_requests(app: ASGIApp, requests: RequestClock) -> ASGIApp:
    """`app` with every HTTP request marked on the clock before it is passed on."""

    async def marked(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            requests.mark()
        await app(scope, receive, send)

    return marked


def build_app(
    root: Path,
    session_file: Path,
    *,
    picked: SessionPick,
    token: str,
    launch: str,
    port: int,
    requests: RequestClock,
) -> Starlette:
    """The page server, opening on `session_file` chosen as `picked`: the fixed routes behind the host, origin,
    token and path guards, each request marked on `requests`."""
    server = XrayServer(safe_resolve(root), session_file, picked=picked, token=token, launch=launch, port=port)
    page = get_xray_path()

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        threading.Thread(target=server.launch_check, daemon=True).start()
        yield

    return Starlette(
        lifespan=lifespan,
        routes=[
            Route("/", server.page, methods=["GET"]),
            Route("/view", server.view, methods=["GET"]),
            Route("/peek", server.peek, methods=["GET"]),
            Route("/brief", server.brief, methods=["GET"]),
            Route("/system", server.system, methods=["GET"]),
            Route("/prompt", server.prompt, methods=["GET"]),
            Route("/call", server.call, methods=["GET"]),
            Route("/sessions", server.sessions, methods=["GET"]),
            Route("/first-prompt", server.first_prompt, methods=["GET"]),
            Route("/launch", server.launch, methods=["GET"]),
            Route("/check", server.check, methods=["POST"]),
            Route("/heal", server.heal, methods=["POST"]),
            Mount("/static", StaticFiles(directory=page)),
        ],
        middleware=[
            Middleware(TrustedHostMiddleware, allowed_hosts=[HOST]),
            Middleware(_mark_requests, requests=requests),
        ],
    )


def bound_socket() -> socket.socket:
    """A listening socket on `127.0.0.1` at a free port, so the port is known before the page address prints."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    sock.listen(16)
    return sock


def _stop_when_idle(server: uvicorn.Server, requests: RequestClock, idle_s: int, stopped: threading.Event) -> None:
    """Tell the server to stop once no request has come for `idle_s` seconds, and set `stopped`."""
    while (left := idle_s - requests.quiet_s()) > 0:
        time.sleep(left)
    stopped.set()
    server.should_exit = True


def _span(seconds: int) -> str:
    """`seconds` in whole minutes when it is one, else in seconds."""
    count, unit = (seconds // 60, "minute") if seconds % 60 == 0 else (seconds, "second")
    return f"{count} {unit}{'' if count == 1 else 's'}"


def _run(server: uvicorn.Server, sock: socket.socket, requests: RequestClock, idle_s: int | None) -> None:
    """Serve on `sock` until stopped, stopping after `idle_s` seconds with no request when given; say so when that
    is why it stopped."""
    idle_stop = threading.Event()
    if idle_s is not None:
        threading.Thread(target=_stop_when_idle, args=(server, requests, idle_s, idle_stop), daemon=True).start()
    server.run(sockets=[sock])
    if idle_s is not None and idle_stop.is_set():
        typer.echo(f"The x-ray page stopped: no request for {_span(idle_s)}.")


def serve(root: Path, session_file: Path, picked: SessionPick, *, open_page: bool) -> None:
    """Serve the page opening on `session_file` until interrupted, or until no request has come for
    `AILS_XRAY_IDLE_S` seconds (30 minutes by default; 0 never stops); print its address and open it unless told
    not to.

    The project's page record names this process while it serves."""
    sock = bound_socket()
    port = sock.getsockname()[1]
    launch = secrets.token_urlsafe(16)
    requests = RequestClock()
    app = build_app(
        root,
        session_file,
        picked=picked,
        token=secrets.token_urlsafe(32),
        launch=launch,
        port=port,
        requests=requests,
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    idle_s = parse_idle_timeout_env("AILS_XRAY_IDLE_S", _DEFAULT_IDLE_S)
    url = f"http://{HOST}:{port}/"
    recorded = False
    try:
        register_page(safe_resolve(root), port, launch)
        recorded = True
    except OSError as exc:
        logger.warning("the x-ray page will not be reused by a later `ails xray` or agent call: %s", exc)
    try:
        stops = "" if idle_s is None else f"; it stops after {_span(idle_s)} with no request"
        typer.echo(f"{xray_line(session_file.stem, url, picked)}  (Ctrl-C to stop{stops})")
        if open_page:
            open_in_browser(url)
        _run(server, sock, requests, idle_s)
    finally:
        if recorded:
            forget_page(safe_resolve(root), launch)
