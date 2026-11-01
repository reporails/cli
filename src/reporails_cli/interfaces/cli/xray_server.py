"""The local x-ray page server: serves the bundled page and translates its requests into core calls.

Binds `127.0.0.1` only. Every request is refused before any core call unless its `Host`, `Origin` (a POST),
launch token and file path pass; the routes only translate between HTTP and the core.
"""

from __future__ import annotations

import secrets
import shlex
import socket
import threading
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import typer
import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from reporails_cli.bundled import get_xray_path
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.heal.apply import heal_one, resolved_within
from reporails_cli.core.pipeline.check_one import Refusal, check_path, file_findings
from reporails_cli.core.platform.adapters.registry import file_level_check_ids
from reporails_cli.core.platform.adapters.rules_query import rule_category, rule_title
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import FindingItem
from reporails_cli.core.platform.dto.xray import FindingTally, XrayCheck
from reporails_cli.core.xray.session import XraySession
from reporails_cli.core.xray.tally import tallies_by_file, tally_of
from reporails_cli.formatters.mcp_view import render_heal_apply
from reporails_cli.formatters.text.rule_meta import rule_docs_url
from reporails_cli.interfaces.cli.helpers import open_in_browser

HOST = "127.0.0.1"
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


def _refused(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


class XrayServer:
    """One launch: the session being followed, the launch token, and the one-at-a-time lock on slow core calls."""

    def __init__(self, root: Path, session_file: Path, token: str, port: int) -> None:
        self._root = root
        self._session = XraySession(root, session_file)
        self._token = token
        self._origin = f"http://{HOST}:{port}"
        self._findings: dict[str, FindingTally] = {}
        self._launch = XrayCheck("running", None)
        self._view_lock = threading.Lock()
        self._work_lock = threading.Lock()

    def _wrong_token(self, request: Request) -> bool:
        sent = request.headers.get(TOKEN_HEADER, "")
        return not secrets.compare_digest(sent.encode(), self._token.encode())

    async def _guard(self, request: Request) -> JSONResponse | None:
        """The refusal for a request that carries no valid token (or, for a POST, a foreign `Origin`), else None."""
        if request.method == "POST" and request.headers.get("origin") != self._origin:
            return _refused(403, "foreign origin")
        if self._wrong_token(request):
            return _refused(403, "missing or wrong token")
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
        with self._view_lock:
            return self._session.acts_on(path)

    async def page(self, _request: Request) -> Response:
        """The bundled page with the launch token in it."""
        html = (get_xray_path() / "index.html").read_text(encoding="utf-8").replace(TOKEN_PLACEHOLDER, self._token)
        return Response(html, media_type="text/html", headers=PAGE_HEADERS)

    async def view(self, request: Request) -> Response:
        """The session view, `304` when its version is the one the page holds."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        payload, version = await run_in_threadpool(self._build_view)
        etag = f'"{version}"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(payload, headers={"ETag": etag, **NO_STORE})

    def _build_view(self) -> tuple[JsonObject, int]:
        with self._view_lock:
            self._session.refresh()
            view = self._session.view(self._findings, self._launch)
            return view.to_json(), view.version

    async def peek(self, request: Request) -> Response:
        """The text of one listed file."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        path = request.query_params.get("path")
        if path is None:
            return _refused(400, "the query is ?path=<file>")
        found = await run_in_threadpool(self._peek, path)
        if found is None:
            return _refused(400, "not a file this page lists")
        text, truncated = found
        return JSONResponse({"path": path, "text": text, "truncated": truncated}, headers=NO_STORE)

    def _peek(self, path: str) -> tuple[str, bool] | None:
        with self._view_lock:
            return self._session.peek(path)

    async def brief(self, request: Request) -> Response:
        """The brief one listed subagent was given."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        subagent = request.query_params.get("subagent")
        if subagent is None:
            return _refused(400, "the query is ?subagent=<id>")
        try:
            text = await run_in_threadpool(self._brief, subagent)
        except PayloadRefused as err:
            return _refused(400, err.reason)
        if text is None:
            return _refused(400, "not a subagent this page lists")
        return JSONResponse({"id": subagent, "text": text}, headers=NO_STORE)

    def _brief(self, subagent: str) -> str | None:
        with self._view_lock:
            return self._session.brief(subagent)

    async def prompt(self, request: Request) -> Response:
        """The text of one typed prompt of the session."""
        refusal = await self._guard(request)
        if refusal is not None:
            return refusal
        prompt_id = request.query_params.get("id")
        if prompt_id is None:
            return _refused(400, "the query is ?id=<prompt id>")
        try:
            text = await run_in_threadpool(self._prompt, prompt_id)
        except PayloadRefused as err:
            return _refused(400, err.reason)
        if text is None:
            return _refused(400, "not a prompt this page lists")
        return JSONResponse({"id": prompt_id, "text": text}, headers=NO_STORE)

    def _prompt(self, prompt_id: str) -> str | None:
        with self._view_lock:
            return self._session.prompt(prompt_id)

    async def check(self, request: Request) -> Response:
        """Check one file and reply with its findings."""
        target = await self._target(request)
        if isinstance(target, JSONResponse):
            return target
        return await run_in_threadpool(self._check, target)

    def _check(self, target: Path) -> JSONResponse:
        with self._work_lock:
            run = check_path(str(target))
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
        """Check the whole project once and hold the tally of every file it covers."""
        with self._work_lock:
            run = check_path(str(self._root))
        if isinstance(run, Refusal):
            outcome = XrayCheck("refused", run.text)
            tallies: dict[str, FindingTally] = {}
        else:
            outcome = XrayCheck("done", None)
            tallies = tallies_by_file(run)
        with self._view_lock:
            self._findings.update(tallies)
            self._launch = outcome

    async def heal(self, request: Request) -> Response:
        """Heal one file and reply with the receipt."""
        target = await self._target(request)
        if isinstance(target, JSONResponse):
            return target
        return await run_in_threadpool(self._heal, target)

    def _heal(self, target: Path) -> JSONResponse:
        with self._work_lock:
            outcome = heal_one(str(target))
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


def _line(finding: FindingItem) -> JsonObject:
    """One finding as the page shows it."""
    return {
        "line": finding.line,
        "rule": finding.rule,
        "message": finding.message,
        "severity": finding.severity,
        "title": rule_title(finding.rule),
        "category": rule_category(finding.rule),
        "file_level": finding.check_id in file_level_check_ids() or finding.line <= 1,
        "docs_url": rule_docs_url(finding.rule),
    }


def _static(name: str) -> Callable[[Request], Awaitable[Response]]:
    """The endpoint that serves one file of the bundled page."""

    async def endpoint(_request: Request) -> Response:
        return FileResponse(get_xray_path() / name)

    return endpoint


def build_app(root: Path, session_file: Path, token: str, port: int) -> Starlette:
    """The page server for one session: the fixed routes behind the host, origin, token and path guards."""
    server = XrayServer(safe_resolve(root), session_file, token, port)
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
            Route("/prompt", server.prompt, methods=["GET"]),
            Route("/check", server.check, methods=["POST"]),
            Route("/heal", server.heal, methods=["POST"]),
            Route("/xray.js", _static("xray.js"), methods=["GET"]),
            Route("/xray.css", _static("xray.css"), methods=["GET"]),
            Mount("/fonts", StaticFiles(directory=page / "fonts")),
        ],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=[HOST])],
    )


def bound_socket() -> socket.socket:
    """A listening socket on `127.0.0.1` at a free port, so the port is known before the page address prints."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    sock.listen(16)
    return sock


def serve(root: Path, session_file: Path, *, open_page: bool) -> None:
    """Serve the page for `session_file` until interrupted; print its address and open it unless told not to."""
    sock = bound_socket()
    port = sock.getsockname()[1]
    app = build_app(root, session_file, secrets.token_urlsafe(32), port)
    url = f"http://{HOST}:{port}/"
    typer.echo(f"x-ray of session {session_file.stem}: {url}  (Ctrl-C to stop)")
    if open_page:
        open_in_browser(url)
    uvicorn.Server(uvicorn.Config(app, log_level="warning")).run(sockets=[sock])
