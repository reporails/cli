"""Shared behave support — build a real project on disk and drive the real `ails` CLI.

Every behavioral feature builds a tmp project (a git repo with instruction files)
and shells out to the actual `ails` console script the user/harness invokes. These
helpers are the single foundation so each feature's steps stay thin and consistent.

The top of the test pyramid: nothing here runs the CLI in-process (no `CliRunner`) —
every assertion is against the real binary's stdout / exit code / persisted state.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote

from reporails_cli.core.mapper.daemon import pid_path, socket_path
from reporails_cli.core.platform.config.bootstrap import get_reporails_home
from tests.suite_env import suite_env

# The real console script (`[project.scripts] ails = …:app`), installed in the
# venv `uv run behave` runs in. None when not installed — a step asserts on it so
# a missing binary fails loudly, never passes vacuously.
AILS_BIN = shutil.which("ails")

# The MCP server console script (`reporails-mcp`); the property scenarios drive `validate` over stdio.
MCP_BIN = shutil.which("reporails-mcp")

FIXTURE_PROJECTS = Path(__file__).resolve().parents[1] / "fixtures" / "projects"

# The local dev stack the api-backed scenarios run against; never a hosted address.
LOCAL_API_URL = os.environ.get("AILS_LOCAL_API_URL", "http://localhost:8001")
LOCAL_API_ENV = {"AILS_SERVER_URL": LOCAL_API_URL, "AILS_DEV_MODE": "true", "AILS_TIER": "pro"}


def _encode_budget() -> dict[str, str]:
    """The encode-pool size a parallel run grants each `ails` (`BEHAVE_ENCODE_WORKERS`, set by the parallel runner).

    `suite_env` strips every ambient `AILS_*` key, so the budget travels under a name of its own.
    """
    workers = os.environ.get("BEHAVE_ENCODE_WORKERS")
    return {"AILS_MAP_ENCODE_WORKERS": workers} if workers else {}


def scenario_home(tmpdir: Path, real_models: Path) -> Path:
    """A home of the scenario's own, so the developer's sign-in and config never reach the binary.

    The downloaded model set is shared into it when the machine has one, so no scenario downloads.
    """
    home = tmpdir / "home"
    models = home / ".reporails" / "cache" / "models"
    models.parent.mkdir(parents=True, exist_ok=True)
    if real_models.is_dir():
        with contextlib.suppress(OSError):  # no symlink privilege (Windows): the run works offline without the model
            models.symlink_to(real_models, target_is_directory=True)
    return home


def stop_xray_pages(home: Path) -> None:
    """Kill every x-ray page process the scenario's own home records, so no server outlives its scenario."""
    for record in (home / ".reporails" / "xray-pages").glob("*.json"):
        with contextlib.suppress(OSError, ValueError, KeyError):
            os.kill(
                int(json.loads(record.read_text(encoding="utf-8"))["pid"]), getattr(signal, "SIGKILL", signal.SIGTERM)
            )  # Windows has no SIGKILL; SIGTERM ends the process there


def daemon_started(home: Path) -> bool:
    """True when a mapper daemon left its pid or socket file under the scenario's own home."""
    real = get_reporails_home()
    return any((home / ".reporails" / p.relative_to(real)).exists() for p in (pid_path(), socket_path()))


def build_project(root: Path) -> Path:
    """Create a real git project under ``root`` and return its path.

    A git repo so `ails check` does not emit the `Not a git repository` governance
    finding as noise; steps layer the instruction files (a `CLAUDE.md`) on top.
    """
    project = root / "project"
    project.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.email", "behave@ails"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.name", "behave"], cwd=project, check=True)
    return project


def write_claude(project: Path, content: str) -> Path:
    """Write ``content`` to ``project/CLAUDE.md`` (the instruction file under test)."""
    target = project / "CLAUDE.md"
    target.write_text(content, encoding="utf-8")
    return target


def run_ails(
    project: Path, *args: str, home: Path, timeout: int = 120, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run ``ails <args>`` with ``project`` as cwd; return the CompletedProcess.

    Runs from the project dir with no target so `ails` scans the whole project —
    the way a user invokes it in their repo. Forces a wide, color-free render so
    literal token assertions are not split by ANSI styling or column wrapping.
    Does NOT assert on the return code — a scenario testing `--strict` needs the
    non-zero exit, so the exit-code assertion belongs in the step. `env` adds to the
    environment the binary runs in. `home` is the scenario's own home: `HOME` and `USERPROFILE` always point there.
    No ambient `AILS_*` setting reaches the binary: it starts from `suite_env`.
    """
    assert AILS_BIN is not None, "`ails` console script not on PATH (run via `uv run behave`)"
    run_env = {
        **suite_env(os.environ),
        **_encode_budget(),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "COLUMNS": "200",
        "NO_COLOR": "1",
        **(env or {}),
    }
    return subprocess.run(
        [str(AILS_BIN), *args],
        cwd=str(project),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        env=run_env,
    )


def document(result: subprocess.CompletedProcess[str]) -> dict:
    """Parse the whole `--format json` envelope (files map, surface_health, level, …)."""
    return json.loads(result.stdout)


def findings(result: subprocess.CompletedProcess[str]) -> list[dict]:
    """Flatten every per-file finding from a `--format json` result into one list."""
    return [f for record in document(result).get("files", {}).values() for f in record.get("findings", [])]


# ---------------------------------------------------------------------------
# Property helpers — one run through every output format, read back as finding sets
# ---------------------------------------------------------------------------

FORMATS = ("text", "json", "github", "mcp")
RULE_ID = re.compile(r"\b[A-Z]+:[A-Z]:\d{4}\b")
_GITHUB_ANNOTATION = re.compile(r"^::(?P<level>error|warning|notice) (?P<props>.*?)::(?P<message>.*)$")


def fixture_project(root: Path, name: str) -> Path:
    """A real git project holding a copy of the shared fixture ``name`` (`tests/fixtures/projects/<name>`)."""
    source = FIXTURE_PROJECTS / name
    assert source.is_dir(), f"no fixture project {name!r} under {FIXTURE_PROJECTS}"
    project = build_project(root)
    shutil.copytree(source, project, dirs_exist_ok=True)
    return project


def write_config(project: Path, text: str) -> Path:
    """Write ``text`` as the project's `.ails/config.yml` — the persisted config a user edits."""
    target = project / ".ails" / "config.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def local_api_answers() -> bool:
    """True when the local dev api answers `/health` with 200; a closed port or any other status is False."""
    try:
        with urllib.request.urlopen(f"{LOCAL_API_URL}/health", timeout=3) as response:
            return bool(response.status == 200)
    except (urllib.error.URLError, OSError, ValueError):
        return False


def rule_ids_in(node: object) -> Iterator[str]:
    """Every string found under a ``rule`` key anywhere in a JSON-shaped payload."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "rule" and isinstance(value, str):
                yield value
            else:
                yield from rule_ids_in(value)
    elif isinstance(node, list):
        for item in node:
            yield from rule_ids_in(item)


async def _mcp_validate(project: Path, env: dict[str, str]) -> dict:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    assert MCP_BIN is not None, "`reporails-mcp` console script not on PATH (run via `uv run behave`)"
    params = StdioServerParameters(command=str(MCP_BIN), env=env, cwd=str(project))
    # behave replaces `sys.stderr` with an object that has no file descriptor, which the child process needs.
    with open(os.devnull, "w", encoding="utf-8") as server_log:
        async with stdio_client(params, errlog=server_log) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            reply = await session.call_tool("validate", {"path": str(project), "full": True})
    assert not reply.is_error, f"MCP validate errored: {reply.content}"
    return json.loads(reply.content[0].text)


def run_mcp_validate(project: Path, *, home: Path, env: dict[str, str] | None = None) -> dict:
    """The full `validate` payload the MCP server returns for ``project`` — same environment rules as `run_ails`."""
    run_env = {
        **suite_env(os.environ),
        **_encode_budget(),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "NO_COLOR": "1",
        **(env or {}),
    }
    return asyncio.run(asyncio.wait_for(_mcp_validate(project, run_env), timeout=180))


def run_all_formats(project: Path, *, home: Path, env: dict[str, str] | None = None, strict: bool = False) -> dict:
    """One run per output format over ``project``: ``{"text"|"json"|"github": CompletedProcess, "mcp": payload}``."""
    extra = ["--strict"] if strict else []
    return {
        "text": run_ails(project, "check", "-v", *extra, home=home, env=env),
        "json": run_ails(project, "check", "--format", "json", *extra, home=home, env=env),
        "github": run_ails(project, "check", "--format", "github", *extra, home=home, env=env),
        "mcp": run_mcp_validate(project, home=home, env=env),
    }


# The workflow command a finding of each severity is annotated with.
_ANNOTATION_LEVEL = {"error": "error", "warning": "warning", "info": "notice"}


def json_finding_keys(payload: dict) -> list[tuple[str, str, int, str]]:
    """(file, rule, line, annotation level) of every per-file finding in a json / MCP payload, sorted."""
    return sorted(
        (path, f["rule"], int(f.get("line", 0)), _ANNOTATION_LEVEL[f["severity"]])
        for path, record in payload.get("files", {}).items()
        for f in record.get("findings", [])
    )


def github_finding_keys(stdout: str) -> list[tuple[str, str, int, str]]:
    """(file, rule, line, level) of every `--format github` annotation that names a file, sorted."""
    keys: list[tuple[str, str, int, str]] = []
    for raw in stdout.splitlines():
        match = _GITHUB_ANNOTATION.match(raw)
        if match is None:
            continue
        props = dict(part.split("=", 1) for part in match["props"].split(",") if "=" in part)
        if "file" not in props:
            continue  # a run-level notice (the server could not be reached), not a finding
        title = unquote(props.get("title", ""))
        assert title.startswith("[") and title.endswith("]"), f"github annotation title is not a [rule]: {raw}"
        keys.append((unquote(props["file"]), title[1:-1], int(props.get("line", 0)), match["level"]))
    return sorted(keys)


def text_finding_rules(stdout: str) -> list[str]:
    """The rule id of every finding line in a `check -v` text report, sorted.

    A finding line sits inside a file's box (`│ …`) and ends with its rule id.
    """
    return sorted(
        match["rule"]
        for raw in stdout.splitlines()
        if (match := re.match(r"^\s*│\s+.*\s(?P<rule>[A-Z]+:[A-Z]:\d{4})\s*$", raw))
    )


# ---------------------------------------------------------------------------
# One headless Chrome per behave process, shared by every x-ray page script
# ---------------------------------------------------------------------------


def start_shared_chrome() -> tuple[subprocess.Popen[bytes], Path, str] | None:
    """Start one headless Chrome on a free port; return (process, profile dir, CDP url), None without Chrome."""
    import socket as _socket
    import tempfile
    import time

    chrome = shutil.which(os.environ.get("CHROME_BIN", "google-chrome")) or shutil.which("chromium")
    if chrome is None:
        return None
    with _socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    profile = Path(tempfile.mkdtemp(prefix="ails-behave-chrome-"))
    process = subprocess.Popen(
        [
            chrome,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/json/version", timeout=1):
                return process, profile, url
        except (urllib.error.URLError, OSError):
            time.sleep(0.05)
    process.kill()
    shutil.rmtree(profile, ignore_errors=True)
    return None
