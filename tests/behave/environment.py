"""behave environment — per-scenario lifecycle for the behavioral demonstration tier.

Each scenario gets a fresh tmp directory (the synthetic project the steps populate
and the real `ails` binary scans) torn down after. No state leaks between scenarios
— the same isolation the pytest fixtures give the unit tier.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # `tests.suite_env`, shared with pytest

from support import (
    LOCAL_API_ENV,
    LOCAL_API_URL,
    daemon_started,
    local_api_answers,
    run_ails,
    scenario_home,
    start_shared_chrome,
    stop_xray_pages,
)


def before_all(context) -> None:
    # The pretty formatter holds the very sys.stdout object (formatter/base.py StreamOpener,
    # built before this hook), so reconfiguring it in place makes the report independent of the
    # console code page (a Windows cp1252 console cannot encode the feature text's arrows).
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    # The real model cache, read once with the real HOME, is shared into every scenario's own HOME.
    context.real_models = Path.home() / ".reporails" / "cache" / "models"
    context.api_up = local_api_answers()
    context.api_skipped = []
    # One browser serves every x-ray page script of this process (each opens its own tab in it).
    context.chrome = None if os.environ.get("XRAY_CDP_URL") else start_shared_chrome()
    if context.chrome is not None:
        os.environ["XRAY_CDP_URL"] = context.chrome[2]


def before_scenario(context, scenario) -> None:
    if "api" in scenario.tags and not context.api_up:
        context.api_skipped.append(scenario.name)
        scenario.skip(f"local api not answering at {LOCAL_API_URL} — api-backed scenario NOT run")
        return  # nothing is built for a skipped scenario, so nothing is left to tear down
    run_anyway = os.environ.get("AILS_RUN_WINDOWS_UNVERIFIED")
    if "windows_unverified" in scenario.tags and sys.platform == "win32" and not run_anyway:
        scenario.skip("not yet verified on Windows: this scenario fails there and is tracked for a fix")
        return
    context.tmpdir = Path(tempfile.mkdtemp(prefix="ails-behave-"))
    context.home = scenario_home(context.tmpdir, context.real_models)
    context.project = None  # the steps build it (a git project with instruction files)
    context.result = None  # the last CompletedProcess from a real `ails` run
    # `@api` scenarios point the binary at the local api
    context.run_env = dict(LOCAL_API_ENV) if "api" in scenario.tags else None


def after_all(context) -> None:
    if context.chrome is not None:
        process, profile, _ = context.chrome
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        shutil.rmtree(profile, ignore_errors=True)
        os.environ.pop("XRAY_CDP_URL", None)
    if context.api_skipped:
        banner = "!" * 78
        print(
            f"\n{banner}\nLOUD SKIP: {len(context.api_skipped)} api-backed scenario(s) did NOT run — "
            f"the local api is not answering at {LOCAL_API_URL}.\n"
            f"Start it, then re-run `uv run behave --tags=api`.\n{banner}",
            file=sys.__stderr__,  # behave captures `sys.stderr`; a skip must reach the terminal
        )


def after_scenario(context, scenario) -> None:
    if scenario.status == "skipped":
        return  # skipped before any setup ran: there is no home or tmp project to tear down
    tmpdir = getattr(context, "tmpdir", None)
    if tmpdir is not None and tmpdir.exists():
        stop_xray_pages(context.home)  # a detached x-ray page the scenario started must not outlive it
    if tmpdir is not None and tmpdir.exists() and daemon_started(context.home):
        # A check starts a mapper daemon under the scenario's own home; stop it before the home goes.
        run_ails(tmpdir, "daemon", "stop", home=context.home, timeout=30)
    if tmpdir is not None and tmpdir.exists():
        shutil.rmtree(tmpdir, ignore_errors=True)
