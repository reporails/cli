"""behave environment — per-scenario lifecycle for the behavioral demonstration tier.

Each scenario gets a fresh tmp directory (the synthetic project the steps populate
and the real `ails` binary scans) torn down after. No state leaks between scenarios
— the same isolation the pytest fixtures give the unit tier.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # `tests.suite_env`, shared with pytest

from support import run_ails, scenario_home


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


def before_scenario(context, scenario) -> None:
    context.tmpdir = Path(tempfile.mkdtemp(prefix="ails-behave-"))
    context.home = scenario_home(context.tmpdir, context.real_models)
    context.project = None  # the steps build it (a git project with instruction files)
    context.result = None  # the last CompletedProcess from a real `ails` run


def after_scenario(context, scenario) -> None:
    tmpdir = getattr(context, "tmpdir", None)
    if tmpdir is not None and tmpdir.exists():
        # A check starts a mapper daemon under the scenario's own home; stop it before the home goes.
        run_ails(tmpdir, "daemon", "stop", home=context.home, timeout=30)
    if tmpdir is not None and tmpdir.exists():
        shutil.rmtree(tmpdir, ignore_errors=True)
