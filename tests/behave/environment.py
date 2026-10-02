"""behave environment — per-scenario lifecycle for the behavioral demonstration tier.

Each scenario gets a fresh tmp directory (the synthetic project the steps populate
and the real `ails` binary scans) torn down after. No state leaks between scenarios
— the same isolation the pytest fixtures give the unit tier.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path


def before_scenario(context, scenario) -> None:
    context.tmpdir = Path(tempfile.mkdtemp(prefix="ails-behave-"))
    context.project = None  # the steps build it (a git project with instruction files)
    context.result = None  # the last CompletedProcess from a real `ails` run


def after_scenario(context, scenario) -> None:
    tmpdir = getattr(context, "tmpdir", None)
    if tmpdir is not None and tmpdir.exists():
        shutil.rmtree(tmpdir, ignore_errors=True)
