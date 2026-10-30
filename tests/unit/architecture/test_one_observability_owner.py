"""Logging setup and run timing live only in `core/platform/observability/`.

Two rules, pure `ast`, over every `src/reporails_cli/**/*.py` outside that folder:

- O1 logging configuration: a call to `logging.basicConfig`, anything under `logging.config`, and a
  `.setLevel(`, `.addHandler(` or `.removeHandler(` call on any object.
- O2 hand timing: a reference to `time.perf_counter`, `time.perf_counter_ns` or `time.process_time`
  (through `import time`, an alias of it, or a name imported from `time`). `time.monotonic` deadlines
  are not stage timing and pass.

Why: handlers, levels and clocks set in many places give each entry point its own output and its own
numbers. One owner gives every entry point the same stderr and the same timeline.

The scanners take the source files and their root, so the planted tests run the same code on tmp files.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.unit.architecture._module_aliases import module_names

pytestmark = pytest.mark.architecture

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
OWNER_DIR = "core/platform/observability/"

_LOGGER_MUTATORS = {"setLevel", "addHandler", "removeHandler"}
_LOGGING_CONFIG_NAMES = {"basicConfig", "config"}
_CLOCKS = {"perf_counter", "perf_counter_ns", "process_time"}


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line."""

    rule: str
    detail: str


def _outside_owner(sources: list[Path], root: Path) -> list[tuple[str, ast.Module]]:
    out = []
    for py in sources:
        rel = py.relative_to(root).as_posix()
        if rel.startswith(OWNER_DIR):
            continue
        out.append((rel, ast.parse(py.read_text(encoding="utf-8"))))
    return out


def logging_config_violations(sources: list[Path], root: Path) -> list[Violation]:
    """O1: logging configured outside the observability folder."""
    out: list[Violation] = []
    for rel, tree in _outside_owner(sources, root):
        logging_names = module_names(tree, "logging")
        called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                out.extend(
                    Violation("O1", f"{rel}:{node.lineno} imports {alias.name}")
                    for alias in node.names
                    if alias.name == "logging.config"
                )
            elif isinstance(node, ast.ImportFrom):
                if node.module == "logging.config":
                    out.append(Violation("O1", f"{rel}:{node.lineno} imports from logging.config"))
                elif node.module == "logging":
                    out.extend(
                        Violation("O1", f"{rel}:{node.lineno} imports logging.{alias.name}")
                        for alias in node.names
                        if alias.name in _LOGGING_CONFIG_NAMES
                    )
            elif isinstance(node, ast.Attribute):
                value = node.value
                if isinstance(value, ast.Name) and value.id in logging_names and node.attr in _LOGGING_CONFIG_NAMES:
                    out.append(Violation("O1", f"{rel}:{node.lineno} uses logging.{node.attr}"))
                elif node.attr in _LOGGER_MUTATORS and id(node) in called:
                    out.append(Violation("O1", f"{rel}:{node.lineno} calls .{node.attr}("))
    return out


def hand_timing_violations(sources: list[Path], root: Path) -> list[Violation]:
    """O2: a wall or CPU clock read outside the observability folder."""
    out: list[Violation] = []
    for rel, tree in _outside_owner(sources, root):
        time_names = module_names(tree, "time")
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "time":
                out.extend(
                    Violation("O2", f"{rel}:{node.lineno} imports time.{alias.name}")
                    for alias in node.names
                    if alias.name in _CLOCKS
                )
            elif (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in time_names
                and node.attr in _CLOCKS
            ):
                out.append(Violation("O2", f"{rel}:{node.lineno} uses time.{node.attr}"))
    return out


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def test_logging_is_configured_only_in_observability() -> None:
    """O1: no handler, level or basicConfig call outside core/platform/observability/."""
    found = logging_config_violations(_src_files(), SRC)
    lines = [f"{len(found)} O1 violation(s): configure logging in core/platform/observability/log_levels.py"]
    lines.extend(f"  {v.detail}" for v in found)
    assert not found, "\n".join(lines)


def test_timing_is_read_only_in_observability() -> None:
    """O2: no perf_counter or process_time outside core/platform/observability/."""
    found = hand_timing_violations(_src_files(), SRC)
    lines = [f"{len(found)} O2 violation(s): time through core/platform/observability/stage_timer.py"]
    lines.extend(f"  {v.detail}" for v in found)
    assert not found, "\n".join(lines)


# ---- planted cases -------------------------------------------------------------------------


def _plant(tmp_path: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ("import logging\nlogging.basicConfig()\n", "mod.py:2 uses logging.basicConfig"),
        ("import logging as lg\nlg.basicConfig()\n", "mod.py:2 uses logging.basicConfig"),
        ("from logging import basicConfig\n", "mod.py:1 imports logging.basicConfig"),
        ("import logging.config\n", "mod.py:1 imports logging.config"),
        ("from logging.config import dictConfig\n", "mod.py:1 imports from logging.config"),
        ("import logging.handlers\nlogging.basicConfig(level=10)\n", "mod.py:2 uses logging.basicConfig"),
        ("import logging\nlogging.getLogger('x').setLevel(10)\n", "mod.py:2 calls .setLevel("),
        ("def f(log, h):\n    log.addHandler(h)\n", "mod.py:2 calls .addHandler("),
        ("def f(log, h):\n    log.removeHandler(h)\n", "mod.py:2 calls .removeHandler("),
    ],
)
def test_o1_logging_configuration_fires(tmp_path: Path, body: str, detail: str) -> None:
    """Each way of configuring logging outside the owner is flagged with its site."""
    found = logging_config_violations(_plant(tmp_path, {"mod.py": body}), tmp_path)
    assert [v.detail for v in found] == [detail]


@pytest.mark.parametrize(
    ("name", "body"),
    [
        (f"{OWNER_DIR}log_levels.py", "import logging\nlogging.getLogger('x').setLevel(10)\n"),
        ("mod.py", "import logging\nlog = logging.getLogger(__name__)\nlog.warning('x')\n"),
        ("mod.py", "def setLevel():\n    pass\nsetLevel()\n"),
    ],
)
def test_o1_owner_and_plain_logging_are_quiet(tmp_path: Path, name: str, body: str) -> None:
    """The owner folder, plain `getLogger` use and an unrelated function name pass."""
    assert logging_config_violations(_plant(tmp_path, {name: body}), tmp_path) == []


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ("import time\nt = time.perf_counter()\n", "mod.py:2 uses time.perf_counter"),
        ("import time as t\nx = t.perf_counter_ns()\n", "mod.py:2 uses time.perf_counter_ns"),
        ("import time\nx = time.process_time()\n", "mod.py:2 uses time.process_time"),
        ("import time.zone\nx = time.perf_counter()\n", "mod.py:2 uses time.perf_counter"),
        ("from time import perf_counter\n", "mod.py:1 imports time.perf_counter"),
    ],
)
def test_o2_hand_timing_fires(tmp_path: Path, body: str, detail: str) -> None:
    """Each clock read outside the owner is flagged with its site."""
    found = hand_timing_violations(_plant(tmp_path, {"mod.py": body}), tmp_path)
    assert [v.detail for v in found] == [detail]


@pytest.mark.parametrize(
    ("name", "body"),
    [
        (f"{OWNER_DIR}stage_timer.py", "import time\nt = time.perf_counter()\n"),
        ("mod.py", "import time\nt = time.monotonic()\ntime.sleep(1)\n"),
    ],
)
def test_o2_owner_and_monotonic_deadlines_are_quiet(tmp_path: Path, name: str, body: str) -> None:
    """The owner folder and `time.monotonic` deadlines pass."""
    assert hand_timing_violations(_plant(tmp_path, {name: body}), tmp_path) == []
