"""Records live in `core/platform/dto/` — no data-shape class is declared anywhere else under `core/`.

A record is a `@dataclass`, a `NamedTuple`, a `TypedDict` or a pydantic `BaseModel` subclass, in class or
call form. `core/platform/contract/` keeps its own typed contracts. No allowlist.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
CORE = ROOT / "src" / "reporails_cli" / "core"
_HOMES = ("platform/dto/", "platform/contract/")

_RECORD_BASES = frozenset({"NamedTuple", "TypedDict", "BaseModel"})
_RECORD_CALLS = frozenset({"namedtuple", "NamedTuple", "TypedDict", "make_dataclass"})


def _last_name(node: ast.expr) -> str:
    """The trailing name of `x`, `a.b.x` or `x(...)`."""
    if isinstance(node, ast.Call):
        return _last_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def records_in(source: str) -> list[str]:
    """Each record a module declares, as `<line> <name>`."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ClassDef):
            decorated = any(_last_name(d) == "dataclass" for d in node.decorator_list)
            based = any(_last_name(b) in _RECORD_BASES for b in node.bases)
            if decorated or based:
                found.append(f"{node.lineno} {node.name}")
        elif isinstance(node, ast.Call) and _last_name(node.func) in _RECORD_CALLS:
            found.append(f"{node.lineno} {_last_name(node.func)}(...)")
    return found


@pytest.mark.architecture
def test_records_live_in_dto() -> None:
    """No module under `core/` outside `platform/dto/` and `platform/contract/` declares a record."""
    assert CORE.is_dir(), f"{CORE} must exist"
    violations = [
        f"{py.relative_to(ROOT)}:{record}"
        for py in sorted(CORE.rglob("*.py"))
        if "__pycache__" not in py.parts and not py.relative_to(CORE).as_posix().startswith(_HOMES)
        for record in records_in(py.read_text(encoding="utf-8"))
    ]
    assert not violations, "records outside core/platform/dto/:\n  " + "\n  ".join(violations)


@pytest.mark.architecture
@pytest.mark.parametrize(
    "source",
    [
        "from dataclasses import dataclass\n@dataclass(frozen=True)\nclass A:\n    x: int\n",
        "import dataclasses\n@dataclasses.dataclass\nclass A:\n    x: int\n",
        "from typing import NamedTuple\nclass A(NamedTuple):\n    x: int\n",
        "import typing\nclass A(typing.TypedDict):\n    x: int\n",
        "from pydantic import BaseModel\nclass A(BaseModel):\n    x: int\n",
        "from collections import namedtuple\nA = namedtuple('A', 'x')\n",
        "from dataclasses import make_dataclass\nA = make_dataclass('A', ['x'])\n",
        "def f() -> None:\n    from typing import NamedTuple\n    class A(NamedTuple):\n        x: int\n",
    ],
)
def test_planted_record_is_found(source: str) -> None:
    """Each record form, planted, is reported."""
    assert records_in(source)


@pytest.mark.architecture
@pytest.mark.parametrize(
    "source",
    [
        "class A:\n    x: int = 0\n",
        "from enum import Enum\nclass A(Enum):\n    X = 1\n",
        "from typing import Protocol\nclass A(Protocol):\n    def f(self) -> int: ...\n",
        "from functools import cache\n@cache\ndef f() -> int:\n    return 1\n",
    ],
)
def test_non_record_class_is_not_reported(source: str) -> None:
    """A plain class, an enum, a protocol and a decorated function are not records."""
    assert records_in(source) == []
