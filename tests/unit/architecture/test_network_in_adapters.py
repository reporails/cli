"""Network I/O lives only in the driven adapters under `core/platform/adapters/`.

One rule, pure `ast`, over every `src/reporails_cli/core/**/*.py` outside `core/platform/adapters/`:

- N1 network use: an import of `httpx`, `socket`, `socketserver`, `ssl`, `urllib.request`, `http.client`
  or `http.server` (`import x`, `import x as y`, `import x.sub`, `from x import ...`, `from x.sub import
  ...`, `from urllib import request`, `from http import client|server`), at module or function level or
  under `if TYPE_CHECKING:`; `importlib.import_module("<one of them>")` or `__import__("<one of them>")`
  with a string constant; `urllib.request` reached as an attribute after `import urllib`; an attribute
  reference to `asyncio.open_connection`, `open_unix_connection`, `start_server` or `start_unix_server`
  (through `import asyncio` or an alias of it), or those names imported from `asyncio`.
  There is no allowlist.

Known limits: a module name built at run time (`import_module(name)`), `getattr(asyncio, "...")` and
a module reached through another module's re-export (`from some_core_module import socket`) are not
seen. Only `core/` is scanned.

Why: a connection opened in many places gets its timeout, TLS and error handling many ways. The
adapters own the wire and core receives ports.

The scanner takes the source files and their root, so the planted tests below run the same code on
tmp files.
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
CORE_DIR = "core/"
ADAPTERS_DIR = "core/platform/adapters/"

NETWORK_MODULES = frozenset({"httpx", "socket", "socketserver", "ssl", "urllib.request", "http.client", "http.server"})
ASYNCIO_OPENERS = frozenset({"open_connection", "open_unix_connection", "start_server", "start_unix_server"})


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line."""

    rule: str
    detail: str


def _is_network_module(name: str | None) -> bool:
    """True for a network module or a submodule of one."""
    return any(name == m or (name or "").startswith(f"{m}.") for m in NETWORK_MODULES)


def _import_hits(node: ast.AST) -> list[str]:
    """Network modules an import statement brings in."""
    if isinstance(node, ast.Import):
        return [a.name for a in node.names if _is_network_module(a.name)]
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        if _is_network_module(node.module):
            return [node.module]
        return [f"{node.module}.{a.name}" for a in node.names if _is_network_module(f"{node.module}.{a.name}")]
    return []


def _dynamic_import_hit(node: ast.AST) -> str | None:
    """The network module named by `importlib.import_module("m")`, `import_module("m")` or `__import__("m")`."""
    if not (isinstance(node, ast.Call) and node.args):
        return None
    func = node.func
    called = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    arg = node.args[0]
    if (
        called in {"import_module", "__import__"}
        and isinstance(arg, ast.Constant)
        and isinstance(arg.value, str)
        and _is_network_module(arg.value)
    ):
        return arg.value
    return None


def _asyncio_hit(node: ast.AST, aliases: set[str]) -> str | None:
    """The asyncio opener `node` references, or None."""
    if (
        isinstance(node, ast.Attribute)
        and node.attr in ASYNCIO_OPENERS
        and isinstance(node.value, ast.Name)
        and node.value.id in aliases
    ):
        return f"asyncio.{node.attr}"
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "asyncio":
        for alias in node.names:
            if alias.name in ASYNCIO_OPENERS:
                return f"asyncio.{alias.name}"
    return None


def _node_hits(node: ast.AST, asyncio_names: set[str], urllib_names: set[str]) -> list[str]:
    """Every network use one node stands for."""
    found = _import_hits(node)
    for hit in (_dynamic_import_hit(node), _asyncio_hit(node, asyncio_names)):
        if hit:
            found.append(hit)
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and isinstance(node.value, ast.Name)
        and node.value.id in urllib_names
    ):
        found.append("urllib.request")
    return found


def network_violations(sources: list[Path], root: Path) -> list[Violation]:
    """N1: network I/O named under `core/` outside `core/platform/adapters/`."""
    out: set[Violation] = set()
    for py in sources:
        rel = py.relative_to(root).as_posix()
        if not rel.startswith(CORE_DIR) or rel.startswith(ADAPTERS_DIR):
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        asyncio_names = module_names(tree, "asyncio")
        urllib_names = module_names(tree, "urllib")
        for node in ast.walk(tree):
            line = getattr(node, "lineno", 0)
            out.update(
                Violation("N1", f"{rel}:{line} uses {name}") for name in _node_hits(node, asyncio_names, urllib_names)
            )
    return sorted(out, key=lambda v: v.detail)


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def test_network_io_lives_only_in_the_adapters() -> None:
    """N1: no network module or connection opener under core outside `core/platform/adapters/`."""
    found = network_violations(_src_files(), SRC)
    lines = [f"{len(found)} N1 violation(s): reach the network through an adapter port"]
    lines.extend(f"  {v.detail}" for v in found)
    assert not found, "\n".join(lines)


# ---- planted cases -------------------------------------------------------------------------


def _details(tmp_path: Path, name: str, body: str) -> list[str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return [v.detail for v in network_violations([path], tmp_path)]


RED_CASES = [
    ("import httpx\n", "core/x/mod.py:1 uses httpx"),
    ("import httpx as h\n", "core/x/mod.py:1 uses httpx"),
    ("import httpx.sub\n", "core/x/mod.py:1 uses httpx.sub"),
    ("from httpx import Client\n", "core/x/mod.py:1 uses httpx"),
    ("from httpx.sub import Client\n", "core/x/mod.py:1 uses httpx.sub"),
    ("import socket\n", "core/x/mod.py:1 uses socket"),
    ("import socket as s\n", "core/x/mod.py:1 uses socket"),
    ("from socket import socket\n", "core/x/mod.py:1 uses socket"),
    ("import socketserver\n", "core/x/mod.py:1 uses socketserver"),
    ("import ssl\n", "core/x/mod.py:1 uses ssl"),
    ("import ssl as t\n", "core/x/mod.py:1 uses ssl"),
    ("from ssl import create_default_context\n", "core/x/mod.py:1 uses ssl"),
    ("import urllib.request\n", "core/x/mod.py:1 uses urllib.request"),
    ("import urllib.request as ur\n", "core/x/mod.py:1 uses urllib.request"),
    ("from urllib.request import urlopen\n", "core/x/mod.py:1 uses urllib.request"),
    ("from urllib import request\n", "core/x/mod.py:1 uses urllib.request"),
    ("import http.client\n", "core/x/mod.py:1 uses http.client"),
    ("import http.client as hc\n", "core/x/mod.py:1 uses http.client"),
    ("from http.client import HTTPSConnection\n", "core/x/mod.py:1 uses http.client"),
    ("from http import client\n", "core/x/mod.py:1 uses http.client"),
    ("import http.server\n", "core/x/mod.py:1 uses http.server"),
    ("from http import server\n", "core/x/mod.py:1 uses http.server"),
    ("def f():\n    import socket\n", "core/x/mod.py:2 uses socket"),
    ("def f():\n    from http.client import HTTPConnection\n", "core/x/mod.py:2 uses http.client"),
    ("from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import httpx\n", "core/x/mod.py:3 uses httpx"),
    ("import urllib\nurllib.request.urlopen(u)\n", "core/x/mod.py:2 uses urllib.request"),
    ("import asyncio\nasyncio.open_unix_connection(p)\n", "core/x/mod.py:2 uses asyncio.open_unix_connection"),
    ("import asyncio as aio\naio.open_connection(h, 1)\n", "core/x/mod.py:2 uses asyncio.open_connection"),
    ("import asyncio\nasyncio.start_server(cb, h)\n", "core/x/mod.py:2 uses asyncio.start_server"),
    ("import asyncio\nasyncio.start_unix_server(cb, p)\n", "core/x/mod.py:2 uses asyncio.start_unix_server"),
    ("from asyncio import open_connection\n", "core/x/mod.py:1 uses asyncio.open_connection"),
    ('import importlib\nimportlib.import_module("socket")\n', "core/x/mod.py:2 uses socket"),
    ('__import__("ssl")\n', "core/x/mod.py:1 uses ssl"),
]


@pytest.mark.parametrize(("body", "detail"), RED_CASES)
def test_n1_network_use_fires(tmp_path: Path, body: str, detail: str) -> None:
    """Each way of reaching the network under core is flagged with its site."""
    assert detail in _details(tmp_path, "core/x/mod.py", body)


CLEAN_BODIES = [
    "import httpx\nimport socket\nimport ssl\nimport urllib.request\nimport http.client\nimport http.server\n",
    "import asyncio\nasyncio.open_unix_connection(p)\nfrom urllib import request\n",
]


@pytest.mark.parametrize("body", CLEAN_BODIES)
def test_n1_adapters_are_exempt(tmp_path: Path, body: str) -> None:
    """The adapters folder may use the network."""
    assert _details(tmp_path, "core/platform/adapters/net.py", body) == []


@pytest.mark.parametrize("body", CLEAN_BODIES)
def test_n1_out_of_scope_folders_are_quiet(tmp_path: Path, body: str) -> None:
    """Only `core/` is scanned."""
    assert _details(tmp_path, "interfaces/cli/cmd.py", body) == []


@pytest.mark.parametrize(
    "body",
    [
        "socket_path = '/tmp/x'\nx = socket_path\n",
        "import urllib.parse\nurllib.parse.quote(s)\n",
        "from http import HTTPStatus\n",
        "import asyncio\nasyncio.run(main())\n",
        "import urllib\nurllib.parse.quote(s)\n",
        "import importlib\nimportlib.import_module('json')\n",
    ],
)
def test_n1_clean_shapes_are_quiet(tmp_path: Path, body: str) -> None:
    """Lookalike names and non-network stdlib use pass."""
    assert _details(tmp_path, "core/x/mod.py", body) == []
