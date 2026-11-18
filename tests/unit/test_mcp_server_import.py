"""Importing the MCP server module builds no model handle; the entry point builds it and hands it in."""

from __future__ import annotations

import asyncio
import subprocess
import sys

import pytest

from reporails_cli.interfaces.mcp import server
from tests.fake_models import no_models

_TOOLS = ["explain", "preflight", "prepare", "remedy_brief", "validate", "xray"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_import_constructs_no_models() -> None:
    """A fresh process that imports the module with `Models` construction forbidden still imports."""
    code = (
        "from reporails_cli.core.mapper.models import Models\n"
        "def refuse(*_a, **_k):\n"
        "    raise AssertionError('a model handle was built at import')\n"
        "Models.__init__ = refuse\n"
        "import reporails_cli.interfaces.mcp.server\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr


@pytest.mark.unit
@pytest.mark.subsys_server
def test_built_server_lists_the_tools() -> None:
    """The server built from a model handle serves exactly the tools the process always served."""
    built = server.build_server(no_models())
    assert sorted(t.name for t in asyncio.run(built.list_tools())) == _TOOLS
