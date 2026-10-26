"""Shared by the env-read and process-runner floors: the local names the `os` module is bound to."""

from __future__ import annotations

import ast


def os_names(tree: ast.Module) -> set[str]:
    """The local names the `os` module is bound to: `import os`, `import os as x`, `import os.path`."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if alias.name == "os":
                names.add(alias.asname or "os")
            elif alias.name.startswith("os.") and not alias.asname:
                names.add("os")
    return names
