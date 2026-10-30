"""Shared by the architecture floors: the local names a module is bound to in a file."""

from __future__ import annotations

import ast


def module_names(tree: ast.Module, module: str) -> set[str]:
    """The local names `module` is bound to: `import m`, `import m as x`, `import m.sub` (binds `m`)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if alias.name == module:
                names.add(alias.asname or module)
            elif alias.name.startswith(f"{module}.") and not alias.asname:
                names.add(module)
    return names
