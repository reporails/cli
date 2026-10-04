"""Block ``import torch`` at every CLI / daemon / MCP entry point.

Why this exists
---------------

Importing ``torch`` on CPU is very slow, and the ``reporails`` pipeline does not
need it at runtime, but some transitive import paths drag it in anyway. Installing
a ``sys.meta_path`` finder that raises ``ImportError`` for any
``torch`` / ``torch.*`` module forces thinc's ``try: import torch`` into
its ``except ImportError: has_torch = False`` branch. spaCy then loads
cleanly in **<1 s** and torch never enters ``sys.modules``.

Install points
--------------

``install()`` must be called **before** any reporails module import that
transitively reaches ``thinc`` or ``sentence_transformers``. Concretely,
the very first non-stdlib import in each entry point:

- ``src/reporails_cli/interfaces/cli/main.py`` — the ``ails`` CLI
- ``src/reporails_cli/interfaces/mcp/server.py`` — the MCP server
- ``src/reporails_cli/core/mapper/daemon.py`` — inside ``_daemon_main``
  (the forked daemon child re-enters Python-land and must reinstall)

Calling ``install()`` twice is safe (idempotent).

Guarantees
----------

After ``install()`` returns:

- ``"torch" not in sys.modules`` (any stale torch reference is cleared)
- Any subsequent ``import torch`` raises ``ImportError`` with a clear
  reporails-flavoured message
- Packages the pipeline uses are unaffected — none of them require torch at
  runtime on our code path
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from importlib.machinery import ModuleSpec


class _TorchBlocker:
    """``sys.meta_path`` finder that rejects any ``torch*`` import.

    Returning ``None`` from ``find_spec`` means "not my problem, try the
    next finder." Raising ``ImportError`` means "this import cannot
    succeed." We raise, because a silent skip would let a later finder
    successfully import torch.
    """

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,  # noqa: ARG002  (MetaPathFinder protocol)
        target: object | None = None,  # noqa: ARG002  (MetaPathFinder protocol)
    ) -> ModuleSpec | None:
        if fullname == "torch" or fullname.startswith("torch."):
            raise ImportError(
                f"torch import blocked by ails entry-point hook: {fullname}. "
                "The reporails pipeline runs on ONNX Runtime; torch is not a "
                "runtime dependency."
            )
        return None


def install() -> None:
    """Install the torch blocker and drop any stale torch references.

    Idempotent. Safe to call multiple times — only the first call
    actually mutates ``sys.meta_path``.
    """
    if not any(isinstance(f, _TorchBlocker) for f in sys.meta_path):
        sys.meta_path.insert(0, _TorchBlocker())

    # Defensive cleanup: if anything already imported torch before we
    # got a chance to install the blocker (e.g. a test runner or a
    # recently-cached module), drop those references so the next
    # ``import torch`` triggers the blocker instead of reusing the
    # cached module.
    for name in list(sys.modules):
        if name == "torch" or name.startswith("torch."):
            del sys.modules[name]
