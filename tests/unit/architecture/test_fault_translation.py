"""Fault-translation boundary — adapters must not collapse a caught fault into a sentinel.

The import-direction boundary is enforced by `test_adapter_boundary.py`. This is the
error-translation contract on the same boundary: a fault caught in an `except` handler
must not silently become a sentinel (`""` / `None` / `0` / empty collection / a no-arg
constructor like `LintResponse()`) or `pass` that flows downstream as authoritative truth.
Adapters raise a typed `PlatformError` on fault and return a sentinel only for guard-clause
absence — see `core/platform/contract/errors.py`.

Each flagged site is keyed by (path, enclosing-function, handler-exception-type) so the
allowlist survives line shifts and a NEW sentinel-collapse in a seeded function is still
caught. `_KNOWN_EXCEPTIONS` carries two classes: legitimate logged-isolation / dependency
degrades, and grandfathered debt tagged with a `# TODO`.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
ADAPTERS = ROOT / "src" / "reporails_cli" / "core" / "platform" / "adapters"

_FAIL_ON_VIOLATION = True

# (relative_path, enclosing_function, handler_exception_type) tuples whose sentinel-collapse
# is reviewed-and-allowed. Regenerate by running this module's AST walk against the adapters.
_KNOWN_EXCEPTIONS: set[tuple[str, str, str]] = {
    # Legitimate dependency-missing degrades — optional package absent → genuine anonymous.
    ("src/reporails_cli/core/platform/adapters/api_client.py", "_tier_from_config", "ImportError"),
    ("src/reporails_cli/core/platform/adapters/api_client.py", "_api_key_from_credentials", "ImportError"),
    ("src/reporails_cli/core/platform/adapters/api_client.py", "_lint_remote", "ImportError"),
    # Legitimate crash-firewall — PlatformError surfaced as a WARNING, session continues anonymous.
    ("src/reporails_cli/core/platform/adapters/api_client.py", "_degrade_on_fault", "PlatformError"),
    # Legitimate logged-isolation — network / parse faults logged at WARNING, server call degrades.
    ("src/reporails_cli/core/platform/adapters/api_client.py", "_post_payload", "httpx.TimeoutException"),
    ("src/reporails_cli/core/platform/adapters/api_client.py", "_post_payload", "httpx.HTTPStatusError"),
    ("src/reporails_cli/core/platform/adapters/api_client.py", "_post_payload", "httpx.HTTPError"),
    (
        "src/reporails_cli/core/platform/adapters/api_client.py",
        "_post_payload",
        "json.JSONDecodeError,KeyError,ValueError,TypeError",
    ),
    # Grandfathered debt — collapses a load fault to an empty result. TODO: raise a typed fault.
    (
        "src/reporails_cli/core/platform/adapters/registry.py",
        "structural_rule_ids",
        "OSError,ValueError,KeyError",
    ),  # TODO: raise a typed fault
    (
        "src/reporails_cli/core/platform/adapters/registry.py",
        "_load_from_path",
        "Exception",
    ),  # TODO: raise a typed fault
    (
        "src/reporails_cli/core/platform/adapters/registry.py",
        "_apply_agent_overrides",
        "ValueError",
    ),  # TODO: raise a typed fault
}


def _handler_type(handler: ast.ExceptHandler) -> str:
    """Stable string for the caught exception type(s)."""
    if handler.type is None:
        return "BARE"
    if isinstance(handler.type, ast.Tuple):
        return ",".join(ast.unparse(e) for e in handler.type.elts)
    return ast.unparse(handler.type)


def _sentinel_kind(node: ast.stmt) -> str | None:
    """Return a label when `node` is a sentinel collapse (`pass` or a bare-sentinel return)."""
    if isinstance(node, ast.Pass):
        return "pass"
    if isinstance(node, ast.Return):
        value = node.value
        if value is None:
            return "return None"
        if isinstance(value, ast.Constant) and value.value in ("", None, 0, False):
            return f"return {value.value!r}"
        if isinstance(value, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
            elts = getattr(value, "elts", None)
            keys = getattr(value, "keys", None)
            if not elts and not keys:
                return "return empty-collection"
        if isinstance(value, ast.Call) and not value.args and not value.keywords:
            return f"return {ast.unparse(value)}"
    return None


def _collapsing_handlers(file_path: Path) -> list[tuple[str, str, str]]:
    """Find except handlers whose last statement collapses the fault into a sentinel."""
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return []
    rel = file_path.relative_to(ROOT).as_posix()
    found: list[tuple[str, str, str]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for handler in ast.walk(fn):
            if not isinstance(handler, ast.ExceptHandler) or not handler.body:
                continue
            if _sentinel_kind(handler.body[-1]) is not None:
                found.append((rel, fn.name, _handler_type(handler)))
    return found


@pytest.mark.architecture
def test_adapters_do_not_collapse_faults_into_sentinels() -> None:
    """Adapter except handlers must raise a typed fault, not silently return a sentinel."""
    if not ADAPTERS.is_dir():
        pytest.skip(f"{ADAPTERS} does not exist yet")
    violations = [
        site
        for py in sorted(ADAPTERS.rglob("*.py"))
        if "__pycache__" not in py.parts
        for site in _collapsing_handlers(py)
        if site not in _KNOWN_EXCEPTIONS
    ]
    if not violations:
        return
    lines = [f"adapters layer has {len(violations)} unreviewed fault-collapse(s):"]
    lines.extend(f"  {v[0]}::{v[1]} catching {v[2]} returns a sentinel" for v in violations)
    lines.append("Raise a typed PlatformError, or allowlist the site in _KNOWN_EXCEPTIONS with a rationale.")
    msg = "\n".join(lines)
    if _FAIL_ON_VIOLATION:
        pytest.fail(msg)
    else:
        print(f"\n[report-only]\n{msg}\n")
