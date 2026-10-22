"""MCP `prepare` tool: map the files a `validate` would check, without checking them.

The map is kept on disk, so the next `validate` with the same `path` and `targets` returns
sooner. Nothing here contacts the server, reads an account or counts as a `validate` call.
"""

from pathlib import Path

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.interfaces.mcp.tools import Scope, _resolve_scan_target, build_map, scope_for_path
from reporails_cli.interfaces.mcp.validate_targets import named_files, resolve_validate_targets, target_tokens


def prepare_for_path(path: str, targets: list[str] | None = None) -> JsonObject:
    """Map the files `validate(path, targets)` checks; `{"files": n}` is how many are ready.

    Answers `validate`'s own payload for every condition that stops it (model not ready,
    unknown target, missing path, unknown agent), and `mapper_unavailable` when the map
    cannot be built.
    """
    try:
        # A long-running server keeps the detected-agent list between calls: detect afresh, so a
        # file added or removed since the last call is mapped as `validate` will find it.
        clear_agent_cache()
        named: frozenset[Path] = frozenset()
        tokens = target_tokens(targets)
        target = Path(path).resolve()
        if tokens and target.exists():
            resolved = resolve_validate_targets(tokens, _resolve_scan_target(target)[0])
            if isinstance(resolved, dict):
                return resolved
            named = named_files(resolved)
        scope = scope_for_path(path, named)
        if not isinstance(scope, Scope):
            return {"files": 0} if "files" in scope else scope
        ruleset_map, mapper_error = build_map(scope.scan_root, scope.instruction_files, scope.filter_agents)
        if ruleset_map is None:
            return {"error": "mapper_unavailable", "mapper_error": mapper_error}
        return {"files": len(ruleset_map.files)}
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return {"error": str(e)}
