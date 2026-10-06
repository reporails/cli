"""Agent capability matrix loader.

Reads ``capabilities_matrix.yml`` from the framework root and exposes each
agent's declared capability set. The rule-filter path uses this to gate
``requires_capability`` rules: a rule that names a capability the target agent
lacks is dropped before it can fire.
"""

from __future__ import annotations

from functools import lru_cache

from reporails_cli.core.platform.config.bootstrap import get_framework_root
from reporails_cli.core.platform.utils.utils import load_yaml_file

_MATRIX_FILENAME = "capabilities_matrix.yml"


@lru_cache(maxsize=1)
def load_capability_matrix() -> dict[str, frozenset[str]]:
    """Return ``{agent_id: frozenset(capability_ids)}`` from the matrix file.

    Returns an empty dict when the matrix file is absent, so a missing file
    degrades to no gating rather than an error.
    """
    path = get_framework_root() / _MATRIX_FILENAME
    if not path.exists():
        return {}
    data = load_yaml_file(path) or {}
    agents = data.get("agents", {})
    if not isinstance(agents, dict):
        return {}
    return {agent: frozenset(caps) for agent, caps in agents.items() if isinstance(caps, list)}


def agent_capabilities(agent: str) -> frozenset[str] | None:
    """Return the capability set for ``agent``.

    Returns ``None`` when ``agent`` is empty or is not present in the matrix —
    both cases mean "capability unknown", which the filter reads as no gating.
    """
    if not agent:
        return None
    return load_capability_matrix().get(agent.lower())


def clear_capability_cache() -> None:
    """Clear the cached matrix. Called by --refresh and after ails update."""
    load_capability_matrix.cache_clear()
