"""Agent capability matrix loader.

Reads ``capabilities_matrix.yml`` from the framework root and exposes each
agent's declared capability set. The rule-filter path uses this to gate
``requires_capability`` rules: a rule that names a capability the target agent
lacks is dropped before it can fire.
"""

from __future__ import annotations

from functools import lru_cache

from reporails_cli.core.platform.config.config import get_framework_root
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
from reporails_cli.core.platform.utils.utils import load_yaml_file

_MATRIX_FILENAME = "capabilities_matrix.yml"


def _matrix_section(name: str) -> JsonObject:
    """The mapping under ``name`` in the matrix file; empty when the file or the section is absent."""
    path = get_framework_root() / _MATRIX_FILENAME
    if not path.exists():
        return {}
    return as_object(as_object(load_yaml_file(path)).get(name, {}))


@lru_cache(maxsize=1)
def legacy_main_files() -> dict[str, frozenset[str]]:
    """Return ``{agent_id: frozenset(file_names)}`` of root instruction files the matrix lists
    for cataloged agents that no implemented agent config declares.

    Returns an empty dict when the matrix file or the section is absent.
    """
    files = _matrix_section("legacy_main_files")
    return {
        agent: frozenset(name for name in names if isinstance(name, str))
        for agent, names in files.items()
        if isinstance(names, list)
    }


@lru_cache(maxsize=1)
def load_capability_matrix() -> dict[str, frozenset[str]]:
    """Return ``{agent_id: frozenset(capability_ids)}`` from the matrix file.

    Returns an empty dict when the matrix file is absent, so a missing file
    degrades to no gating rather than an error.
    """
    agents = _matrix_section("agents")
    return {
        agent: frozenset(cap for cap in caps if isinstance(cap, str))
        for agent, caps in agents.items()
        if isinstance(caps, list)
    }


def agent_capabilities(agent: str) -> frozenset[str] | None:
    """Return the capability set for ``agent``.

    Returns ``None`` when ``agent`` is empty or is not present in the matrix —
    both cases mean "capability unknown", which the filter reads as no gating.
    """
    if not agent:
        return None
    return load_capability_matrix().get(agent.lower())
