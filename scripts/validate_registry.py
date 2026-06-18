#!/usr/bin/env python3
"""Enforce the capabilities-matrix connection rule against shipped agent configs.

For each implemented agent, every capability in its matrix row must be
*anchored* in `framework/rules/<agent>/config.yml` — satisfied by a file_type
key, a location scope, or an AGENTS.md pattern — OR be an explicit, documented
exemption for a capability the agent supports but cannot be measured on disk
(e.g. cloud-hosted memory, undocumented plugin marketplace paths).

An exemption is justified only while a matching comment survives in the config;
a stale exemption (its justification comment gone) fails like any other gap.

Exit non-zero on any unanchored-and-unexempted capability, any stale exemption,
or any structural mismatch between matrix and configs.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = REPO_ROOT / "framework" / "capabilities_matrix.yml"
CONFIG_PATH = REPO_ROOT / "framework" / "rules" / "{agent}" / "config.yml"

# Capability -> file_type keys that anchor it (any-of).
FILE_TYPE_ANCHORS: dict[str, set[str]] = {
    "root": {"main"},
    "scoped": {"rules", "legacy_cursorrules", "cursorrules", "nested_context"},
    "skills": {"skills", "skill_metadata"},
    "hooks": {"hooks"},
    "mcp": {"mcp"},
    "subagents": {"agents"},
    "memory": {"memory"},
    "enterprise": {"enterprise", "managed_policy"},
    "plugins": {"plugins", "extensions"},
    "config": {"config"},
    "templates": {"prompts", "commands", "templates", "system_prompt"},
    "output": {"output_styles", "system_prompt", "output"},
    "scheduled_tasks": {"scheduled_tasks"},
}

# Capability -> location scope names that anchor it (any-of). These capabilities
# are expressed as scopes on other file_types, not as a dedicated file_type key.
SCOPE_ANCHORS: dict[str, set[str]] = {
    "enterprise": {"managed", "system", "system_overrides", "system_defaults", "managed_dropin"},
    "user_surfaces": {"user", "user_project"},
}

# Capability -> substring any file_type pattern must contain to anchor it. The
# AGENTS.md cross-agent standard anchors both agents_md (the agent reads it as a
# primary file) and cross_read (the agent reads another agent's file).
PATTERN_ANCHORS: dict[str, str] = {
    "agents_md": "AGENTS.md",
    "cross_read": "AGENTS.md",
}

# Documented exemptions: (agent, capability) -> substring that MUST appear in
# the agent's config.yml text justifying why the capability has no on-disk
# surface. The substring keys the exemption to its justification comment, so the
# exemption dies if the comment is removed.
EXEMPTIONS: dict[tuple[str, str], str] = {
    ("codex", "plugins"): "marketplace install path not documented",
    ("codex", "scheduled_tasks"): "Codex Desktop Automations on-disk path not documented",
    ("copilot", "memory"): "Copilot Memory: cloud-hosted",
    ("copilot", "enterprise"): "Org instructions: GitHub org settings",
    ("copilot", "plugins"): "Copilot Extensions: cloud-hosted",
    ("cursor", "memory"): "Cursor Memories",
    ("cursor", "output"): "CLI --output-format",
    ("cursor", "scheduled_tasks"): "Cursor Automations (cloud-only",
}


def _collect(config: dict) -> tuple[set[str], set[str], list[str]]:
    """Return (file_type keys, scope names, all glob patterns) from a config."""
    file_types = config.get("file_types") or {}
    keys = set(file_types)
    scopes: set[str] = set()
    patterns: list[str] = []
    for spec in file_types.values():
        for scope_name, scope in (spec.get("scopes") or {}).items():
            scopes.add(scope_name)
            patterns.extend(scope.get("patterns") or [])
    return keys, scopes, patterns


def _is_anchored(cap: str, keys: set[str], scopes: set[str], patterns: list[str]) -> bool:
    """True when a capability has a concrete on-disk anchor in the config."""
    if keys & FILE_TYPE_ANCHORS.get(cap, set()):
        return True
    if scopes & SCOPE_ANCHORS.get(cap, set()):
        return True
    marker = PATTERN_ANCHORS.get(cap)
    return bool(marker and any(marker in pattern for pattern in patterns))


def _check_agent(agent: str, row: list[str]) -> list[str]:
    """Return a list of failure messages for one implemented agent."""
    config_path = Path(str(CONFIG_PATH).format(agent=agent))
    if not config_path.exists():
        return [f"{agent}: config.yml not found at {config_path}"]

    text = config_path.read_text(encoding="utf-8")
    config = yaml.safe_load(text) or {}
    keys, scopes, patterns = _collect(config)
    failures: list[str] = []

    for cap in row:
        if _is_anchored(cap, keys, scopes, patterns):
            continue
        justification = EXEMPTIONS.get((agent, cap))
        if justification is None:
            failures.append(
                f"{agent}: capability '{cap}' is in the matrix row but has no file_type/scope "
                f"anchor in config.yml and no documented exemption"
            )
        elif justification not in text:
            failures.append(
                f"{agent}: capability '{cap}' is exempted, but its justification comment "
                f"({justification!r}) is missing from config.yml — stale exemption"
            )

    # Orphan exemptions: an exemption for a capability the matrix no longer claims.
    for (ex_agent, ex_cap) in EXEMPTIONS:
        if ex_agent == agent and ex_cap not in row:
            failures.append(
                f"{agent}: exemption for '{ex_cap}' but it is not in the matrix row — remove the exemption"
            )
    return failures


def main() -> int:
    matrix = yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8")) or {}
    implemented = matrix.get("implemented") or []
    taxonomy = matrix.get("taxonomy") or {}
    agents = matrix.get("agents") or {}

    failures: list[str] = []
    for agent in implemented:
        row = agents.get(agent)
        if row is None:
            failures.append(f"{agent}: listed in 'implemented' but absent from 'agents' matrix")
            continue
        unknown = [cap for cap in row if cap not in taxonomy]
        if unknown:
            failures.append(f"{agent}: matrix row references capabilities not in taxonomy: {unknown}")
        failures.extend(_check_agent(agent, row))

    if failures:
        print("Registry connection-rule FAILED:\n")
        for failure in failures:
            print(f"  ✗ {failure}")
        print(f"\n{len(failures)} failure(s) across {len(implemented)} implemented agents.")
        return 1

    print(f"Registry connection-rule OK — {len(implemented)} implemented agents, all capabilities anchored.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
