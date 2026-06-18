"""Shell-completion callbacks for `ails` arguments and options.

Each callback is wired to its consuming Argument / Option via the
`shell_complete=` parameter. The user runs `ails --install-completion`
once per shell to register them.
"""

from __future__ import annotations

from pathlib import Path


def complete_rule_token(incomplete: str) -> list[str]:
    """Complete a rule ID (`CORE:S:0024`) or slug (`italic-constraints`)."""
    from reporails_cli.core.platform.adapters.rules_query import load_all_rules

    needle = incomplete.lower()
    out: set[str] = set()
    for rule in load_all_rules():
        if rule.id.lower().startswith(needle):
            out.add(rule.id)
        if rule.slug and rule.slug.startswith(needle):
            out.add(rule.slug)
    return sorted(out)


def complete_capability(incomplete: str) -> list[str]:
    """Complete a capability keyword for the currently-detected agent."""
    from reporails_cli.core.classify.capability_paths import available_capabilities
    from reporails_cli.core.discovery.agents import detect_agents

    project_root = Path.cwd()
    detected = detect_agents(project_root)
    if not detected:
        return []
    agent_id = detected[0].agent_type.id
    caps = available_capabilities(agent_id, project_root)
    return sorted(c for c in caps if c.startswith(incomplete))


def complete_agent(incomplete: str) -> list[str]:
    """Complete an agent name (`claude`, `codex`, `copilot`, ...)."""
    from reporails_cli.core.platform.adapters.rules_query import list_known_agents

    return sorted(a for a in list_known_agents() if a.startswith(incomplete))


def complete_target_token(incomplete: str) -> list[str]:
    """Complete a target token for `ails check`: bare capability, `capability:name`, or path prefix.

    Dispatch on shape: `<cap>:<prefix>` → name candidates for that capability;
    else → bare capability nouns (all-of-kind), `<cap>:` (one), and path candidates.
    """
    if ":" in incomplete:
        cap, name_prefix = incomplete.split(":", 1)
        return [f"{cap}:{n}" for n in _complete_capability_target_name(cap, name_prefix)]
    # Bare prefix: offer the bare noun (all-of-kind) and the `<cap>:` (one)
    # forms; paths fall through to the shell's default completion.
    caps = complete_capability(incomplete)
    return [*caps, *[f"{c}:" for c in caps]]


def _complete_capability_target_name(capability: str, name_prefix: str) -> list[str]:
    """Names declared under <capability> for the current agent (e.g. skills under .claude/skills/)."""
    from reporails_cli.core.classify.capability_paths import list_capability_targets
    from reporails_cli.core.discovery.agents import detect_agents

    project_root = Path.cwd()
    detected = detect_agents(project_root)
    if not detected:
        return []
    agent_id = detected[0].agent_type.id
    out: set[str] = set()
    for p in list_capability_targets(agent_id, capability, project_root, None):
        # Take the directory or filename stem as the "name" the user types.
        stem = p.name if p.is_dir() else p.stem
        if stem.startswith(name_prefix):
            out.add(stem)
    return sorted(out)
