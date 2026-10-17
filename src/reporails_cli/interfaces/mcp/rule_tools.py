"""MCP `preflight` and `explain` tool implementations."""

from reporails_cli.core.classify import load_file_types
from reporails_cli.core.discovery.agents import get_known_agents
from reporails_cli.core.lint.rule_pages import load_rule_examples, rule_page_data, rule_page_summary
from reporails_cli.core.platform.adapters.registry import infer_agent_from_rule_id, load_rules
from reporails_cli.core.platform.adapters.rules_query import rules_for_capability
from reporails_cli.core.platform.config.config import is_initialized
from reporails_cli.core.platform.config.vocabulary import load_capability_vocabulary
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.models import Rule
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.interfaces.mcp.tools import _rules_missing_payload, _unknown_agent_error


def _known_capabilities(agent: str) -> set[str]:
    """Every capability keyword `preflight(capability=..., agent=...)` accepts for `agent` — its
    own declared `file_types`, or the union across every known agent when `agent` is empty (the
    same agent-agnostic union `rules_for_capability` mixes into a no-agent reply) — plus the
    vocabulary's input-form words, fold aliases, and virtual (classifier-synthesized)
    capabilities."""

    agents = [agent] if agent else list(get_known_agents())
    vocab = load_capability_vocabulary()
    declared = {decl.name for a in agents for decl in load_file_types(a)}
    return declared | set(vocab.input_forms) | set(vocab.fold) | set(vocab.virtual)


def preflight_tool(capability: str, agent: str = "") -> JsonObject:
    """Return workflow-ordered rules for authoring a file of `capability`.

    Backs `/reporails:ails preflight <capability>` in the plugin. Returns the
    same data the CLI's `ails rules list --capability=<capability> -f json` emits — rules
    sorted by category in workflow order (structure → direction → coherence
    → efficiency → maintenance → governance), severity tiebreaker, with
    Pass / Fail example blocks attached.

    The SKILL.md body presents the rule list and offers to draft; the
    structured shape lets the model walk rules category-by-category without
    parsing markdown.

    An unknown `agent` or `capability` used to fall through to
    `filter_rules_by_capability`'s universal-rule branch (a rule with no `match.type`
    matches every capability, bogus or not), so a typo silently returned a plausible-looking
    generic rule set instead of naming the typo. Both are validated first, each against its own
    known list, mirroring the CLI's `_validate_agent` / `TargetError` shape.
    """

    if not is_initialized():
        return _rules_missing_payload()
    if not capability:
        return {"error": "capability argument is required (e.g. 'skills', 'agents', 'rules', 'main')"}
    if agent and agent not in get_known_agents():
        return _unknown_agent_error(agent)

    capability = load_capability_vocabulary().input_forms.get(capability, capability)
    known = _known_capabilities(agent)
    if capability not in known:
        return {
            "error": "unknown_capability",
            "capability": capability,
            "known_capabilities": [*sorted(known)],
        }

    agents = [agent] if agent else None
    rules = rules_for_capability(capability, agents=agents)

    return {
        "capability": capability,
        "agent": agent,
        "rules": [_serialize_preflight_rule(r) for r in rules],
        "count": len(rules),
    }


def _serialize_preflight_rule(rule: Rule) -> JsonObject:
    """Shape one rule for the preflight response payload."""

    examples = load_rule_examples(rule)
    payload: JsonObject = rule_page_summary(rule)
    if examples.get("pass"):
        payload["pass_example"] = examples["pass"]
    if examples.get("fail"):
        payload["fail_example"] = examples["fail"]
    return payload


def explain_tool(rule_id: str) -> str | JsonObject:
    """Get detailed info about a specific rule."""
    rule_id_upper = rule_id.upper()
    agent = infer_agent_from_rule_id(rule_id_upper)
    rules = load_rules(agent=agent)

    if rule_id_upper not in rules:
        return {
            "error": f"Unknown rule: {rule_id}",
            "available_rules": [*sorted(rules.keys())],
        }

    return mcp_formatter.format_rule(rule_id_upper, rule_page_data(rules[rule_id_upper]))
