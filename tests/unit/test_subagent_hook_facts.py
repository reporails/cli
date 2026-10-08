"""Each implemented agent's config.yml records how its hooks reach a sub-agent it starts."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.utils.utils import load_yaml_file

AGENTS = ("claude", "codex", "copilot", "cursor", "antigravity")
FACTS = ("fire_in_subagents", "identifies_agent", "extension_opt_out")
VALUES = {"yes", "no", "unconfirmed"}
RULES_DIR = Path(__file__).resolve().parents[2] / "framework" / "rules"


def _facts(agent: str) -> dict:
    config = load_yaml_file(RULES_DIR / agent / "config.yml")
    return config.get("subagent_hooks") or {}


@pytest.mark.unit
@pytest.mark.subsys_gates
@pytest.mark.parametrize("agent", AGENTS)
def test_three_facts_present(agent: str) -> None:
    assert set(_facts(agent)) == set(FACTS)


@pytest.mark.unit
@pytest.mark.subsys_gates
@pytest.mark.parametrize("fact", FACTS)
@pytest.mark.parametrize("agent", AGENTS)
def test_value_is_valid(agent: str, fact: str) -> None:
    assert _facts(agent)[fact]["value"] in VALUES


@pytest.mark.unit
@pytest.mark.subsys_gates
@pytest.mark.parametrize("fact", FACTS)
@pytest.mark.parametrize("agent", AGENTS)
def test_decided_value_has_https_source(agent: str, fact: str) -> None:
    entry = _facts(agent)[fact]
    if entry["value"] == "unconfirmed":
        assert "source" not in entry
        return
    assert str(entry.get("source", "")).startswith("https://")


@pytest.mark.unit
@pytest.mark.subsys_gates
@pytest.mark.parametrize("agent", AGENTS)
def test_fields_only_on_identified_agent(agent: str) -> None:
    for fact, entry in _facts(agent).items():
        has_fields = "fields" in entry
        assert has_fields == (fact == "identifies_agent" and entry["value"] == "yes")
