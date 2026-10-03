"""Bundled rules apply only to the kinds of file they fit."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

import reporails_cli

RULES = Path(reporails_cli.__file__).parents[2] / "framework" / "rules"


def _frontmatter(rule: str) -> dict:
    text = (RULES / "core" / rule / "rule.md").read_text(encoding="utf-8")
    return yaml.safe_load(text.split("---")[1])


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_filename_rule_accepts_cursor_mdc_rules():
    checks = yaml.safe_load((RULES / "core" / "descriptive-filenames" / "checks.yml").read_text(encoding="utf-8"))
    pattern = checks["checks"][0]["args"]["pattern"]
    assert re.match(pattern, "testing.mdc")
    assert re.match(pattern, "testing.md")
    assert not re.match(pattern, "Testing.mdc")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_italic_rule_skips_agent_configuration_files():
    formats = _frontmatter("italic-constraints")["match"]["format"]
    assert "schema_validated" not in formats
    assert set(formats) == {"freeform", "frontmatter"}


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("agent", ["claude", "cursor"])
def test_identity_field_rule_is_not_asked_of_rule_files_without_identity_fields(agent):
    config = yaml.safe_load((RULES / agent / "config.yml").read_text(encoding="utf-8"))
    assert "CORE:S:0005" in config["excludes"]
