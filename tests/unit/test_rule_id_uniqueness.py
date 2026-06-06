"""Unit test guarding global rule-ID uniqueness across the bundled framework corpus."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
import yaml

FRAMEWORK_RULES = Path(__file__).parents[2] / "framework" / "rules"

pytestmark = pytest.mark.skipif(not FRAMEWORK_RULES.is_dir(), reason="in-repo framework/rules not present")


def _iter_rule_ids() -> list[tuple[str, Path]]:
    ids: list[tuple[str, Path]] = []
    for rule_md in sorted(FRAMEWORK_RULES.rglob("rule.md")):
        parts = rule_md.relative_to(FRAMEWORK_RULES).parts
        if "tests" in parts or "_deferred" in parts:
            continue
        text = rule_md.read_text(encoding="utf-8")
        if not text.startswith("---"):
            continue
        frontmatter = yaml.safe_load(text.split("---", 2)[1])
        rule_id = frontmatter.get("id")
        if rule_id:
            ids.append((rule_id, rule_md))
    return ids


class TestRuleIdUniqueness:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_duplicate_rule_ids(self) -> None:
        """Every bundled rule.md declares a globally unique id (loader is last-writer-wins)."""
        ids = _iter_rule_ids()
        assert ids, "no rule.md files found under framework/rules"
        counts = Counter(rule_id for rule_id, _ in ids)
        duplicates = {
            rule_id: [str(p.parent.name) for i, p in ids if i == rule_id]
            for rule_id, n in counts.items()
            if n > 1
        }
        assert not duplicates, f"duplicate rule IDs (silently dropped at load): {duplicates}"
