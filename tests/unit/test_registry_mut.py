"""Mutation-closing behavioral tests for registry.py.

Each test reddens when a specific operator mutation is reintroduced into the
source (verified with scripts/mutation_probe.py). Scope is LOCAL registry
behavior: rule loading filters, supersession, dependency validation, cycle
detection, and scan/project disabled-rule merging.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters import registry as reg
from reporails_cli.core.platform.dto.models import Category, Execution, Rule, RuleType
from reporails_cli.core.platform.dto.results import ProjectConfig


def _rule(rid: str, **over) -> Rule:
    base = {
        "id": rid,
        "title": rid,
        "category": Category.STRUCTURE,
        "type": RuleType.MECHANICAL,
        "slug": rid.lower().replace(":", "-"),
    }
    base.update(over)
    return Rule(**base)


def _write_rule_md(root: Path, subdir: str, rid: str, *, extra_frontmatter: str = "") -> Path:
    """Write a minimal valid rule.md under root/subdir and return the dir."""
    d = root / subdir
    d.mkdir(parents=True, exist_ok=True)
    (d / "rule.md").write_text(
        "---\n"
        f'id: "{rid}"\n'
        f'title: "Rule {rid}"\n'
        "category: structure\n"
        "type: deterministic\n"
        f"slug: {rid.lower().replace(':', '-')}\n"
        "match:\n"
        "  type: main\n"
        f"{extra_frontmatter}"
        "---\n"
        "body\n",
        encoding="utf-8",
    )
    return d


# --- L76: structural_rule_ids filter (MECHANICAL and LOCAL) [and -> or] ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_structural_rule_ids_requires_both_mechanical_and_local(monkeypatch):
    """Only rules that are BOTH mechanical AND local execution qualify.

    With `and` flipped to `or`, a mechanical-server or deterministic-local
    rule would leak in; asserting the exact set reddens the mutant.
    """
    crafted = {
        "M_LOCAL": _rule("M_LOCAL", type=RuleType.MECHANICAL, execution=Execution.LOCAL),
        "M_SERVER": _rule("M_SERVER", type=RuleType.MECHANICAL, execution=Execution.SERVER),
        "D_LOCAL": _rule("D_LOCAL", type=RuleType.DETERMINISTIC, execution=Execution.LOCAL),
    }
    monkeypatch.setattr(reg, "load_rules", lambda agent="": crafted)
    reg.structural_rule_ids.cache_clear()
    result = reg.structural_rule_ids("mutprobe-agent")
    assert result == frozenset({"M_LOCAL"})
    reg.structural_rule_ids.cache_clear()


# --- L246: _apply_supersession guard [or -> and] ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_supersession_skips_rule_pointing_at_missing_parent():
    """A rule that supersedes a non-loaded id must be skipped, not crash.

    Normal guard `not supersedes or supersedes not in rules` -> continue.
    The `or -> and` mutant proceeds to `rules[missing]` -> KeyError.
    """
    rules = {"CHILD": _rule("CHILD", supersedes="GHOST")}
    result = reg._apply_supersession(rules)
    assert result == {}
    assert "CHILD" in rules


# --- L284: _validate_depends_on redirects default [or -> and] ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_validate_depends_on_none_superseded_by_does_not_crash(caplog):
    """With superseded_by=None, redirects must default to {} (not None).

    `None or {}` -> {}; the `or -> and` mutant yields None, so the later
    `dep_id in redirects` raises TypeError on a missing dependency.
    """
    rules = {"A": _rule("A", depends_on=["GHOST"])}
    with caplog.at_level("WARNING"):
        reg._validate_depends_on(rules)  # must not raise
    assert "GHOST" in caplog.text


# --- L289: redirects membership guard [and -> or] ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_validate_depends_on_missing_dep_not_in_redirects_does_not_crash():
    """A missing dependency absent from the redirects map must warn, not crash.

    Normal `dep in redirects and redirects[dep] in rules` short-circuits on
    the absent key. The `and -> or` mutant evaluates `redirects[dep]` -> KeyError.
    """
    rules = {"A": _rule("A", depends_on=["GHOST"])}
    reg._validate_depends_on(rules, superseded_by={"OTHER": "X"})  # must not raise


# --- L306/L312/L315/L318: _detect_dependency_cycles (acyclic must stay silent) ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_linear_acyclic_chain_logs_no_cycle(caplog):
    """A -> B (acyclic) must not report a circular chain.

    Kills the `and -> or` short-circuits (L312, L318) and the final
    `return False -> True` (L315) that would spuriously flag a cycle.
    """
    rules = {
        "A": _rule("A", depends_on=["B"]),
        "B": _rule("B"),
    }
    with caplog.at_level("WARNING"):
        reg._detect_dependency_cycles(rules)
    assert "Circular" not in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_diamond_acyclic_graph_logs_no_cycle(caplog):
    """A diamond (A->B, A->C, B->D, C->D) revisits D without a cycle.

    Kills the `if rid in visited: return False -> True` mutant (L306): the
    second visit to D must return False, not spuriously report a cycle.
    """
    rules = {
        "A": _rule("A", depends_on=["B", "C"]),
        "B": _rule("B", depends_on=["D"]),
        "C": _rule("C", depends_on=["D"]),
        "D": _rule("D"),
    }
    with caplog.at_level("WARNING"):
        reg._detect_dependency_cycles(rules)
    assert "Circular" not in caplog.text


# --- L103: _load_from_path skips _deferred rules [or -> and] ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_deferred_rule_is_not_loaded(tmp_path):
    """A rule under a `_deferred/` directory must be skipped.

    Normal `"tests" in parts or "_deferred" in parts` -> skip. The `or -> and`
    mutant only skips when BOTH appear, so the deferred rule would load.
    """
    reg.clear_rule_cache()
    _write_rule_md(tmp_path, "_deferred/myrule", "CORE:S:0099")
    result = reg._load_from_path(tmp_path)
    assert "CORE:S:0099" not in result
    assert result == {}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_normal_rule_is_loaded(tmp_path):
    reg.clear_rule_cache()
    _write_rule_md(tmp_path, "active/myrule", "CORE:S:0098")
    result = reg._load_from_path(tmp_path)
    assert "CORE:S:0098" in result


# --- unreadable rule.md is logged and skipped, not raised ---


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="chmod 000 unreadable file requires POSIX non-root",
)
def test_unreadable_rule_md_is_skipped_with_warning(tmp_path, caplog):
    """`ails explain` / `ails rules list` / `ails check` all load rules through `load_rules` ->
    `_load_from_path`, which used to read every `rule.md` unguarded — an unreadable file (e.g.
    permission-denied) raised `PermissionError` straight through `load_rules`, crashing every
    command that loads the pack it lives in with a Rich traceback and exit 1, even though the
    CLI's own post-load `explain` guard (`interfaces/cli/main.py`) suggested this case was
    handled. The good sibling rule must still load; only the unreadable one is skipped, and a
    warning names the file (matching the `checks.yml` parse-failure handling)."""
    reg.clear_rule_cache()
    _write_rule_md(tmp_path, "active/goodrule", "CORE:S:0094")
    bad_dir = _write_rule_md(tmp_path, "active/badrule", "CORE:S:0093")
    bad_md = bad_dir / "rule.md"
    os.chmod(bad_md, 0o000)
    try:
        with caplog.at_level("WARNING"):
            result = reg._load_from_path(tmp_path)
    finally:
        os.chmod(bad_md, 0o644)

    assert "CORE:S:0094" in result
    assert "CORE:S:0093" not in result
    assert str(bad_md) in caplog.text


# --- L118: checks.yml pre-parse guard [and -> or] ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_inline_checks_win_over_checks_yml(tmp_path):
    """When frontmatter already carries checks, checks.yml must NOT override.

    Normal `yml_path is not None and not frontmatter.get("checks")` -> skip
    pre-parse (keep inline). The `and -> or` mutant overwrites the inline
    checks with the checks.yml contents.
    """
    reg.clear_rule_cache()
    d = _write_rule_md(
        tmp_path,
        "active/myrule",
        "CORE:S:0097",
        extra_frontmatter='checks:\n  - id: "CORE.S.0097.inline"\n    type: deterministic\n',
    )
    (d / "checks.yml").write_text(
        "checks:\n"
        '  - id: "CORE.S.0097.fromyml"\n'
        "    type: deterministic\n"
        '  - id: "CORE.S.0097.fromyml2"\n'
        "    type: deterministic\n",
        encoding="utf-8",
    )
    result = reg._load_from_path(tmp_path)
    rule = result["CORE:S:0097"]
    assert [c.id for c in rule.checks] == ["CORE.S.0097.inline"]


# --- L195/L197: scan_root disabled-rule merge ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_scan_root_disabled_rules_are_merged(tmp_path, monkeypatch):
    """A rule disabled only via scan_root's config must be removed.

    Normal `scan_root and scan_root != project_root` enters and merges the
    scan config's disabled set. Kills L195 `!= -> ==` (would skip the merge)
    and L197 `or -> and` (would drop the disabled ids to []).
    """
    reg.clear_rule_cache()
    rules_root = tmp_path / "rules"
    _write_rule_md(rules_root, "core/myrule", "CORE:S:0096")
    project_root = tmp_path / "proj"
    scan_root = tmp_path / "scan"
    project_root.mkdir()
    scan_root.mkdir()

    def _fake_config(root):
        if root == scan_root:
            return ProjectConfig(disabled_rules=["CORE:S:0096"])
        return ProjectConfig()

    monkeypatch.setattr(reg, "_load_project_config", _fake_config)
    loaded = reg.load_rules(
        rules_paths=[rules_root],
        project_root=project_root,
        scan_root=scan_root,
    )
    assert "CORE:S:0096" not in loaded


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_present_without_scan_disable(tmp_path, monkeypatch):
    """Control: with no scan disable, the rule loads (guards the above)."""
    reg.clear_rule_cache()
    rules_root = tmp_path / "rules"
    _write_rule_md(rules_root, "core/myrule", "CORE:S:0095")
    monkeypatch.setattr(reg, "_load_project_config", lambda root: ProjectConfig())
    loaded = reg.load_rules(rules_paths=[rules_root], project_root=tmp_path / "p")
    assert "CORE:S:0095" in loaded
