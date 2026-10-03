"""Mutation-killing behavioral tests for formatters/text/display_constants.py.

Despite the module name, these are real pure helpers with behavioral contracts:
truncate boundary, path classification, friendly-name fallbacks, short-path
casing, the norm-path memo, the per-file guard, and the directive/constraint
counters. Each assertion reddens the moment the operator under it flips (verified
against the mutation probe). Cosmetic display strings carry no contract and are
left to the equivalent bucket.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.classify.file_tags import classify_file
from reporails_cli.core.platform.runtime.merger import normalize_finding_path
from reporails_cli.formatters.text.display_constants import (
    friendly_name,
    group_stats_line,
    index_atoms_by_norm_path,
    per_file_stats,
    short_path,
    truncate,
)


# --- truncate: `<=` boundary (L205) ---------------------------------------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_truncate_keeps_text_at_exact_max_len() -> None:
    # len == max_len must pass through untouched; `<` would clip + ellipsize.
    assert truncate("abcde", 5) == "abcde"


# --- classify_file: structural-dir predicates (L217/L220/L222) -------------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_classify_file_non_skill_in_skills_dir_is_plain_file() -> None:
    # `and`->`or` would tag any file under skills/ as a skill.
    assert classify_file("skills/foo/helper.md") == "file"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_classify_file_skill_md_in_skills_dir() -> None:
    # `==`->`!=` on the SKILL.md name check would drop the real skill.
    assert classify_file("skills/foo/SKILL.md") == "skills:foo"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_classify_file_non_md_in_agents_dir_is_plain_file() -> None:
    # `and`->`or` would tag a non-.md file under agents/ as an agent.
    assert classify_file("agents/foo.txt") == "file"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_classify_file_non_md_in_rules_dir_is_plain_file() -> None:
    # `and`->`or` would tag a non-.md file under rules/ as a rule.
    assert classify_file("rules/foo.txt") == "file"


# --- _classify_by_name via classify_file: root vs nested (L243) ------------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_classify_file_root_main_name_is_main() -> None:
    # single-component path (len(parts) == 1) is `main`; `<` would call it nested.
    assert classify_file("CLAUDE.md") == "main"
    assert classify_file("GEMINI.md") == "main"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("path", [".gemini/extensions/acme/GEMINI.md", ".gemini/extensions/acme/AGENTS.md"])
def test_classify_file_main_name_inside_a_config_surface_is_config(path: str) -> None:
    assert classify_file(path) == "config"


# --- friendly_name: nested/relative + parent fallbacks (L258/L261) ---------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_friendly_name_nested_returns_full_relative_path() -> None:
    # `==`->`!=` on the tag check drops the full-path nested branch.
    assert friendly_name("packages/web/CLAUDE.md", "nested") == "packages/web/CLAUDE.md"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_friendly_name_non_nested_uses_parent_slash_name() -> None:
    # `and`->`or` on the nested guard would emit the full posix path here.
    assert friendly_name("a/b/c.md", "main") == "b/c.md"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_friendly_name_root_file_is_bare_name() -> None:
    # empty parent.name: `and`->`or` would prepend a bare "/".
    assert friendly_name("file.md", "file") == "file.md"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_friendly_name_uses_parent_dir_when_present() -> None:
    # `!=`->`==` on the parent-dir check would drop the "web/" prefix.
    assert friendly_name("web/file.md", "file") == "web/file.md"


# --- short_path: uppercase .md detection (L286) ---------------------------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_short_path_ignores_uppercase_non_md_component() -> None:
    # `and`->`or` would slice at the uppercase non-.md "Foo/" component.
    assert short_path("Foo/bar.txt") == "bar.txt"


# --- index_atoms_by_norm_path: memo `is None` gate (L322) ------------------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_index_atoms_groups_by_normalized_path() -> None:
    atoms = [SimpleNamespace(file_path="src/a.md"), SimpleNamespace(file_path="src/a.md")]
    result = index_atoms_by_norm_path(atoms, Path("/proj"))
    # `is`->`is not` skips the compute so every atom groups under a None key.
    assert None not in result
    assert result["src/a.md"] == atoms


# --- per_file_stats: short-filepath guard (L341) --------------------------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_per_file_stats_short_filepath_returns_empty() -> None:
    root = Path("/proj")
    atom = SimpleNamespace(charge_value=1, ambiguous=False)
    index = {normalize_finding_path("ab", root): [atom]}
    # len("ab") < 3 must short-circuit to ""; `or`->`and` would compute stats.
    assert per_file_stats("ab", object(), root, index) == ""


# --- group_stats_line: charge counters (L407/L408) ------------------------
@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_group_stats_line_counts_directive_and_constraint() -> None:
    atoms = [
        SimpleNamespace(charge_value=1),
        SimpleNamespace(charge_value=-1),
        SimpleNamespace(charge_value=0),
    ]
    out = group_stats_line(atoms)
    # `==`->`!=` on either counter would report 2 instead of 1.
    assert "1 directive" in out
    assert "1 constraint" in out
