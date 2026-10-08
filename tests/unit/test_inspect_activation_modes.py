"""Activation SEAM: a rule file's loading, scope and globs follow the frontmatter keys its
agent's registry config declares (Copilot instructions, Cursor rules, Antigravity rules)."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.inspect import _detect_file_loading, _load_registry

COPILOT = ".github/instructions/a.instructions.md"
CURSOR = ".cursor/rules/a.mdc"
ANTI = ".agents/rules/a.md"


def _loading(root: Path, rel: str, frontmatter: str, registry=None):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{frontmatter}---\n\nBody.\n" if frontmatter else "Body.\n", encoding="utf-8")
    result = _detect_file_loading(path, root, registry or _load_registry())
    return result[:3]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("rel", "frontmatter", "expected"),
    [
        # Copilot instructions
        (COPILOT, 'applyTo: "src/**/*.ts"\n', ("on_demand", "path_scoped", ("src/**/*.ts",))),
        (COPILOT, "description: Use for API work\n", ("on_invocation", "global", ())),
        (COPILOT, "", ("on_demand", "global", ())),
        (COPILOT, "excludeAgent: code-review\n", ("on_demand", "global", ())),
        # Cursor rules
        (CURSOR, "alwaysApply: true\ndescription: x\n", ("session_start", "global", ())),
        (CURSOR, 'globs: "src/**"\n', ("on_demand", "path_scoped", ("src/**",))),
        (CURSOR, "description: Use for UI\nalwaysApply: false\n", ("on_invocation", "global", ())),
        (CURSOR, "alwaysApply: false\n", ("on_demand", "global", ())),
        (CURSOR, "", ("on_demand", "global", ())),
        # Antigravity rules by trigger
        (ANTI, "trigger: always_on\n", ("session_start", "global", ())),
        (ANTI, 'trigger: glob\nglobs: "src/**"\n', ("on_demand", "path_scoped", ("src/**",))),
        (ANTI, "trigger: model_decision\ndescription: d\n", ("on_invocation", "global", ())),
        (ANTI, "trigger: manual\n", ("on_demand", "global", ())),
        (ANTI, "", ("on_demand", "global", ())),
        (ANTI, "description: d\n", ("on_demand", "global", ())),
        (ANTI, "trigger: sometimes\nglobs: 'src/**'\n", ("on_demand", "global", ())),
        (ANTI, "trigger: manual\nglobs: 'src/**'\n", ("on_demand", "global", ())),
        (ANTI, "trigger: glob\n", ("on_demand", "global", ())),
        # Claude unchanged
        (".claude/rules/a.md", "", ("session_start", "global", ())),
        (".claude/rules/a.md", 'paths: "src/**"\n', ("on_demand", "path_scoped", ("src/**",))),
    ],
)
def test_activation_mode(tmp_path: Path, rel: str, frontmatter: str, expected) -> None:
    assert _loading(tmp_path, rel, frontmatter) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("frontmatter", "expected"),
    [
        ('paths: "src/**"\n', ("on_demand", "path_scoped", ("src/**",))),
        ('applyTo: "src/**"\n', ("session_start", "global", ())),
        ("description: d\n", ("session_start", "global", ())),
        ("", ("session_start", "global", ())),
    ],
)
def test_copilot_reads_claude_rules_by_paths(tmp_path: Path, frontmatter: str, expected) -> None:
    registry = {"copilot": _load_registry()["copilot"]}
    assert _loading(tmp_path, ".claude/rules/a.md", frontmatter, registry) == expected
