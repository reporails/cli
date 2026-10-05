"""The mapper's registry-pattern match and the path-tag classifier use the shared glob matcher.

`*` stays inside one path segment (as in the classify match), a directory pattern names the
`.md` files at any depth under it, and a machine-config surface matches by its trailing segments.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.classify.file_tags import classify_file
from reporails_cli.core.platform.utils.utils import config_pattern_matches


@pytest.mark.unit
@pytest.mark.subsys_map
def test_star_does_not_cross_a_directory_boundary() -> None:
    assert config_pattern_matches(".claude/rules/a.md", ".claude/rules/*.md", ignore_case=True)
    assert not config_pattern_matches(".claude/rules/sub/a.md", ".claude/rules/*.md", ignore_case=True)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_directory_pattern_names_markdown_files_at_any_depth_under_it() -> None:
    assert config_pattern_matches(".claude/agent-memory/bot/notes.md", ".claude/agent-memory/*/", ignore_case=True)
    assert config_pattern_matches(".claude/agent-memory/bot/deep/notes.md", ".claude/agent-memory/*/", ignore_case=True)
    assert not config_pattern_matches(".claude/agent-memory/bot/notes.txt", ".claude/agent-memory/*/", ignore_case=True)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_match_ignores_case() -> None:
    assert config_pattern_matches("Docs/CLAUDE.MD", "**/claude.md", ignore_case=True)


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("path", "tag"),
    [
        (".gemini/extensions/tool/readme.md", "config"),
        ("pkg/.GEMINI/Extensions/x/y.md", "config"),
        ("/abs/proj/.claude/settings.json", "config"),
        ("pkg/.agents/skills/foo/agents/openai.yaml", "config"),
        ("docs/agents/openai.yaml", "file"),
        ("docs/readme.md", "file"),
    ],
)
def test_config_surface_matches_by_trailing_segments(path: str, tag: str) -> None:
    assert classify_file(path) == tag
