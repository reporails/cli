"""Path-filter SEAM for the mapper's per-file loading classification.

`_detect_file_loading` decides whether a rule file is always loaded or loaded only
for matching paths, by reading the frontmatter key the matched file type declares
as its path filter. A Claude rule scoped with `paths:` read as `session_start`
before the key was declared, so these run the real bundled registry and redden
if the key is dropped or read for the wrong agent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.inspect import (
    _detect_file_loading,
    _load_registry,
    skill_dirs_by_owner,
    skill_typed_file_type,
)
from reporails_cli.core.platform.adapters.payload import MAX_FILE_GLOBS, project_payload
from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap, RulesetSummary


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("rel", "frontmatter", "expected"),
    [
        # Claude rule scoped with a `paths:` list — path-scoped, not always-on.
        (
            ".claude/rules/api.md",
            'paths:\n  - "src/api/**/*.ts"\n',
            ("on_demand", "path_scoped", ("src/api/**/*.ts",), "claude", "rules"),
        ),
        # One comma-separated string; the comma inside a brace group stays in its pattern.
        (
            ".claude/rules/ui.md",
            'paths: "src/*.{ts,tsx}, lib/**/*.md"\n',
            ("on_demand", "path_scoped", ("src/*.{ts,tsx}", "lib/**/*.md"), "claude", "rules"),
        ),
        # One unquoted line starting with `*` is not valid YAML; Claude Code still scopes the rule.
        (
            ".claude/rules/any-ts.md",
            "paths: **/*.ts\n",
            ("on_demand", "path_scoped", ("**/*.ts",), "claude", "rules"),
        ),
        # The same glob as an unquoted list item leaves the rule unscoped in Claude Code too.
        (
            ".claude/rules/any-ts-list.md",
            "paths:\n  - **/*.ts\n",
            ("session_start", "global", (), "claude", "rules"),
        ),
        # A colon inside `description:` breaks the YAML block; the `paths:` list still scopes it.
        (
            ".claude/rules/described.md",
            'description: Use when: editing the API\npaths:\n  - "src/api/**"\n',
            ("on_demand", "path_scoped", ("src/api/**",), "claude", "rules"),
        ),
        # A brace group can lead the one-line value; a trailing comment is not part of it.
        (
            ".claude/rules/src-lib.md",
            "paths: {src,lib}/**/*.ts  # both trees\n",
            ("on_demand", "path_scoped", ("{src,lib}/**/*.ts",), "claude", "rules"),
        ),
        # Re-reading a broken block keeps `null` a null: the rule stays unscoped.
        (
            ".claude/rules/null.md",
            "description: a: b\npaths: null\n",
            ("session_start", "global", (), "claude", "rules"),
        ),
        # A `paths:` list with only an empty item scopes nothing.
        (
            ".claude/rules/empty.md",
            "paths:\n  -\n",
            ("session_start", "global", (), "claude", "rules"),
        ),
        # A Claude rule without `paths:` loads at session start, whatever other key it carries.
        (
            ".claude/rules/legacy.md",
            'globs: ["src/**"]\n',
            ("session_start", "global", (), "claude", "rules"),
        ),
        # Cursor rules keep reading `globs:`.
        (
            ".cursor/rules/style.mdc",
            'globs: ["src/**/*.py"]\n',
            ("on_demand", "path_scoped", ("src/**/*.py",), "cursor", "rules"),
        ),
        # A Cursor rule is always loaded only with `alwaysApply: true`.
        (
            ".cursor/rules/always.mdc",
            "alwaysApply: true\n",
            ("session_start", "global", (), "cursor", "rules"),
        ),
        # `alwaysApply: true` loads the rule every session; a `globs:` filter beside it is ignored.
        (
            ".cursor/rules/always-globs.mdc",
            'globs: ["src/**"]\nalwaysApply: true\n',
            ("session_start", "global", (), "cursor", "rules"),
        ),
        # `globs:` with `alwaysApply: false` stays path scoped.
        (
            ".cursor/rules/globs-not-always.mdc",
            'globs: ["src/**"]\nalwaysApply: false\n',
            ("on_demand", "path_scoped", ("src/**",), "cursor", "rules"),
        ),
        # Description only (`alwaysApply: false`): the agent decides when to load it.
        (
            ".cursor/rules/intelligent.mdc",
            "description: Testing guidance\nalwaysApply: false\n",
            ("on_demand", "global", (), "cursor", "rules"),
        ),
        # No filter and no `alwaysApply`: loaded only when the rule is @-mentioned.
        (
            ".cursor/rules/other.mdc",
            'paths: ["src/**/*.py"]\n',
            ("on_demand", "global", (), "cursor", "rules"),
        ),
    ],
)
def test_rule_loading_reads_the_declared_path_key(tmp_path, rel, frontmatter, expected):
    path = _write(tmp_path, rel, f"---\n{frontmatter}---\n\n# Rule\n\nUse the shared client.\n")
    assert _detect_file_loading(path, tmp_path, _load_registry()) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
def test_payload_caps_file_globs():
    """A file record carries at most `MAX_FILE_GLOBS` of a rule's patterns, in order."""
    globs = tuple(f"pkg{i}/**" for i in range(MAX_FILE_GLOBS + 5))
    ruleset_map = RulesetMap(
        schema_version="1",
        embedding_model="m",
        generated_at="t",
        files=(
            FileRecord(
                path="r.md", content_hash="h", loading="on_demand", scope="path_scoped", globs=globs, type="rules"
            ),
        ),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0, n_topic_clusters=0),
    )
    sent = project_payload(ruleset_map, Path("/p"))["files"][0]
    assert sent["globs"] == list(globs[:MAX_FILE_GLOBS])
    assert sent["type"] == "rules"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        # The root file loads at session start; a subdirectory's copy loads only when the
        # agent works under that subdirectory.
        ("CLAUDE.md", ("session_start", "global", (), "claude", "main")),
        ("tests/CLAUDE.md", ("on_demand", "nested", (), "claude", "child_instruction")),
        ("tests/skills/CLAUDE.md", ("on_demand", "nested", (), "claude", "child_instruction")),
        # A file name several agents declare belongs to the generic standard, not to one of them.
        ("AGENTS.md", ("session_start", "global", (), "generic", "main")),
        ("src/AGENTS.md", ("on_demand", "nested", (), "generic", "nested_context")),
        ("GEMINI.md", ("session_start", "global", (), "antigravity", "main")),
        # The project file may also live at `.claude/CLAUDE.md`; it loads at session start.
        (".claude/CLAUDE.md", ("session_start", "global", (), "claude", "main")),
        # A subdirectory copy of a leaf with no nested type keeps its agent and loads on demand.
        ("src/AGENTS.override.md", ("on_demand", "nested", (), "codex", "override")),
        ("src/CONTEXT.md", ("on_demand", "nested", (), "antigravity", "cross_read")),
        # A subagent's own memory is named by a directory pattern; it loads into that subagent only.
        (
            ".claude/agent-memory/weather-agent/MEMORY.md",
            ("session_start", "task_scoped", (), "claude", "subagent_memory"),
        ),
        # A rule without a path filter still loads at session start.
        (".claude/rules/plain.md", ("session_start", "global", (), "claude", "rules")),
    ],
)
def test_nested_instruction_files_load_on_demand(tmp_path, rel, expected):
    path = _write(tmp_path, rel, "# Notes\n\nUse the shared client.\n")
    assert _detect_file_loading(path, tmp_path, _load_registry()) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("order", ["outer_first", "inner_first"], ids=["outer_first", "inner_first"])
def test_skill_typed_file_type_picks_the_deepest_owning_skill(tmp_path, order):
    """`.claude/skills/foo/SKILL.md` and `.claude/skills/foo/sub/SKILL.md` both contain
    `foo/sub/ref.md` -- the deepest (longest) skill directory must own it, not whichever
    directory the dict happens to iterate to first."""
    outer = _write(tmp_path, ".claude/skills/foo/SKILL.md", "# Foo\n")
    inner = _write(tmp_path, ".claude/skills/foo/sub/SKILL.md", "# Sub\n")
    outer_record = FileRecord(path=str(outer), content_hash="h1", type="skills")
    inner_record = FileRecord(path=str(inner), content_hash="h2", type="skills")
    records = [outer_record, inner_record] if order == "outer_first" else [inner_record, outer_record]

    skill_dirs = skill_dirs_by_owner(records)
    ref_path = tmp_path / ".claude" / "skills" / "foo" / "sub" / "ref.md"

    new_type, owner = skill_typed_file_type(ref_path, "generic", skill_dirs)

    assert new_type == "skills"
    assert owner is inner_record


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("rel", "key", "value"),
    [
        (".github/instructions/ts.instructions.md", "applyTo", '"**/*.ts,**/*.tsx"'),
        (".cursor/rules/ts.mdc", "globs", "src/**/*.ts, src/**/*.tsx"),
    ],
)
def test_a_comma_separated_path_filter_is_split_for_every_agent(tmp_path: Path, rel: str, key: str, value: str) -> None:
    path = _write(tmp_path, rel, f"---\n{key}: {value}\n---\nbody\n")
    _loading, _scope, globs, _agent, _ft = _detect_file_loading(path, tmp_path, _load_registry())
    assert len(globs) == 2 and all("," not in g for g in globs)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_the_agent_registry_is_read_through_the_cached_yaml_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    def _fail(*_a: object, **_k: object) -> None:
        raise AssertionError("slow loader used")

    monkeypatch.setattr(yaml, "safe_load", _fail)
    assert "claude" in _load_registry()
