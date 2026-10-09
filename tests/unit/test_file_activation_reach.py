"""Each file record carries when its agent loads it (`activation`) and which project files and
folders its text points at (`reach`); the wire carries both as codes and paths, never text."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.inspect import _detect_file_activation, _load_registry
from reporails_cli.core.mapper.reach import MAX_REACH, record_reach
from reporails_cli.core.platform.adapters.payload import project_payload
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary


def _activation(root: Path, rel: str, frontmatter: str = "", registry=None) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{frontmatter}---\n\nBody.\n" if frontmatter else "Body.\n", encoding="utf-8")
    return _detect_file_activation(path, root, registry or _load_registry())[5]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("rel", "frontmatter", "expected"),
    [
        ("CLAUDE.md", "", "always"),
        (".claude/rules/a.md", "", "always"),
        (".claude/rules/a.md", 'paths: "src/**"\n', "file_match"),
        ("pkg/CLAUDE.md", "", "subtree"),
        (".github/instructions/a.instructions.md", "", "manual"),
        (".github/instructions/a.instructions.md", "description: Use for API work\n", "agent_decides"),
        (".github/instructions/a.instructions.md", 'applyTo: "src/**"\n', "file_match"),
        (".cursor/rules/a.mdc", "description: Use for UI\nalwaysApply: false\n", "agent_decides"),
        (".cursor/rules/a.mdc", "alwaysApply: true\n", "always"),
        (".agents/rules/a.md", "trigger: model_decision\ndescription: d\n", "agent_decides"),
        (".agents/rules/a.md", "trigger: manual\n", "manual"),
        (".claude/skills/s/SKILL.md", "name: s\ndescription: d\n", "invoked"),
        (".claude/agents/a.md", "name: a\ndescription: d\n", "invoked"),
    ],
)
def test_activation(tmp_path: Path, rel: str, frontmatter: str, expected: str) -> None:
    assert _activation(tmp_path, rel, frontmatter) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
def test_codex_nested_agents_md_loads_only_when_a_run_starts_in_its_folder(tmp_path: Path) -> None:
    registry = {"codex": _load_registry()["codex"]}
    assert _activation(tmp_path, "AGENTS.md", registry=registry) == "always"
    assert _activation(tmp_path, "pkg/AGENTS.md", registry=registry) == "launch_subtree"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_claude_nested_agents_md_is_subtree(tmp_path: Path) -> None:
    registry = {"claude": _load_registry()["claude"]}
    assert _activation(tmp_path, "pkg/AGENTS.md", registry=registry) == "subtree"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_memory_topic_file_is_manual(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = tmp_path / "proj"
    root.mkdir()
    note = home / ".claude" / "projects" / "proj-slug" / "memory" / "notes.md"
    note.parent.mkdir(parents=True)
    note.write_text("# Notes\n", encoding="utf-8")
    result = _detect_file_activation(note, root, _load_registry())
    assert result[4] == "memory"
    assert result[5] == "manual"


def _map(root: Path, files: dict[str, str], tokens: dict[str, list[str]] | None = None) -> RulesetMap:
    records, atoms = [], []
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        records.append(FileRecord(path=p.as_posix(), content_hash="sha256:x"))
        if tokens and rel in tokens:
            atoms.append(
                Atom(
                    line=1,
                    text="t",
                    kind="instruction",
                    charge="NEUTRAL",
                    charge_value=0,
                    modality="none",
                    specificity="named",
                    named_tokens=tokens[rel],
                    file_path=p.as_posix(),
                )
            )
    return RulesetMap(
        schema_version="1",
        embedding_model="m",
        generated_at="t",
        files=tuple(records),
        atoms=tuple(atoms),
        summary=RulesetSummary(n_atoms=len(atoms), n_charged=0, n_neutral=len(atoms)),
    )


def _reach(root: Path, files: dict[str, str], tokens=None) -> dict[str, tuple[str, ...]]:
    m = _map(root, files, tokens)
    record_reach(m, root)
    return {
        Path(f.path).relative_to(root).as_posix(): tuple(Path(r).relative_to(root).as_posix() for r in f.reach)
        for f in m.files
    }


@pytest.mark.unit
@pytest.mark.subsys_map
def test_reach_from_backtick_link_and_import(tmp_path: Path) -> None:
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("g\n", encoding="utf-8")
    (tmp_path / "shared.md").write_text("s\n", encoding="utf-8")
    reach = _reach(
        tmp_path,
        {"CLAUDE.md": "Run `src/app/`.\nSee [guide](docs/guide.md#top).\n@shared.md\n"},
        {"CLAUDE.md": ["src/app/"]},
    )
    assert reach["CLAUDE.md"] == ("docs/guide.md", "shared.md", "src/app")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_reach_resolves_against_own_folder_then_root(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "local.py").write_text("x\n", encoding="utf-8")
    (tmp_path / "top.py").write_text("x\n", encoding="utf-8")
    reach = _reach(tmp_path, {"pkg/AGENTS.md": "x\n"}, {"pkg/AGENTS.md": ["local.py", "top.py"]})
    assert reach["pkg/AGENTS.md"] == ("pkg/local.py", "top.py")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_reach_drops_missing_and_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (tmp_path / "secret.md").write_text("s\n", encoding="utf-8")
    reach = _reach(
        root,
        {"CLAUDE.md": "[x](../secret.md) [y](gone.md)\n"},
        {"CLAUDE.md": ["missing.py", "../secret.md", "https://example.com/a"]},
    )
    assert reach["CLAUDE.md"] == ()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_reach_is_capped(tmp_path: Path) -> None:
    names = [f"f{i:03d}.txt" for i in range(MAX_REACH + 20)]
    for n in names:
        (tmp_path / n).write_text("x\n", encoding="utf-8")
    reach = _reach(tmp_path, {"CLAUDE.md": "x\n"}, {"CLAUDE.md": names})
    assert reach["CLAUDE.md"] == tuple(names[:MAX_REACH])


@pytest.mark.unit
@pytest.mark.subsys_map
def test_wire_carries_act_and_reach_but_no_text(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    m = _map(tmp_path, {"CLAUDE.md": "Secret prose `src`.\n"}, {"CLAUDE.md": ["src"]})
    m.files[0].activation = "always"
    record_reach(m, tmp_path)
    files = project_payload(m, tmp_path)["files"]
    assert files[0]["act"] == "always"
    assert files[0]["reach"] == ["src"]
    assert "Secret prose" not in repr(files)
    bare = _map(tmp_path, {"b/CLAUDE.md": "x\n"})
    bare.files[0].activation = ""
    out = project_payload(bare, tmp_path)["files"][0]
    assert "act" not in out and "reach" not in out
