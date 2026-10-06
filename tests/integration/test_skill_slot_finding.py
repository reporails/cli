"""CORE:S:0015 anchors on a skill slot folder; that finding is a Skills finding end to end."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from reporails_cli.core.mapper.inspect import _load_registry
from reporails_cli.core.mapper.skills import record_skills
from reporails_cli.core.pipeline.assemble import _local_finding_type_resolver
from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

_SKILL = "---\nname: good\ndescription: Does a good thing when asked.\n---\n\n# Good\n\nUse it.\n"


def _fixture(root: Path) -> None:
    (root / ".claude/skills/good").mkdir(parents=True)
    (root / ".claude/skills/broken").mkdir()
    (root / ".claude/skills/good/SKILL.md").write_text(_SKILL, encoding="utf-8")
    (root / ".claude/skills/broken/notes.md").write_text("# Notes\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text("# Project\n\nRun tests with pytest.\n", encoding="utf-8")


@pytest.mark.integration
@pytest.mark.subsys_map
def test_slot_finding_wire_type_is_skills_and_its_file_is_generic(tmp_path: Path) -> None:
    _fixture(tmp_path)
    recs = tuple(
        FileRecord(path=(tmp_path / rel).as_posix(), content_hash=rel, type=t, agent="claude")
        for rel, t in (
            (".claude/skills/good/SKILL.md", "skills"),
            (".claude/skills/broken/notes.md", "skills"),
            ("CLAUDE.md", "main"),
        )
    )
    rmap = RulesetMap(schema_version="1", embedding_model="", generated_at="2026-01-01T00:00:00Z", files=recs, atoms=())
    record_skills(rmap, ["claude"], tmp_path)
    typed = _local_finding_type_resolver(SimpleNamespace(ruleset_map=rmap, scan_root=tmp_path), _load_registry())  # type: ignore[arg-type]
    assert typed(str(tmp_path / ".claude/skills/broken")) == "skills"
    assert typed(str(tmp_path / ".claude/skills/broken/notes.md")) == "generic"
    assert typed(str(tmp_path / ".claude/skills/broken/README.md")) == "generic"  # unmapped, in a slot: a plain file
    assert typed(str(tmp_path / ".claude/skills/good/extra/README.md")) == "skills"  # below a recorded skill
    assert typed(str(tmp_path / "CLAUDE.md")) == "main"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_slot_finding_counts_on_skills_surface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fixture(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["check", "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    slot = data["files"][".claude/skills/broken"]["findings"]
    assert any(f["rule"] == "CORE:S:0015" for f in slot)
    skills = next(s for s in data["surface_health"] if s["name"] == "Skills")
    total = sum(len(v["findings"]) for k, v in data["files"].items() if k.startswith(".claude/skills/"))
    assert skills["finding_count"] == total
