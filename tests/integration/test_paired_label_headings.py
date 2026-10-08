"""A heading that labels a category beside a sibling label is not an instruction (CORE:S:0039).

`## Keep — …` beside `## Partial — …` sorts a memory index into groups; the verb-shaped word
`Keep` must not read as an imperative. A heading that gives an instruction, or a label with
no sibling label, keeps its verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.mapper import bio_pipeline
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

KEEP = "## Keep — maintainer-ordered notes"
PARTIAL = "## Partial — docs cover most, residual scope noted"
ITEMS = "- [Title one](one.md) — first hook\n- [Title two](two.md) — second hook\n"
MEMORY_INDEX = f"# Memory\n\n{KEEP}\n\n{ITEMS}\n{PARTIAL}\n\n{ITEMS}"


def _check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> set[str]:
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project\n\nA minimal CLAUDE.md.\n", encoding="utf-8")
    (project / ".claude" / "rules" / "memory.md").write_text(body, encoding="utf-8")
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "--agent", "claude", "-f", "json"])
    data = json.loads(result.output[result.output.index("{") :])
    return {f["rule"] for record in data.get("files", {}).values() for f in record["findings"]}


@pytest.mark.e2e
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_paired_label_headings_raise_no_heading_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert "CORE:S:0039" not in _check(tmp_path, monkeypatch, MEMORY_INDEX)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_paired_label_heading_atoms_carry_no_charge() -> None:
    atoms = bio_pipeline.apply_multislot(tokenize(MEMORY_INDEX))
    labels = [a for a in atoms if a.kind == "heading" and a.depth == 2]
    assert [a.charge_value for a in labels] == [0, 0]
    assert [a.modality for a in labels] == ["none", "none"]


@pytest.mark.e2e
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_an_instruction_heading_still_raises_the_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = "## Run the tests before you commit\n\nUse pytest for all test runs.\n"
    assert "CORE:S:0039" in _check(tmp_path, monkeypatch, body)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_an_unpaired_label_heading_keeps_its_verdict() -> None:
    atoms = bio_pipeline.apply_multislot(tokenize(f"# Memory\n\n{KEEP}\n\n{ITEMS}"))
    heading = next(a for a in atoms if a.kind == "heading" and a.depth == 2)
    assert heading.charge_value != 0  # today's verdict: "Keep" reads as an imperative


DIRECTIVE_PAIR = (
    "# Rules\n\n## Always — run the tests before pushing\n\nFirst body.\n\n"
    "## Never — force-push to main\n\nSecond body.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_paired_directive_headings_keep_their_charge() -> None:
    atoms = bio_pipeline.apply_multislot(tokenize(DIRECTIVE_PAIR))
    labels = [a for a in atoms if a.kind == "heading" and a.depth == 2]
    assert len(labels) == 2
    assert all(a.charge_value != 0 for a in labels)


@pytest.mark.e2e
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_paired_directive_headings_still_raise_the_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert "CORE:S:0039" in _check(tmp_path, monkeypatch, DIRECTIVE_PAIR)


INSTRUCTION_TAIL_PAIR = (
    "# Rules\n\n## Keep — never force-push to main\n\nFirst body.\n\n"
    "## Drop — always rebase before merging\n\nSecond body.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_paired_headings_with_an_instruction_after_the_dash_keep_their_charge() -> None:
    atoms = bio_pipeline.apply_multislot(tokenize(INSTRUCTION_TAIL_PAIR))
    labels = [a for a in atoms if a.kind == "heading" and a.depth == 2]
    assert len(labels) == 2
    assert all(a.charge_value != 0 for a in labels)


@pytest.mark.e2e
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_paired_headings_with_an_instruction_after_the_dash_still_raise_the_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "CORE:S:0039" in _check(tmp_path, monkeypatch, INSTRUCTION_TAIL_PAIR)
