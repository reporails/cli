"""Charge floors and finding attribution in the mapper.

- A heading that names no action (`Step 2: PRD Structure`) titles its section and reads neutral.
- A charged heading takes its place in document order; a section-title heading does not.
- A bold label that a dash sets off from its instruction (`**Comments** — never log PII`) is not
  bold on that instruction.
- A line read out of a fence is charged like running text and keeps its `code_block` format.
- An instruction given with `should` reads hedged; `might` and `could` are not floored.
- A finding on an instruction an `@path` import brings in names the imported file and line.

The cases that read text end to end skip when the charge files are not bundled.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.client_checks import _check_bold_patterns
from reporails_cli.core.mapper import bio_pipeline
from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.mapper.bio_tagger import AtomTuple, Span
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.pipeline import _tokenize_and_cache
from reporails_cli.core.platform.dto.diagnostics import Diagnostic, FileAnalysis, RulesetReport
from reporails_cli.core.platform.dto.ruleset import (
    LIST_OBJECT_ROLE,
    Atom,
    FileRecord,
    RulesetMap,
    RulesetSummary,
)

_CHARGE = {-1: "CONSTRAINT", 0: "NEUTRAL", 1: "DIRECTIVE"}


def _atom(text: str, cv: int = 1, *, kind: str = "excitation", modality: str = "direct", **kw: object) -> Atom:
    return Atom(
        line=1,
        text=text,
        kind=kind,
        charge=_CHARGE[cv],
        charge_value=cv,
        modality=modality if cv else "none",
        specificity="abstract",
        plain_text=text,
        format="heading" if kind == "heading" else "prose",
        **kw,  # type: ignore[arg-type]
    )


def _span(text: str = "", offset: tuple[int, int] | None = None) -> Span:
    return Span(text, 0.9 if offset else 0.0, offset)


def _heading_tuple(text: str, polarity: int, predicate: Span) -> AtomTuple:
    empty = _span()
    return AtomTuple(polarity, "imperative", empty, predicate, empty, empty, 0.0, False, text)


def _charged(text: str) -> list[Atom]:
    """The decoded atoms for `text`, via the production tokenize → decode path."""
    return bio_pipeline.apply_multislot(tokenize(text))


# ── headings ────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_heading_that_decodes_no_action_reads_neutral() -> None:
    heading = _atom("Step 2: PRD Structure", 0, kind="heading")
    bio_pipeline._apply_heading_tuple(heading, _heading_tuple(heading.text, 1, _span()))
    assert (heading.charge, heading.charge_value, heading.modality) == ("NEUTRAL", 0, "none")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_heading_that_decodes_an_action_keeps_its_charge() -> None:
    heading = _atom("Step 3: Count Skills", 0, kind="heading")
    bio_pipeline._apply_heading_tuple(heading, _heading_tuple(heading.text, 1, _span("Count", (2, 3))))
    assert (heading.charge_value, heading.modality) == (1, "imperative")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_terse_no_prohibition_heading_keeps_its_charge_without_a_verb() -> None:
    heading = _atom("No Inline Chaining", 0, kind="heading")
    bio_pipeline._apply_heading_tuple(heading, _heading_tuple(heading.text, -1, _span()))
    assert heading.charge_value == -1


@pytest.mark.requires_model
@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_step_heading_naming_a_topic_reads_neutral_end_to_end() -> None:
    atoms = _charged("# Guide\n\n### Step 2: PRD Structure\n\nRun the tests before every commit.\n")
    heading = next(a for a in atoms if a.text == "Step 2: PRD Structure")
    assert heading.charge_value == 0


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_charged_heading_takes_its_place_in_document_order() -> None:
    from reporails_cli.core.mapper.parse import reindex_positions

    title = _atom("Guide", 0, kind="heading")
    rule_heading = _atom("Always follow these conventions", 1, kind="heading")
    first = _atom("Keep the diff small.")
    lead = _atom("Audit these files:")
    item = _atom("README.md", 0, role=LIST_OBJECT_ROLE)
    last = _atom("Run the tests.")
    atoms = [title, first, rule_heading, lead, item, last]
    reindex_positions(atoms)
    assert [a.position_index for a in atoms] == [0, 0, 1, 2, -1, 3]


@pytest.mark.requires_model
@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_charged_heading_holds_a_place_end_to_end() -> None:
    atoms = _charged("Keep the diff small.\n\n## Always follow these conventions\n\nRun the tests before merging.\n")
    heading = next(a for a in atoms if a.kind == "heading")
    assert heading.charge_value != 0
    assert [(a.kind, a.position_index) for a in atoms] == [("excitation", 0), ("heading", 1), ("excitation", 2)]


# ── bold label ──────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "text",
    [
        "**Comments** — never log PII in any handler.",
        "**Groups** - Organize related pages.",
        "**Named parameters**: always use one destructured object.",
    ],
)
def test_a_bold_label_that_titles_the_line_is_not_bold_on_it(text: str) -> None:
    assert check_specificity(text)[4] == []


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("text", "bold"),
    [
        ("Never commit **secrets** to the repository.", ["secrets"]),
        ("**Pre**-commit hooks run on every commit.", ["Pre"]),
        ("**Comments** — never log **PII** in any handler.", ["PII"]),
    ],
)
def test_bold_that_is_not_a_title_label_still_counts(text: str, bold: list[str]) -> None:
    assert check_specificity(text)[4] == bold


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_dash_set_bold_label_draws_no_local_bold_finding() -> None:
    atom = _atom("**Groups** - Organize related pages. Keep hierarchy shallow.", 1)
    assert _check_bold_patterns([atom], "SKILL.md") == []


@pytest.mark.requires_model
@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_prohibition_behind_a_bold_label_carries_no_bold() -> None:
    atoms = _charged("- **Comments** — never log PII in any handler.\n")
    prohibitions = [a for a in atoms if a.charge_value == -1]
    assert prohibitions
    assert all(a.bold_tokens == [] for a in prohibitions)


# ── fenced lines ────────────────────────────────────────────────────────────


@pytest.mark.requires_model
@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_fenced_never_line_is_charged_like_running_text() -> None:
    atoms = _charged("Rules:\n\n```\nNever push **directly** to the main branch.\n```\n")
    fenced = [a for a in atoms if a.format == "code_block"]
    assert fenced
    assert all(a.stage == "multislot" for a in fenced)
    never = next(a for a in fenced if "Never" in a.text)
    assert never.charge_value == -1
    # Fenced markdown is literal text: its `**` is not emphasis.
    assert never.bold_tokens == [] and never.italic_tokens == []


@pytest.mark.requires_model
@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_fenced_line_that_reads_as_no_instruction_stays_neutral() -> None:
    atoms = _charged("Ask like this:\n\n```\nNever skip the question.\nB. Increase user retention\n```\n")
    option = next(a for a in atoms if a.text.startswith("B."))
    assert (option.format, option.charge_value, option.stage) == ("code_block", 0, "")


@pytest.mark.requires_model
@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_code_fence_kept_whole_stays_one_neutral_block() -> None:
    atoms = _charged("Run it:\n\n```python\nprint('never')\n```\n")
    block = next(a for a in atoms if a.format == "code_block")
    assert (block.charge_value, block.stage) == (0, "")


# ── should ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("text", "hedged"),
    [
        ("You should run the linter before you open a pull request.", True),
        ("You should avoid long-running transactions.", True),
        ("You should not commit generated files.", True),
        ("Never merge on Friday; you should wait for Monday.", False),
        ("You must run the linter; the output should be clean.", False),
        ("You might want to cache expensive lookups.", False),
        ("You could split large modules into packages.", False),
    ],
)
def test_only_a_should_instruction_reads_hedged(text: str, hedged: bool) -> None:
    from reporails_cli.core.mapper.classify import hedges_with_should

    assert hedges_with_should(text) is hedged


@pytest.mark.unit
@pytest.mark.subsys_map
def test_the_should_floor_touches_only_charged_atoms_and_only_modality() -> None:
    from reporails_cli.core.mapper.parse import _apply_hedged_should_floor

    charged = _atom("You should avoid long-running transactions.", -1, modality="direct")
    neutral = _atom("The build should finish in a minute.", 0)
    could = _atom("You could split large modules into packages.", 1, modality="direct")
    _apply_hedged_should_floor([charged, neutral, could])
    assert (charged.charge_value, charged.modality) == (-1, "hedged")
    assert (neutral.charge_value, neutral.modality) == (0, "none")
    assert could.modality == "direct"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("text", "hedged"),
    [
        ("Perhaps run `pytest` after editing a migration.", True),
        ("Try not to use global state.", True),
        ("You could prefer real objects in tests.", False),
        ("Please consider running the linter.", True),
        ("Prefer real objects in tests.", True),
        ("Run the linter and try again.", False),
        ("Never try to bypass the hook.", False),
    ],
)
def test_an_instruction_opening_with_a_hedge_word_reads_hedged(text: str, hedged: bool) -> None:
    from reporails_cli.core.mapper.classify import hedges_with_lead

    assert hedges_with_lead(text) is hedged


@pytest.mark.unit
@pytest.mark.subsys_map
def test_the_hedge_floor_reads_a_lead_hedge_on_a_charged_atom() -> None:
    from reporails_cli.core.mapper.parse import _apply_hedged_should_floor

    lead = _atom("Try not to use global state.", -1, modality="imperative")
    neutral = _atom("Perhaps the build is slow.", 0)
    _apply_hedged_should_floor([lead, neutral])
    assert (lead.charge_value, lead.modality) == (-1, "hedged")
    assert (neutral.charge_value, neutral.modality) == (0, "none")


@pytest.mark.requires_model
@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_should_instruction_reads_hedged_end_to_end() -> None:
    atoms = _charged("You should run the linter before you open a pull request.\n")
    charged = [a for a in atoms if a.charge_value != 0]
    assert charged
    assert all(a.modality == "hedged" for a in charged)


# ── imported instructions ───────────────────────────────────────────────────


def _import_fixture(tmp_path: Path) -> Path:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "extra.md").write_text("Tag each release.\n", encoding="utf-8")
    (docs / "style.md").write_text("# Style\n\nKeep the diff small.\n\n@extra.md\n", encoding="utf-8")
    main = tmp_path / "CLAUDE.md"
    main.write_text("# Main\n\nRun the tests.\n\n@docs/style.md\n\nLint every file.\n", encoding="utf-8")
    return main


@pytest.mark.unit
@pytest.mark.subsys_map
def test_each_expanded_line_knows_the_file_and_line_it_is_written_in(tmp_path: Path) -> None:
    from reporails_cli.core.mapper.imports import expand_imports_with_origins

    main = _import_fixture(tmp_path)
    expanded, line_map, origins = expand_imports_with_origins(main.read_text(encoding="utf-8"), main)
    by_text = dict(zip(expanded.split("\n"), zip(line_map, origins, strict=True), strict=False))
    assert by_text["Run the tests."] == (3, None)
    assert by_text["Keep the diff small."] == (5, (tmp_path / "docs" / "style.md", 3))
    assert by_text["Tag each release."] == (5, (tmp_path / "docs" / "extra.md", 1))
    assert by_text["Lint every file."] == (7, None)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_an_imported_atom_keeps_the_import_line_and_names_where_it_is_written(tmp_path: Path) -> None:
    from reporails_cli.core.mapper.imports import expand_imports_with_origins

    main = _import_fixture(tmp_path)
    expanded, line_map, origins = expand_imports_with_origins(main.read_text(encoding="utf-8"), main)
    atoms = {a.text: a for a in _tokenize_and_cache(main, expanded, line_map, origins, "legacy")}
    kept = atoms["Keep the diff small."]
    assert (kept.line, kept.imported_from, kept.imported_line) == (5, "docs/style.md", 3)
    nested = atoms["Tag each release."]
    assert (nested.line, nested.imported_from, nested.imported_line) == (5, "docs/extra.md", 1)
    own = atoms["Lint every file."]
    assert (own.line, own.imported_from, own.imported_line) == (7, "", 0)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_finding_on_an_imported_instruction_names_its_file_and_line(tmp_path: Path) -> None:
    from reporails_cli.core.pipeline.assemble import name_imported_instructions

    main = tmp_path / "CLAUDE.md"
    own = _atom("Run the tests.", position_index=0, file_path=str(main))
    own.line = 3
    first = _atom("Use `pnpm` for installs.", position_index=1, file_path=str(main))
    second = _atom("Keep the diff small.", position_index=2, file_path=str(main))
    for atom, line in ((first, 3), (second, 7)):
        atom.line, atom.imported_from, atom.imported_line = 5, "docs/style.md", line
    rmap = RulesetMap(
        schema_version="1",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path=main.as_posix(), content_hash="sha256:x"),),
        atoms=(own, first, second),
        summary=RulesetSummary(n_atoms=3, n_charged=3, n_neutral=0),
    )
    brief = "Too brief (5 words) — not enough detail for the model to act on."
    report = RulesetReport(
        per_file=(
            FileAnalysis(
                file="CLAUDE.md",
                diagnostics=(
                    Diagnostic("CLAUDE.md", 3, "warning", "CORE:E:0004", brief, pi=0),
                    Diagnostic("CLAUDE.md", 5, "warning", "CORE:E:0004", brief, pi=1),
                    Diagnostic("CLAUDE.md", 5, "warning", "CORE:E:0004", brief, pi=2),
                    Diagnostic("CLAUDE.md", 5, "warning", "CORE:C:0053", "Too weak.", pi=None),
                ),
            ),
        )
    )
    messages = [d.message for d in name_imported_instructions(report, rmap, tmp_path).per_file[0].diagnostics]
    assert messages == [
        brief,
        f'{brief} (from docs/style.md:3: "Use `pnpm` for installs.")',
        f'{brief} (from docs/style.md:7: "Keep the diff small.")',
        "Too weak.",
    ]


@pytest.mark.unit
@pytest.mark.subsys_api
def test_a_server_finding_keeps_the_place_of_the_instruction_it_addresses() -> None:
    from reporails_cli.core.platform.adapters.api_client import _deserialize_per_file

    fa = _deserialize_per_file(
        {
            "per_file": [
                {
                    "file": "CLAUDE.md",
                    "diagnostics": [
                        {"line": 5, "severity": "warning", "rule": "CORE:E:0004", "message": "m", "pi": 2},
                        {"line": 1, "severity": "error", "rule": "CORE:C:0053", "message": "m", "pi": None},
                    ],
                }
            ]
        }
    )
    assert [d.pi for d in fa[0].diagnostics] == [2, None]
