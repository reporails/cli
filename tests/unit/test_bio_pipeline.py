"""Charge stage — stage routing + real-model smoke.

The ``map_ruleset`` charge-stage routing is tested with a stubbed applier so no
ONNX model is required. Real-model smoke tests skip when the artifacts are not
bundled.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper import bio_pipeline, bio_tagger, multislot_frames
from reporails_cli.core.mapper.bio_tagger import AtomTuple, Span
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.pipeline import _apply_charge_stage
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom(text: str, *, kind: str = "excitation", fmt: str = "prose", file_path: str = "a.md") -> Atom:
    atom = Atom(
        line=1,
        text=text,
        kind=kind,
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="abstract",
        plain_text=text,
        format=fmt,
        rule="p0_neutral",
    )
    atom.file_path = file_path
    return atom


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_stage_rebuilds_fresh_files_only(monkeypatch: pytest.MonkeyPatch) -> None:
    cached = _atom("Cached prose.", file_path="cached.md")
    fresh = _atom("Never commit to main.", file_path="fresh.md")
    replacement = _atom("Never commit to main.", file_path="fresh.md")
    replacement.charge, replacement.charge_value, replacement.stage = "CONSTRAINT", -1, "multislot"
    monkeypatch.setattr(bio_tagger, "multislot_available", lambda: True)
    # The charge stage batches every fresh file's decode in one call; the stub
    # returns one rebuilt group per input group (only the fresh group is passed).
    monkeypatch.setattr(bio_pipeline, "apply_multislot_groups", lambda groups, *a, **k: [[replacement] for _ in groups])

    all_atoms, fresh_out = _apply_charge_stage([cached, fresh], [fresh])
    assert all_atoms == [cached, replacement]
    assert fresh_out == [replacement]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_stage_noops_when_graphs_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    # No charge-classifier graphs bundled -> the stage is a no-op; atoms keep their lexical charge.
    monkeypatch.setattr(bio_tagger, "multislot_available", lambda: False)
    fresh = _atom("Use pytest.")
    all_atoms, fresh_out = _apply_charge_stage([fresh], [fresh])
    assert all_atoms == [fresh]
    assert fresh_out == [fresh]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_multislot_head_decodes_all_seven_outputs() -> None:
    # Swap-smoke: the bundled graph pair decodes a sentence through all seven named
    # outputs (subject split out of the object axis) without a shape error, and returns a
    # well-formed 5-tuple. Reddens if a graph swap changes an output name or shape
    # the decode depends on — including a missing `logits_subject`.
    if not bio_tagger.multislot_available():
        pytest.skip("charge-classifier graphs not bundled")
    t = bio_tagger.tag_atom_multislot("Always run the tests before committing.")
    assert t.polarity in (-1, 0, 1)
    assert t.modality in {"imperative", "direct", "absolute", "hedged", "none"}
    assert all(isinstance(s.text, str) for s in (t.subject, t.predicate, t.object, t.scope))
    assert 0.0 <= t.compound_prob <= 1.0


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_multislot_per_span_confidence_in_unit_range() -> None:
    # The triage consumes per-span confidence; each of the four span axes must
    # report a probability in [0, 1] (0.0 exactly when the axis decodes no span).
    if not bio_tagger.multislot_available():
        pytest.skip("charge-classifier graphs not bundled")
    t = bio_tagger.tag_atom_multislot("Do not commit secrets to the repository.")
    for span in (t.subject, t.predicate, t.object, t.scope):
        assert 0.0 <= span.conf <= 1.0
        # A span with text carries positive confidence; an empty span reads exactly 0.0.
        assert (span.conf > 0.0) == bool(span.text)


# ── named-ness survives the multislot rebuild ─────────────────────────────
# The multislot stage decodes every sentence from the parent's AST-clean
# `plain_text` (no formatting markers), so a span atom rebuilt from it must
# re-derive its specificity from the PARENT's formatted text projected onto
# the span — else every backticked name in a production map reads `abstract`
# (the defect: `CORE:C:0042` fired on fully backticked lines and could
# never be cleared by naming).


def _multislot_neutral_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route every sentence through the multislot rebuild as one neutral frame."""
    monkeypatch.setattr(bio_pipeline, "multislot_available", lambda: True)
    monkeypatch.setattr(bio_pipeline, "_decode_logits_batch", lambda texts: [None] * len(texts))


def _rebuilt(md: str, monkeypatch: pytest.MonkeyPatch) -> list[Atom]:
    _multislot_neutral_stub(monkeypatch)
    return bio_pipeline.apply_multislot(tokenize(md))


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_span_keeps_backtick_named_ness(monkeypatch: pytest.MonkeyPatch) -> None:
    md = "Load role depth via `/orient knowledge:roles/business-strategist/` before the first position forms."
    (atom,) = _rebuilt(md, monkeypatch)
    assert atom.stage == "multislot"
    assert (
        atom.plain_text
        == "Load role depth via /orient knowledge:roles/business-strategist/ before the first position forms."
    )
    assert atom.specificity == "named"
    assert atom.named_tokens == ["/orient knowledge:roles/business-strategist/"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_projects_markers_per_sentence_not_per_paragraph(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two sentences in one paragraph: only the second carries a code span. The
    # projection is per span — the first stays abstract, the second is named with
    # exactly its own token, and the bold / italic runs land on the sentence that
    # carries them.
    md = "The operator decides what ships. Run **`uv run poe qa_fast`** before *every* commit."
    first, second = _rebuilt(md, monkeypatch)
    assert (first.specificity, first.named_tokens, first.bold_tokens, first.italic_tokens) == ("abstract", [], [], [])
    assert second.specificity == "named"
    assert second.named_tokens == ["uv run poe qa_fast"]
    assert second.bold_tokens == ["`uv run poe qa_fast`"]
    assert second.italic_tokens == ["every"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_unformatted_code_excludes_backticked_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    # A code-shaped token INSIDE a code span is named, not "unformatted"; a bare
    # one outside stays unformatted — the same rule the legacy per-sentence path
    # applies to the formatted text.
    md = "Edit `formatters/mcp.py` and then run pytest.py to confirm."
    edit, run = _rebuilt(md, monkeypatch)
    assert (edit.text, run.text) == ("Edit `formatters/mcp.py`", "and then run pytest.py to confirm.")
    assert (edit.named_tokens, edit.unformatted_code, edit.specificity) == (["formatters/mcp.py"], [], "named")
    assert run.named_tokens == []
    assert run.unformatted_code == ["pytest", "pytest.py"]  # parity with check_specificity on the formatted text


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_structural_neutral_floor_survives_the_charge_head() -> None:
    # REGRESSION: a deterministically-determined NEUTRAL (a structural non-instruction)
    # must not be re-charged to ±1 by the argmax head — `_apply_structural_neutral_floor`
    # re-imposes it after the recharge, so the neutral charge is kept.
    for text in ["No mocks.", "See: config.md", "Knowledge: the theory doc"]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and all(a.charge_value == 0 and a.modality == "none" for a in atoms), (
            text,
            [(a.charge, a.charge_value, a.modality) for a in atoms],
        )
    # Real instructions are untouched by the floor (it fires only on the structural guards).
    for text, cv in [("Always run the tests", 1), ("Never mock the client", -1)]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert any(a.charge_value == cv for a in atoms), (
            text,
            [(a.charge, a.charge_value) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_structural_neutral_floor_keeps_a_riding_instruction() -> None:
    # REGRESSION: a label/narration opener must not zero the WHOLE atom
    # when a genuine instruction rides along after it on the production
    # path, where the head decodes the label+instruction as one continuous run.
    for text, cv in [
        ("Reference: never delete the cache directory.", -1),
        ("Triggers a rebuild; always run the linter afterwards.", 1),
    ]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert any(a.charge_value == cv for a in atoms), (text, [(a.charge, a.charge_value, a.text) for a in atoms])
    # Pure label/narration/status shapes (nothing rides along) still floor to neutral.
    for text in ["See docs/configuration.md.", "Knowledge: cli/map", "No mocks."]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and all(a.charge_value == 0 and a.modality == "none" for a in atoms), (
            text,
            [(a.charge, a.charge_value, a.modality) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_structural_floor_runs_before_deontic_floor() -> None:
    # The structural-NEUTRAL floor must run BEFORE the deontic
    # floor. A bare-negative item (`No mocks.`) matches both, and under `## Don'ts` the deontic
    # prohibition must win — so it stays CONSTRAINT, not reverted to NEUTRAL by the structural floor.
    atoms = bio_pipeline.apply_multislot(list(tokenize("## Donts\n\n- No mocks.\n", "structure-aware")))
    items = [a for a in atoms if a.kind != "heading"]
    assert items and all(a.charge_value == -1 for a in items), [(a.text, a.charge_value) for a in items]


# ── table cell-edge fold-back ───────────────────────────────────
# A table row is one joined line; a charge-run boundary that lands exactly on the
# `" | "` cell join must not orphan a bare label (`Deploy |`) from its neighbour.


def _empty_span() -> Span:
    return Span("", 0.0, None)


def _tuple(polarity: int, text: str, *, subject: Span | None = None) -> AtomTuple:
    empty = _empty_span()
    return AtomTuple(
        polarity, "direct" if polarity else "none", subject or empty, empty, empty, empty, 0.0, False, text
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_merge_cell_edge_frames_folds_bare_label_into_neighbour() -> None:
    frames = [_tuple(-1, "Deploy |"), _tuple(-1, "Never deploy on Friday")]
    merged = bio_pipeline._merge_cell_edge_frames(frames)
    assert len(merged) == 1
    assert merged[0].text == "Deploy | Never deploy on Friday"
    assert not merged[0].text.rstrip().endswith("|")
    assert merged[0].polarity == -1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_merge_cell_edge_frames_rebases_neighbour_span_offset() -> None:
    right_subject = Span("it", 0.9, (0, 1))
    frames = [_tuple(-1, "Deploy |"), _tuple(-1, "Never deploy on Friday", subject=right_subject)]
    merged = bio_pipeline._merge_cell_edge_frames(frames)
    (atom,) = merged
    # "Deploy |" is 2 words, so the neighbour's own (0, 1) offset rebases to (2, 3).
    assert atom.subject.offset == (2, 3)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_merge_cell_edge_frames_leaves_non_edge_frames_alone() -> None:
    frames = [_tuple(1, "Always run tests."), _tuple(-1, "Never skip linting.")]
    merged = bio_pipeline._merge_cell_edge_frames(frames)
    assert merged == frames


def _action(start: int, end: int) -> Span:
    return Span("act", 0.9, (start, end))


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_charged_run_with_no_action_folds_into_the_run_after_it() -> None:
    runs = [(0, 1, "DIRECTIVE", "direct", 0.9), (1, 5, "DIRECTIVE", "direct", 0.8)]
    assert multislot_frames._fold_actionless_runs(runs, [_action(1, 2)]) == [(0, 5, "DIRECTIVE", "direct", 0.8)]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_last_charged_run_with_no_action_folds_into_the_run_before_it() -> None:
    runs = [(0, 4, "DIRECTIVE", "direct", 0.9), (4, 5, "DIRECTIVE", "direct", 0.8)]
    assert multislot_frames._fold_actionless_runs(runs, [_action(0, 1)]) == [(0, 5, "DIRECTIVE", "direct", 0.9)]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "runs",
    [
        [(0, 2, "DIRECTIVE", "direct", 0.9), (2, 4, "RESTRICTIVE", "direct", 0.9)],
        [(0, 1, "NEUTRAL", "none", 0.9), (1, 4, "DIRECTIVE", "direct", 0.9)],
        [(0, 4, "DIRECTIVE", "direct", 0.9)],
    ],
)
def test_a_run_with_no_action_stays_apart_from_an_opposite_sign_or_alone(runs: list) -> None:
    assert multislot_frames._fold_actionless_runs(runs, [_action(0, 1)] if runs[0][2] == "DIRECTIVE" else []) == runs


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
@pytest.mark.parametrize(
    ("line", "instruction"),
    [
        (
            "Or audit a subset: `/audit-agent codex`, `/audit-agent cursor`, etc.",
            "Or audit a subset: `/audit-agent codex`, `/audit-agent cursor`, etc.",
        ),
        (
            "Cross-team-touching tickets require lead approval per ADR-0005 before they file publicly.",
            "Cross-team-touching tickets require lead approval per ADR-0005 before they file publicly.",
        ),
        (
            "- *Pre-release validation.* `scripts/pre-release-check.sh` must probe external API contracts (auth "
            "surface returns JSON) and validate Python-version constraints match `pyproject.toml requires-python`.",
            "`scripts/pre-release-check.sh` must probe external API contracts (auth surface returns JSON) and "
            "validate Python-version constraints match `pyproject.toml requires-python`.",
        ),
    ],
)
def test_a_subject_or_joining_word_is_not_an_instruction_of_its_own(line: str, instruction: str) -> None:
    atoms = bio_pipeline.apply_multislot(list(tokenize(f"# Rules\n\n{line}\n")))
    assert [a.text for a in atoms if a.charge_value != 0] == [instruction]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_a_quoted_sample_line_stays_one_neutral_quotation() -> None:
    quote = (
        '"Official docs recommend X. However, we found Y works better (confirmed in 3 builds). Consider both options."'
    )
    atoms = [a for a in bio_pipeline.apply_multislot(list(tokenize(f"# Use\n\n> {quote}\n"))) if a.kind != "heading"]
    assert [(a.text, a.charge_value) for a in atoms] == [(quote, 0)]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_table_cell_edge_cut_becomes_one_atom() -> None:
    md = "| Step | Rule |\n| --- | --- |\n| Deploy | Never deploy on Friday |\n"
    atoms = bio_pipeline.apply_multislot(list(tokenize(md)))
    rows = [a for a in atoms if a.kind != "heading" and a.format == "table" and "Deploy" in a.text]
    assert len(rows) == 1, [a.text for a in rows]
    assert rows[0].text == "Deploy | Never deploy on Friday"
    assert not rows[0].text.rstrip().endswith("|")


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_table_row_two_independent_sentences_still_yields_two_atoms() -> None:
    md = "| Cell | Rule |\n| --- | --- |\n| A | Always run it. Do not skip it. |\n"
    atoms = bio_pipeline.apply_multislot(list(tokenize(md)))
    rows = [a for a in atoms if a.kind != "heading" and a.format == "table" and a.text != "Cell | Rule"]
    assert len(rows) == 2, [a.text for a in rows]
    assert any(a.text.startswith("A |") for a in rows)
    assert any(a.text == "Do not skip it." for a in rows)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_table_header_row_is_a_label_row_not_an_instruction() -> None:
    # `Leverage tier | Severity floor | Reading` names columns; `Leverage` is not an imperative.
    md = "| Leverage tier | Severity floor | Reading |\n| --- | --- | --- |\n| Deploy | Never deploy on Friday |\n"
    atoms = [a for a in tokenize(md) if a.format == "table"]
    header = next(a for a in atoms if a.line == 1)
    assert (header.charge, header.charge_value) == ("NEUTRAL", 0)
    assert header.text == "Leverage tier | Severity floor | Reading", "the header's words are kept"
    assert any(a.charge_value != 0 for a in atoms if a.line == 3), "a body row still carries its instruction"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_table_header_row_stays_neutral_through_the_charge_head() -> None:
    md = "| Leverage tier | Severity floor | Reading |\n| --- | --- | --- |\n| Deploy | Never deploy on Friday |\n"
    atoms = bio_pipeline.apply_multislot(list(tokenize(md)))
    header = [a for a in atoms if a.format == "table" and a.line == 1]
    assert [(a.text, a.charge_value) for a in header] == [("Leverage tier | Severity floor | Reading", 0)]
    assert any(a.charge_value == -1 for a in atoms if a.format == "table" and a.line == 3)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
@pytest.mark.parametrize(
    "header",
    [
        "| Don't | Do |",  # a do/don't table: the prohibition words label a column
        "| No. | Rule | Owner |",  # a numbering column reads like a terse `No <what>` prohibition
        "| Always | Never |",  # labels of opposite sign are not two instructions
        "| Do this; never that | Why |",
    ],
)
@pytest.mark.parametrize("segmentation", ["legacy", "structure-aware"])
def test_a_table_header_with_charge_words_stays_a_neutral_label(header: str, segmentation: str) -> None:
    columns = header.count("|") - 1
    md = f"{header}\n|{'---|' * columns}\n|{' push to main |' * columns}\n"
    atoms = bio_pipeline.apply_multislot(list(tokenize(md, segmentation)))
    (row,) = [a for a in atoms if a.format == "table" and a.line == 1]
    assert (row.charge, row.charge_value) == ("NEUTRAL", 0)


# ── conditional-frame wiring (scope_conditional) ─────────────────────────────
# The head decodes a `scope` slot; `Atom.scope_conditional` is what two paid-surface
# checks read (`has_branching_steps`, `_check_broad_scope`) and what the wire's `sc`
# field carries. It must be DERIVED from that decode, not hardcoded off.


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_multislot_marks_a_conditional_frame_scope_conditional() -> None:
    for text in [
        "If the tests fail, do not push.",
        "When editing migrations, run the linter first.",
        "Only for TypeScript files, prefer interfaces.",
        "Keep the file unless it is empty.",
    ]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and any(a.scope_conditional for a in atoms), (
            text,
            [(a.text, a.scope_conditional) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_multislot_leaves_an_unconditional_sentence_unconditional() -> None:
    for text in [
        "Always run the linter.",
        "Format the code with the project formatter.",
        "Never commit a credential.",
        # A frame word that opens no frame — the subject of the sentence, or a
        # heading. A frame closes on a comma/`then` before the main clause.
        "While loops must be bounded.",
        "Before hooks run on every commit.",
    ]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and not any(a.scope_conditional for a in atoms), (
            text,
            [(a.text, a.scope_conditional) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_multislot_leaves_a_frame_word_heading_unconditional() -> None:
    # `## When to use` is a section label, not a condition on anything.
    atoms = bio_pipeline.apply_multislot(list(tokenize("## When to use\n\nRun the linter.\n")))
    headings = [a for a in atoms if a.kind == "heading"]
    assert headings and not any(a.scope_conditional for a in headings), [
        (a.text, a.scope_conditional) for a in headings
    ]


# ── `No <complement>` prohibition vs `No <noun>` status ──────────────────────
# A terse prohibition carries a complement (`No hardcoded secrets in code`); a status
# line is a bare noun phrase (`No open issues.`). The head scores both as plain
# statements, so the deterministic discriminator has to floor the prohibition back.


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_complemented_no_prohibition_charges_constraint() -> None:
    for text in [
        "No blank lines between sections.",
        "No hardcoded secrets in code.",
        "No console.log in production code.",
        "No console logging in tests.",
        "No secrets in seed.",
        "No string formatting in log calls.",
    ]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and all(a.charge_value == -1 and a.charge == "CONSTRAINT" for a in atoms), (
            text,
            [(a.text, a.charge, a.charge_value) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_terse_no_prohibition_without_a_complement_charges_constraint() -> None:
    # A `No <thing>` line names what is forbidden; the scope complement is optional.
    for text in ["No console.log", "No hardcoded secrets", "No blank lines"]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and all(a.charge_value == -1 and a.charge == "CONSTRAINT" for a in atoms), (
            text,
            [(a.text, a.charge, a.charge_value) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_described_absence_is_not_a_prohibition() -> None:
    # `for`/`of` name what is absent, not where a rule binds; a status adverb reports.
    # (The floor only declines to PROMOTE — a charge the head itself decoded stands.)
    for text in ["No support for Windows", "No data in this table yet"]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and all(a.charge_value == 0 for a in atoms), (
            text,
            [(a.text, a.charge, a.charge_value) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_bare_no_status_line_stays_neutral() -> None:
    for text in [
        "No regressions.",
        "No open issues.",
        "No changes.",
        "None.",
        "No cloud dependencies",
        "No drift detected on the tracked dimensions",
    ]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and all(a.charge_value == 0 and a.modality == "none" for a in atoms), (
            text,
            [(a.text, a.charge, a.charge_value) for a in atoms],
        )


# ── `<Label>: see <ref>` cross-reference ─────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_labelled_see_reference_stays_neutral() -> None:
    for text in [
        "Knowledge: see docs/architecture/map.md",
        "Design: see docs/architecture.md",
        "See also: docs/architecture.md",
    ]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert atoms and all(a.charge_value == 0 and a.modality == "none" for a in atoms), (
            text,
            [(a.text, a.charge, a.charge_value) for a in atoms],
        )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_labelled_see_reference_keeps_a_riding_prohibition() -> None:
    text = "Knowledge: see the runbook, and never commit a credential."
    atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
    assert any(a.charge_value == -1 for a in atoms), [(a.text, a.charge, a.charge_value) for a in atoms]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_instruction_fronting_a_see_pointer_keeps_its_charge() -> None:
    # The label of a `<Label>: see ...` pointer is a bare noun, not a clause.
    for text in [
        "Never commit secrets: see security.md",
        "Always run the linter first: see docs/lint.md",
        "Do not skip tests: see CONTRIBUTING.md",
    ]:
        atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
        assert any(a.charge_value != 0 for a in atoms), [(a.text, a.charge, a.charge_value) for a in atoms]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")
def test_pointer_title_carrying_and_is_still_a_pointer() -> None:
    # `and` inside a reference title does not break the pointer into a second clause.
    text = "Knowledge: see the build and deploy guide"
    atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
    assert all(a.charge_value == 0 for a in atoms), [(a.text, a.charge, a.charge_value) for a in atoms]
