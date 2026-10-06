"""Mutation-killing behavioral tests for `client_checks`.

Targets survivors in `_check_bold_patterns` (L134, L140), and pins that a charged
heading is left to the heading rule's own check.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary


def _make_map(atoms: list[Atom]) -> RulesetMap:
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path="test.md", content_hash="sha256:abc"),),
        atoms=tuple(atoms),
        summary=RulesetSummary(n_atoms=len(atoms), n_charged=0, n_neutral=0),
    )


def _atom(
    line: int,
    charge_value: int,
    *,
    kind: str = "excitation",
    position_index: int = 0,
    text: str | None = None,
) -> Atom:
    charge = {-1: "CONSTRAINT", 0: "NEUTRAL", 1: "DIRECTIVE"}[charge_value]
    text = text if text is not None else f"test atom at line {line}"
    return Atom(
        line=line,
        text=text,
        bold_tokens=check_specificity(text)[4],
        kind=kind,
        charge=charge,
        charge_value=charge_value,
        modality="direct",
        specificity="named",
        position_index=position_index,
        file_path="test.md",
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_charged_heading_is_left_to_the_heading_rule() -> None:
    # The client checks report no heading finding: the heading rule's check is its one emitter.
    atoms = [_atom(5, +1, kind="heading", text="Deploy the service now")]
    findings = run_client_checks(_make_map(atoms))
    assert [f for f in findings if "heading" in f.rule] == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fully_bold_atom_not_flagged() -> None:
    # Kills L134 `== -> !=`: a fully-bold atom (span == whole text) is skipped, no bold finding.
    atoms = [_atom(5, +1, text="**deploy the service**")]
    findings = run_client_checks(_make_map(atoms))
    bold = [f for f in findings if f.rule == "bold"]
    assert len(bold) == 0


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_partial_bold_directive_flagged() -> None:
    # Kills L140 `== -> !=`: a +1 directive with a harmful partial bold span is flagged.
    atoms = [_atom(5, +1, text="Please **carefully** review the code")]
    findings = run_client_checks(_make_map(atoms))
    bold = [f for f in findings if f.rule == "bold"]
    assert len(bold) == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_partial_bold_constraint_not_flagged() -> None:
    # Companion for L140: a -1 constraint with the same bold span is NOT flagged (bold is +1-only).
    atoms = [_atom(5, -1, text="Please **carefully** review the code")]
    findings = run_client_checks(_make_map(atoms))
    bold = [f for f in findings if f.rule == "bold"]
    assert len(bold) == 0
