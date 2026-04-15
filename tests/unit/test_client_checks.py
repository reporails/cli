"""Tests for core/client_checks.py — D-level checks."""

from __future__ import annotations

from reporails_cli.core.client_checks import run_client_checks
from reporails_cli.core.mapper.mapper import Atom, FileRecord, RulesetMap, RulesetSummary


def _make_map(atoms: list[Atom]) -> RulesetMap:
    """Build a minimal RulesetMap from atoms."""
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path="test.md", content_hash="sha256:abc"),),
        atoms=tuple(atoms),
        summary=RulesetSummary(n_atoms=len(atoms), n_charged=0, n_neutral=0),
    )


def _atom(line: int, charge_value: int, cluster_id: int = 0, position_index: int = 0, **kwargs: object) -> Atom:
    """Build a minimal Atom for testing."""
    charge = {-1: "CONSTRAINT", 0: "NEUTRAL", 1: "DIRECTIVE"}[charge_value]
    return Atom(
        line=line,
        text=kwargs.get("text", f"test atom at line {line}"),  # type: ignore[arg-type]
        kind="excitation",
        charge=charge,
        charge_value=charge_value,
        modality="direct",
        specificity="named",
        position_index=position_index,
        cluster_id=cluster_id,
        file_path="test.md",
        **{k: v for k, v in kwargs.items() if k != "text"},  # type: ignore[arg-type]
    )


class TestChargeOrdering:
    def test_inverted_ordering_detected(self) -> None:
        atoms = [
            _atom(10, -1, cluster_id=1, position_index=0),  # constraint first
            _atom(20, +1, cluster_id=1, position_index=1),  # directive second
        ]
        findings = run_client_checks(_make_map(atoms))
        ordering = [f for f in findings if f.rule == "ordering"]
        assert len(ordering) == 1
        assert "before directive" in ordering[0].message

    def test_correct_ordering_no_finding(self) -> None:
        atoms = [
            _atom(10, +1, cluster_id=1, position_index=0),  # directive first
            _atom(20, -1, cluster_id=1, position_index=1),  # constraint second
        ]
        findings = run_client_checks(_make_map(atoms))
        ordering = [f for f in findings if f.rule == "ordering"]
        assert len(ordering) == 0


class TestOrphanAtoms:
    def test_directive_only_cluster_not_orphan(self) -> None:
        """Directive-only is valid — no orphan finding.

        The golden pattern (+1, 0, -1) only requires a prohibition when there's
        a behavior to suppress. 'Use ruff' stands alone without a constraint.
        """
        atoms = [_atom(10, +1, cluster_id=1, position_index=0)]
        findings = run_client_checks(_make_map(atoms))
        orphans = [f for f in findings if f.rule == "orphan"]
        assert len(orphans) == 0

    def test_constraint_only_cluster(self) -> None:
        atoms = [_atom(10, -1, cluster_id=1, position_index=0)]
        findings = run_client_checks(_make_map(atoms))
        orphans = [f for f in findings if f.rule == "orphan"]
        assert len(orphans) == 1
        assert "prohibition" in orphans[0].message

    def test_balanced_cluster_no_orphan(self) -> None:
        atoms = [
            _atom(10, +1, cluster_id=1, position_index=0),
            _atom(20, -1, cluster_id=1, position_index=1),
        ]
        findings = run_client_checks(_make_map(atoms))
        orphans = [f for f in findings if f.rule == "orphan"]
        assert len(orphans) == 0


class TestUnformattedCode:
    def test_unformatted_tokens_detected(self) -> None:
        atoms = [_atom(10, +1, unformatted_code=["pytest"])]
        findings = run_client_checks(_make_map(atoms))
        fmt = [f for f in findings if f.rule == "format"]
        assert len(fmt) == 1
        assert "pytest" in fmt[0].message

    def test_no_unformatted_no_finding(self) -> None:
        atoms = [_atom(10, +1, unformatted_code=[])]
        findings = run_client_checks(_make_map(atoms))
        fmt = [f for f in findings if f.rule == "format"]
        assert len(fmt) == 0
