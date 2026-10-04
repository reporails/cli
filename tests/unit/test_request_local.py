"""Tests for the local findings shipped to the scoring server.

Rules that run client-side reach the server as one entry per reported finding — rule, file,
line (0 for a whole-file finding), severity and check id. These tests cover which findings are
sent, the keys on the wire, and which entries survive the per-request bound.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.runner import run_mechanical_checks
from reporails_cli.core.lint.regex.compiler import display_severity
from reporails_cli.core.platform.adapters.payload import (
    _MAX_LOCAL_ENTRIES,
    encode_msgpack,
    local_entries,
    project_local,
)
from reporails_cli.core.platform.adapters.registry import registry_rule_ids, structural_rule_ids
from reporails_cli.core.platform.dto.models import (
    Category,
    Check,
    ClassifiedFile,
    FileMatch,
    Rule,
    RuleType,
    Severity,
)
from reporails_cli.core.platform.runtime.merger import FindingItem


def _finding(rule: str, severity: str = "error", file: str = "a.md", line: int = 1, check: str = "") -> FindingItem:
    return FindingItem(file=file, line=line, severity=severity, rule=rule, message="m", check_id=check)


def _entries(findings: list[FindingItem], file_level: frozenset[str] = frozenset()) -> list[tuple]:
    return [
        (e.rule, e.file, e.line)
        for e in local_entries(findings, file_level, frozenset(f.rule for f in findings), lambda rel: f"/p/{rel}")
    ]


class TestLocalEntries:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_each_finding_is_one_entry_in_order(self) -> None:
        findings = [
            _finding("CORE:C:0034", "error", file="a.md"),
            _finding("CORE:S:0007", "error", file="a.md", line=4),
            _finding("CORE:C:0034", "warning", file="a.md"),
            _finding("CORE:C:0042", "error", file="b.md"),
        ]
        assert _entries(findings) == [
            ("CORE:C:0034", "/p/a.md", 1),
            ("CORE:S:0007", "/p/a.md", 4),
            ("CORE:C:0034", "/p/a.md", 1),
            ("CORE:C:0042", "/p/b.md", 1),
        ]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_whole_file_finding_is_sent_at_line_zero(self) -> None:
        """A requirement check reports line 1 for display; the request says it is the whole file."""
        finding = _finding("CORE:C:0034", "warning", check="CORE.C.0034.content_check")
        assert _entries([finding], frozenset({"CORE.C.0034.content_check"})) == [("CORE:C:0034", "/p/a.md", 0)]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_instruction_level_findings_are_sent(self) -> None:
        rules = ("CORE:E:0006", "CORE:S:0039", "format", "bold", "heading_instruction")
        findings = [_finding(rule) for rule in rules]
        assert [e[0] for e in _entries(findings)] == list(rules)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_label_the_registry_does_not_define_is_not_sent(self) -> None:
        findings = [_finding("CORE:E:0006"), _finding("memory_frontmatter")]
        entries = local_entries(findings, frozenset(), frozenset({"CORE:E:0006"}), lambda rel: f"/p/{rel}")
        assert [e.rule for e in entries] == ["CORE:E:0006"]


class TestRequestWire:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_encoded_local_entries_carry_exactly_the_keys_r_f_l_s_k(self) -> None:
        import msgpack

        findings = [_finding("CORE:S:0007", "error", line=4), _finding("CORE:E:0006", "warning", line=2)]
        entries = local_entries(findings, frozenset(), frozenset(f.rule for f in findings), lambda rel: f"/p/{rel}")
        fields = project_local(entries, ["a.md"], Path("/p"))
        decoded = msgpack.unpackb(encode_msgpack(fields)[1:], raw=False)
        assert [set(e) for e in decoded["local"]] == [{"r", "f", "l", "s", "k"}] * 2
        assert [e["r"] for e in decoded["local"]] == ["CORE:S:0007", "CORE:E:0006"]

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_past_the_bound_error_entries_are_kept_first(self) -> None:
        findings = [_finding("CORE:C:0005", "warning", line=n) for n in range(_MAX_LOCAL_ENTRIES + 2)]
        findings += [_finding("CORE:S:0056", "error", line=n) for n in (3, 4)]
        entries = local_entries(findings, frozenset(), frozenset(f.rule for f in findings), lambda rel: f"/p/{rel}")
        sent = project_local(entries, ["/p/a.md"], Path("/p"))["local"]
        assert len(sent) == _MAX_LOCAL_ENTRIES
        assert [e["l"] for e in sent if e["s"] == "error"] == [3, 4]
        assert sent[0]["s"] == "error"


class TestBroadScopeIsSent:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_broad_scope_finding_is_one_entry(self) -> None:
        from reporails_cli.core.lint.client_checks import run_client_checks
        from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary

        atom = Atom(
            line=3,
            text="When any external service fails, retry the request.",
            kind="excitation",
            charge="DIRECTIVE",
            charge_value=1,
            modality="direct",
            specificity="named",
            position_index=0,
            file_path="a.md",
            scope_conditional=True,
        )
        ruleset = RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=(FileRecord(path="a.md", content_hash="sha256:abc"),),
            atoms=(atom,),
            summary=RulesetSummary(n_atoms=1, n_charged=1, n_neutral=0),
        )
        findings = run_client_checks(ruleset)
        assert [f.rule for f in findings] == ["CORE:C:0060"]
        entries = local_entries(findings, frozenset(), registry_rule_ids(), lambda rel: f"/p/{rel}")
        assert [(e.rule, e.line) for e in entries] == [("CORE:C:0060", 3)]
        assert "CORE:C:0060" not in structural_rule_ids()


class TestCodexOverLimit:
    """An over-limit Codex `AGENTS.md` chain produces an error entry on the main file's path.

    This exercises the real chain: `aggregate_byte_size` fires -> violation on the main path ->
    display severity `error` -> sent entry.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_codex_e_0001_is_in_structural_set(self) -> None:
        # The structural set must be resolved under the SAME agent the findings carry:
        # CODEX:E:0001 supersedes CORE:E:0001, so it only appears under the codex agent.
        # The no-agent (core-only) set would miss it and drop the over-limit finding.
        assert "CODEX:E:0001" in structural_rule_ids("codex")
        assert "CODEX:E:0001" not in structural_rule_ids("")

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_over_limit_chain_yields_error_entry_on_main_path(self, tmp_path: Path) -> None:
        agents = tmp_path / "AGENTS.md"
        agents.write_text("x" * 40_000)  # > 32 KiB Codex cap
        classified = [ClassifiedFile(path=agents, file_type="main", properties={"format": "freeform"})]
        rule = Rule(
            id="CODEX:E:0001",
            title="AGENTS.md Within Size Limit",
            category=Category.EFFICIENCY,
            type=RuleType.MECHANICAL,
            severity=Severity.HIGH,
            match=FileMatch(format="freeform"),
            checks=[
                Check(
                    id="CODEX.E.0001.check",
                    type="mechanical",
                    check="aggregate_byte_size",
                    args={"max": 32768},
                )
            ],
        )

        violations = run_mechanical_checks({"CODEX:E:0001": rule}, tmp_path, classified)
        assert len(violations) == 1

        findings = [
            FindingItem(
                file=v.location.rsplit(":", 1)[0],
                line=0,
                severity=display_severity(v.severity.value),
                rule=v.rule_id,
                message=v.message,
            )
            for v in violations
        ]
        entries = local_entries(findings, frozenset(), frozenset({"CODEX:E:0001"}), lambda rel: rel)
        assert [(e.file, e.severity) for e in entries] == [("AGENTS.md", "error")]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_within_limit_chain_yields_no_finding(self, tmp_path: Path) -> None:
        agents = tmp_path / "AGENTS.md"
        agents.write_text("x" * 1_000)  # well under the cap
        classified = [ClassifiedFile(path=agents, file_type="main", properties={"format": "freeform"})]
        rule = Rule(
            id="CODEX:E:0001",
            title="AGENTS.md Within Size Limit",
            category=Category.EFFICIENCY,
            type=RuleType.MECHANICAL,
            severity=Severity.HIGH,
            match=FileMatch(format="freeform"),
            checks=[
                Check(
                    id="CODEX.E.0001.check",
                    type="mechanical",
                    check="aggregate_byte_size",
                    args={"max": 32768},
                )
            ],
        )
        assert run_mechanical_checks({"CODEX:E:0001": rule}, tmp_path, classified) == []
