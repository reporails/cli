"""Integration tests for M→(M↔D)*n→S pipeline — metadata propagation and timing.

Exercises the full pipeline path through execute_rule_checks with synthetic
rules, real PipelineState, and crafted SARIF data. Every test asserts a
per-rule timing ceiling to catch algorithmic regressions.

M gate leads (file existence), then M and D interleave freely, then S.

Sequence coverage:
  M→D→M, M→D→M→S, M→D→D→M→S, M→D→M→D→S, M→M→D→M→D→S
"""

from __future__ import annotations

import time
from pathlib import Path

from reporails_cli.core.models import Category, Check, Rule, RuleType, Severity
from reporails_cli.core.pipeline import PipelineState, TargetMeta
from reporails_cli.core.pipeline_exec import execute_rule_checks

# Per-rule execution ceiling in milliseconds.
# Synthetic rules with tiny files should complete in <2ms.
# 50ms gives 25x headroom for CI variance while catching O(N) blowups.
RULE_EXEC_CEILING_MS = 50


def _timed_execute(rule, state, scan_root, tvars, instruction_files):
    """Wrap execute_rule_checks with timing assertion."""
    start = time.perf_counter()
    result = execute_rule_checks(rule, state, scan_root, tvars, instruction_files)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < RULE_EXEC_CEILING_MS, (
        f"Rule {rule.id} took {elapsed_ms:.1f}ms (ceiling: {RULE_EXEC_CEILING_MS}ms)"
    )
    return result


def _make_d_to_m_rule(
    rule_id: str,
    metadata_key: str,
    m_probe: str,
    m_args: dict | None = None,
) -> Rule:
    """Build a synthetic rule with D→M metadata propagation.

    Creates a two-check rule: deterministic extracts into metadata_key,
    mechanical consumes it via the named probe.
    """
    return Rule(
        id=rule_id,
        title=f"D→M test rule {rule_id}",
        category=Category.CONTENT,
        type=RuleType.DETERMINISTIC,
        level="L2",
        targets="{{instruction_files}}",
        checks=[
            Check(
                id=f"{rule_id}:check:0001",
                severity=Severity.MEDIUM,
                type="deterministic",
                metadata_keys=[metadata_key],
            ),
            Check(
                id=f"{rule_id}:check:0002",
                severity=Severity.HIGH,
                type="mechanical",
                check=m_probe,
                args=m_args or {},
                metadata_keys=[metadata_key],
            ),
        ],
    )


def _sarif_results(rule_id: str, check_num: str, matches: list[tuple[str, str, int]]) -> dict:
    """Build SARIF results for a rule's check.

    Args:
        rule_id: e.g. "CORE:C:0060"
        check_num: e.g. "0001"
        matches: list of (message_text, file_uri, line_number) tuples
    """
    sarif_rule_id = rule_id.replace(":", ".") + f".check.{check_num}"
    return {
        rule_id: [
            {
                "ruleId": sarif_rule_id,
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": line},
                        }
                    }
                ],
            }
            for msg, uri, line in matches
        ]
    }


class TestDToMCountAtMost:
    """D extracts items → M checks count_at_most → fires when too many."""

    def test_violation_when_count_exceeds_threshold(self, tmp_path: Path) -> None:
        """3 D matches with threshold=0 → M violation fires."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n")
        rule = _make_d_to_m_rule(
            "CORE:C:0060",
            metadata_key="style_rules",
            m_probe="count_at_most",
            m_args={"threshold": 0},
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = _sarif_results(
            "CORE:C:0060",
            "0001",
            [
                ("indent with 4 spaces", "CLAUDE.md", 3),
                ("use tabs for indent", "CLAUDE.md", 7),
                ("trailing comma required", "CLAUDE.md", 12),
            ],
        )
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        # D produced 3 violations
        d_findings = [f for f in state.findings if "check:0001" in (f.check_id or "")]
        assert len(d_findings) == 3

        # M consumed the 3-item list → exceeds threshold 0 → violation
        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0060:check:0002"]
        assert len(m_findings) == 1
        assert "exceeds" in m_findings[0].message

        # Annotations are on the target
        assert state.targets["CLAUDE.md"].annotations["style_rules"] == [
            "indent with 4 spaces",
            "use tabs for indent",
            "trailing comma required",
        ]

    def test_pass_when_count_within_threshold(self, tmp_path: Path) -> None:
        """1 D match with threshold=5 → M passes (no violation)."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n")
        rule = _make_d_to_m_rule(
            "CORE:C:0061",
            metadata_key="items",
            m_probe="count_at_most",
            m_args={"threshold": 5},
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = _sarif_results(
            "CORE:C:0061",
            "0001",
            [("single item", "CLAUDE.md", 1)],
        )
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0061:check:0002"]
        assert len(m_findings) == 0

    def test_no_d_matches_m_sees_empty(self, tmp_path: Path) -> None:
        """No SARIF results → D writes nothing → M sees no metadata → passes (0 <= threshold)."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n")
        rule = _make_d_to_m_rule(
            "CORE:C:0062",
            metadata_key="items",
            m_probe="count_at_most",
            m_args={"threshold": 0},
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        # No D results → no annotations → M gets empty args → count=0 ≤ threshold=0 → pass
        assert not any(f.check_id == "CORE:C:0062:check:0002" for f in state.findings)
        assert state.targets["CLAUDE.md"].annotations == {}


class TestDToMCountAtLeast:
    """D extracts items → M checks count_at_least → fires when too few."""

    def test_violation_when_below_minimum(self, tmp_path: Path) -> None:
        """1 D match with threshold=3 → count_at_least fires."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n")
        rule = _make_d_to_m_rule(
            "CORE:C:0063",
            metadata_key="prohibitions",
            m_probe="count_at_least",
            m_args={"threshold": 3},
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = _sarif_results(
            "CORE:C:0063",
            "0001",
            [("NEVER do X", "CLAUDE.md", 5)],
        )
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0063:check:0002"]
        assert len(m_findings) == 1
        assert "below" in m_findings[0].message

    def test_pass_when_meets_minimum(self, tmp_path: Path) -> None:
        """3 D matches with threshold=2 → count_at_least passes."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n")
        rule = _make_d_to_m_rule(
            "CORE:C:0064",
            metadata_key="prohibitions",
            m_probe="count_at_least",
            m_args={"threshold": 2},
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = _sarif_results(
            "CORE:C:0064",
            "0001",
            [
                ("NEVER do X", "CLAUDE.md", 5),
                ("DO NOT do Y", "CLAUDE.md", 8),
                ("MUST NOT do Z", "CLAUDE.md", 11),
            ],
        )
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0064:check:0002"]
        assert len(m_findings) == 0


class TestDToMImportTargetsExist:
    """D extracts @import paths → M resolves them against filesystem."""

    def test_all_imports_resolve(self, tmp_path: Path) -> None:
        """All extracted import paths exist → pass."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n@rules.md\n@config.md\n")
        (tmp_path / "rules.md").write_text("# Rules")
        (tmp_path / "config.md").write_text("# Config")
        rule = _make_d_to_m_rule(
            "CORE:C:0065",
            metadata_key="import_paths",
            m_probe="check_import_targets_exist",
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = _sarif_results(
            "CORE:C:0065",
            "0001",
            [
                ("@rules.md", "CLAUDE.md", 2),
                ("@config.md", "CLAUDE.md", 3),
            ],
        )
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0065:check:0002"]
        assert len(m_findings) == 0

    def test_missing_import_fires_violation(self, tmp_path: Path) -> None:
        """One import doesn't resolve → violation."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n@rules.md\n@missing.md\n")
        (tmp_path / "rules.md").write_text("# Rules")
        rule = _make_d_to_m_rule(
            "CORE:C:0066",
            metadata_key="import_paths",
            m_probe="check_import_targets_exist",
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = _sarif_results(
            "CORE:C:0066",
            "0001",
            [
                ("@rules.md", "CLAUDE.md", 2),
                ("@missing.md", "CLAUDE.md", 3),
            ],
        )
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0066:check:0002"]
        assert len(m_findings) == 1
        assert "missing.md" in m_findings[0].message


class TestMultipleMetadataKeys:
    """A single D check can write to multiple metadata keys."""

    def test_multiple_keys_propagated(self, tmp_path: Path) -> None:
        """D check with two metadata_keys writes same data to both annotations."""
        (tmp_path / "CLAUDE.md").write_text("# Hello\n")
        rule = Rule(
            id="CORE:C:0070",
            title="Multi-key test",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            targets="{{instruction_files}}",
            checks=[
                Check(
                    id="CORE:C:0070:check:0001",
                    severity=Severity.LOW,
                    type="deterministic",
                    metadata_keys=["key_alpha", "key_beta"],
                ),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = _sarif_results(
            "CORE:C:0070",
            "0001",
            [("data point", "CLAUDE.md", 1)],
        )
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        _timed_execute(rule, state, tmp_path, tvars, None)

        annotations = state.targets["CLAUDE.md"].annotations
        assert annotations["key_alpha"] == ["data point"]
        assert annotations["key_beta"] == ["data point"]


# ---------------------------------------------------------------------------
# Multi-gate sequence tests — representative signal catalog patterns
# ---------------------------------------------------------------------------


# Helper to build SARIF for a specific check within a rule
def _check_sarif(rule_id: str, check_num: str, messages: list[str], uri: str = "CLAUDE.md") -> list[dict]:
    """Build raw SARIF result list for one check."""
    sarif_rule_id = rule_id.replace(":", ".") + f".check.{check_num}"
    return [
        {
            "ruleId": sarif_rule_id,
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": i + 1},
                    }
                }
            ],
        }
        for i, msg in enumerate(messages)
    ]


class TestSequenceMDMS:
    """M→D→M→S: CODING_STYLE_ABSENT pattern.

    1. M: file_exists (gate)
    2. D: extract inline style rules → metadata_keys=[inline_style_rules]
    3. M: count_at_most(threshold=0) ← reads inline_style_rules
    4. S: semantic evaluation (produces JudgmentRequest)
    """

    def test_m_d_m_s_violation_fires(self, tmp_path: Path) -> None:
        """D finds style rules → M count_at_most(0) fires → S still produces JudgmentRequest."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# Project\nindent with 4 spaces\nSome content.\n")
        rule = Rule(
            id="CORE:C:0080",
            title="M→D→M→S test",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            targets="{{instruction_files}}",
            question="Are inline style rules harmful?",
            criteria=[{"key": "check1", "check": "Has inline style rules"}],
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0080:check:0001", severity=Severity.LOW, type="mechanical", check="file_exists"),
                Check(
                    id="CORE:C:0080:check:0002",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["inline_style_rules"],
                ),
                Check(
                    id="CORE:C:0080:check:0003",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 0},
                    metadata_keys=["inline_style_rules"],
                ),
                Check(id="CORE:C:0080:check:0004", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        # Semantic handler iterates ALL SARIF results for the rule to build requests.
        # Provide only the D results — semantic uses them as candidates.
        d_results = _check_sarif("CORE:C:0080", "0002", ["indent with 4 spaces"])
        state._sarif_by_rule = {"CORE:C:0080": d_results}
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        jrs = _timed_execute(rule, state, tmp_path, tvars, None)

        # M (file_exists) passed — no violation for check:0001
        assert not any(f.check_id == "CORE:C:0080:check:0001" for f in state.findings)
        # D produced violation + wrote annotations
        assert any("check:0002" in (f.check_id or "") for f in state.findings)
        assert state.targets["CLAUDE.md"].annotations["inline_style_rules"] == ["indent with 4 spaces"]
        # M (count_at_most 0) consumed 1-item list → violation
        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0080:check:0003"]
        assert len(m_findings) == 1
        # S produced JudgmentRequest (one per SARIF result available)
        assert len(jrs) == 1

    def test_m_d_m_s_no_style_rules_m_passes(self, tmp_path: Path) -> None:
        """D finds nothing → M count_at_most sees empty → passes → S still fires on SARIF."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# Clean project\nNo style rules here.\n")
        rule = Rule(
            id="CORE:C:0081",
            title="M→D→M→S clean test",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            targets="{{instruction_files}}",
            question="Is this clean?",
            criteria=[{"key": "check1", "check": "No inline styles"}],
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0081:check:0001", severity=Severity.LOW, type="mechanical", check="file_exists"),
                Check(
                    id="CORE:C:0081:check:0002",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["inline_style_rules"],
                ),
                Check(
                    id="CORE:C:0081:check:0003",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 0},
                    metadata_keys=["inline_style_rules"],
                ),
                Check(id="CORE:C:0081:check:0004", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        # Only semantic SARIF — D finds nothing
        s_results = _check_sarif("CORE:C:0081", "0004", ["semantic content"])
        state._sarif_by_rule = {"CORE:C:0081": s_results}
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        jrs = _timed_execute(rule, state, tmp_path, tvars, None)

        # No D violations, no M violations
        assert not any("check:0002" in (f.check_id or "") for f in state.findings)
        assert not any(f.check_id == "CORE:C:0081:check:0003" for f in state.findings)
        # S still fires (semantic SARIF exists)
        assert len(jrs) == 1


class TestSequenceMDDMS:
    """M→D→D→M→S: CONTENT_NON_REDUNDANT pattern.

    1. M: file_exists
    2. D: extract potentially redundant content → metadata_keys=[redundant_candidates]
    3. D: second deterministic check (another pattern)
    4. M: count_at_most ← reads redundant_candidates
    5. S: semantic evaluation
    """

    def test_m_d_d_m_s_two_d_checks_both_contribute(self, tmp_path: Path) -> None:
        """Two D checks: first writes metadata, second is a plain violation; M reads first's metadata."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# Project\nnpm install\npip install\nContent.\n")
        rule = Rule(
            id="CORE:C:0082",
            title="M→D→D→M→S test",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            targets="{{instruction_files}}",
            question="Is content non-redundant?",
            criteria=[{"key": "check1", "check": "No redundancy"}],
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0082:check:0001", severity=Severity.LOW, type="mechanical", check="file_exists"),
                Check(
                    id="CORE:C:0082:check:0002",
                    severity=Severity.LOW,
                    type="deterministic",
                    metadata_keys=["redundant_candidates"],
                ),
                Check(
                    id="CORE:C:0082:check:0003",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                ),
                Check(
                    id="CORE:C:0082:check:0004",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 2},
                    metadata_keys=["redundant_candidates"],
                ),
                Check(id="CORE:C:0082:check:0005", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        d1 = _check_sarif("CORE:C:0082", "0002", ["npm install", "pip install", "poetry add"])
        d2 = _check_sarif("CORE:C:0082", "0003", ["some other pattern"])
        state._sarif_by_rule = {"CORE:C:0082": d1 + d2}
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        jrs = _timed_execute(rule, state, tmp_path, tvars, None)

        # D1 wrote 3 items to redundant_candidates
        assert state.targets["CLAUDE.md"].annotations["redundant_candidates"] == [
            "npm install",
            "pip install",
            "poetry add",
        ]
        # D2 produced its own violation (no metadata_keys)
        d2_findings = [f for f in state.findings if "check:0003" in (f.check_id or "")]
        assert len(d2_findings) == 1
        # M (count_at_most 2) consumed 3-item list → violation (3 > 2)
        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0082:check:0004"]
        assert len(m_findings) == 1
        # S produced JudgmentRequests (semantic handler iterates all SARIF for rule)
        assert len(jrs) == 1


class TestSequenceMDMDS:
    """M→D→M→D→S: CONTENT_ACTIONABLE pattern.

    1. M: file_exists
    2. D: extract instruction sentences → metadata_keys=[instruction_sentences]
    3. M: count_at_least(threshold=1) ← reads instruction_sentences
    4. D: flag vague language → metadata_keys=[vague_flags]
    5. S: semantic evaluation
    """

    def test_m_d_m_d_s_full_chain(self, tmp_path: Path) -> None:
        """Full 5-step chain: each gate runs in order, metadata propagates correctly."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# Project\nAlways use strict mode.\nEnsure quality.\n")
        rule = Rule(
            id="CORE:C:0083",
            title="M→D→M→D→S test",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            targets="{{instruction_files}}",
            question="Are instructions specific?",
            criteria=[{"key": "check1", "check": "Specific instructions"}],
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0083:check:0001", severity=Severity.LOW, type="mechanical", check="file_exists"),
                Check(
                    id="CORE:C:0083:check:0002",
                    severity=Severity.LOW,
                    type="deterministic",
                    metadata_keys=["instruction_sentences"],
                ),
                Check(
                    id="CORE:C:0083:check:0003",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="count_at_least",
                    args={"threshold": 1},
                    metadata_keys=["instruction_sentences"],
                ),
                Check(
                    id="CORE:C:0083:check:0004",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["vague_flags"],
                ),
                Check(id="CORE:C:0083:check:0005", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        d1 = _check_sarif("CORE:C:0083", "0002", ["Always use strict mode"])
        d2 = _check_sarif("CORE:C:0083", "0004", ["ensure quality"])
        state._sarif_by_rule = {"CORE:C:0083": d1 + d2}
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        jrs = _timed_execute(rule, state, tmp_path, tvars, None)

        # D1 wrote instruction_sentences
        assert state.targets["CLAUDE.md"].annotations["instruction_sentences"] == ["Always use strict mode"]
        # M (count_at_least 1) sees 1 item → passes
        assert not any(f.check_id == "CORE:C:0083:check:0003" for f in state.findings)
        # D2 wrote vague_flags
        assert state.targets["CLAUDE.md"].annotations["vague_flags"] == ["ensure quality"]
        # S produced JudgmentRequests (one per SARIF result for the rule)
        assert len(jrs) == 1

    def test_m_d_m_d_s_no_instructions_m_fires(self, tmp_path: Path) -> None:
        """D1 finds nothing → M count_at_least(1) fires → rest continues."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# Empty project\nNo instructions.\n")
        rule = Rule(
            id="CORE:C:0084",
            title="M→D→M→D→S empty test",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            targets="{{instruction_files}}",
            question="Is this actionable?",
            criteria=[{"key": "check1", "check": "Actionable"}],
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0084:check:0001", severity=Severity.LOW, type="mechanical", check="file_exists"),
                Check(
                    id="CORE:C:0084:check:0002",
                    severity=Severity.LOW,
                    type="deterministic",
                    metadata_keys=["instruction_sentences"],
                ),
                Check(
                    id="CORE:C:0084:check:0003",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="count_at_least",
                    args={"threshold": 1},
                    metadata_keys=["instruction_sentences"],
                ),
                Check(
                    id="CORE:C:0084:check:0004",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["vague_flags"],
                ),
                Check(id="CORE:C:0084:check:0005", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        # No D results at all
        state._sarif_by_rule = {}
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        jrs = _timed_execute(rule, state, tmp_path, tvars, None)

        # M (count_at_least 1) with no metadata → empty → fires
        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0084:check:0003"]
        assert len(m_findings) == 1
        assert "below" in m_findings[0].message
        # S short-circuits (no SARIF candidates at all)
        assert jrs == []


class TestSequenceMMDMDS:
    """M→M→D→M→D→S: Deep sequence with two leading M checks.

    1. M: file_exists (gate)
    2. M: line_count (structural check)
    3. D: extract content → metadata_keys=[extracted_items]
    4. M: count_at_most ← reads extracted_items
    5. D: second extraction (plain violation)
    6. S: semantic evaluation
    """

    def test_m_m_d_m_d_s_full_deep_chain(self, tmp_path: Path) -> None:
        """6-step chain: two M gates, D→M metadata, second D, then S."""
        (tmp_path / ".git").mkdir()
        content = "# Project\n" + "\n".join(f"Line {i}" for i in range(20)) + "\n"
        (tmp_path / "CLAUDE.md").write_text(content)
        rule = Rule(
            id="CORE:C:0085",
            title="M→M→D→M→D→S test",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            targets="{{instruction_files}}",
            question="Is content well-structured?",
            criteria=[{"key": "check1", "check": "Well-structured"}],
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0085:check:0001", severity=Severity.LOW, type="mechanical", check="file_exists"),
                Check(
                    id="CORE:C:0085:check:0002",
                    severity=Severity.LOW,
                    type="mechanical",
                    check="line_count",
                    args={"max": 500},
                ),
                Check(
                    id="CORE:C:0085:check:0003",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["extracted_items"],
                ),
                Check(
                    id="CORE:C:0085:check:0004",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 1},
                    metadata_keys=["extracted_items"],
                ),
                Check(
                    id="CORE:C:0085:check:0005",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                ),
                Check(id="CORE:C:0085:check:0006", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        d1 = _check_sarif("CORE:C:0085", "0003", ["item A", "item B", "item C"])
        d2 = _check_sarif("CORE:C:0085", "0005", ["second det match"])
        state._sarif_by_rule = {"CORE:C:0085": d1 + d2}
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        jrs = _timed_execute(rule, state, tmp_path, tvars, None)

        # M1 (file_exists) passed
        assert not any(f.check_id == "CORE:C:0085:check:0001" for f in state.findings)
        # M2 (line_count max=500) passed (21 lines)
        assert not any(f.check_id == "CORE:C:0085:check:0002" for f in state.findings)
        # D1 wrote 3 items
        assert state.targets["CLAUDE.md"].annotations["extracted_items"] == ["item A", "item B", "item C"]
        # M3 (count_at_most 1) consumed 3-item list → violation
        m_findings = [f for f in state.findings if f.check_id == "CORE:C:0085:check:0004"]
        assert len(m_findings) == 1
        # D2 produced its own violation
        d2_findings = [f for f in state.findings if "check:0005" in (f.check_id or "")]
        assert len(d2_findings) == 1
        # S produced JudgmentRequests (one per SARIF result for the rule)
        assert len(jrs) == 1

    def test_m_m_d_m_d_s_line_count_fails(self, tmp_path: Path) -> None:
        """M2 (line_count) fails → violation recorded, but rest of chain continues."""
        (tmp_path / ".git").mkdir()
        content = "# Big\n" + "\n".join(f"Line {i}" for i in range(100)) + "\n"
        (tmp_path / "CLAUDE.md").write_text(content)
        rule = Rule(
            id="CORE:C:0086",
            title="M→M fail→D→M→D→S test",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            targets="{{instruction_files}}",
            question="Is content ok?",
            criteria=[{"key": "check1", "check": "OK"}],
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0086:check:0001", severity=Severity.LOW, type="mechanical", check="file_exists"),
                Check(
                    id="CORE:C:0086:check:0002",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="line_count",
                    args={"max": 10},
                ),
                Check(
                    id="CORE:C:0086:check:0003",
                    severity=Severity.LOW,
                    type="deterministic",
                    metadata_keys=["items"],
                ),
                Check(
                    id="CORE:C:0086:check:0004",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 5},
                    metadata_keys=["items"],
                ),
                Check(
                    id="CORE:C:0086:check:0005",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                ),
                Check(id="CORE:C:0086:check:0006", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        d1 = _check_sarif("CORE:C:0086", "0003", ["a", "b"])
        state._sarif_by_rule = {"CORE:C:0086": d1}
        tvars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        jrs = _timed_execute(rule, state, tmp_path, tvars, None)

        # M2 (line_count max=10) failed → violation
        m2_findings = [f for f in state.findings if f.check_id == "CORE:C:0086:check:0002"]
        assert len(m2_findings) == 1
        assert "exceeds" in m2_findings[0].message
        # D→M chain still ran despite M2 failure (non-blocking)
        assert state.targets["CLAUDE.md"].annotations["items"] == ["a", "b"]
        # M4 (count_at_most 5) passed (2 ≤ 5)
        assert not any(f.check_id == "CORE:C:0086:check:0004" for f in state.findings)
        # S produced JudgmentRequests (from D SARIF results as candidates)
        assert len(jrs) == 1
