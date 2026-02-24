"""Unit tests for pipeline state engine."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.models import Category, Check, Rule, RuleType, Severity
from reporails_cli.core.pipeline import PipelineState, TargetMeta, build_initial_state
from reporails_cli.core.pipeline_exec import execute_rule_checks
from reporails_cli.core.sarif import distribute_sarif_by_rule

# ---------------------------------------------------------------------------
# TargetMeta
# ---------------------------------------------------------------------------


class TestTargetMeta:
    def test_defaults(self) -> None:
        meta = TargetMeta(path=Path("CLAUDE.md"))
        assert not meta.excluded
        assert meta.excluded_by is None
        assert meta.annotations == {}

    def test_exclusion(self) -> None:
        meta = TargetMeta(path=Path("CLAUDE.md"))
        meta.excluded = True
        meta.excluded_by = "file_exists"
        assert meta.excluded
        assert meta.excluded_by == "file_exists"

    def test_annotations(self) -> None:
        meta = TargetMeta(path=Path("CLAUDE.md"))
        meta.annotations["discovered_imports"] = ["foo", "bar"]
        assert meta.annotations["discovered_imports"] == ["foo", "bar"]


# ---------------------------------------------------------------------------
# PipelineState
# ---------------------------------------------------------------------------


class TestPipelineState:
    def test_active_targets_excludes_excluded(self) -> None:
        state = PipelineState()
        state.targets["a.md"] = TargetMeta(path=Path("a.md"))
        state.targets["b.md"] = TargetMeta(path=Path("b.md"), excluded=True, excluded_by="file_exists")
        state.targets["c.md"] = TargetMeta(path=Path("c.md"))

        active = state.active_targets()
        assert len(active) == 2
        paths = {t.path for t in active}
        assert Path("a.md") in paths
        assert Path("c.md") in paths

    def test_active_targets_all_active(self) -> None:
        state = PipelineState()
        state.targets["a.md"] = TargetMeta(path=Path("a.md"))
        state.targets["b.md"] = TargetMeta(path=Path("b.md"))
        assert len(state.active_targets()) == 2

    def test_active_targets_empty(self) -> None:
        state = PipelineState()
        assert state.active_targets() == []

    def test_exclude_target(self) -> None:
        state = PipelineState()
        state.targets["a.md"] = TargetMeta(path=Path("a.md"))
        state.exclude_target("a.md", "file_exists")
        assert state.targets["a.md"].excluded
        assert state.targets["a.md"].excluded_by == "file_exists"

    def test_exclude_target_idempotent(self) -> None:
        """Second exclusion does not overwrite the first."""
        state = PipelineState()
        state.targets["a.md"] = TargetMeta(path=Path("a.md"))
        state.exclude_target("a.md", "file_exists")
        state.exclude_target("a.md", "directory_exists")
        assert state.targets["a.md"].excluded_by == "file_exists"

    def test_exclude_target_unknown_path_noop(self) -> None:
        state = PipelineState()
        state.exclude_target("nonexistent.md", "file_exists")  # no error

    def test_annotate_target(self) -> None:
        state = PipelineState()
        state.targets["a.md"] = TargetMeta(path=Path("a.md"))
        state.annotate_target("a.md", "imports", ["x", "y"])
        assert state.targets["a.md"].annotations["imports"] == ["x", "y"]

    def test_annotate_target_unknown_path_noop(self) -> None:
        state = PipelineState()
        state.annotate_target("nonexistent.md", "key", "val")  # no error

    def test_get_rule_sarif_found(self) -> None:
        state = PipelineState()
        state._sarif_by_rule = {"CORE:S:0001": [{"ruleId": "CORE.S.0001"}]}
        assert len(state.get_rule_sarif("CORE:S:0001")) == 1

    def test_get_rule_sarif_missing(self) -> None:
        state = PipelineState()
        assert state.get_rule_sarif("CORE:S:9999") == []


# ---------------------------------------------------------------------------
# build_initial_state
# ---------------------------------------------------------------------------


class TestBuildInitialState:
    def test_with_instruction_files(self, tmp_path: Path) -> None:
        root = tmp_path
        f1 = root / "CLAUDE.md"
        f2 = root / ".claude" / "rules" / "foo.md"
        f1.touch()
        f2.parent.mkdir(parents=True)
        f2.touch()

        state = build_initial_state([f1, f2], root)

        assert "CLAUDE.md" in state.targets
        assert str(Path(".claude/rules/foo.md")) in state.targets
        assert len(state.targets) == 2
        assert state.targets["CLAUDE.md"].path == f1

    def test_with_none(self) -> None:
        state = build_initial_state(None, Path("/tmp"))
        assert state.targets == {}

    def test_with_empty_list(self) -> None:
        state = build_initial_state([], Path("/tmp"))
        assert state.targets == {}

    def test_fallback_for_unrelated_path(self, tmp_path: Path) -> None:
        """Files outside scan_root use absolute string as key."""
        external = Path("/some/other/place.md")
        state = build_initial_state([external], tmp_path)
        assert str(external) in state.targets


# ---------------------------------------------------------------------------
# distribute_sarif_by_rule
# ---------------------------------------------------------------------------


def _make_rule(
    rule_id: str,
    rule_type: RuleType = RuleType.DETERMINISTIC,
    checks: list[Check] | None = None,
) -> Rule:
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=Category.STRUCTURE,
        type=rule_type,
        level="L2",
        checks=checks or [Check(id=f"{rule_id}:check:0001", severity=Severity.MEDIUM)],
    )


class TestDistributeSarifByRule:
    def test_empty_sarif(self) -> None:
        assert distribute_sarif_by_rule({}, {}) == {}
        assert distribute_sarif_by_rule({"runs": []}, {}) == {}

    def test_groups_by_rule_id(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {"ruleId": "CORE.S.0001.check.0001", "message": {"text": "v1"}},
                        {"ruleId": "CORE.C.0002.check.0001", "message": {"text": "v2"}},
                        {"ruleId": "CORE.S.0001.check.0002", "message": {"text": "v3"}},
                    ],
                }
            ]
        }
        rules = {
            "CORE:S:0001": _make_rule("CORE:S:0001"),
            "CORE:C:0002": _make_rule("CORE:C:0002"),
        }
        result = distribute_sarif_by_rule(sarif, rules)

        assert len(result["CORE:S:0001"]) == 2
        assert len(result["CORE:C:0002"]) == 1

    def test_skips_unknown_rules(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {"ruleId": "CORE.S.9999.check.0001", "message": {"text": "v1"}},
                    ],
                }
            ]
        }
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001")}
        result = distribute_sarif_by_rule(sarif, rules)
        assert result == {}

    def test_skips_info_level(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "CORE.S.0001.check.0001",
                                    "defaultConfiguration": {"level": "note"},
                                }
                            ]
                        }
                    },
                    "results": [
                        {"ruleId": "CORE.S.0001.check.0001", "message": {"text": "v1"}},
                    ],
                }
            ]
        }
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001")}
        result = distribute_sarif_by_rule(sarif, rules)
        assert result == {}

    def test_handles_temp_prefixed_rule_ids(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {"ruleId": "tmp.tmpXXX.CORE.C.0006.check.0001", "message": {"text": "v1"}},
                    ],
                }
            ]
        }
        rules = {"CORE:C:0006": _make_rule("CORE:C:0006")}
        result = distribute_sarif_by_rule(sarif, rules)
        assert len(result["CORE:C:0006"]) == 1

    def test_multiple_runs(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {"ruleId": "CORE.S.0001.check.0001", "message": {"text": "v1"}},
                    ],
                },
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {"ruleId": "CORE.S.0001.check.0002", "message": {"text": "v2"}},
                    ],
                },
            ]
        }
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001")}
        result = distribute_sarif_by_rule(sarif, rules)
        assert len(result["CORE:S:0001"]) == 2


# ---------------------------------------------------------------------------
# execute_rule_checks
# ---------------------------------------------------------------------------


class TestExecuteRuleChecks:
    def test_mechanical_only_rule(self, tmp_path: Path) -> None:
        """Mechanical-only rule dispatches checks and records violations."""
        (tmp_path / ".git").mkdir()
        rule = _make_rule(
            "CORE:S:0001",
            RuleType.MECHANICAL,
            checks=[
                Check(
                    id="CORE:S:0001:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="file_exists",
                    args={"path": "nonexistent.md"},
                )
            ],
        )
        state = PipelineState()
        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)
        assert jrs == []
        assert len(state.findings) == 1
        assert state.findings[0].rule_id == "CORE:S:0001"

    def test_deterministic_from_sarif(self, tmp_path: Path) -> None:
        """Deterministic rule reads from pre-distributed SARIF."""
        rule = _make_rule("CORE:C:0002", RuleType.DETERMINISTIC)
        state = PipelineState()
        state._sarif_by_rule = {
            "CORE:C:0002": [
                {
                    "ruleId": "CORE.C.0002.check.0001",
                    "message": {"text": "violation found"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "CLAUDE.md"}, "region": {"startLine": 5}}}
                    ],
                }
            ]
        }
        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)
        assert jrs == []
        assert len(state.findings) == 1
        assert state.findings[0].location == "CLAUDE.md:5"

    def test_deterministic_no_sarif_means_pass(self, tmp_path: Path) -> None:
        """Rule with no SARIF results produces no violations."""
        rule = _make_rule("CORE:C:0002", RuleType.DETERMINISTIC)
        state = PipelineState()
        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)
        assert jrs == []
        assert state.findings == []

    def test_ceiling_enforcement(self, tmp_path: Path) -> None:
        """Mechanical rule cannot have deterministic checks."""
        rule = _make_rule(
            "CORE:S:0001",
            RuleType.MECHANICAL,
            checks=[
                Check(id="CORE:S:0001:check:0001", severity=Severity.MEDIUM, type="mechanical", check="git_tracked"),
                Check(id="CORE:S:0001:check:0002", severity=Severity.MEDIUM, type="deterministic"),
            ],
        )
        (tmp_path / ".git").mkdir()
        state = PipelineState()
        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)
        assert jrs == []
        # Only the mechanical check ran (git_tracked passes), deterministic skipped
        assert state.findings == []

    def test_negation_no_finding_produces_violation(self, tmp_path: Path) -> None:
        """Negated check with no SARIF match produces violation."""
        rule = _make_rule(
            "CORE:C:0005",
            RuleType.DETERMINISTIC,
            checks=[
                Check(
                    id="CORE:C:0005:check:0001",
                    severity=Severity.HIGH,
                    type="deterministic",
                    negate=True,
                )
            ],
        )
        state = PipelineState()
        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)
        assert jrs == []
        assert len(state.findings) == 1
        assert state.findings[0].message == "Expected content not found"

    def test_negation_finding_means_pass(self, tmp_path: Path) -> None:
        """Negated check with SARIF match means pass (content present)."""
        rule = _make_rule(
            "CORE:C:0005",
            RuleType.DETERMINISTIC,
            checks=[
                Check(
                    id="CORE:C:0005:check:0001",
                    severity=Severity.HIGH,
                    type="deterministic",
                    negate=True,
                )
            ],
        )
        state = PipelineState()
        state._sarif_by_rule = {
            "CORE:C:0005": [
                {
                    "ruleId": "CORE.C.0005.check.0001",
                    "message": {"text": "found"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "f.md"}, "region": {"startLine": 1}}}
                    ],
                }
            ]
        }
        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)
        assert jrs == []
        assert state.findings == []

    def test_semantic_short_circuit(self, tmp_path: Path) -> None:
        """Semantic check with no deterministic candidates never fires."""
        rule = Rule(
            id="CORE:C:0010",
            title="Semantic rule",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            question="Is this good?",
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(id="CORE:C:0010:check:0001", severity=Severity.MEDIUM, type="deterministic"),
                Check(id="CORE:C:0010:check:0002", severity=Severity.MEDIUM, type="semantic"),
            ],
        )
        state = PipelineState()
        # No SARIF results -> short-circuit
        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)
        assert jrs == []

    def test_negated_deterministic_uses_effective_vars(self, tmp_path: Path) -> None:
        """Negated deterministic violation location resolves {{instruction_files}} via effective_vars."""
        (tmp_path / "CLAUDE.md").touch()
        rule = _make_rule(
            "CORE:C:0005",
            RuleType.DETERMINISTIC,
            checks=[
                Check(
                    id="CORE:C:0005:check:0001",
                    severity=Severity.HIGH,
                    type="deterministic",
                    negate=True,
                )
            ],
        )
        rule = Rule(
            id=rule.id,
            title=rule.title,
            category=rule.category,
            type=rule.type,
            level=rule.level,
            checks=rule.checks,
            targets="{{instruction_files}}",
        )
        state = PipelineState()
        # Pass instruction_files so effective_vars binds concrete paths
        jrs = execute_rule_checks(rule, state, tmp_path, {}, [tmp_path / "CLAUDE.md"])
        assert jrs == []
        assert len(state.findings) == 1
        # Location must resolve to actual file, NOT raw placeholder
        assert "{{" not in state.findings[0].location
        assert "CLAUDE.md" in state.findings[0].location

    def test_mechanical_negate_inverts_result(self, tmp_path: Path) -> None:
        """Mechanical check with negate=True inverts pass/fail logic."""
        (tmp_path / ".git").mkdir()
        rule = _make_rule(
            "CORE:S:0099",
            RuleType.MECHANICAL,
            checks=[
                Check(
                    id="CORE:S:0099:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="git_tracked",
                    negate=True,
                )
            ],
        )
        state = PipelineState()
        execute_rule_checks(rule, state, tmp_path, {}, None)
        # git_tracked normally passes (git exists) → negate inverts → violation
        assert len(state.findings) == 1

    def test_check_cache_populated(self, tmp_path: Path) -> None:
        """Pipeline state check_cache is populated after mechanical dispatch."""
        (tmp_path / ".git").mkdir()
        rule = _make_rule(
            "CORE:S:0001",
            RuleType.MECHANICAL,
            checks=[
                Check(
                    id="CORE:S:0001:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="git_tracked",
                )
            ],
        )
        state = PipelineState()
        execute_rule_checks(rule, state, tmp_path, {}, None)
        # check_cache is available on state (even though not used for dedup yet in single-rule case)
        assert state.check_cache is not None


# ---------------------------------------------------------------------------
# Blocking behavior — cross-rule target exclusion
# ---------------------------------------------------------------------------


class TestBlockingBehaviorAcrossRules:
    """Blocking check failure must exclude target for subsequent rules.

    When file_exists fails, the target is recorded as excluded in PipelineState.
    Subsequent rules executed against the same state see the exclusion.
    """

    @staticmethod
    def _blocking_rule(rule_id: str, check_name: str = "file_exists", args: dict | None = None) -> Rule:
        """Create a rule with a blocking check and proper targets."""
        return Rule(
            id=rule_id,
            title=f"Rule {rule_id}",
            category=Category.STRUCTURE,
            type=RuleType.MECHANICAL,
            level="L1",
            targets="{{instruction_files}}",
            checks=[
                Check(
                    id=f"{rule_id}:check:0001",
                    severity=Severity.CRITICAL,
                    type="mechanical",
                    check=check_name,
                    args=args,
                )
            ],
        )

    def test_file_exists_failure_excludes_target(self, tmp_path: Path) -> None:
        """file_exists failure marks the target as excluded in state."""
        rule = self._blocking_rule("CORE:S:0001")
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        vars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        assert len(state.findings) == 1
        assert state.targets["CLAUDE.md"].excluded
        assert state.targets["CLAUDE.md"].excluded_by == "file_exists"

    def test_excluded_target_not_in_active_targets(self, tmp_path: Path) -> None:
        """After blocking failure, active_targets() filters out the excluded target."""
        rule = self._blocking_rule("CORE:S:0001")
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state.targets["other.md"] = TargetMeta(path=tmp_path / "other.md")
        vars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        active = state.active_targets()
        active_paths = {t.path.name for t in active}
        assert "CLAUDE.md" not in active_paths
        assert "other.md" in active_paths

    def test_blocking_persists_across_two_rules(self, tmp_path: Path) -> None:
        """Exclusion from rule A is visible when processing rule B with same state."""
        rule_a = self._blocking_rule("CORE:S:0001")
        rule_b = Rule(
            id="CORE:S:0002",
            title="Rule CORE:S:0002",
            category=Category.STRUCTURE,
            type=RuleType.MECHANICAL,
            level="L1",
            targets="{{instruction_files}}",
            checks=[
                Check(
                    id="CORE:S:0002:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="git_tracked",
                )
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        vars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        # Rule A: file_exists fails → target excluded
        execute_rule_checks(rule_a, state, tmp_path, vars, None)
        assert state.targets["CLAUDE.md"].excluded

        # Rule B executes against same state — target still excluded
        execute_rule_checks(rule_b, state, tmp_path, vars, None)
        assert state.targets["CLAUDE.md"].excluded
        assert state.targets["CLAUDE.md"].excluded_by == "file_exists"

    def test_directory_exists_failure_excludes_target(self, tmp_path: Path) -> None:
        """directory_exists is also a blocking check and excludes targets."""
        rule = Rule(
            id="CORE:S:0003",
            title="Rule CORE:S:0003",
            category=Category.STRUCTURE,
            type=RuleType.MECHANICAL,
            level="L1",
            targets=".claude/rules",
            checks=[
                Check(
                    id="CORE:S:0003:check:0001",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="directory_exists",
                    args={"path": ".claude/rules"},
                )
            ],
        )
        state = PipelineState()
        # Target key matches the resolved location path
        state.targets[".claude/rules"] = TargetMeta(path=tmp_path / ".claude" / "rules")
        vars = {"instruction_files": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        assert len(state.findings) == 1
        assert state.targets[".claude/rules"].excluded
        assert state.targets[".claude/rules"].excluded_by == "directory_exists"


# ---------------------------------------------------------------------------
# Interleaved check types — M→D→S within a single rule
# ---------------------------------------------------------------------------


class TestInterleavedCheckTypes:
    """Rules with mixed check types must execute M→D→S in declaration order."""

    def test_semantic_rule_with_mds_sequence(self, tmp_path: Path) -> None:
        """Semantic rule with M+D+S checks: mechanical runs, deterministic reads SARIF, semantic fires."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# Project\n\nContent for semantic evaluation.\n")
        rule = Rule(
            id="CORE:C:0010",
            title="Comprehensive rule",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L2",
            question="Is this good?",
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(
                    id="CORE:C:0010:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="git_tracked",
                ),
                Check(
                    id="CORE:C:0010:check:0002",
                    severity=Severity.HIGH,
                    type="deterministic",
                ),
                Check(
                    id="CORE:C:0010:check:0003",
                    severity=Severity.MEDIUM,
                    type="semantic",
                ),
            ],
        )
        state = PipelineState()
        # Provide SARIF results for the deterministic check
        state._sarif_by_rule = {
            "CORE:C:0010": [
                {
                    "ruleId": "CORE.C.0010.check.0002",
                    "message": {"text": "section candidate"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "CLAUDE.md"},
                                "region": {"startLine": 10},
                            }
                        }
                    ],
                }
            ]
        }

        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)

        # Mechanical passed (git_tracked), no violation for it
        mechanical_violations = [f for f in state.findings if f.check_id == "CORE:C:0010:check:0001"]
        assert len(mechanical_violations) == 0

        # Deterministic produced a violation from SARIF
        det_violations = [f for f in state.findings if "check:0002" in f.check_id]
        assert len(det_violations) == 1

        # Semantic produced a JudgmentRequest (not a violation — needs human judgment)
        assert len(jrs) == 1

    def test_mechanical_failure_still_allows_deterministic(self, tmp_path: Path) -> None:
        """Failing mechanical check within a rule does not block subsequent deterministic checks."""
        rule = Rule(
            id="CORE:C:0020",
            title="Multi-gate rule",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            checks=[
                Check(
                    id="CORE:C:0020:check:0001",
                    severity=Severity.LOW,
                    type="mechanical",
                    check="git_tracked",
                ),
                Check(
                    id="CORE:C:0020:check:0002",
                    severity=Severity.HIGH,
                    type="deterministic",
                ),
            ],
        )
        state = PipelineState()
        state._sarif_by_rule = {
            "CORE:C:0020": [
                {
                    "ruleId": "CORE.C.0020.check.0002",
                    "message": {"text": "violation"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "CLAUDE.md"},
                                "region": {"startLine": 5},
                            }
                        }
                    ],
                }
            ]
        }

        execute_rule_checks(rule, state, tmp_path, {}, None)

        # Both checks produced violations (no .git → mechanical fails, SARIF hit → deterministic fails)
        assert len(state.findings) == 2
        check_ids = {f.check_id for f in state.findings}
        assert "CORE:C:0020:check:0001" in check_ids
        assert "check:0002" in {f.check_id for f in state.findings}

    def test_semantic_short_circuits_without_deterministic_candidates(self, tmp_path: Path) -> None:
        """Semantic check never fires when there are no deterministic candidates."""
        (tmp_path / ".git").mkdir()
        rule = Rule(
            id="CORE:C:0030",
            title="Semantic with no candidates",
            category=Category.CONTENT,
            type=RuleType.SEMANTIC,
            level="L3",
            question="Is this good?",
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(
                    id="CORE:C:0030:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="git_tracked",
                ),
                Check(
                    id="CORE:C:0030:check:0002",
                    severity=Severity.HIGH,
                    type="deterministic",
                ),
                Check(
                    id="CORE:C:0030:check:0003",
                    severity=Severity.MEDIUM,
                    type="semantic",
                ),
            ],
        )
        state = PipelineState()
        # No SARIF results — deterministic produces 0 candidates

        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)

        # Mechanical passed, deterministic had no results, semantic short-circuited
        assert state.findings == []
        assert jrs == []

    def test_ceiling_blocks_semantic_in_deterministic_rule(self, tmp_path: Path) -> None:
        """Deterministic rule cannot execute semantic checks — ceiling enforcement."""
        rule = Rule(
            id="CORE:C:0040",
            title="Det rule with semantic check",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            question="Is this good?",
            choices=[{"value": "pass"}, {"value": "fail"}],
            pass_value="pass",
            checks=[
                Check(
                    id="CORE:C:0040:check:0001",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                ),
                Check(
                    id="CORE:C:0040:check:0002",
                    severity=Severity.MEDIUM,
                    type="semantic",
                ),
            ],
        )
        state = PipelineState()

        jrs = execute_rule_checks(rule, state, tmp_path, {}, None)

        # Semantic check skipped due to ceiling — no judgment requests
        assert jrs == []


# ---------------------------------------------------------------------------
# Negate on blocking checks (file_exists, directory_exists)
# ---------------------------------------------------------------------------


class TestNegateBlockingChecks:
    """Negate=True on blocking checks inverts pass/fail at the pipeline level."""

    def test_negate_file_exists_present_means_violation(self, tmp_path: Path) -> None:
        """file_exists + negate=True: file present → violation (require file absent)."""
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        rule = _make_rule(
            "CORE:S:0098",
            RuleType.MECHANICAL,
            checks=[
                Check(
                    id="CORE:S:0098:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="file_exists",
                    negate=True,
                )
            ],
        )
        state = PipelineState()
        vars = {"instruction_files": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        # file_exists returns passed=True, negate inverts → violation
        assert len(state.findings) == 1

    def test_negate_file_exists_absent_means_pass(self, tmp_path: Path) -> None:
        """file_exists + negate=True: file absent → pass (desired state)."""
        rule = _make_rule(
            "CORE:S:0098",
            RuleType.MECHANICAL,
            checks=[
                Check(
                    id="CORE:S:0098:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="file_exists",
                    negate=True,
                )
            ],
        )
        state = PipelineState()
        vars = {"instruction_files": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        # file_exists returns passed=False, negate inverts → pass
        assert state.findings == []

    def test_negate_directory_exists_present_means_violation(self, tmp_path: Path) -> None:
        """directory_exists + negate=True: dir present → violation."""
        (tmp_path / ".claude" / "rules").mkdir(parents=True)
        rule = _make_rule(
            "CORE:S:0097",
            RuleType.MECHANICAL,
            checks=[
                Check(
                    id="CORE:S:0097:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="directory_exists",
                    args={"path": ".claude/rules"},
                    negate=True,
                )
            ],
        )
        state = PipelineState()

        execute_rule_checks(rule, state, tmp_path, {}, None)

        assert len(state.findings) == 1

    def test_negate_directory_exists_absent_means_pass(self, tmp_path: Path) -> None:
        """directory_exists + negate=True: dir absent → pass."""
        rule = _make_rule(
            "CORE:S:0097",
            RuleType.MECHANICAL,
            checks=[
                Check(
                    id="CORE:S:0097:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="directory_exists",
                    args={"path": ".claude/rules"},
                    negate=True,
                )
            ],
        )
        state = PipelineState()

        execute_rule_checks(rule, state, tmp_path, {}, None)

        assert state.findings == []


# ---------------------------------------------------------------------------
# D→M metadata propagation via metadata_keys
# ---------------------------------------------------------------------------


class TestMetadataKeysPropagation:
    """D checks with metadata_keys write to annotations; M checks read them."""

    def test_deterministic_writes_annotations(self, tmp_path: Path) -> None:
        """D check with metadata_keys stores match texts in state annotations."""
        rule = Rule(
            id="CORE:C:0050",
            title="D→annotations test",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            checks=[
                Check(
                    id="CORE:C:0050:check:0001",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["found_items"],
                )
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = {
            "CORE:C:0050": [
                {
                    "ruleId": "CORE.C.0050.check.0001",
                    "message": {"text": "match alpha"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "CLAUDE.md"}, "region": {"startLine": 1}}}
                    ],
                },
                {
                    "ruleId": "CORE.C.0050.check.0001",
                    "message": {"text": "match beta"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "CLAUDE.md"}, "region": {"startLine": 5}}}
                    ],
                },
            ]
        }

        execute_rule_checks(rule, state, tmp_path, {}, None)

        # Violations created as normal
        assert len(state.findings) == 2
        # Annotations written to target
        assert "found_items" in state.targets["CLAUDE.md"].annotations
        assert state.targets["CLAUDE.md"].annotations["found_items"] == ["match alpha", "match beta"]

    def test_deterministic_no_results_no_annotations(self, tmp_path: Path) -> None:
        """D check with metadata_keys but no SARIF matches writes nothing."""
        rule = Rule(
            id="CORE:C:0051",
            title="D→annotations empty test",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            checks=[
                Check(
                    id="CORE:C:0051:check:0001",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["items"],
                )
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")

        execute_rule_checks(rule, state, tmp_path, {}, None)

        assert state.findings == []
        assert state.targets["CLAUDE.md"].annotations == {}

    def test_mechanical_reads_annotations(self, tmp_path: Path) -> None:
        """M check with metadata_keys gets annotations injected into args."""
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        rule = Rule(
            id="CORE:C:0052",
            title="D→M metadata test",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            targets="{{instruction_files}}",
            checks=[
                Check(
                    id="CORE:C:0052:check:0001",
                    severity=Severity.MEDIUM,
                    type="deterministic",
                    metadata_keys=["style_rules"],
                ),
                Check(
                    id="CORE:C:0052:check:0002",
                    severity=Severity.HIGH,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 0},
                    metadata_keys=["style_rules"],
                ),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = {
            "CORE:C:0052": [
                {
                    "ruleId": "CORE.C.0052.check.0001",
                    "message": {"text": "indent with 4 spaces"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "CLAUDE.md"}, "region": {"startLine": 3}}}
                    ],
                },
                {
                    "ruleId": "CORE.C.0052.check.0001",
                    "message": {"text": "use tabs for indent"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "CLAUDE.md"}, "region": {"startLine": 7}}}
                    ],
                },
            ]
        }
        vars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        # D check produced 2 violations + annotations
        det_findings = [f for f in state.findings if "check:0001" in (f.check_id or "")]
        assert len(det_findings) == 2

        # M check (count_at_most threshold=0) consumed the 2-item list → violation
        mech_findings = [f for f in state.findings if f.check_id == "CORE:C:0052:check:0002"]
        assert len(mech_findings) == 1
        assert "exceeds" in mech_findings[0].message

    def test_d_to_m_pass_when_within_threshold(self, tmp_path: Path) -> None:
        """D→M chain: count_at_most passes when items within threshold."""
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        rule = Rule(
            id="CORE:C:0053",
            title="D→M pass test",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            targets="{{instruction_files}}",
            checks=[
                Check(
                    id="CORE:C:0053:check:0001",
                    severity=Severity.LOW,
                    type="deterministic",
                    metadata_keys=["items"],
                ),
                Check(
                    id="CORE:C:0053:check:0002",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 5},
                    metadata_keys=["items"],
                ),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        state._sarif_by_rule = {
            "CORE:C:0053": [
                {
                    "ruleId": "CORE.C.0053.check.0001",
                    "message": {"text": "item 1"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "CLAUDE.md"}, "region": {"startLine": 1}}}
                    ],
                },
            ]
        }
        vars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        # D violation exists, but M check passes (1 item <= 5 threshold)
        mech_findings = [f for f in state.findings if f.check_id == "CORE:C:0053:check:0002"]
        assert len(mech_findings) == 0

    def test_metadata_keys_without_annotations_m_sees_empty(self, tmp_path: Path) -> None:
        """M check with metadata_keys but no prior D annotations gets empty args — no crash."""
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        rule = Rule(
            id="CORE:C:0054",
            title="M without prior D test",
            category=Category.CONTENT,
            type=RuleType.DETERMINISTIC,
            level="L2",
            targets="{{instruction_files}}",
            checks=[
                Check(
                    id="CORE:C:0054:check:0001",
                    severity=Severity.MEDIUM,
                    type="mechanical",
                    check="count_at_most",
                    args={"threshold": 0},
                    metadata_keys=["nonexistent_key"],
                ),
            ],
        )
        state = PipelineState()
        state.targets["CLAUDE.md"] = TargetMeta(path=tmp_path / "CLAUDE.md")
        vars = {"instruction_files": ["CLAUDE.md"], "main_instruction_file": ["CLAUDE.md"]}

        execute_rule_checks(rule, state, tmp_path, vars, None)

        # count_at_most with no metadata → empty list → passes (0 <= 0)
        assert not any(f.check_id == "CORE:C:0054:check:0001" for f in state.findings)
