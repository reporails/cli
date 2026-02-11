"""Unit tests for pipeline state engine."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.models import Category, Check, Rule, RuleType, Severity
from reporails_cli.core.pipeline import CEILING, PipelineState, TargetMeta, build_initial_state
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

    def test_ceiling_constant(self) -> None:
        """Verify CEILING mapping is correct."""
        assert CEILING[RuleType.MECHANICAL] == frozenset({"mechanical"})
        assert CEILING[RuleType.DETERMINISTIC] == frozenset({"mechanical", "deterministic"})
        assert CEILING[RuleType.SEMANTIC] == frozenset({"mechanical", "deterministic", "semantic"})

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
