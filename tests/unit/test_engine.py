"""Unit tests for engine module."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.engine import _compute_category_summary, _find_project_root
from reporails_cli.core.models import Category, Rule, RuleType, Severity, Violation


def _rule(rule_id: str, category: Category) -> Rule:
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=category,
        type=RuleType.DETERMINISTIC,
        level="L2",
    )


def _violation(rule_id: str, severity: Severity = Severity.MEDIUM) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title="Test",
        location="test.md:1",
        message="msg",
        severity=severity,
    )


class TestComputeCategorySummary:
    def test_all_passing(self) -> None:
        rules = {
            "S1": _rule("S1", Category.STRUCTURE),
            "C1": _rule("C1", Category.CONTENT),
        }
        stats = _compute_category_summary(rules, [])

        s_stat = next(s for s in stats if s.code == "S")
        c_stat = next(s for s in stats if s.code == "C")
        assert s_stat.total == 1 and s_stat.failed == 0 and s_stat.passed == 1
        assert c_stat.total == 1 and c_stat.failed == 0 and c_stat.passed == 1

    def test_mixed_violations(self) -> None:
        rules = {
            "S1": _rule("S1", Category.STRUCTURE),
            "S2": _rule("S2", Category.STRUCTURE),
            "C1": _rule("C1", Category.CONTENT),
            "E1": _rule("E1", Category.EFFICIENCY),
        }
        violations = [
            _violation("S1", Severity.HIGH),
            _violation("C1", Severity.LOW),
        ]
        stats = _compute_category_summary(rules, violations)

        s_stat = next(s for s in stats if s.code == "S")
        c_stat = next(s for s in stats if s.code == "C")
        e_stat = next(s for s in stats if s.code == "E")
        assert s_stat.failed == 1 and s_stat.passed == 1 and s_stat.worst_severity == "high"
        assert c_stat.failed == 1 and c_stat.passed == 0 and c_stat.worst_severity == "low"
        assert e_stat.failed == 0 and e_stat.passed == 1 and e_stat.worst_severity is None

    def test_empty_rules(self) -> None:
        stats = _compute_category_summary({}, [])
        for s in stats:
            assert s.total == 0 and s.failed == 0 and s.passed == 0

    def test_worst_severity_across_violations(self) -> None:
        rules = {"S1": _rule("S1", Category.STRUCTURE), "S2": _rule("S2", Category.STRUCTURE)}
        violations = [
            _violation("S1", Severity.LOW),
            _violation("S2", Severity.CRITICAL),
        ]
        stats = _compute_category_summary(rules, violations)
        s_stat = next(s for s in stats if s.code == "S")
        assert s_stat.worst_severity == "critical"


class TestFindProjectRoot:
    """Tests for _find_project_root() project root detection."""

    def test_finds_git_root(self, tmp_path: Path) -> None:
        """Direct directory with .git/ returns itself."""
        (tmp_path / ".git").mkdir()
        assert _find_project_root(tmp_path) == tmp_path

    def test_walks_up_to_git_root(self, tmp_path: Path) -> None:
        """Subdirectory walks up to find .git/ in parent."""
        (tmp_path / ".git").mkdir()
        subdir = tmp_path / "packages" / "child"
        subdir.mkdir(parents=True)
        assert _find_project_root(subdir) == tmp_path

    def test_no_git_falls_back_to_target(self, tmp_path: Path) -> None:
        """No .git/ anywhere falls back to original target."""
        subdir = tmp_path / "some" / "deep" / "path"
        subdir.mkdir(parents=True)
        assert _find_project_root(subdir) == subdir

    def test_git_file_for_submodule(self, tmp_path: Path) -> None:
        """.git as a file (submodule) is detected."""
        (tmp_path / ".git").write_text("gitdir: ../.git/modules/sub")
        subdir = tmp_path / "src"
        subdir.mkdir()
        assert _find_project_root(subdir) == tmp_path

    def test_file_target_uses_parent(self, tmp_path: Path) -> None:
        """When target is a file, walks from its parent directory."""
        (tmp_path / ".git").mkdir()
        target_file = tmp_path / "src" / "main.py"
        target_file.parent.mkdir()
        target_file.touch()
        assert _find_project_root(target_file) == tmp_path

    def test_coordination_backbone_preferred_over_child_git(self, tmp_path: Path) -> None:
        """Monorepo: coordination backbone with children takes priority over child .git."""
        # Parent coordination root
        (tmp_path / ".git").mkdir()
        backbone_dir = tmp_path / ".reporails"
        backbone_dir.mkdir()
        (backbone_dir / "backbone.yml").write_text(
            "version: 2\nchildren:\n  child:\n    backbone: child/.reporails/backbone.yml\n"
        )
        # Child with its own .git
        child = tmp_path / "child"
        child.mkdir()
        (child / ".git").mkdir()
        child_backbone = child / ".reporails"
        child_backbone.mkdir()
        (child_backbone / "backbone.yml").write_text("version: 3\ndepends_on:\n  rules: {}\n")
        assert _find_project_root(child) == tmp_path

    def test_backbone_with_repos_preferred(self, tmp_path: Path) -> None:
        """Backbone with repos key is recognized as coordination root."""
        (tmp_path / ".git").mkdir()
        backbone_dir = tmp_path / ".reporails"
        backbone_dir.mkdir()
        (backbone_dir / "backbone.yml").write_text("version: 2\nrepos:\n  rules:\n    path: rules\n")
        subdir = tmp_path / "rules"
        subdir.mkdir()
        (subdir / ".git").mkdir()
        assert _find_project_root(subdir) == tmp_path

    def test_child_git_used_when_no_coordination_backbone(self, tmp_path: Path) -> None:
        """Without coordination backbone, falls back to nearest .git."""
        child = tmp_path / "child"
        child.mkdir()
        (child / ".git").mkdir()
        subdir = child / "src"
        subdir.mkdir()
        assert _find_project_root(subdir) == child
