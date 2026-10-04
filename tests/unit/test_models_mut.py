"""Mutation-killing behavioral tests for core/platform/dto/models.py.

Most operators in this DTO module are equivalent mutants and are documented
below rather than decorated:

  - `model_config = ConfigDict(frozen=True)` on FileTypeDeclaration,
    ClassifiedFile, FileMatch, Check, Rule and `@dataclass(frozen=True)` on
    LocalFinding, Violation, JudgmentRequest, JudgmentResponse: none of these
    models is ever hashed as a whole object or used as a set member / dict key
    (dedup throughout the codebase keys on strings and tuples), and no code path
    relies on assignment raising. Flipping `frozen` to False changes no
    observable behavior — equivalent.
  - `FileTypeDeclaration.required: bool = False`: `.required` is only ever
    copied (classify/__init__.py propagates `required=decl.required`); it is
    never read to drive a decision anywhere in src, so the default value is not
    behaviorally exercised — equivalent.

The one real contract is `Check.project_scope` (default `""`), which the
mechanical runner consumes to skip project-aggregate checks under a scoped run
(`if scoped and check.project_scope == "aggregate"`). That default is exercised below.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.runner import run_mechanical_checks
from reporails_cli.core.platform.dto.models import (
    Category,
    Check,
    ClassifiedFile,
    FileMatch,
    Rule,
    RuleType,
    Severity,
)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_check_default_project_scope_runs_under_scoped_run(tmp_path: Path) -> None:
    """A Check built without project_scope must NOT be skipped when scoped=True.

    The default is empty; making it `"aggregate"` would make every default check a
    project-aggregate check and silently skip it under a scoped run, so the
    failing file_exists check would produce no violation.
    """
    rule = Rule(
        id="CORE:S:0001",
        title="Rule CORE:S:0001",
        category=Category.STRUCTURE,
        type=RuleType.MECHANICAL,
        severity=Severity.CRITICAL,
        match=FileMatch(),
        checks=[Check(id="CORE:S:0001:check:0001", type="mechanical", check="file_exists")],
    )
    # Missing CLAUDE.md -> file_exists fails -> one violation, but only if the
    # check is not skipped as project-scoped under the scoped run.
    classified = [ClassifiedFile(path=tmp_path / "CLAUDE.md", file_type="main")]
    violations = run_mechanical_checks({"CORE:S:0001": rule}, tmp_path, classified, scoped=True)
    assert len(violations) == 1
    assert violations[0].rule_id == "CORE:S:0001"
