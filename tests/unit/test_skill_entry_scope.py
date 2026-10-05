"""Entry-scoped skill checks judge a skill's entry file only."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from reporails_cli.core.lint.rule_runner import run_m_probes
from reporails_cli.core.mapper.skills import skill_entry_paths

RULES = Path(__file__).resolve().parents[2] / "framework" / "rules" / "core"
GOOD = "---\nname: wrong\ndescription: does a thing\n---\nbody\n"
GATES = "---\nname: foo\ndescription: d\ndisable-model-invocation: true\nuser-invocable: false\n---\nbody\n"


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _ids(findings: list, rel: str) -> set[str]:
    return {f.rule for f in findings if f.file.replace("\\", "/").endswith(rel)}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_nested_skill_md_alone_has_no_missing_description(tmp_path: Path) -> None:
    entry = _write(tmp_path, ".claude/skills/foo/SKILL.md", GOOD.replace("wrong", "foo"))
    inner = _write(tmp_path, ".claude/skills/foo/sub/SKILL.md", GOOD)
    skills = {str(entry): str(entry.parent), str(inner): str(entry.parent)}
    ids = _ids(run_m_probes(tmp_path, [inner], agent="claude", skills=skills), "sub/SKILL.md")
    assert "CORE:S:0040" not in ids


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_nested_skill_md_is_not_judged_by_entry_rules(tmp_path: Path) -> None:
    entry = _write(tmp_path, ".claude/skills/foo/SKILL.md", GATES.replace("disable-model-invocation: true\n", ""))
    inner = _write(tmp_path, ".claude/skills/foo/sub/SKILL.md", GATES.replace("foo", "other"))
    skills = {str(entry): str(entry.parent), str(inner): str(entry.parent)}
    findings = run_m_probes(tmp_path, [entry, inner], agent="claude", skills=skills)
    ids = _ids(findings, "sub/SKILL.md")
    assert "CORE:S:0036" not in ids
    assert "CORE:C:0057" not in ids


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_bad_entry_still_judged(tmp_path: Path) -> None:
    entry = _write(tmp_path, ".claude/skills/foo/SKILL.md", GOOD)
    skills = {str(entry): str(entry.parent)}
    ids = _ids(run_m_probes(tmp_path, [entry], agent="claude", skills=skills), "foo/SKILL.md")
    assert "CORE:S:0036" in ids


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_reference_file_is_not_an_entry() -> None:
    class CF:
        def __init__(self, path: str) -> None:
            self.path = Path(path)
            self.properties = {"skill": "/nowhere/skills/foo"}

    entries = skill_entry_paths([CF("/nowhere/skills/foo/SKILL.md"), CF("/nowhere/skills/foo/reference.md")])
    assert entries is not None
    assert {p.name for p in entries} == {"SKILL.md"}


def _skill_md_checks() -> list[tuple[str, dict]]:
    out = []
    for yml in sorted(RULES.glob("*/checks.yml")):
        for chk in (yaml.safe_load(yml.read_text(encoding="utf-8")) or {}).get("checks", []):
            args = chk.get("args") or {}
            text = " ".join([str(args.get("path", "")), *map(str, (chk.get("paths") or {}).get("include", []))])
            if (
                "SKILL.md" in text
                or chk.get("check") == "frontmatter_matches_dirname"
                or (chk["id"].startswith("CORE.C.0057.") and chk.get("type") == "deterministic")
            ):
                out.append((chk["id"], chk))
    return out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_every_skill_md_check_is_entry_scoped() -> None:
    found = _skill_md_checks()
    assert found
    unscoped = [
        i for i, c in found if not (c.get("entry_only") is True or (c.get("args") or {}).get("entry_only") is True)
    ]
    assert unscoped == []


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("expect", ["present", "absent"])
def test_entry_only_check_with_no_entry_in_scope_yields_no_violation(tmp_path: Path, expect: str) -> None:
    from reporails_cli.core.lint.mechanical.runner import dispatch_single_check
    from reporails_cli.core.platform.dto.models import Category, Check, ClassifiedFile, Rule, RuleType

    entry = _write(tmp_path, ".claude/skills/foo/SKILL.md", GOOD.replace("wrong", "foo"))
    inner = _write(tmp_path, ".claude/skills/foo/sub/SKILL.md", GOOD)
    cf = ClassifiedFile(path=inner, file_type="skill", properties={"skill": str(entry.parent)})
    check = Check(
        id="T.entry",
        type="mechanical",
        check="frontmatter_matches_dirname",
        args={"entry_only": True, "path": "**/SKILL.md"},
        expect=expect,
    )
    rule = Rule(id="T:1", title="t", category=Category.STRUCTURE, type=RuleType.MECHANICAL, checks=[check])
    violation, result = dispatch_single_check(check, rule, tmp_path, [cf], "loc")
    assert violation is None
    assert result is None


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_keyerror_inside_a_check_is_logged_as_a_crash_not_as_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import patch

    from reporails_cli.core.lint.mechanical import runner
    from reporails_cli.core.platform.dto.models import Category, Check, Rule, RuleType

    def boom(root: Path, args: dict, classified: list) -> None:
        raise KeyError("inside")

    monkeypatch.setitem(runner.MECHANICAL_CHECKS, "boom_check", boom)
    check = Check(id="CORE:X:0001:boom", type="mechanical", check="boom_check", expect="present")
    rule = Rule(id="CORE:X:0001", title="t", category=Category.STRUCTURE, type=RuleType.MECHANICAL, checks=[check])
    with patch.object(runner.logger, "exception") as crashed, patch.object(runner.logger, "warning") as unknown:
        assert runner.dispatch_single_check(check, rule, tmp_path, [], "loc") == (None, None)
    crashed.assert_called_once()
    unknown.assert_not_called()
