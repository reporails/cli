"""Mutation-killing tests for core.lint.rule_runner.

Covers the pure decision helpers (severity normalizer, deterministic-check
predicate, generic-file extender) plus the collect/dispatch seams: which rules get
their mechanical checks run, the check_id fallback, the deterministic-eligibility
guard, the yml_path guard, the scoped default, and the config-error fallbacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.lint.regex.compiler import display_severity
from reporails_cli.core.lint.rule_runner import (
    _collect_deterministic_findings,
    _collect_mechanical_findings,
    _extend_with_generic,
    _has_deterministic_checks,
    run_content_quality_checks,
    run_m_probes,
)
from reporails_cli.core.platform.dto.models import (
    Category,
    Check,
    Execution,
    FileMatch,
    Rule,
    RuleType,
    Severity,
)

_CLASSIFY = "reporails_cli.core.classify"
_REGISTRY = "reporails_cli.core.platform.adapters.registry"
_CONFIG = "reporails_cli.core.platform.config.config"
_MECH_RUNNER = "reporails_cli.core.lint.mechanical.runner"
_REGEX = "reporails_cli.core.lint.regex"
_CONTENT = "reporails_cli.core.lint.content_checker"
_RR = "reporails_cli.core.lint.rule_runner"


def _rule(**kw: object) -> Rule:
    base: dict[str, object] = {
        "id": "CORE:X:0001",
        "title": "t",
        "category": Category.EFFICIENCY,
        "type": RuleType.MECHANICAL,
        "severity": Severity.HIGH,
        "match": FileMatch(format="freeform"),
        "checks": [Check(id="c", type="mechanical", check="regex_present", args={})],
    }
    base.update(kw)
    return Rule(**base)  # type: ignore[arg-type]


# --- display_severity (L34, L36) ----------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("error", "error"),
        ("critical", "error"),
        ("high", "error"),
        ("low", "info"),
        ("info", "info"),
        ("medium", "warning"),
        ("unknown", "warning"),
    ],
)
def test_display_severity(raw: str, expected: str) -> None:
    """Each SARIF-adjacent severity maps to the display vocabulary.

    Kills: L34 `raw in ("error","critical","high") -> not in`; L36
    `raw in ("low","info") -> not in`.
    """
    assert display_severity(raw) == expected


# --- _has_deterministic_checks (L78) ----------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_deterministic_true() -> None:
    """A rule carrying a deterministic check is detected.

    Kills: L78 `c.type == "deterministic" -> !=`.
    """
    assert _has_deterministic_checks(_rule(checks=[Check(id="c", type="deterministic", check="x", args={})])) is True


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_deterministic_false() -> None:
    """A rule with only a mechanical check has no deterministic check.

    Kills: L78 `== -> !=`.
    """
    assert _has_deterministic_checks(_rule(checks=[Check(id="c", type="mechanical", check="x", args={})])) is False


# --- _extend_with_generic (L144-151) ----------------------------------------


@dataclass
class _CF:
    path: Path
    file_type: str


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_extend_appends_generic_when_scanning() -> None:
    """A link-walked generic file not already present is appended.

    Kills: `cf.path not in known -> in known`.
    """
    instr = [Path("a.md")]
    classified = [_CF(Path("a.md"), "main"), _CF(Path("g.md"), "generic")]
    assert _extend_with_generic(instr, classified, generic_scanning=True) == [Path("a.md"), Path("g.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_extend_noop_when_scanning_off() -> None:
    """With generic scanning off, nothing is appended.

    Kills: `if not generic_scanning: return`.
    """
    instr = [Path("a.md")]
    classified = [_CF(Path("g.md"), "generic")]
    assert _extend_with_generic(instr, classified, generic_scanning=False) == [Path("a.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_extend_does_not_duplicate_known_generic() -> None:
    """A generic file already in the instruction set is not re-added.

    Kills: `not in known and file_type == "generic"` with `and -> or`.
    """
    instr = [Path("a.md")]
    classified = [_CF(Path("a.md"), "generic")]
    assert _extend_with_generic(instr, classified, generic_scanning=True) == [Path("a.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_extend_skips_non_generic() -> None:
    """A non-generic link-walked file is not appended.

    Kills: `cf.file_type == "generic" -> !=`.
    """
    instr = [Path("a.md")]
    classified = [_CF(Path("b.md"), "main")]
    assert _extend_with_generic(instr, classified, generic_scanning=True) == [Path("a.md")]


# --- _collect_mechanical_findings (L52, L70) --------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mechanical_check_runs_in_a_local_rule_of_any_type(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A mechanical check is run whether its rule is deterministic or mechanical, unless the rule runs on the server.

    A three-line main file is checked by three rules that each hold the same
    one-line limit: the two locally-run rules report it, the server-run rule does not.
    """
    main = tmp_path / "CLAUDE.md"
    main.write_text("one\ntwo\nthree\n", encoding="utf-8")
    one_line = Check(id="c", type="mechanical", check="line_count", args={"max": 1})
    rules = {
        rule_id: _rule(id=rule_id, type=rule_type, execution=execution, match=FileMatch(type="main"), checks=[one_line])
        for rule_id, rule_type, execution in (
            ("CORE:X:0001", RuleType.DETERMINISTIC, Execution.LOCAL),
            ("CORE:X:0002", RuleType.MECHANICAL, Execution.LOCAL),
            ("CORE:X:0003", RuleType.MECHANICAL, Execution.SERVER),
        )
    }
    monkeypatch.setattr(f"{_REGISTRY}.load_rules", lambda **k: rules)

    findings = run_m_probes(tmp_path, [main], agent="claude")

    assert sorted((f.rule, f.file) for f in findings) == [("CORE:X:0001", "CLAUDE.md"), ("CORE:X:0002", "CLAUDE.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_collect_mechanical_preserves_check_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A violation's check_id is carried onto the LocalFinding.

    Kills: L70 `check_id=v.check_id or "" -> and` (which would blank a real id).
    """
    viol = SimpleNamespace(
        location="a.md:5",
        severity=SimpleNamespace(value="high"),
        rule_id="R",
        message="m",
        fix=None,
        check_id="CHK1",
    )
    monkeypatch.setattr(f"{_MECH_RUNNER}.run_mechanical_checks", lambda *a, **k: [viol])

    findings = _collect_mechanical_findings({}, tmp_path, [])
    assert len(findings) == 1
    assert findings[0].check_id == "CHK1"
    assert findings[0].file == "a.md"
    assert findings[0].line == 5


# --- _collect_deterministic_findings (L110, L112) ---------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_deterministic_type_rule_with_mechanical_checks_still_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DETERMINISTIC-typed rule runs even when its checks are not deterministic.

    Kills: L110 `type != DETERMINISTIC and not _has_deterministic_checks` with
    `!= -> ==` and with `and -> or` (either would wrongly skip the rule).
    """
    sentinel = object()
    monkeypatch.setattr(f"{_REGEX}.run_checks", lambda *a, **k: [sentinel])

    yml = tmp_path / "r.yml"
    yml.write_text("x")
    rule = _rule(id="R", type=RuleType.DETERMINISTIC, match=None, yml_path=yml)

    out = _collect_deterministic_findings({"R": rule}, tmp_path, [tmp_path / "a.md"], [])
    assert sentinel in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_deterministic_rule_without_yml_path_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A rule whose yml_path is None is skipped gracefully.

    Kills: L112 `not yml_path or not yml_path.exists()` with `or -> and`
    (`and` dereferences `.exists()` on None -> AttributeError).
    """
    monkeypatch.setattr(f"{_REGEX}.run_checks", lambda *a, **k: [object()])
    rule = _rule(
        id="R",
        type=RuleType.DETERMINISTIC,
        match=None,
        yml_path=None,
        checks=[Check(id="c", type="deterministic", check="x", args={})],
    )
    assert _collect_deterministic_findings({"R": rule}, tmp_path, [tmp_path / "a.md"], []) == []


# --- run_m_probes (L181 scoped default, L201 config-error fallback) ---------


class TestRunMProbesScopedDefault:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_default_scoped_false_fires_project_shape_rule(self, dev_rules_dir: Path, level1_project: Path) -> None:
        """Called without `scoped`, the whole-project rule CORE:S:0010 still fires.

        Kills: L181 `scoped: bool = False -> True` (a True default would narrow
        every unscoped call and drop the project-aggregate rule).
        """
        from reporails_cli.core.discovery.agents import get_all_instruction_files

        files = get_all_instruction_files(level1_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        rules_hit = {f.rule for f in run_m_probes(level1_project, files)}
        assert "CORE:S:0010" in rules_hit


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_run_m_probes_config_error_defaults_generic_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When project-config load fails, generic scanning defaults OFF.

    Kills: L201 `generic_scanning = False -> True` in the except branch.
    """
    captured: dict[str, object] = {}

    def raise_cfg(_pd: Path) -> object:
        raise ValueError("boom")

    def fake_classify(pd: Path, files: list, ft: object, generic_scanning: bool) -> list:
        captured["gs"] = generic_scanning
        return []

    monkeypatch.setattr(f"{_REGISTRY}.load_rules", lambda **k: {})
    monkeypatch.setattr(f"{_CLASSIFY}.load_file_types", lambda _a, **_kw: {})
    monkeypatch.setattr(f"{_CONFIG}.get_project_config", raise_cfg)
    monkeypatch.setattr(f"{_CLASSIFY}.classify_files", fake_classify)
    monkeypatch.setattr(f"{_RR}._collect_mechanical_findings", lambda *a, **k: [])
    monkeypatch.setattr(f"{_RR}._collect_deterministic_findings", lambda *a, **k: [])

    assert run_m_probes(tmp_path, []) == []
    assert captured["gs"] is False


# --- run_content_quality_checks (L241 agent default, L247 config fallback) --


def _ruleset_map():
    from reporails_cli.core.platform.dto.ruleset import RulesetMap

    return RulesetMap(schema_version="1", embedding_model="none", generated_at="t", files=[], atoms=[])


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_content_quality_agent_defaults_to_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty agent id resolves to the `generic` file-type set.

    Kills: L241 `load_file_types(agent or "generic") -> and` (which would pass
    the empty string through instead of the generic default).
    """
    captured: dict[str, object] = {}
    monkeypatch.setattr(f"{_REGISTRY}.load_rules", lambda **k: {})
    monkeypatch.setattr(f"{_CONTENT}.run_content_checks", lambda *a, **k: [])
    monkeypatch.setattr(f"{_CLASSIFY}.load_file_types", lambda a, **_kw: captured.__setitem__("agent", a) or {})
    monkeypatch.setattr(f"{_CLASSIFY}.classify_files", lambda *a, **k: [])
    monkeypatch.setattr(
        f"{_CONFIG}.get_project_config",
        lambda _pd: SimpleNamespace(generic_scanning=False, exclude_files=None),
    )

    run_content_quality_checks(_ruleset_map(), tmp_path, instruction_files=[tmp_path / "a.md"], agent="")
    assert captured["agent"] == "generic"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_content_quality_config_error_defaults_generic_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When project-config load fails, content-quality generic scanning is OFF.

    Kills: L247 `generic_scanning = False -> True` in the except branch.
    """
    captured: dict[str, object] = {}

    def raise_cfg(_pd: Path) -> object:
        raise ValueError("boom")

    def fake_classify(pd: Path, files: list, ft: object, generic_scanning: bool) -> list:
        captured["gs"] = generic_scanning
        return []

    monkeypatch.setattr(f"{_REGISTRY}.load_rules", lambda **k: {})
    monkeypatch.setattr(f"{_CONTENT}.run_content_checks", lambda *a, **k: [])
    monkeypatch.setattr(f"{_CLASSIFY}.load_file_types", lambda _a, **_kw: {})
    monkeypatch.setattr(f"{_CONFIG}.get_project_config", raise_cfg)
    monkeypatch.setattr(f"{_CLASSIFY}.classify_files", fake_classify)

    run_content_quality_checks(_ruleset_map(), tmp_path, instruction_files=[tmp_path / "a.md"], agent="claude")
    assert captured["gs"] is False
