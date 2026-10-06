"""Tests for core/client_checks.py — D-level checks."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.mechanical_fixers import fix_unformatted_code
from reporails_cli.core.lint.client_checks import _check_unformatted_code, run_client_checks
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary


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


def _atom(line: int, charge_value: int, position_index: int = 0, **kwargs: object) -> Atom:
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
        file_path="test.md",
        **{k: v for k, v in kwargs.items() if k != "text"},  # type: ignore[arg-type]
    )


class TestUnformattedCode:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unformatted_tokens_detected(self) -> None:
        atoms = [_atom(10, +1, unformatted_code=["build.sh"])]
        findings = run_client_checks(_make_map(atoms))
        fmt = [f for f in findings if f.rule == "format"]
        assert len(fmt) == 1
        assert "build.sh" in fmt[0].message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_unformatted_no_finding(self) -> None:
        atoms = [_atom(10, +1, unformatted_code=[])]
        findings = run_client_checks(_make_map(atoms))
        fmt = [f for f in findings if f.rule == "format"]
        assert len(fmt) == 0

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_same_token_by_case_reported_once(self) -> None:
        """Regression: the same word reached `unformatted_code` twice under
        different casing (a known code word matched case-insensitively, the same
        text also matched by its mixed-case shape) — reported once, not twice."""
        atoms = [_atom(10, +1, unformatted_code=["fastapi", "FastAPI"]), _atom(11, +1, named_tokens=["FastAPI"])]
        findings = run_client_checks(_make_map(atoms))
        fmt = [f for f in findings if f.rule == "format"]
        assert len(fmt) == 1, [f.message for f in fmt]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_finding_quotes_the_name_as_written(self) -> None:
        """The mapper lower-cases a known code word; the finding quotes the line's own spelling."""
        text = "Use FastAPI and Pydantic for models."
        atoms = [
            _atom(1, +1, text=text, unformatted_code=["fastapi", "pydantic"]),
            _atom(2, +1, named_tokens=["FastAPI", "Pydantic"]),
        ]
        findings = _check_unformatted_code(atoms, "a.md", [text])
        assert [f.message.split("'")[1] for f in findings] == ["FastAPI", "Pydantic"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_one_name_on_a_line_is_one_finding(self) -> None:
        """`json` inside `settings.json` is not a second unformatted name."""
        text = "Open settings.json and edit it."
        atoms = [_atom(1, +1, text=text, unformatted_code=["json", "settings.json"])]
        findings = _check_unformatted_code(atoms, "a.md", [text])
        assert [f.message.split("'")[1] for f in findings] == ["settings.json"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_short_name_standing_alone_is_still_reported(self) -> None:
        text = "Edit settings.json and validate the json."
        atoms = [
            _atom(1, +1, text=text, unformatted_code=["json", "settings.json"]),
            _atom(2, +1, named_tokens=["json"]),
        ]
        findings = _check_unformatted_code(atoms, "a.md", [text])
        assert sorted(f.message.split("'")[1] for f in findings) == ["json", "settings.json"]


class TestLibraryNameInProse:
    """A library or web-API name in prose is a finding only when the file backticks it elsewhere."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(("name", "known"), [("FastAPI", "fastapi"), ("WebSocket", "WebSocket")])
    def test_a_name_never_backticked_in_the_file_draws_no_finding(self, name: str, known: str) -> None:
        text = f"The service is built with {name} for streaming."
        atoms = [_atom(1, +1, text=text, unformatted_code=[known])]
        assert _check_unformatted_code(atoms, "a.md", [text]) == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(("name", "known"), [("FastAPI", "fastapi"), ("WebSocket", "WebSocket")])
    def test_a_name_backticked_elsewhere_in_the_file_draws_the_finding(self, name: str, known: str) -> None:
        text = f"The service is built with {name} for streaming."
        atoms = [_atom(1, +1, text=text, unformatted_code=[known]), _atom(5, +1, named_tokens=[name])]
        findings = _check_unformatted_code(atoms, "a.md", [text])
        assert [f.message.split("'")[1] for f in findings] == [name]


class TestLibraryNameInRealMarkdown:
    """The same rule on markdown read by the parse: the check and `--heal` agree."""

    _WITH = "The service is built with FastAPI for streaming.\n\nStart the `FastAPI` app first.\n"
    _WITHOUT = "The service is built with FastAPI for streaming.\n\nStart the app first.\n"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_name_the_file_backticks_elsewhere_is_reported_and_wrapped(self) -> None:
        lines = self._WITH.splitlines(keepends=True)
        atoms = tokenize(self._WITH)
        assert [f.message.split("'")[1] for f in _check_unformatted_code(atoms, "a.md", lines)] == ["FastAPI"]
        assert len(fix_unformatted_code(atoms, lines)) == 1
        assert lines[0] == "The service is built with `FastAPI` for streaming.\n"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_name_the_file_never_backticks_is_neither_reported_nor_wrapped(self) -> None:
        lines = self._WITHOUT.splitlines(keepends=True)
        atoms = tokenize(self._WITHOUT)
        assert _check_unformatted_code(atoms, "a.md", lines) == []
        assert fix_unformatted_code(atoms, lines) == []


class TestBroadScope:
    """The broad-conditional-scope check reads `scope_conditional`.

    It was unreachable while every atom shipped `scope_conditional=False`; with the
    flag derived again, the term match has to be a WORD match — `sql` inside
    `postgresql` is not a broad scope term.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_broad_term_as_a_whole_word_is_flagged(self) -> None:
        atoms = [
            _atom(10, +1, text="When external services fail, retry the request.", scope_conditional=True),
            _atom(11, -1, text="If third-party integrations are unavailable, skip the sync.", scope_conditional=True),
        ]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert len(findings) == 2, [f.message for f in findings]
        assert "services" in findings[0].message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_broad_term_inside_a_longer_word_is_not_flagged(self) -> None:
        atoms = [
            _atom(10, +1, text="If postgresql is unreachable, cache the request.", scope_conditional=True),
        ]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert findings == [], [f.message for f in findings]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unconditional_atom_is_never_scope_checked(self) -> None:
        atoms = [_atom(10, +1, text="When any edit lands, re-run the check.", scope_conditional=False)]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert findings == []


class TestBroadScopeWordingsRestrictedToOpposition:
    """The scope check fires on outside systems (external services, third-party
    integrations, dependencies, database or SQL code) and stays quiet on the
    universal `editing any file`."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_external_services_fires(self) -> None:
        atoms = [_atom(10, +1, text="When external services are down, queue the job.", scope_conditional=True)]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert len(findings) == 1, [f.message for f in findings]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_third_party_api_integrations_fires(self) -> None:
        atoms = [
            _atom(10, +1, text="Before third-party API integrations run, log the payload.", scope_conditional=True)
        ]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert len(findings) == 1, [f.message for f in findings]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_database_or_sql_code_fires(self) -> None:
        atoms = [_atom(10, +1, text="When touching database or SQL code, add a migration.", scope_conditional=True)]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert len(findings) == 1, [f.message for f in findings]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_scope_instruction_conflict_fail_example_fires(self) -> None:
        # CORE:C:0049's own Fail example (framework/rules/core/semantic-interference/rule.md).
        atoms = [_atom(10, -1, text="When testing API integrations, don't use mocks.", scope_conditional=True)]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert len(findings) == 1, [f.message for f in findings]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_external_dependency_boundaries_fires(self) -> None:
        # A dependency on an outside system is a risky scope, as the rule page's own examples say.
        atoms = [
            _atom(10, +1, text="When crossing external dependency boundaries, log the call.", scope_conditional=True)
        ]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert len(findings) == 1, [f.message for f in findings]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_editing_any_file_does_not_fire(self) -> None:
        # The universal case — too broad to carry any scope signal.
        atoms = [_atom(10, +1, text="When editing any file, keep the header intact.", scope_conditional=True)]
        findings = [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]
        assert findings == [], [f.message for f in findings]


class TestBroadScopeRiskyWording:
    """Scopes naming outside systems fire, singular or plural; wide but harmless wording stays quiet."""

    @staticmethod
    def _scope_findings(text: str) -> list:
        atoms = [_atom(10, +1, text=text, scope_conditional=True)]
        return [f for f in run_client_checks(_make_map(atoms)) if f.rule == "CORE:C:0060"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        "text",
        [
            "When any external service fails, retry the request up to 3 times.",
            "If all dependencies are unavailable, fall back to cached data.",
            "When the payment service times out, retry the request.",
            "Before calling any third-party integration, log the request payload.",
            "If the database is down, serve cached data.",
            "When a SQL query fails, roll back.",
            "If an external API is slow, cut the timeout.",
            "When a dependency is unavailable, skip the step.",
        ],
    )
    def test_outside_system_scope_is_flagged(self, text: str) -> None:
        assert len(self._scope_findings(text)) == 1, text

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        "text",
        [
            "When any file changes, re-run the tests.",
            "If all tests pass, tag the release.",
            "Before any commit, run the linter.",
            "If postgresql is unreachable, cache the request.",
        ],
    )
    def test_wide_but_harmless_scope_stays_quiet(self, text: str) -> None:
        assert self._scope_findings(text) == [], text
