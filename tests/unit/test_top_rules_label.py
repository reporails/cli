"""The text output's `Top rules` block labels each rule by what the rule is."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from reporails_cli.formatters.text import scorecard
from reporails_cli.formatters.text.display_constants import rule_label


@dataclass
class _Finding:
    rule: str
    message: str
    severity: str = "warning"


@dataclass
class _Result:
    findings: tuple


def _render(result: object, width: int, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(scorecard, "get_term_width", lambda: width)
    monkeypatch.setattr(scorecard.console, "width", width)
    with scorecard.console.capture() as cap:
        scorecard._render_top_rules(result)
    return cap.get()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
@pytest.mark.parametrize("width", [80, 120])
def test_a_rule_row_carries_the_rule_title_not_a_fragment_of_one_message(
    width: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    title = (rule_label("CORE:E:0003") or {}).get("title", "")
    assert title, "the registry has no title for the rule used by this test"
    findings = tuple(
        _Finding("CORE:E:0003", "Instruction 'authentication.py handler' is vague. Name the file.") for _ in range(3)
    )
    out = _render(_Result(findings), width, monkeypatch)
    row = next(line for line in out.splitlines() if "CORE:E:0003" in line)
    assert title[: width - 30] in row
    assert "'authentication" not in row


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_without_a_known_title_the_label_is_the_messages_first_sentence(monkeypatch: pytest.MonkeyPatch) -> None:
    findings = (_Finding("CORE:Z:9999", "Unreadable block here. The second sentence is not shown."),)
    out = _render(_Result(findings), 120, monkeypatch)
    assert "Unreadable block here" in out
    assert "second sentence" not in out


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_period_inside_a_quoted_name_does_not_end_the_label(monkeypatch: pytest.MonkeyPatch) -> None:
    findings = (_Finding("CORE:Z:9999", "File `app.config.yml` has no owner. Add one."),)
    out = _render(_Result(findings), 120, monkeypatch)
    assert "`app.config.yml` has no owner" in out
    assert "Add one" not in out


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_cut_label_never_ends_inside_a_backticked_token(monkeypatch: pytest.MonkeyPatch) -> None:
    findings = (
        _Finding("CORE:Z:9999", "The command `pytest --maxfail=1 --disable-warnings -q tests/unit` hides output"),
    )
    out = _render(_Result(findings), 80, monkeypatch)
    row = next(line for line in out.splitlines() if "CORE:Z:9999" in line)
    assert row.count("`") % 2 == 0
    assert row.rstrip().endswith("…")
