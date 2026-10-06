"""Notice text is the server's, so it prints literally: never as markup."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from reporails_cli.core.platform.dto.diagnostics import Notice
from reporails_cli.formatters.text.notices import notice_lines, print_notices


def _printed(notices: list[Notice]) -> str:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=200, emoji=False, highlight=False)
    print_notices(console, notices)
    return buf.getvalue()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_markup_in_text_prints_literally() -> None:
    text = "Pay [bold]now[/bold] at [link=https://evil.test]here[/link]"
    out = _printed([Notice("a", "info", text)])
    assert text in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_markup_in_text_carries_no_style_when_rendered() -> None:
    console = Console(force_terminal=True, color_system="standard", width=200, file=io.StringIO(), highlight=False)
    with console.capture() as cap:
        print_notices(console, [Notice("a", "info", "[bold]loud[/bold]")])
    assert "\x1b[1m" not in cap.get()
    assert "[bold]loud[/bold]" in cap.get()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_warn_is_yellow_and_info_is_plain() -> None:
    warn, info = (notice_lines([Notice("a", level, "msg")])[0] for level in ("warn", "info"))
    assert warn == "[yellow]msg[/yellow]"
    assert info == "msg"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_https_url_renders_as_a_link_and_brackets_cannot_close_the_tag() -> None:
    lines = notice_lines([Notice("a", "info", "msg", "https://example.test/a[1]")])
    assert lines[1].startswith("→ [link=https://example.test/a%5B1%5D]")
    assert "https://example.test/a[1]" not in lines[1].split("]", 1)[0]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_non_web_url_is_text_not_a_link() -> None:
    lines = notice_lines([Notice("a", "info", "msg", "file:///etc/passwd")])
    assert "[link" not in lines[1]
    assert "file:///etc/passwd" in lines[1]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_long_notice_keeps_its_indent_on_every_wrapped_line_and_ends_without_spaces() -> None:
    buf = io.StringIO()
    console = Console(width=40, file=buf, force_terminal=False, highlight=False)
    print_notices(console, [Notice("a", "warn", "Your payment failed and the plan ends soon " * 3)])
    lines = buf.getvalue().splitlines()
    assert len(lines) > 2
    assert all(line.startswith("  ") for line in lines)
    assert all(line == line.rstrip() for line in lines)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_long_link_stays_on_one_line() -> None:
    url = "https://example.test/billing/" + "x" * 50
    buf = io.StringIO()
    print_notices(Console(width=30, file=buf, force_terminal=False, highlight=False), [Notice("a", "info", "Pay", url)])
    assert buf.getvalue().splitlines() == ["  Pay", f"  → {url}"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_blank_line_prints_empty_and_an_emoji_code_prints_literally() -> None:
    buf = io.StringIO()
    print_notices(
        Console(width=40, file=buf, force_terminal=False, highlight=False), [Notice("a", "info", "One\n\nTwo :smile:")]
    )
    assert buf.getvalue().splitlines() == ["  One", "", "  Two :smile:"]
