"""Notice text is the server's, so it prints literally: never as markup."""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console

from reporails_cli.core.platform.dto.diagnostics import Notice
from reporails_cli.formatters.text.notices import _notice_lines, print_notices


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
    warn, info = (_notice_lines(Notice("a", level, "msg"), "→")[0] for level in ("warn", "info"))
    assert warn == "[yellow]msg[/yellow]"
    assert info == "msg"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_https_url_renders_as_a_link_and_brackets_cannot_close_the_tag() -> None:
    lines = _notice_lines(Notice("a", "info", "msg", "https://example.test/a[1]"), "→")
    assert lines[1].startswith("→ [link=https://example.test/a%5B1%5D]")
    assert "https://example.test/a[1]" not in lines[1].split("]", 1)[0]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_non_web_url_is_text_not_a_link() -> None:
    lines = _notice_lines(Notice("a", "info", "msg", "file:///etc/passwd"), "→")
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


PROMO = Notice("p", "info", "Fixture promo.", "https://reporails.com/x", kind="promo")


def _unlinked(out: str) -> str:
    return re.sub(r"\x1b\]8;[^\x1b]*\x1b\\", "", out)


def _render(notices: list[Notice], *, ascii_mode: bool | None = None, **console_args: object) -> str:
    buf = io.StringIO()
    args = {"force_terminal": True, "width": 80, "emoji": False, "highlight": False}
    console = Console(file=buf, **{**args, **console_args})  # type: ignore[arg-type]
    print_notices(console, notices, ascii_mode=ascii_mode)
    return buf.getvalue()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_promo_on_a_terminal_is_a_styled_block() -> None:
    out = _render([PROMO], ascii_mode=False, color_system="standard")
    lines = out.splitlines()
    assert len(lines) == 4
    assert "─" * 60 in lines[0]
    assert "─" * 60 in lines[3]
    assert "\x1b[1m" in lines[1]
    assert "Fixture promo." in lines[1]
    assert "→" in lines[2]
    assert "https://reporails.com/x" in lines[2]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "console_args", [{"no_color": True}, {"force_terminal": False}], ids=["no_color", "not_a_terminal"]
)
def test_promo_without_colour_prints_like_an_info_notice(console_args: dict) -> None:
    out = _unlinked(_render([PROMO], ascii_mode=False, **console_args))
    assert out == "  Fixture promo.\n  → https://reporails.com/x\n"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_promo_in_ascii_mode_is_plain_with_an_ascii_arrow() -> None:
    out = _unlinked(_render([PROMO], ascii_mode=True))
    assert out == "  Fixture promo.\n  -> https://reporails.com/x\n"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_ascii_arrow_applies_to_every_notice() -> None:
    out = _unlinked(_render([Notice("a", "info", "Hi", "https://e.test")], ascii_mode=True))
    assert "-> https://e.test" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("plain", [False, True])
def test_markup_in_promo_text_prints_literally(plain: bool) -> None:
    promo = Notice("p", "info", "Pay [bold]now[/bold] [red]x[/red]", "https://e.test/[a]", kind="promo")
    out = _render([promo], ascii_mode=plain)
    assert "Pay [bold]now[/bold] [red]x[/red]" in out
    assert "https://e.test/[a]" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_notices_are_separated_by_one_blank_line_and_none_around_them() -> None:
    out = _printed([Notice("a", "info", "First"), Notice("b", "info", "Second")])
    assert out.splitlines() == ["  First", "", "  Second"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_promo_text_stays_within_its_rules_on_a_wide_terminal() -> None:
    promo = Notice("p", "info", "Fixture promo text that is long enough to wrap " * 4, kind="promo")
    lines = _render([promo], ascii_mode=False, width=100, color_system="standard")
    plain = [re.sub(r"\x1b\[[0-9;]*m", "", line) for line in lines.splitlines()]
    rule = len(plain[0])
    assert rule == 2 + 60
    body = plain[1:-1]
    assert len(body) > 1
    assert all(len(line) <= rule for line in body)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_long_plain_notice_still_wraps_at_the_console_width() -> None:
    out = _render([Notice("a", "info", "word " * 60)], width=100, force_terminal=False)
    widths = [len(line) for line in out.splitlines()]
    assert max(widths) > 62
    assert max(widths) <= 100
