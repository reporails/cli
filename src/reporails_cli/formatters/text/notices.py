"""Printing the notices the server sends, the one place both printers share.

The text and the link come from outside the client, so both go through `escape`: a
notice that contains `[bold]` prints those characters, never the style. Each notice
prints indented two spaces, wrapped lines included.

An announcement (`kind == "promo"`) prints as a styled block — a rule, the bold text, the
link, a rule — only on a colour terminal outside ASCII mode; anywhere else it prints
exactly like a plain notice.
"""

from __future__ import annotations

from collections.abc import Iterable

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from reporails_cli.core.platform.dto.diagnostics import Notice
from reporails_cli.formatters.text.chars import ASCII_MODE, get_chars
from reporails_cli.formatters.text.funnel_cta import LINK_SCHEMES


def _link_target(url: str) -> str:
    """The url as a `[link=...]` target: brackets percent-encoded so it cannot close the tag."""
    return url.replace("[", "%5B").replace("]", "%5D")


_RULE_STYLE = "magenta"
_RULE_MAX = 60


def _notice_lines(notice: Notice, arrow: str, *, bold: bool = False) -> list[str]:
    """One notice as body lines: the text (yellow for a warning, bold when asked), then its link when it has one."""
    text = escape(notice.text)
    if notice.level == "warn":
        text = f"[yellow]{text}[/yellow]"
    elif bold:
        text = f"[bold]{text}[/bold]"
    lines = [text]
    if notice.url.startswith(LINK_SCHEMES):
        lines.append(f"{arrow} [link={_link_target(notice.url)}]{escape(notice.url)}[/link]")
    elif notice.url:
        lines.append(f"{arrow} {escape(notice.url)}")
    return lines


def _print_body(console: Console, lines: list[str], width: int) -> None:
    """The text wrapped to `width` and indented two spaces, then each link on its own line."""
    indent = Text("  ")
    text, *links = lines
    for wrapped in Text.from_markup(text, emoji=False).wrap(console, width):
        wrapped.rstrip()
        console.print(indent + wrapped if wrapped.plain else "", soft_wrap=True)
    for link in links:
        console.print(indent + Text.from_markup(link, emoji=False), soft_wrap=True)


def print_notices(console: Console, notices: Iterable[Notice], *, ascii_mode: bool | None = None) -> None:
    """Print `notices` on `console`: the text indented two spaces, wrapped lines too; a link on one line.

    `ascii_mode` None follows `AILS_ASCII`.
    """
    ascii_on = ASCII_MODE if ascii_mode is None else ascii_mode
    chars = get_chars(ascii_on)
    styled = console.is_terminal and not console.no_color and not ascii_on
    width = max(console.width - 2, 1)
    rule = Text("  " + chars["sep"] * max(min(console.width - 2, _RULE_MAX), 1), style=_RULE_STYLE)
    for notice in notices:
        promo = styled and notice.kind == "promo"
        if promo:
            console.print(rule, soft_wrap=True)
        _print_body(console, _notice_lines(notice, chars["arrow"], bold=promo), width)
        if promo:
            console.print(rule, soft_wrap=True)
