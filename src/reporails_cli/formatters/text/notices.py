"""Printing the notices the server sends, the one place both printers share.

The text and the link come from outside the client, so both go through `escape`: a
notice that contains `[bold]` prints those characters, never the style. Each notice
prints indented two spaces, wrapped lines included.

An announcement (`kind == "promo"`) prints as a styled block — a rule, the bold text, the
link, a rule — only on a colour terminal outside ASCII mode; anywhere else it prints
exactly like a plain notice. On that same terminal a warning prints as a highlighted block
(bold black on bright yellow, one space of padding each side); anywhere else its text is yellow.
"""

from __future__ import annotations

from collections.abc import Iterable

from rich.cells import cell_len
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
_WARN_BLOCK_STYLE = "bold black on bright_yellow"


def _notice_lines(notice: Notice, arrow: str, *, bold: bool = False, block: bool = False) -> list[str]:
    """One notice as body lines: the text (yellow for a warning unless `block`, bold when asked), then its link."""
    text = escape(notice.text)
    if notice.level == "warn" and not block:
        text = f"[yellow]{text}[/yellow]"
    elif bold:
        text = f"[bold]{text}[/bold]"
    lines = [text]
    if notice.url.startswith(LINK_SCHEMES):
        lines.append(f"{arrow} [link={_link_target(notice.url)}]{escape(notice.url)}[/link]")
    elif notice.url:
        lines.append(f"{arrow} {escape(notice.url)}")
    return lines


def _print_body(console: Console, lines: list[str], width: int, *, block: bool = False) -> None:
    """The text wrapped to `width` and indented two spaces, then each link on its own line.

    With `block` the text prints as a highlighted block of equal-width lines, padded one space each side.
    """
    indent = Text("  ")
    text, *links = lines
    if block:
        rows = [row.plain.rstrip() for row in Text.from_markup(text, emoji=False).wrap(console, max(width - 2, 1))]
        longest = max(cell_len(row) for row in rows)
        for row in rows:
            console.print(
                indent + Text(f" {row}{' ' * (longest - cell_len(row))} ", style=_WARN_BLOCK_STYLE), soft_wrap=True
            )
    else:
        for wrapped in Text.from_markup(text, emoji=False).wrap(console, width):
            wrapped.rstrip()
            console.print(indent + wrapped if wrapped.plain else "", soft_wrap=True)
    for link in links:
        console.print(indent + Text.from_markup(link, emoji=False), soft_wrap=True)


def print_notices(console: Console, notices: Iterable[Notice], *, ascii_mode: bool | None = None) -> None:
    """Print `notices` on `console`: the text indented two spaces, wrapped lines too; a link on one line.

    One blank line separates consecutive notices. An announcement's text wraps within its rules.

    `ascii_mode` None follows `AILS_ASCII`.
    """
    ascii_on = ASCII_MODE if ascii_mode is None else ascii_mode
    chars = get_chars(ascii_on)
    styled = console.is_terminal and not console.no_color and not ascii_on
    width = max(console.width - 2, 1)
    rule_width = max(min(console.width - 2, _RULE_MAX), 1)
    rule = Text("  " + chars["sep"] * rule_width, style=_RULE_STYLE)
    for index, notice in enumerate(notices):
        promo = styled and notice.kind == "promo"
        if index:
            console.print()
        if promo:
            console.print(rule, soft_wrap=True)
        block = styled and notice.level == "warn"
        lines = _notice_lines(notice, chars["arrow"], bold=promo and not block, block=block)
        _print_body(console, lines, rule_width if promo else width, block=block)
        if promo:
            console.print(rule, soft_wrap=True)
