"""Printing the notices the server sends, the one place both printers share.

The text and the link come from outside the client, so both go through `escape`: a
notice that contains `[bold]` prints those characters, never the style. Each notice
prints indented two spaces, wrapped lines included.
"""

from __future__ import annotations

from collections.abc import Iterable

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from reporails_cli.core.platform.dto.diagnostics import Notice

_LINK_SCHEMES = ("https://", "http://")


def _link_target(url: str) -> str:
    """The url as a `[link=...]` target: brackets percent-encoded so it cannot close the tag."""
    return url.replace("[", "%5B").replace("]", "%5D")


def _notice_lines(notice: Notice) -> list[str]:
    """One notice as body lines: the text (yellow for a warning), then its link when it has one."""
    text = escape(notice.text)
    lines = [f"[yellow]{text}[/yellow]" if notice.level == "warn" else text]
    if notice.url.startswith(_LINK_SCHEMES):
        lines.append(f"→ [link={_link_target(notice.url)}]{escape(notice.url)}[/link]")
    elif notice.url:
        lines.append(f"→ {escape(notice.url)}")
    return lines


def notice_lines(notices: Iterable[Notice]) -> list[str]:
    """Rich-markup body lines for `notices`, in order, without the indent."""
    return [line for notice in notices for line in _notice_lines(notice)]


def print_notices(console: Console, notices: Iterable[Notice]) -> None:
    """Print `notices` on `console`: the text indented two spaces, wrapped lines too; a link on one line."""
    indent = Text("  ")
    width = max(console.width - len(indent), 1)
    for notice in notices:
        text, *links = _notice_lines(notice)
        for wrapped in Text.from_markup(text, emoji=False).wrap(console, width):
            wrapped.rstrip()
            console.print(indent + wrapped if wrapped.plain else "", soft_wrap=True)
        for link in links:
            console.print(indent + Text.from_markup(link, emoji=False), soft_wrap=True)
