"""Rich-markup lines for the notices the server sends.

The text and the link come from outside the client, so both go through `escape`: a
notice that contains `[bold]` prints those characters, never the style. No I/O.
"""

from __future__ import annotations

from collections.abc import Iterable

from rich.markup import escape

from reporails_cli.core.platform.dto.diagnostics import Notice

_LINK_SCHEMES = ("https://", "http://")


def _link_target(url: str) -> str:
    """The url as a `[link=...]` target: brackets percent-encoded so it cannot close the tag."""
    return url.replace("[", "%5B").replace("]", "%5D")


def _notice_lines(notice: Notice) -> list[str]:
    """One notice as body lines: the text (yellow for a warning), then its link when it has one."""
    text = escape(notice.text)
    lines = [f"  [yellow]{text}[/yellow]" if notice.level == "warn" else f"  {text}"]
    if notice.url.startswith(_LINK_SCHEMES):
        lines.append(f"  → [link={_link_target(notice.url)}]{escape(notice.url)}[/link]")
    elif notice.url:
        lines.append(f"  → {escape(notice.url)}")
    return lines


def notice_lines(notices: Iterable[Notice]) -> list[str]:
    """Rich-markup body lines for `notices`, in order."""
    return [line for notice in notices for line in _notice_lines(notice)]
