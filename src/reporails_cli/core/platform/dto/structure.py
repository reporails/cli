"""Pure data shape for the block structure of one markdown file: where its headings, list items,
table rows, fenced blocks and links sit. The mapper reads it from the markdown parse; the rewrite
check compares two of them.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DocumentStructure:
    """The blocks of a file, each tied to its 1-based source line.

    - `headings`: line of every heading, `#`-style and underlined alike.
    - `list_items`: `(line, list)` for every list item; `list` numbers the contiguous list
      block the item sits in (a nested item shares its parent's number).
    - `table_rows`: `(line, first cell's plain text)` for every body row (header rows left out).
    - `fences`: `(opening line, body)` for every fenced block.
    - `links`: `(line, target)` for every link, image and bare URL outside code.
    - `block_of`: line -> number of the block (paragraph, list item, heading, table, fence) the
      line belongs to, in document order.
    """

    headings: tuple[int, ...] = ()
    list_items: tuple[tuple[int, int], ...] = ()
    table_rows: tuple[tuple[int, str], ...] = ()
    fences: tuple[tuple[int, str], ...] = ()
    links: tuple[tuple[int, str], ...] = ()
    block_of: dict[int, int] = field(default_factory=dict)
