"""The top-level sections of a recorded system prompt."""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.structure import top_level_sections
from reporails_cli.core.platform.dto.xray_prompt import PromptSection

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

FENCED = "# A\nbody\n```\n# not a heading\n```\n# B\nx\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", ()),
        ("   \n", ()),
        ("just text\nmore", (("Opening", 14),)),
        ("lead\n# A\nx\n# B\ny", (("Opening", 5), ("A", 6), ("B", 5))),
        ("# A\n## sub\nx\n# B\ny", (("A", 13), ("B", 5))),
        ("# A\n\n\n# B\n", (("A", 6), ("B", 4))),
        (FENCED, (("A", FENCED.index("# B")), ("B", 6))),
        ("intro\r\r\r# A\nx\n# B\ny", (("Opening", 8), ("A", 6), ("B", 5))),
        ("intro\r\n# A\r\nx\r\n# B\r\ny", (("Opening", 7), ("A", 8), ("B", 6))),
        ("#  Spaced  \nx", (("Spaced", 13),)),
    ],
)
def test_top_level_sections_split_at_top_level_headings(text: str, expected: tuple[tuple[str, int], ...]) -> None:
    sections = top_level_sections(text)
    assert sections == tuple(PromptSection(h, c) for h, c in expected)
    if sections:
        assert sum(s.chars for s in sections) == len(text)
