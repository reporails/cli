"""A broken markdown link is reported once, on the line that holds it, under `CORE:S:0056`."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.checks_advanced import (
    check_markdown_link_targets_exist,
    extract_markdown_links,
)
from reporails_cli.core.platform.dto.models import ClassifiedFile


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_each_link_is_annotated_with_its_line_past_a_fenced_block(tmp_path: Path) -> None:
    doc = tmp_path / "a.md"
    doc.write_text("# A\n\n```bash\nls\n[not](a-link.md)\n```\n\nSee [b](b.md).\n")
    result = extract_markdown_links(tmp_path, {}, [ClassifiedFile(path=doc, file_type="main")])
    assert (result.annotations or {})["discovered_markdown_links"] == ["a.md::b.md::8"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_each_broken_link_is_located_on_its_own_line(tmp_path: Path) -> None:
    (tmp_path / "src.md").write_text("x\n")
    (tmp_path / "ok.md").write_text("x\n")
    args = {"discovered_markdown_links": ["src.md::missing.md::2", "src.md::ok.md::3", "other.md::gone.md::5"]}
    result = check_markdown_link_targets_exist(tmp_path, args, [])
    assert not result.passed
    assert [loc for loc, _ in result.occurrences or []] == ["src.md:2", "other.md:5"]
    assert "`missing.md`" in (result.occurrences or [])[0][1]
