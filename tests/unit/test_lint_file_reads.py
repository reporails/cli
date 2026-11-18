"""The lint sites that read a file decode it as they did before the shared reader."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.client_checks import _source_lines
from reporails_cli.core.lint.regex.expect import file_below_min_lines
from reporails_cli.core.lint.regex.runner import _is_text_file

pytestmark = [pytest.mark.unit, pytest.mark.subsys_lint]


def test_source_lines_empty_on_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.md"
    path.write_bytes(b"a\n\xffb\n")
    assert _source_lines(str(path)) == []


def test_min_lines_reads_through_a_bom_and_bad_bytes(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_bytes(b"\xef\xbb\xbfone\n\xff\ntwo\n")
    assert file_below_min_lines("a.md", 4, tmp_path) is True
    assert file_below_min_lines("a.md", 3, tmp_path) is False


def test_text_file_probe_reads_the_first_8192_bytes(tmp_path: Path) -> None:
    (tmp_path / "late.bin").write_bytes(b"a" * 8192 + b"\x00")
    (tmp_path / "early.bin").write_bytes(b"a\x00")
    assert _is_text_file(tmp_path / "late.bin") is True
    assert _is_text_file(tmp_path / "early.bin") is False
