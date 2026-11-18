"""The file reader decodes a byte-order-marked and an invalid-UTF-8 file the way each caller depends on."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.utils.file_read import read_file_bytes, read_file_head, read_file_text

BOM = b"\xef\xbb\xbf"

pytestmark = [pytest.mark.unit, pytest.mark.subsys_lint]


def test_utf8_keeps_the_byte_order_mark(tmp_path: Path) -> None:
    path = tmp_path / "bom.md"
    path.write_bytes(BOM + b"hi")
    assert read_file_text(path) == "﻿hi"


def test_utf8_sig_drops_the_byte_order_mark(tmp_path: Path) -> None:
    path = tmp_path / "bom.md"
    path.write_bytes(BOM + b"hi")
    assert read_file_text(path, encoding="utf-8-sig") == "hi"


def test_strict_raises_on_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.md"
    path.write_bytes(b"a\xffb")
    with pytest.raises(UnicodeDecodeError):
        read_file_text(path)
    with pytest.raises(UnicodeDecodeError):
        read_file_text(path, encoding="utf-8-sig")


def test_replace_substitutes_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.md"
    path.write_bytes(b"a\xffb")
    assert read_file_text(path, errors="replace") == "a�b"


def test_bytes_and_head(tmp_path: Path) -> None:
    path = tmp_path / "bad.md"
    path.write_bytes(BOM + b"a\xffb")
    assert read_file_bytes(path) == BOM + b"a\xffb"
    assert read_file_head(path, 4) == BOM + b"a"


def test_missing_file_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        read_file_text(tmp_path / "nope.md")


def test_limit_counts_characters_not_bytes(tmp_path: Path) -> None:
    path = tmp_path / "multi.md"
    path.write_text("é" * 10, encoding="utf-8")
    assert read_file_text(path, limit=4) == "éééé"
    assert read_file_text(path, limit=50) == "é" * 10
