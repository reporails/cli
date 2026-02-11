"""Tests for tarball extraction security and rules structure validation."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from reporails_cli.core.download import _safe_extractall, _validate_rules_structure


class TestSafeExtractall:
    """Verify _safe_extractall blocks malicious archive entries."""

    def _make_tar(self, members: list[tuple[str, bytes]]) -> tarfile.TarFile:
        """Build an in-memory tarball with the given name→content pairs."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in members:
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        return tarfile.open(fileobj=buf, mode="r:gz")

    def test_normal_extraction(self, tmp_path: Path) -> None:
        tar = self._make_tar([("hello.txt", b"world")])
        _safe_extractall(tar, tmp_path)
        assert (tmp_path / "hello.txt").read_text() == "world"

    def test_blocks_absolute_path(self, tmp_path: Path) -> None:
        tar = self._make_tar([("/etc/passwd", b"malicious")])
        with pytest.raises(RuntimeError, match="Unsafe path"):
            _safe_extractall(tar, tmp_path)

    def test_blocks_path_traversal(self, tmp_path: Path) -> None:
        tar = self._make_tar([("../escape.txt", b"malicious")])
        with pytest.raises(RuntimeError, match="Unsafe path"):
            _safe_extractall(tar, tmp_path)

    def test_blocks_nested_traversal(self, tmp_path: Path) -> None:
        tar = self._make_tar([("foo/../../escape.txt", b"malicious")])
        with pytest.raises(RuntimeError, match="Unsafe path"):
            _safe_extractall(tar, tmp_path)

    def test_blocks_symlink_outside(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="evil_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            tar.addfile(info)
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar, pytest.raises(RuntimeError, match="Unsafe symlink"):
            _safe_extractall(tar, tmp_path)

    def test_allows_safe_nested_paths(self, tmp_path: Path) -> None:
        tar = self._make_tar([("core/rules/test.yml", b"data")])
        _safe_extractall(tar, tmp_path)
        assert (tmp_path / "core" / "rules" / "test.yml").exists()


class TestValidateRulesStructure:
    """Verify _validate_rules_structure checks for expected directories."""

    def test_valid_structure(self, tmp_path: Path) -> None:
        (tmp_path / "core").mkdir()
        (tmp_path / "schemas").mkdir()
        _validate_rules_structure(tmp_path)  # Should not raise

    def test_missing_core(self, tmp_path: Path) -> None:
        (tmp_path / "schemas").mkdir()
        with pytest.raises(RuntimeError, match="core"):
            _validate_rules_structure(tmp_path)

    def test_missing_schemas(self, tmp_path: Path) -> None:
        (tmp_path / "core").mkdir()
        with pytest.raises(RuntimeError, match="schemas"):
            _validate_rules_structure(tmp_path)

    def test_empty_dir_fails(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError):
            _validate_rules_structure(tmp_path)
