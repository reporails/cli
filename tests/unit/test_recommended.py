"""Unit tests for recommended rules package download and installation."""

from __future__ import annotations

import tarfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from reporails_cli.core.init import (
    RECOMMENDED_ARCHIVE_URL,
    RECOMMENDED_VERSION,
    download_recommended,
    is_recommended_installed,
)


def _make_archive(files: dict[str, str], prefix: str = "recommended-0.0.1") -> bytes:
    """Create a tar.gz archive in memory with given files under a prefix directory.

    Args:
        files: Mapping of relative path to file content
        prefix: Top-level directory name (GitHub archive style)

    Returns:
        Bytes of the tar.gz archive
    """
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            full_name = f"{prefix}/{name}" if prefix else name
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=full_name)
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
    buf.seek(0)
    return buf.read()


class TestIsRecommendedInstalled:
    """Test is_recommended_installed checks."""

    def test_not_installed_when_missing(self, tmp_path: Path) -> None:
        with patch(
            "reporails_cli.core.init.get_recommended_package_path",
            return_value=tmp_path / "packages" / "recommended",
        ):
            assert is_recommended_installed() is False

    def test_not_installed_when_empty(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "packages" / "recommended"
        pkg_dir.mkdir(parents=True)
        with patch(
            "reporails_cli.core.init.get_recommended_package_path",
            return_value=pkg_dir,
        ):
            assert is_recommended_installed() is False

    def test_installed_when_has_content(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "packages" / "recommended"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "levels.yml").write_text("levels: {}")
        with patch(
            "reporails_cli.core.init.get_recommended_package_path",
            return_value=pkg_dir,
        ):
            assert is_recommended_installed() is True


class TestDownloadRecommended:
    """Test download_recommended extraction and version tracking."""

    def test_extracts_and_strips_prefix(self, tmp_path: Path) -> None:
        """Archive with GitHub-style prefix is extracted correctly."""
        pkg_dir = tmp_path / "packages" / "recommended"
        archive = _make_archive({
            "levels.yml": "levels:\n  L2:\n    rules: [AILS_R1]\n",
            "AILS_R1.md": "---\nid: AILS_R1\ntitle: Test\n---\n",
            "AILS_R1.yml": "rules: []\n",
        })

        mock_response = MagicMock()
        mock_response.content = archive
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=mock_response)

        with (
            patch(
                "reporails_cli.core.init.get_recommended_package_path",
                return_value=pkg_dir,
            ),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
        ):
            result = download_recommended()

        assert result == pkg_dir
        assert (pkg_dir / "levels.yml").exists()
        assert (pkg_dir / "AILS_R1.md").exists()
        assert (pkg_dir / "AILS_R1.yml").exists()

        # Version file written
        version_file = pkg_dir / ".version"
        assert version_file.exists()
        assert version_file.read_text().strip() == RECOMMENDED_VERSION

    def test_clears_existing_before_download(self, tmp_path: Path) -> None:
        """Old content is removed before extracting new."""
        pkg_dir = tmp_path / "packages" / "recommended"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "old_file.txt").write_text("stale")

        archive = _make_archive({"new_file.yml": "content: true"})

        mock_response = MagicMock()
        mock_response.content = archive
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=mock_response)

        with (
            patch(
                "reporails_cli.core.init.get_recommended_package_path",
                return_value=pkg_dir,
            ),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
        ):
            download_recommended()

        assert not (pkg_dir / "old_file.txt").exists()
        assert (pkg_dir / "new_file.yml").exists()

    def test_uses_correct_url(self, tmp_path: Path) -> None:
        """Verifies the correct archive URL is fetched."""
        pkg_dir = tmp_path / "packages" / "recommended"
        archive = _make_archive({"test.yml": "ok: true"})

        mock_response = MagicMock()
        mock_response.content = archive
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=mock_response)

        with (
            patch(
                "reporails_cli.core.init.get_recommended_package_path",
                return_value=pkg_dir,
            ),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
        ):
            download_recommended()

        mock_client.get.assert_called_once_with(RECOMMENDED_ARCHIVE_URL)
