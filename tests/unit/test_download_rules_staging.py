"""Tests for download_rules_version staging behavior.

Verifies that incompatible rules never overwrite a working installation.
The function must extract to a staging directory, verify schema compatibility,
and only then swap into the real rules path.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reporails_cli.core.init import (
    IncompatibleSchemaError,
    download_rules_version,
    update_rules,
)


def _make_rules_tarball(manifest_content: str | None = None) -> bytes:
    """Build an in-memory tarball mimicking a rules release.

    Args:
        manifest_content: YAML string for manifest.yml. If None, no manifest is included.

    Returns:
        gzipped tar bytes ready for httpx mock.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Add a dummy rule file so the tarball isn't empty
        rule_data = b"rules:\n  - id: test\n    message: test\n"
        info = tarfile.TarInfo(name="core/test-rule.yml")
        info.size = len(rule_data)
        tar.addfile(info, io.BytesIO(rule_data))

        if manifest_content is not None:
            manifest_data = manifest_content.encode()
            info = tarfile.TarInfo(name="manifest.yml")
            info.size = len(manifest_data)
            tar.addfile(info, io.BytesIO(manifest_data))

    return buf.getvalue()


COMPATIBLE_MANIFEST = """\
schemas:
  rule: "0.1.0"
  levels: "0.1.0"
  agent: "0.1.0"
"""

INCOMPATIBLE_MANIFEST = """\
schemas:
  rule: "0.0.1"
  levels: "0.0.1"
  agent: "0.0.1"
"""


class TestDownloadRulesVersionStaging:
    """Verify staging-then-swap behavior of download_rules_version."""

    def _mock_http_response(self, tarball_bytes: bytes) -> MagicMock:
        """Create a mock httpx client that returns the given tarball bytes."""
        mock_response = MagicMock()
        mock_response.content = tarball_bytes
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        return mock_client

    def test_incompatible_rules_preserve_existing(self, tmp_path: Path):
        """When schema check fails, existing rules must remain untouched."""
        rules_path = tmp_path / "home" / ".reporails" / "rules"
        rules_path.mkdir(parents=True)

        # Plant an existing rule file as a sentinel
        sentinel = rules_path / "existing-rule.yml"
        sentinel.write_text("original content")

        # Plant an existing version file
        version_file = tmp_path / "home" / ".reporails" / "version"
        version_file.write_text("0.2.0")

        tarball = _make_rules_tarball(INCOMPATIBLE_MANIFEST)
        mock_client = self._mock_http_response(tarball)

        with (
            patch("reporails_cli.core.init.get_reporails_home", return_value=tmp_path / "home" / ".reporails"),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
            patch("reporails_cli.core.init.copy_bundled_yml_files", return_value=0),
            pytest.raises(IncompatibleSchemaError),
        ):
            download_rules_version("0.4.0")

        # Sentinel file must still exist with original content
        assert sentinel.exists(), "Existing rules were destroyed by failed update"
        assert sentinel.read_text() == "original content"

        # Version file must NOT be updated
        assert version_file.read_text() == "0.2.0"

    def test_compatible_rules_replace_existing(self, tmp_path: Path):
        """When schema check passes, existing rules are replaced."""
        reporails_home = tmp_path / "home" / ".reporails"
        rules_path = reporails_home / "rules"
        rules_path.mkdir(parents=True)

        # Plant a sentinel that should be removed after successful update
        sentinel = rules_path / "old-rule.yml"
        sentinel.write_text("old content")

        tarball = _make_rules_tarball(COMPATIBLE_MANIFEST)
        mock_client = self._mock_http_response(tarball)

        with (
            patch("reporails_cli.core.init.get_reporails_home", return_value=reporails_home),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
            patch("reporails_cli.core.init.copy_bundled_yml_files", return_value=0),
            patch("reporails_cli.core.init.write_version_file"),
        ):
            result_path, count = download_rules_version("0.3.0")

        # Old sentinel should be gone (rmtree'd), new rules present
        assert not (result_path / "old-rule.yml").exists()
        assert (result_path / "manifest.yml").exists()
        assert (result_path / "core" / "test-rule.yml").exists()
        assert count > 0

    def test_no_manifest_passes_compatibility(self, tmp_path: Path):
        """Pre-contract rules (no manifest.yml) should be accepted."""
        reporails_home = tmp_path / "home" / ".reporails"
        rules_path = reporails_home / "rules"
        rules_path.mkdir(parents=True)

        tarball = _make_rules_tarball(manifest_content=None)
        mock_client = self._mock_http_response(tarball)

        with (
            patch("reporails_cli.core.init.get_reporails_home", return_value=reporails_home),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
            patch("reporails_cli.core.init.copy_bundled_yml_files", return_value=0),
            patch("reporails_cli.core.init.write_version_file"),
        ):
            result_path, count = download_rules_version("0.1.0")

        assert result_path.exists()
        assert count > 0

    def test_fresh_install_incompatible_leaves_no_rules(self, tmp_path: Path):
        """On fresh install (no existing rules), incompatible download leaves rules_path absent."""
        reporails_home = tmp_path / "home" / ".reporails"
        reporails_home.mkdir(parents=True)
        rules_path = reporails_home / "rules"
        # rules_path does NOT exist yet

        tarball = _make_rules_tarball(INCOMPATIBLE_MANIFEST)
        mock_client = self._mock_http_response(tarball)

        with (
            patch("reporails_cli.core.init.get_reporails_home", return_value=reporails_home),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
            patch("reporails_cli.core.init.copy_bundled_yml_files", return_value=0),
            pytest.raises(IncompatibleSchemaError),
        ):
            download_rules_version("0.4.0")

        # rules_path should still not exist
        assert not rules_path.exists()


class TestUpdateRulesIncompatibleSchema:
    """Verify update_rules returns clean error on incompatible schemas."""

    def test_returns_not_updated_with_message(self, tmp_path: Path):
        """update_rules should catch IncompatibleSchemaError and return clean result."""
        reporails_home = tmp_path / "home" / ".reporails"
        rules_path = reporails_home / "rules"
        rules_path.mkdir(parents=True)

        # Plant existing version
        version_file = reporails_home / "version"
        version_file.write_text("0.2.0")

        tarball = _make_rules_tarball(INCOMPATIBLE_MANIFEST)
        mock_response = MagicMock()
        mock_response.content = tarball
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with (
            patch("reporails_cli.core.init.get_reporails_home", return_value=reporails_home),
            patch("reporails_cli.core.init.get_installed_version", return_value="0.2.0"),
            patch("reporails_cli.core.init.get_latest_version", return_value="0.4.0"),
            patch("reporails_cli.core.init.httpx.Client", return_value=mock_client),
            patch("reporails_cli.core.init.copy_bundled_yml_files", return_value=0),
        ):
            result = update_rules(force=True)

        assert result.updated is False
        assert "schema versions" in result.message.lower() or "incompatible" in result.message.lower() or "doesn't support" in result.message.lower()
        assert result.previous_version == "0.2.0"
