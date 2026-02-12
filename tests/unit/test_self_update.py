"""Unit tests for CLI self-upgrade module.

Tests install method detection, command construction, and upgrade flow.
All subprocess calls and metadata access are mocked.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from reporails_cli.core.self_update import (
    InstallMethod,
    _build_upgrade_command,
    _verify_installed_version,
    detect_install_method,
    upgrade_cli,
)

# ---------------------------------------------------------------------------
# InstallMethod enum
# ---------------------------------------------------------------------------


class TestInstallMethod:
    def test_values(self) -> None:
        assert InstallMethod.UV.value == "uv"
        assert InstallMethod.PIP.value == "pip"
        assert InstallMethod.PIPX.value == "pipx"
        assert InstallMethod.DEV.value == "dev"
        assert InstallMethod.UNKNOWN.value == "unknown"


# ---------------------------------------------------------------------------
# detect_install_method
# ---------------------------------------------------------------------------


class TestDetectInstallMethod:
    def test_dev_install_detected(self) -> None:
        """Editable installs should return DEV."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: (
            json.dumps({"dir_info": {"editable": True}}) if name == "direct_url.json" else None
        )
        with patch("reporails_cli.core.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.DEV

    def test_uv_installer(self) -> None:
        """INSTALLER=uv should return UV."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: {
            "direct_url.json": None,
            "INSTALLER": "uv\n",
        }.get(name)
        mock_dist.files = []
        with patch("reporails_cli.core.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.UV

    def test_pip_installer(self) -> None:
        """INSTALLER=pip should return PIP."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: {
            "direct_url.json": None,
            "INSTALLER": "pip\n",
        }.get(name)
        mock_dist.files = []
        with patch("reporails_cli.core.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.PIP

    def test_pipx_location(self) -> None:
        """Dist path containing 'pipx' should return PIPX."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: {
            "direct_url.json": None,
            "INSTALLER": "pip\n",
        }.get(name)
        mock_file = MagicMock()
        mock_file.__str__ = lambda self: "reporails_cli/__init__.py"
        mock_dist.files = [mock_file]
        mock_dist._path = (
            "/home/user/.local/pipx/venvs/reporails-cli/lib/python3.12/site-packages/reporails_cli-0.1.3.dist-info"
        )
        with patch("reporails_cli.core.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.PIPX

    def test_distribution_not_found(self) -> None:
        """Missing package should return UNKNOWN."""
        with patch("reporails_cli.core.self_update.distribution", side_effect=Exception("not found")):
            assert detect_install_method() == InstallMethod.UNKNOWN

    def test_no_installer_file_defaults_to_pip(self) -> None:
        """When INSTALLER is None, default to PIP."""
        mock_dist = MagicMock()
        mock_dist.read_text.return_value = None
        mock_dist.files = []
        with patch("reporails_cli.core.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.PIP

    def test_corrupt_direct_url_falls_through(self) -> None:
        """Corrupt direct_url.json should not crash, falls through to INSTALLER."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: {
            "direct_url.json": "not json",
            "INSTALLER": "uv\n",
        }.get(name)
        mock_dist.files = []
        with patch("reporails_cli.core.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.UV


# ---------------------------------------------------------------------------
# _build_upgrade_command
# ---------------------------------------------------------------------------


class TestBuildUpgradeCommand:
    def test_uv_latest(self) -> None:
        cmd = _build_upgrade_command(InstallMethod.UV, None)
        assert cmd[:2] == ["uv", "pip"]
        assert "--refresh-package" in cmd
        assert "reporails-cli" in cmd

    def test_uv_pinned(self) -> None:
        cmd = _build_upgrade_command(InstallMethod.UV, "1.0.0")
        assert "reporails-cli==1.0.0" in cmd

    def test_pip_latest(self) -> None:
        cmd = _build_upgrade_command(InstallMethod.PIP, None)
        assert "--no-cache-dir" in cmd
        assert "--upgrade" in cmd
        assert "reporails-cli" in cmd

    def test_pip_pinned(self) -> None:
        cmd = _build_upgrade_command(InstallMethod.PIP, "2.0.0")
        assert "reporails-cli==2.0.0" in cmd

    def test_pipx_latest(self) -> None:
        cmd = _build_upgrade_command(InstallMethod.PIPX, None)
        assert cmd == ["pipx", "upgrade", "reporails-cli"]

    def test_pipx_pinned(self) -> None:
        cmd = _build_upgrade_command(InstallMethod.PIPX, "1.5.0")
        assert cmd == ["pipx", "install", "--force", "reporails-cli==1.5.0"]


# ---------------------------------------------------------------------------
# _verify_installed_version
# ---------------------------------------------------------------------------


class TestVerifyInstalledVersion:
    def test_success(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1.2.3\n"
        with patch("reporails_cli.core.self_update.subprocess.run", return_value=mock_result):
            assert _verify_installed_version() == "1.2.3"

    def test_failure_returns_none(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        with patch("reporails_cli.core.self_update.subprocess.run", return_value=mock_result):
            assert _verify_installed_version() is None

    def test_exception_returns_none(self) -> None:
        with patch("reporails_cli.core.self_update.subprocess.run", side_effect=OSError("boom")):
            assert _verify_installed_version() is None


# ---------------------------------------------------------------------------
# upgrade_cli
# ---------------------------------------------------------------------------


class TestUpgradeCli:
    def test_dev_install_refuses(self) -> None:
        """Dev installs should return without running subprocess."""
        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.DEV),
            patch("reporails_cli.__version__", "0.1.0"),
        ):
            result = upgrade_cli()
        assert result.updated is False
        assert result.method == InstallMethod.DEV
        assert "uv sync" in result.message

    def test_unknown_method_refuses(self) -> None:
        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.UNKNOWN),
            patch("reporails_cli.__version__", "0.1.0"),
        ):
            result = upgrade_cli()
        assert result.updated is False
        assert result.method == InstallMethod.UNKNOWN
        assert "manually" in result.message

    def test_already_at_latest(self) -> None:
        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.PIP),
            patch("reporails_cli.__version__", "1.0.0"),
            patch("reporails_cli.core.update_check._fetch_latest_cli_version", return_value="1.0.0"),
            patch("reporails_cli.core.update_check._is_newer", return_value=False),
        ):
            result = upgrade_cli()
        assert result.updated is False
        assert "Already at" in result.message

    def test_pypi_unreachable(self) -> None:
        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.PIP),
            patch("reporails_cli.__version__", "0.1.0"),
            patch("reporails_cli.core.update_check._fetch_latest_cli_version", return_value=None),
        ):
            result = upgrade_cli()
        assert result.updated is False
        assert "PyPI" in result.message

    def test_successful_upgrade(self) -> None:
        mock_run = MagicMock()
        mock_run.returncode = 0
        mock_run.stdout = ""
        mock_run.stderr = ""

        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.UV),
            patch("reporails_cli.__version__", "0.1.0"),
            patch("reporails_cli.core.update_check._fetch_latest_cli_version", return_value="0.2.0"),
            patch("reporails_cli.core.update_check._is_newer", return_value=True),
            patch("reporails_cli.core.self_update.subprocess.run", return_value=mock_run),
            patch("reporails_cli.core.self_update._verify_installed_version", return_value="0.2.0"),
        ):
            result = upgrade_cli()
        assert result.updated is True
        assert result.new_version == "0.2.0"
        assert result.method == InstallMethod.UV

    def test_subprocess_failure(self) -> None:
        mock_run = MagicMock()
        mock_run.returncode = 1
        mock_run.stderr = "Permission denied"

        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.PIP),
            patch("reporails_cli.__version__", "0.1.0"),
            patch("reporails_cli.core.update_check._fetch_latest_cli_version", return_value="0.2.0"),
            patch("reporails_cli.core.update_check._is_newer", return_value=True),
            patch("reporails_cli.core.self_update.subprocess.run", return_value=mock_run),
        ):
            result = upgrade_cli()
        assert result.updated is False
        assert "Permission denied" in result.message

    def test_subprocess_timeout(self) -> None:
        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.PIP),
            patch("reporails_cli.__version__", "0.1.0"),
            patch("reporails_cli.core.update_check._fetch_latest_cli_version", return_value="0.2.0"),
            patch("reporails_cli.core.update_check._is_newer", return_value=True),
            patch(
                "reporails_cli.core.self_update.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=[], timeout=120),
            ),
        ):
            result = upgrade_cli()
        assert result.updated is False
        assert "timed out" in result.message

    def test_explicit_target_version(self) -> None:
        """When target_version is passed, skip PyPI fetch."""
        mock_run = MagicMock()
        mock_run.returncode = 0
        mock_run.stderr = ""

        with (
            patch("reporails_cli.core.self_update.detect_install_method", return_value=InstallMethod.UV),
            patch("reporails_cli.__version__", "0.1.0"),
            patch("reporails_cli.core.update_check._is_newer", return_value=True),
            patch("reporails_cli.core.self_update.subprocess.run", return_value=mock_run) as mock_sub,
            patch("reporails_cli.core.self_update._verify_installed_version", return_value="0.3.0"),
        ):
            result = upgrade_cli(target_version="0.3.0")
        assert result.updated is True
        assert result.new_version == "0.3.0"
        # Should have called subprocess with the version-pinned command
        call_args = mock_sub.call_args[0][0]
        assert "reporails-cli==0.3.0" in call_args


# ---------------------------------------------------------------------------
# format_update_message (updated to show --cli)
# ---------------------------------------------------------------------------


class TestFormatUpdateMessageCliFlag:
    """Verify the message now tells users to run `ails update --cli`."""

    def test_cli_update_shows_cli_flag(self) -> None:
        from reporails_cli.core.update_check import UpdateNotification, format_update_message

        n = UpdateNotification(cli_current="0.1.0", cli_latest="0.2.0")
        msg = format_update_message(n)
        assert "ails update --cli" in msg

    def test_rules_update_shows_plain_update(self) -> None:
        from reporails_cli.core.update_check import UpdateNotification, format_update_message

        n = UpdateNotification(rules_current="0.0.1", rules_latest="0.0.2")
        msg = format_update_message(n)
        assert "ails update" in msg
        assert "--cli" not in msg

    def test_both_updates_shows_both_commands(self) -> None:
        from reporails_cli.core.update_check import UpdateNotification, format_update_message

        n = UpdateNotification(
            cli_current="0.1.0",
            cli_latest="0.2.0",
            rules_current="0.0.1",
            rules_latest="0.0.2",
        )
        msg = format_update_message(n)
        assert "ails update --cli" in msg
        assert "ails update" in msg
