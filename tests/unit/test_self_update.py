"""Unit tests for install-method detection (used by `ails version`).

All metadata access is mocked.
"""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError
from unittest.mock import MagicMock, patch

import pytest

from reporails_cli.core.install.self_update import (
    InstallMethod,
    detect_install_method,
)

# ---------------------------------------------------------------------------
# detect_install_method
# ---------------------------------------------------------------------------


class TestDetectInstallMethod:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_dev_install_detected(self) -> None:
        """Editable installs should return DEV."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: (
            json.dumps({"dir_info": {"editable": True}}) if name == "direct_url.json" else None
        )
        with patch("reporails_cli.core.install.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.DEV

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_uv_installer(self) -> None:
        """INSTALLER=uv should return UV."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: {
            "direct_url.json": None,
            "INSTALLER": "uv\n",
        }.get(name)
        mock_dist.files = []
        with patch("reporails_cli.core.install.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.UV

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_pip_installer(self) -> None:
        """INSTALLER=pip should return PIP."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: {
            "direct_url.json": None,
            "INSTALLER": "pip\n",
        }.get(name)
        mock_dist.files = []
        with patch("reporails_cli.core.install.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.PIP

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
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
        with patch("reporails_cli.core.install.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.PIPX

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_distribution_not_found(self) -> None:
        """Missing package should return UNKNOWN."""
        with patch(
            "reporails_cli.core.install.self_update.distribution", side_effect=PackageNotFoundError("reporails-cli")
        ):
            assert detect_install_method() == InstallMethod.UNKNOWN

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_installer_file_defaults_to_pip(self) -> None:
        """When INSTALLER is None, default to PIP."""
        mock_dist = MagicMock()
        mock_dist.read_text.return_value = None
        mock_dist.files = []
        with patch("reporails_cli.core.install.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.PIP

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_corrupt_direct_url_falls_through(self) -> None:
        """Corrupt direct_url.json should not crash, falls through to INSTALLER."""
        mock_dist = MagicMock()
        mock_dist.read_text.side_effect = lambda name: {
            "direct_url.json": "not json",
            "INSTALLER": "uv\n",
        }.get(name)
        mock_dist.files = []
        with patch("reporails_cli.core.install.self_update.distribution", return_value=mock_dist):
            assert detect_install_method() == InstallMethod.UV
