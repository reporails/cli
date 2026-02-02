"""Update check unit tests.

Tests the 24-hour cached update check for CLI (PyPI) and framework (GitHub).
All network calls and filesystem access are mocked.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from reporails_cli.core.update_check import (
    UpdateNotification,
    _is_newer,
    check_for_updates,
    format_update_message,
)

# ---------------------------------------------------------------------------
# UpdateNotification
# ---------------------------------------------------------------------------


class TestUpdateNotification:
    def test_has_cli_update_when_versions_differ(self) -> None:
        n = UpdateNotification(cli_current="0.1.0", cli_latest="0.2.0")
        assert n.has_cli_update is True

    def test_no_cli_update_when_same(self) -> None:
        n = UpdateNotification(cli_current="0.1.0", cli_latest="0.1.0")
        assert n.has_cli_update is False

    def test_no_cli_update_when_none(self) -> None:
        n = UpdateNotification()
        assert n.has_cli_update is False

    def test_has_rules_update_when_versions_differ(self) -> None:
        n = UpdateNotification(rules_current="0.0.1", rules_latest="0.0.2")
        assert n.has_rules_update is True

    def test_no_rules_update_when_same(self) -> None:
        n = UpdateNotification(rules_current="0.0.1", rules_latest="0.0.1")
        assert n.has_rules_update is False

    def test_no_rules_update_when_none(self) -> None:
        n = UpdateNotification()
        assert n.has_rules_update is False


# ---------------------------------------------------------------------------
# _is_newer
# ---------------------------------------------------------------------------


class TestIsNewer:
    def test_newer_version(self) -> None:
        assert _is_newer("0.1.0", "0.2.0") is True

    def test_same_version(self) -> None:
        assert _is_newer("0.1.0", "0.1.0") is False

    def test_older_version(self) -> None:
        assert _is_newer("0.2.0", "0.1.0") is False

    def test_strips_v_prefix(self) -> None:
        assert _is_newer("v0.1.0", "v0.2.0") is True

    def test_mixed_v_prefix(self) -> None:
        assert _is_newer("0.1.0", "v0.2.0") is True

    def test_invalid_version_returns_false(self) -> None:
        assert _is_newer("not-a-version", "0.1.0") is False


# ---------------------------------------------------------------------------
# format_update_message
# ---------------------------------------------------------------------------


class TestFormatUpdateMessage:
    def test_cli_only(self) -> None:
        n = UpdateNotification(cli_current="0.1.0", cli_latest="0.2.0")
        msg = format_update_message(n)
        assert "CLI 0.1.0 → 0.2.0" in msg
        assert "ails update" in msg

    def test_rules_only(self) -> None:
        n = UpdateNotification(rules_current="0.0.1", rules_latest="0.0.2")
        msg = format_update_message(n)
        assert "framework 0.0.1 → 0.0.2" in msg

    def test_both_updates(self) -> None:
        n = UpdateNotification(
            cli_current="0.1.0",
            cli_latest="0.2.0",
            rules_current="0.0.1",
            rules_latest="0.0.2",
        )
        msg = format_update_message(n)
        assert "CLI 0.1.0 → 0.2.0" in msg
        assert "framework 0.0.1 → 0.0.2" in msg


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


class TestCacheReadWrite:
    """Test _read_cache and _write_cache via the public check_for_updates."""

    def test_fresh_cache_is_used(self, tmp_path: pytest.TempPathFactory) -> None:
        """A cache written < 24h ago should be read back without fetching."""
        from reporails_cli.core import update_check

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "update-check.json"
        cache_file.write_text(
            json.dumps(
                {
                    "last_checked": datetime.now(UTC).isoformat(),
                    "latest_cli_version": "99.0.0",
                    "latest_rules_version": "99.0.0",
                }
            )
        )

        with patch.object(update_check, "_get_cache_path", return_value=cache_file):
            from reporails_cli.core.update_check import _read_cache

            cached = _read_cache()

        assert cached is not None
        assert cached["latest_cli_version"] == "99.0.0"

    def test_expired_cache_returns_none(self, tmp_path: pytest.TempPathFactory) -> None:
        from reporails_cli.core import update_check

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "update-check.json"
        old_time = datetime.now(UTC) - timedelta(hours=25)
        cache_file.write_text(
            json.dumps(
                {
                    "last_checked": old_time.isoformat(),
                    "latest_cli_version": "99.0.0",
                    "latest_rules_version": "99.0.0",
                }
            )
        )

        with patch.object(update_check, "_get_cache_path", return_value=cache_file):
            from reporails_cli.core.update_check import _read_cache

            cached = _read_cache()

        assert cached is None

    def test_missing_cache_returns_none(self, tmp_path: pytest.TempPathFactory) -> None:
        from reporails_cli.core import update_check

        cache_file = tmp_path / "cache" / "update-check.json"

        with patch.object(update_check, "_get_cache_path", return_value=cache_file):
            from reporails_cli.core.update_check import _read_cache

            cached = _read_cache()

        assert cached is None

    def test_corrupt_cache_returns_none(self, tmp_path: pytest.TempPathFactory) -> None:
        from reporails_cli.core import update_check

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "update-check.json"
        cache_file.write_text("not json at all")

        with patch.object(update_check, "_get_cache_path", return_value=cache_file):
            from reporails_cli.core.update_check import _read_cache

            cached = _read_cache()

        assert cached is None


# ---------------------------------------------------------------------------
# _fetch_latest_cli_version
# ---------------------------------------------------------------------------


class TestFetchLatestCliVersion:
    def test_success(self) -> None:
        from reporails_cli.core.update_check import _fetch_latest_cli_version

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"info": {"version": "1.2.3"}}
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("reporails_cli.core.update_check.httpx.Client", return_value=mock_client):
            result = _fetch_latest_cli_version()

        assert result == "1.2.3"

    def test_network_error_returns_none(self) -> None:
        import httpx

        from reporails_cli.core.update_check import _fetch_latest_cli_version

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = httpx.ConnectError("connection refused")

        with patch("reporails_cli.core.update_check.httpx.Client", return_value=mock_client):
            result = _fetch_latest_cli_version()

        assert result is None


# ---------------------------------------------------------------------------
# check_for_updates (integration of all pieces)
# ---------------------------------------------------------------------------


class TestCheckForUpdates:
    def test_returns_notification_when_cli_outdated(self) -> None:
        with (
            patch(
                "reporails_cli.core.update_check._read_cache",
                return_value={
                    "latest_cli_version": "99.0.0",
                    "latest_rules_version": "0.0.1",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
        ):
            result = check_for_updates()

        assert result is not None
        assert result.has_cli_update is True
        assert result.cli_latest == "99.0.0"

    def test_returns_notification_when_rules_outdated(self) -> None:
        with (
            patch(
                "reporails_cli.core.update_check._read_cache",
                return_value={
                    "latest_cli_version": "0.1.0",
                    "latest_rules_version": "99.0.0",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
        ):
            result = check_for_updates()

        assert result is not None
        assert result.has_rules_update is True
        assert result.rules_latest == "99.0.0"

    def test_returns_none_when_current(self) -> None:
        with (
            patch(
                "reporails_cli.core.update_check._read_cache",
                return_value={
                    "latest_cli_version": "0.1.0",
                    "latest_rules_version": "0.0.1",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
        ):
            result = check_for_updates()

        assert result is None

    def test_fetches_when_cache_expired(self) -> None:
        with (
            patch("reporails_cli.core.update_check._read_cache", return_value=None),
            patch(
                "reporails_cli.core.update_check._fetch_latest_cli_version",
                return_value="99.0.0",
            ),
            patch(
                "reporails_cli.core.init.get_latest_version",
                return_value="99.0.0",
            ),
            patch("reporails_cli.core.update_check._write_cache") as mock_write,
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
        ):
            result = check_for_updates()

        assert result is not None
        assert result.has_cli_update is True
        assert result.has_rules_update is True
        mock_write.assert_called_once_with("99.0.0", "99.0.0")

    def test_returns_none_on_exception(self) -> None:
        with patch(
            "reporails_cli.core.update_check._read_cache",
            side_effect=RuntimeError("boom"),
        ):
            result = check_for_updates()

        assert result is None

    def test_returns_none_when_no_installed_rules(self) -> None:
        """If rules aren't installed yet, no rules update should be reported."""
        with (
            patch(
                "reporails_cli.core.update_check._read_cache",
                return_value={
                    "latest_cli_version": "0.1.0",
                    "latest_rules_version": "99.0.0",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value=None,
            ),
        ):
            result = check_for_updates()

        assert result is None
