"""Update check unit tests.

Tests the 24-hour cached update check for CLI (PyPI), framework (GitHub),
and recommended (GitHub). All network calls and filesystem access are mocked.
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
    prompt_for_updates,
)

# ---------------------------------------------------------------------------
# UpdateNotification
# ---------------------------------------------------------------------------


class TestUpdateNotification:
    @pytest.mark.parametrize("current,latest,expected", [
        ("0.1.0", "0.2.0", True),
        ("0.1.0", "0.1.0", False),
        (None, None, False),
    ])
    def test_has_cli_update(self, current: str | None, latest: str | None, expected: bool) -> None:
        n = UpdateNotification(cli_current=current, cli_latest=latest)
        assert n.has_cli_update is expected

    @pytest.mark.parametrize("current,latest,expected", [
        ("0.0.1", "0.0.2", True),
        ("0.0.1", "0.0.1", False),
        (None, None, False),
    ])
    def test_has_rules_update(self, current: str | None, latest: str | None, expected: bool) -> None:
        n = UpdateNotification(rules_current=current, rules_latest=latest)
        assert n.has_rules_update is expected

    @pytest.mark.parametrize("current,latest,expected", [
        ("0.1.0", "0.2.0", True),
        ("0.1.0", "0.1.0", False),
        (None, None, False),
        ("0.1.0", None, False),
        (None, "0.2.0", False),
    ])
    def test_has_recommended_update(self, current: str | None, latest: str | None, expected: bool) -> None:
        n = UpdateNotification(recommended_current=current, recommended_latest=latest)
        assert n.has_recommended_update is expected

    def test_has_any_update_true_for_cli(self) -> None:
        n = UpdateNotification(cli_current="0.1.0", cli_latest="0.2.0")
        assert n.has_any_update is True

    def test_has_any_update_true_for_recommended(self) -> None:
        n = UpdateNotification(recommended_current="0.1.0", recommended_latest="0.2.0")
        assert n.has_any_update is True

    def test_has_any_update_false_when_all_none(self) -> None:
        n = UpdateNotification()
        assert n.has_any_update is False


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

    def test_recommended_only(self) -> None:
        n = UpdateNotification(recommended_current="0.1.0", recommended_latest="0.2.0")
        msg = format_update_message(n)
        assert "recommended 0.1.0 → 0.2.0" in msg
        assert "ails update" in msg

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

    def test_all_three_updates(self) -> None:
        n = UpdateNotification(
            cli_current="0.1.0",
            cli_latest="0.2.0",
            rules_current="0.0.1",
            rules_latest="0.0.2",
            recommended_current="0.1.0",
            recommended_latest="0.2.0",
        )
        msg = format_update_message(n)
        assert "CLI 0.1.0 → 0.2.0" in msg
        assert "framework 0.0.1 → 0.0.2" in msg
        assert "recommended 0.1.0 → 0.2.0" in msg


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
                    "latest_recommended_version": "99.0.0",
                }
            )
        )

        with patch.object(update_check, "_get_cache_path", return_value=cache_file):
            from reporails_cli.core.update_check import _read_cache

            cached = _read_cache()

        assert cached is not None
        assert cached["latest_cli_version"] == "99.0.0"
        assert cached["latest_recommended_version"] == "99.0.0"

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
                    "latest_recommended_version": "99.0.0",
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

    def test_cache_without_recommended_still_works(self, tmp_path: pytest.TempPathFactory) -> None:
        """Old cache format without recommended field should still parse."""
        from reporails_cli.core import update_check

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache_file = cache_dir / "update-check.json"
        cache_file.write_text(
            json.dumps(
                {
                    "last_checked": datetime.now(UTC).isoformat(),
                    "latest_cli_version": "1.0.0",
                    "latest_rules_version": "1.0.0",
                }
            )
        )

        with patch.object(update_check, "_get_cache_path", return_value=cache_file):
            from reporails_cli.core.update_check import _read_cache

            cached = _read_cache()

        assert cached is not None
        assert cached.get("latest_recommended_version") is None


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
                    "latest_recommended_version": "0.1.0",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
            patch(
                "reporails_cli.core.bootstrap.get_installed_recommended_version",
                return_value="0.1.0",
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
                    "latest_recommended_version": "0.1.0",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
            patch(
                "reporails_cli.core.bootstrap.get_installed_recommended_version",
                return_value="0.1.0",
            ),
        ):
            result = check_for_updates()

        assert result is not None
        assert result.has_rules_update is True
        assert result.rules_latest == "99.0.0"

    def test_returns_notification_when_recommended_outdated(self) -> None:
        with (
            patch(
                "reporails_cli.core.update_check._read_cache",
                return_value={
                    "latest_cli_version": "0.1.0",
                    "latest_rules_version": "0.0.1",
                    "latest_recommended_version": "99.0.0",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
            patch(
                "reporails_cli.core.bootstrap.get_installed_recommended_version",
                return_value="0.1.0",
            ),
        ):
            result = check_for_updates()

        assert result is not None
        assert result.has_recommended_update is True
        assert result.recommended_latest == "99.0.0"

    def test_returns_none_when_current(self) -> None:
        with (
            patch(
                "reporails_cli.core.update_check._read_cache",
                return_value={
                    "latest_cli_version": "0.1.0",
                    "latest_rules_version": "0.0.1",
                    "latest_recommended_version": "0.1.0",
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
            patch(
                "reporails_cli.core.bootstrap.get_installed_recommended_version",
                return_value="0.1.0",
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
            patch(
                "reporails_cli.core.init.get_latest_recommended_version",
                return_value="99.0.0",
            ),
            patch("reporails_cli.core.update_check._write_cache") as mock_write,
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.0.1",
            ),
            patch(
                "reporails_cli.core.bootstrap.get_installed_recommended_version",
                return_value="0.1.0",
            ),
        ):
            result = check_for_updates()

        assert result is not None
        assert result.has_cli_update is True
        assert result.has_rules_update is True
        mock_write.assert_called_once_with("99.0.0", "99.0.0", "99.0.0")

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
                    "latest_recommended_version": None,
                },
            ),
            patch("reporails_cli.__version__", "0.1.0"),
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value=None,
            ),
            patch(
                "reporails_cli.core.bootstrap.get_installed_recommended_version",
                return_value=None,
            ),
        ):
            result = check_for_updates()

        assert result is None


# ---------------------------------------------------------------------------
# prompt_for_updates
# ---------------------------------------------------------------------------


class TestPromptForUpdates:
    def test_skip_on_flag(self) -> None:
        mock_console = MagicMock()
        result = prompt_for_updates(mock_console, no_update_check=True)
        assert result is False
        mock_console.print.assert_not_called()

    def test_skip_on_config(self) -> None:
        mock_console = MagicMock()
        with (
            patch("reporails_cli.core.update_check.sys.stdout") as mock_stdout,
            patch(
                "reporails_cli.core.bootstrap.get_global_config",
                return_value=MagicMock(auto_update_check=False),
            ),
        ):
            mock_stdout.isatty.return_value = True
            result = prompt_for_updates(mock_console)
        assert result is False

    def test_skip_on_no_updates(self) -> None:
        mock_console = MagicMock()
        with (
            patch("reporails_cli.core.update_check.sys.stdout") as mock_stdout,
            patch(
                "reporails_cli.core.bootstrap.get_global_config",
                return_value=MagicMock(auto_update_check=True),
            ),
            patch("reporails_cli.core.update_check.check_for_updates", return_value=None),
        ):
            mock_stdout.isatty.return_value = True
            result = prompt_for_updates(mock_console)
        assert result is False

    def test_skip_on_non_tty(self) -> None:
        mock_console = MagicMock()
        with (
            patch("reporails_cli.core.update_check.sys.stdout") as mock_stdout,
            patch(
                "reporails_cli.core.bootstrap.get_global_config",
                return_value=MagicMock(auto_update_check=True),
            ),
        ):
            mock_stdout.isatty.return_value = False
            result = prompt_for_updates(mock_console)
        assert result is False

    def test_user_accepts(self) -> None:
        mock_console = MagicMock()
        mock_console.input.return_value = ""  # default = yes

        notification = UpdateNotification(
            rules_current="0.0.1",
            rules_latest="0.0.2",
        )

        mock_update_result = MagicMock(updated=True, previous_version="0.0.1", new_version="0.0.2")

        with (
            patch("reporails_cli.core.update_check.sys.stdout") as mock_stdout,
            patch(
                "reporails_cli.core.bootstrap.get_global_config",
                return_value=MagicMock(auto_update_check=True),
            ),
            patch("reporails_cli.core.update_check.check_for_updates", return_value=notification),
            patch("reporails_cli.core.init.update_rules", return_value=mock_update_result),
        ):
            mock_stdout.isatty.return_value = True
            result = prompt_for_updates(mock_console)

        assert result is True

    def test_user_declines(self) -> None:
        mock_console = MagicMock()
        mock_console.input.return_value = "n"

        notification = UpdateNotification(
            rules_current="0.0.1",
            rules_latest="0.0.2",
        )

        with (
            patch("reporails_cli.core.update_check.sys.stdout") as mock_stdout,
            patch(
                "reporails_cli.core.bootstrap.get_global_config",
                return_value=MagicMock(auto_update_check=True),
            ),
            patch("reporails_cli.core.update_check.check_for_updates", return_value=notification),
        ):
            mock_stdout.isatty.return_value = True
            result = prompt_for_updates(mock_console)

        assert result is False

    def test_eof_treated_as_no(self) -> None:
        mock_console = MagicMock()
        mock_console.input.side_effect = EOFError

        notification = UpdateNotification(
            rules_current="0.0.1",
            rules_latest="0.0.2",
        )

        with (
            patch("reporails_cli.core.update_check.sys.stdout") as mock_stdout,
            patch(
                "reporails_cli.core.bootstrap.get_global_config",
                return_value=MagicMock(auto_update_check=True),
            ),
            patch("reporails_cli.core.update_check.check_for_updates", return_value=notification),
        ):
            mock_stdout.isatty.return_value = True
            result = prompt_for_updates(mock_console)

        assert result is False

    def test_cli_only_update_no_install_prompt(self) -> None:
        """CLI-only updates are shown but not auto-installed."""
        mock_console = MagicMock()

        notification = UpdateNotification(
            cli_current="0.1.0",
            cli_latest="0.2.0",
        )

        with (
            patch("reporails_cli.core.update_check.sys.stdout") as mock_stdout,
            patch(
                "reporails_cli.core.bootstrap.get_global_config",
                return_value=MagicMock(auto_update_check=True),
            ),
            patch("reporails_cli.core.update_check.check_for_updates", return_value=notification),
        ):
            mock_stdout.isatty.return_value = True
            result = prompt_for_updates(mock_console)

        assert result is False
        # Should not prompt for input since only CLI update (not auto-installable)
        mock_console.input.assert_not_called()
