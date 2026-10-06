"""Owner of the stored credentials file: the one writer and the tier refresh."""

from __future__ import annotations

import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.platform.contract.errors import CredentialsUnreadableError

logger = logging.getLogger(__name__)


def credentials_path() -> Path:
    """The credentials file, resolved from the home directory at call time."""
    return Path.home() / ".reporails" / "credentials.yml"


def load_credentials_record(path: Path | None = None) -> dict[str, Any]:
    """The record in `path` (default: the user's file); `{}` when there is no file or it is not a mapping.

    Raises `CredentialsUnreadableError` when the file exists but cannot be read or parsed.
    """
    path = path or credentials_path()
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CredentialsUnreadableError(f"Could not read credentials file: {exc}") from exc
    return data if isinstance(data, dict) else {}


def read_credentials() -> dict[str, str]:
    """The stored credentials for display; `{}` when the file is absent or unreadable."""
    try:
        return load_credentials_record()
    except CredentialsUnreadableError as exc:
        logger.debug("Treating unreadable credentials as none: %s", exc)
    return {}


def env_api_key() -> str:
    """The `AILS_API_KEY` env override ("" when unset); it wins over the stored key."""
    return os.environ.get("AILS_API_KEY", "")


def identity_and_tier(creds: dict[str, str], api_key: str) -> tuple[bool, str]:
    """(stored identity matches the key in effect, stored tier for that key or "").

    The stored login and tier are only meaningful when the key in effect IS the
    locally cached one; an env-provided key may not match anything on disk.
    """
    known_identity = bool(creds.get("api_key")) and creds.get("api_key") == api_key
    return known_identity, creds.get("tier", "") if known_identity else ""


def effective_tier() -> str:
    """Stored tier for the API key in effect ("" when unknown or the key is not the stored one)."""
    creds = read_credentials()
    return identity_and_tier(creds, env_api_key() or creds.get("api_key", ""))[1]


def clear_credentials() -> None:
    """Remove the stored credentials file."""
    path = credentials_path()
    if path.exists():
        path.unlink()


def signed_in_recently(api_key: str, *, within_s: int = 120, now: datetime | None = None) -> bool:
    """True when the stored record holds `api_key` and its `signed_in_at` is within `within_s` seconds of now.

    `signed_in_at` is an ISO-8601 UTC string; an absent or unparseable value is False.
    """
    record = read_credentials()
    if not api_key or record.get("api_key") != api_key:
        return False
    try:
        signed_in = datetime.fromisoformat(str(record.get("signed_in_at", "")))
    except ValueError:
        return False
    if signed_in.tzinfo is None:
        signed_in = signed_in.replace(tzinfo=UTC)
    elapsed = ((now or datetime.now(UTC)) - signed_in).total_seconds()
    return 0 <= elapsed <= within_s


def _stored_key(path: Path) -> str:
    """The api_key currently in the file, or "" when absent or unreadable."""
    try:
        return str(load_credentials_record(path).get("api_key") or "")
    except CredentialsUnreadableError:
        return ""


def write_credentials_file(path: Path, record: dict[str, str], *, expect_key: str | None = None) -> bool:
    """Replace the credentials file in one step, owner-only from the first byte.

    The record goes to a temp file in the same directory and `os.replace` swaps
    it in, so a parallel reader sees the old or the new file, never an empty one.
    On POSIX the temp file is created by `os.open` at 0600 (no umask can widen
    it). On NTFS (no POSIX mode bits) that guarantee does not apply, so Windows
    keeps the filesystem default and only warns.

    With `expect_key`, the file is re-read just before the swap and left alone
    (returns False) when its api_key is no longer that key, so a concurrent
    sign-in is never overwritten with the old key.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = yaml.dump(record, default_flow_style=False)
    windows = sys.platform == "win32"
    if not windows:
        path.parent.chmod(0o700)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        if windows:
            tmp.write_text(data, encoding="utf-8")
        else:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                if sys.platform != "win32":  # no fchmod on Windows before Python 3.13
                    os.fchmod(fd, 0o600)
            except BaseException:
                os.close(fd)
                raise
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
        if expect_key is not None and _stored_key(path) != expect_key:
            logger.debug("Credentials changed during the write — left as they are")
            return False
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    if windows:
        logger.warning("File permissions not enforced on Windows — secure %s manually", path)
    return True


def refresh_stored_tier(api_key: str, tier: str, path: Path | None = None) -> None:
    """Rewrite the stored tier to the one a server reply named, when it differs.

    Acts only when `api_key` is the key stored in the file (an env override for a
    different key leaves it alone). Never raises: an unreadable or unwritable
    file is a debug log, never a failed check.
    """
    if not api_key or not tier:
        return
    target = path or credentials_path()
    try:
        data = load_credentials_record(target)
    except CredentialsUnreadableError as exc:
        logger.debug("Could not refresh the stored tier: %s", exc)
        return
    if data.get("api_key") != api_key or data.get("tier") == tier:
        return
    try:
        record = {str(k): str(v) for k, v in data.items()}
        record["tier"] = tier
        write_credentials_file(target, record, expect_key=api_key)
    except Exception as exc:
        logger.debug("Could not refresh the stored tier: %s", exc)
