"""Owner of the stored credentials file: the one writer and the tier refresh."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def credentials_path() -> Path:
    """The credentials file, resolved from the home directory at call time."""
    return Path.home() / ".reporails" / "credentials.yml"


def _stored_key(path: Path) -> str:
    """The api_key currently in the file, or "" when absent or unreadable."""
    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return ""
    return str(data.get("api_key") or "") if isinstance(data, dict) else ""


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
    try:
        target = path or credentials_path()
        if not target.exists():
            return
        data: Any = yaml.safe_load(target.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("api_key") != api_key or data.get("tier") == tier:
            return
        record = {str(k): str(v) for k, v in data.items()}
        record["tier"] = tier
        write_credentials_file(target, record, expect_key=api_key)
    except Exception as exc:
        logger.debug("Could not refresh the stored tier: %s", exc)
