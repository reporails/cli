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


def write_credentials_file(path: Path, record: dict[str, str]) -> None:
    """Store credentials owner-only from the first byte.

    On NTFS (no POSIX mode bits) the guarantee does not apply, so Windows keeps
    the filesystem default and only warns. On POSIX, `os.open` with an explicit
    0600 mode creates the file without group/other bits, so no umask can widen
    it; `fchmod` then forces 0600 on a file that already existed at a wider mode.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = yaml.dump(record, default_flow_style=False)
    if sys.platform == "win32":
        path.write_text(data, encoding="utf-8")
        logger.warning("File permissions not enforced on Windows — secure %s manually", path)
        return
    path.parent.chmod(0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)


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
        write_credentials_file(target, record)
    except Exception as exc:
        logger.debug("Could not refresh the stored tier: %s", exc)
