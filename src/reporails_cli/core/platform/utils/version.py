"""The installed reporails-cli version, and a stamp of the installed code that moves when its files change."""

from __future__ import annotations

import functools
import hashlib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

UNKNOWN_VERSION = "unknown"


@functools.cache
def installed_version() -> str:
    """The installed package version, or ``"unknown"`` when no package metadata is present."""
    try:
        return version("reporails-cli")
    except PackageNotFoundError:
        return UNKNOWN_VERSION


def installed_code_stamp() -> str:
    """The installed version with a digest of the package's files: their names, sizes and modification times.

    An editable install changes files without changing the version, so the stamp is what tells a running
    process that the code on disk is no longer the code it started with. It reads every file of the package
    each call; a caller that asks often keeps the answer for a few seconds.
    """
    package = Path(__file__).resolve().parents[3]
    digest = hashlib.sha256()
    for path in sorted(package.rglob("*")):
        if "__pycache__" in path.parts or not path.is_file():
            continue
        info = path.stat()
        digest.update(f"{path.relative_to(package).as_posix()}\0{info.st_size}\0{info.st_mtime_ns}\n".encode())
    return f"{installed_version()}+{digest.hexdigest()[:16]}"
