"""File hashes used as cache keys."""

from __future__ import annotations

import hashlib
from pathlib import Path

from reporails_cli.core.platform.utils.file_read import read_file_bytes


def content_hash(text: str) -> str:
    """Compute SHA-256 hash of text with sha256: prefix."""
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def file_bytes_digest(path: Path) -> str:
    """SHA256 digest of a file's bytes, prefixed and truncated for cache keys."""
    return "sha256:" + hashlib.sha256(read_file_bytes(path)).hexdigest()[:16]
