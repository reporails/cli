"""File hashes used as cache keys."""

from __future__ import annotations

import hashlib
from pathlib import Path


def content_hash(text: str) -> str:
    """Compute SHA-256 hash of text with sha256: prefix."""
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def file_bytes_digest(path: Path) -> str:
    """SHA256 digest of a file's bytes, prefixed and truncated for cache keys."""
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()[:16]
