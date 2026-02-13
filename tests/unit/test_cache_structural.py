"""Unit tests for structural_hash and three-tier cache invalidation.

Tests cover:
- structural_hash determinism, sensitivity, and insensitivity
- Three-tier lookup: fresh, stale, invalidated
- V1→V2 migration (missing structural_hash field)
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.cache import ProjectCache, structural_hash

# ---------------------------------------------------------------------------
# structural_hash
# ---------------------------------------------------------------------------


class TestStructuralHash:
    def test_deterministic(self, tmp_path: Path) -> None:
        """Same content produces same structural hash."""
        f = tmp_path / "test.md"
        f.write_text("# Title\n- MUST do X\n- NEVER do Y\n")
        h1 = structural_hash(f)
        h2 = structural_hash(f)
        assert h1 == h2
        assert h1.startswith("struct:")
        assert len(h1) == len("struct:") + 16

    def test_heading_change_differs(self, tmp_path: Path) -> None:
        """Changing a heading produces a different structural hash."""
        f = tmp_path / "test.md"
        f.write_text("# Original Title\n\nSome body text.\n")
        h1 = structural_hash(f)
        f.write_text("# Changed Title\n\nSome body text.\n")
        h2 = structural_hash(f)
        assert h1 != h2

    def test_constraint_change_differs(self, tmp_path: Path) -> None:
        """Changing a constraint keyword line changes the hash."""
        f = tmp_path / "test.md"
        f.write_text("# Title\nYou MUST use Python\n")
        h1 = structural_hash(f)
        f.write_text("# Title\nYou MUST use Rust\n")
        h2 = structural_hash(f)
        assert h1 != h2

    def test_list_item_change_differs(self, tmp_path: Path) -> None:
        """Changing a list item changes the hash."""
        f = tmp_path / "test.md"
        f.write_text("# Title\n- First item\n- Second item\n")
        h1 = structural_hash(f)
        f.write_text("# Title\n- First item\n- Modified item\n")
        h2 = structural_hash(f)
        assert h1 != h2

    def test_whitespace_only_change_same(self, tmp_path: Path) -> None:
        """Adding blank lines between structural elements keeps the same hash."""
        f = tmp_path / "test.md"
        f.write_text("# Title\n- Item one\n- Item two\n")
        h1 = structural_hash(f)
        f.write_text("# Title\n\n\n- Item one\n\n- Item two\n\n\n")
        h2 = structural_hash(f)
        assert h1 == h2

    def test_body_prose_change_same(self, tmp_path: Path) -> None:
        """Changing non-structural prose (no headings/keywords/lists) keeps the same hash."""
        f = tmp_path / "test.md"
        f.write_text("# Title\n\nSome paragraph text here.\n\n- Item\n")
        h1 = structural_hash(f)
        f.write_text("# Title\n\nCompletely different paragraph.\n\n- Item\n")
        h2 = structural_hash(f)
        assert h1 == h2

    def test_empty_file(self, tmp_path: Path) -> None:
        """Empty file produces a valid hash."""
        f = tmp_path / "empty.md"
        f.write_text("")
        h = structural_hash(f)
        assert h.startswith("struct:")


# ---------------------------------------------------------------------------
# Three-tier cache lookup
# ---------------------------------------------------------------------------


class TestThreeTierLookup:
    def test_fresh_hit(self, tmp_path: Path) -> None:
        """Tier 1: content_hash matches → returns results."""
        cache = ProjectCache(tmp_path)
        cache.set_cached_judgment(
            "CLAUDE.md",
            "sha256:aaa",
            {"C6": {"verdict": "pass", "reason": "ok"}},
            structural_hash="struct:bbb",
        )
        result = cache.get_cached_judgment("CLAUDE.md", "sha256:aaa", structural_hash="struct:bbb")
        assert result is not None
        assert result["C6"]["verdict"] == "pass"

    def test_stale_hit(self, tmp_path: Path) -> None:
        """Tier 2: content_hash differs, structural_hash matches → stale but usable."""
        cache = ProjectCache(tmp_path)
        cache.set_cached_judgment(
            "CLAUDE.md",
            "sha256:old_content",
            {"C6": {"verdict": "pass", "reason": "ok"}},
            structural_hash="struct:same_structure",
        )
        # Content changed, but structure is the same
        result = cache.get_cached_judgment(
            "CLAUDE.md",
            "sha256:new_content",
            structural_hash="struct:same_structure",
        )
        assert result is not None
        assert result["C6"]["verdict"] == "pass"

    def test_invalidated(self, tmp_path: Path) -> None:
        """Tier 3: both hashes differ → cache invalidated."""
        cache = ProjectCache(tmp_path)
        cache.set_cached_judgment(
            "CLAUDE.md",
            "sha256:old_content",
            {"C6": {"verdict": "pass", "reason": "ok"}},
            structural_hash="struct:old_structure",
        )
        result = cache.get_cached_judgment(
            "CLAUDE.md",
            "sha256:new_content",
            structural_hash="struct:new_structure",
        )
        assert result is None

    def test_no_structural_hash_in_query(self, tmp_path: Path) -> None:
        """Without structural_hash in query, falls back to content-only matching."""
        cache = ProjectCache(tmp_path)
        cache.set_cached_judgment(
            "CLAUDE.md",
            "sha256:aaa",
            {"C6": {"verdict": "pass", "reason": "ok"}},
            structural_hash="struct:bbb",
        )
        # Content matches → still returns results
        result = cache.get_cached_judgment("CLAUDE.md", "sha256:aaa")
        assert result is not None

        # Content differs, no structural_hash to compare → invalidated
        result = cache.get_cached_judgment("CLAUDE.md", "sha256:different")
        assert result is None


# ---------------------------------------------------------------------------
# V1 → V2 migration (missing structural_hash field)
# ---------------------------------------------------------------------------


class TestV1Migration:
    def test_v1_cache_content_match_still_works(self, tmp_path: Path) -> None:
        """V1 cache entry (no structural_hash) still works with content_hash match."""
        cache = ProjectCache(tmp_path)
        # Simulate V1 entry: no structural_hash
        cache.set_cached_judgment(
            "CLAUDE.md",
            "sha256:v1hash",
            {"C6": {"verdict": "pass", "reason": "ok"}},
        )
        result = cache.get_cached_judgment("CLAUDE.md", "sha256:v1hash", structural_hash="struct:anything")
        assert result is not None

    def test_v1_cache_content_mismatch_invalidated(self, tmp_path: Path) -> None:
        """V1 cache entry with content mismatch → no structural_hash to fall back on → invalidated."""
        cache = ProjectCache(tmp_path)
        cache.set_cached_judgment(
            "CLAUDE.md",
            "sha256:v1hash",
            {"C6": {"verdict": "pass", "reason": "ok"}},
        )
        result = cache.get_cached_judgment("CLAUDE.md", "sha256:different", structural_hash="struct:anything")
        assert result is None
