"""Unit tests for in-memory check result cache."""

from __future__ import annotations

from reporails_cli.core.check_cache import CheckCache
from reporails_cli.core.mechanical.checks import CheckResult


class TestCheckCache:
    def test_miss_returns_none(self) -> None:
        cache = CheckCache()
        key = cache.key("mechanical", "file_exists", {"path": "x.md"}, "CLAUDE.md:0")
        assert cache.get(key) is None

    def test_hit_returns_result(self) -> None:
        cache = CheckCache()
        result = CheckResult(passed=True, message="found")
        key = cache.key("mechanical", "file_exists", {"path": "x.md"}, "CLAUDE.md:0")
        cache.set(key, result)
        assert cache.get(key) is result

    def test_different_args_different_keys(self) -> None:
        cache = CheckCache()
        k1 = cache.key("mechanical", "file_exists", {"path": "a.md"}, ".:0")
        k2 = cache.key("mechanical", "file_exists", {"path": "b.md"}, ".:0")
        assert k1 != k2

    def test_different_targets_different_keys(self) -> None:
        cache = CheckCache()
        k1 = cache.key("mechanical", "file_exists", None, "a.md:0")
        k2 = cache.key("mechanical", "file_exists", None, "b.md:0")
        assert k1 != k2

    def test_none_args(self) -> None:
        cache = CheckCache()
        k1 = cache.key("mechanical", "git_tracked", None, ".:0")
        k2 = cache.key("mechanical", "git_tracked", None, ".:0")
        assert k1 == k2

    def test_len(self) -> None:
        cache = CheckCache()
        assert len(cache) == 0
        result = CheckResult(passed=True, message="ok")
        cache.set(cache.key("mechanical", "a", None, ".:0"), result)
        cache.set(cache.key("mechanical", "b", None, ".:0"), result)
        assert len(cache) == 2

    def test_result_with_annotations(self) -> None:
        cache = CheckCache()
        result = CheckResult(passed=True, message="ok", annotations={"imports": ["x"]})
        key = cache.key("mechanical", "extract_imports", None, "CLAUDE.md:0")
        cache.set(key, result)
        cached = cache.get(key)
        assert cached is not None
        assert cached.annotations == {"imports": ["x"]}

    def test_arg_key_order_does_not_affect_cache_key(self) -> None:
        """sort_keys=True in json.dumps should make key order irrelevant."""
        cache = CheckCache()
        k1 = cache.key("mechanical", "check", {"a": 1, "b": 2}, ".:0")
        k2 = cache.key("mechanical", "check", {"b": 2, "a": 1}, ".:0")
        assert k1 == k2

    def test_overwrite_existing_entry(self) -> None:
        """Setting a key twice should overwrite the previous result."""
        cache = CheckCache()
        key = cache.key("mechanical", "file_exists", None, ".:0")
        first = CheckResult(passed=True, message="ok")
        second = CheckResult(passed=False, message="gone")
        cache.set(key, first)
        cache.set(key, second)
        assert cache.get(key) is second
        assert len(cache) == 1
