"""The shipped hidden-character and secret-file patterns finish inside the search timeout on large input."""

from __future__ import annotations

from pathlib import Path

import pytest
import regex as re
import yaml

from reporails_cli.core.lint.regex.matching import safe_search

_RULES = Path(__file__).resolve().parents[2] / "framework" / "rules" / "core"
_PROSE = "Plain prose line with `code`, a link (https://example.com/a) and a number 42.\n"


def _pattern(slug: str) -> re.Pattern[str]:
    doc = yaml.safe_load((_RULES / slug / "checks.yml").read_text(encoding="utf-8"))
    return re.compile(next(c["pattern-regex"] for c in doc["checks"] if "pattern-regex" in c))


class TestShippedPatternTime:
    """GUARD: both patterns timed out under load on large files and were reported not evaluated."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_hidden_unicode_scans_800kb_inside_timeout(self) -> None:
        # safe_search raises PatternTimeoutError past REGEX_TIMEOUT_S
        assert safe_search(_pattern("no-hidden-unicode"), _PROSE * 10000) is None

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        "content",
        [
            _PROSE * 10000,
            "Chrome " * 8000 + "\n",
            "curl https://a.b " * 3000 + "\n",
        ],
        ids=["prose-800kb", "long-browser-line", "long-curl-line"],
    )
    def test_secret_file_exfiltration_inside_timeout(self, content: str) -> None:
        assert safe_search(_pattern("no-secret-file-exfiltration"), content) is None
