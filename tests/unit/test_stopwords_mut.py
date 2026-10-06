"""Mutation-killing behavioral tests for `classify/stopwords.py`.

Targets survivors in `_match_close_paren` char-class handling (L57, L58),
`is_guard` (L165), `_try_decompose` (L178), `_analyze_check` (L200, L208),
and `write_vocab` output format (L279).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.stopwords import (
    _analyze_check,
    _try_decompose,
    decompose,
    is_guard,
    write_vocab,
)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_decompose_paren_inside_char_class() -> None:
    # Kills L57 (`in_cc = True`) and L58 (`and -> or`): a ')' inside a [...] char class
    # must NOT close the alternation group early.
    parts = decompose("(?:[a)]xy|def)")
    assert parts is not None
    assert parts.terms == ["[a)]xy", "def"]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_is_guard_startswith_guard() -> None:
    # Kills L165 `or -> and`: a pattern that STARTS WITH (but doesn't equal) a guard is a guard.
    assert is_guard(r"\A[\s\S]+foo") is True


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_try_decompose_rejects_guard_prefixed_group() -> None:
    # Kills L178 `or -> and`: a guard-prefixed pattern (even with an alternation group) is skipped.
    assert _try_decompose(r"\A[\s\S]+(foo|bar)", "pattern-regex") is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_analyze_check_content_absent_requires_mechanical() -> None:
    # Kills L200 `and -> or`: content_absent extraction only applies to mechanical checks.
    check = {"type": "other", "check": "content_absent", "args": {"pattern": "(foo|bar)"}}
    assert _analyze_check(check) == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_analyze_check_deterministic_without_patterns() -> None:
    # Kills L208 `and -> or`: a deterministic check with neither pattern-regex nor patterns yields [].
    check = {"type": "deterministic"}
    assert _analyze_check(check) == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_write_vocab_preserves_key_order(tmp_path: Path) -> None:
    # Kills L279 `sort_keys=False -> True`: insertion order is preserved, not alphabetized.
    vocab = {"zebra": ["a"], "alpha": ["b"]}
    out = write_vocab(tmp_path, vocab)
    content = out.read_text(encoding="utf-8")
    assert content.index("zebra") < content.index("alpha")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_write_vocab_uses_block_style(tmp_path: Path) -> None:
    # Kills L279 `default_flow_style=False -> True`: lists render in block style, not inline flow.
    vocab = {"key": ["a", "b"]}
    out = write_vocab(tmp_path, vocab)
    content = out.read_text(encoding="utf-8")
    assert "- a" in content
    assert "[a, b]" not in content
