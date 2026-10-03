"""Mapper lexicon loader: bundled load, project override, shape validation."""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.lexicon import (
    load_dotted_exclusions,
    load_markdown_tokens,
)


class TestCapabilityVocabulary:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_bundled_vocabulary_loads(self):
        from reporails_cli.core.platform.config.vocabulary import load_capability_vocabulary

        vocab = load_capability_vocabulary()
        assert vocab.input_forms["skill"] == "skills"
        assert vocab.fold["memories"] == ["memory", "subagent_memory"]
        assert "referenced" in vocab.virtual

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_fold_source_is_shared_by_both_consumers(self):
        # The classifier resolver and the read-side query must agree on the fold
        # (this is the mirror the externalization removed).
        from reporails_cli.core.platform.config.vocabulary import load_capability_vocabulary

        fold = load_capability_vocabulary().fold
        assert fold.get("main") == ["main", "override"]


class TestParseStageLexicons:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_dotted_exclusions_loads(self):
        exclusions = load_dotted_exclusions().exclusions
        assert "e.g." in exclusions
        assert "i.e." in exclusions

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_markdown_tokens_loads(self):
        tokens = load_markdown_tokens()
        assert tokens.block_types["bullet_list_open"] == "bullet_list"
        assert "table_close" in tokens.block_close
        assert tokens.format_open["strong_open"] == ["**", "bold"]
        assert tokens.format_close["em_close"] == "*"
