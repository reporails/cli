"""Pydantic DTOs for bundled lexicon data files.

Shape-validates the YAML under ``bundled/lexicon/`` at load time so a malformed
data file fails loudly at the read boundary rather than silently mis-driving the
mapper. The model IS the schema — the loader in ``core/mapper/lexicon.py`` calls
``model_validate`` on the parsed YAML.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CapabilityVocabulary(BaseModel):
    """Shape of ``bundled/lexicon/capabilities.yml`` — capability keyword vocabulary.

    ``input_forms`` maps a word a user may type for a kind of file to the agent
    config key it names; ``fold`` maps a display alias to the config keys it
    unions; ``virtual`` names capabilities the classifier synthesizes rather
    than any agent declaring. Shared by ``core/classify`` and the read-side
    ``platform/adapters`` query so the vocabulary has one source, not a mirror.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    input_forms: dict[str, str] = Field(default_factory=dict)
    fold: dict[str, list[str]] = Field(default_factory=dict)
    virtual: list[str] = Field(default_factory=list)


class DottedExclusions(BaseModel):
    """Shape of ``bundled/lexicon/dotted_exclusions.yml``.

    ``exclusions`` are English abbreviations that look like dotted code tokens
    (``e.g.``, ``i.e.``, ``a.m.``) but must not count as unformatted code in the
    specificity annotation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    exclusions: list[str] = Field(default_factory=list)


class MarkdownTokens(BaseModel):
    """Shape of ``bundled/lexicon/markdown_tokens.yml`` — parse-stage token maps.

    Maps markdown-it token-type names to the mapper's block/format vocabulary:
    ``block_types`` opens a nesting context, ``block_close`` names the closers,
    ``format_open``/``format_close`` carry inline emphasis markers.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    block_types: dict[str, str] = Field(default_factory=dict)
    block_close: list[str] = Field(default_factory=list)
    format_open: dict[str, list[str]] = Field(default_factory=dict)
    format_close: dict[str, str] = Field(default_factory=dict)
