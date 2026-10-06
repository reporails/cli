"""Loader for the mapper's bundled lexicon data files.

Reads ``bundled/lexicon/*.yml`` via the cached ``load_yaml_file`` helper and
shape-validates it against a Pydantic DTO. A project may extend a bundled
lexicon with a file of the same name under ``.ails/lexicon/`` — its entries
union onto the bundled base, mirroring the list-field layering in
``platform/config/config.py``.
"""

from __future__ import annotations

from functools import lru_cache

from reporails_cli.bundled import get_lexicon_path
from reporails_cli.core.platform.dto.lexicon import (
    DottedExclusions,
    MarkdownTokens,
)
from reporails_cli.core.platform.utils.utils import load_yaml_file

_DOTTED_EXCLUSIONS_FILE = "dotted_exclusions.yml"
_MARKDOWN_TOKENS_FILE = "markdown_tokens.yml"


@lru_cache(maxsize=1)
def load_dotted_exclusions() -> DottedExclusions:
    """The bundled dotted-abbreviation exclusions, read and validated once per process."""
    return DottedExclusions.model_validate(load_yaml_file(get_lexicon_path() / _DOTTED_EXCLUSIONS_FILE))


@lru_cache(maxsize=1)
def load_markdown_tokens() -> MarkdownTokens:
    """The bundled parse-stage markdown token maps, read and validated once per process."""
    return MarkdownTokens.model_validate(load_yaml_file(get_lexicon_path() / _MARKDOWN_TOKENS_FILE))
