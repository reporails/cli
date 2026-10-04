"""Mapper — client-side instruction file analysis.

Splits instruction files into atoms, classifies them and embeds each one,
producing a RulesetMap. The bundled models run on CPU.
"""

from reporails_cli.core.cache.map_cache import content_hash
from reporails_cli.core.mapper.models import Models, get_models
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.pipeline import (
    map_ruleset,
)
from reporails_cli.core.mapper.serialize import load_ruleset_map, save_ruleset_map
from reporails_cli.core.platform.dto.ruleset import (
    Atom,
    FileRecord,
    RulesetMap,
    RulesetSummary,
)

__all__ = [
    "Atom",
    "FileRecord",
    "Models",
    "RulesetMap",
    "RulesetSummary",
    "content_hash",
    "get_models",
    "load_ruleset_map",
    "map_ruleset",
    "save_ruleset_map",
    "tokenize",
]
