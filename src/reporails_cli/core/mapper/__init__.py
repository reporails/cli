"""Mapper — client-side instruction file analysis.

Classifies instruction files into atoms, embeds them, clusters by topic,
and produces a compact RulesetMap wire format.
"""

from reporails_cli.core.mapper.models import Models, get_models
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.pipeline import (
    content_hash,
    map_file,
    map_ruleset,
)
from reporails_cli.core.mapper.serialize import load_ruleset_map, save_ruleset_map
from reporails_cli.core.platform.dto.ruleset import (
    Atom,
    ClusterRecord,
    FileRecord,
    RulesetMap,
    RulesetSummary,
    TopicCluster,
)

__all__ = [
    "Atom",
    "ClusterRecord",
    "FileRecord",
    "Models",
    "RulesetMap",
    "RulesetSummary",
    "TopicCluster",
    "content_hash",
    "get_models",
    "load_ruleset_map",
    "map_file",
    "map_ruleset",
    "save_ruleset_map",
    "tokenize",
]
