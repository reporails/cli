"""Mapper — client-side instruction file analysis.

Classifies instruction files into atoms, embeds them, clusters by topic,
and produces a compact RulesetMap wire format.
"""

from reporails_cli.core.mapper.mapper import (
    Atom,
    ClusterRecord,
    FileRecord,
    Models,
    RulesetMap,
    RulesetSummary,
    TopicCluster,
    content_hash,
    get_models,
    load_ruleset_map,
    map_file,
    map_ruleset,
    save_ruleset_map,
    tokenize,
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
