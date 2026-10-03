"""File-property matching predicates.

Pure predicates that filter classified files by a rule's `FileMatch` criteria.
`None` fields on the match are wildcards. Shared by the classifier's
match-resolution and by the lint runners that target rules to files.
"""

from __future__ import annotations

from reporails_cli.core.platform.dto.models import ClassifiedFile, FileMatch


def _prop_matches(match_val: list[str] | str | None, actual: list[str] | str | None) -> bool:
    """Check a property match criterion against an actual property value.

    Both sides can be scalar or list:
    - match=None: wildcard (always matches)
    - match=str vs actual=str: exact equality
    - match=str vs actual=list: match_val in actual (file has the property)
    - match=list vs actual=str: actual in match_val (rule accepts the value)
    - match=list vs actual=list: sets intersect (any overlap)
    """
    if match_val is None:
        return True
    if actual is None:
        return False
    if isinstance(match_val, list) and isinstance(actual, list):
        return bool(set(match_val) & set(actual))
    if isinstance(match_val, list):
        return actual in match_val
    if isinstance(actual, list):
        return match_val in actual
    return actual == match_val


# FileMatch properties compared by file_matches(), single-sourced so the
# serializer (interfaces/cli/check_support._serialize_match) cannot drift from
# what matching actually compares. `type` is compared separately, first.
MATCH_PROPERTIES: tuple[str, ...] = (
    "scope",
    "format",
    "content_format",
    "cardinality",
    "lifecycle",
    "maintainer",
    "vcs",
    "loading",
    "precedence",
    "loading_verb",
    "link_source_type",
)


def is_wildcard_match(match: FileMatch) -> bool:
    """True when `match` names no criterion at all (`match: {}` — targets every file).

    A match that names ANY criterion — `{type: config}`, `{format: freeform}`,
    `{cardinality: hierarchical}` — is a targeting statement, so a consumer that
    finds no file satisfying it must run the rule on nothing rather than fall
    back to every file. Only a fully-wildcard match may fall back.
    """
    return match.type is None and all(getattr(match, prop) is None for prop in MATCH_PROPERTIES)


def file_matches(cf: ClassifiedFile, match: FileMatch) -> bool:
    """Check if a classified file matches the given criteria."""
    if not _prop_matches(match.type, cf.file_type):
        return False
    return all(_prop_matches(getattr(match, prop), cf.properties.get(prop)) for prop in MATCH_PROPERTIES)


def match_files(
    classified: list[ClassifiedFile],
    match: FileMatch,
) -> list[ClassifiedFile]:
    """Filter classified files by property match. None properties are wildcards.

    Args:
        classified: Previously classified files
        match: Match criteria (None fields match everything)

    Returns:
        Filtered list of ClassifiedFile
    """
    return [cf for cf in classified if file_matches(cf, match)]
