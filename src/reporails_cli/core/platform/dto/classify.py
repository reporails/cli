"""Pure data shapes of rule word-list extraction and sync, link edges and unresolved skill names."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject


@dataclass(frozen=True)
class UnresolvedSkill:
    """A skill name declared by an agent that discovery could not resolve."""

    declared_in: Path
    skill_name: str
    agent: str


@dataclass(frozen=True)
class LinkEdge:
    """One `(source, target)` link emitted by `walk_markdown_links`."""

    target: Path
    source: Path
    source_type: str
    depth: int
    verb: str


@dataclass
class PatternParts:
    """Decomposed regex pattern: flags + prefix + group(terms) + suffix."""

    flags: str
    prefix: str
    group_open: str  # "(?:" or "("
    terms: list[str]
    suffix: str


@dataclass
class PatternInfo:
    """Info about one extractable pattern within a check."""

    target: str  # "pattern-regex", "pattern-not-regex", "args.pattern"
    terms: list[str]


@dataclass
class ExtractResult:
    """Result of extracting vocab from one rule directory."""

    rule_dir: Path
    vocab: JsonObject | None
    message: str
    problem: str = ""  # why the rule's checks.yml was skipped; empty when it was read


FieldStatus = Literal["changed", "unchanged", "no_target", "invalid"]
"""What a vocab field did to its check: rewrote a pattern, matched one, found no pattern, or cannot be used."""


@dataclass(frozen=True, slots=True)
class FieldOutcome:
    """The result of walking one vocab field against a check; nothing is written until the whole entry is read."""

    status: FieldStatus
    reasons: tuple[str, ...] = ()  # why an `invalid` field cannot be used, one message per fault
    write: tuple[JsonObject, str, str] | None = None  # (container, key, new pattern) of a `changed` field


@dataclass
class SyncResult:
    """Result of syncing vocab into checks.yml for one rule."""

    rule_dir: Path
    updated: int = 0
    skipped: int = 0
    messages: list[str] = field(default_factory=list)
