"""Stopwords sync — compile vocab.yml terms into checks.yml patterns."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import regex
import yaml

from reporails_cli.core.classify.stopwords import PatternParts, decompose, is_guard, recompose
from reporails_cli.core.platform.adapters.registry import RuleReadError, read_checks_document
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    JsonValue,
    as_list,
    as_str,
    str_list,
)
from reporails_cli.core.platform.contract.rule_pattern import compile_rule_pattern
from reporails_cli.core.platform.dto.models import REGEX_PATTERN_FIELDS
from reporails_cli.core.platform.utils.utils import fast_yaml_load, non_text_items, unreadable_file_problem


def _find_check_by_suffix(
    checks: list[JsonValue],
    suffix: str,
) -> JsonObject | None:
    """Find a check whose ID ends with the given suffix."""
    for check in checks:
        if not isinstance(check, dict):
            continue
        cid = as_str(check.get("id", ""))
        check_suffix = cid.rsplit(".", 1)[-1] if "." in cid else cid
        if check_suffix == suffix:
            return check
    return None


FieldStatus = Literal["changed", "unchanged", "no_target", "invalid"]
"""What a vocab field did to its check: rewrote a pattern, matched one, found no pattern, or cannot be used."""


@dataclass(frozen=True, slots=True)
class _FieldOutcome:
    """The result of walking one vocab field against a check; nothing is written until the whole entry is read."""

    status: FieldStatus
    reasons: tuple[str, ...] = ()  # why an `invalid` field cannot be used, one message per fault
    write: tuple[JsonObject, str, str] | None = None  # (container, key, new pattern) of a `changed` field


def _invalid(*reasons: str) -> _FieldOutcome:
    return _FieldOutcome("invalid", reasons=reasons)


def _pattern_slots(container: JsonObject, keys: tuple[str, ...]) -> list[tuple[JsonObject, str]]:
    """The non-guard, non-empty pattern fields of `container` named in `keys`."""
    return [(container, key) for key in keys if as_str(container.get(key)) and not is_guard(as_str(container[key]))]


def _args_slot(check: JsonObject) -> list[tuple[JsonObject, str]]:
    args = check.get("args")
    return _pattern_slots(args, ("pattern",)) if isinstance(args, dict) else []


def _slots_for_list(check: JsonObject) -> list[tuple[JsonObject, str]]:
    """Every pattern a plain list of terms could replace in `check`, in order of preference."""
    ctype = as_str(check.get("type", ""))
    if ctype == "mechanical" and check.get("check") == "content_absent":
        return _args_slot(check)
    if ctype != "deterministic":
        return []
    if "pattern-regex" in check and "patterns" not in check:
        return _pattern_slots(check, ("pattern-regex",))
    slots: list[tuple[JsonObject, str]] = []
    for entry in as_list(check.get("patterns")):
        if isinstance(entry, dict):
            slots.extend(_pattern_slots(entry, REGEX_PATTERN_FIELDS))
    return slots


def _slots_for_field(check: JsonObject, target: str) -> list[tuple[JsonObject, str]]:
    """The pattern the vocab field `target` names in `check`."""
    if target == "args.pattern" and as_str(check.get("type", "")) == "mechanical":
        return _args_slot(check)
    if target == "pattern-regex" and "pattern-regex" in check and "patterns" not in check:
        return _pattern_slots(check, ("pattern-regex",))
    for entry in as_list(check.get("patterns")):
        if isinstance(entry, dict) and target in entry and not is_guard(as_str(entry[target])):
            return _pattern_slots(entry, (target,))
    return []


def _unusable_terms(value: JsonValue) -> tuple[str, ...]:
    """Why `value` cannot be a vocab term list; empty when it can."""
    if value is None:
        return ("is empty; give it a list of terms",)
    if isinstance(value, dict):
        return ("holds a mapping, not a list of terms",)
    if not isinstance(value, list):
        return ("holds a single value, not a list of terms",)
    if not value:
        return ("is empty; give it a list of terms",)
    if len(value) == 1:
        return ("holds one term; a term list needs two or more terms",)
    blanks = tuple(
        f"item {position} is blank text; remove it"
        for position, item in enumerate(value, start=1)
        if isinstance(item, str) and not item.strip()
    )
    return (*(reading for _, reading in non_text_items(value)), *blanks)


def _rewrite(container: JsonObject, key: str, parts: PatternParts, terms: list[str]) -> _FieldOutcome:
    """The outcome of putting `terms` into the pattern at `container[key]`: unchanged, a write, or invalid."""
    new = recompose(parts, terms)
    if new == container[key]:
        return _FieldOutcome("unchanged")
    try:
        compile_rule_pattern(new)
    except regex.error as exc:
        return _invalid(f"the pattern {new!r} does not compile ({exc})")
    read_back = decompose(new)
    if read_back is None or read_back.terms != terms:
        return _invalid(f"the pattern {new!r} does not read back as the term list")
    return _FieldOutcome("changed", write=(container, key, new))


def _walk_field(check: JsonObject, field_name: str, value: JsonValue) -> _FieldOutcome:
    """Read one vocab field (`field_name` is empty for a plain list) against `check`; writes nothing."""
    reasons = _unusable_terms(value)
    if reasons:
        return _invalid(*reasons)
    terms = str_list(value)
    slots = _slots_for_field(check, field_name) if field_name else _slots_for_list(check)
    if not slots:
        return _FieldOutcome("no_target")
    decomposed = [(slot, decompose(as_str(slot[0][slot[1]]))) for slot in slots]
    for (container, key), parts in decomposed:
        if parts is not None:
            return _rewrite(container, key, parts, terms)
    return _invalid(
        *(
            f"the pattern {as_str(container[key])!r} is not an alternation of terms; it cannot take terms"
            for container, key in slots
        )
    )


def _walk_entry(check: JsonObject, value: JsonValue) -> list[tuple[str, _FieldOutcome]]:
    """Walk one vocab entry: a `(field name, outcome)` per field (name empty for a plain list)."""
    if isinstance(value, dict):
        if not value:
            return [("", _invalid("names no field; give it a list of terms"))]
        return [(name, _walk_field(check, name, terms)) for name, terms in value.items()]
    return [("", _walk_field(check, "", value))]


def _entry_messages(suffix: str, outcomes: list[tuple[str, _FieldOutcome]]) -> list[str]:
    """The warnings one entry's outcomes call for; a field that is `changed` or `unchanged` says nothing."""
    messages: list[str] = []
    for name, outcome in outcomes:
        label = f"'{suffix}'" + (f" {name}" if name else "")
        if outcome.status == "invalid":
            messages.extend(f"{label}: {reason}. No pattern written" for reason in outcome.reasons)
        elif outcome.status == "no_target":
            what = "this field" if name else "these terms"
            messages.append(f"{label}: no pattern of the check takes {what}")
    return messages


def _read_vocab_file(path: Path) -> tuple[JsonValue, str | None]:
    """Load a vocab.yml. Returns (data, error_message)."""
    if not path.exists():
        return None, f"no {path.name}"
    try:
        data = fast_yaml_load(path.read_text(encoding="utf-8"))
        return data, None
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return None, f"{path.name} {unreadable_file_problem(exc)}"


@dataclass
class SyncResult:
    """Result of syncing vocab into checks.yml for one rule."""

    rule_dir: Path
    updated: int = 0
    skipped: int = 0
    messages: list[str] = field(default_factory=list)


def _sync_entry(result: SyncResult, suffix: str, check: JsonObject, value: JsonValue) -> bool:
    """Walk one vocab entry, record its messages and counts in `result`, write it when no field is invalid."""
    outcomes = _walk_entry(check, value)
    statuses = {outcome.status for _, outcome in outcomes}
    result.messages.extend(_entry_messages(suffix, outcomes))
    if "invalid" in statuses:
        result.skipped += 1
        return False
    if "changed" in statuses:
        for _, outcome in outcomes:
            if outcome.write is not None:
                container, key, new = outcome.write
                container[key] = new
        result.updated += 1
        return True
    if "no_target" in statuses:
        result.skipped += 1
    return False


def sync_vocab(rule_dir: Path, *, dry_run: bool = False) -> SyncResult:
    """Sync vocab.yml terms into checks.yml patterns for a single rule."""
    result = SyncResult(rule_dir=rule_dir)
    checks_path = rule_dir / "checks.yml"

    vocab, err = _read_vocab_file(rule_dir / "vocab.yml")
    if err:
        result.messages.append(err)
        return result
    if not isinstance(vocab, dict):
        result.messages.append("vocab.yml is not a mapping")
        return result

    if not checks_path.exists():
        result.messages.append(f"no {checks_path.name}")
        return result
    try:
        checks_data = deepcopy(read_checks_document(checks_path))
    except RuleReadError as exc:
        result.messages.append(str(exc))
        return result

    checks = as_list(checks_data.get("checks"))
    if not checks:
        result.messages.append("checks.yml has no checks")
        return result

    modified = False
    for suffix, value in vocab.items():
        check = _find_check_by_suffix(checks, suffix)
        if check is None:
            result.skipped += 1
            result.messages.append(f"no check matching suffix '{suffix}'")
            continue

        modified = _sync_entry(result, suffix, check, value) or modified

    if modified and not dry_run:
        checks_path.write_text(
            yaml.dump(checks_data, default_flow_style=False, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

    return result


def sync_all(rules_root: Path, *, dry_run: bool = False) -> list[SyncResult]:
    """Sync all vocab.yml files under rules_root."""
    results: list[SyncResult] = []

    for vocab_path in sorted(rules_root.rglob("vocab.yml")):
        if "tests" in vocab_path.parts:
            continue
        rule_dir = vocab_path.parent
        results.append(sync_vocab(rule_dir, dry_run=dry_run))

    return results
