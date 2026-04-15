"""Stopwords sync — compile vocab.yml terms into checks.yml patterns."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.stopwords import decompose, is_guard, recompose


def _find_check_by_suffix(
    checks: list[dict[str, Any]],
    suffix: str,
) -> dict[str, Any] | None:
    """Find a check whose ID ends with the given suffix."""
    for check in checks:
        cid = check.get("id", "")
        check_suffix = cid.rsplit(".", 1)[-1] if "." in cid else cid
        if check_suffix == suffix:
            return check
    return None


def _update_pattern(existing: str, new_terms: list[str]) -> str | None:
    """Replace alternation terms in an existing pattern, preserving wrapper."""
    parts = decompose(existing)
    if parts is None:
        return None
    return recompose(parts, new_terms)


def _try_update_field(container: dict[str, Any], key: str, terms: list[str]) -> bool:
    """Try to update a pattern field in a dict. Returns True if modified."""
    existing = container.get(key, "")
    if not existing:
        return False
    updated = _update_pattern(existing, terms)
    if updated and updated != existing:
        container[key] = updated
        return True
    return False


def _sync_patterns_array(patterns: list[dict[str, Any]], terms: list[str]) -> bool:
    """Sync terms into the first non-guard decomposable entry."""
    for entry in patterns:
        for fld in ("pattern-regex", "pattern-not-regex"):
            if fld not in entry or is_guard(entry[fld]):
                continue
            if decompose(entry[fld]):
                return _try_update_field(entry, fld, terms)
    return False


def _sync_flat(check: dict[str, Any], terms: list[str]) -> bool:
    """Auto-detect target field and sync terms. Returns True if modified."""
    ctype = check.get("type", "")

    if ctype == "mechanical" and check.get("check") == "content_absent":
        args = check.get("args") or {}
        if _try_update_field(args, "pattern", terms):
            check["args"] = args
            return True
        return False

    if ctype != "deterministic":
        return False

    if "pattern-regex" in check and "patterns" not in check:
        return _try_update_field(check, "pattern-regex", terms)

    if "patterns" in check:
        return _sync_patterns_array(check["patterns"], terms)

    return False


def _sync_targeted(check: dict[str, Any], terms: list[str], target: str) -> bool:
    """Sync terms into a specific pattern field. Returns True if modified."""
    ctype = check.get("type", "")

    if target == "args.pattern" and ctype == "mechanical":
        args = check.get("args") or {}
        if _try_update_field(args, "pattern", terms):
            check["args"] = args
            return True
        return False

    if target == "pattern-regex" and "pattern-regex" in check and "patterns" not in check:
        return _try_update_field(check, "pattern-regex", terms)

    if "patterns" in check:
        for entry in check["patterns"]:
            if target in entry and not is_guard(entry[target]):
                return _try_update_field(entry, target, terms)

    return False


def _dispatch_sync(check: dict[str, Any], value: Any) -> bool:
    """Dispatch sync for a single vocab entry. Returns True if modified."""
    if isinstance(value, list):
        return _sync_flat(check, value)
    if isinstance(value, dict):
        changed = False
        for field_name, field_terms in value.items():
            if isinstance(field_terms, list) and _sync_targeted(check, field_terms, field_name):
                changed = True
        return changed
    return False


def _load_yaml(path: Path) -> tuple[Any, str | None]:
    """Load a YAML file. Returns (data, error_message)."""
    if not path.exists():
        return None, f"no {path.name}"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data, None
    except (yaml.YAMLError, OSError) as e:
        return None, f"failed to read {path.name}: {e}"


@dataclass
class SyncResult:
    """Result of syncing vocab into checks.yml for one rule."""

    rule_dir: Path
    updated: int = 0
    skipped: int = 0
    messages: list[str] = field(default_factory=list)


def sync_vocab(rule_dir: Path, *, dry_run: bool = False) -> SyncResult:
    """Sync vocab.yml terms into checks.yml patterns for a single rule."""
    result = SyncResult(rule_dir=rule_dir)
    checks_path = rule_dir / "checks.yml"

    vocab, err = _load_yaml(rule_dir / "vocab.yml")
    if err:
        result.messages.append(err)
        return result
    if not isinstance(vocab, dict):
        result.messages.append("vocab.yml is not a mapping")
        return result

    checks_data, err = _load_yaml(checks_path)
    if err:
        result.messages.append(err)
        return result

    checks = (checks_data.get("checks") or []) if isinstance(checks_data, dict) else []
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

        if _dispatch_sync(check, value):
            result.updated += 1
            modified = True
        else:
            result.skipped += 1

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


def _decompose_terms(pattern: str) -> list[str] | None:
    """Decompose a pattern and return its terms, or None."""
    d = decompose(pattern)
    return d.terms if d else None


def _auto_detect_terms(check: dict[str, Any]) -> list[str] | None:
    """Auto-detect and extract terms from the first decomposable pattern."""
    ctype = check.get("type", "")
    if ctype == "mechanical":
        pat = (check.get("args") or {}).get("pattern", "")
        return _decompose_terms(pat) if pat else None

    if "pattern-regex" in check and "patterns" not in check:
        return _decompose_terms(check["pattern-regex"])

    if "patterns" in check:
        for entry in check["patterns"]:
            for fld in ("pattern-regex", "pattern-not-regex"):
                if fld in entry and not is_guard(entry[fld]):
                    terms = _decompose_terms(entry[fld])
                    if terms:
                        return terms
    return None


def _extract_current_terms(check: dict[str, Any], target: str) -> list[str] | None:
    """Extract current alternation terms from a check's pattern field."""
    if target == "auto":
        return _auto_detect_terms(check)

    if target == "args.pattern":
        pat = (check.get("args") or {}).get("pattern", "")
        return _decompose_terms(pat) if pat else None

    if target == "pattern-regex" and "pattern-regex" in check and "patterns" not in check:
        return _decompose_terms(check["pattern-regex"])

    if "patterns" in check:
        for entry in check["patterns"]:
            if target in entry and not is_guard(entry[target]):
                return _decompose_terms(entry[target])

    return None


@dataclass
class StalenessResult:
    """Result of checking vocab.yml vs checks.yml staleness."""

    rule_dir: Path
    stale: bool
    stale_checks: list[str] = field(default_factory=list)


def check_staleness(rule_dir: Path) -> StalenessResult | None:
    """Check if checks.yml patterns are stale. Returns None if no vocab.yml."""
    vocab_path = rule_dir / "vocab.yml"
    if not vocab_path.exists():
        return None

    checks_path = rule_dir / "checks.yml"
    if not checks_path.exists():
        return StalenessResult(rule_dir=rule_dir, stale=True, stale_checks=["checks.yml missing"])

    try:
        vocab = yaml.safe_load(vocab_path.read_text(encoding="utf-8"))
        checks_data = yaml.safe_load(checks_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return StalenessResult(rule_dir=rule_dir, stale=True, stale_checks=["parse error"])

    if not isinstance(vocab, dict) or not isinstance(checks_data, dict):
        return StalenessResult(rule_dir=rule_dir, stale=True, stale_checks=["invalid format"])

    checks = checks_data.get("checks") or []
    stale_list: list[str] = []

    for suffix, value in vocab.items():
        check = _find_check_by_suffix(checks, suffix)
        if check is None:
            stale_list.append(suffix)
            continue

        if isinstance(value, list):
            pairs = [("auto", value)]
        elif isinstance(value, dict):
            pairs = [(k, v) for k, v in value.items() if isinstance(v, list)]
        else:
            stale_list.append(suffix)
            continue

        for target, expected in pairs:
            actual = _extract_current_terms(check, target)
            if actual is None or sorted(actual) != sorted(expected):
                stale_list.append(suffix)
                break

    return StalenessResult(rule_dir=rule_dir, stale=bool(stale_list), stale_checks=stale_list)
