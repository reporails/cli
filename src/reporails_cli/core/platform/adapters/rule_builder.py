"""Rule construction from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

from pathlib import Path
from types import UnionType
from typing import Annotated, Union, get_args, get_origin

from pydantic import BaseModel, ValidationError

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.models import Check, FieldProblem, FileMatch, Rule, Severity


class RuleFieldError(ValueError):
    """A `rule.md` whose fields cannot build a rule; `problems` has one record per rejected field."""

    def __init__(self, problems: list[FieldProblem]) -> None:
        super().__init__("; ".join(p.text for p in problems))
        self.problems = problems


def _step(candidates: list[object], part: str | int) -> list[object] | None:
    """The annotations `part` leads to from `candidates`; None when `part` names no field, index or key."""
    members: list[object] = []
    for ann in candidates:
        while get_origin(ann) is Annotated:
            ann = get_args(ann)[0]
        if get_origin(ann) in (Union, UnionType):
            members.extend(get_args(ann))
        else:
            members.append(ann)
    nxt: list[object] = []
    for ann in members:
        origin, args = get_origin(ann), get_args(ann)
        if isinstance(ann, type) and issubclass(ann, BaseModel):
            for name, info in ann.model_fields.items():
                if part == (info.alias or name):
                    nxt.append(info.annotation)
        elif origin in (list, set, frozenset) and isinstance(part, int) and args:
            nxt.append(args[0])
        elif origin is dict and len(args) == 2:
            nxt.append(args[1])
    return nxt or None


def _field_path(model: type[BaseModel], loc: tuple[int | str, ...]) -> str:
    """The dotted path of `loc` through `model`, ending at the first part that names no field, index or key.

    That part is a union member tag pydantic adds, so every branch of a union field shares the field's path.
    """
    candidates: list[object] = [model]
    parts: list[str] = []
    for part in loc:
        stepped = _step(candidates, part)
        if stepped is None:
            break
        candidates = stepped
        parts.append(str(part))
    return ".".join(parts)


def _joined(messages: list[str]) -> str:
    """The messages as one line; a shared leading `Input should be ` is stated once."""
    unique = list(dict.fromkeys(messages))
    prefix = "Input should be "
    if len(unique) > 1 and all(m.startswith(prefix) for m in unique):
        return prefix + " or ".join(m[len(prefix) :] for m in unique)
    return "; ".join(unique)


def field_problems(exc: ValidationError, model: type[BaseModel]) -> list[FieldProblem]:
    """One record per rejected field path of `exc` against `model`: dotted path, one-line message, missing or invalid.

    Several errors on one path (one per union member) give one record whose message joins them.
    """
    grouped: dict[str, list[tuple[str, str]]] = {}
    for err in exc.errors():
        if err["type"] == "extra_forbidden":
            parent = _field_path(model, err["loc"][:-1])
            path = f"{parent}.{err['loc'][-1]}" if parent else str(err["loc"][-1])
            grouped.setdefault(path, []).append(("is not a known key", err["type"]))
            continue
        path = _field_path(model, err["loc"])
        grouped.setdefault(path, []).append((err["msg"], err["type"]))
    return [
        FieldProblem(
            field=path,
            message=_joined([msg for msg, _ in found]),
            kind="missing" if all(kind == "missing" for _, kind in found) else "invalid",
        )
        for path, found in grouped.items()
    ]


def load_checks(frontmatter: JsonObject) -> list[Check]:
    """Load check entries from frontmatter (pre-populated by registry from checks.yml).

    Raises ValueError naming up to three problems as `check N (id): field: message`.
    """
    raw_checks = frontmatter.get("checks", [])
    if not isinstance(raw_checks, list):
        raise ValueError(f"`checks` must be a list, not a {type(raw_checks).__name__}")
    checks: list[Check] = []
    problems: list[str] = []
    for index, item in enumerate(raw_checks, start=1):
        if not isinstance(item, dict):
            problems.append(f"check {index} must be a mapping, not a {type(item).__name__}")
            continue
        try:
            checks.append(Check.model_validate(item))
        except ValidationError as exc:
            label = f"check {index}" + (f" ({item['id']})" if isinstance(item.get("id"), str) else "")
            problems.extend(f"{label}: {p.text}" for p in field_problems(exc, Check)[:2])
    if problems:
        raise ValueError("; ".join(problems[:3]))
    return checks


def _parse_severity(frontmatter: JsonObject, checks: list[Check]) -> JsonValue | Severity:
    """The rule-level severity: the frontmatter value, else the first check's severity; falsy when neither."""
    return frontmatter.get("severity") or (checks[0].severity if checks else None)


def _parse_match(frontmatter: JsonObject) -> JsonValue | FileMatch:
    """Property-based file targeting from frontmatter; an empty `match:` (YAML null) matches all files."""
    raw = frontmatter.get("match")
    if isinstance(raw, dict) or raw is None:
        return raw
    return FileMatch()


def build_rule(frontmatter: JsonObject, md_path: Path, yml_path: Path | None, checks: list[Check]) -> Rule:
    """Build Rule from parsed frontmatter and its already-built `checks`.

    Raises RuleFieldError with one problem per rejected field when the fields do not validate.
    """
    raw: dict[str, object] = {
        "fix": str(frontmatter.get("fix", "") or "").strip(),
        "match": _parse_match(frontmatter),
        "depends_on": frontmatter.get("depends_on", []),
        "see_also": frontmatter.get("see_also", []),
        "checks": checks,
        "md_path": md_path,
        "yml_path": yml_path,
    }
    for name in (
        "id",
        "title",
        "category",
        "type",
        "slug",
        "execution",
        "supersedes",
        "inherited",
        "requires_capability",
        "surface_mutations",
    ):
        if name in frontmatter:
            raw[name] = frontmatter[name]
    severity = _parse_severity(frontmatter, checks)
    if severity:
        raw["severity"] = severity
    try:
        return Rule.model_validate(raw)
    except ValidationError as exc:
        raise RuleFieldError(field_problems(exc, Rule)) from exc
