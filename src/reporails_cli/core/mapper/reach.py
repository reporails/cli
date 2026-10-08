"""Reach: the project files and folders an instruction file's own text points at.

Sources are the backticked path tokens the mapper already read, the markdown link targets and the
`@` imports. Each is resolved against the file's own folder, then the project root, and kept only
when it exists inside the scan root.
"""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from reporails_cli.core.mapper.imports import import_refs, import_target
from reporails_cli.core.mapper.structure import link_targets, strip_anchor

MAX_REACH = 50


def _candidates(text: str, tokens: list[str]) -> list[tuple[str, bool]]:
    """`(reference, is_import)` of every path the file points at, in source order."""
    refs = [(t, False) for t in tokens]
    refs += [(strip_anchor(target), False) for _, target in link_targets(text)]
    refs += [(r, True) for r in import_refs(text)]
    return [(r, imp) for r, imp in refs if r]


def _resolve(ref: str, imp: bool, file_path: Path, root: Path, root_real: Path) -> str | None:
    """The posix path (in `root`'s own form) `ref` names, or None when it names nothing inside `root`."""
    if "://" in ref or ref.startswith(("#", "mailto:")) or any(c in ref for c in "*?<>|{}\n\t ") or ref.startswith("~"):
        return None
    options = [import_target(ref, file_path)] if imp else [file_path.parent / ref]
    if not os.path.isabs(ref):
        options.append(root / ref)
    for option in options:
        norm = Path(os.path.normpath(option))
        if not norm.exists() or norm == Path(os.path.normpath(file_path)):
            continue
        try:
            norm.resolve().relative_to(root_real)
            norm.relative_to(Path(os.path.normpath(root)))
        except ValueError:
            continue
        return norm.as_posix()
    return None


def file_reach(file_path: Path, root: Path, tokens: list[str]) -> tuple[str, ...]:
    """Sorted, deduped paths of existing files and folders in `root` that `file_path` points at."""
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        text = ""
    root_real = root.resolve()
    found = {
        hit
        for ref, imp in _candidates(text, tokens)
        if (hit := _resolve(ref, imp, file_path, root, root_real)) is not None
    }
    return tuple(sorted(found))[:MAX_REACH]


def record_reach(ruleset_map: Any, root: Path) -> None:
    """Record each file's `reach` in place, from its atoms' backticked tokens, its links and its imports."""
    files = getattr(ruleset_map, "files", None)
    if not files:
        return
    tokens: dict[str, list[str]] = defaultdict(list)
    for atom in ruleset_map.atoms:
        tokens[atom.file_path].extend(atom.named_tokens)
    for rec in files:
        rec.reach = file_reach(Path(rec.path), root, tokens.get(rec.path, []))
