"""Compact projection of a RulesetMap for HTTP transport.

The body starts with a single version byte and packs binary fields as raw
bytes via msgpack ``bin``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import msgpack

from reporails_cli.core.platform.adapters.api_client import (
    _CHARGE_ENC,
    _FORMAT_ENC,
    _KIND_ENC,
    _MODALITY_ENC,
    _SPECIFICITY_ENC,
)
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import LIST_OBJECT_ROLE
from reporails_cli.core.platform.policy.negative_headings import in_negative_section, is_negative_heading

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.ruleset import RulesetMap

logger = logging.getLogger(__name__)

WIRE_SCHEMA_VERSION_V4 = 4

# A file record carries at most this many activation patterns; the rest are dropped.
MAX_FILE_GLOBS = 50


def _project_soas_span(slots: Any) -> dict[str, Any] | None:
    """Project ``AtomSlots``' coordinate half to the frozen ``so`` wire block.

    Coordinates + per-span confidences only — never slot text.
    Returns ``None`` when every span offset is absent, so the caller omits the
    key entirely rather than emit an all-null block.
    """
    spans = (slots.subject_span, slots.predicate_span, slots.object_span, slots.scope_span)
    if all(s is None for s in spans):
        return None
    return {
        "su": list(slots.subject_span) if slots.subject_span is not None else None,
        "pr": list(slots.predicate_span) if slots.predicate_span is not None else None,
        "ob": list(slots.object_span) if slots.object_span is not None else None,
        "scp": list(slots.scope_span) if slots.scope_span is not None else None,
        "sconf": slots.subject_conf,
        "pconf": slots.predicate_conf,
        "oconf": slots.object_conf,
        "scconf": slots.scope_conf,
    }


def _project_atom(a: Any, file_idx: dict[str, int]) -> dict[str, Any]:
    """Project a single Atom to the v4 wire shape."""
    d: dict[str, Any] = {
        "line": a.line,
        "t": _KIND_ENC.get(a.kind, 1),
        "c": _CHARGE_ENC.get(a.charge, 3),
        "cv": a.charge_value,
        "m": _MODALITY_ENC.get(a.modality, 4),
        "s": _SPECIFICITY_ENC.get(a.specificity, 1),
        "sc": a.scope_conditional,
        "f": _FORMAT_ENC.get(a.format, 0),
        "pi": a.position_index,
        "tc": a.token_count,
        "fi": file_idx.get(a.file_path, -1),
        "nb": len(a.named_tokens) if a.named_tokens else 0,
        "ib": len(a.italic_tokens) if a.italic_tokens else 0,
        "bb": len(a.bold_tokens) if a.bold_tokens else 0,
        "ub": len(a.unformatted_code) if a.unformatted_code else 0,
    }
    if a.embedding_int8:
        d["e"] = bytes(v & 0xFF for v in a.embedding_int8)
    if a.depth is not None:
        d["d"] = a.depth
    if a.ambiguous:
        d["a"] = True
    if (a.kind == "heading" and is_negative_heading(a.text)) or in_negative_section(
        a.kind, a.format, a.heading_context
    ):
        d["ns"] = True  # a bare negative heading, or a list item directly under one
    if a.lead_in:
        d["li"] = True  # a line ending with a colon that introduces the list, code block or table after it
    if a.embedded_charge_markers:
        d["ecm"] = list(a.embedded_charge_markers)
    if a.caps_tokens:
        d["cap"] = list(a.caps_tokens)
    if a.slots is not None:
        so = _project_soas_span(a.slots)
        if so is not None:
            d["so"] = so
    return d


def _relativize(path: str, root: Path) -> str:
    """`path` as it rides the wire, relative to `root` — the checked project's root, never
    a root guessed from the mapped files themselves (that guess collapses to the wrong
    directory whenever the mapped set doesn't happen to span down from the real root —
    a single mapped file, or a `.claude/rules/`-only project).

    Three forms, decided by where `path` actually sits, each one mapping back to the
    same local file when the response is read:

    * inside `root`: the project-relative posix path.
    * outside `root` but inside the user's home directory (a user-level
      `~/.claude/CLAUDE.md`, an agent-memory file) — `~/`-relative, so the home
      directory and the username never ride the wire, only the literal `~`.
    * neither: `path` unchanged. This only reaches a file the CLI itself resolved
      outside both the project and the home directory, which carries no home-directory
      component to begin with.
    """
    p = Path(path)
    if p.is_relative_to(root):
        return p.relative_to(root).as_posix()
    home = Path.home()
    if p.is_relative_to(home):
        return "~/" + p.relative_to(home).as_posix()
    return path


def _project_files(ruleset_map: RulesetMap, root: Path) -> list[dict[str, Any]]:
    """Project file records to v4 — path relative to the scan root, never the frontmatter
    `description` prose (only its embedding, `de`, is projected)."""
    out: list[dict[str, Any]] = []
    for f in ruleset_map.files:
        fd: dict[str, Any] = {
            "path": _relativize(f.path, root),
            "content_hash": f.content_hash,
            "loading": f.loading,
            "scope": f.scope,
            "agent": f.agent,
            "type": f.type,
        }
        if f.globs:
            fd["globs"] = list(f.globs[:MAX_FILE_GLOBS])
        if f.description_embedding:
            fd["de"] = bytes(v & 0xFF for v in f.description_embedding)
        out.append(fd)
    return out


def project_payload(ruleset_map: RulesetMap, root: Path) -> dict[str, Any]:
    """Build the v4 payload dict (pre-encoding). `root` is the scan root every wire path
    rides relative to — the same root the rest of the run resolves local paths against.
    Required: there is no current-directory fallback, so a payload can never silently
    ride relative to wherever the process happens to be running from."""
    file_idx = {f.path: i for i, f in enumerate(ruleset_map.files)}
    return {
        "schema_version": "4",
        "embedding_model": ruleset_map.embedding_model,
        "generated_at": ruleset_map.generated_at,
        "files": _project_files(ruleset_map, root),
        # A list item read as its instruction's object is part of that instruction, not an atom of its own.
        "atoms": [_project_atom(a, file_idx) for a in ruleset_map.atoms if a.role != LIST_OBJECT_ROLE],
    }


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


# At most this many local entries are sent per request.
_MAX_LOCAL_ENTRIES = 10_000


def local_entries(
    findings: Iterable[Any],
    file_level_checks: frozenset[str],
    registry_ids: frozenset[str],
    resolve: Callable[[str], str],
    type_of: Callable[[str], str] = lambda _path: "generic",
) -> list[LocalEntry]:
    """One entry per reported local finding, in order — no message and no matched text.

    `findings` are the local findings as they will be reported (suppressions applied);
    `file_level_checks` are the check ids whose finding concerns the whole file, sent at line 0;
    `registry_ids` are the rule ids the registry defines: a finding under any other label stays
    in the user's output but is not sent;
    `resolve` maps a reported path to its absolute path, and `type_of` an absolute path to its
    file type.
    """
    entries: list[LocalEntry] = []
    for f in findings:
        if f.rule not in registry_ids:
            continue
        check = getattr(f, "check_id", "") or ""
        line = 0 if check in file_level_checks else max(f.line, 0)
        file = resolve(f.file)
        entries.append(
            LocalEntry(rule=f.rule, file=file, line=line, severity=f.severity, check=check, type=type_of(file))
        )
    return entries


def _within_bound(local: Sequence[LocalEntry]) -> list[LocalEntry]:
    """The entries to send: all of them, or — past the bound — every error entry first, then the
    others in order, up to the bound. The findings are still reported either way."""
    if len(local) <= _MAX_LOCAL_ENTRIES:
        return list(local)
    logger.warning("%d local findings exceed the request bound; sending %d", len(local), _MAX_LOCAL_ENTRIES)
    errors = [e for e in local if e.severity == "error"]
    others = [e for e in local if e.severity != "error"]
    return (errors + others)[:_MAX_LOCAL_ENTRIES]


def project_local(local: Sequence[LocalEntry], mapped: list[str], root: Path) -> dict[str, Any]:
    """The request's `local` entries, and the `local_files` they name beyond the mapped files with
    each one's type in `local_types`. `local_files` rides `root`-relative too, via the exact same
    `_relativize` rule `mapped` was built from — a local entry's absolute file matches a mapped
    file by exact string equality on that shared wire form, never by a path-suffix guess (a
    suffix match attributes `tests/CLAUDE.md` to a mapped root `CLAUDE.md`, since `tests/CLAUDE.md`
    ends with `/CLAUDE.md` too).

    Each entry's `f` indexes the mapped files first, then `local_files`. `root` is required, like
    `project_payload`'s — the caller always has the real one.
    """
    local = _within_bound(local)
    mapped_index = {m: i for i, m in enumerate(mapped)}
    resolved: dict[str, int] = {}
    extra: list[str] = []
    extra_types: list[str] = []
    entries: list[dict[str, Any]] = []
    for e in local:
        key = _path_key(e.file)
        if key not in resolved:
            wire = _relativize(e.file, root)
            i = mapped_index.get(wire)
            if i is not None:
                resolved[key] = i
            else:
                resolved[key] = len(mapped) + len(extra)
                extra.append(wire)
                extra_types.append(e.type)
        entries.append({"r": e.rule, "f": resolved[key], "l": e.line, "s": e.severity, "k": e.check})
    fields: dict[str, Any] = {"local": entries}
    if extra:
        fields["local_files"] = extra
        fields["local_types"] = extra_types
    return fields


def encode_msgpack(payload: dict[str, Any]) -> bytes:
    """Encode the v4 payload as msgpack with a leading version byte."""
    encoded = msgpack.packb(payload, use_bin_type=True)
    if not isinstance(encoded, bytes):
        raise RuntimeError(f"msgpack.packb returned {type(encoded).__name__}, expected bytes")
    return bytes([WIRE_SCHEMA_VERSION_V4]) + encoded


def estimated_byte_size(ruleset_map: RulesetMap) -> int:
    """Cheap upper-bound estimate of the encoded body size."""
    n_atoms = len(ruleset_map.atoms) if ruleset_map.atoms else 0
    n_files = len(ruleset_map.files) if ruleset_map.files else 0
    # Per-atom metadata plus the embedding when the atom carries one.
    has_emb_atoms = sum(1 for a in ruleset_map.atoms if a.embedding_int8)
    atom_bytes = n_atoms * 120 + has_emb_atoms * 384
    has_emb_files = sum(1 for f in ruleset_map.files if f.description_embedding)
    file_bytes = n_files * 80 + has_emb_files * 386
    return atom_bytes + file_bytes + 1024
