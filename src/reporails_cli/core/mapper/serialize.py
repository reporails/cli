# ruff: noqa: PERF401
"""RulesetMap serialization + deterministic validation.

Two responsibilities:

1. JSON round-trip — `save_ruleset_map` / `load_ruleset_map` and their per-atom
   helpers serialize the full client-side wire format (including int8
   embeddings as base64 byte strings). This is the on-disk format the mapper
   daemon hands back to the client.

2. Post-hoc validation — `validate_atoms` / `validate_map` apply three layers
   of deterministic invariants over a finished atom set: schema (legal
   charge/modality values), charge consistency (negation→constraint), and
   distribution sanity (charge ratios outside the expected bands). Findings
   are returned as a list; the orchestration spine in `pipeline.py` decides
   which severities to log or raise on.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reporails_cli.core.mapper.classify import (
    _MODAL_ABSOLUTE,
    ABSOLUTE_CUES,
    _strip_md_for_classify,
    leading_prohibition,
    starts_bare_no_status,
    starts_descriptive_no,
    words_of,
)
from reporails_cli.core.platform.dto.ruleset import (
    Atom,
    AtomSlots,
    FileRecord,
    RulesetMap,
    RulesetSummary,
)

# ──────────────────────────────────────────────────────────────────
# SERIALIZATION
# ──────────────────────────────────────────────────────────────────


def _pack_optional_atom_fields(atom: Atom, d: dict[str, Any]) -> None:
    """Add optional per-atom fields to the dict when populated."""
    if atom.topics:
        d["topics"] = list(atom.topics)
    if atom.role:
        d["role"] = atom.role
    if atom.heading_context:
        d["heading_context"] = atom.heading_context
    if atom.depth is not None:
        d["depth"] = atom.depth
    if atom.list_depth:
        d["list_depth"] = atom.list_depth
    if atom.lead_in:
        d["lead_in"] = True
    if atom.rule:
        d["rule"] = atom.rule
    if atom.ambiguous:
        d["ambiguous"] = True
    if atom.embedded_charge_markers:
        d["embedded_charge_markers"] = list(atom.embedded_charge_markers)
    _pack_granularity_and_span_fields(atom, d)


def _pack_granularity_and_span_fields(atom: Atom, d: dict[str, Any]) -> None:
    """Add the caps/cell/stage/granularity-audit fields, the import origin, and the slot coordinates."""
    if atom.cell_straddle:
        d["cell_straddle"] = True
    if atom.stage:
        d["stage"] = atom.stage
    if atom.over_merged:
        d["over_merged"] = True
    if atom.min_clause_cosine is not None:
        d["min_clause_cosine"] = atom.min_clause_cosine
    if atom.abstained:
        d["abstained"] = True
    if atom.imported_from:
        d["imported_from"] = atom.imported_from
        d["imported_line"] = atom.imported_line
    _pack_slot_coords(atom, d)


def _pack_slot_coords(atom: Atom, d: dict[str, Any]) -> None:
    """Add the axis-span coordinate half of ``slots`` under ``slot_coords``.

    Mirrors `map_cache._SLOT_COORD_FIELDS`: token-offset spans + per-span
    confidences only — never the slot text (subject/predicate/object/scope
    strings). Omitted entirely when every span offset is absent.
    """
    from reporails_cli.core.cache.map_cache import _SLOT_COORD_FIELDS, _SLOT_SPAN_FIELDS

    slots = atom.slots
    if slots is None:
        return
    if not any(getattr(slots, f) is not None for f in _SLOT_SPAN_FIELDS):
        return
    d["slot_coords"] = {f: getattr(slots, f) for f in _SLOT_COORD_FIELDS}


def _encode_embedding_b64(vec: tuple[int, ...] | None) -> str | None:
    """Base64-encode an int8 embedding vector (None → None)."""
    import numpy as np

    if vec is None:
        return None
    return base64.b64encode(np.asarray(vec, dtype=np.int8).tobytes()).decode("ascii")


def _atom_to_dict(atom: Atom) -> dict[str, Any]:
    """Serialize an Atom to a JSON-compatible dict."""
    d: dict[str, Any] = {
        "line": atom.line,
        "text": atom.text,
        "kind": atom.kind,
        "charge": atom.charge,
        "charge_value": atom.charge_value,
        "modality": atom.modality,
        "specificity": atom.specificity,
        "scope_conditional": atom.scope_conditional,
        "format": atom.format,
        "position_index": atom.position_index,
        "token_count": atom.token_count,
        "file_path": atom.file_path,
        "plain_text": atom.plain_text,
    }
    emb = _encode_embedding_b64(atom.embedding_int8)
    if emb is not None:
        d["embedding_b64"] = emb
    # Inline formatting — converged format
    inline: list[dict[str, str]] = []
    for tok in atom.named_tokens:
        inline.append({"term": tok, "style": "backtick"})
    for tok in atom.italic_tokens:
        inline.append({"term": tok, "style": "italic"})
    for tok in atom.bold_tokens:
        inline.append({"term": tok, "style": "bold"})
    for tok in atom.unformatted_code:
        inline.append({"term": tok, "style": "none"})
    if inline:
        d["inline"] = inline
    _pack_optional_atom_fields(atom, d)
    return d


def _decode_embedding_b64(b64: str | None) -> tuple[int, ...] | None:
    """Decode a base64-encoded int8 embedding vector."""
    if b64 is None:
        return None
    raw = base64.b64decode(b64)
    # Convert unsigned bytes back to signed int8 (-128..127)
    return tuple(v if v < 128 else v - 256 for v in raw)


def _atom_from_dict(d: dict[str, Any]) -> Atom:
    """Deserialize an Atom from a dict."""
    # Parse converged inline format back to separate lists
    named_tokens: list[str] = []
    italic_tokens: list[str] = []
    bold_tokens: list[str] = []
    unformatted_code: list[str] = []
    for span in d.get("inline", []):
        style = span.get("style", "none")
        term = span["term"]
        if style == "backtick":
            named_tokens.append(term)
        elif style == "italic":
            italic_tokens.append(term)
        elif style == "bold":
            bold_tokens.append(term)
        elif style == "none":
            unformatted_code.append(term)

    return Atom(
        line=d["line"],
        text=d["text"],
        kind=d.get("kind", "excitation"),
        charge=d["charge"],
        charge_value=d["charge_value"],
        modality=d["modality"],
        specificity=d.get("specificity", "abstract"),
        scope_conditional=d.get("scope_conditional", False),
        format=d.get("format", "prose"),
        named_tokens=named_tokens,
        italic_tokens=italic_tokens,
        bold_tokens=bold_tokens,
        unformatted_code=unformatted_code,
        position_index=d.get("position_index", 0),
        token_count=d.get("token_count", 0),
        file_path=d.get("file_path", ""),
        embedding_int8=_decode_embedding_b64(d.get("embedding_b64")),
        plain_text=d.get("plain_text", ""),
        heading_context=d.get("heading_context", ""),
        depth=d.get("depth"),
        list_depth=d.get("list_depth", 0),
        lead_in=d.get("lead_in", False),
        rule=d.get("rule", ""),
        ambiguous=d.get("ambiguous", False),
        cell_straddle=d.get("cell_straddle", False),
        embedded_charge_markers=d.get("embedded_charge_markers", []),
        topics=tuple(d.get("topics", [])),
        role=d.get("role", ""),
        over_merged=d.get("over_merged", False),
        min_clause_cosine=d.get("min_clause_cosine"),
        abstained=d.get("abstained", False),
        stage=d.get("stage", ""),
        slots=_unpack_slot_coords(d.get("slot_coords")),
        imported_from=d.get("imported_from", ""),
        imported_line=d.get("imported_line", 0),
    )


def _unpack_slot_coords(slot_coords: dict[str, Any] | None) -> AtomSlots | None:
    """Restore the axis-span coordinate half of ``slots`` from ``slot_coords``.

    Tolerant of older JSON with no `slot_coords` key (returns None — slots
    stay unset, exactly like an atom that never carried spans). Slot TEXT is
    never round-tripped (see `_pack_slot_coords`); only offsets + confidences.
    """
    from reporails_cli.core.cache.map_cache import _as_offset

    if not slot_coords:
        return None
    return AtomSlots(
        subject_span=_as_offset(slot_coords.get("subject_span")),
        predicate_span=_as_offset(slot_coords.get("predicate_span")),
        object_span=_as_offset(slot_coords.get("object_span")),
        scope_span=_as_offset(slot_coords.get("scope_span")),
        subject_conf=slot_coords.get("subject_conf", 0.0),
        predicate_conf=slot_coords.get("predicate_conf", 0.0),
        object_conf=slot_coords.get("object_conf", 0.0),
        scope_conf=slot_coords.get("scope_conf", 0.0),
    )


def save_ruleset_map(ruleset_map: RulesetMap, path: Path) -> None:
    """Serialize a RulesetMap to JSON."""
    import numpy as np

    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": ruleset_map.schema_version,
        "embedding_model": ruleset_map.embedding_model,
        "generated_at": ruleset_map.generated_at,
        "files": [
            {
                "path": f.path,
                "content_hash": f.content_hash,
                "loading": f.loading,
                "scope": f.scope,
                "agent": f.agent,
                "type": f.type,
                "activation": f.activation,
                **({"reach": list(f.reach)} if f.reach else {}),
                **({"globs": list(f.globs)} if f.globs else {}),
                **({"description": f.description} if f.description else {}),
                **(
                    {
                        "description_embedding_b64": base64.b64encode(
                            np.asarray(f.description_embedding, dtype=np.int8).tobytes()
                        ).decode("ascii")
                    }
                    if f.description_embedding
                    else {}
                ),
            }
            for f in ruleset_map.files
        ],
        "atoms": [_atom_to_dict(a) for a in ruleset_map.atoms],
        "summary": {
            "n_atoms": ruleset_map.summary.n_atoms,
            "n_charged": ruleset_map.summary.n_charged,
            "n_neutral": ruleset_map.summary.n_neutral,
        },
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_ruleset_map(path: Path) -> RulesetMap:
    """Deserialize a RulesetMap from JSON."""
    data = json.loads(path.read_text(encoding="utf-8"))

    files = tuple(
        FileRecord(
            path=f["path"],
            content_hash=f["content_hash"],
            loading=f.get("loading", "session_start"),
            scope=f.get("scope", "global"),
            globs=tuple(f.get("globs", [])),
            agent=f.get("agent", "generic"),
            type=f.get("type", "generic"),
            activation=f.get("activation", "always"),
            reach=tuple(f.get("reach", [])),
            description=f.get("description", ""),
            description_embedding=_decode_embedding_b64(f.get("description_embedding_b64")),
        )
        for f in data["files"]
    )
    atoms = tuple(_atom_from_dict(a) for a in data["atoms"])
    s = data["summary"]
    summary = RulesetSummary(
        n_atoms=s["n_atoms"],
        n_charged=s["n_charged"],
        n_neutral=s["n_neutral"],
    )

    return RulesetMap(
        schema_version=data["schema_version"],
        embedding_model=data["embedding_model"],
        generated_at=data["generated_at"],
        files=files,
        atoms=atoms,
        summary=summary,
    )


# ──────────────────────────────────────────────────────────────────
# MAP VALIDATION
# ──────────────────────────────────────────────────────────────────


@dataclass
class MapFinding:
    """A validation finding from map inspection."""

    severity: str  # error | warn | info
    rule: str
    message: str
    line: int = 0
    text: str = ""
    charge: str = ""


# Strong charge words that should not appear in NEUTRAL atoms (unless quoted): the classifier's words
# for an order that admits no exception, in capitals, and the two capitalised prohibition adjectives
# it carries only as verb stems.
_STRONG_CHARGE_RE = re.compile(
    r"\b("
    + "|".join(sorted(w.upper() for w in _MODAL_ABSOLUTE | ABSOLUTE_CUES | {"forbidden", "prohibited"}))
    + r")\b",
)
_QUOTED_ATOM_RE = re.compile(r'^["“„]')


_VALID_CHARGES = frozenset({"CONSTRAINT", "DIRECTIVE", "IMPERATIVE", "NEUTRAL", "AMBIGUOUS"})
_VALID_MODS = frozenset({"imperative", "direct", "absolute", "hedged", "none"})


def _validate_atom_schema(a: Atom, findings: list[MapFinding]) -> None:
    """Check schema and consistency invariants for a single atom."""
    cv, chg, mod = a.charge_value, a.charge, a.modality
    _checks: list[tuple[bool, str, str]] = [
        (chg not in _VALID_CHARGES, "schema", f"Invalid charge: {chg}"),
        (mod not in _VALID_MODS, "schema", f"Invalid modality: {mod}"),
        (cv not in (-1, 0, 1), "schema", f"Invalid charge_value: {cv}"),
        (cv == 0 and chg not in ("NEUTRAL", "AMBIGUOUS"), "consistency", f"charge_value=0 but charge={chg}"),
        (cv != 0 and chg == "NEUTRAL", "consistency", "charge_value!=0 but charge=NEUTRAL"),
        (cv == 0 and mod != "none", "consistency", f"NEUTRAL with modality={mod}"),
        (cv != 0 and mod == "none", "consistency", "Charged with modality=none"),
    ]
    for condition, rule, message in _checks:
        if condition:
            findings.append(MapFinding("error", rule, message, a.line, a.text[:80], chg))


def validate_atoms(atoms: tuple[Atom, ...] | list[Atom]) -> list[MapFinding]:
    """Validate atoms against deterministic invariants.

    Three layers:
      1. Schema — charge/modality/value consistency (hard errors)
      2. Deterministic charge — negation→constraint, heading→neutral (must hold)
      3. Statistical + suspicious — distribution anomalies, charge words in neutral

    Works on raw atom lists (from tokenize) or RulesetMap.atoms.
    Returns list of findings. Empty list = clean.
    """
    findings: list[MapFinding] = []
    exc: list[Atom] = []

    for a in atoms:
        _validate_atom_schema(a, findings)
        if a.kind == "excitation":
            exc.append(a)

    # Deterministic charge invariants
    for a in exc:
        clean = _strip_md_for_classify(a.text)
        clean_words = words_of(clean)
        # "No X is/are Y" is descriptive, not a required prohibition — mirror the
        # Phase 1 classifier guard so the check does not over-flag it. A bare
        # "No <noun phrase>" status line (`No mocks.`, `No open issues.`) is the same
        # non-prohibition shape the classifier already floors to NEUTRAL — reuse that
        # predicate here instead of re-deriving the guard, so this warning does not
        # contradict the classifier's own determination on the identical shape.
        if (
            leading_prohibition(clean) is not None
            and a.charge_value != -1
            and not starts_descriptive_no(clean_words)
            and not starts_bare_no_status(clean_words)
        ):
            msg = f"Negation at start but charge={a.charge}"
            findings.append(MapFinding("warn", "must_constraint", msg, a.line, a.text[:80], a.charge))
        is_unquoted_neutral = (
            a.charge_value == 0 and not _QUOTED_ATOM_RE.match(a.text.strip()) and _STRONG_CHARGE_RE.search(a.text)
        )
        if is_unquoted_neutral:
            findings.append(
                MapFinding(
                    "info",
                    "suspicious_neutral",
                    "NEUTRAL atom contains strong charge word",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )

    # Statistical checks
    n_exc = len(exc)
    if n_exc > 0:
        n_charged = sum(1 for a in exc if a.charge_value != 0)
        ratio = n_charged / n_exc
        if ratio > 0.90:
            msg = f"Charge ratio {ratio:.0%} ({n_charged}/{n_exc}) — unusually high"
            findings.append(MapFinding("warn", "distribution", msg))
        if ratio < 0.05 and n_exc > 10:
            msg = f"Charge ratio {ratio:.0%} ({n_charged}/{n_exc}) — unusually low"
            findings.append(MapFinding("warn", "distribution", msg))

    return findings


def validate_map(ruleset_map: RulesetMap) -> list[MapFinding]:
    """Validate a RulesetMap. Delegates to validate_atoms."""
    return validate_atoms(ruleset_map.atoms)
