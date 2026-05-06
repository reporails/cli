"""Wire schema v3 — compact projection for HTTP transport.

v3 prefixes a single version byte and packs binary fields as raw bytes
via msgpack ``bin``. The legacy v2 path remains supported by the backend.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import msgpack

from reporails_cli.core.api_client import (
    _CHARGE_ENC,
    _FORMAT_ENC,
    _KIND_ENC,
    _MODALITY_ENC,
    _SPECIFICITY_ENC,
)

if TYPE_CHECKING:
    from reporails_cli.core.mapper.mapper import RulesetMap

WIRE_SCHEMA_VERSION_V3 = 3


def _project_atom(a: Any, file_idx: dict[str, int]) -> dict[str, Any]:
    """Project a single Atom to the v3 wire shape."""
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
        "k": a.cluster_id,
        "nb": len(a.named_tokens) if a.named_tokens else 0,
        "ib": len(a.italic_tokens) if a.italic_tokens else 0,
        "bb": len(a.bold_tokens) if a.bold_tokens else 0,
        "ub": len(a.unformatted_code) if a.unformatted_code else 0,
    }
    if a.embedding_int8 is not None:
        d["e"] = bytes(v & 0xFF for v in a.embedding_int8)
    if a.depth is not None:
        d["d"] = a.depth
    if a.ambiguous:
        d["a"] = True
    if a.embedded_charge_markers:
        d["ecm"] = list(a.embedded_charge_markers)
    return d


def _project_files(ruleset_map: RulesetMap) -> list[dict[str, Any]]:
    """Project file records to v3."""
    out: list[dict[str, Any]] = []
    for f in ruleset_map.files:
        fd: dict[str, Any] = {
            "path": f.path,
            "content_hash": f.content_hash,
            "loading": f.loading,
            "scope": f.scope,
            "agent": f.agent,
        }
        if f.globs:
            fd["globs"] = list(f.globs)
        if f.description:
            fd["description"] = f.description
        if f.description_embedding:
            fd["de"] = bytes(v & 0xFF for v in f.description_embedding)
        out.append(fd)
    return out


def _project_clusters(ruleset_map: RulesetMap) -> list[dict[str, Any]]:
    """Project cluster records to v3."""
    return [
        {"id": c.id, "n_atoms": c.n_atoms, "n_charged": c.n_charged, "n_neutral": c.n_neutral}
        for c in ruleset_map.clusters
    ]


def project_payload(ruleset_map: RulesetMap) -> dict[str, Any]:
    """Build the v3 payload dict (pre-encoding)."""
    file_idx = {f.path: i for i, f in enumerate(ruleset_map.files)}
    return {
        "schema_version": "3",
        "embedding_model": ruleset_map.embedding_model,
        "generated_at": ruleset_map.generated_at,
        "files": _project_files(ruleset_map),
        "atoms": [_project_atom(a, file_idx) for a in ruleset_map.atoms],
        "clusters": _project_clusters(ruleset_map),
        "summary": {
            "n_atoms": ruleset_map.summary.n_atoms,
            "n_charged": ruleset_map.summary.n_charged,
            "n_neutral": ruleset_map.summary.n_neutral,
            "n_topics": ruleset_map.summary.n_topics,
            "n_topics_charged": ruleset_map.summary.n_topics_charged,
        },
    }


def encode_msgpack(payload: dict[str, Any]) -> bytes:
    """Encode the v3 payload as msgpack with a leading version byte."""
    encoded = msgpack.packb(payload, use_bin_type=True)
    if not isinstance(encoded, bytes):
        raise RuntimeError(f"msgpack.packb returned {type(encoded).__name__}, expected bytes")
    return bytes([WIRE_SCHEMA_VERSION_V3]) + encoded


def serialize(ruleset_map: RulesetMap) -> bytes:
    """Convenience: project + encode in one call."""
    return encode_msgpack(project_payload(ruleset_map))


def estimated_byte_size(ruleset_map: RulesetMap) -> int:
    """Cheap upper-bound estimate of the encoded body size."""
    n_atoms = len(ruleset_map.atoms) if ruleset_map.atoms else 0
    n_files = len(ruleset_map.files) if ruleset_map.files else 0
    has_emb_atoms = sum(1 for a in ruleset_map.atoms if a.embedding_int8 is not None)
    atom_bytes = n_atoms * 120 + has_emb_atoms * 386
    has_emb_files = sum(1 for f in ruleset_map.files if f.description_embedding)
    file_bytes = n_files * 80 + has_emb_files * 386
    return atom_bytes + file_bytes + 1024
