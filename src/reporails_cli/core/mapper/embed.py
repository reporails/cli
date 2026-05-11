"""Mapper Stage 5: Embed atoms via the ONNX MiniLM-L6-v2 encoder.

Builds embedding text from `atom.plain_text` only (no heading prepend, to avoid
double-counting heading atoms and artificial clustering by heading structure).
Deduplicates identical text values before the model call so each unique string
hits the encoder exactly once per run. Quantises the float32 output to int8 for
compact wire-format storage; the per-vector scale is not retained because
cosine similarity is preserved under L2 normalisation.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord


def _embed_text(atom: Atom) -> str:
    """Build embedding text for an atom.

    Uses plain_text (AST-stripped) for cleaner embeddings — formatting markers
    (**bold**, *italic*, `backtick`) add noise without semantic content.
    Heading context is NOT prepended — headings are their own atoms.
    Prepending created double-counting and artificial clustering by
    heading rather than by semantic content.
    """
    return atom.plain_text or atom.text


def _quantize_int8(vec: Any) -> tuple[int, ...]:
    """Quantize a float32 embedding vector to int8 (-128..127).

    Preserves cosine similarity with < 1% error for all-MiniLM-L6-v2 vectors.
    """
    import numpy as np

    arr = np.asarray(vec, dtype=np.float32)
    # Scale to [-127, 127] range based on max absolute value
    scale = max(float(np.abs(arr).max()), 1e-10)
    quantized = np.clip(np.round(arr * 127.0 / scale), -128, 127).astype(np.int8)
    return tuple(int(v) for v in quantized)


def _embed_atoms_deduped(atoms: list[Atom], encoder: Any) -> None:
    """Embed atoms with deduplication. Atoms with identical text share embeddings."""
    texts = [_embed_text(a) for a in atoms]
    unique_texts: list[str] = []
    text_index: dict[str, int] = {}
    atom_to_unique: list[int] = []
    for t in texts:
        idx = text_index.get(t)
        if idx is None:
            idx = len(unique_texts)
            text_index[t] = idx
            unique_texts.append(t)
        atom_to_unique.append(idx)
    unique_embeddings = encoder.encode(unique_texts)
    for atom, u_idx in zip(atoms, atom_to_unique, strict=True):
        atom.embedding_int8 = _quantize_int8(unique_embeddings[u_idx])


def _embed_file_descriptions(file_records: list[FileRecord], encoder: Any) -> None:
    """Embed frontmatter descriptions for on_invocation files."""
    desc_texts = [fr.description for fr in file_records if fr.description]
    if not desc_texts:
        return
    desc_embeddings = encoder.encode(desc_texts)
    desc_idx = 0
    for fr in file_records:
        if fr.description:
            fr.description_embedding = _quantize_int8(desc_embeddings[desc_idx])
            desc_idx += 1
