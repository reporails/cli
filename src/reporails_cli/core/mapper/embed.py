"""Embed atoms via the bundled embedding encoder.

Builds embedding text from `atom.plain_text` only (no heading prepend).
Quantises the float32 output to int8.
"""

from __future__ import annotations

from collections.abc import Callable
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

    Keeps cosine similarity between vectors close to the float original.
    """
    import numpy as np

    arr = np.asarray(vec, dtype=np.float32)
    # Scale to [-127, 127] range based on max absolute value
    scale = max(float(np.abs(arr).max()), 1e-10)
    quantized = np.clip(np.round(arr * 127.0 / scale), -128, 127).astype(np.int8)
    return tuple(int(v) for v in quantized)


def _embed_atoms_deduped(atoms: list[Atom], encoder: Any) -> None:
    """Embed atoms and store each one's int8 embedding."""
    embeddings = encoder.encode([_embed_text(a) for a in atoms])
    for atom, vec in zip(atoms, embeddings, strict=True):
        atom.embedding_int8 = _quantize_int8(vec)


def _embed_file_descriptions(file_records: list[FileRecord], encoder: Callable[[], Any]) -> list[FileRecord]:
    """Embed the frontmatter descriptions of on_invocation files that carry no embedding yet.

    `encoder` returns the embedder; it is called only when some description is still
    unembedded, so a map whose records all arrive embedded (read back from the per-file
    cache) never loads the model. Identical descriptions are encoded once. Returns the
    records embedded here, for the caller to persist.
    """
    pending = [fr for fr in file_records if fr.description and fr.description_embedding is None]
    if not pending:
        return []
    texts = sorted({fr.description for fr in pending})
    quantized = {t: _quantize_int8(v) for t, v in zip(texts, encoder().encode(texts), strict=True)}
    for fr in pending:
        fr.description_embedding = quantized[fr.description]
    return pending
