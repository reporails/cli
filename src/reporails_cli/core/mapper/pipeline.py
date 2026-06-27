"""Mapper — client-side spectrograph for instruction file analysis.

Classifies instruction files into atoms, embeds them, clusters by topic,
and produces a compact RulesetMap. This module is the client-side component
of the reporails architecture — classification, embedding, and clustering.

The RulesetMap is the wire format: ~32KB covering an entire instruction
ruleset, suitable for transmission to the diagnostic API.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reporails_cli.core.mapper.assemble import build_ruleset_map
from reporails_cli.core.mapper.cluster import cluster_topics
from reporails_cli.core.mapper.embed import _embed_atoms_deduped, _embed_file_descriptions
from reporails_cli.core.mapper.imports import expand_imports
from reporails_cli.core.mapper.inspect import (
    _detect_file_loading,
    _load_registry,
    _parse_frontmatter_description,
)
from reporails_cli.core.mapper.models import Models, get_models
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.serialize import validate_atoms
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap

if TYPE_CHECKING:
    pass  # sentence_transformers types if needed

logger = logging.getLogger(__name__)


def content_hash(text: str) -> str:
    """Compute SHA-256 hash of text with sha256: prefix."""
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def map_file(path: Path) -> tuple[list[Atom], str]:
    """Classify a single instruction file into atoms.

    Returns:
        (atoms, content_hash)
    """
    from reporails_cli.core.lint.suppression import strip_directives

    content = strip_directives(path.read_text(encoding="utf-8", errors="replace"))
    atoms = tokenize(content)
    for a in atoms:
        a.file_path = str(path)
    return atoms, content_hash(content)


def _classify_file(
    path: Path,
    map_cache: Any,
    all_atoms: list[Atom],
    atoms_needing_embed: list[Atom],
) -> str:
    """Classify a single file: tokenize or use cache. Returns content hash."""
    from reporails_cli.core.cache.map_cache import (
        CachedFileEntry,
        atoms_to_dicts,
        dicts_to_atoms,
    )
    from reporails_cli.core.lint.suppression import strip_directives

    raw_content = path.read_text(encoding="utf-8", errors="replace")
    content = strip_directives(expand_imports(raw_content, path))
    chash = content_hash(content)

    cached = map_cache.get(chash) if map_cache else None
    if cached is not None:
        atoms = dicts_to_atoms(cached.atoms)
        for a in atoms:
            a.file_path = str(path)
        all_atoms.extend(atoms)
    else:
        atoms = tokenize(content)
        for a in atoms:
            a.file_path = str(path)
        all_atoms.extend(atoms)
        atoms_needing_embed.extend(atoms)
        if map_cache is not None:
            map_cache.put(chash, CachedFileEntry(chash, atoms_to_dicts(atoms)))

    return chash


def _update_cache_after_embedding(
    map_cache: Any,
    all_atoms: list[Atom],
    atoms_needing_embed: list[Atom],
    file_records: list[FileRecord],
) -> None:
    """Update cache entries with embeddings for newly-embedded atoms."""
    from reporails_cli.core.cache.map_cache import CachedFileEntry, atoms_to_dicts

    by_file: dict[str, list[Atom]] = {}
    for a in all_atoms:
        by_file.setdefault(a.file_path, []).append(a)
    embed_set = {id(a) for a in atoms_needing_embed}
    for frec in file_records:
        file_atoms = by_file.get(frec.path, [])
        if any(id(a) in embed_set for a in file_atoms):
            map_cache.put(frec.content_hash, CachedFileEntry(frec.content_hash, atoms_to_dicts(file_atoms)))


def _validate_and_log(ruleset: RulesetMap) -> None:
    """Validate atoms, log findings, raise on errors."""
    findings = validate_atoms(ruleset.atoms)
    for f in findings:
        if f.severity == "error":
            logger.error("Map validation: [%s] L%d: %s — %s", f.rule, f.line, f.message, f.text)
        elif f.severity == "warn":
            logger.warning("Map validation: [%s] L%d: %s — %s", f.rule, f.line, f.message, f.text)
    errors = [f for f in findings if f.severity == "error"]
    if errors:
        raise ValueError(
            f"Map validation failed with {len(errors)} error(s). First: [{errors[0].rule}] {errors[0].message}"
        )


def _classify_all_files(
    paths: list[Path],
    root: Path,
    map_cache: Any,
    registry: dict[str, dict[str, Any]],
) -> tuple[list[FileRecord], list[Atom], list[Atom]]:
    """Classify all instruction files. Returns (file_records, all_atoms, atoms_needing_embed)."""
    file_records: list[FileRecord] = []
    all_atoms: list[Atom] = []
    atoms_needing_embed: list[Atom] = []

    for path in paths:
        chash = _classify_file(path, map_cache, all_atoms, atoms_needing_embed)
        loading, scope, globs, agent = _detect_file_loading(path, root, registry)
        desc = _parse_frontmatter_description(path) if loading == "on_invocation" else ""
        file_records.append(
            FileRecord(
                path=str(path),
                content_hash=chash,
                loading=loading,
                scope=scope,
                globs=globs,
                agent=agent,
                description=desc,
            )
        )

    return file_records, all_atoms, atoms_needing_embed


def map_ruleset(
    paths: list[Path],
    *,
    models: Models | None = None,
    root: Path | None = None,
    cache_dir: Path | None = None,
) -> RulesetMap:
    """Build a compact ruleset map from instruction files.

    This is the main client-side entry point. Classifies all files,
    embeds atoms, clusters by topic, and produces the wire format.

    When cache_dir is provided, uses incremental caching: unchanged files
    (by content hash) reuse cached atoms and embeddings. Only changed
    files are re-tokenized and re-embedded. Clustering always re-runs.
    """
    from reporails_cli.core.cache.map_cache import MapCache
    from reporails_cli.core.platform.observability.stage_timer import get_stage_timer

    timer = get_stage_timer()

    if models is None:
        models = get_models()
    if root is None:
        root = paths[0].parent if paths else Path(".")

    map_cache: MapCache | None = None
    if cache_dir is not None:
        map_cache = MapCache(cache_dir)
        map_cache.load()

    file_records, all_atoms, atoms_needing_embed = _classify_all_files(
        paths,
        root,
        map_cache,
        _load_registry(),
    )
    timer.mark("classify")

    # Embed uncached atoms. Force the lazy ONNX load before the first encode so
    # the model-load cost times apart from embed-inference — on a warm daemon
    # the model is already resident and this load mark reads ~0.
    if atoms_needing_embed:
        _ = models.st
        timer.mark("load")
        _embed_atoms_deduped(atoms_needing_embed, models.st)
        if map_cache is not None:
            _update_cache_after_embedding(map_cache, all_atoms, atoms_needing_embed, file_records)

    # Enforce cache cap (LRU eviction) and save
    if map_cache is not None:
        map_cache.enforce_cap()
        map_cache.save()

    # Ensure ALL atoms have embeddings (cached atoms may lack them)
    unembedded = [a for a in all_atoms if a.embedding_int8 is None]
    if unembedded:
        _embed_atoms_deduped(unembedded, models.st)

    _embed_file_descriptions(file_records, models.st)
    timer.mark("embed")

    clusters = cluster_topics(all_atoms)
    timer.mark("cluster")

    ruleset = build_ruleset_map(file_records, all_atoms, clusters)
    _validate_and_log(ruleset)

    return ruleset
