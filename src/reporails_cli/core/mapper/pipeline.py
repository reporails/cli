"""Mapper — local analysis of instruction files.

Classifies instruction files into atoms, embeds them, and produces a compact
RulesetMap covering the whole instruction ruleset.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reporails_cli.core.cache.map_cache import cache_key_for_path, content_hash, file_cache_key
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.assemble import build_ruleset_map
from reporails_cli.core.mapper.embed import _embed_atoms_deduped, _embed_file_descriptions
from reporails_cli.core.mapper.granularity import audit_over_merged
from reporails_cli.core.mapper.imports import expand_imports_with_origins
from reporails_cli.core.mapper.inspect import (
    _detect_file_activation,
    _load_registry,
    _parse_frontmatter_description,
)
from reporails_cli.core.mapper.models import Models, get_models
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.prose_split import SEGMENTATION_STRUCTURE_AWARE
from reporails_cli.core.mapper.serialize import validate_atoms
from reporails_cli.core.mapper.split_topic import split_over_merged_atoms
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap
from reporails_cli.core.platform.observability.stage_timer import get_stage_timer as _get_stage_timer

logger = logging.getLogger(__name__)


def _translate_atom_lines(
    atoms: list[Atom],
    line_map: list[int],
    origins: list[tuple[Path, int] | None],
    path: Path,
) -> None:
    """Rewrite each atom's `line` from import-EXPANDED coordinates back to the
    importing file's own source line, and name where an imported atom is written.

    `line_map[i]` (0-based) is the 1-based source line for expanded line
    `i + 1` (see `expand_imports_with_origins`). An atom whose own line
    originates inside imported content is attributed to the `@import`
    reference line that pulled it in — it has no line of its own in the
    importing file — and carries the imported file (relative to `path`'s
    directory) and its line there, so a finding on it can name them. A no-op on
    a file with no imports, since the map is then the identity map.
    """
    for a in atoms:
        idx = a.line - 1
        if not 0 <= idx < len(line_map):
            continue
        a.line = line_map[idx]
        origin = origins[idx]
        if origin is not None:
            a.imported_from = Path(os.path.relpath(origin[0], safe_resolve(path).parent)).as_posix()
            a.imported_line = origin[1]


def _atoms_from_cache(cached: Any, path: Path) -> list[Atom]:
    """Rehydrate cached atoms for `path`.

    Lines were already translated to source coordinates the first time this
    content was tokenized (`_tokenize_and_cache`); the cache identity
    (`map_cache._CACHE_VERSION`) folds that shape, so a pre-translation entry
    never reaches here. Entries only ever land in the persistent cache via
    `_update_cache_after_embedding` (post charge + embed), so a hit here is
    always a fully-charged, embedded atom set — never a same-run duplicate's
    pre-charge tokenization (see `_tokenize_and_cache`).
    """
    from reporails_cli.core.cache.map_cache import dicts_to_atoms

    atoms = dicts_to_atoms(cached.atoms)
    for a in atoms:
        a.file_path = path.as_posix()
    return atoms


def _tokenize_and_cache(
    path: Path,
    content: str,
    line_map: list[int],
    origins: list[tuple[Path, int] | None],
    segmentation: str,
) -> list[Atom]:
    """Tokenize fresh content and translate atom lines back to source.

    Deliberately does NOT write to `map_cache`: an atom fresh out of `tokenize()`
    carries only the tokenize-time lexical charge (`stage=""`, no `so` block) —
    charge classification (`_apply_charge_stage`) and embedding still need to
    run on it. Writing here would let a later same-run file with identical
    content (`_classify_file`'s cache lookup keys on content hash only) hit this
    pre-charge entry and skip those steps. The sole cache writer is
    `_update_cache_after_embedding`, which runs after both steps — so a
    same-run duplicate always finds either no entry (both copies go fresh
    through every step) or a fully-charged one.
    """
    atoms = tokenize(content, segmentation)
    _translate_atom_lines(atoms, line_map, origins, path)
    for a in atoms:
        a.file_path = path.as_posix()
    return atoms


def _classify_file(
    path: Path,
    map_cache: Any,
    all_atoms: list[Atom],
    atoms_needing_embed: list[Atom],
    segmentation: str = "legacy",
) -> str:
    """Classify a single file: tokenize or use cache. Returns content hash.

    A cache hit only ever serves a fully-charged, embedded entry (see
    `_tokenize_and_cache`), so a same-run content-identical file that missed the
    cache goes fresh through charge + embed exactly like the first copy — it is
    never short-circuited by an earlier, not-yet-charged same-run write.
    """
    from reporails_cli.core.lint.suppression import strip_directives

    expanded, line_map, origins = expand_imports_with_origins(path.read_text(encoding="utf-8", errors="replace"), path)
    content = strip_directives(expanded)
    chash = content_hash(content)

    cached = map_cache.get(file_cache_key(path, chash, line_map, origins)) if map_cache else None
    if cached is not None:
        all_atoms.extend(_atoms_from_cache(cached, path))
    else:
        atoms = _tokenize_and_cache(path, content, line_map, origins, segmentation)
        all_atoms.extend(atoms)
        atoms_needing_embed.extend(atoms)

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
            try:
                key = cache_key_for_path(Path(frec.path))
            except OSError:
                continue
            map_cache.put(key, CachedFileEntry(key, atoms_to_dicts(file_atoms)))


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


def _element_label(path: Path, root: Path | None = None) -> str:
    """Coarsen a file's classify tag to its harness-element group for progress.

    `classify_file` returns finer tags (`skills:<name>`, `agents:<stem>`,
    `rules:<stem>`); the progress counter groups by the tag's base (skills / agents /
    rules / main / nested / memory / config). `root` is threaded so the top-level
    instruction file reads `main`, not `nested`, on the absolute paths discovery
    actually yields.
    """
    from reporails_cli.core.classify.file_tags import classify_file

    return classify_file(str(path), root=root).split(":", 1)[0]


def _element_progress_reporter(
    paths: list[Path], progress: Callable[[str], None] | None, root: Path | None = None
) -> Callable[[int], None]:
    """Build a per-index reporter that emits ``Mapping <element>: <i>/<n>``.

    Precomputes each path's harness-element group and the per-element totals so
    the classify loop stays a single call; a no-op when ``progress`` is None.
    """
    if progress is None:
        return lambda _idx: None
    elements = [_element_label(p, root) for p in paths]
    totals: dict[str, int] = {}
    for element in elements:
        totals[element] = totals.get(element, 0) + 1
    seen: dict[str, int] = {}

    def report(idx: int) -> None:
        element = elements[idx]
        seen[element] = seen.get(element, 0) + 1
        progress(f"Mapping {element}: {seen[element]}/{totals[element]}")

    return report


def _classify_all_files(
    paths: list[Path],
    root: Path,
    map_cache: Any,
    registry: dict[str, dict[str, Any]],
    segmentation: str = "legacy",
    progress: Callable[[str], None] | None = None,
) -> tuple[list[FileRecord], list[Atom], list[Atom]]:
    """Classify all instruction files. Returns (file_records, all_atoms, atoms_needing_embed).

    When ``progress`` is given, emits a per-harness-element counter
    (``Mapping agents: 2/14``) as each file is classified, so a caller's spinner
    advances through the map instead of parking on a single label.
    """
    file_records: list[FileRecord] = []
    all_atoms: list[Atom] = []
    atoms_needing_embed: list[Atom] = []

    report_progress = _element_progress_reporter(paths, progress, root)

    for idx, path in enumerate(paths):
        report_progress(idx)
        file_records.append(
            _classify_one_file(path, root, map_cache, registry, all_atoms, atoms_needing_embed, segmentation)
        )

    return file_records, all_atoms, atoms_needing_embed


def _classify_one_file(
    path: Path,
    root: Path,
    map_cache: Any,
    registry: dict[str, dict[str, Any]],
    all_atoms: list[Atom],
    atoms_needing_embed: list[Atom],
    segmentation: str,
) -> FileRecord:
    """Classify one instruction file, appending its atoms to the shared lists."""
    loading, scope, globs, agent, file_type, activation = _detect_file_activation(path, root, registry)
    chash = _classify_file(path, map_cache, all_atoms, atoms_needing_embed, segmentation)
    description = _parse_frontmatter_description(path) if loading == "on_invocation" else ""
    return FileRecord(
        path=path.as_posix(),
        content_hash=chash,
        loading=loading,
        scope=scope,
        globs=globs,
        agent=agent,
        type=file_type,
        activation=activation,
        description=description,
        description_embedding=map_cache.description_embedding(path) if map_cache and description else None,
    )


def _embed_and_audit_fresh(
    atoms_needing_embed: list[Atom],
    all_atoms: list[Atom],
    file_records: list[FileRecord],
    map_cache: Any,
    models: Models,
    timer: Any,
    structure_aware: bool,
) -> None:
    """Embed the fresh atoms, run the granularity audit, and re-put the cache.

    Force the lazy ONNX load before the first encode so the model-load cost times
    apart from embed-inference. The audit is skipped under structure-aware mode —
    the clause split it feeds is suppressed, so its flags would never be consumed.
    """
    if not atoms_needing_embed:
        return
    _ = models.st
    timer.mark("load")
    _embed_atoms_deduped(atoms_needing_embed, models.st)
    if not structure_aware:
        audit_over_merged(atoms_needing_embed, models.st)
    if map_cache is not None:
        _update_cache_after_embedding(map_cache, all_atoms, atoms_needing_embed, file_records)


def _open_map_cache(cache_dir: Path | None, segmentation: str) -> Any:
    """Open the incremental map cache keyed to the current classification-model
    fingerprint, or None.

    The identity folds that fingerprint so cached atoms never cross model
    versions (an updated bundled model re-keys).
    """
    if cache_dir is None:
        return None
    from reporails_cli.core.cache.map_cache import MapCache
    from reporails_cli.core.mapper.bio_tagger import multislot_fingerprint

    charge_id = multislot_fingerprint()
    map_cache = MapCache(cache_dir, segmentation=segmentation, charge=charge_id)
    map_cache.load()
    return map_cache


def _fill_missing_embeddings(all_atoms: list[Atom], models: Models) -> None:
    """Ensure ALL atoms have embeddings (cached atoms may lack them)."""
    unembedded = [a for a in all_atoms if a.embedding_int8 is None]
    if unembedded:
        _embed_atoms_deduped(unembedded, models.st)


def _charge_applier() -> Any:
    """Return the per-file charge function, or None when the bundled classification models are absent."""
    from reporails_cli.core.mapper.bio_pipeline import apply_multislot
    from reporails_cli.core.mapper.bio_tagger import multislot_available

    return apply_multislot if multislot_available() else None


def _apply_charge_stage(
    all_atoms: list[Atom], atoms_needing_embed: list[Atom], progress: Callable[[str], None] | None = None
) -> tuple[list[Atom], list[Atom]]:
    """Charge classification — classifies each atom's charge, replacing the tokenize-time
    lexical charge and prose splits when the bundled classification models are
    available.

    Fresh files' atoms are rebuilt per file (per-file position re-index); cached
    atoms already carry their charge from a prior run (the cache identity folds
    the model fingerprint). No-op when the bundled classification models are
    not available, so atoms keep the tokenize-time lexical charge.

    All fresh files go through one batched call; ``progress`` receives a live
    ``done/total`` counter.
    """
    if _charge_applier() is None:
        return all_atoms, atoms_needing_embed
    from reporails_cli.core.mapper.bio_pipeline import apply_multislot_groups

    fresh_ids = {id(a) for a in atoms_needing_embed}
    groups: list[tuple[str, list[Atom]]] = []
    for atom in all_atoms:
        if groups and groups[-1][0] == atom.file_path:
            groups[-1][1].append(atom)
        else:
            groups.append((atom.file_path, [atom]))

    fresh_positions = [i for i, (_p, g) in enumerate(groups) if any(id(a) in fresh_ids for a in g)]
    fresh_lists = [groups[i][1] for i in fresh_positions]
    total = sum(len(g) for g in fresh_lists)

    def _report(done: int, count: int) -> None:
        if progress is not None:
            progress(f"Analyzing instructions: {done}/{count}")

    rebuilt_fresh = apply_multislot_groups(fresh_lists, _report) if total else []

    remap = dict(zip(fresh_positions, rebuilt_fresh, strict=True))

    rebuilt: list[Atom] = []
    fresh_out: list[Atom] = []
    for i, (_path, group) in enumerate(groups):
        new_group = remap.get(i)
        if new_group is not None:
            rebuilt.extend(new_group)
            fresh_out.extend(new_group)
        else:
            rebuilt.extend(group)
    return rebuilt, fresh_out


def _count_over_merged(atoms: list[Atom]) -> int:
    """Count atoms the granularity audit flagged `over_merged`, pre-split.

    `RulesetSummary.n_over_merged` documents this as the audit's flag count
    (`core/platform/dto/ruleset.py`), which is not the same number as how many
    units the later split actually cut: a flagged unit whose split
    yields fewer than two clauses, or that was already cut into several
    instructions, stays flagged but unsplit. The count is read here, right
    before `_topic_split_if_enabled` replaces split units with
    their sub-atoms, so it stays the number of flagged units.
    """
    return sum(1 for a in atoms if a.over_merged)


def _topic_split_if_enabled(all_atoms: list[Atom], models: Models, *, structure_aware: bool) -> tuple[list[Atom], int]:
    """Boundary-aware topic split, unless structure-aware mode is on.

    Over-merged atoms (flagged by the granularity audit, from cache or fresh) split
    at clause boundaries into per-topic sub-atoms; runs over the full set so cached
    over-merged atoms split too. Sub-atoms are re-charged through the same charge
    source as the rest of the map. Suppressed under structure-aware mode, where
    prose is already whole-sentence and list/numbered items stay whole.

    Guarded on `over_merged`: `split_over_merged_atoms` is itself a no-op when no
    atom is flagged (every atom's clause list comes out empty, so `fresh` stays
    empty and its own encoder call never fires) — but `models.st` is a lazy
    ONNX-loading property, and passing it as this call's second positional
    argument forces that load at the call site regardless. Skipping the call
    entirely when nothing is flagged keeps a fully warm map from ever touching
    the embedder.
    """
    if structure_aware:
        return all_atoms, 0
    if not any(a.over_merged for a in all_atoms):
        return all_atoms, 0
    return split_over_merged_atoms(
        all_atoms,
        models.st,
        recharge=lambda _: None,
    )


def _embed_file_descriptions_if_any(file_records: list[FileRecord], models: Models, map_cache: Any) -> None:
    """Embed the on_invocation file descriptions that did not come back from the per-file cache.

    The embedder (`models.st`, a lazy ONNX-loading property) is handed over as a callable, so
    a map whose descriptions all came from the cache, or that has none, never touches it.
    What is embedded here is stored with the file's cache entry for the next run.
    """
    embedded = _embed_file_descriptions(file_records, lambda: models.st)
    if map_cache is not None:
        map_cache.store_description_embeddings(embedded)


def _classify_charge_embed_dispatch(
    paths: list[Path],
    root: Path,
    cache_dir: Path | None,
    models: Models,
    segmentation: str,
    timer: Any,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[FileRecord], list[Atom]]:
    """Classify all files, then charge + embed the fresh atoms, then persist.

    The tokenize + cache lookup runs first (cheap, no inference), then the expensive
    per-atom charge + embedding runs in this process, where the encode fans its
    per-bucket forwards across a shared-session thread pool. The charge decode is
    batched across all fresh files at once so the pool stays full.
    """
    # Derived here and in map_ruleset from the same `segmentation`; kept local
    # rather than passed to hold the dispatch under the pylint arg-count baseline.
    structure_aware = segmentation == SEGMENTATION_STRUCTURE_AWARE
    map_cache = _open_map_cache(cache_dir, segmentation)
    file_records, all_atoms, atoms_needing_embed = _classify_all_files(
        paths,
        root,
        map_cache,
        _load_registry(),
        segmentation,
        progress=progress,
    )
    timer.mark("classify")
    if progress is not None:
        progress("Mapping done")

    had_fresh = bool(atoms_needing_embed)
    if atoms_needing_embed:
        all_atoms, atoms_needing_embed = _apply_charge_stage(all_atoms, atoms_needing_embed, progress)
    _embed_and_audit_fresh(atoms_needing_embed, all_atoms, file_records, map_cache, models, timer, structure_aware)
    _embed_file_descriptions_if_any(file_records, models, map_cache)
    # Fire the completion flash only after BOTH charge and the (silent) embed finish,
    # so the label never claims "done" while the embed step is still running.
    if had_fresh and progress is not None:
        progress("Analyzing instructions done")

    if map_cache is not None:
        map_cache.enforce_cap()
        map_cache.save()
    _fill_missing_embeddings(all_atoms, models)
    return file_records, all_atoms


def map_ruleset(
    paths: list[Path],
    *,
    models: Models | None = None,
    root: Path | None = None,
    cache_dir: Path | None = None,
    segmentation: str = "legacy",
    progress: Callable[[str], None] | None = None,
) -> RulesetMap:
    """Build a compact ruleset map from instruction files.

    This is the main client-side entry point. Classifies all files,
    embeds atoms, and produces the wire format.

    When cache_dir is provided, uses incremental caching: unchanged files
    (by content hash) reuse cached atoms and embeddings. Only changed
    files are re-tokenized and re-embedded.

    `segmentation` selects the atomizer boundary policy (`legacy` |
    `structure-aware`). It is folded into the cache identity so cached atoms
    never cross modes, and it suppresses the clause split under
    structure-aware mode.

    The classification-model fingerprint folds into the cache identity too, so
    cached atoms never cross model versions.
    """
    from reporails_cli.core.mapper.bio_tagger import multislot_available

    if not multislot_available():
        raise RuntimeError("the reporails model is not complete on disk; fetch it by running `ails check` online")
    timer = _get_stage_timer()
    structure_aware = segmentation == SEGMENTATION_STRUCTURE_AWARE

    if models is None:
        models = get_models()
    if root is None:
        root = paths[0].parent if paths else Path(".")

    # Map every file (across worker processes when enabled), then save the
    # per-file cache. The result is order-stable, so it does not
    # depend on how the file list was split.
    file_records, all_atoms = _classify_charge_embed_dispatch(
        paths, root, cache_dir, models, segmentation, timer, progress
    )
    n_over_merged = _count_over_merged(all_atoms)

    all_atoms, n_split = _topic_split_if_enabled(all_atoms, models, structure_aware=structure_aware)
    timer.mark("embed")

    ruleset = build_ruleset_map(file_records, all_atoms)
    ruleset.summary.n_over_merged = n_over_merged
    if n_split:
        logger.info("Granularity: split %d over-merged atoms at clause boundaries", n_split)
    _validate_and_log(ruleset)

    return ruleset
