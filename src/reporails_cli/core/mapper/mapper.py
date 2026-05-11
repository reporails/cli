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
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reporails_cli.core.mapper.cluster import cluster_topics
from reporails_cli.core.mapper.embed import _embed_atoms_deduped, _embed_file_descriptions
from reporails_cli.core.mapper.imports import expand_imports
from reporails_cli.core.mapper.models import Models, get_models
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.serialize import validate_atoms
from reporails_cli.core.platform.dto.ruleset import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    Atom,
    ClusterRecord,
    FileRecord,
    RulesetMap,
    RulesetSummary,
    TopicCluster,
)

if TYPE_CHECKING:
    pass  # sentence_transformers types if needed

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────
# RULESET MAP CONSTRUCTION
# ──────────────────────────────────────────────────────────────────


def content_hash(text: str) -> str:
    """Compute SHA-256 hash of text with sha256: prefix."""
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def map_file(path: Path) -> tuple[list[Atom], str]:
    """Classify a single instruction file into atoms.

    Returns:
        (atoms, content_hash)
    """
    content = path.read_text(encoding="utf-8", errors="replace")
    atoms = tokenize(content)
    for a in atoms:
        a.file_path = str(path)
    return atoms, content_hash(content)


def _extract_frontmatter_yaml(path: Path) -> str:
    """Read a file and return the raw YAML frontmatter block, or empty string."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    return text[3:end] if end != -1 else ""


def _parse_frontmatter_description(path: Path) -> str:
    """Extract name + description from YAML frontmatter.

    These fields are surfaced into the model's base context by all agents
    (Agent Skills standard) for skill/agent discoverability. The combined
    string is what competes for attention even when the file isn't invoked.
    """
    raw = _extract_frontmatter_yaml(path)
    if not raw:
        return ""
    try:
        import yaml

        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            return ""
        name = str(data.get("name", ""))
        desc = str(data.get("description", ""))
        return f"{name}: {desc}" if name and desc else (name or desc)
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        return ""


def _parse_frontmatter_globs(path: Path) -> tuple[str, ...]:
    """Extract globs from YAML frontmatter of a rule/skill file."""
    raw = _extract_frontmatter_yaml(path)
    if not raw:
        return ()
    try:
        import yaml

        data = yaml.safe_load(raw)
        if not isinstance(data, dict) or "globs" not in data:
            return ()
        globs = data["globs"]
        if isinstance(globs, list):
            return tuple(str(g) for g in globs)
        if isinstance(globs, str):
            return (globs,)
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        pass
    return ()


def _load_registry() -> dict[str, dict[str, Any]]:
    """Load all agent registry configs. Returns {agent: config_dict}."""
    try:
        from reporails_cli.core.platform.config.bootstrap import get_rules_path

        registry_dir = get_rules_path()
    except ImportError:
        registry_dir = Path(__file__).parent.parent / "data" / "registry"
    configs: dict[str, dict[str, Any]] = {}
    if not registry_dir.is_dir():
        return configs
    try:
        import yaml
    except ImportError:
        return configs
    for config_path in sorted(registry_dir.glob("*/config.yml")):
        try:
            data = yaml.safe_load(config_path.read_text())
            agent = data.get("agent", config_path.parent.name)
            configs[agent] = data
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Failed to load agent config %s: %s", config_path, exc)
            continue
    return configs


def _find_best_registry_match(
    rel_lower: str,
    registry: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    """Find the most specific registry pattern match for a file path.

    Returns (agent_id, properties) or None if no match.
    """
    import fnmatch

    from reporails_cli.core.discovery.agents import _extract_patterns, _extract_properties

    best: tuple[int, str, dict[str, Any]] | None = None  # (specificity, agent, props)

    for agent_id, config in registry.items():
        for ft in (config.get("file_types") or {}).values():
            patterns = _extract_patterns(ft) if isinstance(ft, dict) else []
            props = ft.get("properties", {}) if isinstance(ft, dict) else {}
            if not props:
                props = _extract_properties(ft) if isinstance(ft, dict) else {}
            for pat in patterns:
                pat_lower = pat.lower()
                candidates = [pat_lower]
                if "**/" in pat_lower:
                    candidates.append(pat_lower.replace("**/", ""))
                    candidates.append(pat_lower.replace("**/", "*/"))
                if any(fnmatch.fnmatch(rel_lower, c) for c in candidates):
                    specificity = len(pat_lower.split("*")[0])
                    if best is None or specificity > best[0]:
                        best = (specificity, agent_id, props)

    if best is None:
        return None
    return best[1], best[2]


def _detect_file_loading(
    path: Path,
    root: Path,
    registry: dict[str, dict[str, Any]],
) -> tuple[str, str, tuple[str, ...], str]:
    """Determine loading/scope/globs/agent for an instruction file.

    Matches the file against all agent registry patterns.
    Falls back to session_start/global/generic if no match.

    Returns:
        (loading, scope, globs, agent)
    """
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    match = _find_best_registry_match(rel.lower(), registry)
    if match is None:
        return "session_start", "global", (), "generic"

    agent_id, props = match
    loading = props.get("loading", "session_start")
    scope = props.get("scope", "global")
    globs: tuple[str, ...] = ()
    if loading in ("on_demand", "on_invocation"):
        globs = _parse_frontmatter_globs(path)
    if loading == "on_demand" and not globs:
        loading = "session_start"
        scope = "global"
    return loading, scope, globs, agent_id


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

    raw_content = path.read_text(encoding="utf-8", errors="replace")
    content = expand_imports(raw_content, path)
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


def _build_ruleset_map(
    file_records: list[FileRecord],
    all_atoms: list[Atom],
    topics: list[TopicCluster],
) -> RulesetMap:
    """Assemble the final RulesetMap from classified and clustered data."""
    cluster_records = [
        ClusterRecord(
            id=tc.topic_id,
            n_atoms=len(tc.atoms),
            n_charged=len(tc.charged),
            n_neutral=len(tc.atoms) - len(tc.charged),
            centroid=tc.centroid,
        )
        for tc in topics
    ]

    n_charged = sum(1 for a in all_atoms if a.charge_value != 0)
    summary = RulesetSummary(
        n_atoms=len(all_atoms),
        n_charged=n_charged,
        n_neutral=len(all_atoms) - n_charged,
        n_topics=len(topics),
        n_topics_charged=sum(1 for tc in topics if tc.charged),
    )

    return RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at=datetime.now(UTC).isoformat(),
        files=tuple(file_records),
        atoms=tuple(all_atoms),
        clusters=tuple(cluster_records),
        summary=summary,
    )


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

    # Embed uncached atoms
    if atoms_needing_embed:
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

    ruleset = _build_ruleset_map(file_records, all_atoms, cluster_topics(all_atoms))
    _validate_and_log(ruleset)

    return ruleset
