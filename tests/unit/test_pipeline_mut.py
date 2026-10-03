"""Mutation-closing behavioral tests for mapper/pipeline.py.

Each test reddens when a specific operator mutation is reintroduced into the
source (verified with scripts/mutation_probe.py). Scope is LOCAL pipeline
wiring: validation severity routing, cache open, embedding backfill, the
topic-split gate, file-record description, and map_ruleset argument plumbing.
These tests stub the model-bearing stages so no model loads.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.mapper import pipeline as pl

# --- L121/L123/L125: _validate_and_log severity routing ---


def _finding(sev):
    return SimpleNamespace(severity=sev, rule="R1", line=1, message="m", text="t")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_warn_finding_logs_warning_not_error(monkeypatch, caplog):
    """A 'warn' finding logs at WARNING, never ERROR (L121/L123 `==`)."""
    monkeypatch.setattr(pl, "validate_atoms", lambda atoms: [_finding("warn")])
    ruleset = SimpleNamespace(atoms=())
    with caplog.at_level("WARNING"):
        pl._validate_and_log(ruleset)  # no error findings -> no raise
    levels = {r.levelname for r in caplog.records}
    assert "WARNING" in levels
    assert "ERROR" not in levels


@pytest.mark.unit
@pytest.mark.subsys_map
def test_error_finding_raises(monkeypatch):
    """An 'error' finding must raise ValueError (L125 `== "error"`)."""
    monkeypatch.setattr(pl, "validate_atoms", lambda atoms: [_finding("error")])
    ruleset = SimpleNamespace(atoms=())
    with pytest.raises(ValueError):
        pl._validate_and_log(ruleset)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_warn_only_does_not_raise(monkeypatch):
    """Warn-only findings must NOT raise (guards L125)."""
    monkeypatch.setattr(pl, "validate_atoms", lambda atoms: [_finding("warn")])
    pl._validate_and_log(SimpleNamespace(atoms=()))  # must not raise


# --- L195: _open_map_cache None guard ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_open_map_cache_none_returns_none():
    """cache_dir=None must short-circuit to None (L195 `is None`)."""
    assert pl._open_map_cache(None, "legacy") is None


# --- L200: _open_map_cache charge identity ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_open_map_cache_charge_identity(monkeypatch, tmp_path):
    """The cache key is the charge-head fingerprint (a head re-export re-keys)."""
    import reporails_cli.core.cache.map_cache as mc
    import reporails_cli.core.mapper.bio_tagger as bt

    captured = {}

    class _FakeCache:
        def __init__(self, cache_dir, segmentation, charge):
            captured["charge"] = charge

        def load(self):
            return None

    monkeypatch.setattr(mc, "MapCache", _FakeCache)
    monkeypatch.setattr(bt, "multislot_fingerprint", lambda: "MS")
    pl._open_map_cache(tmp_path, "legacy")
    assert captured["charge"] == "MS"


# --- L208: _fill_missing_embeddings selects the unembedded atoms ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fill_missing_embeddings_targets_none_embeddings(monkeypatch):
    """Only atoms whose embedding is None get embedded (L208 `is None`)."""
    captured = {}
    monkeypatch.setattr(pl, "_embed_atoms_deduped", lambda atoms, st: captured.setdefault("atoms", atoms))
    none_atom = SimpleNamespace(embedding_int8=None)
    emb_atom = SimpleNamespace(embedding_int8=(1, 2, 3))
    pl._fill_missing_embeddings([emb_atom, none_atom], SimpleNamespace(st=object()))
    assert captured["atoms"] == [none_atom]


# --- L270: _topic_split_if_enabled gate ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_topic_split_suppressed_when_structure_aware(monkeypatch):
    """structure_aware must suppress the split (L270 first `or`)."""
    called = []
    monkeypatch.setattr(pl, "split_over_merged_atoms", lambda *a, **k: called.append(a) or ([], 9))
    atoms = [SimpleNamespace()]
    out, n = pl._topic_split_if_enabled(atoms, SimpleNamespace(st=object()), structure_aware=True)
    assert called == []
    assert (out, n) == (atoms, 0)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_topic_split_runs_when_not_structure_aware(monkeypatch):
    """Non-structure-aware must run the split when an atom is flagged over_merged (guards the gate)."""
    called = []
    monkeypatch.setattr(pl, "split_over_merged_atoms", lambda *a, **k: called.append(a) or ([], 9))
    _out, n = pl._topic_split_if_enabled(
        [SimpleNamespace(over_merged=True)], SimpleNamespace(st=object()), structure_aware=False
    )
    assert called
    assert n == 9


@pytest.mark.unit
@pytest.mark.subsys_map
def test_topic_split_skips_encoder_when_nothing_over_merged(monkeypatch):
    """No atom flagged over_merged must skip the call entirely — the ONNX-loading
    `models.st` property must never be forced when the split would be a no-op."""
    called = []
    monkeypatch.setattr(pl, "split_over_merged_atoms", lambda *a, **k: called.append(a) or ([], 9))

    class _ExplodingModels:
        @property
        def st(self):
            raise AssertionError("models.st must not be touched when no atom is over_merged")

    atoms = [SimpleNamespace(over_merged=False), SimpleNamespace(over_merged=False)]
    out, n = pl._topic_split_if_enabled(atoms, _ExplodingModels(), structure_aware=False)
    assert called == []
    assert (out, n) == (atoms, 0)


# --- _embed_file_descriptions_if_any: warm-map ONNX-touch guard ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_embed_descriptions_runs_when_a_record_has_one_without_embedding(monkeypatch):
    captured = {}

    def _fake(records, encoder):
        captured["records"] = records
        return []

    monkeypatch.setattr(pl, "_embed_file_descriptions", _fake)
    records = [SimpleNamespace(description=""), SimpleNamespace(description="DESC")]
    pl._embed_file_descriptions_if_any(records, SimpleNamespace(st=object()), None)
    assert captured["records"] is records


@pytest.mark.unit
@pytest.mark.subsys_map
def test_embed_descriptions_skips_encoder_when_none_need_one():
    class _ExplodingModels:
        @property
        def st(self):
            raise AssertionError("models.st must not be touched when no description needs embedding")

    none = [SimpleNamespace(description="", description_embedding=None)] * 2
    embedded = [SimpleNamespace(description="DESC", description_embedding=(1, 2))]
    pl._embed_file_descriptions_if_any(none, _ExplodingModels(), None)
    pl._embed_file_descriptions_if_any(embedded, _ExplodingModels(), None)
    assert embedded[0].description_embedding == (1, 2)


# --- L156: _classify_all_files description gate ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_on_invocation_file_gets_description(monkeypatch, tmp_path):
    """An on_invocation file must carry its parsed description (L156 `==`)."""
    monkeypatch.setattr(
        pl, "_detect_file_loading", lambda path, root, reg: ("on_invocation", "global", (), "claude", "skills")
    )
    monkeypatch.setattr(pl, "_classify_file", lambda *a, **k: "sha256:x")
    monkeypatch.setattr(pl, "_parse_frontmatter_description", lambda path: "DESC")
    records, _atoms, _embed = pl._classify_all_files([tmp_path / "f.md"], tmp_path, None, {}, "legacy")
    assert records[0].description == "DESC"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_non_invocation_file_has_empty_description(monkeypatch, tmp_path):
    monkeypatch.setattr(
        pl, "_detect_file_loading", lambda path, root, reg: ("session_start", "global", (), "claude", "main")
    )
    monkeypatch.setattr(pl, "_classify_file", lambda *a, **k: "sha256:x")
    monkeypatch.setattr(pl, "_parse_frontmatter_description", lambda path: "DESC")
    records, _atoms, _embed = pl._classify_all_files([tmp_path / "f.md"], tmp_path, None, {}, "legacy")
    assert records[0].description == ""


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_skills_supporting_file_takes_the_skill_s_type(monkeypatch, tmp_path):
    """A skill is its directory: a `generic`-matched file inside a `skills`-typed `SKILL.md`'s
    directory, at any depth below it, is re-typed `skills` too — a supporting file
    (`intake-flow.md`, `references/x.md`) belongs to the skill's location instead of becoming
    a `generic` location on its own. An unrelated file elsewhere stays `generic`."""
    skill_dir = tmp_path / ".claude" / "skills" / "digest"
    skill_dir.mkdir(parents=True)
    skill_md = skill_dir / "SKILL.md"
    intake = skill_dir / "intake-flow.md"
    nested = skill_dir / "references" / "x.md"
    nested.parent.mkdir(parents=True)
    other = tmp_path / "notes.md"
    for p in (skill_md, intake, nested, other):
        p.write_text("x")

    def _loading(path, root, reg):
        file_type = "skills" if path == skill_md else "generic"
        return ("session_start", "global", (), "claude", file_type)

    monkeypatch.setattr(pl, "_detect_file_loading", _loading)
    monkeypatch.setattr(pl, "_classify_file", lambda *a, **k: "sha256:x")
    monkeypatch.setattr(pl, "_parse_frontmatter_description", lambda path: "")

    records, _atoms, _embed = pl._classify_all_files([skill_md, intake, nested, other], tmp_path, None, {}, "legacy")

    types = {r.path: r.type for r in records}
    assert types[str(skill_md)] == "skills"
    assert types[str(intake)] == "skills"
    assert types[str(nested)] == "skills"
    assert types[str(other)] == "generic"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_retyped_skill_supporting_file_inherits_the_skill_s_loading_and_scope(monkeypatch, tmp_path):
    """A supporting file re-typed `skills` must also carry the owning `SKILL.md` record's
    `loading` and `scope` (and its `globs`/`agent`) instead of keeping the generic fallback's —
    otherwise the server ranks the whole `skills` kind as session-start/global. An unrelated
    file elsewhere keeps its own generic loading."""
    skill_dir = tmp_path / ".claude" / "skills" / "digest"
    skill_dir.mkdir(parents=True)
    skill_md = skill_dir / "SKILL.md"
    reference = skill_dir / "reference.md"
    other = tmp_path / "CLAUDE.md"
    for p in (skill_md, reference, other):
        p.write_text("x")

    def _loading(path, root, reg):
        if path == skill_md:
            return ("on_invocation", "global", ("digest/**",), "claude", "skills")
        return ("session_start", "global", (), "generic", "generic")

    monkeypatch.setattr(pl, "_detect_file_loading", _loading)
    monkeypatch.setattr(pl, "_classify_file", lambda *a, **k: "sha256:x")
    monkeypatch.setattr(pl, "_parse_frontmatter_description", lambda path: "")

    records, _atoms, _embed = pl._classify_all_files([skill_md, reference, other], tmp_path, None, {}, "legacy")

    by_path = {r.path: r for r in records}
    skill_rec = by_path[str(skill_md)]
    ref_rec = by_path[str(reference)]
    other_rec = by_path[str(other)]

    assert ref_rec.type == "skills"
    assert ref_rec.loading == skill_rec.loading == "on_invocation"
    assert ref_rec.scope == skill_rec.scope == "global"
    assert ref_rec.globs == skill_rec.globs == ("digest/**",)
    assert ref_rec.agent == skill_rec.agent == "claude"
    assert other_rec.type == "generic"
    assert other_rec.loading == "session_start"


# --- L308/L310/L312/L323: map_ruleset argument plumbing ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_map_ruleset_arg_plumbing(monkeypatch):
    """map_ruleset must forward the caller's models/root and compute structure_aware
    from segmentation.

    Kills L310 (`models is None`), L312 (`root is None`) and L308 (segmentation `==`)
    by capturing what the stubbed stages receive.
    """
    classify_args = {}
    split_args = {}

    def _fake_classify(paths, root, map_cache, registry, segmentation, progress=None):
        classify_args["root"] = root
        return [], [], []

    def _fake_split(all_atoms, models, *, structure_aware):
        split_args["structure_aware"] = structure_aware
        split_args["models"] = models
        return [], 0

    sentinel_models = SimpleNamespace(st=object())
    sentinel_root = Path("/sentinel/root")
    other_models = SimpleNamespace(st=object())

    monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: True)
    monkeypatch.setattr(pl, "_get_stage_timer", lambda: SimpleNamespace(mark=lambda *a, **k: None))
    monkeypatch.setattr(pl, "get_models", lambda: other_models)
    monkeypatch.setattr(pl, "_open_map_cache", lambda *a, **k: None)
    monkeypatch.setattr(pl, "_load_registry", lambda: {})
    monkeypatch.setattr(pl, "_classify_all_files", _fake_classify)
    monkeypatch.setattr(pl, "_embed_and_audit_fresh", lambda *a, **k: None)
    monkeypatch.setattr(pl, "_fill_missing_embeddings", lambda *a, **k: None)
    monkeypatch.setattr(pl, "_topic_split_if_enabled", _fake_split)
    monkeypatch.setattr(pl, "_embed_file_descriptions", lambda *a, **k: None)
    monkeypatch.setattr(
        pl, "build_ruleset_map", lambda *a, **k: SimpleNamespace(summary=SimpleNamespace(n_over_merged=0), atoms=())
    )
    monkeypatch.setattr(pl, "_validate_and_log", lambda *a, **k: None)

    pl.map_ruleset(
        [Path("/some/dir/file.md")],
        models=sentinel_models,
        root=sentinel_root,
        segmentation="legacy",
    )

    assert classify_args["root"] is sentinel_root  # L312
    assert split_args["structure_aware"] is False  # L308
    assert split_args["models"] is sentinel_models  # L310


# --- n_over_merged: audit-flag count, not the split count ---


@pytest.mark.unit
@pytest.mark.subsys_map
def test_n_over_merged_is_audit_flag_count_not_split_count(monkeypatch):
    """RulesetSummary.n_over_merged documents the granularity audit's flag count
    (core/platform/dto/ruleset.py). A flagged unit the later split does not
    actually cut (clause split < 2, or stage == 'multislot') must still count —
    2 atoms flagged, 0 atoms split, must report n_over_merged == 2, not 0."""
    flagged_atoms = [
        SimpleNamespace(over_merged=True),
        SimpleNamespace(over_merged=True),
        SimpleNamespace(over_merged=False),
    ]

    def _fake_classify(paths, root, map_cache, registry, segmentation, progress=None):
        return [], list(flagged_atoms), []

    def _fake_split(all_atoms, models, *, structure_aware):
        return all_atoms, 0  # audit flagged 2, but nothing actually split

    captured = {}

    def _fake_build(file_records, all_atoms):
        captured["ruleset"] = SimpleNamespace(summary=SimpleNamespace(n_over_merged=0), atoms=())
        return captured["ruleset"]

    monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: True)
    monkeypatch.setattr(pl, "_get_stage_timer", lambda: SimpleNamespace(mark=lambda *a, **k: None))
    monkeypatch.setattr(pl, "get_models", lambda: SimpleNamespace(st=object()))
    monkeypatch.setattr(pl, "_open_map_cache", lambda *a, **k: None)
    monkeypatch.setattr(pl, "_load_registry", lambda: {})
    monkeypatch.setattr(pl, "_classify_all_files", _fake_classify)
    monkeypatch.setattr(pl, "_embed_and_audit_fresh", lambda *a, **k: None)
    monkeypatch.setattr(pl, "_fill_missing_embeddings", lambda *a, **k: None)
    monkeypatch.setattr(pl, "_topic_split_if_enabled", _fake_split)
    monkeypatch.setattr(pl, "_embed_file_descriptions_if_any", lambda *a, **k: None)
    monkeypatch.setattr(pl, "build_ruleset_map", _fake_build)
    monkeypatch.setattr(pl, "_validate_and_log", lambda *a, **k: None)

    pl.map_ruleset([Path("/some/dir/file.md")], segmentation="legacy")

    assert captured["ruleset"].summary.n_over_merged == 2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_map_ruleset_refuses_to_map_without_the_whole_model(monkeypatch):
    """A model set that is only partly on disk is not mapped with a stand-in charge:
    the mapper reports itself unavailable, as it does with no model at all."""
    monkeypatch.setattr("reporails_cli.core.mapper.bio_tagger.multislot_available", lambda: False)

    with pytest.raises(RuntimeError, match="not complete on disk"):
        pl.map_ruleset([Path("/some/dir/file.md")], root=Path("/some/dir"))


# --- description embeddings live in the per-file cache entry ---


class _CountingEncoder:
    def __init__(self):
        self.encoded: list[list[str]] = []

    def encode(self, texts):
        self.encoded.append(list(texts))
        return [[float(len(t)), 1.0, -2.0] for t in texts]


def _skill_file(tmp_path, description="Does one thing well."):
    path = tmp_path / "SKILL.md"
    path.write_text(f"---\nname: one\ndescription: {description}\n---\n\n# One\n\n- Use uv.\n", encoding="utf-8")
    return path


def _record(path, description="Does one thing well.", embedding=None):
    return SimpleNamespace(path=str(path), description=description, description_embedding=embedding)


def _seed_entry(cache, path):
    from reporails_cli.core.cache.map_cache import CachedFileEntry, cache_key_for_path

    key = cache_key_for_path(path)
    cache.put(key, CachedFileEntry(key, [{"text": "x"}]))
    return key


@pytest.mark.unit
@pytest.mark.subsys_map
def test_description_embedding_is_encoded_once_and_served_from_the_cache_entry(tmp_path):
    from reporails_cli.core.cache.map_cache import MapCache

    path = _skill_file(tmp_path)
    cache = MapCache(tmp_path / "cache", charge="m")
    cache.load()
    _seed_entry(cache, path)
    encoder = _CountingEncoder()
    models = SimpleNamespace(st=encoder)

    first = [_record(path)]
    pl._embed_file_descriptions_if_any(first, models, cache)
    assert encoder.encoded == [["Does one thing well."]]
    assert first[0].description_embedding is not None

    # A later process opens the cache cold: the vector comes back from the shard, no encode.
    reopened = MapCache(tmp_path / "cache", charge="m")
    reopened.load()
    second = [_record(path, embedding=reopened.description_embedding(path))]
    pl._embed_file_descriptions_if_any(second, models, reopened)
    assert encoder.encoded == [["Does one thing well."]]
    assert second[0].description_embedding == first[0].description_embedding


@pytest.mark.unit
@pytest.mark.subsys_map
def test_an_edited_description_is_encoded_again(tmp_path):
    from reporails_cli.core.cache.map_cache import MapCache

    path = _skill_file(tmp_path)
    cache = MapCache(tmp_path / "cache", charge="m")
    cache.load()
    _seed_entry(cache, path)
    encoder = _CountingEncoder()
    pl._embed_file_descriptions_if_any([_record(path)], SimpleNamespace(st=encoder), cache)

    edited = _skill_file(tmp_path, "Does another thing.")
    _seed_entry(cache, edited)
    assert cache.description_embedding(edited) is None
    record = _record(edited, "Does another thing.")
    pl._embed_file_descriptions_if_any([record], SimpleNamespace(st=encoder), cache)
    assert encoder.encoded == [["Does one thing well."], ["Does another thing."]]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_description_embedding_does_not_cross_a_charge_model_change(tmp_path):
    from reporails_cli.core.cache.map_cache import MapCache

    path = _skill_file(tmp_path)
    cache = MapCache(tmp_path / "cache", charge="model-a")
    cache.load()
    _seed_entry(cache, path)
    pl._embed_file_descriptions_if_any([_record(path)], SimpleNamespace(st=_CountingEncoder()), cache)
    assert cache.description_embedding(path) is not None

    other = MapCache(tmp_path / "cache", charge="model-b")
    other.load()
    assert other.description_embedding(path) is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_identical_descriptions_are_encoded_once_per_build():
    from reporails_cli.core.mapper import embed

    encoder = _CountingEncoder()
    records = [
        SimpleNamespace(description="alpha", description_embedding=None),
        SimpleNamespace(description="beta", description_embedding=None),
        SimpleNamespace(description="alpha", description_embedding=None),
        SimpleNamespace(description="kept", description_embedding=(5, 6, 7)),
    ]
    embedded = embed._embed_file_descriptions(records, lambda: encoder)
    assert encoder.encoded == [["alpha", "beta"]]
    assert embedded == records[:3]
    assert records[0].description_embedding == records[2].description_embedding
    assert records[3].description_embedding == (5, 6, 7)
