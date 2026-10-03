"""Unit tests for caching system — project-local cache and global analytics.

Uses tmp_path fixtures; only mocks subprocess calls (get_git_remote).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from reporails_cli.core.cache import ProjectCache, content_hash
from reporails_cli.core.platform.dto.analytics import ProjectAnalytics
from reporails_cli.core.platform.observability.analytics import (
    get_project_id,
    get_project_name,
    load_project_analytics,
    record_scan,
    save_project_analytics,
)

# ---------------------------------------------------------------------------
# content_hash
# ---------------------------------------------------------------------------


class TestContentHash:
    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_deterministic_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "test.md"
        f.write_text("hello world")
        h1 = content_hash(f)
        h2 = content_hash(f)
        assert h1 == h2
        assert h1.startswith("sha256:")
        assert len(h1) == len("sha256:") + 16


# ---------------------------------------------------------------------------
# Project identification
# ---------------------------------------------------------------------------


class TestGetProjectId:
    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_with_git_remote(self, tmp_path: Path) -> None:
        with patch(
            "reporails_cli.core.platform.observability.analytics.get_git_remote",
            return_value="git@github.com:org/repo.git",
        ):
            pid = get_project_id(tmp_path)
        assert len(pid) == 12
        assert pid.isalnum()

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_without_git_remote(self, tmp_path: Path) -> None:
        with patch("reporails_cli.core.platform.observability.analytics.get_git_remote", return_value=None):
            pid = get_project_id(tmp_path)
        assert len(pid) == 12
        assert pid.isalnum()

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_different_remotes_different_ids(self, tmp_path: Path) -> None:
        with patch(
            "reporails_cli.core.platform.observability.analytics.get_git_remote",
            return_value="git@github.com:org/a.git",
        ):
            id_a = get_project_id(tmp_path)
        with patch(
            "reporails_cli.core.platform.observability.analytics.get_git_remote",
            return_value="git@github.com:org/b.git",
        ):
            id_b = get_project_id(tmp_path)
        assert id_a != id_b


class TestGetProjectName:
    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_returns_directory_name(self, tmp_path: Path) -> None:
        name = get_project_name(tmp_path)
        assert name == tmp_path.resolve().name


# ---------------------------------------------------------------------------
# ProjectCache — file map
# ---------------------------------------------------------------------------


class TestProjectCacheFileMap:
    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_round_trip(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        # Create real files so get_cached_files validation passes
        f1 = tmp_path / "a.md"
        f2 = tmp_path / "b.md"
        f1.write_text("a")
        f2.write_text("b")

        cache.save_file_map([f1, f2])
        loaded = cache.load_file_map()

        assert loaded is not None
        assert loaded["count"] == 2
        assert set(loaded["files"]) == {"a.md", "b.md"}

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_returns_none_on_missing(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        assert cache.load_file_map() is None

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_returns_none_on_corrupt_json(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        cache.ensure_dir()
        cache.file_map_path.write_text("not json")
        assert cache.load_file_map() is None


# ---------------------------------------------------------------------------
# ProjectCache — judgment cache
# ---------------------------------------------------------------------------


class TestProjectCacheJudgment:
    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_set_then_get_hit(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        results = {"C6": {"verdict": "pass", "reason": "ok"}}
        cache.set_cached_judgment("CLAUDE.md", "sha256:abc123", results)

        cached = cache.get_cached_judgment("CLAUDE.md", "sha256:abc123")
        assert cached == results

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_get_with_wrong_hash_miss(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        results = {"C6": {"verdict": "pass", "reason": "ok"}}
        cache.set_cached_judgment("CLAUDE.md", "sha256:abc123", results)

        cached = cache.get_cached_judgment("CLAUDE.md", "sha256:DIFFERENT")
        assert cached is None

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_get_missing_file_returns_none(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        assert cache.get_cached_judgment("nope.md", "sha256:x") is None


# ---------------------------------------------------------------------------
# Global analytics round-trip
# ---------------------------------------------------------------------------


class TestProjectAnalytics:
    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_save_load_round_trip(self, tmp_path: Path) -> None:
        analytics = ProjectAnalytics(
            project_id="abc123def456",
            project_name="test-project",
            project_path="/tmp/test",
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T00:00:00Z",
            scan_count=1,
            history=[],
        )

        with patch("reporails_cli.core.platform.observability.analytics.get_analytics_dir", return_value=tmp_path):
            save_project_analytics(analytics)
            loaded = load_project_analytics("abc123def456")

        assert loaded is not None
        assert loaded.project_id == "abc123def456"
        assert loaded.project_name == "test-project"
        assert loaded.scan_count == 1

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_load_returns_none_on_missing(self, tmp_path: Path) -> None:
        with patch("reporails_cli.core.platform.observability.analytics.get_analytics_dir", return_value=tmp_path):
            assert load_project_analytics("nonexistent") is None

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_load_returns_none_on_corrupt(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("not json")
        with patch("reporails_cli.core.platform.observability.analytics.get_analytics_dir", return_value=tmp_path):
            assert load_project_analytics("bad") is None


# ---------------------------------------------------------------------------
# record_scan
# ---------------------------------------------------------------------------


class TestRecordScan:
    def _record(self, target: Path, analytics_dir: Path, score: float = 7.5) -> None:
        with (
            patch("reporails_cli.core.platform.observability.analytics.get_git_remote", return_value=None),
            patch("reporails_cli.core.platform.observability.analytics.get_analytics_dir", return_value=analytics_dir),
        ):
            record_scan(
                target=target,
                score=score,
                level="L3",
                violations_count=3,
                rules_checked=10,
                elapsed_ms=50.0,
                instruction_files=1,
            )

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_creates_new_analytics(self, tmp_path: Path) -> None:
        target = tmp_path / "project"
        target.mkdir()
        analytics_dir = tmp_path / "analytics"

        self._record(target, analytics_dir)

        # Should have created a file
        files = list(analytics_dir.glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["scan_count"] == 1
        assert len(data["history"]) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_appends_to_existing(self, tmp_path: Path) -> None:
        target = tmp_path / "project"
        target.mkdir()
        analytics_dir = tmp_path / "analytics"

        self._record(target, analytics_dir, score=6.0)
        self._record(target, analytics_dir, score=7.0)

        files = list(analytics_dir.glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["scan_count"] == 2
        assert len(data["history"]) == 2

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_caps_at_100_entries(self, tmp_path: Path) -> None:
        target = tmp_path / "project"
        target.mkdir()
        analytics_dir = tmp_path / "analytics"

        for i in range(105):
            self._record(target, analytics_dir, score=float(i % 10))

        files = list(analytics_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert len(data["history"]) == 100
        assert data["scan_count"] == 105


class TestMapCacheRehydrateTolerance:
    """A cached atom dict from a prior CLI version must rehydrate, not crash."""

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_stale_unknown_key_is_dropped_not_raised(self) -> None:
        # A warm cache written before a field was removed carries that key. The
        # reload must drop it rather than raise Atom(**d) on an unexpected kwarg.
        from reporails_cli.core.cache.map_cache import dicts_to_atoms

        stale = {
            "line": 1,
            "text": "use x",
            "kind": "excitation",
            "charge": "DIRECTIVE",
            "charge_value": 1,
            "modality": "imperative",
            "specificity": "named",
            "conflicts": [{"partner": 2, "obj": "`x.yml`", "action": "use"}],  # removed field
        }
        (atom,) = dicts_to_atoms([stale])
        assert atom.text == "use x"
        assert not hasattr(atom, "conflicts")


def _make_map(text: str = "use x"):
    """Build a minimal RulesetMap for cache round-trip tests."""
    from reporails_cli.core.platform.dto.ruleset import (
        EMBEDDING_MODEL,
        SCHEMA_VERSION,
        Atom,
        FileRecord,
        RulesetMap,
        RulesetSummary,
    )

    atom = Atom(
        line=1,
        text=text,
        kind="excitation",
        charge="DIRECTIVE",
        charge_value=1,
        modality="imperative",
        specificity="named",
    )
    return RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at="2026-07-06T00:00:00Z",
        files=(FileRecord(path="a.md", content_hash="sha256:abc"),),
        atoms=(atom,),
        summary=RulesetSummary(n_atoms=1, n_charged=1, n_neutral=0),
    )


class TestSlotsNotPersisted:
    """The dev-preview 5-tuple slots are a pipeline-local intermediate — the multi-slot
    head sets them for the same-run atomizer to consume, but neither the daemon cache
    nor the client-side JSON round-trip persists them (their sole downstream reader,
    the on-box conflict detector, is removed)."""

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_cache_dict_round_trip_drops_slot_text(self) -> None:
        # atoms_to_dicts flattens the nested slots via asdict(); the cache round-trip
        # must not carry slot TEXT back — a stale/foreign string on Atom.slots would be
        # worse than dropping it, since nothing downstream reads it anymore. The atom
        # still carried a `slots` object (the head always sets one), so the rehydrated
        # atom keeps a `slots` object too (see TestSlotCoordsPersisted for the
        # fresh-vs-cached symmetry this is the text-half of).
        from reporails_cli.core.cache.map_cache import atoms_to_dicts, dicts_to_atoms
        from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots

        atom = Atom(
            line=1,
            text="use tabs",
            kind="excitation",
            charge="DIRECTIVE",
            charge_value=1,
            modality="imperative",
            specificity="named",
            slots=AtomSlots(subject="indentation", predicate="use", object="tabs", scope="in tests"),
        )
        (rt,) = dicts_to_atoms(atoms_to_dicts([atom]))
        assert rt.slots is not None
        assert (rt.slots.subject, rt.slots.predicate, rt.slots.object, rt.slots.scope) == ("", "", "", "")
        # The fields the head actually charges the atom with still round-trip.
        assert (rt.charge, rt.charge_value, rt.modality) == ("DIRECTIVE", 1, "imperative")

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_serialize_map_round_trip_drops_slots(self, tmp_path: Path) -> None:
        # The client-side JSON round-trip (the daemon wire format) never carries slots.
        from reporails_cli.core.mapper.serialize import load_ruleset_map, save_ruleset_map
        from reporails_cli.core.platform.dto.ruleset import AtomSlots

        m = _make_map()
        m.atoms[0].slots = AtomSlots(subject="the response", predicate="return", object="JSON", scope="")
        path = tmp_path / "map.json"
        save_ruleset_map(m, path)
        loaded = load_ruleset_map(path)
        assert loaded.atoms[0].slots is None
        assert "slots" not in json.loads(path.read_text(encoding="utf-8"))["atoms"][0]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_serialize_map_round_trip_none_slots_stays_none(self, tmp_path: Path) -> None:
        # An atom with no slots (the bio default) round-trips as None.
        from reporails_cli.core.mapper.serialize import load_ruleset_map, save_ruleset_map

        path = tmp_path / "map.json"
        save_ruleset_map(_make_map(), path)
        assert load_ruleset_map(path).atoms[0].slots is None


class TestSlotCoordsPersisted:
    """The span COORDINATE half of `slots` (token offsets + per-span
    confidence) must survive the atom-cache round-trip, even though the slot TEXT
    stays cli-local-per-run and is dropped (see TestSlotsNotPersisted above)."""

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_cache_dict_round_trip_keeps_span_coords_drops_text(self) -> None:
        from reporails_cli.core.cache.map_cache import atoms_to_dicts, dicts_to_atoms
        from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots

        atom = Atom(
            line=1,
            text="use tabs",
            kind="excitation",
            charge="DIRECTIVE",
            charge_value=1,
            modality="imperative",
            specificity="named",
            slots=AtomSlots(
                subject="",
                predicate="use",
                object="tabs",
                scope="in tests",
                predicate_span=(0, 1),
                object_span=(1, 2),
                scope_span=(2, 4),
                predicate_conf=0.91,
                object_conf=0.88,
                scope_conf=0.77,
            ),
        )
        dicts = atoms_to_dicts([atom])
        # The wire-adjacent coordinate half persists on the cache entry ...
        assert dicts[0]["slot_coords"]["predicate_span"] == (0, 1)
        assert dicts[0]["slot_coords"]["object_span"] == (1, 2)
        assert dicts[0]["slot_coords"]["scope_span"] == (2, 4)
        assert dicts[0]["slot_coords"]["predicate_conf"] == pytest.approx(0.91)
        # ... but the dict never carries a "slots" key with slot TEXT on it.
        assert "slots" not in dicts[0]

        (rt,) = dicts_to_atoms(dicts)
        assert rt.slots is not None
        assert rt.slots.predicate_span == (0, 1)
        assert rt.slots.object_span == (1, 2)
        assert rt.slots.scope_span == (2, 4)
        assert rt.slots.predicate_conf == pytest.approx(0.91)
        # Text never rehydrates — it was never written to the cache entry.
        assert rt.slots.subject == ""
        assert rt.slots.predicate == ""
        assert rt.slots.object == ""

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_json_round_trip_keeps_span_coords(self) -> None:
        """The coordinates survive an actual JSON serialize/deserialize (disk shape),
        not just the in-memory dict — a tuple offset round-trips through a JSON list."""
        from reporails_cli.core.cache.map_cache import atoms_to_dicts, dicts_to_atoms
        from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots

        atom = Atom(
            line=1,
            text="use tabs",
            kind="excitation",
            charge="DIRECTIVE",
            charge_value=1,
            modality="imperative",
            specificity="named",
            slots=AtomSlots(object="tabs", object_span=(1, 2), object_conf=0.88),
        )
        raw = json.loads(json.dumps(atoms_to_dicts([atom])))
        (rt,) = dicts_to_atoms(raw)
        assert rt.slots.object_span == (1, 2)
        assert rt.slots.object_conf == pytest.approx(0.88)

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_all_default_slots_round_trips_to_all_default_slots(self) -> None:
        """Regression: a fresh atom carrying `AtomSlots()` (no span decoded on any
        axis) used to rehydrate as `slots=None` — the write gated on "any span set",
        so an all-None `AtomSlots` looked indistinguishable from "no slots object at
        all". Fresh and cached must agree: `AtomSlots()` in, `AtomSlots()` back out,
        not `None`."""
        from reporails_cli.core.cache.map_cache import atoms_to_dicts, dicts_to_atoms
        from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots

        fresh = Atom(
            line=1,
            text="use tabs",
            kind="excitation",
            charge="DIRECTIVE",
            charge_value=1,
            modality="imperative",
            specificity="named",
            slots=AtomSlots(),
        )
        (cached,) = dicts_to_atoms(atoms_to_dicts([fresh]))
        assert cached.slots is not None
        assert cached.slots == AtomSlots()
        assert cached.slots == fresh.slots


class TestFullMapIdentity:
    """compute_identity must key on the exact input set so a stale map is never served."""

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_identity_stable_across_path_order(self, tmp_path: Path) -> None:
        from reporails_cli.core.cache.full_map_cache import compute_identity

        a = tmp_path / "a.md"
        b = tmp_path / "b.md"
        a.write_text("alpha content")
        b.write_text("beta content")
        assert compute_identity([a, b], root=tmp_path) == compute_identity([b, a], root=tmp_path)

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_identity_changes_on_content_change(self, tmp_path: Path) -> None:
        from reporails_cli.core.cache.full_map_cache import compute_identity

        a = tmp_path / "a.md"
        a.write_text("original")
        before = compute_identity([a], root=tmp_path)
        a.write_text("edited")
        assert compute_identity([a], root=tmp_path) != before

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_identity_changes_when_file_added(self, tmp_path: Path) -> None:
        # A targeted check maps a subset; a superset must key differently so the
        # smaller run never receives the larger run's cached map (and vice versa).
        from reporails_cli.core.cache.full_map_cache import compute_identity

        a = tmp_path / "a.md"
        b = tmp_path / "b.md"
        a.write_text("alpha")
        b.write_text("beta")
        assert compute_identity([a], root=tmp_path) != compute_identity([a, b], root=tmp_path)

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_identity_changes_on_model(self, tmp_path: Path) -> None:
        from reporails_cli.core.cache.full_map_cache import compute_identity

        a = tmp_path / "a.md"
        a.write_text("alpha")
        assert compute_identity([a], root=tmp_path, model="m1") != compute_identity([a], root=tmp_path, model="m2")

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_identity_changes_when_the_agent_registry_changes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rules update that re-declares an agent's file types must miss the cached map.

        `loading` / `scope` / `globs` / `agent` on every FileRecord come from the
        `<agent>/config.yml` registry the mapper reads, which `ails update` swaps wholesale.
        Leave the registry out of the identity and the pre-update classification keeps being
        served off disk until the files themselves change.
        """
        from reporails_cli.core.cache.full_map_cache import compute_identity

        rules = tmp_path / "rules" / "cursor"
        rules.mkdir(parents=True)
        config = rules / "config.yml"
        config.write_text(
            "agent: cursor\nfile_types:\n  rules:\n    loading: on_demand\n"
            '    detection:\n      project:\n        patterns: [".cursor/rules/**/*.mdc"]\n'
        )
        monkeypatch.setattr("reporails_cli.core.platform.config.bootstrap.get_rules_path", lambda: tmp_path / "rules")
        a = tmp_path / "a.md"
        a.write_text("alpha")

        before = compute_identity([a], root=tmp_path)
        config.write_text(config.read_text().replace("on_demand", "on_invocation"))

        assert compute_identity([a], root=tmp_path) != before

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_identity_changes_with_the_project_root(self, tmp_path: Path) -> None:
        """The same file set mapped against a different root is a different map.

        `_detect_file_loading` matches `path.relative_to(root)` against the registry, so the
        root decides whether `.cursor/rules/x.mdc` reads as a cursor rule or as an unmatched
        generic file. Two roots must therefore never share one cache entry.
        """
        from reporails_cli.core.cache.full_map_cache import compute_identity

        nested = tmp_path / ".cursor" / "rules"
        nested.mkdir(parents=True)
        rule = nested / "style.mdc"
        rule.write_text("alpha")

        assert compute_identity([rule], root=tmp_path) != compute_identity([rule], root=nested)


class TestFullMapCache:
    """Whole-map cache hit must reconstruct the map."""

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_miss_then_hit_preserves_map(self, tmp_path: Path) -> None:
        from reporails_cli.core.cache.full_map_cache import FullMapCache

        cache = FullMapCache(tmp_path)
        assert cache.get("k1") is None  # empty → miss

        cache.put("k1", _make_map(text="use postgres"))
        hit = cache.get("k1")
        assert hit is not None
        assert hit.atoms[0].text == "use postgres"

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_get_corrupt_returns_none(self, tmp_path: Path) -> None:
        from reporails_cli.core.cache.full_map_cache import FullMapCache

        cache = FullMapCache(tmp_path)
        cache.dir.mkdir(parents=True, exist_ok=True)
        (cache.dir / "bad.json").write_text("{ not valid json")
        assert cache.get("bad") is None

    @pytest.mark.unit
    @pytest.mark.subsys_caching
    def test_evict_caps_entries(self, tmp_path: Path) -> None:
        from reporails_cli.core.cache import full_map_cache

        cache = full_map_cache.FullMapCache(tmp_path)
        for i in range(full_map_cache._MAX_ENTRIES + 5):
            cache.put(f"k{i:03d}", _make_map(text=f"atom {i}"))
        remaining = list(cache.dir.glob("*.json"))
        assert len(remaining) <= full_map_cache._MAX_ENTRIES
