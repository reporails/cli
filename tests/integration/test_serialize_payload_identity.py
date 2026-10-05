"""The JSON serialize round-trip must be payload-lossless.

`ails check` tries the mapper daemon first, and the daemon hands the client its
`RulesetMap` via `daemon._ruleset_map_to_dict` — a JSON round-trip through
`save_ruleset_map`/`load_ruleset_map` (`core/mapper/serialize.py`). The
whole-map cache (`full_map_cache.py`) round-trips the SAME two functions to
disk. `_atom_to_dict`/`_atom_from_dict` must carry `slots` (the span coordinates the
wire `so` block projects), plus `stage`, `over_merged`, `min_clause_cosine`,
`caps_tokens`, `cell_straddle`, and `abstained` — so a daemon or whole-map-cache-hit run
ships the same payload, `so` block included, as a cold in-process run.

This runs the real bundled multi-slot classifier + embedder (no stubs — the
claim is about a real wire payload) over a small two-file fixture, once cold
in-process and once through the serialize round-trip, and asserts the
projected+encoded msgpack payloads are byte-identical.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_FILE_A = """# Rules

Never push directly to main.
Add backtick-wrapped names to your instructions.
Always run the test suite before committing.
Do not commit secrets to the repository.
"""

_FILE_B = """# More rules

Reporails recognizes agent files and runs the validator.
You must document every public function.
Avoid using bare except clauses in production code.
"""


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_daemon_style_round_trip_preserves_the_v4_payload(tmp_path: Path) -> None:
    """Cold in-process map, projected+encoded, must byte-match the same map
    after a save_ruleset_map/load_ruleset_map JSON round-trip (the shape both
    the daemon dict path and the whole-map cache disk path exercise)."""
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset
    from reporails_cli.core.mapper.serialize import load_ruleset_map, save_ruleset_map
    from reporails_cli.core.platform.adapters.payload import encode_msgpack, project_payload

    f_a = tmp_path / "a.md"
    f_a.write_text(_FILE_A)
    f_b = tmp_path / "b.md"
    f_b.write_text(_FILE_B)

    models = get_models()
    # cache_dir=None: a full cold classify+embed, no per-file cache shortcut —
    # the comparison must be between two REAL passes through the same atoms,
    # not a cache hit masquerading as one.
    cold_map = map_ruleset([f_a, f_b], models=models, root=tmp_path, cache_dir=None)

    cold_payload = project_payload(cold_map, tmp_path)
    n_so = sum(1 for a in cold_payload["atoms"] if "so" in a)
    assert n_so > 0, "fixture must exercise the multi-slot span decode — a vacuous comparison otherwise"

    roundtrip_path = tmp_path / "roundtrip-map.json"
    save_ruleset_map(cold_map, roundtrip_path)
    reloaded_map = load_ruleset_map(roundtrip_path)

    cold_bytes = encode_msgpack(cold_payload)
    reloaded_bytes = encode_msgpack(project_payload(reloaded_map, tmp_path))

    assert reloaded_bytes == cold_bytes
