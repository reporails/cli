"""A duplicate-content file must not skip the charge classifier.

Two content-identical `.claude/agents/*.md` files in one run must both reach
`apply_multislot` and both carry the multislot charge (`stage` set, `slots`/`so` block
present), not the tokenize-time lexical charge. `_update_cache_after_embedding` is the
only cache writer, so a same-run cache hit is always a fully-charged, embedded entry.

Runs the real bundled classifier + ONNX embedder (no stubs) so the
claim is about the actual charge/stage/slots a real run produces.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_SHARED_CONTENT = "# Rule\n\nAlways validate user input before use.\n"


def _atom_shape(ruleset, file_path: Path) -> list[tuple[str, int, str, str, bool]]:
    """(charge, charge_value, modality, stage, has_slots) per non-heading atom."""
    return [
        (a.charge, a.charge_value, a.modality, a.stage, a.slots is not None)
        for a in ruleset.atoms
        if a.file_path == str(file_path) and a.kind != "heading"
    ]


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_duplicate_content_files_charge_identically_in_one_cold_run(tmp_path: Path) -> None:
    """Two content-identical files, mapped together in one cold run, must come
    out of the charge stage with identical (charge, charge_value, modality,
    stage, has_slots) — the second file must not be short-circuited to the
    first file's PRE-charge tokenization."""
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    f_a = tmp_path / "a_one.md"
    f_b = tmp_path / "b_two.md"
    f_a.write_text(_SHARED_CONTENT)
    f_b.write_text(_SHARED_CONTENT)

    models = get_models()
    cache_dir = tmp_path / "cache"

    cold_map = map_ruleset([f_a, f_b], models=models, root=tmp_path, cache_dir=cache_dir)

    shape_a = _atom_shape(cold_map, f_a)
    shape_b = _atom_shape(cold_map, f_b)
    assert shape_a, "fixture must produce at least one non-heading atom"
    assert shape_a == shape_b, f"duplicate-content files diverged in one cold run: {shape_a} != {shape_b}"
    # Both must actually have reached the charge stage (not fallen back to the
    # tokenize-time lexical charge with an empty stage and no slots).
    assert all(stage == "multislot" and has_slots for _, _, _, stage, has_slots in shape_a), shape_a


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_cold_and_warm_payload_bytes_match_for_duplicate_content(tmp_path: Path) -> None:
    """A cold run's projected+encoded payload must byte-match a subsequent warm
    run's, for a project made entirely of content-identical files."""
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset
    from reporails_cli.core.platform.adapters.payload import encode_msgpack, project_payload

    f_a = tmp_path / "a_one.md"
    f_b = tmp_path / "b_two.md"
    f_a.write_text(_SHARED_CONTENT)
    f_b.write_text(_SHARED_CONTENT)

    models = get_models()
    cache_dir = tmp_path / "cache"

    cold_map = map_ruleset([f_a, f_b], models=models, root=tmp_path, cache_dir=cache_dir)
    warm_map = map_ruleset([f_a, f_b], models=models, root=tmp_path, cache_dir=cache_dir)

    # `generated_at` is a wall-clock stamp set fresh on every `map_ruleset` call
    # (`assemble.py`) — normalize it before comparing so the byte comparison is
    # about the mapped CONTENT, not incidental timestamp drift between the two
    # calls this test makes on purpose.
    cold_map.generated_at = warm_map.generated_at = "1970-01-01T00:00:00+00:00"

    cold_bytes = encode_msgpack(project_payload(cold_map, tmp_path))
    warm_bytes = encode_msgpack(project_payload(warm_map, tmp_path))

    assert warm_bytes == cold_bytes
