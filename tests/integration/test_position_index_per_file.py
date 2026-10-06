"""`position_index` must be per-file, not global, across `map_ruleset`: each file's atoms are
numbered from zero in document order, including after the topic-split pass
(`split_over_merged_atoms`, `split_topic.py`).

Uses the real bundled ONNX model end to end (no stubs) with `cache_dir=None`, so the
whole default (`legacy` segmentation) path — including the topic-split pass — actually
runs."""

from __future__ import annotations

from pathlib import Path

import pytest

_onnx_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
)
_has_onnx_model = _onnx_path.exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_model
def test_position_index_is_per_file_across_map_ruleset(tmp_path: Path) -> None:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    a = tmp_path / "a.md"
    a.write_text(
        "Run the linter before committing.\nNever skip the test suite.\nDocument every public function.\n",
        encoding="utf-8",
    )
    b = tmp_path / "b.md"
    b.write_text(
        "Pin the dependency version.\nWrite the changelog entry.\n",
        encoding="utf-8",
    )

    models = get_models()
    ruleset = map_ruleset([a, b], models=models, root=tmp_path, cache_dir=None)

    by_file: dict[str, list[int]] = {}
    for atom in ruleset.atoms:
        if atom.kind == "heading":
            continue
        by_file.setdefault(atom.file_path, []).append(atom.position_index)

    assert set(by_file) == {a.as_posix(), b.as_posix()}
    for path, positions in by_file.items():
        assert sorted(positions) == list(range(len(positions))), (path, positions)
