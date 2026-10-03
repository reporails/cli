"""Integration coverage for import line mapping through the real `map_ruleset` entry point.

A cold run tokenizes the importing file fresh and translates `atom.line` back
to source coordinates before the per-file cache `put` (`map_cache._CACHE_VERSION`
folds this shape change so a pre-fix cache entry never serves stale lines). A
warm run must read the SAME lines back off the cache. Uses the real bundled
ONNX model (embedding is unrelated to the bug, but `map_ruleset` needs it to
run end to end) — no stubs, so a cache round-trip through the real code path is
actually exercised.
"""

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
def test_map_ruleset_import_lines_stable_across_cache_hit(tmp_path: Path) -> None:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    (tmp_path / "b.md").write_text(
        "Imported line one.\nImported line two.\nImported line three.",
        encoding="utf-8",
    )
    main = tmp_path / "main.md"
    main.write_text(
        "Setup step one.\n"
        "Setup step two.\n"
        "Setup step three.\n"
        "Setup step four.\n"
        "Setup step five.\n"
        "@b.md\n"
        "Never skip the final step.\n",
        encoding="utf-8",
    )

    cache_dir = tmp_path / "cache"
    models = get_models()

    def _lines_by_text(paths: list[Path]) -> dict[str, int]:
        ruleset = map_ruleset(paths, models=models, root=tmp_path, cache_dir=cache_dir)
        return {a.text: a.line for a in ruleset.atoms if a.kind != "heading"}

    cold = _lines_by_text([main])
    assert cold["Never skip the final step."] == 7
    assert cold["Setup step one."] == 1
    for text in ("Imported line one.", "Imported line two.", "Imported line three."):
        assert cold[text] == 6, (text, cold[text])

    warm = _lines_by_text([main])
    assert warm == cold, "cache hit must report the same source lines as the cold run"
