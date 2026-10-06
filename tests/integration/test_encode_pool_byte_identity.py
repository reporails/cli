"""Thread-pooled encode must produce byte-identical output to the serial encode.

The pooled encode fans the per-bucket forwards across a thread pool over one
warm session. Like that, it
changes *when* the work happens, never *what* comes out: each bucket forward is
independent and the caller scatters results back into the original order. This
runs the real mapper against the real bundled model once at
`AILS_MAP_ENCODE_WORKERS=1` (serial) and once at `=8` (pooled), and asserts the
serialized atoms match byte-for-byte — the guard that pool size never changes
output.
"""

from __future__ import annotations

import json
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

_CORPUS = Path(__file__).resolve().parent.parent / "fixtures" / "shard_corpus"


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_model
def test_pooled_encode_byte_identical_to_serial(monkeypatch: pytest.MonkeyPatch, deterministic_ort: None) -> None:
    """Real multi-file corpus, real model: encode-workers=8 output == workers=1 output.

    `cache_dir=None` on both runs forces a full cold embed (a shared warm cache
    would let the second run skip inference and prove nothing). Spies on
    `run_buckets` to confirm the multi-bucket pooled path actually ran, so a
    single-bucket or disabled-pool fallback cannot make the comparison vacuous.
    """
    from reporails_cli.core.mapper import encode_pool as pool_mod
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset
    from reporails_cli.core.mapper.serialize import _atom_to_dict

    paths = sorted(_CORPUS.glob("*.md"))
    assert len(paths) >= 4, "fixture corpus must span several files"

    models = get_models()

    pooled_worker_counts: list[int] = []
    real_run_buckets = pool_mod.run_buckets

    def _spy(tasks):  # type: ignore[no-untyped-def]
        pooled_worker_counts.append((pool_mod.encode_pool_workers(), len(tasks)))
        return real_run_buckets(tasks)

    # bio_tagger and onnx_embedder import run_buckets locally at call time, so
    # patching the module attribute is seen by both call sites.
    monkeypatch.setattr(pool_mod, "run_buckets", _spy)

    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "1")
    serial = map_ruleset(paths, models=models, root=_CORPUS, cache_dir=None)

    monkeypatch.setenv("AILS_MAP_ENCODE_WORKERS", "8")
    pooled = map_ruleset(paths, models=models, root=_CORPUS, cache_dir=None)

    # The pooled run must have had >1 worker AND a multi-bucket call, else the
    # concurrent path never actually engaged and the comparison is vacuous.
    assert any(w > 1 and n > 1 for w, n in pooled_worker_counts), (
        f"pooled encode path never ran with >1 worker over >1 bucket: {pooled_worker_counts}"
    )

    assert len(serial.atoms) > 20
    assert len(serial.atoms) == len(pooled.atoms)

    serial_json = json.dumps([_atom_to_dict(a) for a in serial.atoms], indent=2, sort_keys=True)
    pooled_json = json.dumps([_atom_to_dict(a) for a in pooled.atoms], indent=2, sort_keys=True)
    assert pooled_json == serial_json


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_model
def test_batched_charge_groups_byte_identical_to_per_file(deterministic_ort: None) -> None:
    """`apply_multislot_groups` (one cross-file decode batch) == per-file `apply_multislot`.

    The charge stage batches every fresh file's decode into ONE encoder forward so the
    batch is large enough to fill the encode thread pool, instead of one small per-file
    batch that leaves most workers idle. Each file is still rebuilt on its own atoms,
    so the batched result must match charging each file alone — the guard that batching
    the decode changed only WHEN the forward runs, not what it returns. Reddens if the
    per-group decode slice is mis-offset or the file-scoped floors / position re-index
    leak across the batch boundary.
    """
    from reporails_cli.core.mapper.bio_pipeline import apply_multislot, apply_multislot_groups
    from reporails_cli.core.mapper.parse import tokenize
    from reporails_cli.core.mapper.serialize import _atom_to_dict

    files = sorted(_CORPUS.glob("*.md"))
    assert len(files) >= 4, "fixture corpus must span several files"

    per_file = [apply_multislot(list(tokenize(f.read_text()))) for f in files]
    batched = apply_multislot_groups([list(tokenize(f.read_text())) for f in files])

    assert sum(len(g) for g in batched) > 20
    assert [len(g) for g in batched] == [len(g) for g in per_file]

    def _dump(groups: list[list]) -> str:  # type: ignore[type-arg]
        return json.dumps([[_atom_to_dict(a) for a in g] for g in groups], indent=2, sort_keys=True)

    assert _dump(batched) == _dump(per_file)
