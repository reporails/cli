"""`prepare` then `validate`: the reply is the one a cold `validate` gives, and no map is rebuilt."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.pipeline import mapping
from reporails_cli.interfaces.mcp import tools
from reporails_cli.interfaces.mcp.prepare import prepare_for_path

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project\n\nAlways run the tests before you commit.\n", encoding="utf-8")
    (project / ".claude" / "rules" / "style.md").write_text(
        "# Style\n\nNever leave commented-out code in a change.\n", encoding="utf-8"
    )
    return project


def _use_cache(monkeypatch: pytest.MonkeyPatch, cache: Path) -> None:
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping.get_global_cache_dir", lambda: cache)
    monkeypatch.setattr(
        "reporails_cli.core.pipeline.mapping._resolve_daemon",
        lambda *_a, **_k: mapping.DaemonStatus.UNAVAILABLE,
    )


@requires_model
@pytest.mark.integration
@pytest.mark.subsys_server
def test_validate_after_prepare_replies_as_a_cold_validate_and_does_not_map_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.config.get_global_config_path", lambda: tmp_path / "no-global.yml"
    )
    project = _project(tmp_path)

    _use_cache(monkeypatch, tmp_path / "cold-cache")
    cold = json.dumps(tools.run_pipeline_for_path(str(project), full=True)[0], sort_keys=True)

    _use_cache(monkeypatch, tmp_path / "warm-cache")
    assert prepare_for_path(str(project))["files"] == 2
    real_map = mapping._map_via_daemon_or_process
    maps: list[int] = []

    def counting(*args: object, **kwargs: object):
        maps.append(1)
        return real_map(*args, **kwargs)

    monkeypatch.setattr("reporails_cli.core.pipeline.mapping._map_via_daemon_or_process", counting)
    warm = json.dumps(tools.run_pipeline_for_path(str(project), full=True)[0], sort_keys=True)

    assert maps == []
    assert warm == cold
