"""A tool name that is only link text is not reported as unformatted code, on a real file.

The file goes through the real map and the client checks, the way `ails check` does: the mapped
text has its link syntax removed, so the check reads the line as written.
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
requires_model = pytest.mark.skipif(not _onnx_path.exists(), reason="Bundled ONNX model not available")


@pytest.mark.integration
@pytest.mark.subsys_lint
@requires_model
def test_tool_name_in_link_text_is_not_reported_but_a_bare_one_is(tmp_path: Path) -> None:
    from reporails_cli.core.lint.client_checks import run_client_checks
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    doc = tmp_path / "CLAUDE.md"
    doc.write_text(
        "# Project\n\n"
        "See [the build.sh guide](docs/guide.md) for details.\n\n"
        "Read [build.sh](https://example.com/build.sh/stable/) before writing tests.\n\n"
        "Run build.sh before every commit.\n\n"
        "Follow [the style guide](https://example.com/ruff/config) when editing.\n",
        encoding="utf-8",
    )
    ruleset = map_ruleset([doc], models=get_models(), root=tmp_path, cache_dir=None)
    reported = {f.line for f in run_client_checks(ruleset) if f.rule == "format"}
    assert reported == {7}
