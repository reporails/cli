"""`No <X>` prohibition vs `No <X>` status report, through the real `map_ruleset`.

The discriminator (`starts_bare_no_status`) is shared by the deterministic
classifier, the post-head neutral floor and the map validator, but only the full
pipeline exercises the multislot head that re-charges every atom in between. A
terse prohibition written as a bullet (`- No console.log`) must reach the wire as
CONSTRAINT; a status report written the same way (`- No open issues`) must reach
it as NEUTRAL.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_FIXTURE = """# Project rules

- No console.log
- No hardcoded secrets
- No secrets in seed
- No regressions.
- No open issues
- No drift detected on the tracked dimensions
"""

_EXPECTED = {
    "No console.log": -1,
    "No hardcoded secrets": -1,
    "No secrets in seed": -1,
    "No regressions.": 0,
    "No open issues": 0,
    "No drift detected on the tracked dimensions": 0,
}


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_map_ruleset_separates_terse_prohibition_from_status_report(tmp_path: Path) -> None:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    target = tmp_path / "CLAUDE.md"
    target.write_text(_FIXTURE, encoding="utf-8")

    ruleset = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    charged = {a.text: a.charge_value for a in ruleset.atoms if a.kind != "heading"}

    missing = [text for text in _EXPECTED if text not in charged]
    assert not missing, f"atomizer dropped {missing}; got {list(charged)}"
    for text, want in _EXPECTED.items():
        assert charged[text] == want, f"{text!r} mapped to {charged[text]:+d}, want {want:+d}"
