"""The release workflow stamps the Action's `version` default with the released version."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action" / "action.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


def _stamp_script() -> str:
    workflow = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    for step in workflow["jobs"]["tag"]["steps"]:
        if step.get("name") == "Stamp the Action's default version":
            return step["run"]
    raise AssertionError("the release workflow has no step that stamps the Action's version default")


def _stamp_lines(script: str) -> str:
    """The script up to the git commands: the part that edits and checks action.yml."""
    return script.split("git config", 1)[0]


@pytest.mark.unit
@pytest.mark.subsys_gates
@pytest.mark.skipif(sys.platform == "win32", reason="the stamp runs bash/sed in the ubuntu release job only")
@pytest.mark.parametrize("version", ["0.6.0", "1.2.3"])
def test_stamp_sets_the_version_default_and_nothing_else(tmp_path: Path, version: str) -> None:
    (tmp_path / "action").mkdir()
    copy = tmp_path / "action" / "action.yml"
    original = ACTION.read_text(encoding="utf-8")
    copy.write_text(original, encoding="utf-8")
    script = _stamp_lines(_stamp_script()).replace("${{ needs.check-release.outputs.version }}", version)

    done = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True, check=False)

    assert done.returncode == 0, done.stdout + done.stderr
    stamped = yaml.safe_load(copy.read_text(encoding="utf-8"))
    assert stamped["inputs"]["version"]["default"] == version
    changed = [
        (a, b)
        for a, b in zip(original.splitlines(), copy.read_text(encoding="utf-8").splitlines(), strict=True)
        if a != b
    ]
    assert len(changed) == 1


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_version_input_describes_the_stamped_default() -> None:
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    version = action["inputs"]["version"]

    assert version["default"] == ""
    assert "released with" in version["description"]
    assert "Defaults to latest" not in version["description"]
