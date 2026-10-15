"""An unreadable config file stops the run with one error naming the file and the problem."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.platform.config import config as config_mod
from reporails_cli.core.platform.contract.errors import ConfigUnreadableError
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()
_BAD = "disabled_rules: [CORE:E:0003\n"


@pytest.fixture
def global_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A global config location under tmp, used by the reader and by `ails config`."""
    path = tmp_path / "home" / "config.yml"
    path.parent.mkdir()
    monkeypatch.setattr(config_mod, "get_global_config_path", lambda: path)
    monkeypatch.setattr("reporails_cli.interfaces.cli.config_command.get_global_config_path", lambda: path)
    return path


def _project(tmp_path: Path, name: str | None = None, body: str = _BAD) -> Path:
    root = tmp_path / "proj"
    (root / ".ails").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\n\nUse uv.\n", encoding="utf-8")
    if name:
        (root / ".ails" / name).write_text(body, encoding="utf-8")
    return root


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("name", ["config.yml", "config.local.yml"])
def test_check_stops_on_an_unreadable_project_file(tmp_path: Path, global_path: Path, name: str) -> None:
    root = _project(tmp_path, name)
    result = runner.invoke(app, ["check", str(root)])
    assert result.exit_code == 2
    assert f"Error: {root / '.ails' / name}" in result.output
    assert "line 2" in result.output or "line 1" in result.output
    assert "Traceback" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_check_stops_on_an_unreadable_global_file(tmp_path: Path, global_path: Path) -> None:
    global_path.write_text(_BAD, encoding="utf-8")
    result = runner.invoke(app, ["check", str(_project(tmp_path))])
    assert result.exit_code == 2
    assert f"Error: {global_path}" in result.output
    assert "line" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_config_commands_report_the_same_error_and_set_leaves_the_file(tmp_path: Path, global_path: Path) -> None:
    root = _project(tmp_path, "config.yml")
    target = root / ".ails" / "config.yml"
    before = target.read_bytes()
    for args in (["get", "disabled_rules"], ["list"], ["set", "default_agent", "claude"]):
        result = runner.invoke(app, ["config", *args, "--path", str(root)])
        assert result.exit_code == 2, args
        assert f"Error: {target}" in result.output, args
    assert target.read_bytes() == before
    global_path.write_text(_BAD, encoding="utf-8")
    result = runner.invoke(app, ["config", "set", "--global", "default_agent", "claude"])
    assert result.exit_code == 2
    assert global_path.read_text(encoding="utf-8") == _BAD


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_that_is_not_a_mapping_or_not_utf8_is_unreadable(tmp_path: Path) -> None:
    listing = tmp_path / "a.yml"
    listing.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ConfigUnreadableError, match="not a mapping"):
        config_mod.read_config_file(listing)
    binary = tmp_path / "b.yml"
    binary.write_bytes(b"tier: \xff\xfe\n")
    with pytest.raises(ConfigUnreadableError, match=str(binary)):
        config_mod.read_config_file(binary)
    assert config_mod.read_config_file(tmp_path / "absent.yml") == {}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_tab_before_an_inline_comment_gets_one_outcome_from_check_and_config(
    tmp_path: Path, global_path: Path
) -> None:
    root = _project(tmp_path, "config.yml", "exclude_dirs: [vendor]\t# keep vendored code out\n")
    checked = runner.invoke(app, ["check", str(root)])
    read = runner.invoke(app, ["config", "get", "exclude_dirs", "--path", str(root)])
    assert (checked.exit_code == 2) == (read.exit_code == 2)
    if read.exit_code == 2:
        assert read.output.strip().startswith("Error:") and "Error:" in checked.output
    else:
        assert "vendor" in read.output


@pytest.mark.unit
@pytest.mark.subsys_server
def test_mcp_validate_returns_the_structured_error(tmp_path: Path, global_path: Path) -> None:
    from reporails_cli.interfaces.mcp.server import _run_heal_apply, _run_validate

    root = _project(tmp_path, "config.yml")
    payload = asyncio.run(_run_validate(str(root), False))
    assert payload["error"] == "config_unreadable"
    assert str(root / ".ails" / "config.yml") in payload["message"]
    healed = asyncio.run(_run_heal_apply(str(root)))
    assert healed.startswith("heal_apply: ") and str(root / ".ails" / "config.yml") in healed


@pytest.mark.unit
@pytest.mark.subsys_server
def test_mcp_explain_returns_the_structured_error(
    tmp_path: Path, global_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    from reporails_cli.interfaces.mcp import server

    global_path.write_text(_BAD, encoding="utf-8")
    monkeypatch.chdir(_project(tmp_path))
    payload = json.loads(asyncio.run(server.explain("CORE:E:0003")))
    assert payload["error"] == "config_unreadable"
    assert str(global_path) in payload["message"]


_NOT_TEXT = {
    "exclude_dirs: [2024, archive]\n": "exclude_dirs: item 1 reads as the number 2024, not text; quote it",
    "exclude_dirs: [docs, 12:30, on, ~]\n": "exclude_dirs: item 2 reads as the number 750, not text; quote it",
    "exclude_dirs: [docs, 0755]\n": "exclude_dirs: item 2 reads as the number 493, not text; quote it",
    "disabled_rules: [CORE:E:0003, yes]\n": (
        "disabled_rules: item 2 reads as true/false (yes, no, on, off, true and false all do), not text; quote it"
    ),
    "exclude_dirs: [docs, .nan]\n": "exclude_dirs: item 2 reads as a special number (.nan or .inf), not text; quote it",
    "exclude_dirs: [.inf]\n": "exclude_dirs: item 1 reads as a special number (.nan or .inf), not text; quote it",
    "exclude_dirs: [a, [b]]\n": "exclude_dirs: item 2 is a nested list, not text",
    "exclude_dirs: [a, {b: c}]\n": "exclude_dirs: item 2 is a nested mapping, not text",
    "exclude_dirs:\n  - archive\n  -\n": "exclude_dirs: item 2 is empty; remove it",
    "packages: yes\n": "packages must be a list of text items",
    "agents: [claude]\n": "agents must be a mapping",
    "surfaces: {claude: 3}\n": "surfaces.claude must be a mapping",
}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(("body", "problem"), _NOT_TEXT.items(), ids=range(len(_NOT_TEXT)))
def test_a_setting_of_the_wrong_shape_is_unreadable_not_dropped(
    tmp_path: Path, global_path: Path, body: str, problem: str
) -> None:
    root = _project(tmp_path, "config.yml", body)
    with pytest.raises(ConfigUnreadableError) as raised:
        config_mod.get_project_config(root)
    assert str(raised.value) == f"{root / '.ails' / 'config.yml'}: {problem}"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_check_stops_on_a_non_text_setting(tmp_path: Path, global_path: Path) -> None:
    root = _project(tmp_path, "config.yml", "exclude_dirs: [2024, archive]\n")
    result = runner.invoke(app, ["check", str(root)])
    assert result.exit_code == 2
    assert (
        f"Error: {root / '.ails' / 'config.yml'}: exclude_dirs: item 1 reads as the number 2024, not text; quote it"
        in result.output
    )
