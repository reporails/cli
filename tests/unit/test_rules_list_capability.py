"""`ails rules list --capability` rejects a capability the agent does not declare."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_unknown_capability_is_an_error_naming_it_and_listing_the_known_ones() -> None:
    result = runner.invoke(app, ["rules", "list", "--capability", "bogus", "--agent", "claude"])

    assert result.exit_code != 0
    assert "bogus" in result.output
    assert "skills" in result.output
    assert "hooks" in result.output
    assert "Checks for" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_one_unknown_capability_among_known_ones_is_still_an_error() -> None:
    result = runner.invoke(app, ["rules", "list", "-c", "skills", "-c", "nonesuch", "--agent", "claude"])

    assert result.exit_code != 0
    assert "nonesuch" in result.output
    assert "nonesuch" in result.output.split("known:")[0]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_unknown_capability_without_an_agent_is_checked_against_every_agent() -> None:
    result = runner.invoke(app, ["rules", "list", "--capability", "bogus"])

    assert result.exit_code != 0
    assert "bogus" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("capability", ["skills", "skill", "hooks"])
def test_a_known_capability_lists_its_rules(capability: str) -> None:
    result = runner.invoke(app, ["rules", "list", "--capability", capability, "--agent", "claude"])

    assert result.exit_code == 0
    assert "applicable" in result.output
